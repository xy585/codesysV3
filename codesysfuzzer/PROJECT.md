# CODESYS V3 协议 Fuzzer —— 项目说明

> 面向 CODESYS V3 runtime 的通用协议 fuzzer。目标不是复现某一个已知漏洞，而是
> 能对各个 service 做定向与广域 fuzzing。
>
> 状态：可用，已完成 26 个 request model（其中 8 个从反汇编推导），跑了单轮
> 434 case 的长会话，并录到过一次崩溃（**待归因**，见 §8.3）。

---

## 1. 定位与目标

已有资产给了很好的起点：`codesys_tcp.py` 是一个逐字节对照过抓包的 CODESYS V3
客户端，`trace_poc.py` / `poc_tcp.py` 已确认了 CmpTraceMgr 的一个栈溢出。但它们
都是**针对单一报文**的，覆盖不了 760 个 `(group, service)` 组合。

本项目的目标：

1. **通用**：请求形状数据驱动，能覆盖所有 service，而不是为每个漏洞写一个 PoC；
2. **报文永远合法**：变异不能因为长度/CRC 不一致而被运行时静默丢弃；
3. **可复现**：任何一次运行、任何一个 case 都能精确重放；
4. **能找到新东西**：能枚举服务面、能按优先级定向打击、崩溃时自动落地证据。

---

## 2. 架构

### 2.1 分层

CODESYS V3 的报文是四层嵌套，每层都有自己的长度字段，其中一层还有 CRC32：

```
┌─ Block Driver (CmpBlkDrvTcp, TCP 11740) ───────────────────────┐
│  magic(4) + total_len(4)                        每帧一个      │
│ ┌─ Datagram (CmpRouter, 20B) ───────────────────────────────┐ │
│ │ magic/hop_info/pkt_info/svc/mid/lengths + sender + recv   │ │
│ │ ┌─ Channel (CmpChannelMgr) ─────────────────────────────┐ │ │
│ │ │ type/flags/token/channel_id/blk_id/ack_id             │ │ │
│ │ │ + data_size + CRC32                 （仅首帧带后两者） │ │ │
│ │ │ ┌─ Services (0xCD55) ───────────────────────────────┐ │ │ │
│ │ │ │ proto/hdrsize/group/service/session/content_size  │ │ │ │
│ │ │ │ ┌─ Body：扁平 tag 流 ──────────────────────────┐  │ │ │ │
│ │ │ │ │ [tag_id][LEB128 len][value] ...              │  │ │ │ │
│ │ │ │ │ 容器 tag 的 bit7=1，长度是该容器的字节数     │  │ │ │ │
│ │ │ │ └──────────────────────────────────────────────┘  │ │ │ │
│ │ │ └───────────────────────────────────────────────────┘ │ │ │
│ │ └───────────────────────────────────────────────────────┘ │ │
│ └───────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────┘
```

### 2.2 数据流

```
CLI ──► Fuzzer ──► boofuzz Session ──► CodesysConnection ──► TCP
          │             │                     │
          │             │                     ├─ open(): 握手（GET_CHANNEL → session
          │             │                     │   → pubkey/challenge → login → app login）
          │             │                     ├─ send(): 渲染好的整帧序列
          │             │                     └─ probe(): 崩溃判定
          │             │
          │             ├─ pre_send: 注入 session_id
          │             ├─ 渲染: FrameEncoder 生成 BLK 帧序列
          │             └─ post_test: 记录运行状态
          │
          └─ CodesysMonitor: 读回复、回显 keepalive、判活、写崩溃报告
```

---

## 3. 模块设计

| 文件 | 行数 | 职责 |
|---|---|---|
| `proto.py` | 96 | `sys.path` 引导 + 重新导出 `codesys_tcp.py` 的协议层。**不复写任何已验证的编码**，`codesys_tcp.py` 本身不改动。 |
| `utils.py` | 543 | 核心机制：`Leb128Size`、`LyingLeb128Size`、`FrameEncoder`、`RunRandom`（按运行种子）、请求骨架、group 表。 |
| `services.py` | 603+ | 26 个 request model + 分级黑盒模式；`REQUESTS` 注册表。 |
| `corpus.py` | 新增 | 种子语料：真实 body + pair 元数据，sha1 去重、稳定排序、digest/manifest。 |
| `mutator.py` | 新增 | 数据驱动变异：raw 字节 havoc、structured tag 树变异、mixed hybrid；每 case 确定性。 |
| `transport.py` | 701 | `SessionState`、握手、**持久 channel**、回复读取、keepalive 回显、backpressure 分类、崩溃探针。 |
| `monitor.py` | 670+ | `BaseMonitor` 实现：读回复、判活、服务面记录、崩溃报告落盘、accepted body 回灌。 |
| `fuzzer.py` | 284+ | boofuzz 装配：Target / Session / 回调 / 日志策略；三种 body 源（model / seed / static）。 |
| `runstate.py` | 129+ | 运行状态（JSON）：断点续跑、种子记录、语料 digest。原子写。 |
| `codesys_fuzzer.py` | 835+ | CLI：单模型 / `--all` / `--all-groups` / `--from-pairs` / `--from-seeds` / `--replay` / dry-run。 |
| `test_framing.py` | 334 | 离线逐字节回归（67 断言）。 |
| `test_surface.py` | 446 | 离线：pair 记录、tag 种子、运行状态、崩溃报告（74 断言）。 |
| `test_seed.py` | 新增 | 离线：语料去重/排序、tag 编解码、变异确定性、SeedBody 索引映射、多帧重组（54 断言）。 |
| `tools/extract_seeds.py` | 新增 | 从 pcap/pcapng 提取请求 body（TCP block driver + UDP gateway）。 |
| `tools/extract_service_tags.py` | 378 | IDAPython：从二进制推导服务/标签表（在 GUI 里跑）。 |
| `tools/summarise_surface.py` | 166 | 把 surface 文件汇总成服务地图。 |

### 3.1 为什么让 boofuzz 只建模 services 层

`FrameEncoder` 挂在 boofuzz 的 block `encoder` 上。已验证：**encoder 在子节点渲染
完成之后才执行**，因此：

- boofuzz 只需要建模最里层的 services + body；
- 外层三层的长度和 CRC32 由 encoder 在拿到最终字节后**重新计算**。

这样无论变异把 body 撑到多大，报文都合法。这是整个设计的支点。

---

## 4. 关键机制

### 4.1 帧化：`FrameEncoder`

输入是渲染好的 services 字节，输出是**完整的 TCP 帧序列**：

- 每帧各自带 BD 头和 datagram 头（不是整条消息共用一个）；
- 首帧 468 字节数据、后续 476；
- `data_size` 与 CRC32 描述**整条消息**，写在首帧；
- **纯函数**：只读状态、返回字节，不推进计数器（原因见 §5.3）。

### 4.2 LEB128：两种宽度

CODESYS 对叶子 tag 的长度用 **3 字节** LEB128（4 → `84 80 00`），对容器长度用
**2 字节**最小编码（96 → `e0 00`）。`Leb128Size` 因此带 `width` 参数；`s_container`
用 2 字节。**逐字节复现抓包依赖这个区别。**

### 4.3 持久 channel

一次运行只握一次手，全程复用一个 channel；只有会话真断了才重握。

### 4.4 三个"种子"概念，别混

| 名字 | 是什么 | 在哪 |
|---|---|---|
| `--seed` / `state.seed` | **fuzz 随机种子**，决定 `RunRandom` 生成什么字节 | run state 文件 |
| tag 种子（`tag_tree`） | 某 pair **被接受过的 body 结构**，用来重建可被解析的 body | surface 文件 |
| pair（group/service） | 定向 fuzz 的目标 | surface 文件 |

`seed` **不是**状态的标识符——状态靠**路径**区分。

### 4.5 断点续跑

`<log-dir>/<request>.state.json` 记录请求、group/service、**种子**、最后 case。
第一个完成的 case 后、每 25 case、以及运行结束时各原子写一次（临时文件 +
`os.replace`），中断不会留下半截索引。注意 `last_case`/`cases_run` 只统计**已完成**
的 case：状态文件为 0 表示该 pair 连会话都没建立，不是没写盘。

seed 模式额外记录 `corpus_path`/`corpus_digest`/`corpus_manifest`/
`mutation_mode`/`mutations_per_seed`/`max_body_size`/`seed_order`。resume 用
记录值重建同一枚举；语料、预算、顺序或 body 上限任一变化都会拒绝，因为 case N
会指向另一个包。进度**写回被 resume 的那个文件**，不会另建
`<log-dir>/<request>.state.json`。批量 `--from-seeds` 在中断、崩溃或拿不到会话时
停止，并打印该 pair 的 `--resume` 命令；再次执行同一条命令会**逐 pair 自动
resume**（连运行种子一起恢复），`--force-new` 才是从头开始。

### 4.6 崩溃报告

探针一旦判定死亡，**当场**写盘（不等运行结束）：

- `<request>_crash_<stamp>.txt` / `.json`
- 内容：复现命令、结构化 tag 树（容器 ID 用线上字节）、**完整原始 hex**

---

## 5. 遇到的问题与解决

### 5.1 协议与帧化

| 问题 | 现象 | 解决 |
|---|---|---|
| 变异后长度/CRC 不自洽 | 运行时静默丢包，fuzz 全部无效 | `FrameEncoder` 在渲染后重算；`s_size` 跟踪实际内容 |
| **多帧时每帧都要独立的 BD+datagram 头** | 单帧正常、多帧全废 | 重写 encoder 输出整帧；回归测试逐帧对比 `send_blk` |
| 容器与叶子 LEB128 宽度不同 | 逐字节对不上抓包 | `Leb128Size(width=2/3)` |
| boofuzz 渲染一个 block **多次** | encoder 每次调用都推进 `tx_blk`，发出去的 `blk_id` 与计算 size/CRC 时的不一致 | encoder 改为**纯函数**；由 `send()` 按实际帧数推进计数器。加了"渲染确定性"回归测试 |

### 5.2 传输与会话（最耗时的一类）

| 问题 | 现象 | 解决 |
|---|---|---|
| **`CLOSE_CHANNEL` 不释放 channel** | 连续握手 4 次后第 5 次被拒，约 20s 后才回收 | 实测确认；改为**复用单一 channel**。实测 434 case / 1 次握手 |
| 运行时在 channel 表满时**不再应答，而是重置连接** | 看起来像崩溃 | `open()` 先探活再判断：**连接被拒**=进程没了；**监听还在但握手被拒**=backpressure，安静等 20s 重试 |
| 退避期间不断重试反而阻止回收 | 越等越死 | 分类一次后**安静等 60s**（后调为 20s），不在等待中产生流量 |
| **keepalive 必须回显** | 不回显会被运行时主动关 channel → 每个 case 都重握 | 在读回复时回显 |
| 回复读取只按**帧数**设上限 | keepalive 不计帧数 → 循环跑满 → 每 case 烧掉 ~64s | 加**墙钟**上限；且只有**数据帧**算"有进展"（第一版把 keepalive 算进去，导致每 case 撞 120s 硬顶） |
| 大回复（35–95KB，约 200 帧） | 固定 deadline 必然截断；截断会让流错位 | 改为**静默超时**（有帧到达就继续）；再加总时长上限，超限**主动放弃**并重握手 |
| 只在整条回复读完才 ACK | 200 帧的流以 ~590 B/s 推进（滑动窗口在等确认） | 改成**在途每 8 帧 ACK** |
| `--reply-timeout` 调得太短 | 帧中途超时 → `_recv_exact` 丢弃已读字节 → 流错位 → 重握手 | 默认恢复到 2.0s，并在文档里写明"调低是假省钱" |

### 5.3 boofuzz 集成（几个必须知道的坑）

| 问题 | 现象 | 解决 |
|---|---|---|
| `_main_fuzz_loop` **用 `pass` 吞掉** `BoofuzzTargetConnectionFailedError` | 握手失败被报成 "0 cases / no crash / exit 0" | `Fuzzer.fuzz()` 在交给 boofuzz 之前**自己先握手**；`open()` 幂等；失败 exit 2 |
| `session_filename` **不是** case 数据库，而是续跑 pickle | 第二次运行静默"0 cases, no error" | 完全不用它；用自研 JSON state + boofuzz 的 `db_filename` |
| `FuzzLoggerText(bytes_to_str=...)` **参数是死的** | 传了也不生效，payload 照打 | 0.4.2 里 `_print_log_msg` 没传它；改为子类覆写 `log_send`/`log_recv` |
| DB 的 `send` step **截断在 512 字节** | 多帧请求只留首帧 | 崩溃报告从 `session.last_send` 取完整字节，不依赖 DB |
| `RandomData` 写死 `random.Random(0)` | 同一模型跑第二遍字节完全相同——不是可复现，是**固定语料** | `RunRandom`：每运行一个种子，与 primitive 名混合；种子记录进 state |
| 单节点图一次只变异一个 primitive | group/service/tag/length 从未组合测试 | 已知限制，见 §9 |

### 5.4 判定语义（踩过的最大一个坑）

最初的分类是 `status=None → accepted`，于是 434 case 里 396 个"接受"。

**错在**：`status=None` 只表示"没找到 0xFF7F 状态标签"，不等于成功。

修正后的判据（用 group 0x12 做过对照实验，**其 service 集合由反汇编已知**）：

- **"服务不存在" = `refused` 且状态 == 该 group 自己的兜底码**（per-group！0x12/0x13 是 `24`，多数是 `770`）；
- 其余都算"存在"：`replied`（有内容）、**`empty`（空回复，也是存在）**、`refused` 且状态**非**兜底码（服务在、body 不对）。

验证结果：45 个 service id 中，36 个回 `24`（不存在），9 个真服务**一个不漏、一个不多**。
而旧规则（"有内容才算存在"）只找到 2/9 —— 是**漏报**，不是误报。
`empty` 的语义也曾被我写错（"被忽略"），实为成功答复。

### 5.5 逆向推导（第 1 项工作）

| 问题 | 现象 | 解决 |
|---|---|---|
| 没有 group→handler 映射表 | 只能靠 Kaspersky 文章的表 | 找到注册原语 `sub_106BFA0(group, handler)`，22 个调用点，读 call 前的两条 `push` 得到 **21 个 group**（含两个未公开的 0x03/0x14） |
| 跳转表标签 ≠ group id | CmpIecVarAccess 标签写 `case 10`，实际 push `9` | 以 `push` 的值为准 |
| 自动化抽取 tag id **不可靠** | 抽出 `0x0c,0x10,0x14…` 一串 4 的倍数——那些是**长度**，不是 id | 改为读 handler：service id 是 `switch(*(WORD*)(req+6))` 的 case；tag id 是**内层 switch** 的 case（比较的是 tag 迭代器的返回值，不是裸立即数） |
| 依据不足就写 model | `appforce` 的 service id 用了占位 `0x0001` → 运行时回 `24` | 读 `sub_EC5900` 得到真值 `0x20/0x21/0x41`，三个全部实测通过。**凡是新推导的 model 必须先 `--dry-run --send`** |
| 扁平 tag 列表无法重建 body | `parse_tags` 会掩掉 bit7，容器 `0x81` 读回来是 `0x01`，重建会变成**叶子** | 种子存成**树**，容器 id 保留 bit7 |

### 5.6 运维侧

- **"卡死"多数不是崩溃。** 判据：服务状态 `Stopped` + 无 WER dump + 无 Application
  日志错误 = 被停止；`Running` 但握手被拒 = channel 表 backpressure。
- **重复起停会污染 channel 表**：一次运行泄漏一个 channel，连续跑几次就满。规矩：
  跑长会话，别跑短会话；批次之间留停顿（`--between-models`）。
- **状态文件会被覆盖**：`<request>.state.json` 不带时间戳，新开一次同名运行会覆盖
  上一次的断点。现在会**拒绝**并给出三个选项（`--resume` / `--state` / `--force-new`），
  批量模式豁免。

---

## 6. 逆向所得（对 fuzzing 的指导）

1. **21 个 group**，其中 **0x03、0x14 未公开**，且都是大 handler（0x03 有 44 个直接
   被调函数）。
2. **共享 tag 解析器**：7 个 group 走同一个入口 `sub_ECA510`，背后约 22 个共享函数。
   → **generic / raw-body 模式打的是三分之一组件共用的代码**，不是兜底。
3. **memcpy 面**：7 个服务函数调 `memcpy`，其中 3 个同时解析 tag 流：
   `0x03/sub_FC0E10`、`0x09/sub_FAAC70`、`0x0f/TraceMgrServiceHandler`。
   自动化方法在不知道答案的前提下把已知有漏洞的那个挑了出来。

---

## 7. 使用

```bash
pip install -r codesysfuzzer/requirements.txt

# 先确认报文能被接受
python codesysfuzzer/codesys_fuzzer.py 192.168.125.129 -r trace_configure --dry-run --send

# 单模型长会话
python codesysfuzzer/codesys_fuzzer.py 192.168.125.129 -r trace_configure --cases 5000

# 分级黑盒
python codesysfuzzer/codesys_fuzzer.py 192.168.125.129 -r generic_sweep --group 0x03 --raw-body

# 枚举服务面（每个 group 一个 session）
python codesysfuzzer/codesys_fuzzer.py 192.168.125.129 --all-groups

# 按 pair 文件定向 fuzz
python codesysfuzzer/codesys_fuzzer.py 192.168.125.129 --from-pairs logs/service_surface.jsonl

# 数据驱动：真实 body 种子变异
python codesysfuzzer/codesys_fuzzer.py 192.168.125.129 -r trace_configure \
    --dry-run --send --save-seed seeds/          # 从模型默认 body 采集种子
python codesysfuzzer/tools/extract_seeds.py trace2.pcapng -o seeds/
python codesysfuzzer/codesys_fuzzer.py 192.168.125.129 --from-seeds seeds/ \
    --mutate structured --cases 5000
python codesysfuzzer/codesys_fuzzer.py 192.168.125.129 \
    --replay logs/seed_0f_0002_crash_*.json

# 断点续跑
python codesysfuzzer/codesys_fuzzer.py 192.168.125.129 --resume logs/trace_configure.state.json

# 离线测试
python codesysfuzzer/test_framing.py && python codesysfuzzer/test_surface.py \
    && python codesysfuzzer/test_seed.py
```

关键 flag：`--surface {global,separate,off}`、`--seed`、`--state`、`--resume`、
`--from-pairs`、`--pairs-only`、`--from-seeds`、`--mutate {raw,structured,hybrid}`、
`--mutations-per-seed`、`--max-body-size`、`--seed-order`、`--save-seed`、
`--capture-seeds`、`--replay`、`--log-payloads`、`--reply-timeout`、`--force-new`。

---

## 8. 进度与验证

### 8.1 已验证

- **离线 266 个断言**（framing 67 + surface 133 + seed 66）：未变异的
  `trace_configure` body 与抓包**逐字节相同**；完整 TCP 帧与 `codesys_tcp.py`
  构造的一致；分片与 `send_blk` 逐帧一致；渲染确定性；每个 model 都能构建且有
  变异；pair 记录/种子/状态/崩溃报告的规则；tag 树解析→重编码逐字节回环；
  seed 变异确定性与索引映射；多帧 body 重组。
- **实测被运行时接受**：`trace_list`、`trace_configure`、6 个 CmpAppBP model、
  3 个 CmpAppForce model（`--dry-run --send`）。
- **长会话**：434 case / 434 回复 / **1 次握手**。
- **种子确定性**：同 `--case --seed` 两次发出的帧字节完全一致；换种子即不同。
- **服务地图**：单 group 0x12 与反汇编给出的 9 个服务**完全吻合**。
- **pcap 提取**：`trace2.pcapng` 解析出 237 个请求 / 62 个唯一 body / 21 个 pair，
  其中 `0x0f/0x0002` 与手工抓出的 `TRACE_CFG_TEMPLATE` sha1 相同。

### 8.2 未完成

- **第 1 项（推导全部 service 的 body）**：19 个 group 中完成 2 个（CmpAppBP 5 个
  service、CmpAppForce 3 个）。剩余工作与读法见 `DERIVED_MODELS.md`。
- **model 的跨字段组合变异**（tag id × 声明长度 × 内容）仍未实现。数据驱动的
  `hybrid` 模式会在一个 case 里叠加多个字节算子，但那是基于 seed 的，不替代
  语法模型的组合枚举。
- 完整服务地图需要重跑 `--all-groups`（上一批 surface 文件已丢失）。

### 8.3 首次崩溃记录（**待归因**）

`logs/trace_configure_crash_1008-093504.txt`：

```
when        : 2026-10-08 09:35:04     request : trace_configure
case        : 296                     cases run : 296
detector    : TimeoutError: timed out  request size : 432 bytes
seed        : 243565400
结构：container 0x86 内 tag 0x30 = 196 字节（> 32 字节到栈上返回地址的偏移）
```

**与已知漏洞的形状一致**：`trace_poc.py` 记录的 tag 0x30 目的地是 `ebp-0x1C`，距
保存的返回地址 **32 字节**，而这一包给了 **196 字节**。DB 里 case 296 被标为 `fail`。

**但尚未归因**：探针是**连接超时**（不是"连接被拒"），且该时间窗内**没有 WER dump、
没有 Application 日志错误**。超时也可能是运行时繁忙。要确认需要在 x64dbg 下重放：

```
python codesysfuzzer/codesys_fuzzer.py 192.168.125.129 -r trace_configure \
    --case 296 --seed 243565400 --surface off
```

断点 `0x00A88833`（tag 48），目标 `[ebp-0x1C]`。这一步没做，所以本文档不声称"已复现漏洞"。

---

## 9. 已知限制

1. **一次只变异一个 primitive**（boofuzz 单节点图）。group/service/tag/length 的
   组合从未被测过。
2. **只支持 TCP**。UDP 路径一次最多 ~472 字节且拒绝分片，无法测试大多数 tag。
3. **崩溃探针分不清"死了"和"卡了"**：连接超时被当作死亡（上面那次就是），
   没有 WER dump 佐证时应视为**待确认**。
4. **tag id 的自动抽取只是下界**：跳转表分派的 tag 只以边界形式出现。
5. **`implemented` 口径在单 pair 文件上会退化**：兜底码靠该组 refused 状态的众数
   推断，只有一个 pair 时众数就是它自己，会把"真实但拒绝了当前 body"的 pair 滤掉。
   修法：兜底码改为从二进制取常量表，或每组探一次。
6. 默认不记录 payload（`--log-payloads` 恢复）；崩溃那一条始终完整记录。
7. **seed 的配对是硬的**：body 只对采集它的 `(group, service)` 有意义；换 handler
   需要显式的 shape-router 式实验，`--from-seeds` 不做自动跨组重放。
8. **seed 运行中不扩充活跃语料**：`--capture-seeds` 只写 `candidates/`，下一轮才
   导入。否则 case index → mutation 的映射会在运行中变化，断点和复现都会失效。
9. **语料 digest 是整份语料的**，不是单 pair 子集：给别的 pair 加一个 seed 也会
   让当前 pair 的 resume 被拒。这是保守选择，宁可重跑也不静默换包。

---

## 10. 相关文档

- `Readme.md` —— 功能与用法、逐条设计说明
- `DERIVED_MODELS.md` —— 第 1 项工作的读法、进度、剩余清单
- `tools/README.md` —— IDA 提取方法与手工读法
- 记忆：`codesys-service-registry`、`codesys-memcpy-surface`、
  `codesys-tracemgr-stack-overflow`、`codesys-v3-udp-client`、`codesys-trace-protocol`
