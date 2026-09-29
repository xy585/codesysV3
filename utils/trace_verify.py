#!/usr/bin/env python3
"""
完整验证：用捕获的 TRACE_CONFIGURE 模板创建 trace，启动并读取采样。

  python trace_verify.py [trace名] [变量名]
"""

import struct
import sys
import time

sys.path.insert(0, r'C:\Users\Xingy\Desktop\scripts')
from codesys_udp_ds import (CodesysClient, parse_tags, find_tag_deep, _flatten,
                            status_of, GRP_TRACE, TAG_TRACE_HANDLE,
                            TAG_TRACE_DATA)

TARGET = "192.168.125.129"
NAME = sys.argv[1] if len(sys.argv) > 1 else "Py.Trace"
VAR = sys.argv[2] if len(sys.argv) > 2 else "POU.iTest"

CONFIG = bytes.fromhex(
    "108c80004170702e547261636500000016848000000000001184800041707000"
    "128880005461736b000000001384800001000000148480006500000015848000"
    "100000008601e000308480000a00000031848000010000003484800033000000"
    "33848000050000008301bc0021848000010200004e848000050000004d888000"
    "029e3b0600000000208c8000504f552e69546573740000002584800007000000"
    "2684800002000000")


def conn():
    for p in (1741, 1742, 1743):
        for _ in range(3):
            try:
                c = CodesysClient(TARGET, local_port=p, verbose=False)
                c.open_channel()
                return c
            except Exception:
                time.sleep(2)
    return None


def show_list(raw):
    out = []
    for t in _flatten(parse_tags(raw)):
        if not t["children"] and t["value"] and t["id"] == 0x01:
            out.append(t["value"])
    return out


def pad_name(b, total=12):
    """模板里名字占 12 字节；替换后必须仍是 12，否则整个请求体会错位。"""
    if len(b) > total:
        raise ValueError(f"名字太长: {b!r} ({len(b)} > {total})")
    return b.ljust(total, b"\x00")


c = conn()
c.create_session()
pem, ch = c.get_public_key()
c.login(pem, ch, "test", "test")
c.app_login("App")

before, raw0 = c.trace_list()
print(f"1) 创建前: {before}")

# 已存在则先删掉（0x0003 疑似删除）
if NAME in before:
    h0, _ = c.trace_open(NAME)
    if h0:
        s, r = c.trace_ctl(0x0003, h0)
        after_del, _ = c.trace_list()
        print(f"   删除已存在的 {NAME!r}: status={s} -> {after_del}")

old_name = b"App.Trace\x00\x00\x00"
body = CONFIG.replace(old_name, pad_name(NAME.encode()))
assert len(body) == len(CONFIG), f"长度变了 {len(body)} != {len(CONFIG)}"
print(f"2) CONFIGURE 0x0002 ({len(body)}B)")

hdr, resp = c.call(GRP_TRACE, 0x0002, body)
h = find_tag_deep(parse_tags(resp), TAG_TRACE_HANDLE)
handle = h["value"] if h else None
print(f"   -> handle={handle.hex(' ') if handle else None} raw={resp.hex(' ')}")

after, raw1 = c.trace_list()
print(f"3) 创建后原始: {raw1.hex(' ')}")
for n in show_list(raw1):
    print(f"   名字字节: {n}")

new = [n for n in show_list(raw1) if n not in show_list(raw0)]
print(f"   新增: {new}")
name = new[0].rstrip(b"\x00").decode("latin-1") if new else NAME
print(f"   使用名字: {name!r}")

if not handle:
    c.close(); sys.exit(1)

# 打开
h2, st = c.trace_open(name)
print(f"4) OPEN -> handle={h2.hex(' ') if h2 else None} status={st}")
handle = h2 or handle

# 启动
for sid in (0x0004, 0x0003):
    s, _ = c.trace_ctl(sid, handle)
    print(f"5) 启动 0x{sid:04x} -> status={s}")
    if s == 0:
        break

# 读取：状态 16 表示数据还没攒够，需要反复轮询
print("6) READ (轮询):")
for k in range(20):
    time.sleep(1.0)
    tags, raw = c.trace_read(handle, 0)
    st = status_of(tags)
    cnt = find_tag_deep(tags, 0x52)
    n = struct.unpack("<I", cnt["value"][:4])[0] if cnt else None
    print(f"   [{k:2d}] status={st} 采样数={n} resp={len(raw)}B")

    pairs = []
    for t in _flatten(tags):
        if t["id"] == 0x41:
            pairs.append([t["value"], None])
        elif t["id"] == 0x42 and pairs and pairs[-1][1] is None:
            pairs[-1][1] = t["value"]
    got = False
    for hv, data in pairs:
        if not data:
            continue
        vals = [struct.unpack_from("<I", data, i + 1)[0]
                for i in range(0, len(data) - 4, 5)]
        if vals:
            got = True
            print(f"       >>> 句柄 {hv.hex(' ')} 数据 {len(data)}B "
                  f"值={vals[:16]}")
    if got:
        print("   *** 成功读到采样值 ***")
        break
    if k == 0 and not pairs:
        print(f"       (响应无数据块: {raw.hex(' ')}）")

c.close()
print("\n完成")
