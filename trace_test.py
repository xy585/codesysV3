#!/usr/bin/env python3
"""
触发 CmpTraceMgr 全流程：
  LIST -> OPEN -> INFO -> START -> READ(采样) -> STOP -> CLOSE

用法：
  python trace_test.py [target] [trace名]
"""

import struct
import sys
import time

sys.path.insert(0, r'C:\Users\Xingy\Desktop\scripts')
from codesys_udp_ds import (CodesysClient, parse_tags, find_tag_deep, _flatten,
                            status_of, TRACE_START, TRACE_STOP, TRACE_CLOSE,
                            TAG_TRACE_DATA)

TARGET = sys.argv[1] if len(sys.argv) > 1 else "192.168.125.129"
WANT = sys.argv[2] if len(sys.argv) > 2 else "PlcLoad"


def connect():
    for port in (1741, 1742, 1743):
        for _ in range(3):
            try:
                c = CodesysClient(TARGET, local_port=port, verbose=False)
                c.open_channel()
                return c
            except Exception:
                time.sleep(2)
    return None


def leaves(tags):
    return [(t["id"], t["value"]) for t in _flatten(tags)
            if not t["children"] and t["value"]]


def parse_samples(blob):
    """样本块：前 4 字节计数，之后每 5 字节 = 1 字节标志 + u32 值。"""
    if len(blob) < 4:
        return [], 0
    count = struct.unpack_from("<I", blob, 0)[0]
    rest = blob[4:]
    vals = [struct.unpack_from("<I", rest, k + 1)[0]
            for k in range(0, len(rest) - 4, 5)]
    return vals, count


c = connect()
if c is None:
    print("无法建立通道"); sys.exit(1)
c.create_session()
pem, ch = c.get_public_key()
st, _ = c.login(pem, ch, "test", "test")
ok, _ = c.app_login("App")
print(f"设备登录={st}  应用登录={ok}\n")
if st != 0:
    sys.exit(1)

# --- 1) 列出 ---
names, _ = c.trace_list()
print(f"1) TRACE_LIST -> {names}")
if WANT not in names:
    print(f"   {WANT!r} 不存在，改用 {names[0]!r}")
    WANT = names[0]

# --- 2) 打开 ---
handle, status = c.trace_open(WANT)
print(f"2) TRACE_OPEN({WANT!r}) -> handle={handle.hex(' ') if handle else None} "
      f"status={status}")
if handle is None:
    c.close(); sys.exit(1)

# --- 3) 详情 ---
tags, raw = c.trace_info(handle)
print(f"3) TRACE_INFO -> {len(raw)}B  status={status_of(tags)}")
for tid, v in leaves(tags):
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in v[:28])
    print(f"     tag 0x{tid:02x} ({len(v):3d}B) {v[:28].hex(' '):<60} |{asc}|")

# --- 4) 启动 ---
s_start, r1 = c.trace_ctl(TRACE_START, handle)
print(f"4) TRACE_START -> status={s_start}  raw={r1.hex(' ')}")

time.sleep(2.0)

# --- 5) 读采样 ---
print("5) TRACE_READ:")
for off in (0, 0x100):
    tags, raw = c.trace_read(handle, off)
    blob = find_tag_deep(tags, TAG_TRACE_DATA)
    vals, count = parse_samples(blob["value"]) if blob else ([], 0)
    print(f"     offset={off:#06x} status={status_of(tags)} resp={len(raw)}B")
    if blob:
        print(f"       数据 {len(blob['value'])}B 声明计数={count} "
              f"解析出 {len(vals)} 个值")
        if vals:
            print(f"       前 10 个: {vals[:10]}")
            print(f"       后 3 个 : {vals[-3:]}")
            print(f"       变化量  : "
                  f"{[b - a for a, b in zip(vals[:9], vals[1:10])]}")
    else:
        print(f"       原始: {raw.hex(' ')}")

# --- 6) 停止 ---
s_stop, r2 = c.trace_ctl(TRACE_STOP, handle)
print(f"6) TRACE_STOP  -> status={s_stop}  raw={r2.hex(' ')}")

# --- 7) 关闭 ---
s_close, r3 = c.trace_ctl(TRACE_CLOSE, handle)
print(f"7) TRACE_CLOSE -> status={s_close}  raw={r3.hex(' ')}")

c.close()
print("\n完成")
