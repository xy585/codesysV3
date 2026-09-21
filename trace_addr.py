#!/usr/bin/env python3
"""对比：新建 trace 的变量地址 vs 抓包模板里的地址。"""

import sys
import time

sys.path.insert(0, r'C:\Users\Xingy\Desktop\scripts')
from codesys_udp_ds import CodesysClient, parse_tags, _flatten, find_tag_deep


def conn():
    for p in (1741, 1742, 1743):
        for _ in range(3):
            try:
                c = CodesysClient("192.168.125.129", local_port=p, verbose=False)
                c.open_channel()
                return c
            except Exception:
                time.sleep(2)


c = conn()
c.create_session()
pem, ch = c.get_public_key()
c.login(pem, ch, "test", "test")
c.app_login("App")

names, _ = c.trace_list()
print(f"trace 列表: {names}\n")

for n in names:
    if n.startswith("PlcLoad") or n.startswith("CpuCoreLoad"):
        continue
    h, st = c.trace_open(n)
    if not h:
        print(f"{n!r}: open 失败 status={st}")
        continue
    tags, raw = c.trace_info(h)
    print(f"=== {n!r} handle={h.hex(' ')}")
    name = addr = size = None
    for t in _flatten(tags):
        if t["id"] == 0x20 and t["value"]:
            name = t["value"].rstrip(b"\x00").decode("latin-1")
        elif t["id"] == 0x4d and t["value"]:
            addr = t["value"][:4].hex(' ')
        elif t["id"] == 0x4e and t["value"]:
            size = int.from_bytes(t["value"][:4], "little")
        elif t["id"] == 0x25 and t["value"] and name:
            print(f"    变量 {name!r}  地址=0x{addr}  长度={size}")
            name = addr = size = None
    c.trace_ctl(0x0006, h)
c.close()
