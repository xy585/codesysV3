#!/usr/bin/env python3
"""列出指定抓包里 CmpTraceMgr(0x0f) 的全部请求/响应，找出保存/删除用哪个服务号。

用法: python trace_ops.py <pcap文件> [只看的服务号如 0x0003]
"""

import struct
import sys

import scapy.all as scapy

PCAP = sys.argv[1]
ONLY = sys.argv[2] if len(sys.argv) > 2 else None

pkts = scapy.rdpcap(PCAP)


def leb(d, p):
    v = 0; s = 0
    while p < len(d):
        b = d[p]; p += 1; v |= (b & 0x7f) << s
        if not (b & 0x80):
            return v, p
        s += 7
    raise ValueError


def walk(d, depth=0, out=None):
    if out is None:
        out = []
    p = 0
    while p < len(d):
        try:
            tid, p = leb(d, p)
            size, p = leb(d, p)
        except Exception:
            return out
        if p + size > len(d):
            out.append((depth, tid, size, d[p:])); return out
        v = d[p:p + size]; p += size
        out.append((depth, tid, size, v))
        if tid & 0x80:
            walk(v, depth + 1, out)
    return out


pending, messages = {}, []
for i, p in enumerate(pkts):
    if not (p.haslayer(scapy.UDP) and p.haslayer(scapy.IP) and p.haslayer(scapy.Raw)):
        continue
    u = p[scapy.UDP]
    if u.sport not in (1740, 1741, 1742, 1743) or u.dport not in (1740, 1741, 1742, 1743):
        continue
    d = bytes(p[scapy.Raw])
    if len(d) < 13 or d[0] != 0xC5 or d[3] != 0x40:
        continue
    ch = d[12:]
    if not ch or ch[0] != 0x01:
        continue
    sp = u.sport
    if ch[1] & 0x01:
        decl = struct.unpack_from('<I', ch, 16)[0]
        buf = bytearray(ch[24:])
        if len(buf) >= decl:
            messages.append((i, sp, bytes(buf[:decl])))
        else:
            pending[sp] = [decl, buf, i]
    elif sp in pending:
        pending[sp][1] += ch[16:]
        if len(pending[sp][1]) >= pending[sp][0]:
            messages.append((pending[sp][2], sp, bytes(pending[sp][1][:pending[sp][0]])))
            del pending[sp]

print(f"### {PCAP}   ({len(messages)} 条 services 消息)\n")
for i, sp, svc in messages:
    if len(svc) < 20:
        continue
    proto, hs, grp, sid, sess, csz, add = struct.unpack_from('<HHHHIII', svc, 0)
    if proto != 0xCD55 or (grp & 0x7f) != 0x0f:
        continue
    if ONLY and f"0x{int(ONLY,16):04x}" != f"0x{sid:04x}":
        continue
    body = svc[20:20+csz]
    d = "IDE->PLC" if sp != 1740 else "PLC->IDE"
    print(f"pkt#{i:<6} [{d}] svc=0x{sid:04x} sess=0x{sess:08x} content={csz}B")
    if body:
        print(f"      {body[:150].hex(' ')}")
        print(f"      asc: {''.join(chr(c) if 32 <= c < 127 else '.' for c in body[:150])}")
        for depth, tid, size, v in walk(body)[:10]:
            asc = ''.join(chr(c) if 32 <= c < 127 else '.' for c in v[:40])
            print(f"        {'  '*depth}tag 0x{tid & 0x7f:02x} len={size:<5} "
                  f"{v[:36].hex(' '):<74} |{asc}|")
    print()
