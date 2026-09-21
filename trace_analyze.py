#!/usr/bin/env python3
"""解析 trace.pcapng 中的 CmpTraceMgr (group 0x0f) 交互。"""

import collections
import struct
import sys

import scapy.all as scapy

PCAP = sys.argv[1] if len(sys.argv) > 1 else r'C:\Users\Xingy\Desktop\scripts\trace.pcapng'

pkts = scapy.rdpcap(PCAP)


def leb(d, p):
    v = 0
    s = 0
    while p < len(d):
        b = d[p]
        p += 1
        v |= (b & 0x7f) << s
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
            out.append((depth, tid, size, d[p:], True))
            return out
        v = d[p:p + size]
        p += size
        out.append((depth, tid, size, v, False))
        if tid & 0x80:
            walk(v, depth + 1, out)
    return out


def show_tags(body, maxn=14):
    for depth, tid, size, v, trunc in walk(body)[:maxn]:
        asc = ''.join(chr(c) if 32 <= c < 127 else '.' for c in v[:40])
        print(f"        {'  '*depth}tag 0x{tid & 0x7f:02x}"
              f"{'P' if tid & 0x80 else ' '} len={size:<4}{'?' if trunc else ' '} "
              f"{v[:36].hex(' '):<74} |{asc}|")


# --- 重新组装 BLK ---
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

print(f"{len(messages)} 条完整 services 消息\n")

hist = collections.Counter()
for i, sp, svc in messages:
    if len(svc) < 20:
        continue
    proto, hs, grp, sid, sess, csz, add = struct.unpack_from('<HHHHIII', svc, 0)
    if proto == 0xCD55:
        hist[(grp, sid)] += 1

print("服务直方图:")
for (grp, sid), n in sorted(hist.items(), key=lambda x: -x[1]):
    print(f"  grp=0x{grp:04x} id=0x{sid:04x}  x{n}")
print()

n = 0
for i, sp, svc in messages:
    if len(svc) < 20:
        continue
    proto, hs, grp, sid, sess, csz, add = struct.unpack_from('<HHHHIII', svc, 0)
    if proto != 0xCD55 or (grp & 0x7f) != 0x0f:
        continue
    body = svc[20:20 + csz]
    d = "IDE->PLC" if sp != 1740 else "PLC->IDE"
    print(f"### pkt#{i} [{d}] grp=0x{grp:04x} svc=0x{sid:04x} "
          f"sess=0x{sess:08x} content={csz}B")
    if body:
        print(f"      {body[:160].hex(' ')}")
        print(f"      ascii: {''.join(chr(c) if 32 <= c < 127 else '.' for c in body[:160])}")
        show_tags(body)
    else:
        print("      (空)")
    print()
    n += 1
    if n >= 40:
        print("... (截断)")
        break
