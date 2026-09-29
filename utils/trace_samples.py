#!/usr/bin/env python3
"""解析带数据的 READ 响应，确定 tag 0x42 的采样格式。"""

import struct
import sys

import scapy.all as scapy

PCAP = sys.argv[1] if len(sys.argv) > 1 else r'pcapng\trace_delete.pcapng'
pkts = scapy.rdpcap(PCAP)


def leb(d, p):
    v = 0; s = 0
    while p < len(d):
        b = d[p]; p += 1; v |= (b & 0x7f) << s
        if not (b & 0x80):
            return v, p
        s += 7
    raise ValueError


def walk(d, depth=0, out=None, top=True):
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
            walk(v, depth + 1, out, False)
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

found = 0
for i, sp, svc in messages:
    if len(svc) < 20 or sp != 1740:      # 1740 = PLC -> IDE，即响应
        continue
    proto, hs, grp, sid, sess, csz, add = struct.unpack_from('<HHHHIII', svc, 0)
    if proto != 0xCD55 or (grp & 0x7f) != 0x0f or sid != 0x0007:
        continue
    body = svc[20:20+csz]
    off = None
    for depth, tid, size, v in walk(body):
        if (tid & 0x7f) == 0x4a and v:
            off = struct.unpack("<I", v[:4])[0]
    datas = [v for d, t, s, v in walk(body) if (t & 0x7f) == 0x42 and s > 0]
    if not datas:
        continue
    print(f"\n=== pkt#{i} offset={off}")
    for blob in datas:
        # u32 起始索引 | N × (u16 时间戳 + u32 值) | u32 结束索引
        start = struct.unpack_from("<I", blob, 0)[0]
        end = struct.unpack_from("<I", blob, len(blob) - 4)[0]
        body = blob[4:len(blob) - 4]
        ok = len(body) % 6 == 0
        samples = [(struct.unpack_from("<H", body, k)[0],
                    struct.unpack_from("<I", body, k + 2)[0])
                   for k in range(0, len(body), 6)]
        vals = [v for _, v in samples]
        mono = sum(1 for a, b in zip(vals, vals[1:]) if b > a)
        print(f"  数据 {len(blob)}B  索引 {start}..{end}  6字节对齐={ok}")
        print(f"  {len(samples)} 个样本  递增 {mono}/{max(1, len(vals)-1)}")
        print(f"    前 8 个 (时间戳,值): {samples[:8]}")
        print(f"    后 2 个: {samples[-2:]}")
    found += 1
    if found >= 4:
        break
