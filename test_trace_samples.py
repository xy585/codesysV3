#!/usr/bin/env python3
"""回归测试：用抓包里的真实 tag 0x42 数据验证采样解析。"""

import struct
import sys

sys.path.insert(0, r'C:\Users\Xingy\Desktop\scripts')
import scapy.all as scapy
from codesys_udp_ds import parse_trace_samples

ok = True


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
            return out
        v = d[p:p + size]; p += size
        out.append((tid, v))
        if tid & 0x80:
            walk(v, depth + 1, out)
    return out


def blobs(path):
    pkts = scapy.rdpcap(path)
    for i, p in enumerate(pkts):
        if not (p.haslayer(scapy.UDP) and p.haslayer(scapy.IP) and p.haslayer(scapy.Raw)):
            continue
        u = p[scapy.UDP]
        if u.sport != 1740:
            continue
        d = bytes(p[scapy.Raw])
        if len(d) < 13 or d[0] != 0xC5 or d[3] != 0x40 or d[12] != 0x01:
            continue
        ch = d[12:]
        if not (ch[1] & 0x01):
            continue
        svc = ch[24:]
        if len(svc) < 20:
            continue
        proto, hs, grp, sid, sess, csz, add = struct.unpack_from("<HHHHIII", svc, 0)
        if proto != 0xCD55 or (grp & 0x7f) != 0x0f or sid != 0x0007:
            continue
        body = svc[20:20 + csz]
        for tid, v in walk(body):
            if (tid & 0x7f) == 0x42 and len(v) > 8:
                yield i, v


for path, want_first, want_len in (
        (r'pcapng\trace_save.pcapng', (45081, 33), 10),
        (r'pcapng\trace_delete.pcapng', (54011, 33), 18)):
    checked = 0
    for i, blob in blobs(path):
        s0, s1, samples = parse_trace_samples(blob)
        if not samples:
            continue
        if checked == 0:
            good = samples[0] == want_first and len(samples) == want_len
            ok &= good
            print(f"{'PASS' if good else 'FAIL'}  {path} pkt#{i}: "
                  f"索引 {s0}..{s1}, {len(samples)} 样本, 首个={samples[0]}")
            if not good:
                print(f"      期望首个={want_first} 数量={want_len}")
        # 每个块内部值应严格递增
        vals = [v for _, v in samples]
        mono = all(b > a for a, b in zip(vals, vals[1:]))
        if not mono:
            ok = False
            print(f"FAIL  {path} pkt#{i}: 值非单调递增 {vals[:8]}")
        checked += 1
    print(f"      {path}: 检查了 {checked} 个采样块")

print("\n=> ALL PASS" if ok else "\n=> FAILURES")
sys.exit(0 if ok else 1)
