#!/usr/bin/env python3
"""
Capture CODESYS loopback traffic to a file so it can be analysed afterwards.

  python sniff_save.py <seconds> [outfile]

Run it, then perform the IDE action you want to inspect (e.g. "Write values",
or re-enable monitoring) while it is capturing.
"""

import sys
import time

import scapy.all as scapy

SECONDS = int(sys.argv[1]) if len(sys.argv) > 1 else 120
OUT = sys.argv[2] if len(sys.argv) > 2 else "varaccess.pcapng"

kept = []


def handle(pkt):
    if not (pkt.haslayer(scapy.UDP) and pkt.haslayer(scapy.IP)):
        return
    u = pkt[scapy.UDP]
    if u.sport in (1740, 1741, 1742, 1743) and u.dport in (1740, 1741, 1742, 1743):
        kept.append(pkt)


print(f"capturing on the Npcap loopback device for {SECONDS}s -> {OUT}", flush=True)
print("perform the IDE action now (e.g. Ctrl+F7 'Write values', or F5 to "
      "re-enable monitoring).", flush=True)

s = scapy.AsyncSniffer(filter="udp", prn=handle, store=False,
                       iface=r"\Device\NPF_Loopback")
s.start()
try:
    time.sleep(SECONDS)
finally:
    s.stop()

scapy.wrpcap(OUT, kept)
print(f"saved {len(kept)} CODESYS datagrams to {OUT}", flush=True)
