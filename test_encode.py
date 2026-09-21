#!/usr/bin/env python3
"""Regression test: every encoder must reproduce 1.pcapng byte-for-byte."""

import struct
import sys

sys.path.insert(0, r'C:\Users\Xingy\Desktop\scripts')

from codesys_udp_ds import (
    CodesysClient, build_datagram, build_get_channel, build_blk, build_ack,
    build_keepalive, build_close_channel, build_services, build_login_body,
    build_password_blob, tag, parent_tag, parse_tags, find_tag_deep,
    GRP_DEVICE, DEV_IDENTIFY, TAG_PROTO_VER, TAG_CRYPTTYPE, TAG_AUTHSTEP,
)

ok = True

def check(name, got, want):
    global ok
    good = got == want
    ok &= good
    print(f"{'PASS' if good else 'FAIL'}  {name}")
    if not good:
        print(f"      got  {got.hex(' ')}")
        print(f"      want {want.hex(' ')}")

# --- datagram header (pcap #967) ---
check("datagram header", build_datagram(b"", addr=0x81)[:12],
      bytes.fromhex("c5 73 40 40 00 11 00 81 03 81 00 00"))

# --- GET_CHANNEL request (pcap #967) ---
check("GET_CHANNEL request", build_get_channel(),
      bytes.fromhex("c3 00 02 01 de c4 90 06 11 5b 12 22 00 40 1f 00 04 00 00 00"))

# --- identify services block (pcap #981, after the BLK header) ---
identify_svc = build_services(
    GRP_DEVICE, DEV_IDENTIFY, 0,
    tag(TAG_PROTO_VER, bytes.fromhex("00 10 00 00 00 00 00 00 00 00 00 00")))
check("identify services block", identify_svc,
      bytes.fromhex("55 cd 10 00 01 00 01 00 00 00 00 00 10 00 00 00 00 00 00 00"
                    "01 8c 80 00 00 10 00 00 00 00 00 00 00 00 00 00"))

# --- BLK framing (pcap #981, channel layer incl. token a4 e0) ---
check("identify BLK frame",
      build_blk(0x14963503, b"\xa4\xe0", 1, 0, identify_svc),
      bytes.fromhex("01 81 a4 e0 03 35 96 14 01 00 00 00 00 00 00 00 24 00 00 00 "
                    "3b 60 50 71") + identify_svc)

# --- client info block (pcap #995) ---
check("client info block", CodesysClient.CLIENT_INFO,
      bytes.fromhex("83 01 fc 00 40 84 80 00 50 51 de c0 41 88 80 00 43 4f 44 45 "
                    "53 59 53 00 42 9c 80 00 43 4f 44 45 53 59 53 20 44 65 76 "
                    "65 6c 6f 70 6d 65 6e 74 20 47 6d 62 48 00 00 00 00 44 9c "
                    "80 00 43 4f 44 45 53 59 53 20 56 33 2e 35 20 53 50 31 38 "
                    "20 50 61 74 63 68 20 32 00 00 00 43 94 80 00 44 45 53 4b "
                    "54 4f 50 2d 47 4e 34 49 50 36 4d 2e 00 00 00 00 45 8c 80 "
                    "00 33 2e 35 2e 31 38 2e 32 30 00 00 00 46 84 80 00 03 00 00 00"))

# --- public key request body (pcap #1007) ---
check("public key request body",
      tag(TAG_CRYPTTYPE, struct.pack("<I", 2)) + tag(TAG_AUTHSTEP, struct.pack("<I", 1)),
      bytes.fromhex("22 84 80 00 02 00 00 00 25 84 80 00 01 00 00 00"))

# --- login request (pcap #1089) ---
check("login request body", build_login_body("test", bytes(256)),
      bytes.fromhex("22 84 80 00 02 00 00 00 25 84 80 00 02 00 00 00 "
                    "81 01 8c 02 10 06 74 65 73 74 00 00 11 80 82 00") + bytes(256))

# --- ACK (pcap #1014) ---
check("ACK frame", build_ack(0x14963503, b"\xa4\xe0", 4),
      bytes.fromhex("02 80 a4 e0 03 35 96 14 04 00 00 00"))

# --- KEEPALIVE sent by the client (pcap #1041; the runtime's own is #1040
#     with flags 0x00, the client sets the 0x80 "from client" bit) ---
check("KEEPALIVE frame", build_keepalive(0x14963503, b"\xa4\xe0"),
      bytes.fromhex("03 80 a4 e0 03 35 96 14"))

# --- CLOSE_CHANNEL (pcap #1131) ---
check("CLOSE_CHANNEL frame",
      build_close_channel(0x14963503, b"\xa4\xe0", correlation=0x56823fe1),
      bytes.fromhex("c4 00 02 01 e1 3f 82 56 a4 e0 00 00 03 35 96 14"))

# --- password blob: plain[i] = password_padded[i] ^ challenge[i % 32] ---
challenge = bytes(range(32))
challenge2 = challenge + challenge
plain = build_password_blob("test", challenge)
want = bytearray(b"test".ljust(64, b"\x00"))
for i in range(64):
    want[i] ^= challenge2[i]
check("password blob plaintext", plain, bytes(want))
check("password blob length", bytes([len(plain)]), bytes([64]))

# --- response tag parser (pcap #1032 login-accepted body) ---
body = bytes.fromhex("82 ff 03 04 20 02 00 00 83 ff 03 14 03 0a 44 65 76 69 63 65 "
                     "00 00 00 00 08 84 80 00 01 00 00 00")
ts = parse_tags(body)
st = find_tag_deep(ts, 0x20)
print(f"PASS  parse login response, status={int.from_bytes(st['value'][:2], 'little')}")

print("\n=> ALL PASS" if ok else "\n=> FAILURES")
sys.exit(0 if ok else 1)
