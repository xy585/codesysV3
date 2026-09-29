#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Byte-exact regression tests for the fuzzer's framing.  No runtime required.

These exist because a fuzzer that sends malformed framing tests nothing: the
runtime drops the packet and every "pass" is meaningless.  The strongest
available check is that the modelled request, *unmutated*, is byte-for-byte the
request the existing capture-verified client sends — so the fuzzer is provably
mutating a real request rather than a plausible-looking guess.

Run:
    python codesysfuzzer/test_framing.py
"""

import os
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from boofuzz.mutation_context import MutationContext                    # noqa: E402

from proto import (                                                     # noqa: E402
    TRACE_CFG_TEMPLATE, build_blk, build_block_frame, build_datagram,
    build_services, leb128_pad3, parse_tags,
)
from services import build_request                                      # noqa: E402
from transport import SessionState                                      # noqa: E402
from transport import count_frames                                     # noqa: E402
from utils import FrameEncoder, LyingLeb128Size, _s_update              # noqa: E402

#: a fixed, plausible connection state so renders are deterministic
CHANNEL_ID = 0x148C1B77
TOKEN = b"\xa4\xe0"
SESSION_ID = 0x00000042
LOCAL_IP, LOCAL_PORT = "192.168.125.10", 51234
REMOTE_IP, REMOTE_PORT = "192.168.125.129", 11740

PASS, FAIL = [], []


def check(name, got, want):
    if got == want:
        PASS.append(name)
        print("  ok   %s" % name)
    else:
        FAIL.append(name)
        print("  FAIL %s" % name)
        print("       got  %s" % _short(got))
        print("       want %s" % _short(want))


def check_true(name, cond, detail=""):
    if cond:
        PASS.append(name)
        print("  ok   %s" % name)
    else:
        FAIL.append(name)
        print("  FAIL %s %s" % (name, detail))


def _short(v, n=96):
    if isinstance(v, (bytes, bytearray)):
        h = bytes(v).hex(" ")
        return "%d bytes: %s%s" % (len(v), h[:n], " ..." if len(h) > n else "")
    return repr(v)


def make_state():
    st = SessionState()
    st.channel_id = CHANNEL_ID
    st.token = TOKEN
    st.session_id = SESSION_ID
    st.tx_blk = 0
    st.rx_blk = 0
    st.local_ip, st.local_port = LOCAL_IP, LOCAL_PORT
    st.remote_ip, st.remote_port = REMOTE_IP, REMOTE_PORT
    return st


def names_ending(request, suffix):
    hits = [n for n in request.names
            if n == suffix or n.endswith("." + suffix)]
    if len(hits) != 1:
        raise AssertionError("expected exactly one %r, found %r" % (suffix, hits))
    return hits[0]


def render_block(request, suffix):
    """Render one named block of a request in isolation."""
    return request.names[names_ending(request, suffix)].render(
        mutation_context=MutationContext())


def _dg(state):
    from utils import datagram_header
    return datagram_header(state)


def _inject(request, state):
    """Refresh the values a live connection would supply.

    Only the session id: the datagram endpoints and both framing lengths are
    stamped in by FrameEncoder, not by boofuzz primitives.
    """
    _s_update("session_id", state.session_id.to_bytes(4, "little"),
              request=request)


# ============================================================
# 1. the modelled TRACE_CONFIGURE body is the captured body
# ============================================================

def test_body_fidelity():
    print("\n[1] trace_configure unmutated body == TRACE_CFG_TEMPLATE")
    state = make_state()
    request = build_request("trace_configure", state)
    body = render_block(request, "body")
    check("body == captured template", body, TRACE_CFG_TEMPLATE)

    # and it is still a well-formed tag stream the runtime would walk
    tags = parse_tags(body)
    check_true("body parses as a tag stream", len(tags) == 8,
               "(got %d top-level tags)" % len(tags))
    container = [t for t in tags if t["id"] == 0x06 and t["children"]]
    check_true("container 0x86 survives as a container", bool(container))


# ============================================================
# 2. the whole rendered frame is what CodesysTcpClient would send
# ============================================================

def test_full_frame():
    print("\n[2] rendered TCP frame == client-built frame")
    state = make_state()
    request = build_request("trace_configure", state)
    _inject(request, state)

    rendered = request.render(mutation_context=MutationContext())

    # what the existing, capture-verified client puts on the wire
    services = build_services(0x0F, 0x02, SESSION_ID, TRACE_CFG_TEMPLATE)
    blk = build_blk(CHANNEL_ID, TOKEN, 1, 0, services, first=True,
                    total=len(services),
                    crc=zlib.crc32(services) & 0xFFFFFFFF)
    dg = build_datagram(blk, LOCAL_PORT, REMOTE_PORT, LOCAL_IP, REMOTE_IP)
    expected = build_block_frame(dg)

    check("full frame", rendered, expected)
    check("block driver length field",
          rendered[:8], build_block_frame(dg)[:8])

    # the services block boofuzz modelled, not the framing around it
    check("services bytes", render_block(request, "services"), services)


# ============================================================
# 3. fragmentation matches send_blk
# ============================================================

def test_fragmentation():
    print("\n[3] FrameEncoder fragments like send_blk")
    state = make_state()
    enc = FrameEncoder(state)

    for total in (10, 468, 469, 944, 1500, 6316):
        state.tx_blk, state.rx_blk = 0, 0
        services = bytes((i * 7 + 3) & 0xFF for i in range(total))
        got = enc(services)

        # the reference: first frame 468, then 476, each with the whole-message
        # size and CRC in the *first* frame only
        crc = zlib.crc32(services) & 0xFFFFFFFF
        want = b""
        off, first, blk_id = 0, True, 1
        while first or off < total:
            room = 468 if first else 476
            chunk = services[off:off + room]
            frame = build_blk(CHANNEL_ID, TOKEN, blk_id, 0, chunk, first=first,
                              total=total, crc=crc)
            # every BLK frame rides its own datagram behind its own BD header
            want += build_block_frame(build_datagram(
                frame, LOCAL_PORT, REMOTE_PORT, LOCAL_IP, REMOTE_IP))
            off += len(chunk)
            blk_id += 1
            first = False
        n_frames = blk_id - 1

        check("frame sequence for %d-byte services" % total, got, want)
        check("  frame count for %d bytes" % total, count_frames(got), n_frames)
        check_true("  the encoder did not advance tx_blk",
                   state.tx_blk == 0, "(got %r)" % (state.tx_blk,))


# ============================================================
# 4. LEB128 size primitives
# ============================================================

def test_leb128():
    print("\n[4] LEB128 size primitives")

    check("leb128_pad3(4)", leb128_pad3(4), bytes.fromhex("84 80 00"))
    check("leb128_pad3(12)", leb128_pad3(12), bytes.fromhex("8c 80 00"))
    check("leb128_pad3(452)", leb128_pad3(452), bytes.fromhex("c4 83 00"))

    # the primitive itself, exercised through a block it sizes
    from boofuzz import blocks, s_block, s_static
    from utils import s_leb_size

    from boofuzz import s_initialize
    s_initialize("leb_probe")
    s_leb_size("payload", name="probe_len")
    with s_block("payload"):
        s_static(b"Z" * 12)
    req = blocks.CURRENT
    rendered = req.render(mutation_context=MutationContext())
    check("Leb128Size renders leb128_pad3(len)",
          rendered, bytes.fromhex("8c 80 00") + b"Z" * 12)

    # the fuzzable variant must re-encode *mutated* ints as LEB128, not as a
    # fixed-width little-endian integer
    lying = LyingLeb128Size(block_name="payload", request=req, name="lying")
    check("LyingLeb128Size.encode(3000)", lying.encode(3000, MutationContext()),
          leb128_pad3(3000))
    check("LyingLeb128Size.encode(4)", lying.encode(4, MutationContext()),
          bytes.fromhex("84 80 00"))
    check_true("LyingLeb128Size is fuzzable", lying.fuzzable)


# ============================================================
# 5. live value injection reaches the render
# ============================================================

def test_injection():
    print("\n[5] live value injection")
    state = make_state()
    request = build_request("trace_configure", state)

    check("session_id is unique",
          _s_update("session_id", SESSION_ID.to_bytes(4, "little"),
                    request=request), 1)
    check("a typo is reported, not ignored",
          _s_update("no_such_field", b"x", request=request), 0)

    # A changed session id must move exactly 8 bytes: the id itself, plus the
    # CRC32 in the first channel frame, which covers the services block the id
    # lives in.  Anything else moving means a size or a counter is drifting.
    before = request.render(mutation_context=MutationContext())
    _s_update("session_id", b"\xde\xad\xbe\xef", request=request)
    after = request.render(mutation_context=MutationContext())
    check_true("session id change alters the frame", before != after)
    check_true("exactly 8 bytes differ (id + the CRC over it)",
               sum(1 for a, b in zip(before, after) if a != b) == 8,
               "(got %d)" % sum(1 for a, b in zip(before, after) if a != b))


def test_render_is_deterministic():
    """Rendering twice must produce identical bytes.

    Regression for a real bug: boofuzz renders a block more than once per test
    case (``bd_length`` resolves its target by rendering ``datagram``, then
    ``datagram`` renders again), so an encoder that advanced ``tx_blk`` emitted a
    different BLK id on the second pass — the packet sent was not the packet the
    sizes and CRC had been computed for.
    """
    print("\n[5b] rendering is deterministic")
    state = make_state()
    request = build_request("trace_configure", state)
    _inject(request, state)

    first = request.render(mutation_context=MutationContext())
    second = request.render(mutation_context=MutationContext())
    third = request.render(mutation_context=MutationContext())
    check("two renders agree", second, first)
    check("three renders agree", third, first)
    check_true("the render did not advance tx_blk", state.tx_blk == 0,
               "(got %r)" % (state.tx_blk,))

    # the block id of the first frame must be tx_blk + 1, not a drifted value
    check("first frame carries blk_id = tx_blk + 1",
          first[8 + 20 + 8:8 + 20 + 12], (1).to_bytes(4, "little"))

    # and send() is what advances it, by the number of frames written
    check("frame count of a single-frame render", count_frames(first), 1)

    state.tx_blk = 0
    big = FrameEncoder(state)(b"Z" * 1500)
    check("frame count of a 1500-byte services block", count_frames(big), 4)


# ============================================================
# 6. every model at least builds and renders
# ============================================================

def test_all_models():
    print("\n[6] every model builds and renders")
    from services import request_names
    for name in request_names():
        state = make_state()
        try:
            request = build_request(name, state)
            _inject(request, state)
            data = request.render(mutation_context=MutationContext())
            ok = len(data) > 32
            n_mut = request.get_num_mutations()
            check_true("%-22s renders %5d bytes, %5d mutations"
                       % (name, len(data), n_mut), ok and n_mut > 0)
        except Exception as e:
            check_true("%-22s builds" % name, False, "%s: %s" % (type(e).__name__, e))


def main():
    print("=" * 70)
    print("CODESYS fuzzer framing tests (offline)")
    print("=" * 70)
    test_body_fidelity()
    test_full_frame()
    test_fragmentation()
    test_leb128()
    test_injection()
    test_render_is_deterministic()
    test_all_models()
    print("\n" + "=" * 70)
    print("%d passed, %d failed" % (len(PASS), len(FAIL)))
    if FAIL:
        for n in FAIL:
            print("  FAILED: %s" % n)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
