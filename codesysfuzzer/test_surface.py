#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for the pair recorder and the ``--from-pairs`` loader.  No runtime needed.

These cover rules that are easy to get wrong and invisible when they are:
a file that gets created before there is anything to put in it, a pair repeated
once per run instead of once ever, and a verdict that silently overwrites a
better one.  All three produce a plausible-looking file that is wrong.

Run:
    python codesysfuzzer/test_surface.py
"""

import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from proto import (                                                     # noqa: E402
    build_services, leb128, leb128_pad3, tag,
)
from monitor import SurfaceRecorder, parse_sent                         # noqa: E402
from services import build_request, REQUESTS                            # noqa: E402
from transport import SessionState                                      # noqa: E402

PASS, FAIL = [], []


def check(name, got, want):
    if got == want:
        PASS.append(name)
        print("  ok   %s" % name)
    else:
        FAIL.append(name)
        print("  FAIL %s\n       got  %r\n       want %r" % (name, got, want))


def check_true(name, cond, detail=""):
    if cond:
        PASS.append(name)
        print("  ok   %s" % name)
    else:
        FAIL.append(name)
        print("  FAIL %s %s" % (name, detail))


def state():
    st = SessionState()
    st.channel_id = 1
    st.token = b"\xa4\xe0"
    st.session_id = 0x42
    st.local_ip, st.local_port = "1.2.3.4", 5
    st.remote_ip, st.remote_port = "5.6.7.8", 9
    return st


def sent_frame(group, service):
    """A real rendered request for that pair, to feed the recorder as `sent`."""
    for name, (g, s, _b) in REQUESTS.items():
        if g == group and s == service:
            req = build_request(name, state())
            return req.render()
    req = build_request("generic_sweep", state())
    from utils import _s_update
    _s_update("service_group", group.to_bytes(2, "little"), request=req)
    _s_update("service_id", service.to_bytes(2, "little"), request=req)
    return req.render()


def reply_with_content(group, service):
    """A services reply carrying content but no status tag (a real service)."""
    return build_services(group | 0x80, service, 0x42, tag(0x01, b"data\x00"))


def reply_refused(group, service, status=770):
    # The status tag id 0xFF7F needs LEB128 (it encodes as ff fe 03), and tag()
    # only takes a single-byte id, so build that tag by hand.
    st = leb128(0xFF7F) + leb128_pad3(2) + status.to_bytes(2, "little")
    return build_services(group | 0x80, service, 0x42,
                          tag(0x01, b"\x00") + st)


def test_no_empty_file(tmp):
    print("\n[1] no file until a pair actually replies")
    path = os.path.join(tmp, "never.jsonl")
    rec = SurfaceRecorder(path=path, verbose=False)
    rec.record(1, sent_frame(0x0F, 0x0001), None)          # no reply at all
    check_true("nothing written for a no-reply case", not os.path.exists(path))
    rec.record(2, sent_frame(0x0F, 0x0001), None, complete=False)
    check_true("nothing written for an incomplete case",
               not os.path.exists(path))
    check_true("wrote_file is False", not rec.wrote_file)
    rec.close()
    check_true("still no file after close", not os.path.exists(path))


def test_pair_recorded(tmp):
    print("\n[2] a replying pair is recorded, once, with its verdict")
    path = os.path.join(tmp, "pairs.jsonl")
    rec = SurfaceRecorder(path=path, verbose=False)
    rec.record(1, sent_frame(0x0F, 0x0001), reply_with_content(0x0F, 0x0001))
    check_true("file now exists", os.path.exists(path))
    rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    check("one row", len(rows), 1)
    check("group", rows[0]["group"], "0x000f")
    check("service", rows[0]["service"], "0x0001")
    check("verdict", rows[0]["verdict"], "replied")
    check_true("has first_seen", "first_seen" in rows[0])
    rec.close()


def test_global_dedup(tmp):
    print("\n[3] global mode: a re-run does not repeat a known pair")
    path = os.path.join(tmp, "global.jsonl")
    r1 = SurfaceRecorder(path=path, verbose=False)
    r1.record(1, sent_frame(0x0F, 0x0001), reply_with_content(0x0F, 0x0001))
    r1.close()
    before = len(open(path, encoding="utf-8").read().splitlines())

    r2 = SurfaceRecorder(path=path, verbose=False)          # loads known pairs
    check_true("known pair was loaded", (0x0F, 0x0001) in r2.seen)
    r2.record(1, sent_frame(0x0F, 0x0001), reply_with_content(0x0F, 0x0001))
    r2.record(2, sent_frame(0x0F, 0x0001), reply_with_content(0x0F, 0x0001))
    r2.close()
    after = len(open(path, encoding="utf-8").read().splitlines())
    check("no new rows for a known pair", after, before)

    print("\n[4] global mode: a better verdict for a known pair is appended")
    r3 = SurfaceRecorder(path=path, verbose=False)
    r3.record(1, sent_frame(0x0F, 0x0002), reply_refused(0x0F, 0x0002, 770))
    r3.close()
    n1 = len(open(path, encoding="utf-8").read().splitlines())
    r4 = SurfaceRecorder(path=path, verbose=False)
    r4.record(1, sent_frame(0x0F, 0x0002), reply_with_content(0x0F, 0x0002))
    r4.close()
    n2 = len(open(path, encoding="utf-8").read().splitlines())
    check("improvement appended", n2, n1 + 1)
    # and the loader must resolve it to the better verdict
    from codesys_fuzzer import load_pairs
    pairs = load_pairs(path, only="implemented")
    check_true("loader reports the pair as implemented",
               (0x0F, 0x0002) in pairs, "(%r)" % (pairs,))


def test_separate_mode(tmp):
    print("\n[5] separate mode always records, ignoring prior content")
    path = os.path.join(tmp, "sep.jsonl")
    a = SurfaceRecorder(path=path, verbose=False, mode="separate")
    a.record(1, sent_frame(0x0F, 0x0001), reply_with_content(0x0F, 0x0001))
    a.close()
    b = SurfaceRecorder(path=path, verbose=False, mode="separate")
    check_true("separate mode loads nothing", not b.seen)
    b.record(1, sent_frame(0x0F, 0x0001), reply_with_content(0x0F, 0x0001))
    b.close()
    check("both runs recorded", len(open(path, encoding="utf-8").read().splitlines()), 2)


def test_load_pairs_filters(tmp):
    print("\n[6] load_pairs filters and dedups")
    path = os.path.join(tmp, "filt.jsonl")
    with open(path, "w", encoding="utf-8") as fh:
        for row in (
            {"group": "0x000f", "service": "0x0001", "verdict": "replied"},
            {"group": "0x0009", "service": "0x0003", "verdict": "refused",
             "status": 770},
            {"group": "0x0009", "service": "0x0004", "verdict": "empty"},
            {"group": "0x000c", "service": "0x0008", "verdict": "refused",
             "status": 1},
            {"group": "0x000f", "service": "0x0001", "verdict": "replied"},
        ):
            fh.write(json.dumps(row) + "\n")
    from codesys_fuzzer import load_pairs
    ev = load_pairs(path, only="evidence")
    im = load_pairs(path, only="implemented")
    check("evidence count (deduped)", len(ev), 4)
    check("implemented count", len(im), 1)
    check("implemented is the content pair", im, [(0x0F, 0x0001)])


def test_model_lookup():
    print("\n[7] a pair with a model is fuzzed with it")
    from codesys_fuzzer import model_for_pair
    check("trace_list is modelled (0x0f/0x0001)",
          model_for_pair(0x0F, 0x0001), "trace_list")
    check("derived CmpAppBP 0x39 is modelled",
          model_for_pair(0x12, 0x0039), "appbp_0x39")
    check("an unmodelled pair has none",
          model_for_pair(0x08, 0x0003), None)


def test_parse_sent_roundtrip():
    print("\n[8] the recorder reads the pair off the wire, not from a parameter")
    frame = sent_frame(0x12, 0x0039)
    check("parse_sent recovers (group, service)", parse_sent(frame), (0x12, 0x39))


def main():
    tmp = tempfile.mkdtemp(prefix="surface_test_")
    print("=" * 70)
    print("pair recorder tests (offline)")
    print("=" * 70)
    try:
        test_no_empty_file(tmp)
        test_pair_recorded(tmp)
        test_global_dedup(tmp)
        test_separate_mode(tmp)
        test_load_pairs_filters(tmp)
        test_model_lookup()
        test_parse_sent_roundtrip()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("\n" + "=" * 70)
    print("%d passed, %d failed" % (len(PASS), len(FAIL)))
    for n in FAIL:
        print("  FAILED: %s" % n)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
