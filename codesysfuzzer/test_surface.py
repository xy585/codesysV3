#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for the pair recorder, the tag seeds, and the run state.  No runtime.

These cover rules that are easy to get wrong and invisible when they are:
a file created before there is anything to put in it, a pair repeated once per
run instead of once ever, a verdict silently overwritten by a worse one, a
resume that starts over, and seeds recorded for a packet that was dropped.  All
of them produce a plausible-looking artefact that is wrong.

Run:
    python codesysfuzzer/test_surface.py
"""

import json
import os
import shutil
import sys
import tempfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from proto import (                                                     # noqa: E402
    build_blk, build_block_frame, build_datagram, build_services, leb128,
    leb128_pad3, parent_tag, tag,
)
from utils import leb128_pad                                          # noqa: E402
from monitor import SurfaceRecorder, body_seed_tags, parse_sent          # noqa: E402
from services import build_request, REQUESTS                             # noqa: E402
from transport import SessionState                                       # noqa: E402

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


def frame_with(group, service, body):
    """A complete sent frame carrying `body` for that pair."""
    services = build_services(group, service, 0x42, body)
    blk = build_blk(1, b"\xa4\xe0", 1, 0, services, first=True,
                    total=len(services),
                    crc=zlib.crc32(services) & 0xFFFFFFFF)
    dg = build_datagram(blk, 5, 9, "1.2.3.4", "5.6.7.8")
    return build_block_frame(dg)


def sent_frame(group, service):
    """A real rendered request for that pair, to feed the recorder as `sent`."""
    for name, (g, s, _b) in REQUESTS.items():
        if g == group and s == service:
            return build_request(name, state()).render()
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


# ============================================================

def test_no_empty_file(tmp):
    print("\n[1] no file until a pair actually replies")
    path = os.path.join(tmp, "never.jsonl")
    rec = SurfaceRecorder(path=path, verbose=False)
    rec.record(1, sent_frame(0x0F, 0x0001), None)
    check_true("nothing written for a no-reply case", not os.path.exists(path))
    rec.record(2, sent_frame(0x0F, 0x0001), None, complete=False)
    check_true("nothing written for an incomplete case", not os.path.exists(path))
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
    check("a consistent pair just counts its cases", rows[0].get("cases"), 1)
    rec.close()

    print("\n[2b] a pair whose cases disagree says so")
    # The row keeps the *best* verdict, so without this a pair that replied once
    # and was refused twenty times would look as healthy as one that always
    # replied — and a reader could not tell.
    path2 = os.path.join(tmp, "mixed.jsonl")
    rec2 = SurfaceRecorder(path=path2, verbose=False)
    rec2.record(1, sent_frame(0x0F, 0x0001), reply_refused(0x0F, 0x0001, 770))
    rec2.record(2, sent_frame(0x0F, 0x0001), reply_refused(0x0F, 0x0001, 770))
    rec2.record(3, sent_frame(0x0F, 0x0001), reply_with_content(0x0F, 0x0001))
    rec2.close()
    rows = [json.loads(l) for l in open(path2, encoding="utf-8") if l.strip()]
    check("best verdict recorded", rows[-1]["verdict"], "replied")
    check("and the disagreement is recorded too",
          rows[-1].get("verdicts"), {"refused": 2, "replied": 1})


def test_global_dedup(tmp):
    print("\n[3] global mode: a re-run does not repeat a known pair")
    path = os.path.join(tmp, "global.jsonl")
    r1 = SurfaceRecorder(path=path, verbose=False)
    r1.record(1, sent_frame(0x0F, 0x0001), reply_with_content(0x0F, 0x0001))
    r1.close()
    before = len(open(path, encoding="utf-8").read().splitlines())

    r2 = SurfaceRecorder(path=path, verbose=False)
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
    check("both runs recorded",
          len(open(path, encoding="utf-8").read().splitlines()), 2)


def test_load_pairs_filters(tmp):
    print("\n[6] load_pairs: 'implemented' means 'not the group's fallback'")
    # Mirrors the real CmpAppBP picture: a group whose fallback is 24, most ids
    # answering exactly that, and one real service answering a *different*
    # status.  Keying on "the reply carried content" would miss it.
    path = os.path.join(tmp, "filt.jsonl")
    rows = (
        {"group": "0x000f", "service": "0x0001", "verdict": "replied"},
        {"group": "0x000f", "service": "0x0001", "verdict": "replied"},
        {"group": "0x0009", "service": "0x0003", "verdict": "refused",
         "status": 770},
        {"group": "0x0009", "service": "0x0004", "verdict": "empty"},
        # group 0x12: fallback is 24, seen on three ids...
        {"group": "0x0012", "service": "0x0001", "verdict": "refused",
         "status": 24},
        {"group": "0x0012", "service": "0x0002", "verdict": "refused",
         "status": 24},
        {"group": "0x0012", "service": "0x0003", "verdict": "refused",
         "status": 24},
        # ...and one id answering something else, which means it exists
        {"group": "0x0012", "service": "0x0015", "verdict": "refused",
         "status": 1304},
    )
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")

    from codesys_fuzzer import group_fallbacks, load_pairs
    check("fallbacks found per group", group_fallbacks(path),
          {"0x0009": 770, "0x0012": 24})
    ev = load_pairs(path, only="evidence")
    im = load_pairs(path, only="implemented")
    check("evidence count (deduped)", len(ev), 7)
    check("implemented excludes the fallback but keeps empty and 1304", im,
          [(0x09, 0x0004), (0x0F, 0x0001), (0x12, 0x0015)])


def test_model_lookup():
    print("\n[7] a pair with a model is fuzzed with it")
    from codesys_fuzzer import model_for_pair
    check("trace_list is modelled (0x0f/0x0001)",
          model_for_pair(0x0F, 0x0001), "trace_list")
    check("derived CmpAppBP 0x39 is modelled",
          model_for_pair(0x12, 0x0039), "appbp_0x39")
    check("an unmodelled pair has none", model_for_pair(0x08, 0x0003), None)


def test_parse_sent_roundtrip():
    print("\n[8] the recorder reads the pair off the wire, not a parameter")
    frame = sent_frame(0x12, 0x0039)
    check("parse_sent recovers (group, service)", parse_sent(frame), (0x12, 0x39))


def test_tag_seeds(tmp):
    print("\n[9] accepted tag ids are recorded and reloaded")
    from codesys_fuzzer import load_pair_tags
    # container 0x81 with children 0x11 and 0x18, plus a top-level tag 0x10
    body = tag(0x10, bytes(4)) + parent_tag(0x81, tag(0x11, bytes(4))
                                            + tag(0x18, bytes(4)))
    got = body_seed_tags(frame_with(0x12, 0x39, body))
    check("the wire structure comes back, container included", got,
          [{"id": 0x10, "children": []},
           {"id": 0x81, "children": [{"id": 0x11, "children": []},
                                     {"id": 0x18, "children": []}]}])

    path = os.path.join(tmp, "seeds.jsonl")
    rec = SurfaceRecorder(path=path, verbose=False)
    rec.record(1, frame_with(0x12, 0x39, body), reply_with_content(0x12, 0x39))
    rec.close()
    rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    check("row carries the tree", rows[0].get("tag_tree"),
          [{"id": "0x10", "children": []},
           {"id": "0x81", "children": [{"id": "0x11", "children": []},
                                       {"id": "0x18", "children": []}]}])
    check("loader returns it", load_pair_tags(path).get((0x12, 0x39)), got)

    path2 = os.path.join(tmp, "drop.jsonl")
    rec2 = SurfaceRecorder(path=path2, verbose=False)
    rec2.record(1, frame_with(0x12, 0x39, body), None)
    rec2.close()
    check_true("no file, so no seeds, for a dropped packet",
               not os.path.exists(path2))

    print("\n[9b] the richest tree wins when a pair appears in several rows")
    path3 = os.path.join(tmp, "merge.jsonl")
    small = [{"id": "0x11", "children": []}]
    big = [{"id": "0x81", "children": [{"id": "0x11", "children": []},
                                       {"id": "0x18", "children": []}]}]
    with open(path3, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"group": "0x12", "service": "0x39",
                             "verdict": "replied", "tag_tree": big}) + "\n")
        fh.write(json.dumps({"group": "0x12", "service": "0x39",
                             "verdict": "replied", "tag_tree": small}) + "\n")
    check("the richer tree is kept, not the last row",
          load_pair_tags(path3).get((0x12, 0x39)), _unhex(big))


def test_legacy_rows(tmp):
    print("\n[9c] a row in the old flat format is still read")
    from codesys_fuzzer import load_pair_tags
    path = os.path.join(tmp, "legacy.jsonl")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"group": "0x12", "service": "0x39",
                             "verdict": "replied",
                             "tags": ["0x11", "0x18"]}) + "\n")
    check("flat tags become leaves",
          load_pair_tags(path).get((0x12, 0x39)),
          [{"id": 0x11, "children": []}, {"id": 0x18, "children": []}])


def test_run_state(tmp):
    print("\n[10] run state records progress")
    from runstate import RunState
    path = os.path.join(tmp, "run.state.json")
    st = RunState(path=path, request="trace_list", seed=4242, index_end=500,
                  depth1_cases=620)
    check_true("nothing written before save", not os.path.exists(path))
    st.last_case, st.cases_run = 87, 87
    st.save()
    check_true("file written", os.path.exists(path))

    back = RunState.load(path)
    check("request round-trips", back.request, "trace_list")
    check("seed round-trips", back.seed, 4242)
    check("depth-1 case count round-trips", back.depth1_cases, 620)
    check("resume index is the next case", back.resume_index(), 88)

    print("\n[11] resuming with a different model is refused")
    check_true("same model does not conflict",
               back.conflicts_with("trace_list", None, None, None) is None)
    clash = back.conflicts_with("trace_configure", None, None, None)
    check_true("different model conflicts", clash is not None, "(%r)" % (clash,))

    print("\n[12] a finished run reports no resume point")
    back.last_case = 500
    check("resume_index None when complete", back.resume_index(), None)

    print("\n[13] saving replaces rather than truncates in place")
    st.save()
    check("still valid after a second save",
          RunState.load(path).last_case, 87)

    print("\n[13b] the per-seed budget and order are part of an index")
    st2 = RunState(path=path, request="seed_0f_0002", mode="seed",
                   mutations_per_seed=100000, mutation_mode="structured",
                   seed_order="round-robin")
    st2.save()
    back2 = RunState.load(path)
    check("budget round-trips", back2.mutations_per_seed, 100000)
    check("mode round-trips", back2.mutation_mode, "structured")
    check("order round-trips", back2.seed_order, "round-robin")


def _unhex(nodes):
    """The hex-encoded tree as ints, for comparison with the loader's output."""
    return [{"id": int(n["id"], 16),
             "children": _unhex(n.get("children"))} for n in nodes]


def test_seeded_body():
    print("\n[14] a pair's recorded structure drives its body")
    from services import build_request as br
    tree = [{"id": 0x10, "children": []},
            {"id": 0x81, "children": [{"id": 0x11, "children": []},
                                      {"id": 0x18, "children": []}]}]
    req = br("generic_sweep", state(), group=0x12, service=0x39,
             seed_tags=tree)
    body = req.names[[k for k in req.names if k.endswith(".body")][0]].render()
    # A leaf stays a leaf, and 0x81 must come back as a *container* holding the
    # two children — not as a leaf whose id happens to be 0x81.  The container
    # length is written 2 bytes wide (90 00 for 16), which is what the captured
    # CmpTraceMgr template uses; a 1-byte minimal encoding parses identically, so
    # this is a convention, not a requirement.
    kids = (bytes([0x11]) + leb128_pad3(4) + bytes(4)
            + bytes([0x18]) + leb128_pad3(4) + bytes(4))
    check("container rebuilt as a container", body,
          bytes([0x10]) + leb128_pad3(4) + bytes(4)
          + leb128(0x81) + leb128_pad(16, 2) + kids)
    check_true("and it is fuzzable", req.get_num_mutations() > 0,
               "(%d)" % req.get_num_mutations())


def test_crash_report(tmp):
    print("\n[15] a crash lands a reproducible report on disk")
    from monitor import CodesysMonitor
    # a request with a container and two tags, like the real trigger shapes
    body = (tag(0x10, bytes(12)) + parent_tag(0x86, tag(0x30, b"A" * 64)))
    frame = frame_with(0x0F, 0x0002, body)

    crash_dir = os.path.join(tmp, "crashes")
    os.makedirs(crash_dir, exist_ok=True)
    mon = CodesysMonitor(connection=None, enabled=False, crash_dir=crash_dir,
                         request_name="trace_configure", target="10.0.0.5",
                         seed=4242, db_path="logs/x.db")
    check_true("nothing written before a crash", not os.listdir(crash_dir))
    mon.crash = {"case": 417, "cases_run": 417, "when": "2026-09-30T01:02:03",
                 "reason": "ConnectionRefusedError: refused"}
    mon._last_send = frame
    base = mon._write_crash_files()
    check_true("a report was written", base is not None)
    txt, js = base + ".txt", base + ".json"
    check_true("txt exists", os.path.exists(txt))
    check_true("json exists", os.path.exists(js))

    text = open(txt, encoding="utf-8").read()
    check_true("txt names the exact repro command",
               "--case 417 --seed 4242" in text, "(%r)" % text[:200])
    check_true("txt warns the seed is required", "seed is required" in text)
    check_true("txt warns against --resume", "--resume" in text)
    check_true("txt says the db truncates", "truncates this at 512 bytes" in text)
    check_true("txt shows the container", "0x86" in text)
    check_true("txt shows the child tag", "0x30" in text)

    data = json.load(open(js, encoding="utf-8"))
    check("json carries the raw bytes", data["sent_hex"], frame.hex())
    check("json carries the case", data["case"], 417)
    check("json carries the seed", data["seed"], 4242)
    check_true("json carries the command",
               "--case 417" in data["reproduce_command"])
    st = data["structured"]
    check("structured group", st["group"], 0x0F)
    check("structured service", st["service"], 0x0002)
    # 0x86, not 0x06: the report shows the id as it goes on the wire
    check("structured top-level tags", [n["id"] for n in st["body"]],
          [0x10, 0x86])
    cont = st["body"][1]
    check_true("container flagged as one", bool(cont["children"]))
    check("container child", [n["id"] for n in cont["children"]], [0x30])
    check("child holds the 64 bytes", cont["children"][0]["value_len"], 64)
    check("and they are the filler", cont["children"][0]["value_hex"], ("41" * 64))

    print("\n[16] no crash dir means no files, and no crash means no files")
    mon2 = CodesysMonitor(connection=None, enabled=False, crash_dir=None)
    mon2.crash = {"case": 1}
    mon2._last_send = frame
    check_true("no dir -> nothing written", mon2._write_crash_files() is None)


def test_block_recorder(tmp):
    print("\n[17] a requested block is recorded per test case")
    from boofuzz.fuzzable import Mutation
    from boofuzz.mutation_context import MutationContext
    from fuzzer import BlockRecorder

    req = build_request("trace_configure", state())
    path = os.path.join(tmp, "blocks.jsonl")
    rec = BlockRecorder(req, "trace_configure", ["body", "t13"], path, seed=7)
    name = "trace_configure.frames.services.body.t13.t13_data"
    ctx = MutationContext(mutations={
        name: Mutation(value=b"\xaa" * 8, qualified_name=name, index=0)})
    rec.record(ctx, 101)

    with open(path, encoding="utf-8") as fh:
        row = json.loads(fh.readline())
    check("case index recorded", row["case"], 101)
    check("seed recorded", row["seed"], 7)
    check("the mutated element is named", row["mutations"], [name])
    body = "trace_configure.frames.services.body"
    check("both requested blocks recorded", sorted(row["blocks"]),
          [body, body + ".t13"])
    t13 = row["blocks"][body + ".t13"]
    # The named block is the *value* block; tag id and LEB128 length are
    # siblings in `body`, so recording `body` is how you get a whole tag.
    check("t13 is its value block, not id+length+value", t13["length"], 8)
    check("t13 carries the mutated bytes", t13["hex"], "aa" * 8)

    print("\n[18] an unknown block name is refused, not guessed")
    try:
        BlockRecorder(req, "trace_configure", ["no_such_block"], path)
        ok, detail = False, "no exception"
    except KeyError as e:
        ok, detail = "no_such_block" in str(e), str(e)
    check_true("unknown name is an error", ok, detail)

    try:
        BlockRecorder(req, "trace_configure", ["trace_configure"], path)
        ok, detail = False, "no exception"
    except KeyError as e:
        ok, detail = "request itself" in str(e), str(e)
    check_true("recording the request itself is refused", ok, detail)


def test_final_probe(tmp):
    print("\n[19] a crash in the last cases is caught by the end-of-run probe")
    from monitor import CodesysMonitor

    body = (tag(0x10, bytes(12)) + parent_tag(0x86, tag(0x30, b"A" * 64)))
    frame = frame_with(0x0F, 0x0002, body)

    class Link(object):
        """``probe()`` only — the monitor needs nothing else here.

        ``fail_after`` is the number of probes that still answer; it models the
        real crash, where the listener stays up for a few seconds after the
        request that kills the process and then goes away.  Timing-based tests
        would be flaky, so this is driven by call count instead of the clock.
        """
        broken = False
        break_reason = None
        info = "10.0.0.5:11740"

        def __init__(self, alive=True, fail_after=None):
            self.alive = alive
            self.fail_after = fail_after
            self.probes = 0

        def probe(self, timeout=2.0):
            self.probes += 1
            alive = self.alive and (self.fail_after is None
                                    or self.probes <= self.fail_after)
            return alive, ("" if alive else "ConnectionRefusedError: refused")

    crash_dir = os.path.join(tmp, "final")
    os.makedirs(crash_dir, exist_ok=True)

    # 2 cases over probe_every=50: post_send never probes on a cadence here,
    # which is exactly the window a one-case reproduction lives in.
    dead = Link(False)
    mon = CodesysMonitor(dead, enabled=True, probe_every=50,
                         crash_dir=crash_dir, request_name="trace_configure",
                         target="10.0.0.5", seed=4242)
    mon.cases = 2
    mon._last_case_index = 297
    mon._last_send = frame
    check("a dead runtime is found", mon.check_liveness(grace=0), False)
    check("and the probe ran", dead.probes, 1)  # the first probe already failed
    check_true("crash recorded", mon.crash is not None)
    check("crash names the last case", mon.crash["case"], 297)
    check_true("crash report written", bool(mon.crash.get("files")))
    txt = open(mon.crash["files"] + ".txt", encoding="utf-8").read()
    check_true("repro command can run past the state guard",
               "--force-new" in txt)
    check("a second call does not double-probe", mon.check_liveness(grace=0),
          True)

    # the measured shape: alive at the end of the run, gone a few seconds on
    delayed = Link(fail_after=2)
    mon2 = CodesysMonitor(delayed, enabled=True, probe_every=50,
                          crash_dir=crash_dir, request_name="trace_configure",
                          target="10.0.0.5", seed=4242)
    mon2.cases = 1
    mon2._last_case_index = 296
    mon2._last_send = frame
    check("a delayed death is found",
          mon2.check_liveness(grace=10, interval=0), False)
    check("it took three polls", delayed.probes, 3)
    check_true("and is reported as the final probe",
               "final probe" in mon2.crash["reason"])

    live = Link()
    mon3 = CodesysMonitor(live, enabled=True, probe_every=50,
                          crash_dir=crash_dir, request_name="trace_configure",
                          target="10.0.0.5", seed=4242)
    mon3.cases = 2
    mon3._last_case_index = 297
    mon3._last_send = frame
    check("a live runtime is not a crash", mon3.check_liveness(grace=0), True)
    check_true("no crash recorded", mon3.crash is None)
    check("the window was probed", live.probes, 1)

    off = Link(False)
    mon4 = CodesysMonitor(off, enabled=False, crash_dir=crash_dir,
                          request_name="trace_configure", target="10.0.0.5",
                          seed=4242)
    mon4.cases = 2
    check("--no-probe means no probe", mon4.check_liveness(grace=0), True)
    check("and nothing was probed", off.probes, 0)

    none = Link(False)
    mon5 = CodesysMonitor(none, enabled=True, crash_dir=crash_dir,
                          request_name="trace_configure", target="10.0.0.5",
                          seed=4242)
    check("no case ran, nothing to attribute", mon5.check_liveness(grace=0),
          True)
    check("and nothing was probed", none.probes, 0)


def test_stale_send_attribution(tmp):
    print("\n[20] a failed send is not attributed to the case index that failed")
    from monitor import CodesysMonitor

    body_a = tag(0x10, b"A" * 12)
    body_b = tag(0x10, b"B" * 12)
    frame_a = frame_with(0x0F, 0x0002, body_a)
    frame_b = frame_with(0x0F, 0x0002, body_b)

    class Conn(object):
        broken = False
        break_reason = None
        info = "10.0.0.5:11740"
        last_case = None

        def __init__(self):
            self.n = 0

        def service_reply(self, timeout=2.0):
            return None, True

        def probe(self, timeout=2.0):
            self.n += 1
            # healthy on the first case, gone on the second
            return (self.n == 1), ("" if self.n == 1 else "refused")

    class Sess(object):
        def __init__(self, index, sent):
            self.total_mutant_index = index
            self.last_send = sent

    conn = Conn()
    crash_dir = os.path.join(tmp, "stale")
    os.makedirs(crash_dir, exist_ok=True)
    mon = CodesysMonitor(conn, enabled=True, probe_every=1,
                         crash_dir=crash_dir,
                         request_name="seed_0f_0002", target="10.0.0.5",
                         seed=7)
    # case 1 sends frame A
    check("case 1 is healthy", mon.post_send(session=Sess(1, frame_a)), True)
    check("case 1 recorded", mon._last_case_index, 1)
    check("its bytes recorded", mon._last_send is frame_a, True)

    # case 2's send failed: boofuzz still reports frame A as last_send
    check("case 2 detected the crash",
          mon.post_send(session=Sess(2, frame_a)), False)
    check("attributed to the last case that really went out",
          mon.crash["case"], 1)
    check("with that case's bytes", mon._last_send is frame_a, True)
    check("and not case 2's index", mon.crash["case"] != 2, True)

    data = json.load(open(mon.crash["files"] + ".json", encoding="utf-8"))
    check("the report carries the sent body", data["body_hex"],
          body_a.hex())
    check("and the plan is for the same case", data["case"], 1)
    check("the trail has the packet that went out", len(data.get("recent") or []), 1)
    check("the trail names its case", data["recent"][0]["case"], 1)
    check("the trail carries its body", data["recent"][0]["body_hex"],
          body_a.hex())

    # a real new send does advance the attribution
    stale2 = os.path.join(tmp, "stale2")
    os.makedirs(stale2, exist_ok=True)
    mon2 = CodesysMonitor(Conn(), enabled=True, probe_every=1,
                          crash_dir=stale2,
                          request_name="seed_0f_0002", target="10.0.0.5",
                          seed=7)
    mon2.post_send(session=Sess(1, frame_a))
    mon2.post_send(session=Sess(2, frame_b))
    check("a successful send advances the index", mon2._last_case_index, 2)
    check("and the bytes", mon2._last_send is frame_b, True)


def test_seed_prefix_report(tmp):
    print("\n[21] a seed report embeds what is needed to replay the prefix")
    from corpus import Corpus, Seed, write_seed
    from monitor import CodesysMonitor
    from utils import SeedBody

    body = (tag(0x10, b"App.Trace\x00\x00\x00")
            + parent_tag(0x86, tag(0x30, b"\x0a\x00\x00\x00")))
    run_seed = 1234
    sb = SeedBody([Seed(0x0F, 0x0002, body)], run_seed, mode="structured",
                  mutations_per_seed=64, max_body_size=65536)
    frame = frame_with(0x0F, 0x0002, body)

    crash_dir = os.path.join(tmp, "seedrun")
    os.makedirs(crash_dir, exist_ok=True)
    mon = CodesysMonitor(None, enabled=True, crash_dir=crash_dir,
                         request_name="seed_0f_0002", target="10.0.0.5",
                         seed=run_seed, seed_body=sb)
    mon.cases = 7
    mon._last_case_index = 7
    mon._last_send = frame
    mon.crash = {"case": 7, "cases_run": 7, "when": "x", "reason": "probe",
                 "send_len": len(frame)}
    base = mon._write_crash_files()
    data = json.load(open(base + ".json", encoding="utf-8"))
    sr = data.get("seed_run")
    check_true("seed_run present", isinstance(sr, dict))
    check("cases to replay", sr["cases"], 7)
    check("segment start recorded", sr.get("start"), 1)
    check("run seed kept", sr["run_seed"], run_seed)
    check("mutation mode kept", sr["mode"], "structured")
    check("per-seed budget kept", sr["mutations_per_seed"], 64)
    check("corpus size", len(sr["seeds"]), 1)
    check("corpus body kept", bytes.fromhex(sr["seeds"][0]["body"]), body)
    txt = open(base + ".txt", encoding="utf-8").read()
    check_true("report offers the prefix fallback", "--replay-prefix" in txt)
    check_true("report keeps the single body as the default",
               "sends the last body" in txt)

    # Rebuilding from the report's own data must regenerate the same packets
    # for every case in the prefix; that is the whole point of the embedding.
    rebuilt_dir = os.path.join(tmp, "rebuilt")
    for row in sr["seeds"]:
        write_seed(rebuilt_dir, int(row["group"], 16),
                   int(row["service"], 16), bytes.fromhex(row["body"]))
    rebuilt = Corpus.load(rebuilt_dir)
    sb2 = SeedBody(list(rebuilt.by_pair()[(0x0F, 0x0002)]),
                   sr["run_seed"], mode=sr["mode"],
                   mutations_per_seed=sr["mutations_per_seed"],
                   max_body_size=sr["max_body_size"], order=sr["order"])
    same = all(sb._mutate(sb.seeds[0], i)[0] == sb2._mutate(sb2.seeds[0], i)[0]
               for i in range(1, 8))
    check_true("the replay regenerates the same bodies", same)


def test_case_report(tmp):
    print("\n[22] a confirmed case can be written out like a crash report")
    import types
    from codesys_fuzzer import write_case_report
    from corpus import Seed
    from utils import SeedBody

    body = (tag(0x10, b"App.Trace\x00\x00\x00")
            + parent_tag(0x86, parent_tag(0x83,
                                         tag(0x26, b"A" * 32))))
    run_seed = 1234
    sb = SeedBody([Seed(0x0F, 0x0002, body)], run_seed, mode="structured",
                  mutations_per_seed=64, max_body_size=65536)
    plan = sb.plan_for_case(7)
    frame = frame_with(0x0F, 0x0002, body)
    report = {
        "request": "seed_0f_0002", "case": 7, "cases_run": 7,
        "group": "0x000f", "service": "0x0002", "seed": run_seed,
        "database": "logs/x.db", "body_hex": body.hex(),
        "sent_hex": frame.hex(), "seed_plan": plan,
        "seed_run": {
            "run_seed": run_seed, "mode": "structured",
            "mutations_per_seed": 64, "max_body_size": 65536,
            "order": "contiguous", "start": 1, "cases": 7,
            "seeds": [{"group": "0x000f", "service": "0x0002",
                       "body": body.hex()}],
        },
        "recent": [{"case": 7, "group": "0x000f", "service": "0x0002",
                    "body_hex": body.hex(), "sent_hex": frame.hex(),
                    "seed_plan": plan}],
    }
    rep_path = os.path.join(tmp, "case_report.json")
    with open(rep_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh)

    args = types.SimpleNamespace(replay=rep_path, case_report=7,
                                 case_report_out=None, target="10.0.0.5")
    check("case report written", write_case_report(args, report), 0)
    default = os.path.splitext(rep_path)[0] + "_case_7.txt"
    check_true("default path sits next to the report", os.path.exists(default))
    text = open(default, encoding="utf-8").read()
    check_true("names the case", "case         : 7" in text)
    check_true("has the structured request section",
               "Structured request" in text)
    check_true("shows the container", "0x86" in text)
    check_true("shows the grown tag", "0x26" in text)
    check_true("has the mutation plan", "value_grow" in text or "Seed mutation" in text)
    check_true("has the raw body section",
               "Raw bytes (services body" in text)
    check_true("has the recorded frame",
               "block driver + datagram" in text
               and " ".join("%02x" % b for b in frame[:8]) in text)

    # a case outside the recent trail is rebuilt from the embedded corpus
    args2 = types.SimpleNamespace(replay=rep_path, case_report=5,
                                  case_report_out=os.path.join(tmp, "c5.txt"),
                                  target="10.0.0.5")
    check("rebuilt case report written", write_case_report(args2, report), 0)
    text2 = open(args2.case_report_out, encoding="utf-8").read()
    check_true("says it was rebuilt", "embedded seed corpus" in text2)
    check_true("rebuilt body is rendered", "Structured request" in text2)
    check_true("no frame is invented", "not recorded for this case" in text2)

    # a case outside both sources and with no corpus cannot be produced
    bare = dict(report)
    bare.pop("seed_run")
    bare.pop("recent")
    args3 = types.SimpleNamespace(replay=rep_path, case_report=5,
                                  case_report_out=os.path.join(tmp, "c6.txt"),
                                  target="10.0.0.5")
    check("unknown case is refused", write_case_report(args3, bare), 2)


def main():
    tmp = tempfile.mkdtemp(prefix="surface_test_")
    print("=" * 70)
    print("pair recorder / seed / run-state tests (offline)")
    print("=" * 70)
    try:
        test_no_empty_file(tmp)
        test_pair_recorded(tmp)
        test_global_dedup(tmp)
        test_separate_mode(tmp)
        test_load_pairs_filters(tmp)
        test_model_lookup()
        test_parse_sent_roundtrip()
        test_tag_seeds(tmp)
        test_legacy_rows(tmp)
        test_run_state(tmp)
        test_seeded_body()
        test_block_recorder(tmp)
        test_crash_report(tmp)
        test_final_probe(tmp)
        test_stale_send_attribution(tmp)
        test_seed_prefix_report(tmp)
        test_case_report(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("\n" + "=" * 70)
    print("%d passed, %d failed" % (len(PASS), len(FAIL)))
    for n in FAIL:
        print("  FAILED: %s" % n)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
