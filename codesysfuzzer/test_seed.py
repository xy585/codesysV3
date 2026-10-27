#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Offline tests for seed-mode fuzzing: corpus, mutator, SeedBody, run state.

No runtime and no sockets.  What is covered is the machinery that would fail
silently:

* the strict tag parser must round-trip the captured template byte-for-byte;
* a case must be a pure function of (run seed, seed sha1, case index), or
  ``--case``/``--resume`` are lying;
* the case index -> (seed, local mutation) mapping must be the same one boofuzz
  enumerates, or the crash report names the wrong seed;
* the body rendered into a request must be the mutated bytes, with
  ``content_size`` tracking them;
* a resumed run must refuse a changed corpus.

Run:
    python codesysfuzzer/test_seed.py
"""

import json
import os
import shutil
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from boofuzz.mutation_context import MutationContext                  # noqa: E402

from corpus import Corpus, Seed, write_seed                           # noqa: E402
from monitor import parse_sent_parts                                  # noqa: E402
from mutator import (                                                 # noqa: E402
    case_seed, encode_wire_tags, mutate_seed, parse_seed,
    parse_wire_tags, tag_targets,
)
from proto import TRACE_CFG_TEMPLATE, leb128_pad3, read_leb128      # noqa: E402
from runstate import RunState                                         # noqa: E402
from services import build_seed_request, build_static_request        # noqa: E402
from transport import SessionState                                    # noqa: E402
from utils import SeedBody                                            # noqa: E402

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


def session_state():
    st = SessionState()
    st.channel_id = 1
    st.token = b"\xa4\xe0"
    st.session_id = 0x42
    st.local_ip, st.local_port = "1.2.3.4", 5
    st.remote_ip, st.remote_port = "5.6.7.8", 9
    return st


# ============================================================
def test_corpus():
    print("[1] corpus: identity, dedupe, ordering")
    a = Seed(0x0F, 0x0002, TRACE_CFG_TEMPLATE, source="pcap#1")
    a_again = Seed(0x0F, 0x0002, TRACE_CFG_TEMPLATE)
    other_pair = Seed(0x0F, 0x0001, TRACE_CFG_TEMPLATE)

    check("same pair+body -> same sha1", a.sha1, a_again.sha1)
    check_true("different pair -> different sha1", a.sha1 != other_pair.sha1)

    tmp = tempfile.mkdtemp(prefix="seeds-")
    try:
        first = write_seed(tmp, a.group, a.service, a.body, source="one")
        second = write_seed(tmp, a.group, a.service, a.body, source="two")
        check_true("first write creates a file", first is not None)
        check_true("identical seed is deduped", second is None)
        write_seed(tmp, 0x0F, 0x0001, b"\x10\x84\x80\x00\x00\x00\x00\x00")

        corpus = Corpus.load(tmp)
        check("two distinct seeds loaded", len(corpus), 2)
        check("ordered by pair", corpus.pairs(), [(0x0F, 0x0001),
                                                  (0x0F, 0x0002)])
        check("by_pair splits them", sorted(len(v) for v in
                                            corpus.by_pair().values()), [1, 1])
        first_digest = corpus.digest()

        write_seed(tmp, 0x0F, 0x0002, b"\x11\x84\x80\x00\x00\x00\x00\x00")
        check_true("adding a seed changes the digest",
                   Corpus.load(tmp).digest() != first_digest)

        manifest = corpus.manifest()
        check_true("manifest is one line per seed",
                   len(manifest) == 2 and all(":" in line
                                              for line in manifest))

        # --capture-seeds writes here.  It is deliberately outside the active
        # corpus: folding it in would change the digest between a run and its
        # resume.
        cand = os.path.join(tmp, "candidates")
        write_seed(cand, 0x0F, 0x0002,
                   b"\x10\x84\x80\x00\x00\x00\x00\x00", source="candidate")
        check("candidates/ is not part of the active corpus",
              len(Corpus.load(tmp)), 3)     # the three top-level seeds above
        check("candidates/ can be imported explicitly",
              len(Corpus.load(cand)), 1)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_corpus_jsonl_and_bin():
    print("[2] corpus: JSONL and raw .bin input")
    tmp = tempfile.mkdtemp(prefix="seeds-")
    try:
        jsonl = os.path.join(tmp, "x.jsonl")
        with open(jsonl, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"group": "0x0f", "service": "0x0002",
                                 "body": TRACE_CFG_TEMPLATE.hex()}) + "\n")
            fh.write(json.dumps({"group": "0x0f", "service": "0x0001",
                                 "body": "10 84 80 00 00 00 00 00"}) + "\n")
        corpus = Corpus.load(jsonl)
        check("JSONL rows loaded", len(corpus), 2)

        bindir = os.path.join(tmp, "bin")
        os.makedirs(bindir)
        with open(os.path.join(bindir, "0f_0002_raw.bin"), "wb") as fh:
            fh.write(TRACE_CFG_TEMPLATE)
        corpus = Corpus.load(bindir)
        check("filename gives group/service", corpus.seeds[0].pair,
              (0x0F, 0x0002))
        check("raw bytes kept verbatim", corpus.seeds[0].body,
              TRACE_CFG_TEMPLATE)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_tag_codec():
    print("[3] tag codec: strict parse and byte-exact re-encode")
    tree = parse_wire_tags(TRACE_CFG_TEMPLATE)
    check("captured body round-trips", encode_wire_tags(tree),
          TRACE_CFG_TEMPLATE)
    check_true("containers preserved", any(n["children"] is not None
                                           for _p, n in _walk(tree)))
    check("garbage is not a tag stream", parse_seed(b"\xff\xff"), None)
    try:
        parse_wire_tags(b"\x10\x84\x80")
        check("truncated tag rejected", "accepted", "rejected")
    except ValueError:
        check("truncated tag rejected", "rejected", "rejected")


def _walk(nodes, prefix=()):
    for i, node in enumerate(nodes):
        path = prefix + (i,)
        yield path, node
        if node["children"] is not None:
            yield from _walk(node["children"], path)


def test_mutator():
    print("[4] mutator: determinism, stages, bounds")
    seed = Seed(0x0F, 0x0002, TRACE_CFG_TEMPLATE)
    a, plan_a = mutate_seed(seed, 7, 4242, mode="hybrid", budget=64)
    b, plan_b = mutate_seed(seed, 7, 4242, mode="hybrid", budget=64)
    check("same input -> same body", a, b)
    check("same input -> same plan", plan_a, plan_b)
    c, _ = mutate_seed(seed, 8, 4242, mode="hybrid", budget=64)
    check_true("different case -> different body", a != c)
    # cases 1..42 are the deterministic byte/tag sweep and deliberately do not
    # depend on the run seed; havoc starts after them.
    e, _ = mutate_seed(seed, 43, 4242, mode="hybrid", budget=64)
    f, _ = mutate_seed(seed, 43, 4243, mode="hybrid", budget=64)
    check_true("different run seed -> different havoc", e != f)

    check("case_seed is stable", case_seed(1, "ab", 2), case_seed(1, "ab", 2))

    # structured case 1 is the first tag target: node [0] keeps its value and
    # gets a different id, so the length is unchanged and byte 0 changes.
    body, plan = mutate_seed(seed, 1, 4242, mode="structured", budget=256)
    check("first structured case is a tag target", plan["stage"], "tag")
    check("its kind", plan["ops"][0]["kind"], "tag_id")
    check("body length unchanged by an id swap", len(body), len(seed.body))
    check_true("the tag id byte changed", body[0] != seed.body[0])

    # find the first length-lie target and check the declared length on the wire
    targets = tag_targets(parse_wire_tags(TRACE_CFG_TEMPLATE))
    lie_index = next(i for i, t in enumerate(targets) if t["kind"] == "len_lie")
    lie = targets[lie_index]
    body, plan = mutate_seed(seed, lie_index + 1, 4242, mode="structured",
                             budget=256)
    node_path = lie["path"]
    check("length-lie plan names the path", plan["ops"][0]["path"],
          list(node_path))
    declared, _ = read_leb128(body, 1)          # id at 0, length at 1
    check("declared length is the lie", declared, lie["value"])
    check_true("declared length no longer matches the value", declared != 12)

    raw, plan = mutate_seed(seed, 1, 4242, mode="raw", budget=16,
                            max_body_size=64)
    check("byte stage caps the body", len(raw), 64)
    check("byte stage plan", plan["stage"], "byte")

    # a body that is not a tag stream must fall back, not disappear
    junk = Seed(0x0F, 0x0002, b"\xff\xff\xff\xff")
    out, plan = mutate_seed(junk, 5, 1, mode="structured", budget=16)
    check_true("unparseable seed falls back to raw", len(out) > 0,
               repr(out))

    peers = [Seed(0x0F, 0x0002, TRACE_CFG_TEMPLATE[:64]).body]
    out, plan = mutate_seed(seed, 99, 4242, mode="raw", budget=16,
                            max_body_size=65536, peer_bodies=peers)
    check("havoc stays within the ceiling", len(out) <= 65536, True)


def test_seed_body():
    print("[5] SeedBody: budget, ordering, rendering")
    s1 = Seed(0x0F, 0x0002, TRACE_CFG_TEMPLATE)
    s2 = Seed(0x0F, 0x0002, TRACE_CFG_TEMPLATE[:-8] + b"\x26\x84\x80\x00"
              b"\x02\x00\x00\x00")
    body = SeedBody([s1, s2], 99, mode="structured", mutations_per_seed=5,
                    order="contiguous")
    check("num_mutations is seeds * budget", body.num_mutations(), 10)

    req = build_seed_request("seed_body_test", session_state(), 0x0F, 0x0002,
                             body)
    check("request sees the same mutation count", req.get_num_mutations(), 10)

    # unmutated render must still carry the first seed's body
    frame = req.render(mutation_context=MutationContext())
    group, service, rendered = parse_sent_parts(frame)
    check("unmutated render is the first seed", rendered, s1.body)
    check("content_size tracks the body",
          struct.unpack_from("<I", frame, 8 + 20 + 24 + 12)[0], len(rendered))

    mutations = list(body.get_mutations())
    check("generator yields the budget", len(mutations), 10)
    for index, mutation in enumerate(mutations, 1):
        ctx = MutationContext(mutations={m.qualified_name: m
                                         for m in mutation})
        frame = req.render(mutation_context=ctx)
        _g, _s, rendered = parse_sent_parts(frame)
        expected = mutation[0].value
        if rendered != expected:
            check("case %d renders its own mutant" % index, rendered,
                  expected)
            break
    else:
        check("every case renders its own mutant", "ok", "ok")

    # case -> (seed, local) must match the plan the crash report will look up
    plan_first = body.plan_for_case(1)
    _b, want_first = mutate_seed(s1, 1, 99, mode="structured", budget=5,
                                 max_body_size=65536,
                                 parsed=parse_seed(s1.body),
                                 peer_bodies=[s2.body])
    check("case 1 maps to seed 1, local 1", plan_first, want_first)
    plan_sixth = body.plan_for_case(6)
    _b, want_sixth = mutate_seed(s2, 1, 99, mode="structured", budget=5,
                                 max_body_size=65536,
                                 parsed=parse_seed(s2.body),
                                 peer_bodies=[s1.body])
    check("case 6 maps to seed 2, local 1", plan_sixth, want_sixth)

    ring = SeedBody([s1, s2], 99, mode="structured", mutations_per_seed=5,
                    order="round-robin")
    ring_plan = ring.plan_for_case(2)
    _b, want_ring = mutate_seed(s2, 1, 99, mode="structured", budget=5,
                                max_body_size=65536,
                                parsed=parse_seed(s2.body),
                                peer_bodies=[s1.body])
    check("round-robin case 2 is seed 2", ring_plan, want_ring)


def test_runstate():
    print("[6] run state: seed identity and reset rules")
    tmp = tempfile.mkdtemp(prefix="state-")
    try:
        path = os.path.join(tmp, "s.json")
        st = RunState(path=path, request="seed_0f_0002", mode="seed",
                      group="0x0f", service="0x0002", seed=7,
                      corpus_digest="abc", mutation_mode="structured",
                      mutations_per_seed=10, max_body_size=4096,
                      seed_order="round-robin", corpus_path="/tmp/corpus")
        st.save()
        loaded = RunState.load(path)
        check("version", loaded.version, 2)
        check("mode round-trips", loaded.mode, "seed")
        check("digest round-trips", loaded.corpus_digest, "abc")
        check("corpus path round-trips", loaded.corpus_path, "/tmp/corpus")
        check("body cap round-trips", loaded.max_body_size, 4096)
        check("seed order round-trips", loaded.seed_order, "round-robin")

        check("matching corpus is accepted",
              loaded.conflicts_with(None, None, None, None, mode="seed",
                                    corpus_digest="abc"), None)
        check_true("changed corpus is refused",
                   loaded.conflicts_with(None, None, None, None, mode="seed",
                                         corpus_digest="def") is not None)
        check_true("changed mode is refused",
                   loaded.conflicts_with(None, None, None, None,
                                         mode="model") is not None)

        v1 = os.path.join(tmp, "v1.json")
        with open(v1, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "request": "trace_configure",
                       "group": None, "service": None, "raw_body": False,
                       "seed": 5, "last_case": 10, "cases_run": 10}, fh)
        old = RunState.load(v1)
        check("v1 upgraded to the current version", old.version, 2)
        check("v1 state is a model run", old.mode, "model")
        check("v1 resume point preserved", old.resume_index(), 11)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_multiframe_reassembly():
    print("[7] multi-frame bodies survive capture and replay")
    # one tag holding 2000 bytes: far past the 468-byte first frame
    body = b"\x13" + leb128_pad3(2000) + b"B" * 2000
    req = build_static_request("seed_multiframe_test", session_state(),
                               0x0F, 0x0002, body)
    frame = req.render(mutation_context=MutationContext())

    group, service, parsed = parse_sent_parts(frame)
    check("group survives", group, 0x0F)
    check("service survives", service, 0x0002)
    check("all 2000 bytes reassembled", parsed, body)
    check_true("the request really used several frames",
               len(frame) > 8 + 20 + 24 + 468)


def test_crash_report_replay_fields():
    print("[8] crash report carries a replayable body and seed plan")
    from monitor import CodesysMonitor

    tmp = tempfile.mkdtemp(prefix="crash-")
    try:
        seed = Seed(0x0F, 0x0002, TRACE_CFG_TEMPLATE)
        body = SeedBody([seed], 77, mode="structured", mutations_per_seed=4)
        req = build_seed_request("seed_crash_test", session_state(),
                                 0x0F, 0x0002, body)
        # case 2 is a real structured mutation, not the default
        mutations = list(body.get_mutations())
        ctx = MutationContext(mutations={m.qualified_name: m
                                         for m in mutations[1]})
        frame = req.render(mutation_context=ctx)

        monitor = CodesysMonitor(connection=None, crash_dir=tmp,
                                 request_name="seed_crash_test",
                                 target="192.0.2.1", seed=77,
                                 seed_body=body)
        monitor.crash = {"case": 2, "cases_run": 2,
                         "reason": "TimeoutError: timed out",
                         "when": "2026-01-01 00:00:00",
                         "send_len": len(frame)}
        monitor._last_send = frame
        base = monitor._write_crash_files()

        with open(base + ".json", encoding="utf-8") as fh:
            report = json.load(fh)
        check("report names the pair", (report["group"], report["service"]),
              ("0x000f", "0x0002"))
        check("report stores the exact body", report["body_hex"],
              mutations[1][0].value.hex())
        check("report stores the seed id", report["seed_plan"]["seed"],
              seed.sha1)
        check("report stores the mutation", report["seed_plan"]["case"], 2)
        check_true("reproduce command is --replay",
                   "--replay" in report["reproduce_command"])

        with open(base + ".txt", encoding="utf-8") as fh:
            text = fh.read()
        check_true("text report shows the seed plan", "Seed mutation" in text)
        check_true("text report names the seed", seed.sha1 in text)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    test_corpus()
    test_corpus_jsonl_and_bin()
    test_tag_codec()
    test_mutator()
    test_seed_body()
    test_runstate()
    test_multiframe_reassembly()
    test_crash_report_replay_fields()
    print("\n" + "=" * 70)
    print("%d passed, %d failed" % (len(PASS), len(FAIL)))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
