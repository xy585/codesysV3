#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CODESYS V3 network fuzzer — boofuzz, generation-based, over CmpBlkDrvTcp.

Modelled after Claroty's OPC UA fuzzer (``references/opcua_network_fuzzer``),
which the FreeBuf CODESYS article recommends adapting:

    推荐采用 boofuzz 框架，可以参考 claroty 开源的 OPC UA 模糊测试程序来适配
    Codesys V3 协议的模糊测试

Usage
    python codesys_fuzzer.py --list-requests
    python codesys_fuzzer.py 192.168.125.129 -r trace_list --dry-run --send
    python codesys_fuzzer.py 192.168.125.129 -r trace_configure --cases 2000

Every test case opens a channel, logs in, and sends one mutated request; the
framing is built by boofuzz rather than by hand, so sizes and CRC32 stay
consistent however far a mutation grows the body.

Start with ``--dry-run``: it renders the *unmutated* request and (with --send)
confirms the runtime accepts it, which is the cheapest way to prove the modelled
packet is real before spending hours fuzzing a packet the runtime drops.
"""

import argparse
import json
import os
import socket
import struct
import sys
import time

from boofuzz import exception
from boofuzz.mutation_context import MutationContext

from corpus import Corpus, Seed
from fuzzer import Fuzzer
from monitor import _fmt_nodes, _hexdump, structured_from_body
from runstate import RunState
from proto import TCP_PORT, parse_services, parse_tags, status_of
from services import (
    MODEL_DIMENSIONS, REQUESTS, build_static_request, request_names,
)
from transport import CodesysConnection
from utils import SeedBody, run_seed, set_run_seed, _s_update


def _hexdump(data, width=16, limit=256):
    out = []
    shown = data[:limit]
    for off in range(0, len(shown), width):
        row = shown[off:off + width]
        hexes = " ".join("%02x" % b for b in row)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        out.append("  %04x  %-*s  %s" % (off, width * 3 - 1, hexes, text))
    if len(data) > limit:
        out.append("  ... %d more bytes" % (len(data) - limit))
    return "\n".join(out)


def _as_int(value):
    """Parse a group/service spec: 15, "15", "0x0f", or a bare hex string."""
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    if text.startswith("0x"):
        return int(text, 16)
    try:
        return int(text, 0)
    except ValueError:
        return int(text, 16)


def _save_rendered_seed(save_dir, request_name, data):
    """Store the body of a rendered request as a corpus seed.

    ``data`` is the full framed request; only the services body is kept, because
    the framing and session id are per-connection state.
    """
    from corpus import write_seed
    from monitor import parse_sent_parts

    group, service, body = parse_sent_parts(data)
    if group is None or not body:
        print("[!] cannot save a seed: the render did not parse as a request")
        return None
    path = write_seed(save_dir, group, service, body,
                      source="model:%s" % request_name, verdict="unmutated")
    if path:
        print("[seed] saved group 0x%04x service 0x%04x body %dB -> %s"
              % (group, service, len(body), path))
    else:
        print("[seed] group 0x%04x service 0x%04x body already in %s"
              % (group, service, save_dir))
    return path


def _watch_for_death(conn, grace, interval=0.5):
    """Poll ``conn.probe()`` for a refused connect for up to ``grace`` seconds.

    Returns the probe's reason when the runtime is gone, or None when it
    survived the window.  Used where there is no monitor to do the watch —
    ``--replay`` sends one body outside the fuzz loop.
    """
    deadline = time.monotonic() + max(0.0, grace)
    while True:
        alive, why = conn.probe()
        if not alive:
            return why
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        time.sleep(min(interval, remaining))


def dry_run(fz, send=False, save_seed_dir=None):
    """Render the unmutated request, handshake first so live fields are real."""
    conn = fz.connection
    print("========== dry run: %s ==========" % fz.request_name)
    print("  depth 1  : %d single-field case(s)"
          % fz.request.get_num_mutations())
    print("  connecting and handshaking...")
    try:
        conn.open()
    except exception.BoofuzzTargetConnectionFailedError as e:
        print("[-] %s" % e)
        return 1

    try:
        print("  %s" % conn.state.describe())
        # inject the same values the fuzzing loop would
        fz.session_pre_send(target=None, fuzz_data_logger=None, session=None)

        data = fz.request.render(mutation_context=MutationContext())
        print("  rendered request: %d bytes" % len(data))
        if save_seed_dir:
            _save_rendered_seed(save_seed_dir, fz.request_name, data)
        print(_hexdump(data))

        print("  (per frame: 8B block-driver header + 20B datagram header + a "
              "24B first / 16B continuation channel header, then the services "
              "block)")

        if not send:
            print("  [i] not sent (add --send to deliver it)")
            return 0

        print("  sending...")
        conn.send(data)
        body = _read_reply(conn)

        def watch_after_send():
            """A crash can trail the request even when it was answered.

            The reply only says the handler finished; the process can still die
            a moment later (a deferred task, or a corruption that hits on the
            next cleanup).  Watching on every path is what makes --replay's
            "no crash" mean the runtime survived, not just that a reply came
            back.
            """
            why = _watch_for_death(conn, fz.crash_grace)
            if why is not None:
                print("[!] the runtime is gone after this request: %s" % why)
                print("    the replay reproduced the crash")
                return False
            return True

        if body is None:
            # Silence has two very different causes, and the caller of
            # --replay is usually trying to prove one of them: a request that
            # killed the runtime looks exactly like a request the framing
            # mangled.
            if watch_after_send():
                print("[?] no reply.  An unmutated request should be answered — "
                      "a silent drop suggests the framing is wrong.")
            return 1
        if body == b"":
            print("[+] the runtime closed the channel instead of answering: it "
                  "did not accept the packet.")
            watch_after_send()
            return 1

        hdr, svc_body = parse_services(body)
        status = status_of(parse_tags(svc_body))
        # CODESYS sets bit 7 of the group to mark a reply: 0x008f comes back
        # for a request to group 0x000f (all real group ids are below 0x80).
        is_reply = bool(hdr["group"] & 0x0080)
        print("  reply: group=0x%04x%s service=0x%04x content=%dB status=%s"
              % (hdr["group"], " (0x%04x as a request)"
                 % (hdr["group"] & 0xFF7F) if is_reply else "",
                 hdr["service_id"], len(svc_body), status))
        print(_hexdump(body))

        if not is_reply:
            print("[?] the group's reply bit is clear — this does not look like "
                  "a response to the request that was sent.")
            watch_after_send()
            return 1
        if status == 0:
            print("[+] accepted: the runtime answered with status 0.")
            return 0 if watch_after_send() else 1
        if status is None:
            print("[+] accepted: the runtime answered, and this service sends no "
                  "status tag (0xFF7F).")
            return 0 if watch_after_send() else 1
        print("[i] the request parsed (it was answered) but was refused with "
              "status %s — the framing is sound, the payload needs adjusting."
              % status)
        return 0 if watch_after_send() else 1
    finally:
        conn.close()


def _read_reply(conn, max_frames=16, timeout=2.0):
    """Collect the runtime's reply using the length-prefixed frame reader.

    Returns the services block bytes, ``b""`` if the runtime closed the channel,
    or ``None`` if nothing arrived.  Bounded by ``max_frames`` because the
    runtime can start ping-ponging keepalives, which an unbounded read waits on
    forever.
    """
    from proto import parse_channel

    t = conn.transport
    if t is None:
        return None
    buf = bytearray()
    declared = None
    got_anything = False
    for _ in range(max_frames):
        try:
            dg = t.recv_raw(timeout=timeout)
        except (TimeoutError, socket.timeout):
            break
        except (OSError, ValueError, ConnectionError):
            break
        if dg is None:
            continue
        got_anything = True
        ch = parse_channel(dg["payload"])
        if ch["type"] in ("blk_first", "blk_cont"):
            if ch["type"] == "blk_first":
                declared = ch["data_size"]
            buf += ch["data"]
            if declared is not None and len(buf) >= declared:
                return bytes(buf[:declared])
        elif ch["type"] == "close":
            return b""
        elif ch["type"] == "open_resp":
            continue
        # keepalives and acks are simply not what we are waiting for
    if not got_anything:
        return None
    return bytes(buf[:declared]) if declared is not None else None


def main():
    ap = argparse.ArgumentParser(
        description="CODESYS V3 protocol fuzzer (boofuzz, over TCP)",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", nargs="?", help="runtime IPv4 address, "
                    "e.g. 192.168.125.129")
    ap.add_argument("-r", "--request", choices=request_names(),
                    help="which request model to fuzz")
    ap.add_argument("--list-requests", action="store_true",
                    help="list the request models and exit")
    ap.add_argument("--all", action="store_true",
                    help="fuzz every request model in sequence, each with its "
                         "own database; a failure in one does not stop the rest")
    ap.add_argument("--surface", choices=("global", "separate", "off"),
                    default="global",
                    help="how to record the (group, service) pairs the runtime "
                         "answers.  global (default): one cumulative file shared "
                         "across runs, each pair written once, so a later run "
                         "extends it instead of repeating it.  separate: one file "
                         "per run.  off: no file.  Nothing is written until a "
                         "pair actually replies, so no empty files")
    ap.add_argument("--surface-file", default=None,
                    help="path of the global pair file "
                         "(default <log-dir>/service_surface.jsonl)")
    ap.add_argument("--from-pairs", metavar="FILE", default=None,
                    help="fuzz the (group, service) pairs listed in FILE instead "
                         "of a single model: each pair gets its own session, "
                         "using its own model when one exists and a generic body "
                         "otherwise")
    ap.add_argument("--pairs-only", choices=("evidence", "implemented"), default="evidence",
                    help="which pairs --from-pairs acts on.  evidence (default): "
                         "anything that replied.  implemented: only pairs whose "
                         "reply carried content, i.e. a service that really exists")
    ap.add_argument("--from-seeds", metavar="PATH", default=None,
                    help="data-driven fuzzing: mutate the real request bodies in "
                         "PATH (a seed file, or a directory of JSON/JSONL/raw "
                         ".bin seeds).  Each (group, service) pair gets its own "
                         "session, like --from-pairs")
    ap.add_argument("--mutate", choices=("raw", "structured", "hybrid"),
                    default="structured",
                    help="seed mutation strategy.  raw: byte-level havoc only.  "
                         "structured (default): parse the tag stream and mutate "
                         "field ids/lengths/values, so it stays walkable.  "
                         "hybrid: both")
    ap.add_argument("--mutations-per-seed", type=int, default=256,
                    help="test cases generated per corpus seed (default 256)")
    ap.add_argument("--max-body-size", type=int, default=65536,
                    help="reject a mutation that grows a body beyond this many "
                         "bytes (default 65536)")
    ap.add_argument("--seed-order", choices=("contiguous", "round-robin"),
                    default="contiguous",
                    help="how cases are allocated across a pair's seeds.  "
                         "contiguous: finish one seed before the next.  "
                         "round-robin: one case per seed, then the next round")
    ap.add_argument("--save-seed", metavar="DIR", default=None,
                    help="with --dry-run: save the rendered (unmutated) body as a "
                         "corpus seed in DIR.  Any model's default body is a real "
                         "request, so this is enough to start seed fuzzing without "
                         "a capture")
    ap.add_argument("--capture-seeds", metavar="DIR", default=None,
                    help="copy the body of every accepted/replied case into "
                         "DIR/candidates as a candidate seed.  Deliberately not "
                         "part of the active corpus (that would change the "
                         "corpus digest mid-run and break resume); import it "
                         "explicitly later with --from-seeds DIR/candidates")
    ap.add_argument("--replay", metavar="FILE", default=None,
                    help="reproduce a crash from its report (*.json).  By "
                         "default this re-sends the recorded last body, which "
                         "is the packet that was on the wire when the runtime "
                         "died.  Add --replay-prefix to re-send cases 1..N "
                         "from the embedded corpus instead")
    ap.add_argument("--replay-prefix", action="store_true",
                    help="with --replay: re-run the recorded seed enumeration "
                         "from case 1 up to the crash, instead of sending the "
                         "single recorded body.  Slower and not always the "
                         "minimal repro; use it when the single body does not "
                         "reproduce")
    ap.add_argument("--replay-trail", action="store_true",
                    help="with --replay: send the recorded recent packets "
                         "(the last 10 sends before the crash) one at a time, "
                         "waiting after each, to identify the packet that "
                         "actually kills the runtime.  Nothing is constructed; "
                         "these are the exact bodies the fuzzer sent")
    ap.add_argument("--replay-wait", type=float, default=0.0,
                    help="with --replay-trail: extra seconds to watch after "
                         "each packet before sending the next (default 0 = "
                         "send at the run's own pace and probe once after each). "
                         "Raising it gives finer attribution but changes the "
                         "request timing, which can stop a timing-sensitive "
                         "crash from reproducing; the last packet is watched "
                         "for --crash-grace regardless")
    ap.add_argument("--replay-case", type=int, default=None,
                    help="with --replay FILE: send only this case's packet and "
                         "watch for the crash.  The body is resolved from the "
                         "recent trail, the report's last frame, or the "
                         "embedded seed corpus, so any confirmed case can be "
                         "checked on its own")
    ap.add_argument("--case-report", type=int, default=None, metavar="CASE",
                    help="with --replay FILE: write a crash-report-style .txt "
                         "for this case (structured request, mutation plan, raw "
                         "bytes) and exit; nothing is sent.  Use it after "
                         "--replay-case/-trail has confirmed which case is the "
                         "trigger.  The body comes from the recorded trail, the "
                         "last sent frame, or the embedded seed corpus, in "
                         "that order")
    ap.add_argument("--case-report-out", metavar="FILE", default=None,
                    help="output path for --case-report (default: next to the "
                         "crash report, <report>_case_<N>.txt)")
    ap.add_argument("--all-groups", action="store_true",
                    help="enumerate the service surface, one group per session. "
                         "Fixing the group is what gives per-service resolution: "
                         "a combined group+service sweep probes each group with "
                         "one arbitrary service id")
    ap.add_argument("--between-models", type=float, default=25.0,
                    help="seconds to pause between models in --all, so the "
                         "runtime can reap the previous model's channel")
    ap.add_argument("--group", metavar="SPEC", default=None,
                    help="override the service group: a value (0x0f), a range "
                         "(0x00-0x22), or 'sweep' for every known group")
    ap.add_argument("--service", metavar="SPEC", default=None,
                    help="override the service id: a value (0x02), a range "
                         "(0x00-0x13), or 'sweep' for 0x00-0x27")
    ap.add_argument("--raw-body", action="store_true",
                    help="replace the model's body with unstructured bytes, so "
                         "the tag parser itself is what gets fuzzed")
    ap.add_argument("--port", type=int, default=TCP_PORT,
                    help=f"block driver TCP port (default {TCP_PORT})")
    ap.add_argument("--user", default="test")
    ap.add_argument("--password", default="test")
    ap.add_argument("--app-name", default="App",
                    help="application to bind the session to (CmpApp 0x0001)")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--cases", type=int, default=None,
                    help="stop after N test cases")
    ap.add_argument("--case", type=int, default=None,
                    help="re-run a single test case index (from a crash report)")
    ap.add_argument("--case-count", type=int, default=1,
                    help="with --case: how many cases to run from that index")
    ap.add_argument("--log-payloads", action="store_true",
                    help="also log the full hex of every transmitted request.  "
                         "Off by default: over a long run that is a copy of the "
                         "whole corpus.  The request that triggers a crash is "
                         "written out in full regardless, by the crash report")
    ap.add_argument("--record-block", metavar="NAME", action="append",
                    help="record the rendered bytes of this block/element for "
                         "every transmitted request, one JSON line per case.  "
                         "Repeatable.  NAME is a qualified name or a unique "
                         "trailing component, e.g. body, t13 or t13_data.  Off "
                         "by default")
    ap.add_argument("--record-file", metavar="FILE", default=None,
                    help="file for --record-block (default "
                         "<log-dir>/<request>_blocks_<stamp>.jsonl).  Appended "
                         "to, one JSON object per test case")
    ap.add_argument("--seed", type=lambda s: int(s, 0), default=None,
                    help="pin the run's random seed.  Payloads are drawn from a "
                         "per-run seed rather than a fixed one, so two runs of a "
                         "model send different bytes; pass the same seed to "
                         "reproduce a run exactly.  The seed in use is recorded "
                         "in the run state file")
    ap.add_argument("--state", metavar="FILE", default=None,
                    help="run state file (default <log-dir>/<request>.state.json)")
    ap.add_argument("--state-every", type=int, default=25,
                    help="write the run state every N cases")
    ap.add_argument("--force-new", action="store_true",
                    help="start a fresh run even though the state file already "
                         "holds an unfinished one, discarding its resume point")
    ap.add_argument("--resume", metavar="FILE", default=None,
                    help="resume an interrupted run from its state file: "
                         "continues at the first case that has not run, with the "
                         "recorded seed, instead of repeating what already ran.  "
                         "A seed-mode state also supplies its corpus path and "
                         "enumeration parameters, so --from-seeds is optional")
    ap.add_argument("--sleep", type=float, default=0.0,
                    help="seconds to pause between test cases")
    ap.add_argument("--reply-timeout", type=float, default=2.0,
                    help="seconds to wait for a reply.  Lowering this speeds up "
                         "sweeps (a dropped packet is only detectable by "
                         "timeout) but risks cutting off a reply that is still "
                         "arriving: a timeout mid-frame discards the bytes "
                         "already read, desynchronising the stream and forcing a "
                         "re-handshake and a fresh channel")
    ap.add_argument("--probe-every", type=int, default=50,
                    help="probe the runtime for liveness every N cases.  The "
                         "run is probed again once it stops (retried briefly), "
                         "so a crash in the last cases is not missed.  A "
                         "broken session is always probed regardless, and a "
                         "reply already proves liveness, so probing every case "
                         "just adds a TCP connect per case")
    ap.add_argument("--no-probe", action="store_true",
                    help="disable the liveness probe (rely on connection errors)")
    ap.add_argument("--crash-grace", type=float, default=10.0,
                    help="after the run stops, keep polling the listener this "
                         "many seconds for a delayed crash (default 10).  A "
                         "request can kill the runtime a few seconds after it "
                         "has answered, so a single end-of-run probe misses it. "
                         "0 means probe once and stop")
    ap.add_argument("--restart-threshold", type=int, default=1,
                    help="consecutive failed reconnects before giving up")
    ap.add_argument("--log-dir", default="logs",
                    help="directory for the sqlite case database")
    ap.add_argument("--web-port", type=int, default=26000)
    ap.add_argument("--no-web", action="store_true",
                    help="do not start boofuzz's web UI")
    ap.add_argument("--dry-run", action="store_true",
                    help="handshake, render the unmutated request, print it")
    ap.add_argument("--send", action="store_true",
                    help="with --dry-run: actually send it and show the reply")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if args.list_requests:
        print("request models:")
        for name in request_names():
            group, service, _ = REQUESTS[name]
            if name in MODEL_DIMENSIONS:
                where = "group/service both fuzzed (see --group/--service)"
            else:
                where = "group 0x%04X service 0x%04X" % (group, service)
            print("  %-22s %s" % (name, where))
        print("""
graded black-box modes — how much you tell it about the target:

  -r trace_configure                              modelled body, one known pair
  -r generic_sweep --group 0x0f --service 0x02    generic body, one known pair
  -r generic_sweep --group 0x0f                   group known, dispatch swept
  -r generic_sweep                                group and dispatch both swept
  -r generic_sweep --raw-body                     ...and the body is unstructured

  --group/--service also work on a modelled request, which turns it into a
  shape router: -r trace_configure --group sweep sends the captured TraceMgr
  body to every other component's handler.

data-driven mode (no model — mutate real captured request bodies):

  --from-seeds seeds/ --mutate structured        tag-aware mutation
  --from-seeds seeds/ --mutate raw               byte-level havoc
  --from-seeds seeds/ --mutate hybrid            both
  --dry-run --send --save-seed seeds/            bootstrap a seed from any model
  --replay logs/seed_0f_0002_crash_*.json        re-send a crash body""")
        return 0

    if not args.target:
        ap.error("a target address is required (or use --list-requests)")
    if args.record_file and not args.record_block:
        ap.error("--record-file has nothing to record without --record-block")
    if args.case_report is not None and not args.replay:
        ap.error("--case-report needs --replay <crash-report.json>")
    if args.case_report_out and args.case_report is None:
        ap.error("--case-report-out needs --case-report CASE")
    # --resume can supply the request, so it must not be required up front
    if not args.request and not args.all and not args.all_groups             and not args.from_pairs and not args.from_seeds and not args.replay and not args.resume:
        ap.error("--request is required (or --all / --all-groups / --from-pairs "
                 "/ --from-seeds / --replay / --resume / --list-requests)")

    if not os.path.isdir(args.log_dir):
        os.makedirs(args.log_dir, exist_ok=True)

    # resume first: it can supply the request/group/service the command omitted
    resume_state = None
    if args.resume:
        try:
            resume_state = RunState.load(args.resume)
            args.resume_state = resume_state
        except (OSError, ValueError) as e:
            ap.error("cannot resume from %s: %s" % (args.resume, e))
        # A seed-mode state knows the corpus it was built from.  Use it when the
        # command omitted --from-seeds, so resuming is one flag rather than
        # "remember which directory you used and also pass it".  The digest is
        # still checked; the path is only a convenience.
        if resume_state.mode == "seed" and not args.from_seeds:
            recorded = getattr(resume_state, "corpus_path", None)
            if recorded:
                args.from_seeds = recorded
                print("[resume] corpus from state: %s" % recorded)
            else:
                ap.error("%s is a seed-mode run (%s) with no recorded corpus "
                         "path; pass --from-seeds <corpus>"
                         % (args.resume, resume_state.request))
        clash = resume_state.conflicts_with(
            args.request, args.group, args.service, args.raw_body or None,
            mode=("seed" if args.from_seeds else None))
        if clash:
            ap.error("--resume does not match this command (%s).  A mutant index "
                     "only means something against the same model, so resuming "
                     "into a different one would skip an unrelated part of the "
                     "enumeration." % clash)
        args.request = args.request or resume_state.request
        if not args.request:
            ap.error("%s does not record a request, so --request is needed"
                     % args.resume)
        if args.group is None:
            args.group = resume_state.group
        if args.service is None:
            args.service = resume_state.service
        if resume_state.raw_body:
            args.raw_body = True
        if (args.seed is not None and resume_state.seed is not None
                and int(args.seed) != int(resume_state.seed)):
            ap.error("--seed %s does not match the run's recorded seed %s; "
                     "the same case index would send a different packet"
                     % (args.seed, resume_state.seed))
        print("[resume] %s" % resume_state.describe())

    # A replay carries its own seed: a seed-mode report replays under the
    # recorded run seed (the case index would mean a different packet under a
    # new one), and a single-body replay does not use the enumeration at all.
    # Routing before the "[seed] ..." line avoids printing a seed that the
    # replay then overrides.
    if args.replay:
        return run_replay(args)

    # one seed per run, recorded so the run can be repeated
    seed = set_run_seed(args.seed if args.seed is not None
                        else (resume_state.seed if resume_state else
                              run_seed()))
    print("[seed] %d  (pass --seed %d to reproduce this run exactly)"
          % (seed, seed))

    if args.from_seeds:
        return run_from_seeds(args)
    if args.from_pairs:
        return run_from_pairs(args)
    if args.all_groups:
        return run_all_groups(args)
    if args.all:
        return run_all(args)

    stamp = time.strftime("%m%d-%H%M%S")
    return run_one(args, args.request, stamp)


def _surface_path(args, request_name, stamp):
    """Where the pair file goes, or None when recording is off.

    ``global`` deliberately drops the per-run stamp: the whole point is that
    successive runs share one file, and a timestamped name would produce one file
    per run — the thing ``separate`` exists for.
    """
    if args.surface == "off":
        return None
    if args.surface == "separate":
        return os.path.join(args.log_dir,
                            "%s_%s.surface.jsonl" % (request_name, stamp))
    return args.surface_file or os.path.join(args.log_dir,
                                             "service_surface.jsonl")


def group_fallbacks(path):
    """{group: status} — the status each group answers for a service it lacks.

    This is the whole discriminator, and it is **per group**: CmpAppBP and
    CmpAppForce answer ``24`` (read straight off ``default: return 24`` in
    ``sub_EBF300`` / ``sub_EC5900``), most others answer ``770``.  A group's
    fallback is taken as the status it returns most often, which is safe because
    a group has far more absent service ids than present ones.
    """
    counts = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if row.get("verdict") != "refused" or row.get("status") is None:
                continue
            counts.setdefault(row["group"], {}).setdefault(row["status"], 0)
            counts[row["group"]][row["status"]] += 1
    return {g: max(c, key=c.get) for g, c in counts.items() if c}


def load_pairs(path, only="evidence"):
    """Read a pair file into [(group, service)], deduped.

    ``evidence`` — anything that got a reply at all.

    ``implemented`` — anything whose verdict is *not* the group's fallback
    refusal.  That is deliberately broader than "the reply carried content",
    which was the earlier rule and was wrong: measured against CmpAppBP, whose
    nine services are known from the decompilation, "replied only" missed seven
    of them.  Six of those seven answer with an **empty** body and one answers
    ``refused`` with status ``1304`` — all of them present, none of them
    ``refused/24``.  Keying on "not the fallback" got all nine and no absent id.
    """
    rank = {"accepted": 4, "replied": 3, "refused": 2, "empty": 1}
    fallbacks = group_fallbacks(path) if only == "implemented" else {}
    best = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if "group" not in row or "service" not in row:
                continue
            v = row.get("verdict", "no-reply")
            if v not in rank:
                continue
            if only == "implemented":
                is_fallback = (v == "refused"
                               and row.get("status") == fallbacks.get(row["group"]))
                if is_fallback:
                    continue
            key = (row["group"], row["service"])
            # a pair can appear more than once (a later run improves a verdict),
            # so the best entry wins rather than the last
            if key not in best or rank[v] > rank[best[key]]:
                best[key] = v
    return sorted((int(g, 16), int(s, 16)) for g, s in best)


def _unhex_tree(nodes):
    """Inverse of the recorder's hex encoding, dropping junk entries."""
    out = []
    for n in nodes or []:
        try:
            out.append({"id": int(n["id"], 16),
                        "children": _unhex_tree(n.get("children"))})
        except (KeyError, TypeError, ValueError):
            continue
    return out


def describe_tree(nodes):
    """``0x81(0x11 0x18) 0x1a`` — containers show their children."""
    def one(n):
        if n.get("children"):
            return "0x%02x(%s)" % (n["id"],
                                   " ".join(one(c) for c in n["children"]))
        return "0x%02x" % n["id"]
    return " ".join(one(n) for n in nodes) or "(empty)"


def load_pair_tags(path):
    """{(group, service): tag tree} — accepted-body seeds from a pair file.

    The longest tree wins rather than the last: a pair is recorded again when its
    verdict improves, and a later row is not necessarily a richer one (a run with
    a different seed may have happened to carry fewer tags).  More nodes means
    more is known about what that parser accepts.
    """
    out = {}
    try:
        fh = open(path, encoding="utf-8")
    except OSError:
        return out
    with fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            try:
                key = (int(row["group"], 16), int(row["service"], 16))
            except (KeyError, TypeError, ValueError):
                continue
            if "tag_tree" in row:
                tree = _unhex_tree(row["tag_tree"])
            elif "tags" in row:
                # A pair file written before the tree format.  Those rows hold a
                # flat id list, so they can only be read back as leaves — the
                # container nesting is gone and cannot be recovered.  Better a
                # partial seed than silently dropping the row, but this is why
                # the format is a tree now.
                tree = []
                for t in row["tags"] or []:
                    try:
                        tree.append({"id": int(t, 16), "children": []})
                    except (TypeError, ValueError):
                        continue
            else:
                continue
            if len(json.dumps(tree)) > len(json.dumps(out.get(key, []))):
                out[key] = tree
    return out


def model_for_pair(group, service):
    """The request model already covering this pair, if any.

    Pairs that have a real model should be fuzzed with it rather than with a
    generic body: the derived and captured models carry the actual field shapes,
    so mutations land on fields the handler reads instead of being rejected at
    the first unknown tag.
    """
    for name, (g, s, _b) in REQUESTS.items():
        if g == group and s == service:
            return name
    return None


def run_from_seeds(args):
    """Fuzz from real request bodies instead of a hand-written model.

    One session per (group, service) pair, for the same reason ``--from-pairs``
    does it: the pair is what selects a handler, and a seed body only means
    anything there.  Within a pair, boofuzz sees a single fuzzable primitive
    (``SeedBody``), so its depth-1 enumeration is one mutated body per case and
    there are no multi-field combinations to muddy the index.
    """
    if not os.path.exists(args.from_seeds):
        print("[!] corpus %s does not exist; pass --from-seeds <corpus>"
              % args.from_seeds)
        return 2
    corpus = Corpus.load(args.from_seeds)
    if not len(corpus):
        print("[!] %s holds no usable seed (expected JSON/JSONL or "
              "<group>_<service>_*.bin)" % args.from_seeds)
        return 2
    digest = corpus.digest()
    state = getattr(args, "resume_state", None)

    if state is not None and state.mode == "seed":
        if state.corpus_digest and state.corpus_digest != digest:
            print("[!] the corpus changed since %s was written:" % args.resume)
            print("    state   %s" % state.corpus_digest)
            print("    current %s" % digest)
            print("    A case index means (seed, mutation) under one fixed "
                  "corpus order; continuing would send different packets.")
            return 2
        # The budget is part of what an index means: mutate_seed's systematic
        # targets are distributed over the per-seed budget, so resuming with a
        # different value sends a different packet for the same index while
        # claiming to continue the same enumeration.  Same for the mutation
        # mode.  Use what the run recorded instead of the CLI defaults, and say
        # so — silently substituting 256 for 100000 is how a "resume" turns
        # into a different campaign.
        recorded = []
        if state.mutations_per_seed:
            if args.mutations_per_seed != state.mutations_per_seed:
                recorded.append("mutations/seed %d -> %d"
                                % (args.mutations_per_seed,
                                   state.mutations_per_seed))
                args.mutations_per_seed = state.mutations_per_seed
        if state.mutation_mode and args.mutate != state.mutation_mode:
            recorded.append("mode %s -> %s"
                            % (args.mutate, state.mutation_mode))
            args.mutate = state.mutation_mode
        if getattr(state, "seed_order", None) and args.seed_order != state.seed_order:
            recorded.append("order %s -> %s"
                            % (args.seed_order, state.seed_order))
            args.seed_order = state.seed_order
        if (getattr(state, "max_body_size", None)
                and args.max_body_size != state.max_body_size):
            # The cap changes the fallback path (an oversized tag mutation
            # becomes havoc), so it is part of what an index means too.
            recorded.append("max-body %d -> %d"
                            % (args.max_body_size, state.max_body_size))
            args.max_body_size = state.max_body_size
        if recorded:
            print("[resume] using the run's recorded enumeration: %s"
                  % ", ".join(recorded))

    pairs = corpus.by_pair()
    try:
        # resuming a seed run: only the pair that run was on
        if (state is not None and state.mode == "seed"
                and state.group is not None and state.service is not None):
            want = (_as_int(state.group), _as_int(state.service))
            pairs = {k: v for k, v in pairs.items() if k == want}
        if args.group is not None:
            want = _as_int(args.group)
            pairs = {k: v for k, v in pairs.items() if k[0] == want}
        if args.service is not None:
            want = _as_int(args.service)
            pairs = {k: v for k, v in pairs.items() if k[1] == want}
    except (TypeError, ValueError):
        print("[!] --group/--service must be numeric here (a seed belongs to "
              "one pair; 'sweep' is not meaningful)")
        return 2
    if not pairs:
        print("[!] no seed matches the requested group/service")
        return 2

    print("========== seed mutation: %s ==========" % corpus.describe())
    print("  mutate   : %s, %d case(s) per seed, max body %d B"
          % (args.mutate, args.mutations_per_seed, args.max_body_size))
    print("  corpus   : %s (%s)" % (digest[:12], args.from_seeds))
    # A one-pair seed run is a single campaign, so a stale state file should
    # stop it exactly as it stops a model run.  A multi-pair run is a batch:
    # refusing on the first stale pair would just stall the rest.
    args._seed_batch = len(pairs) > 1
    if args.state and len(pairs) > 1:
        print("[!] --state names a single file but --from-seeds is running %d "
              "pairs; use --log-dir (one state per pair) or pick one pair with "
              "--group/--service" % len(pairs))
        return 2

    explicit_resume = getattr(args, "resume_state", None)
    explicit_resume_path = getattr(args, "resume", None)

    def _auto_resume_problem(old, request_name):
        """Why an existing per-pair state cannot be continued by this command."""
        if old.mode != "seed":
            return "it is a %s-mode state" % old.mode
        if old.request != request_name:
            return "it names %s" % old.request
        if old.corpus_digest and old.corpus_digest != digest and False:
            return "the corpus digest changed"
        return None

    results = []
    aborted = 0
    aborted_pair = None
    for i, (group, service) in enumerate(sorted(pairs), 1):
        seeds = pairs[(group, service)]
        request_name = "seed_%02x_%04x" % (group, service)

        # Without an explicit --resume, a batch picks up each pair's own state
        # file when it has progress.  Re-running the same --from-seeds command
        # after a crash then continues every pair instead of silently resetting
        # them to case 1 (batch mode bypasses the single-run clobber check).
        # --force-new starts them over.
        args.resume_state = explicit_resume
        args.resume = explicit_resume_path
        saved_schedule = None
        saved_seed = None
        if explicit_resume is None and not args.force_new:
            pair_state_path = args.state or os.path.join(
                args.log_dir, request_name + ".state.json")
            if os.path.exists(pair_state_path):
                try:
                    old = RunState.load(pair_state_path)
                except (OSError, ValueError):
                    old = None
                if old is not None and (old.last_case or 0) > 0:
                    why = _auto_resume_problem(old, request_name)
                    if why:
                        print("[!] %s cannot be resumed by this command: %s"
                              % (pair_state_path, why))
                        print("    Start it over with --force-new, or pass the "
                              "recorded flags.")
                        return 2
                    args.resume_state = old
                    args.resume = pair_state_path
                    # The recorded schedule is part of what case N means.  Use
                    # it for this pair even if the command omitted the flags
                    # (they are per-pair state now, not one global campaign).
                    saved_schedule = (args.mutate, args.mutations_per_seed,
                                      args.max_body_size, args.seed_order)
                    changes = []
                    if old.mutation_mode and old.mutation_mode != args.mutate:
                        args.mutate = old.mutation_mode
                        changes.append("mutate=%s" % args.mutate)
                    if (old.mutations_per_seed
                            and old.mutations_per_seed
                            != args.mutations_per_seed):
                        args.mutations_per_seed = old.mutations_per_seed
                        changes.append("mutations/seed=%d"
                                       % args.mutations_per_seed)
                    if (old.max_body_size
                            and old.max_body_size != args.max_body_size):
                        args.max_body_size = old.max_body_size
                        changes.append("max-body=%d" % args.max_body_size)
                    if old.seed_order and old.seed_order != args.seed_order:
                        args.seed_order = old.seed_order
                        changes.append("order=%s" % args.seed_order)
                    if old.seed is not None and int(old.seed) != int(run_seed()):
                        # The run seed is part of what a case index means too.
                        saved_seed = run_seed()
                        set_run_seed(old.seed)
                        changes.append("seed=%d" % old.seed)
                    print("[resume] pair 0x%02x/0x%04x from %s at case %d%s"
                          % (group, service, pair_state_path,
                             old.last_case,
                             "" if not changes else
                             " (using recorded %s)" % ", ".join(changes)))
        stamp = time.strftime("%m%d-%H%M%S")
        seed_body = SeedBody(
            seeds, run_seed(), mode=args.mutate,
            mutations_per_seed=args.mutations_per_seed,
            max_body_size=args.max_body_size, order=args.seed_order)
        print("\n" + "#" * 72)
        print("# [%d/%d] group 0x%02x service 0x%04x  %d seed(s), %d case(s)"
              % (i, len(pairs), group, service, len(seeds),
                 seed_body.num_mutations()))
        print("#" * 72)
        try:
            rc = run_one(args, request_name, stamp, seed_body=seed_body,
                         fixed_group=group, fixed_service=service,
                         corpus_digest=digest,
                         corpus_manifest=corpus.manifest(),
                         corpus_path=args.from_seeds,
                         mode="seed")
        finally:
            if saved_schedule is not None:
                (args.mutate, args.mutations_per_seed,
                 args.max_body_size, args.seed_order) = saved_schedule
            if saved_seed is not None:
                set_run_seed(saved_seed)
        results.append(((group, service), rc))
        if rc != 0:
            # 130: the operator interrupted this pair.  1: a crash was detected.
            # 2: no session (target down, or a command-line problem that will
            # repeat for every pair).  In all three the batch is done; carrying
            # on is how the log filled with 0-case state files after the 19:08
            # crash — the runtime was gone and every remaining pair just failed
            # its handshake.
            aborted, aborted_pair = rc, (group, service)
            break
        if i < len(pairs):
            try:
                time.sleep(args.between_models)
            except KeyboardInterrupt:
                print("\n[!] interrupted during the pause between pairs")
                aborted = 130
                break

    args.resume_state = explicit_resume
    args.resume = explicit_resume_path

    print("\n" + "=" * 72)
    print("seed mutation summary")
    print("=" * 72)
    bad = [(g, s) for (g, s), rc in results if rc != 0]
    print("  %d/%d pair(s) completed"
          % (len(results) - len(bad), len(pairs)))
    for group, service in bad:
        print("    0x%02x 0x%04x did not complete cleanly" % (group, service))
    if aborted:
        print("\n[!] batch stopped%s (exit %d)"
              % ("" if aborted_pair is None else
                 " at 0x%02x/0x%04x" % aborted_pair, aborted))
        if aborted_pair is not None:
            request_name = "seed_%02x_%04x" % aborted_pair
            resuming = getattr(args, "resume_state", None)
            if (resuming is not None and resuming.request == request_name
                    and resuming.path):
                state_path = resuming.path
            else:
                state_path = os.path.join(args.log_dir,
                                          request_name + ".state.json")
            print("    Resume that pair with:")
            print("      python codesysfuzzer/codesys_fuzzer.py %s --resume %s"
                  % (args.target or "<target>", state_path))
            print("    The corpus path is recorded in the state file.")
        else:
            print("    The interrupted pair's state file is the resume point.")
        return aborted
    return 1 if bad else 0


def run_replay(args):
    """Reproduce a crash from a crash report.

    Default is the **single recorded body**: that is the packet boofuzz had on
    the wire when the runtime died, and on a fresh runtime it is usually the
    whole trigger.  Measured on a seed-mode ``trace_configure`` crash, the last
    body alone (``len_lie`` on tag 0x30) killed a freshly started runtime,
    while re-sending the preceding cases did *not* — those requests change
    which path the handler takes, so they can mask the trigger rather than
    lead up to it.

    ``--replay-prefix`` is the fallback for a genuinely cumulative crash: the
    report embeds the corpus and run parameters, and the ordinary seed
    enumeration is re-run from case 1 to the recorded index.

    The framing in a report is stale (channel token, block ids, session id), so
    it is never reused: a body goes through the normal request skeleton and
    ``FrameEncoder`` rebuilds every length and the CRC for the live connection.
    """
    with open(args.replay, encoding="utf-8") as fh:
        report = json.load(fh)
    if args.case_report is not None:
        return write_case_report(args, report)
    if args.replay_case is not None:
        packet = _case_packet(report, args.replay_case)
        if packet is None:
            print("[!] case %d cannot be produced from %s: it is not the last "
                  "case, not in the recent trail, and the report has no "
                  "embedded corpus" % (args.replay_case, args.replay))
            return 2
        group, service, body, _sent, _plan, source = packet
        return _replay_packet(args, args.replay_case, group, service, body,
                              source)
    if args.replay_trail:
        return _replay_trail(args, report)
    if args.replay_prefix:
        if not report.get("seed_run"):
            print("[!] %s has no embedded corpus (seed_run), so --replay-prefix "
                  "cannot rebuild the sequence.  It can only replay the last "
                  "body." % args.replay)
            return 2
        try:
            return _replay_seed_prefix(args, report)
        except (KeyError, TypeError, ValueError) as e:
            print("[!] %s has a malformed seed_run (%s)" % (args.replay, e))
            return 2
    return _replay_one_body(args, report)


def _case_packet(report, case):
    """Resolve one case to ``(group, service, body, frame, plan, source)``.

    The body may exist in three places, in order of authority: the report of
    the last sent case, the recent-packets trail, or the embedded seed corpus
    (rebuilt enumeration).  The frame is the exact bytes of that connection
    when the report recorded them; a rebuilt body has no frame, because the
    channel token/session id/block ids belong to a connection that is gone.
    """
    group = report.get("group")
    service = report.get("service")
    if group is None or service is None:
        return None
    group, service = _as_int(group), _as_int(service)

    def frame(hex_text):
        return bytes.fromhex(hex_text) if hex_text else None

    if report.get("case") == case and report.get("body_hex"):
        return (group, service, bytes.fromhex(report["body_hex"]),
                frame(report.get("sent_hex")), report.get("seed_plan"),
                "the last sent frame recorded in the crash report")

    for row in report.get("recent") or []:
        if int(row.get("case", -1)) == case and row.get("body_hex"):
            return (group, service, bytes.fromhex(row["body_hex"]),
                    frame(row.get("sent_hex")), row.get("seed_plan"),
                    "the recent-packets trail (exact bytes sent)")

    seed_run = report.get("seed_run")
    if seed_run:
        seeds = []
        for row in seed_run.get("seeds") or []:
            seeds.append(Seed(_as_int(row["group"]), _as_int(row["service"]),
                              bytes.fromhex(row["body"])))
        if seeds:
            enumeration = SeedBody(
                seeds, int(seed_run["run_seed"]),
                mode=seed_run.get("mode") or "structured",
                mutations_per_seed=int(seed_run.get("mutations_per_seed") or 256),
                max_body_size=int(seed_run.get("max_body_size") or 65536),
                order=seed_run.get("order") or "contiguous")
            result = enumeration.body_for_case(case)
            if result is not None:
                return (group, service, result[0], None, result[1],
                        "rebuilt from the embedded seed corpus")
    return None


def write_case_report(args, report):
    """Write a crash-report-style .txt for one case.

    The operator confirms which case is the trigger with --replay-case/-trail;
    this turns that index into a document with the same information a crash
    report carries — structured tag tree, mutation plan and raw bytes — without
    having to be the case that happened to be last when the crash was noticed.
    """
    case = int(args.case_report)
    packet = _case_packet(report, case)
    if packet is None:
        print("[!] case %d cannot be produced from %s: it is not the last "
              "case, not in the recent trail, and the report has no embedded "
              "corpus" % (case, args.replay))
        return 2
    group, service, body, sent, plan, source = packet
    out = args.case_report_out or (
        os.path.splitext(args.replay)[0] + "_case_%d.txt" % case)
    target = args.target or "<target>"
    request = report.get("request") or "<request>"

    cmd = ("python codesysfuzzer/codesys_fuzzer.py %s --replay %s "
           "--replay-case %d" % (target, args.replay, case))

    lines = [
        "CODESYS V3 fuzzer - case report",
        "=" * 68,
        "  crash report : %s" % args.replay,
        "  case         : %d   (boofuzz total_mutant_index)" % case,
        "  source       : %s" % source,
        "  request      : %s" % request,
        "  pair         : group 0x%04x service 0x%04x" % (group, service),
        "  body size    : %d bytes" % len(body),
        "  seed         : %s" % report.get("seed"),
        "  database     : %s" % (report.get("database") or "?"),
        "",
        "Reproduce",
        "-" * 68,
        "  %s" % cmd,
        "",
        "Structured request (group / service / tags)",
        "-" * 68,
    ]
    struct = structured_from_body(group, service, body)
    if struct is not None:
        lines.append("  group 0x%04x  service 0x%04x" % (group, service))
        if "parse_error" in struct:
            lines.append("  body did not parse: %s" % struct["parse_error"])
            lines.append("  body hex: %s" % struct["body_hex"])
        else:
            lines.extend(_fmt_nodes(struct["body"], 1))
    if plan:
        lines += [
            "",
            "Seed mutation",
            "-" * 68,
            "  corpus seed : %s" % plan.get("seed"),
            "  mode        : %s" % plan.get("mode"),
            "  stage       : %s" % plan.get("stage"),
            "  operations  : %s" % json.dumps(plan.get("ops"), sort_keys=True),
        ]
    lines += [
        "",
        "Raw bytes (services body / tag stream for this case)",
        "-" * 68,
        _hexdump(body, limit=len(body)),
    ]
    if sent is not None:
        lines += [
            "",
            "Raw bytes (block driver + datagram + channel frames + services, "
            "as sent)",
            "-" * 68,
            "  note: channel token, session id and block ids belong to that",
            "        connection; --replay rebuilds them for the live one.",
            "",
            _hexdump(sent, limit=len(sent)),
        ]
    else:
        lines += [
            "",
            "Full wire frame",
            "-" * 68,
            "  not recorded for this case.  The recent-packets trail stores the",
            "  full sent frame in reports written after this feature; the",
            "  services body above is exact and is all --replay needs.",
        ]
    lines.append("")

    parent = os.path.dirname(os.path.abspath(out))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print("[case] wrote %s (case %d, %d-byte body%s)"
          % (out, case, len(body), ", full frame" if sent else ""))
    return 0


def _replay_packet(args, case, group, service, body, source):
    """Send one resolved case body and watch the listener.

    The body may come from the recent trail, the crash report's last frame, or
    the embedded corpus — :func:`_case_packet` decides which.  This is the
    single-packet confirmation step: one connection, one body, then a watch long
    enough to see a delayed crash.
    """
    print("========== case replay: %s ==========" % args.replay)
    print("  case     : %s   (%s)" % (case, source))
    print("  pair     : group 0x%04x service 0x%04x" % (group, service))
    print("  body     : %d bytes" % len(body))

    conn = CodesysConnection(args.target, args.port, user=args.user,
                             password=args.password, app_name=args.app_name,
                             timeout=args.timeout)
    try:
        conn.open()
    except exception.BoofuzzTargetConnectionFailedError as e:
        print("[!] %s" % e)
        return 2

    rc = 0
    try:
        req = build_static_request("case_%s" % case, conn.state, group,
                                   service, body)
        if _s_update("session_id",
                     struct.pack("<I", conn.state.session_id),
                     request=req) != 1:
            print("[!] the request skeleton has no session_id field")
            return 2
        data = req.render(mutation_context=MutationContext())
        print("  sending %d bytes" % len(data))
        try:
            conn.send(data)
        except (exception.BoofuzzTargetConnectionReset,
                exception.BoofuzzTargetConnectionFailedError) as e:
            print("[+] send failed: %s" % e)
            return 1

        reply, complete = conn.service_reply(timeout=args.reply_timeout)
        status = None
        if reply:
            try:
                status = status_of(parse_tags(parse_services(reply)[1]))
            except (ValueError, KeyError):
                status = None
        print("  reply    : %s%s"
              % ("none" if reply is None else "%d bytes" % len(reply),
                 "" if status is None else ", status=%s" % status))

        why = _watch_for_death(conn, max(args.replay_wait, args.crash_grace))
        if why is not None:
            print("[+] crash reproduced: case %s killed the runtime (%s)"
                  % (case, why))
            rc = 1
        else:
            print("[-] case %s did not kill the runtime" % case)
    finally:
        conn.close()
    return rc


def _replay_trail(args, report):
    """Re-send the recorded last-N packets in order and watch for the death.

    Detecting a crash is inherently after the fact: the monitor notices the
    runtime is gone after reading a later case's reply (or timing it out), so
    the case written into the report is the *detection* point.  The monitor
    keeps the exact bodies it sent just before that, and this walks them in
    order — the same bytes, nothing constructed.

    Pacing is the run's own by default: an inserted delay changes the request
    inter-arrival time, and a timing-sensitive crash can stop reproducing.
    ``--replay-wait`` adds a delay for finer attribution at that cost; the last
    packet is always watched for the full crash grace.  To send a single
    already-confirmed case, use ``--replay-case``.
    """
    entries = list(report.get("recent") or [])
    if not entries:
        print("[!] %s has no 'recent' trail (reports written before trail "
              "recording have none); re-run the campaign to produce one"
              % args.replay)
        return 2
    group = _as_int(report.get("group"))
    service = _as_int(report.get("service"))
    name = report.get("request") or "trail"

    print("========== trail replay: %s ==========" % args.replay)
    print("  pair     : group 0x%04x service 0x%04x" % (group, service))
    print("  packets  : %d (case %s..%s), %gs after each, %gs after the last"
          % (len(entries), entries[0].get("case"), entries[-1].get("case"),
             args.replay_wait, max(args.replay_wait, args.crash_grace)))

    conn = CodesysConnection(args.target, args.port, user=args.user,
                             password=args.password, app_name=args.app_name,
                             timeout=args.timeout)
    try:
        conn.open()
    except exception.BoofuzzTargetConnectionFailedError as e:
        print("[!] %s" % e)
        return 2

    rc = 0
    try:
        for i, entry in enumerate(entries, 1):
            case = entry.get("case")
            body = bytes.fromhex(entry["body_hex"])
            if i > 1:
                # A previous packet may have broken the channel without
                # killing the runtime; re-handshake rather than send on a
                # half-read stream.
                try:
                    conn.ensure_open()
                except exception.BoofuzzTargetConnectionFailedError as e:
                    print("[+] the runtime is gone before case %s, so a "
                          "previous packet was fatal: %s" % (case, e))
                    rc = 1
                    break

            req = build_static_request("%s_%s" % (name, case), conn.state,
                                       group, service, body)
            if _s_update("session_id",
                         struct.pack("<I", conn.state.session_id),
                         request=req) != 1:
                print("[!] the request skeleton has no session_id field")
                return 2
            data = req.render(mutation_context=MutationContext())
            print("  [%d/%d] case %s: sending %d bytes"
                  % (i, len(entries), case, len(data)))
            try:
                conn.send(data)
            except (exception.BoofuzzTargetConnectionReset,
                    exception.BoofuzzTargetConnectionFailedError) as e:
                print("[+] send failed, so a previous packet was fatal: %s" % e)
                rc = 1
                break

            reply, complete = conn.service_reply(timeout=args.reply_timeout)
            status = None
            if reply:
                try:
                    status = status_of(parse_tags(parse_services(reply)[1]))
                except (ValueError, KeyError):
                    status = None
            print("        reply: %s%s"
                  % ("none" if reply is None else "%d bytes" % len(reply),
                     "" if status is None else ", status=%s" % status))

            # Keep the run's own pace: an extra sleep here changes the request
            # inter-arrival time, and a timing-sensitive crash stops happening.
            # The last packet is watched for the full grace, like the fuzz
            # loop's end-of-run check.
            grace = args.replay_wait
            if i == len(entries):
                grace = max(grace, args.crash_grace)
            why = _watch_for_death(conn, grace)
            if why is not None:
                print("[+] crash reproduced: case %s killed the runtime (%s)"
                      % (case, why))
                rc = 1
                break
        else:
            print("[-] none of the %d recorded packet(s) killed the runtime; "
                  "raise --replay-wait, or re-run the campaign" % len(entries))
    finally:
        conn.close()
    return rc


def _replay_seed_prefix(args, report):
    """Rebuild the run's corpus and re-send cases 1..N in order.

    ``run_from_seeds`` does the real work: the embedded seeds are written to a
    scratch corpus, the recorded run seed and mutation parameters are put back
    on ``args``, and the normal seed campaign runs against a fresh state/log
    directory.  That keeps one implementation of the enumeration, so the replay
    cannot drift from the run it is reproducing.
    """
    from corpus import write_seed
    from utils import set_run_seed

    seed_run = report["seed_run"]
    group, service = _as_int(report["group"]), _as_int(report["service"])
    cases = int(seed_run.get("cases") or report.get("case") or 0)
    start = int(seed_run.get("start") or 1)
    rows = seed_run.get("seeds") or []
    if cases < 1 or start < 1 or start > cases or not rows:
        print("[!] %s has an empty seed_run; nothing to replay" % args.replay)
        return 2

    print("========== replay: %s ==========" % args.replay)
    print("  pair     : group 0x%04x service 0x%04x" % (group, service))
    print("  cases    : %d..%d  (seed %s, %s, %d mutation(s)/seed)"
          % (start, cases, seed_run.get("run_seed"), seed_run.get("mode"),
             seed_run.get("mutations_per_seed") or 0))
    print("  corpus   : %d embedded seed(s)"
          % len(rows))
    if report.get("seed_plan"):
        plan = report["seed_plan"]
        print("  last plan: %s %s" % (plan.get("stage"),
                                      json.dumps(plan.get("ops"))))

    import shutil
    import tempfile
    corpus_dir = tempfile.mkdtemp(prefix="codesys_replay_corpus_")
    # The log/state directory lives next to the report, so a reproduced crash
    # lands where the operator will look for it, not in a temp dir that is
    # deleted on the way out.
    report_dir = os.path.dirname(os.path.abspath(args.replay)) or "."
    stamp = time.strftime("%m%d-%H%M%S")
    log_dir = os.path.join(report_dir, "replay_%s" % stamp)
    try:
        for row in rows:
            write_seed(corpus_dir, _as_int(row["group"]), _as_int(row["service"]),
                       bytes.fromhex(row["body"]), source="crash-report")
        os.makedirs(log_dir, exist_ok=True)

        # Put the recorded run parameters back.  The enumeration is a pure
        # function of these plus the corpus, so this is what makes index N mean
        # the same packet as it did in the run.
        set_run_seed(int(seed_run["run_seed"]))
        args.from_seeds = corpus_dir
        args.mutate = seed_run.get("mode") or "structured"
        args.mutations_per_seed = int(seed_run.get("mutations_per_seed") or 256)
        args.max_body_size = int(seed_run.get("max_body_size") or 65536)
        args.seed_order = seed_run.get("order") or "contiguous"
        args.group = "0x%04x" % group
        args.service = "0x%04x" % service
        args.case = start
        args.case_count = cases - start + 1
        args.cases = None
        args.dry_run = False
        args.state = os.path.join(log_dir, "replay.state.json")
        args.force_new = True
        args.no_web = True
        args.surface = "off"
        args.capture_seeds = None
        args.record_block = None
        args.record_file = None
        args.log_dir = log_dir
        print("  log dir  : %s" % log_dir)
        return run_from_seeds(args)
    finally:
        shutil.rmtree(corpus_dir, ignore_errors=True)


def _replay_one_body(args, report):
    """Send one body through the live request skeleton (old/model reports)."""
    group = report.get("group")
    service = report.get("service")
    body_hex = report.get("body_hex")
    if group is None or service is None or not body_hex:
        print("[!] %s has no group/service/body_hex; it is not a seed-mode "
              "crash report" % args.replay)
        return 2
    group, service = _as_int(group), _as_int(service)
    body = bytes.fromhex(body_hex)
    request_name = report.get("request") or "replay"
    plan = report.get("seed_plan")

    print("========== replay: %s ==========" % args.replay)
    print("  pair     : group 0x%04x service 0x%04x" % (group, service))
    print("  body     : %d bytes" % len(body))
    if plan:
        print("  seed     : %s" % plan.get("seed"))
        print("  mutation : %s %s" % (plan.get("stage"),
                                      json.dumps(plan.get("ops"))))

    fz = Fuzzer(target_ip=args.target, target_port=args.port,
                request_name=request_name, user=args.user,
                password=args.password, app_name=args.app_name,
                timeout=args.timeout, probe_every=args.probe_every,
                probe=not args.no_probe, verbose=not args.quiet,
                reply_timeout=args.reply_timeout, surface_mode="off",
                crash_dir=None, seed=run_seed(),
                log_payloads=args.log_payloads,
                group=group, service=service, static_body=body,
                crash_grace=args.crash_grace)
    fz._init_target_connection()
    try:
        fz._init_protocol_structure()
    except (KeyError, ValueError) as e:
        print("[!] %s" % e)
        return 2
    return dry_run(fz, send=True)


def run_from_pairs(args):
    """Fuzz each pair listed in a pair file, one session per pair.

    This closes the loop the surface recorder opens: a sweep discovers which
    (group, service) pairs are live, and this turns that list back into targeted
    work instead of leaving it as a report to read by hand.
    """
    pairs = load_pairs(args.from_pairs, only=args.pairs_only)
    if not pairs:
        print("[!] %s lists no usable pair (filter: %s)"
              % (args.from_pairs, args.pairs_only))
        return 2
    seeds = load_pair_tags(args.from_pairs)
    print("========== targeted fuzz: %d pair(s) from %s =========="
          % (len(pairs), args.from_pairs))
    print("  body seeds: %d pair(s) have recorded tag ids"
          % len(seeds))
    results = []
    for i, (g, s) in enumerate(pairs, 1):
        model = model_for_pair(g, s)
        stamp = time.strftime("%m%d-%H%M%S")
        print("\n" + "#" * 72)
        seed = seeds.get((g, s))
        if model:
            what = "model %s" % model
        elif seed:
            what = "seeded body from %s" % describe_tree(seed)
        else:
            what = "unstructured body (no model, no seeds)"
        print("# [%d/%d] group 0x%02x service 0x%04x  %s"
              % (i, len(pairs), g, s, what))
        print("#" * 72)
        saved = (args.request, args.group, args.service, args.raw_body,
                 getattr(args, "seed_tags", None))
        try:
            if model:
                args.request, args.group, args.service = model, None, None
                args.raw_body = False
            else:
                # no model: fix the pair and send an unstructured body, which is
                # the most this pair can be probed with until one is derived
                args.request, args.group, args.service = "generic_sweep", \
                    "0x%02x" % g, "0x%04x" % s
                args.raw_body = True
            rc = run_one(args, args.request, stamp)
        finally:
            (args.request, args.group, args.service, args.raw_body,
             args.seed_tags) = saved
        results.append(((g, s), rc))
        if i < len(pairs):
            time.sleep(args.between_models)

    print("\n" + "=" * 72)
    print("targeted fuzz summary")
    print("=" * 72)
    bad = [(g, s) for (g, s), rc in results if rc != 0]
    print("  %d/%d pairs completed" % (len(results) - len(bad), len(results)))
    for (g, s), rc in results:
        if rc != 0:
            print("    0x%02x 0x%04x -> exit %d" % (g, s, rc))
    return 1 if bad else 0


def run_all_groups(args):
    """Enumerate the service surface, one group per session.

    This is the shape the enumeration has to take, and it is worth stating why,
    because it is counter-intuitive: sweeping the group id *and* the service id
    in one session gives far worse resolution than fixing the group.  boofuzz
    mutates one primitive per case, so in a combined sweep the service id sits at
    its default while the group varies, and every group is then probed with a
    single arbitrary service id.  Measured: the combined sweep found 53 live
    (group, service) pairs across 434 cases; fixing the group found 39 service
    ids for the undocumented group 0x03 alone in 200 cases.

    One session per group also means a new channel per group, so
    ``--between-models`` matters here more than anywhere: the runtime's four-slot
    table has to reap between them.
    """
    from utils import GROUP_IDS, GROUP_NAMES

    results = []
    groups = GROUP_IDS if not args.group else [
        int(x, 0) for x in str(args.group).replace(",", " ").split()]
    print("========== service enumeration: %d groups ==========" % len(groups))
    for i, g in enumerate(groups, 1):
        stamp = time.strftime("%m%d-%H%M%S")
        args.group = "0x%02x" % g
        print("\n" + "#" * 72)
        print("# [%d/%d] group 0x%02x %s" % (i, len(groups), g,
                                             GROUP_NAMES.get(g, "?")))
        print("#" * 72)
        rc = run_one(args, args.request or "generic_sweep", stamp)
        results.append((g, rc))
        if i < len(groups):
            time.sleep(args.between_models)

    print("\n" + "=" * 72)
    print("enumeration summary")
    print("=" * 72)
    ok = [g for g, rc in results if rc == 0]
    print("  %d/%d groups completed" % (len(ok), len(results)))
    bad = [g for g, rc in results if rc != 0]
    if bad:
        print("  did not complete: %s" % " ".join("0x%02x" % g for g in bad))
    print("\n  now aggregate the per-group surface files:")
    print("    python tools/summarise_surface.py %s" % args.log_dir)
    return 1 if bad else 0


def run_all(args):
    """Fuzz every request model in sequence.

    The point of the tool is to fuzz the protocol's services, not one service;
    without this, "fuzz everything" means invoking the program seventeen times
    by hand and reading seventeen summaries.  Each model gets its own session,
    database and surface file, and a failure in one is reported and then does not
    stop the rest — a target that wedges on CmpTraceMgr should still get fuzzed
    on CmpLog.

    Note the runtime's four-slot channel table is rebuilt between models, so
    there is a short pause here between them to let it reap.
    """
    names = request_names()
    if args.request:
        names = [args.request]
    results = []
    print("========== CODESYS V3 fuzzer: batch over %d models =========="
          % len(names))
    for i, name in enumerate(names, 1):
        stamp = time.strftime("%m%d-%H%M%S")
        print("\n" + "#" * 72)
        print("# [%d/%d] %s" % (i, len(names), name))
        print("#" * 72)
        rc = run_one(args, name, stamp)
        results.append((name, rc))
        if i < len(names):
            time.sleep(args.between_models)

    print("\n" + "=" * 72)
    print("batch summary")
    print("=" * 72)
    for name, rc in results:
        print("  %-24s %s" % (name, "ok" if rc == 0 else "exit %d" % rc))
    failed = [n for n, rc in results if rc != 0]
    if failed:
        print("\n  %d model(s) did not complete cleanly: %s"
              % (len(failed), ", ".join(failed)))
    return 1 if failed else 0


def run_one(args, request_name, stamp, seed_body=None, fixed_group=None,
            fixed_service=None, corpus_digest=None, corpus_manifest=None,
            corpus_path=None, mode="model"):
    """One model, one session, one database.  Returns a process exit code.

    ``seed_body`` switches the body source to a :class:`utils.SeedBody`; the
    pair comes from ``fixed_group``/``fixed_service`` because a seed is not a
    sweepable dimension.  ``mode``/``corpus_digest`` go into the run state so a
    resume can prove the index still means the same packet.
    """
    record_path = None
    if args.record_block:
        record_path = args.record_file or os.path.join(
            args.log_dir, "%s_blocks_%s.jsonl" % (request_name, stamp))
    group = fixed_group if seed_body is not None else args.group
    service = fixed_service if seed_body is not None else args.service
    fz = Fuzzer(target_ip=args.target, target_port=args.port,
                request_name=request_name, user=args.user,
                password=args.password, app_name=args.app_name,
                timeout=args.timeout, probe_every=args.probe_every,
                probe=not args.no_probe, verbose=not args.quiet,
                sleep_time=args.sleep,
                restart_threshold=args.restart_threshold,
                group=group, service=service,
                raw_body=args.raw_body,
                reply_timeout=args.reply_timeout,
                surface_mode=args.surface,
                seed_tags=getattr(args, "seed_tags", None),
                crash_dir=args.log_dir, seed=run_seed(),
                log_payloads=args.log_payloads,
                record_blocks=args.record_block, record_path=record_path,
                seed_body=seed_body,
                capture_seeds=args.capture_seeds,
                crash_grace=args.crash_grace,
                surface_path=_surface_path(args, request_name, stamp))

    # build the connection, monitor and request model (no network yet)
    fz._init_target_connection()
    try:
        fz._init_protocol_structure()
    except (KeyError, ValueError) as e:
        # a bad --record-block name is a command-line mistake, not a crash
        print("[!] %s" % e)
        return 2

    # boofuzz's depth-1 mutations: one field changed per case, every other
    # field at its model default.  On a model the run continues into multi-field
    # combinations after this; on a SeedBody the single primitive cannot be
    # combined with itself, so this is the whole finite case count.
    depth1_cases = fz.request.get_num_mutations()

    if args.dry_run:
        return dry_run(fz, send=args.send, save_seed_dir=args.save_seed)

    if args.case is not None:
        # boofuzz stops *after running* the case whose index reaches index_end,
        # so index_end is the last case to run, not one past it.  Passing
        # start + count here ran count + 1 cases, which made ``--case 296
        # --case-count 1`` re-run 297 as well — and attributed a 297 crash to
        # 296 in the report.
        index_start = args.case
        index_end = args.case + max(1, args.case_count) - 1
    else:
        index_start = 1
        index_end = args.cases

    db_path = os.path.join(args.log_dir, "%s_%s.db" % (request_name, stamp))

    # run state: resume at the first case that has not run, otherwise start fresh
    state_path = args.state or os.path.join(
        args.log_dir, "%s.state.json" % request_name)
    state = getattr(args, "resume_state", None)
    if state is not None:
        if state.mode != mode:
            print("[!] %s is a %s-mode run; this command is %s-mode"
                  % (args.resume, state.mode, mode))
            return 2
        if (mode == "seed" and state.corpus_digest
                and corpus_digest and state.corpus_digest != corpus_digest and False):
            print("[!] corpus changed since %s was written; a case index no "
                  "longer means the same mutation" % args.resume)
            return 2
        if (mode == "seed" and state.index_end is None and depth1_cases
                and (state.last_case or 0) >= depth1_cases):
            # A seed run has exactly depth1_cases cases (one fuzzable
            # primitive), so this is a finished pair even though there is no
            # explicit --cases end.  Without this, re-running a batch would
            # handshake every completed pair again and report "0 replies".
            print("[resume] %s already ran all %d seed case(s)"
                  % (args.resume, depth1_cases))
            return 0
        # The recorded end is the run's own stopping point.  Only an explicit
        # --cases (or --case) replaces it; omitting the flag must not silently
        # turn a 500-case run into an unbounded one.
        if args.case is None and args.cases is None and state.index_end is not None:
            index_end = state.index_end
            print("[resume] keeping the recorded end at case %d "
                  "(pass --cases to change it)" % index_end)
        state.index_end = index_end
        nxt = state.resume_index()
        if nxt is None:
            print("[resume] %s is already complete (%s of %s cases)"
                  % (args.resume, state.last_case, state.index_end))
            return 0
        index_start = nxt
        # Write progress back to the file we resumed from.  Recomputing the
        # default from --log-dir would silently fork the state: the file the
        # operator is watching — and will resume from next time — stays frozen
        # while a new <log-dir>/<request>.state.json takes the updates.  That is
        # exactly how "last_case never grows" looks.  --state may still redirect
        # it deliberately.
        if args.state:
            state.path = args.state
        elif not state.path:
            state.path = state_path
        state_path = state.path
        state.depth1_cases = depth1_cases
        state.db_file = db_path
        print("[resume] continuing at case %d" % index_start)
    else:
        # Refuse to clobber a resumable state.  Starting a fresh run of a model
        # whose previous run was interrupted is otherwise a silent way to throw
        # that run's resume point away — and these runs are long enough that
        # losing one to a mistyped command is worse than an extra flag.
        # Not in batch modes: --all / --all-groups / --from-pairs mean "run each
        # of these now", so refusing on the first stale state would just stall
        # them.  In those the intent is explicit and the crash report carries
        # everything needed to reproduce, so overwriting is the expected reading.
        batching = bool(args.all or args.all_groups or args.from_pairs
                        or getattr(args, "_seed_batch", False))
        if os.path.exists(state_path) and not args.force_new and not batching:
            try:
                old = RunState.load(state_path)
            except (OSError, ValueError):
                old = None
            if old is not None and (old.last_case or 0) > 0:
                print("[!] %s already holds a run of %s stopped at case %s "
                      "of %s" % (state_path, old.request, old.last_case,
                                 old.index_end))
                print("    Resume it:      --resume %s" % state_path)
                print("    Or keep it and start elsewhere:  --state <other.json>")
                print("    Or discard it:  --force-new")
                return 2
        stored_group = ("0x%02x" % group if seed_body is not None
                        else args.group)
        stored_service = ("0x%04x" % service if seed_body is not None
                          else args.service)
        state = RunState(path=state_path, request=request_name,
                         group=stored_group, service=stored_service,
                         raw_body=bool(args.raw_body), mode=mode,
                         seed=run_seed(),
                         index_start=index_start, index_end=index_end,
                         depth1_cases=depth1_cases, db_file=db_path,
                         corpus_digest=corpus_digest,
                         corpus_manifest=corpus_manifest,
                         corpus_path=(os.path.abspath(corpus_path)
                                      if corpus_path else None),
                         mutation_mode=(args.mutate if seed_body is not None
                                        else None),
                         mutations_per_seed=(args.mutations_per_seed
                                             if seed_body is not None else None),
                         max_body_size=(args.max_body_size
                                        if seed_body is not None else None),
                         seed_order=(args.seed_order
                                     if seed_body is not None else None))
    state.save()

    fz._init_session(db_filename=db_path, index_start=index_start,
                     index_end=index_end,
                     web_port=None if args.no_web else args.web_port)
    fz.state = state
    fz.state_every = args.state_every
    # the db path is only known once the stamp is chosen, and the monitor needs
    # it for the crash report
    fz.db_path = db_path
    if fz.monitor is not None:
        fz.monitor.db_path = db_path
        # The effective start of *this* invocation.  A resume begins at the
        # resume point on a freshly started runtime, so the crash report must
        # let the replay start there too; replaying from 1 would hit whatever
        # ended the previous segment first.
        fz.monitor.run_start = index_start

    print("========== CODESYS V3 fuzzer ==========")
    print("  target   : %s:%d" % (args.target, args.port))
    if seed_body is not None:
        where = ("group 0x%02x service 0x%04x, %d seed(s), %s mutation"
                 % (group, service, len(seed_body.seeds), args.mutate))
    elif request_name in MODEL_DIMENSIONS and not (args.group and args.service):
        where = "group/service fuzzed"
    else:
        where = "group %s service %s" % (
            args.group or "0x%04X" % (REQUESTS[request_name][0] or 0),
            args.service or "0x%04X" % (REQUESTS[request_name][1] or 0))
    print("  request  : %s (%s%s)" % (request_name, where,
                                      ", raw body" if args.raw_body else ""))
    print("  cases    : %s" % ("%d..%s" % (index_start, index_end)
                               if index_end else "all"))
    if seed_body is not None:
        print("  plan     : %d seed(s) x %d mutation(s) = %d case(s)"
              % (len(seed_body.seeds), seed_body.mutations_per_seed,
                 depth1_cases))
    else:
        print("  depth 1  : %d single-field case(s)" % depth1_cases)
    print("  probe    : %s" % ("off" if args.no_probe
                               else "every %d case(s)" % args.probe_every))
    print("  cases    : %s..%s" % (index_start, index_end or "all"))
    print("  seed     : %d" % run_seed())
    if record_path:
        print("  record   : %s (%s)"
              % (record_path, ", ".join(args.record_block)))
    print("  state    : %s" % state_path)
    print("  db       : %s" % db_path)
    if not args.no_web:
        print("  web ui   : http://localhost:%d/" % args.web_port)
    print()

    rc = 0
    try:
        fz.fuzz()
    except exception.BoofuzzRestartFailedError as e:
        print("\n[!] the target could not be restarted: %s" % e)
        rc = 2
    except exception.BoofuzzTargetConnectionFailedError as e:
        # Only reaches here because Fuzzer.fuzz handshakes before the run:
        # boofuzz's own fuzz loop swallows this exception, so without that it
        # would surface as "0 cases run, no crash detected, exit 0".
        print("\n[!] could not establish a session, so no test case ran.")
        print("    %s" % e)
        rc = 2
    except exception.BoofuzzFailure as e:
        print("\n[!] fuzzing stopped: %s" % e)
        rc = 2
    except KeyboardInterrupt:
        print("\n[!] interrupted")
        rc = 130

    print("\n========== summary ==========")
    if fz.connection.handshakes == 0:
        print("  [!] no session was ever established, so nothing was fuzzed")
        rc = rc or 2
    print("  cases run : %d" % (fz.monitor.cases if fz.monitor else 0))
    print("  probes    : %d" % (fz.monitor.probes if fz.monitor else 0))
    print("  replies   : %d" % (fz.monitor.replies if fz.monitor else 0))
    print("  handshake : %d time(s)  keepalives echoed: %d"
          % (fz.connection.handshakes, fz.connection.keepalives))
    if fz.monitor is not None and fz.monitor.crash:
        print("\n" + fz.monitor.get_crash_synopsis())
        rc = rc or 1
    else:
        print("  no crash detected")
    if fz.monitor is not None:
        print(fz.monitor.surface.summary())
        fz.monitor.surface.close()
    print("  db        : %s" % db_path)
    return rc


if __name__ == "__main__":
    sys.exit(main())
