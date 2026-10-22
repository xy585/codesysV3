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
import sys
import time

from boofuzz import exception
from boofuzz.mutation_context import MutationContext

from fuzzer import Fuzzer
from runstate import RunState
from proto import TCP_PORT
from utils import run_seed, set_run_seed
from services import MODEL_DIMENSIONS, REQUESTS, request_names


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


def dry_run(fz, send=False):
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
        if body is None:
            print("[?] no reply.  An unmutated request should be answered — a "
                  "silent drop suggests the framing is wrong.")
            return 1
        if body == b"":
            print("[+] the runtime closed the channel instead of answering: it "
                  "did not accept the packet.")
            return 1

        from proto import parse_services, parse_tags, status_of
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
            return 1
        if status == 0:
            print("[+] accepted: the runtime answered with status 0.")
            return 0
        if status is None:
            print("[+] accepted: the runtime answered, and this service sends no "
                  "status tag (0xFF7F).")
            return 0
        print("[i] the request parsed (it was answered) but was refused with "
              "status %s — the framing is sound, the payload needs adjusting."
              % status)
        return 0
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
                         "recorded seed, instead of repeating what already ran")
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
                    help="probe the runtime for liveness every N cases.  A "
                         "broken session is always probed regardless, and a "
                         "reply already proves liveness, so probing every case "
                         "just adds a TCP connect per case")
    ap.add_argument("--no-probe", action="store_true",
                    help="disable the liveness probe (rely on connection errors)")
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
  body to every other component's handler.""")
        return 0

    if not args.target:
        ap.error("a target address is required (or use --list-requests)")
    if args.record_file and not args.record_block:
        ap.error("--record-file has nothing to record without --record-block")
    # --resume can supply the request, so it must not be required up front
    if not args.request and not args.all and not args.all_groups             and not args.from_pairs and not args.resume:
        ap.error("--request is required (or --all / --all-groups / --from-pairs "
                 "/ --resume / --list-requests)")

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
        clash = resume_state.conflicts_with(args.request, args.group,
                                           args.service, args.raw_body or None)
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
        print("[resume] %s" % resume_state.describe())

    # one seed per run, recorded so the run can be repeated
    seed = set_run_seed(args.seed if args.seed is not None
                        else (resume_state.seed if resume_state else
                              run_seed()))
    print("[seed] %d  (pass --seed %d to reproduce this run exactly)"
          % (seed, seed))

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


def run_one(args, request_name, stamp):
    """One model, one session, one database.  Returns a process exit code."""
    record_path = None
    if args.record_block:
        record_path = args.record_file or os.path.join(
            args.log_dir, "%s_blocks_%s.jsonl" % (request_name, stamp))
    fz = Fuzzer(target_ip=args.target, target_port=args.port,
                request_name=request_name, user=args.user,
                password=args.password, app_name=args.app_name,
                timeout=args.timeout, probe_every=args.probe_every,
                probe=not args.no_probe, verbose=not args.quiet,
                sleep_time=args.sleep,
                restart_threshold=args.restart_threshold,
                group=args.group, service=args.service,
                raw_body=args.raw_body,
                reply_timeout=args.reply_timeout,
                surface_mode=args.surface,
                seed_tags=getattr(args, "seed_tags", None),
                crash_dir=args.log_dir, seed=run_seed(),
                log_payloads=args.log_payloads,
                record_blocks=args.record_block, record_path=record_path,
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
    # field at its model default.  The run continues into multi-field
    # combinations after this, so this is the finite count worth recording.
    depth1_cases = fz.request.get_num_mutations()

    if args.dry_run:
        return dry_run(fz, send=args.send)

    if args.case is not None:
        index_start, index_end = args.case, args.case + args.case_count
    else:
        index_start = 1
        index_end = args.cases

    db_path = os.path.join(args.log_dir, "%s_%s.db" % (request_name, stamp))

    # run state: resume at the first case that has not run, otherwise start fresh
    state_path = args.state or os.path.join(
        args.log_dir, "%s.state.json" % request_name)
    state = getattr(args, "resume_state", None)
    if state is not None:
        nxt = state.resume_index()
        if nxt is None:
            print("[resume] %s is already complete (%s of %s cases)"
                  % (args.resume, state.last_case, state.index_end))
            return 0
        index_start = nxt
        state.path = state_path
        state.index_end = index_end
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
        batching = bool(args.all or args.all_groups or args.from_pairs)
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
        state = RunState(path=state_path, request=request_name,
                         group=args.group, service=args.service,
                         raw_body=bool(args.raw_body), seed=run_seed(),
                         index_start=index_start, index_end=index_end,
                         depth1_cases=depth1_cases, db_file=db_path)
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

    print("========== CODESYS V3 fuzzer ==========")
    print("  target   : %s:%d" % (args.target, args.port))
    if request_name in MODEL_DIMENSIONS and not (args.group and args.service):
        where = "group/service fuzzed"
    else:
        where = "group %s service %s" % (
            args.group or "0x%04X" % (REQUESTS[request_name][0] or 0),
            args.service or "0x%04X" % (REQUESTS[request_name][1] or 0))
    print("  request  : %s (%s%s)" % (request_name, where,
                                      ", raw body" if args.raw_body else ""))
    print("  cases    : %s" % ("%d..%s" % (index_start, index_end)
                               if index_end else "all"))
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
