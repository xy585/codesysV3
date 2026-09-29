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
from proto import TCP_PORT
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
    if not args.request and not args.all and not args.all_groups             and not args.from_pairs:
        ap.error("--request is required (or --all / --all-groups / --from-pairs "
                 "/ --list-requests)")

    if not os.path.isdir(args.log_dir):
        os.makedirs(args.log_dir, exist_ok=True)

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


def load_pairs(path, only="evidence"):
    """Read a pair file into [(group, service)], deduped, best verdict wins.

    A pair file is append-only lines and a pair may appear more than once (a
    later run can improve a verdict), so the last and best entry per pair is what
    counts.  ``evidence`` keeps anything that replied; ``implemented`` keeps only
    pairs whose reply carried content, which — calibrated against
    CmpTraceMgr's ``trace_list`` — is what a service that really exists looks
    like.
    """
    rank = {"accepted": 4, "replied": 3, "refused": 2, "empty": 1}
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
            if only == "implemented" and v not in ("replied", "accepted"):
                continue
            if v not in rank:
                continue
            key = (row["group"], row["service"])
            # a pair can appear more than once (a later run improves a verdict),
            # so the best entry wins rather than the last
            if key not in best or rank[v] > rank[best[key]]:
                best[key] = v
    return sorted((int(g, 16), int(s, 16)) for g, s in best)


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
    print("========== targeted fuzz: %d pair(s) from %s =========="
          % (len(pairs), args.from_pairs))
    results = []
    for i, (g, s) in enumerate(pairs, 1):
        model = model_for_pair(g, s)
        stamp = time.strftime("%m%d-%H%M%S")
        print("\n" + "#" * 72)
        print("# [%d/%d] group 0x%02x service 0x%04x  %s"
              % (i, len(pairs), g, s,
                 "model %s" % model if model else "generic body (no model)"))
        print("#" * 72)
        saved = (args.request, args.group, args.service, args.raw_body)
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
            args.request, args.group, args.service, args.raw_body = saved
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
                surface_path=_surface_path(args, request_name, stamp))

    # build the connection, monitor and request model (no network yet)
    fz._init_target_connection()
    fz._init_protocol_structure()

    if args.dry_run:
        return dry_run(fz, send=args.send)

    if args.case is not None:
        index_start, index_end = args.case, args.case + args.case_count
    else:
        index_start = 1
        index_end = args.cases

    db_path = os.path.join(args.log_dir, "%s_%s.db" % (request_name, stamp))

    fz._init_session(db_filename=db_path, index_start=index_start,
                     index_end=index_end,
                     web_port=None if args.no_web else args.web_port)

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
    print("  probe    : %s" % ("off" if args.no_probe
                               else "every %d case(s)" % args.probe_every))
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
