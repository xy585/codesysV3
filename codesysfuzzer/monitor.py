#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Crash detection for the CODESYS runtime.

boofuzz's contract is simple: a monitor whose ``post_send`` returns ``False``
marks the test case as crashing, and ``get_crash_synopsis`` supplies the report.
So the whole job here is deciding *when* the runtime is dead.

Two checks, not one.  The per-case probe runs on a cadence (``probe_every``)
and after a broken session; :meth:`CodesysMonitor.check_liveness` runs again
once the fuzz loop has stopped.  The second one exists because a run ends at
its configured index, not on a cadence boundary: without it, a crash among the
last ``probe_every - 1`` cases — which is where the whole of a single-case
reproduction lives — would finish the run reporting "no crash detected".

The probe is a short-timeout TCP connect to the block driver port.  If nothing
answers, the process is gone — that is the signal this fuzzer is built around,
and it is the reason the transport is TCP rather than UDP: CmpBlkDrvTcp gets a
reset, which is unambiguous, where a lost UDP datagram is indistinguishable from
a lost packet.

What the probe does *not* catch: a runtime that is hung, deadlocked or otherwise
wedged while still holding the listening socket looks alive.  Distinguishing that
needs an in-guest check (a process monitor, or the IDE), which is out of scope
here.  Budget a few probes per second at most: each one is a full TCP handshake
to the same service the fuzzer is hammering.
"""

import collections
import json
import os
import struct
import time

from boofuzz.monitors.base_monitor import BaseMonitor

from corpus import write_seed
from proto import (
    BD_MAGIC, parse_channel, parse_datagram, parse_services, parse_tags,
    status_of,
)


def parse_sent_parts(data):
    """``(group, service, body)`` for a sent request, or ``(None, None, None)``.

    Needed because in a sweep the ids that went out are the *mutated* ones, not
    the model's defaults — reading them back off the wire is simpler and more
    trustworthy than threading the mutation context through.

    The body is reassembled across every ``blk_first``/``blk_cont`` frame.  A
    mutated body can be several KB, and a caller capturing it as a seed or
    replaying it needs all of it, not the first frame's 468 bytes.
    """
    if not data or len(data) < 8 + 20:
        return None, None, None
    position = 0
    buffer = bytearray()
    declared = None
    try:
        while position + 8 <= len(data):
            magic, length = struct.unpack_from("<II", data, position)
            if (magic != BD_MAGIC or length < 8
                    or position + length > len(data)):
                break
            dg = parse_datagram(data[position + 8:position + length])
            if dg is None:
                break
            ch = parse_channel(dg["payload"])
            kind = ch.get("type")
            if kind == "blk_first":
                declared = ch.get("data_size") or 0
                buffer = bytearray(ch["data"])
            elif kind == "blk_cont" and declared is not None:
                buffer.extend(ch["data"])
            else:
                position += length
                continue
            position += length
            if declared is not None and len(buffer) >= declared:
                break
        if declared is None:
            return None, None, None
        hdr, body = parse_services(bytes(buffer[:declared]))
        return hdr["group"], hdr["service_id"], body
    except (ValueError, struct.error, KeyError, IndexError):
        return None, None, None


def parse_sent(data):
    """``(group, service)`` for a sent frame, or ``(None, None)``."""
    group, service, _body = parse_sent_parts(data)
    return group, service


def body_seed_tags(sent, limit=24):
    """The tag structure a *sent* request carried, as a nested wire-id tree.

    This is the difference between a pair file that says "0x12/0x39 answered"
    and one that says "0x12/0x39 answered when the body carried container 0x81
    holding tags 0x11 and 0x18".  The second is a usable seed: it is the only
    evidence available about what that service's parser accepts, and it is what
    lets a later run for the same pair stop sending unstructured bytes.

    **A flat list of ids will not do.**  ``parse_tags`` masks bit 7 off a tag id,
    so container ``0x81`` is reported as id ``0x01`` — and rebuilding from that
    would emit ``0x01`` as a leaf, producing a body the handler never walks into.
    So the nesting is preserved and the id is restored to its *wire* form
    (container ids carry bit 7), which is what has to be written back out.

    Returns ``[{"id": int, "children": [...]}, ...]``.
    """
    _g, _s, body = parse_sent_parts(sent)
    if not body:
        return []
    budget = [limit]

    def walk(tags):
        out = []
        for t in tags:
            if budget[0] <= 0:
                break
            budget[0] -= 1
            wire = (t["id"] | 0x80) if t["children"] else t["id"]
            out.append({"id": wire,
                        "children": walk(t["children"]) if t["children"] else []})
        return out

    try:
        return walk(parse_tags(body))
    except ValueError:
        return []


def _hex_tree(nodes):
    """The tree with ids as hex strings, so the file stays readable."""
    return [{"id": "0x%02x" % n["id"], "children": _hex_tree(n["children"])}
            for n in nodes]


class SurfaceRecorder(object):
    """Records which (group, service) pairs the runtime actually answers.

    A sweep sends ids nobody has modelled, and the runtime's reply is what says
    whether that pair is real.  Three outcomes carry different information:

        accepted   replied, status 0 or no status tag  -> the pair exists and the
                   body was acceptable
        refused    replied, non-zero status            -> the pair exists; the
                   arguments were rejected.  This is the more interesting one:
                   it separates "no such service" from "that service, wrong
                   request", and it is the state a vulnerable handler is in
                   right before it is driven with the right shape.
        no-reply   nothing came back                   -> dropped earlier: not a
                   service, or the packet was rejected before dispatch.

    Only the first two are evidence of a live dispatch path, so those are what
    get logged and summarised; every case goes to the JSONL file regardless, so
    the run can be mined afterwards.
    """

    def __init__(self, path=None, verbose=True, mode="global"):
        """``mode`` decides what the file means.

        ``global``   one cumulative record of the (group, service) pairs this
                     runtime answers, shared across runs.  A pair is written the
                     first time it is seen and then not again — so successive
                     runs against the same target extend the file instead of
                     repeating it, which is what makes it usable as the input to
                     ``--from-pairs``.  Existing pairs are loaded at startup so a
                     re-run does not re-emit them.
        ``separate`` one file per run, for when a run's own findings are wanted
                     in isolation.
        ``off``      no file at all.
        """
        self.path = path if mode != "off" else None
        self.mode = mode
        self.verbose = verbose
        self.fh = None                       # opened on first write, never before
        self.written = 0
        self.tally = {}         # (group, service) -> Counter of verdicts
        self.seen = {}          # (group, service) -> verdict
        self.status = {}        # (group, service) -> last status seen
        self.counts = {"accepted": 0, "refused": 0, "replied": 0, "empty": 0,
                       "no-reply": 0, "unparsed": 0, "incomplete": 0}
        if mode == "global" and self.path and os.path.exists(self.path):
            self._load_known()

    #: verdicts that are evidence a service exists, best last
    RANK = {"no-reply": 0, "unparsed": 0, "incomplete": 0, "empty": 1,
            "refused": 2, "replied": 3, "accepted": 4}

    def _load_known(self):
        """Pairs already in the file, so a re-run does not repeat them."""
        n = 0
        try:
            with open(self.path, encoding="utf-8") as fh:
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
                    # keys are (int, int) everywhere else — parse_sent returns
                    # ints — so a string key here would never match and the
                    # dedup would silently do nothing while looking correct
                    key = (int(row["group"], 16), int(row["service"], 16))
                    v = row.get("verdict", "no-reply")
                    if self.RANK.get(v, 0) >= self.RANK.get(self.seen.get(key), 0):
                        self.seen[key] = v
                        self.status[key] = row.get("status")
                    n += 1
        except OSError:
            return
        if n and self.verbose:
            print("[surface] %d known pair(s) loaded from %s" % (n, self.path))

    def _ensure_open(self):
        """Create the file only when there is something to put in it.

        Opening eagerly leaves a zero-byte file behind whenever a run finds
        nothing, or whenever a target is down — and a directory of empty files
        is indistinguishable from one of runs that found nothing.
        """
        if self.fh is None and self.path:
            d = os.path.dirname(self.path)
            if d:
                os.makedirs(d, exist_ok=True)
            self.fh = open(self.path, "a", encoding="utf-8")
        return self.fh

    def record(self, case, sent, reply_body, complete=True):
        if not complete:
            # Not evidence either way: the reply was cut short, so it says
            # nothing about whether the pair is live.  Counting it would put
            # phantom entries in the surface map.
            self.counts["incomplete"] += 1
            if self.fh is not None:
                self.fh.write(json.dumps(
                    {"case": case, "verdict": "incomplete"}) + "\n")
                self.fh.flush()
            return None
        return self._record(case, sent, reply_body)

    def _record(self, case, sent, reply_body):
        # The pair that was *sent* is the authoritative key — it is what the
        # fuzzer chose.  The reply is only consulted for the verdict.
        group, service = parse_sent(sent)
        if group is None:
            self.counts["unparsed"] += 1
            return None

        status = None
        mismatch = False
        empty = False
        if reply_body:
            try:
                hdr, body = parse_services(reply_body)
                empty = (hdr["content_size"] == 0 and len(body) == 0)
                # The reply marks itself by setting bit 7 of the group, not bit
                # 15: a request to group 0x000f is answered from 0x008f.  All
                # real group ids are below 0x80, so the bit is unambiguous —
                # but masking with 0x7fff (bit 15) leaves it set, which records
                # phantom groups like 0x008f.
                reply_group = hdr["group"] & 0xFF7F
                status = status_of(parse_tags(body))
                mismatch = (reply_group != group
                            or hdr["service_id"] != service)
            except (ValueError, KeyError):
                status = None
            # Say only what the reply proves.  A status tag is authoritative.
            # Without one, a reply that carries *content* is an answer of some
            # kind (trace_list succeeds exactly this way, with no status tag at
            # all) but not proof of acceptance, so it is labelled "replied".
            # An empty reply is the opposite of acceptance: the runtime declined
            # to act.  Treating "no status tag" as success is what produced a
            # surface map claiming 396 of 434 pairs were accepted.
            if status == 0:
                verdict = "accepted"
            elif status is not None:
                verdict = "refused"
            elif empty:
                verdict = "empty"
            else:
                verdict = "replied"
        else:
            verdict = "no-reply"

        self.counts[verdict] += 1
        key = (group, service)
        self.tally.setdefault(key, collections.Counter())[verdict] += 1
        previous = self.seen.get(key)
        # keep the most informative verdict for a pair: a refusal proves the
        # dispatch path exists, a later no-reply does not disprove it
        if previous is None or (previous == "no-reply" and verdict != "no-reply"):
            self.seen[key] = verdict
            self.status[key] = status

        is_new = previous is None and verdict != "no-reply"
        if mismatch and self.verbose:
            print("[!] reply did not echo the request: sent group 0x%04x "
                  "service 0x%04x" % (group, service))

        # A *pair* is recorded, not a case.  Two reasons: a run produces hundreds
        # of cases over a handful of pairs, and what the next run needs is the
        # pair list, not the history.  Nothing is written for a pair that has
        # produced no reply, and in ``global`` mode nothing is written for a pair
        # already in the file — so repeated runs extend it rather than repeat it.
        improved = (self.RANK.get(verdict, 0)
                    > self.RANK.get(previous or "", 0))
        # The tag ids the request carried.  This is what turns "0x12/0x39
        # answered" into "0x12/0x39 answered when the body carried tags 0x11 and
        # 0x18" — the only evidence available about what that parser accepts, and
        # what lets a later run for the same pair send a shaped body instead of
        # garbage.  Recorded only for replies that are evidence, because for a
        # dropped packet the body says nothing about what was accepted.
        seeds = body_seed_tags(sent) if verdict in ("replied", "accepted") else []
        row = {"group": "0x%04x" % group, "service": "0x%04x" % service,
               "verdict": verdict, "status": status,
               "first_seen": time.strftime("%Y-%m-%dT%H:%M:%S")}
        if seeds:
            row["tag_tree"] = _hex_tree(seeds)
        # How the cases for this pair actually split.  The row records the *best*
        # verdict, so a pair that replied once and was refused twenty times would
        # otherwise look as healthy as one that replied every time — and the
        # reader has no way to tell.  One counter makes that visible.
        tally = self.tally.get(key)
        if tally and len(tally) > 1:
            row["verdicts"] = dict(tally)
        elif tally:
            row["cases"] = sum(tally.values())
        worth_writing = (verdict != "no-reply"
                         and (is_new or (self.mode == "global" and improved)))
        if worth_writing:
            fh = self._ensure_open()
            if fh is not None:
                fh.write(json.dumps(row) + "\n")
                fh.flush()
                self.written += 1
        row["new"] = is_new
        row["case"] = case
        return row

    @property
    def live_pairs(self):
        """Pairs the runtime demonstrably dispatched, best verdict first."""
        order = {"accepted": 0, "refused": 1, "replied": 2, "empty": 3}
        return sorted(((g, s, v, self.status.get((g, s)))
                       for (g, s), v in self.seen.items() if v != "no-reply"),
                      key=lambda r: (order.get(r[2], 9), r[0], r[1]))

    def summary(self):
        live = self.live_pairs
        lines = ["", "========== service surface discovered ==========",
                 "  cases   : accepted %d, refused %d, replied %d, empty %d, "
                 "no-reply %d, incomplete %d"
                 % (self.counts["accepted"], self.counts["refused"],
                    self.counts["replied"], self.counts["empty"],
                    self.counts["no-reply"], self.counts["incomplete"]),
                 "  live (group, service) pairs: %d" % len(live)]
        if live:
            lines.append("")
            lines.append("  %-8s %-9s %-9s %s" % ("group", "service", "verdict",
                                                   "last status"))
            for g, s, v, st in live:
                lines.append("  0x%04x   0x%04x    %-9s %s" % (g, s, v, st))
        lines.append("")
        if self.wrote_file:
            lines.append("  pair record: %s (%d pair(s) written this run, %d total)"
                         % (self.path, self.written, len(self.seen)))
        elif self.mode == "off":
            lines.append("  pair record: disabled (--surface off)")
        else:
            lines.append("  pair record: nothing written (no pair replied)")
        return "\n".join(lines)

    def close(self):
        if self.fh is not None:
            self.fh.close()
            self.fh = None

    @property
    def wrote_file(self):
        """Whether anything was actually written — the file may not exist."""
        return self.written > 0 and self.path and os.path.exists(self.path)


class CodesysMonitor(BaseMonitor):
    """Liveness probe + crash report, with restart left to the operator.

    ``start_target`` returns False deliberately.  Restarting a CODESYS runtime
    means starting a Windows service or reverting a VM, neither of which this
    process can assume; when a crash is found boofuzz stops the run, records the
    case and reports, and the operator brings the runtime back for the next pass.
    """

    def __init__(self, connection, probe_every=1, enabled=True, verbose=False,
                 surface_path=None, reply_timeout=2.0, surface_mode="global",
                 crash_dir=None, request_name=None, target=None, seed=None,
                 db_path=None, seed_body=None, capture_seeds=None,
                 crash_grace=10.0):
        super().__init__()
        self.connection = connection
        self.probe_every = max(1, probe_every)
        self.enabled = enabled
        self.verbose = verbose
        self.surface = SurfaceRecorder(path=surface_path, verbose=verbose,
                                       mode=surface_mode)
        self.crash_dir = crash_dir
        self.request_name = request_name
        self.target = target
        self.seed = seed
        self.db_path = db_path
        self.reply_timeout = reply_timeout
        #: set for seed-mode runs: used to recover the mutation plan behind a
        #: crash, and to know that the reproduce recipe is ``--replay``, not a
        #: case index.
        self.seed_body = seed_body
        #: directory that accepted bodies are copied into as candidate seeds
        self.capture_seeds = capture_seeds
        #: seconds to keep polling the listener after the run stops.  See
        #: ``check_liveness``: the crash can trail the request by a few seconds.
        self.crash_grace = max(0.0, crash_grace)

        self.cases = 0
        self.probes = 0
        self.replies = 0
        self.crash = None            # dict once a crash is detected
        self._last_send = None
        self._last_case_index = None
        #: the last few requests that actually went out, oldest first.  A
        #: delayed crash is first noticed after the packet that caused it, so
        #: the report needs the candidates, not just the detection point.  This
        #: is observation only: the fuzzer still sends nothing but its own
        #: mutated bodies, and no runtime state is touched.
        #: first case index of this invocation.  A resume is its own segment on
        #: a freshly started runtime, so a faithful replay starts here, not at
        #: case 1 (replaying from 1 would hit whatever crash ended the earlier
        #: segment first).
        self.run_start = 1
        self.recent = collections.deque(maxlen=10)

    # ------------------------------------------------------------
    # BaseMonitor
    # ------------------------------------------------------------
    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        """Read the reply, keep the channel healthy, decide whether it died.

        Reading has to happen here because the connection is reused and boofuzz
        is not reading (it cannot reassemble a framed reply).  Echoing the
        runtime's keepalives happens in the same call — skip it and the runtime
        closes a channel it has pinged too many times unanswered.
        """
        self.cases += 1
        if session is not None:
            last = getattr(session, "last_send", None)
            index = getattr(session, "total_mutant_index", None)
            # ``session.last_send`` is set by boofuzz *after* a successful
            # send.  When this case's send raised — which is exactly what
            # happens once the runtime is gone — it still holds the previous
            # case's bytes.  Pairing those bytes with this case's index is what
            # produced a crash report naming case 44 and carrying case 43's
            # body, so ``--replay`` sent the wrong packet and "did not
            # reproduce".  Identity, not equality: every render returns a new
            # bytes object, so the same object means no new send happened.
            if last is not None and last is not self._last_send:
                self._last_send = last
                self._last_case_index = index
                self.recent.append((index, last))

        if self.crash is not None:
            return True

        # let the transport know which case it is, so a break can name it
        self.connection.last_case = self._last_case_index
        # drain the reply even when probing is off: the channel depends on it
        body, complete = self.connection.service_reply(
            timeout=self.reply_timeout)
        # say it out loud when the session breaks: it costs a re-handshake, and
        # in a sweep that is the difference between a case being free and a case
        # costing a channel slot plus a backpressure wait
        if self.connection.broken and self.connection.break_reason:
            if fuzz_data_logger is not None:
                fuzz_data_logger.log_info("SESSION BROKEN: %s"
                                          % self.connection.break_reason)
            self.connection.break_reason = None
        self.replies += 1

        # A reply is evidence: in a sweep it is what says the group/service pair
        # is real, so accepted and (more often) refused answers are logged as
        # they are discovered rather than left implicit in the case database.
        row = self.surface.record(self._last_case_index, self._last_send, body,
                                  complete=complete)
        if row is not None and row["new"] and fuzz_data_logger is not None:
            fuzz_data_logger.log_info(
                "SERVICE SURFACE: group %s service %s -> %s%s"
                % (row["group"], row["service"], row["verdict"],
                   "" if row["status"] is None else " (status %s)" % row["status"]))
        elif (row is not None and row["verdict"] == "accepted"
                and fuzz_data_logger is not None):
            fuzz_data_logger.log_info(
                "VALID RESPONSE: group %s service %s accepted"
                % (row["group"], row["service"]))

        # Corpus feedback: a body the runtime answered is a new starting point
        # for the next seed-mutation run.  Written to ``candidates`` rather than
        # into the active corpus, because adding seeds mid-run would change the
        # case-index -> mutation mapping the run is resuming against.
        if (self.capture_seeds and row is not None
                and row["verdict"] in ("accepted", "replied")):
            group, service, sent_body = parse_sent_parts(self._last_send)
            if group is not None and sent_body:
                write_seed(os.path.join(self.capture_seeds, "candidates"),
                           group, service, sent_body,
                           source="case:%s:%s"
                                  % (self.request_name, self._last_case_index),
                           verdict=row["verdict"])

        if not self.enabled:
            return True
        # A broken session is the interesting case, so probe then regardless of
        # cadence; a healthy one is probed every Nth case to keep the overhead
        # off the hot path.
        #
        # A *silent* case is probed too, whatever the cadence.  That is the
        # only warning a stack-smash gives: the request is never answered, the
        # process then spends a moment dying, and probing right here is what
        # names the packet that did it.  Without this the death is first seen
        # at the end of the run and the report blames the last case sent —
        # measured: the real trigger was a tag-0x30 length lie three cases
        # before the one that got recorded, so --replay sent a harmless packet.
        silent = body is None and complete
        if (not self.connection.broken and not silent
                and self.cases % self.probe_every):
            return True

        self.probes += 1
        alive, why = self.connection.probe()
        if alive:
            return True

        self._set_crash(why)
        if fuzz_data_logger is not None:
            fuzz_data_logger.log_fail(
                "CODESYS runtime is gone after case %s: %s"
                % (self._last_case_index, why))
            if self.crash.get("files"):
                fuzz_data_logger.log_info("crash report written to %s.txt / .json"
                                          % self.crash["files"])
        return False

    def check_liveness(self, grace=None, interval=0.5):
        """Watch the listener for a while once the fuzz loop has stopped.

        The per-case probe is a *cadence* check (``probe_every``, default 50),
        and a run ends at its configured index, not at a cadence boundary.  So
        every case in the last ``probe_every - 1`` cases of a run — which is the
        whole ``--case 296 --case-count 1`` reproduction command — is never
        probed.  The run's own summary then says "no crash detected" about a
        runtime that is gone.  The same call covers the other silent exit: when
        a dead runtime makes the next case's handshake fail, boofuzz swallows
        ``BoofuzzTargetConnectionFailedError`` and the loop returns as if the
        run had completed normally.

        The watch is a *window*, not a single probe, because this crash is not
        synchronous with the request that triggers it: measured on
        ``trace_configure`` case 296, the runtime answered the request, kept
        the block-driver listener open while it processed the trace config,
        and only then died — after the run had already closed its channel.
        Three probes over two seconds all connected; the process was gone a
        few seconds later.  So keep polling until the grace window expires.

        Each poll is a bare TCP connect: no channel is allocated, nothing is
        sent, so a live runtime pays only an accept/close.  A refused connect
        is the crash signal — the whole process is gone, not just one handler.

        Returns True when the runtime survived the window (or there is nothing
        to check), False when *this* call is what found the crash.
        """
        if self.crash is not None or not self.enabled or self.cases == 0:
            return True
        if grace is None:
            grace = self.crash_grace
        deadline = time.monotonic() + max(0.0, grace)
        if self.verbose and grace > 0:
            print("[i] watching %s for a delayed crash for up to %gs"
                  % (self.connection.info, grace))
        while True:
            self.probes += 1
            alive, why = self.connection.probe()
            if not alive:
                self._set_crash("final probe after the run stopped: %s" % why)
                return False
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return True
            time.sleep(min(interval, remaining))

    def _set_crash(self, why):
        self.crash = {
            "case": self._last_case_index,
            "cases_run": self.cases,
            "reason": why,
            "when": time.strftime("%Y-%m-%d %H:%M:%S"),
            "send_len": len(self._last_send) if self._last_send else 0,
        }
        self._write_crash_files()
        return self.crash

    def _write_crash_files(self):
        """Land the crash on disk the moment it is detected.

        Written as soon as the probe fails rather than at the end of the run,
        because the interesting case is exactly the one where the run does not
        continue, and a report that only appears in a summary is a report that a
        killed process never writes.

        The raw bytes matter here specifically because **boofuzz's database
        truncates them**: its ``send`` steps are capped (measured at 512 bytes,
        flagged ``is_truncated``), so for anything larger than one datagram the
        database holds only the first frame.  This file is the authoritative
        copy of what was sent.
        """
        if not self.crash_dir or not self._last_send:
            return None
        stamp = time.strftime("%m%d-%H%M%S")
        base = os.path.join(self.crash_dir,
                            "%s_crash_%s" % (self.request_name or "run", stamp))
        struct = structured_request(self._last_send)
        case = self.crash.get("case")

        group, service, sent_body = parse_sent_parts(self._last_send)
        body_hex = sent_body.hex() if sent_body is not None else None
        plan = None
        seed_run = None
        if self.seed_body is not None:
            try:
                plan = self.seed_body.plan_for_case(case)
            except Exception:
                plan = None
            # The recorded case is the one whose send was being read when the
            # death was noticed.  A crash can trail its trigger by a few
            # requests, so the report also keeps the last few packets that went
            # out (below).  The corpus/parameters are kept for the optional
            # whole-prefix replay, not because the last body is useless.
            # The cap only exists so a pathological corpus (thousands of large
            # bodies) cannot bloat every report.
            if case is not None:
                seeds = self.seed_body.seeds
                if (len(seeds) <= 512
                        and sum(len(s.body) for s in seeds) <= (1 << 20)):
                    seed_run = {
                        "run_seed": self.seed_body.run_seed,
                        "mode": self.seed_body.mode,
                        "mutations_per_seed":
                            self.seed_body.mutations_per_seed,
                        "max_body_size": self.seed_body.max_body_size,
                        "order": self.seed_body.order,
                        "start": int(self.run_start or 1),
                        "cases": int(case),
                        "seeds": [{"group": "0x%04x" % s.group,
                                   "service": "0x%04x" % s.service,
                                   "body": s.body.hex()} for s in seeds],
                    }

        # The candidates: the last few requests that actually went out, oldest
        # first.  Pure recorded bytes — replay sends these, it does not build
        # anything.  One MiB is enough for the default ten bodies even when
        # some of them are multi-KB grow mutations.
        trail = []
        trail_bytes = 0
        for index, raw in self.recent:
            if raw is None:
                continue
            g, s, sent = parse_sent_parts(raw)
            if g is None or not sent:
                continue
            if trail_bytes + len(sent) > (1 << 20):
                break
            row = {"case": index, "group": "0x%04x" % g,
                   "service": "0x%04x" % s, "body_hex": sent.hex(),
                   # The full frame as it went on the wire, so a later
                   # --case-report can print the same "Raw bytes" section a
                   # crash report does.  The framing is per-connection (token,
                   # session id, block ids), but it is still the exact bytes
                   # that were sent, which is what a report should show.
                   "sent_hex": raw.hex()}
            if self.seed_body is not None:
                try:
                    row["seed_plan"] = self.seed_body.plan_for_case(index)
                except Exception:
                    row["seed_plan"] = None
            trail.append(row)
            trail_bytes += len(raw)

        if plan is not None:
            # A seed-mode case cannot be reproduced by index alone: the index
            # maps to a (seed, mutation) pair under a particular corpus.  The
            # report carries the corpus and the run parameters, so --replay
            # does not depend on the original corpus still being there.
            cmd = ("python codesysfuzzer/codesys_fuzzer.py %s --replay %s.json"
                   % (self.target or "<target>", base))
            cmd_replay =  ("python codesysfuzzer/codesys_fuzzer.py %s --replay %s.json --replay-case %s"
                   % (self.target or "<target>", base, int(case)-2))
        else:
            cmd = ("python codesysfuzzer/codesys_fuzzer.py %s -r %s --case %s "
                   "--seed %s --surface off --force-new"
                   % (self.target or "<target>", self.request_name or "<request>",
                      case, self.seed))

        lines = [
            "CODESYS V3 fuzzer - crash report",
            "=" * 68,
            "  when        : %s" % self.crash.get("when"),
            "  target      : %s" % (self.target or "?"),
            "  request     : %s" % (self.request_name or "?"),
            "  case        : %s   (boofuzz total_mutant_index)" % case,
            "  cases run   : %s" % self.crash.get("cases_run"),
            "  detector    : %s" % self.crash.get("reason"),
            "  request size: %d bytes as sent" % len(self._last_send),
            "  seed        : %s" % self.seed,
            "  database    : %s" % (self.db_path or "?"),
            "",
            "Reproduce",
            "-" * 68,
            "  %s" % cmd_replay if plan else cmd,
            "",
        ]
        if seed_run is not None:
            lines += [
                "  --replay sends the last body above (the packet that was on the",
                "  wire when the runtime died).  Detection is after the fact, so",
                "  the recent-packets list below is the better first stop when",
                "  this one does not reproduce.",
                "",
                "  This report also embeds the corpus and the run parameters.  To",
                "  re-send the whole segment this run covered:",
                "    %s --replay-prefix" % cmd,
                "  (cases %d..%d — a resumed run is its own segment on a fresh"
                % (int(seed_run.get("start") or 1), case),
                "  runtime, so the replay starts at the resume point, not at 1).",
            ]
        elif plan is not None:
            lines += [
                "  Warning: the corpus was too large to embed in this report, so",
                "  --replay can send only the last body.  If it does not reproduce,",
                "  re-run the original --from-seeds campaign with the same --seed",
                "  and corpus.",
            ]
        else:
            lines += [
                "  The seed is required: the random parts of a request come from",
                "  the run's seed, so the same case index with a different seed",
                "  sends different bytes.  --surface off keeps the replay out of",
                "  the pair file.  --force-new discards this run's resume point:",
                "  the crashed run left a state file, and the guard against",
                "  clobbering it would otherwise refuse the command.  Do not use",
                "  --resume instead: it continues at the next case and skips this",
                "  one.",
            ]
        lines += [
            "",
            "Structured request (group / service / tags)",
            "-" * 68,
        ]
        if struct:
            lines.append("  group 0x%04x  service 0x%04x"
                         % (struct["group"], struct["service"]))
            if "parse_error" in struct:
                lines.append("  body did not parse: %s" % struct["parse_error"])
                lines.append("  body hex: %s" % struct["body_hex"])
            else:
                lines.extend(_fmt_nodes(struct["body"], 1))
        else:
            lines.append("  (the sent frame did not parse as a services request)")
        if plan is not None:
            lines += [
                "",
                "Seed mutation",
                "-" * 68,
                "  corpus seed : %s" % plan.get("seed"),
                "  mode        : %s" % plan.get("mode"),
                "  stage       : %s" % plan.get("stage"),
                "  operations  : %s" % json.dumps(plan.get("ops"), sort_keys=True),
                "",
                "  The final body and (when it fits) the corpus are stored in the",
                "  JSON report, so --replay does not need the original corpus",
                "  directory to still exist.",
            ]
        if trail:
            lines += [
                "",
                "Recent packets, oldest first (candidates for the real trigger)",
                "-" * 68,
                "  the crash is noticed after the packet that caused it, so the",
                "  case above is the detection point, not necessarily the trigger",
                "",
                "  case   bytes  mutation",
            ]
            for row in trail:
                op = ""
                p = row.get("seed_plan")
                if p and p.get("ops"):
                    op = " ".join("%s %s" % (o.get("kind"), o.get("path"))
                                  for o in p["ops"])
                lines.append("  %-5s  %-5d  %s"
                             % (row["case"], len(row["body_hex"]) // 2, op))
            lines += [
                "",
                "  Send them one at a time, in order, keeping the run's pace:",
                "    %s --replay-trail" % cmd,
                "  or isolate a candidate:",
                "    %s --replay-case <case>" % cmd,
                "  (--replay-wait N inserts N seconds between packets; that can",
                "   suppress a timing-sensitive crash, so use it only when finer",
                "   attribution is worth changing the pacing.)",
                "",
                "  Once a case is confirmed, write it up like this report:",
                "    %s --case-report <case>" % cmd,
            ]
        lines += [
            "",
            "Raw bytes (block driver + datagram + channel frames + services)",
            "-" * 68,
            "  note: the sqlite database truncates this at 512 bytes; this file",
            "        does not, so it is the copy to keep",
            "",
            _hexdump(self._last_send, limit=len(self._last_send)),
            "",
        ]

        with open(base + ".txt", "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        with open(base + ".json", "w", encoding="utf-8") as fh:
            json.dump({
                "when": self.crash.get("when"),
                "target": self.target,
                "request": self.request_name,
                "case": case,
                "cases_run": self.crash.get("cases_run"),
                "detector": self.crash.get("reason"),
                "seed": self.seed,
                "group": "0x%04x" % group if group is not None else None,
                "service": "0x%04x" % service if service is not None else None,
                "body_hex": body_hex,
                "seed_plan": plan,
                "seed_run": seed_run,
                "recent": trail,
                "database": self.db_path,
                "reproduce_command": cmd,
                "sent_bytes": len(self._last_send),
                "sent_hex": self._last_send.hex(),
                "structured": struct,
            }, fh, indent=2)
        self.crash["files"] = base
        return base

    def get_crash_synopsis(self):
        if self.crash is None:
            return "no crash detected"
        c = self.crash
        lines = [
            "CODESYS runtime did not answer a TCP connect on %s"
            % (self.connection.info,),
            "  case            : %s" % (c["case"],),
            "  cases this run  : %d" % (c["cases_run"],),
            "  detector        : %s" % (c["reason"],),
            "  time            : %s" % (c["when"],),
            "  request sent    : %d bytes" % (c["send_len"],),
        ]
        if self._last_send:
            lines.append("")
            lines.append("Last request on the wire (framing included):")
            lines.append(_hexdump(self._last_send))
            lines.append("")
            lines.append("Reproduce the payload with:")
            lines.append("  codesysfuzzer/codesys_fuzzer.py <target> "
                         "--request <name> --case %s" % (c["case"],))
        return "\n".join(lines)

    def start_target(self):
        """No automatic restart — see the class docstring."""
        return False

    def retrieve_data(self):
        if self.crash is None:
            return None
        return ("crash case=%s detector=%s"
                % (self.crash["case"], self.crash["reason"])).encode()


def structured_from_body(group, service, body):
    """A services body as the nested tag tree a crash report shows.

    Factored out of :func:`structured_request` because the case-report
    generator has the body (rebuilt from the seed enumeration) but not the
    original live frame.
    """
    if body is None:
        return {"group": group, "service": service, "parse_error": "no body",
                "body_hex": ""}

    def node(t):
        # wire id: parse_tags masks bit 7, so a container 0x86 arrives as 0x06.
        # The report has to show the byte that goes on the wire or it cannot be
        # copied back into a body.
        return {"id": (t["id"] | 0x80) if t["children"] else t["id"],
                "container": bool(t["children"]),
                "value_hex": t["value"].hex(),
                "value_len": len(t["value"]),
                "children": [node(c) for c in t["children"]] if t["children"]
                else []}

    try:
        tags = parse_tags(body)
    except ValueError as e:
        return {"group": group, "service": service, "parse_error": str(e),
                "body_hex": body.hex()}
    return {"group": group, "service": service, "body": [node(t) for t in tags]}


def structured_request(sent):
    """The sent request as a nested tag tree with values, for a crash report.

    ``{"group": int, "service": int, "body": [node, ...]}`` where a node is
    ``{"id": int, "container": bool, "value": bytes, "children": [...]}``.  This
    is the "simplified" form: the same bytes as the hexdump, but arranged the way
    the handler reads them, so a reader can see which tag held the oversized
    value without decoding LEB128 by hand.
    """
    group, service, body = parse_sent_parts(sent)
    if group is None:
        return None
    return structured_from_body(group, service, body)


def _fmt_nodes(nodes, indent=0):
    """``0x81(0x11=00000000 0x18=00000000)`` across several lines."""
    pad = "  " * indent
    out = []
    for n in nodes:
        raw = bytes.fromhex(n["value_hex"])
        head = "%s0x%02x" % (pad, n["id"])
        if n["children"]:
            out.append("%s  (container, %d byte(s) of children)"
                       % (head, n["value_len"]))
            out.extend(_fmt_nodes(n["children"], indent + 2))
            continue
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in raw[:16])
        shown = " ".join("%02x" % b for b in raw[:24]) or "(empty)"
        out.append("%s  = %s  |%s|  (%d byte(s))"
                   % (head, shown, asc, n["value_len"]))
    return out


def _hexdump(data, width=16, limit=512):
    """Hex + ASCII, capped — a crash report wants the shape, not a transcript."""
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
