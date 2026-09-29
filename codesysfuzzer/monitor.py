#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Crash detection for the CODESYS runtime.

boofuzz's contract is simple: a monitor whose ``post_send`` returns ``False``
marks the test case as crashing, and ``get_crash_synopsis`` supplies the report.
So the whole job here is deciding *when* the runtime is dead.

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

import json
import os
import struct
import time

from boofuzz.monitors.base_monitor import BaseMonitor

from proto import (
    BD_MAGIC, parse_channel, parse_datagram, parse_services, parse_tags,
    status_of,
)


def parse_sent(data):
    """Pull the (group, service) actually transmitted out of a sent frame.

    Needed because in a sweep the ids that went out are the *mutated* ones, not
    the model's defaults — reading them back off the wire is simpler and more
    trustworthy than threading the mutation context through.  Only the first
    frame is inspected; the services header is in it either way.
    """
    if not data or len(data) < 8 + 20:
        return None, None
    try:
        magic, length = struct.unpack_from("<II", data, 0)
        if magic != BD_MAGIC or length < 8 or length > len(data):
            return None, None
        dg = parse_datagram(data[8:length])
        if dg is None:
            return None, None
        ch = parse_channel(dg["payload"])
        if ch.get("type") not in ("blk_first", "blk_cont"):
            return None, None
        hdr, _ = parse_services(ch["data"])
        return hdr["group"], hdr["service_id"]
    except (ValueError, struct.error, KeyError, IndexError):
        return None, None


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
        row = {"group": "0x%04x" % group, "service": "0x%04x" % service,
               "verdict": verdict, "status": status,
               "first_seen": time.strftime("%Y-%m-%dT%H:%M:%S")}
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
                 surface_path=None, reply_timeout=2.0, surface_mode="global"):
        super().__init__()
        self.connection = connection
        self.probe_every = max(1, probe_every)
        self.enabled = enabled
        self.verbose = verbose
        self.surface = SurfaceRecorder(path=surface_path, verbose=verbose,
                                       mode=surface_mode)
        self.reply_timeout = reply_timeout

        self.cases = 0
        self.probes = 0
        self.replies = 0
        self.crash = None            # dict once a crash is detected
        self._last_send = None
        self._last_case_index = None

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
            self._last_send = getattr(session, "last_send", None)
            self._last_case_index = getattr(session, "total_mutant_index", None)

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

        if not self.enabled:
            return True
        # A broken session is the interesting case, so probe then regardless of
        # cadence; a healthy one is probed every Nth case to keep the overhead
        # off the hot path.
        if not self.connection.broken and self.cases % self.probe_every:
            return True

        self.probes += 1
        alive, why = self.connection.probe()
        if alive:
            return True

        self.crash = {
            "case": self._last_case_index,
            "cases_run": self.cases,
            "reason": why,
            "when": time.strftime("%Y-%m-%d %H:%M:%S"),
            "send_len": len(self._last_send) if self._last_send else 0,
        }
        if fuzz_data_logger is not None:
            fuzz_data_logger.log_fail(
                "CODESYS runtime is gone after case %s: %s"
                % (self._last_case_index, why))
        return False

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
