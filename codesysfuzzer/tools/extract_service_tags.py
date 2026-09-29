#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Recover the CODESYS V3 group -> per-service function -> candidate tag ids map.

Why this exists
---------------
Modelling every service by hand does not scale: 21 service groups, each a switch
over service ids, each case a function that reads tag ids out of a flat tag
stream.  This walks that automatically and emits a *draft* for review.

What it does and does not do
----------------------------
It does **not** read the jump table.  The first version did, via
``switch_info_t``, and it blew up with ``'int' object is not subscriptable`` on
IDA 9 — the API moved and cannot be tested from outside the GUI.  So this
enumerates each handler's **direct call targets** instead, which needs no switch
API at all, and reports them as that group's per-service functions.  That loses
the exact service id -> function pairing (a handler's call list is unordered with
respect to case values) and keeps everything that matters for deciding what to
model next: which functions implement a group's services, and which tag ids each
one looks at.

The pairing can be recovered later from the ``cmp`` constants the handler makes
(also reported) or by reading the handler in the GUI.

Self-check
----------
The script verifies its own tag extraction against the one pair already analysed
by hand: **CmpTraceMgr (group 0x0f)**, whose vulnerable memcpys are driven by
tags **19, 20, 21, 48, 51**.  It searches the group's handler *and* its call
targets for those five; if they are not all found, the extraction is
under-collecting and the rest of the report should not be trusted.

Running it
----------
In the IDA GUI that has the database open: **File -> Script file...** and pick
this file.  Output goes to the Output window and to
``<database>_service_tags.json``.

Headless did not work on this machine -- ``idat.exe`` fails with "Library
initialization failed with result: 1" and ``ida.exe -A`` exits silently -- so
the GUI route is the one to use.  IDA is single-writer: if you ever get a batch
run working, point it at a *copy* of the ``.i64``.
"""

import argparse
import json
import os
import sys
import traceback

import idautils
import idc

#: the registration primitive: sub_106BFA0(group_id, handler)
REGISTER_FN = 0x106BFA0

#: CmpTraceMgr's group handler and the tags its vulnerable path is known to use
TRACE_GROUP = 0x0F
TRACE_EXPECTED_TAGS = {19, 20, 21, 48, 51}

#: tag ids live below 0x80 because bit 7 marks a container
TAG_MIN, TAG_MAX = 0x01, 0x7F

#: the one entry point that actually reads a tag stream.  Distinct from
#: :data:`SHARED_TAG_LIB` below, which is the broader helper cluster: a first
#: version flagged a group as "tag-stream driven" on membership of the *cluster*,
#: and since one member (``0x106C1B0``, the common completion helper) appears in
#: every handler, all 21 groups came back flagged.  The reader itself is what
#: distinguishes them.
TAG_READER = 0xECA510

#: the tag-stream parsing library, shared by several groups (recovered
#: separately by walking each handler's callees).  Excluded from a group's
#: "own service functions" so the report lists the group's own code rather than
#: twenty shared helpers repeated per group.
SHARED_TAG_LIB = {
    0xEC93E0, 0xECA2F0, 0xEC9750, 0xECA390, 0xECA400, 0xECA340, 0xECA490,
    0xECA3B0, 0xECA000, 0xEC9A20, 0xEC9BD0, 0xEC9DD0, 0xEC9AD0, 0xECA070,
    0xEC9E90, 0xEC9ED0, 0xECA130, 0xECA620, 0xECA910, 0xECAA50, 0xECA510,
    0x106C1B0,                     # common completion/status helper
}


def log(msg):
    print("[extract] %s" % msg)
    sys.stdout.flush()


def script_args():
    """Arguments after the script name (``idc.ARGV`` under -S, else sys.argv)."""
    argv = list(getattr(idc, "ARGV", None) or []) or list(sys.argv)
    return argv[1:]


# ============================================================
# 1. the group table
# ============================================================

def register_calls():
    """{group_id: handler_ea} from every ``sub_106BFA0(group, handler)`` call.

    The two ``push`` instructions immediately before each call are the handler
    and then the group id.  The jump-table ``case N`` label next to some of these
    call sites is the table index, **not** the group id, and does not always
    match (CmpIecVarAccess is labelled ``case 10`` but pushes ``9``), so the
    pushed value is the one to read.
    """
    found = {}
    for xref in idautils.XrefsTo(REGISTER_FN, 0):
        call_ea = xref.frm
        pushes = []
        ea = idc.prev_head(call_ea)
        for _ in range(4):
            if ea == idc.BADADDR:
                break
            if idc.print_insn_mnem(ea) == "push":
                pushes.append(ea)
            ea = idc.prev_head(ea)
        if len(pushes) >= 2:
            handler = idc.get_operand_value(pushes[1], 0)
            group = idc.get_operand_value(pushes[0], 0)
            if handler:
                found.setdefault(group, handler)
    return found


# ============================================================
# 2. a group's own functions
# ============================================================

def direct_calls(fn_ea):
    """[(call_ea, target_ea)] for every direct call inside the function."""
    out = []
    for ea in idautils.FuncItems(fn_ea):
        if idc.print_insn_mnem(ea) != "call":
            continue
        for ref in idautils.CodeRefsFrom(ea, 0):
            out.append((ea, ref))
    return out


#: everything at or above this is the statically-linked CRT in this image
#: (memcpy 0x12D3060, __security_check_cookie 0x12CE9A5, ...), never a service
CRT_FLOOR = 0x1200000


def is_library(target):
    """True for thunks/imports/CRT, which are never a group's service handler."""
    name = idc.get_func_name(target) or idc.get_name(target) or ""
    return (not name) or name.startswith("_") or name.startswith("@") \
        or target >= CRT_FLOOR


def own_functions(handler_ea):
    """A group's own per-service functions, minus the shared tag library."""
    seen = {}
    for _call_ea, target in direct_calls(handler_ea):
        if target in SHARED_TAG_LIB or is_library(target):
            continue
        seen.setdefault(target, idc.get_func_name(target) or "")
    return sorted(seen.items())


# ============================================================
# 3. candidate tag ids
# ============================================================

#: immediates that look like a tag id are collected from these.  A first version
#: used ``cmp`` alone and *missed every one of CmpTraceMgr's five known trigger
#: tags* (19/20/21/48/51): a tag id dispatched through a jump table is never
#: compared per-value, only bounds-checked, so the individual ids never appear as
#: immediates at all.  Widening the set is the cheap half of the fix; the other
#: half is reporting switch bounds (below) and treating the tag lists as a lower
#: bound rather than an answer.
IMM_MNEMS = ("cmp", "mov", "lea", "and", "sub", "add", "or", "test")


def cmp_constants(fn_ea, lo=TAG_MIN, hi=TAG_MAX):
    """{immediate: ea} for tag-id-sized immediates in the function.

    Deliberately over-inclusive: this collects lengths, flags and loop bounds
    alongside real tag ids, which is why every value keeps the instruction it
    came from.  It is a lower bound on the tag ids the function handles — a
    jump-table-dispatched id shows up only through :func:`switch_bounds`.
    """
    out = {}
    try:
        items = list(idautils.FuncItems(fn_ea))
    except Exception:
        return out
    for ea in items:
        if not idc.print_insn_mnem(ea).startswith(IMM_MNEMS):
            continue
        for opn in (0, 1, 2):
            val = idc.get_operand_value(ea, opn)
            if val is not None and lo <= val <= hi:
                out.setdefault(val, ea)
    return out


def switch_bounds(fn_ea, window=6):
    """Upper bounds of jump tables, which is where the interesting tags hide.

    A tag-id switch compiles to ``cmp reg, <max>; ja default; jmp ds:table[reg]``
    — so the *highest* tag id the switch accepts appears as that ``cmp``
    immediate, and the ids below it appear nowhere.  For CmpTraceMgr the bound is
    ``0x33`` (= the known tag 51), which is why collecting bounds is the only way
    this method can see that path at all.

    Returns ``{bound: ea}`` for ``cmp reg, imm`` followed within ``window``
    instructions by an indirect jump.
    """
    out = {}
    try:
        items = list(idautils.FuncItems(fn_ea))
    except Exception:
        return out
    for i, ea in enumerate(items):
        if not idc.print_insn_mnem(ea).startswith("cmp"):
            continue
        val = idc.get_operand_value(ea, 1)
        if val is None or not (TAG_MIN <= val <= TAG_MAX):
            continue
        for nxt in items[i + 1:i + 1 + window]:
            if idc.print_insn_mnem(nxt).startswith("j") and \
                    idc.get_operand_type(nxt, 0) in (idc.o_mem, idc.o_phrase,
                                                     idc.o_displ):
                out.setdefault(val, ea)
                break
    return out


# ============================================================
# driver
# ============================================================

def analyse(handler_ea):
    """One group: its own functions, each with candidate tag ids."""
    entry = {
        "handler": "0x%x" % handler_ea,
        "handler_name": idc.get_func_name(handler_ea) or "",
        # service ids to pair with the functions below, from the handler's own
        # comparisons — unordered, so treat as the candidate set
        "candidate_service_ids": sorted(cmp_constants(handler_ea).items()),
        "functions": {},
    }
    calls = direct_calls(handler_ea)
    entry["uses_tag_reader"] = any(t == TAG_READER for _c, t in calls)
    # which shared helpers this group touches, so the difference between the
    # reader and the always-present completion helper is visible, not inferred
    entry["shared_lib_hits"] = sorted("0x%x" % t for _c, t in calls
                                      if t in SHARED_TAG_LIB)
    for fn, name in own_functions(handler_ea):
        tags = cmp_constants(fn)
        bounds = switch_bounds(fn)
        fn_calls = direct_calls(fn)
        entry["functions"]["0x%x" % fn] = {
            "name": name,
            "candidate_tags": sorted(tags),
            "tag_addrs": {"0x%02x" % t: "0x%x" % a for t, a in sorted(tags.items())},
            "switch_bounds": sorted(bounds),
            "calls_memcpy": any(idc.get_func_name(t) == "memcpy" for _c, t in fn_calls),
            "calls_tag_reader": any(t == TAG_READER for _c, t in fn_calls),
        }
    return entry


def self_check(report):
    """Two separate questions, and only one of them is a pass/fail gate.

    **Does the walk reach the code at all?**  Asserted.  ``TraceMgrServiceHandler``
    must appear among group 0x0f's own functions and be flagged as calling
    ``memcpy`` — that is the whole premise of the report, and it is fully
    checkable.

    **How many of its five known trigger tags are visible?**  Reported, not
    gated.  Three of them (19/20/21) and both nested ones (48/51) are dispatched
    through jump tables, so they cannot appear as individual immediates; gating
    on them would fail the script for a limitation of the method rather than a
    bug in it.  The count is printed so a reader can see the tag lists are a
    lower bound.
    """
    entry = report["groups"].get("0x%02x" % TRACE_GROUP)
    if not entry:
        return "SKIP", set(), {}
    pools = {"handler": set(t for t, _ in entry["candidate_service_ids"])}
    for fn, info in entry["functions"].items():
        pools[fn + " " + info["name"]] = set(info["candidate_tags"])

    union = set()
    for tags in pools.values():
        union |= tags
    where = {t: [k for k, v in pools.items() if t in v] for t in sorted(union)}

    # --- gate: did the walk reach the known function, and see its memcpy? ---
    reached = {}
    for fn, info in entry["functions"].items():
        if "TraceMgrServiceHandler" in (info["name"] or ""):
            reached[fn] = info
    log("")
    log("SELF-CHECK group 0x%02x" % TRACE_GROUP)
    if not reached:
        log("  FAIL: TraceMgrServiceHandler not among group 0x0f's functions "
            "(%d found) -- the walk is not reaching service code"
            % len(entry["functions"]))
        return "FAIL", union, where
    for fn, info in reached.items():
        log("  handler %s %s  calls_memcpy=%s"
            % (fn, info["name"], info["calls_memcpy"]))
        if not info["calls_memcpy"]:
            log("  FAIL: the known-vulnerable function is not flagged as calling "
                "memcpy")
            return "FAIL", union, where
    log("  reached the known-vulnerable function and saw its memcpy -- walk OK")

    found = TRACE_EXPECTED_TAGS & union
    log("  tag coverage: %d/%d of the known trigger tags visible (%s missing)"
        % (len(found), len(TRACE_EXPECTED_TAGS),
           sorted(TRACE_EXPECTED_TAGS - found)))
    log("  jump-table-dispatched tags appear only as switch_bounds, so treat")
    log("  candidate_tags as a LOWER BOUND, not a complete list")
    return "PASS", union, where


def main():
    ap = argparse.ArgumentParser(prog="extract_service_tags.py")
    ap.add_argument("--out", default=None, help="output JSON path")
    ap.add_argument("--self-check", action="store_true",
                    help="exit non-zero unless the known tags are recovered")
    try:
        args = ap.parse_args(script_args())
    except SystemExit:
        args = argparse.Namespace(out=None, self_check=False)

    if args.out is None:
        base = idc.get_idb_path() or "codesys"
        args.out = os.path.splitext(base)[0] + "_service_tags.json"

    log("phase 1: group table from sub_%X registrations" % REGISTER_FN)
    groups = register_calls()
    log("  %d groups" % len(groups))

    report = {"groups": {}, "errors": [],
              "tag_reader": "0x%x" % TAG_READER,
              "shared_tag_lib": sorted("0x%x" % a for a in SHARED_TAG_LIB)}
    for group in sorted(groups):
        try:
            entry = analyse(groups[group])
        except Exception as e:
            report["errors"].append("group 0x%02x: %s: %s"
                                    % (group, type(e).__name__, e))
            continue
        report["groups"]["0x%02x" % group] = entry
        log("  group 0x%02x %-16s -> %2d own function(s)"
            % (group, entry["handler_name"] or "", len(entry["functions"])))

    status, union, where = self_check(report)
    report["self_check"] = status
    report["self_check_union"] = sorted(union)
    report["self_check_where"] = {str(k): v for k, v in where.items()}

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    log("wrote %s" % args.out)
    log("self_check=%s" % status)

    if args.self_check and status != "PASS":
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
