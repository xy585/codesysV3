#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Aggregate ``*.surface.jsonl`` files into the runtime's service map.

Pairs with ``--all-groups``: that produces one surface file per service group,
this reads them back and answers the question the enumeration exists for —
**which service ids are actually implemented, and in which groups**.

Reading the verdicts
--------------------
The verdicts are only meaningful when compared against a known-good reply, so
the mapping below is calibrated against one:

* ``replied`` — the runtime answered with content and no status tag.  This is
  what a real service looks like: CmpTraceMgr's ``trace_list`` (0x0f/0x01)
  answers exactly this way, with four name tags.
* ``refused`` with status ``770`` (0x0302) — uniform across almost every
  (group, service) pair tried, including service ids that cannot exist.  That
  makes it the runtime's "no such service" fallback, so it means the *group* is
  live but the service is not implemented.  Do not read it as "the service
  exists and rejected us".
* any other non-zero status — genuinely service-specific: the handler ran and
  decided something.  These are the most interesting rows, because a handler
  that rejects is a handler that is *there*.
* ``empty`` — answered, but with a zero-length body: declined to act.
* ``no-reply`` / ``incomplete`` — no evidence either way; excluded.

Usage
    python tools/summarise_surface.py logs/map
    python tools/summarise_surface.py logs/map --json map.json
"""

import argparse
import collections
import glob
import json
import os
import sys

#: the "no such service" status seen uniformly across groups
NO_SUCH_SERVICE = 770


def load(paths):
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except ValueError:
                    continue


def main():
    ap = argparse.ArgumentParser(prog="summarise_surface.py")
    ap.add_argument("paths", nargs="+",
                    help="surface jsonl files, or directories containing them")
    ap.add_argument("--json", default=None, help="also write the map as JSON")
    args = ap.parse_args()

    files = []
    for p in args.paths:
        if os.path.isdir(p):
            files.extend(sorted(glob.glob(os.path.join(p, "*.surface.jsonl"))))
        else:
            files.extend(sorted(glob.glob(p)))
    if not files:
        print("no surface files found", file=sys.stderr)
        return 1
    print("reading %d surface file(s)" % len(files))

    # (group, service) -> Counter of (verdict, status)
    per = collections.defaultdict(collections.Counter)
    for row in load(files):
        if row.get("verdict") == "incomplete" or "group" not in row:
            continue
        key = (row["group"], row["service"])
        per[key][(row.get("verdict"), row.get("status"))] += 1

    def verdict_of(counter):
        """The strongest verdict seen for a pair, best first."""
        for want in ("replied", "accepted"):
            if any(k[0] == want for k in counter):
                return want
        for (v, st), _n in counter.most_common():
            if v == "refused" and st != NO_SUCH_SERVICE:
                return "refused-specific"
        if any(k[0] == "refused" for k in counter):
            return "refused"
        if any(k[0] == "empty" for k in counter):
            return "empty"
        return "no-reply"

    implemented, specific, groups_seen = [], [], set()
    for (g, s), c in per.items():
        groups_seen.add(g)
        v = verdict_of(c)
        if v in ("replied", "accepted"):
            implemented.append((g, s))
        elif v == "refused-specific":
            st = [k[1] for k in c if k[0] == "refused" and k[1] != NO_SUCH_SERVICE]
            specific.append((g, s, sorted(set(st))))

    print("\n========== service map ==========")
    print("  groups probed          : %d" % len(groups_seen))
    print("  (group, service) pairs : %d" % len(per))
    print("  IMPLEMENTED (content)  : %d" % len(implemented))
    print("  refused, non-770 status: %d  <- handlers that ran and decided"
          % len(specific))

    by_group = collections.defaultdict(list)
    for g, s in implemented:
        by_group[g].append(s)
    print("\n  implemented services, by group:")
    if not by_group:
        print("    (none — every reply was the no-such-service fallback)")
    for g in sorted(by_group):
        svcs = sorted(int(x, 16) for x in by_group[g])
        print("    %s  %2d  %s" % (g, len(svcs), " ".join("0x%02x" % v for v in svcs)))

    if specific:
        print("\n  service-specific rejections (a handler is present):")
        for g, s, st in sorted(specific):
            print("    %s %s  status %s" % (g, s, st))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({
                "implemented": [{"group": g, "service": s} for g, s in implemented],
                "refused_specific": [{"group": g, "service": s, "status": st}
                                     for g, s, st in specific],
                "pairs_probed": len(per),
            }, fh, indent=2)
        print("\nwrote %s" % args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
