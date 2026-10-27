# tools/

## `extract_seeds.py` — turn a capture into a seed corpus

Reads a pcap/pcapng and writes one JSON file per request body, ready for
`--from-seeds`.  It handles both framings the repository's captures contain:

* TCP block driver (`CmpBlkDrvTcp`, port 11740): 8-byte BD header per frame,
  datagram, channel frames, services;
* UDP flash gateway (`CmpBlkDrvUdp`, ports 1740-1743): the datagram is the
  packet, reusing `codesys_udp_ds.parse_datagram/parse_channel`.

Only requests are kept (the runtime marks a reply with bit 7 of the group), and
only the services **body** is written — session id, token and block counters are
one connection's state.  Multi-frame messages are reassembled before writing.

```
python tools/extract_seeds.py trace2.pcapng -o seeds/
python tools/extract_seeds.py trace2.pcapng -o seeds/ --group 0x0f
python tools/extract_seeds.py trace2.pcapng -o seeds/ --jsonl all.jsonl
```

Needs `scapy` (optional; the fuzzer itself does not).  The default is to inspect
every TCP/UDP stream and let the block-driver magic decide — the runtime and the
gateway do not share a port.

## `extract_service_tags.py` — recover the (group, service) → tag-id map

Walks the runtime's dispatch in IDA and emits a draft table of which tag ids each
per-service function compares against, so models can be written from evidence
instead of guessing.

### How to run it

**In the running IDA GUI** (the database is already open there):

> File → Script file… → pick `extract_service_tags.py`

Output goes to the Output window and to `<database>_service_tags.json` next to
the `.i64`.

**Headless — does not work on this machine.** Both batch binaries fail before the
script is reached, so the GUI route above is the one to use:

```
idat.exe -A -S"extract_service_tags.py --out out.json" -L extract.log db.i64
    -> "Library initialization failed with result: 1"

ida.exe  -A -S"extract_service_tags.py --out out.json" -L extract.log db.i64
    -> exits 1, writes no log at all
```

IDA is single-writer, so if you do get a batch run working, point it at a *copy*
of the `.i64` rather than the database the GUI has open.

### It does not read the jump table (deliberately)

The first version tried to pair each service id with its function via
``switch_info_t`` and died with ``'int' object is not subscriptable`` on IDA 9 —
that API moved between versions and cannot be exercised from outside the GUI.
So the script enumerates each handler's **direct call targets** instead: no
switch API, nothing version-dependent. What is lost is the exact
``service id -> function`` pairing; what is kept is everything needed to decide
what to model next — which functions implement a group's services, which of them
call ``memcpy``, and which tag ids each one compares against. The handler's own
``cmp`` constants are reported alongside as the candidate service ids, so the
pairing can be recovered by reading one function in the GUI.

The shared tag-parsing library (``0xEC9xxx``/``0xECaxxx``, ~22 functions reached
by seven of the groups) is listed in the output and excluded from each group's
"own functions", so the report shows a group's own code rather than the same
twenty helpers repeated 21 times.

### The self-check gates two different things

**Gated — does the walk reach service code?** `TraceMgrServiceHandler` must appear
among group `0x0f`'s own functions *and* be flagged `calls_memcpy`. That is the
premise of the whole report and it is fully checkable. A first run failed here
for a different reason (`switch_info_t` blew up), so this is worth watching.

**Reported, not gated — how many known tags are visible.** CmpTraceMgr's five
trigger tags are **19, 20, 21, 48, 51**, and an earlier version of the script
recovered **none** of them: a tag id dispatched through a jump table is never
compared per value, only bounds-checked, so the ids never appear as immediates.
Gating on that would fail the script for a limitation of the method rather than a
bug in it, so the run prints the count instead:

```
  tag coverage: 1/5 of the known trigger tags visible ([19, 20, 21, 48] missing)
  jump-table-dispatched tags appear only as switch_bounds, so treat
  candidate_tags as a LOWER BOUND, not a complete list
```

`switch_bounds` is the mitigation: it records the `cmp reg, <max>` that precedes
an indirect jump, which is where the highest tag id of each switch does appear.
`--self-check` makes a gate failure a non-zero exit.

### The rule for reading a handler by hand (this is the part that works)

The automated tag scan is a lower bound; the following rule is exact, and it is
how the CmpAppBP and CmpAppForce models were derived. Read the group handler and
then each per-service function in the GUI:

1. **Service ids** are the `case` labels of the `switch (*(_WORD *)(req + 6))` at
   the top of the group handler. `CmpAppBP`'s `sub_EBF300` yields
   `0x13, 0x15, 0x16, 0x19, 0x22, 0x32, 0x33, 0x39, 0x40` in one read.
2. **`default: return <small>` is that group's "no such service" code**, and it is
   *per group* — `0x12`/`0x13` return `24`, most groups return `770`. This is why
   "non-770 means the service exists" is wrong, and why a group's own fallback has
   to be read before its statuses mean anything.
3. **Tag ids are the `case` labels of the inner switch** — the one over the value
   returned by `sub_ECA400`, reached after `if (tagid == 129)` (container `0x81`).
   Every CmpAppBP service reads its fields from inside container `0x81`.
4. Each field is fetched with `sub_ECA510(parser, &ptr, &len)`; the first `dword`
   at `*ptr` is the value.
5. **A tag id can be an output.** `sub_EC1790` emits tags `0x82, 0x21, 0x14, 0x16`
   into the response — those are not request fields. The tell is `sub_EC9750` /
   `sub_EC9A20` (writing into the response buffer) rather than `sub_ECA510`
   (reading from the request).

```c
sub_EC93E0(resp, req, len);        // build response
sub_ECA2F0(parser, body, len);     // parse request tag stream
sub_ECA400(parser, &tagid);        // next tag id
if (tagid == 129) {                // container 0x81
    while (!sub_ECA340(parser)) {
        sub_ECA400(parser, &tagid);
        switch (tagid) { case 17: sub_ECA510(...); /* tag 0x11 */ }
    }
}
```

### The highest-signal column

`calls_memcpy` and `calls_tag_reader` on the *same* function is the combination
worth reading first: a function that parses an attacker-shaped tag stream and
then calls `memcpy` is the shape of the CmpTraceMgr bug, and it is how group
`0x03` (undocumented, 28 own functions) surfaced as the top unmodelled target.

### Expect a draft, not an answer

The tag ids are read as the immediate constants a per-service function compares
against, filtered to `0x01..0x7f` (bit 7 marks a container). That over-collects:
the same function also compares service ids, lengths and flag bits. The report
therefore keeps every constant **with the instruction address it came from**, so
a reader can tell a tag id from a loop bound — which is the review step the
script is designed to feed, not replace.

Run it after `--request`-based fuzzing starts finding things in a group: the
report tells you which tag ids that group's handler actually looks at, which is
what a targeted model needs.
