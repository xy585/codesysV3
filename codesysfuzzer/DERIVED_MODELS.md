# Item 1: derive real request bodies for un-modelled services

**Status: in progress — 6 of the 19 listed groups' services modelled.**
Written 2026-09-29 to be resumed later.

## The goal

The fuzzer's request models were hand-written for the components that had
captures (CmpTraceMgr, CmpIecVarAccess, CmpApp, CmpDevice) — 13 of the 760
possible `(group, service)` pairs. Everything else was only reachable with a
generic or unstructured body, which exercises a handler's early parse and
nothing deeper. The goal is to **derive each service's real request shape from
the binary** so models can be written for the rest.

The work has three parts:

1. recover the group → handler dispatch table (done, see
   `memory/codesys-service-registry.md`)
2. read each group handler for its **service ids** (done per group as reached)
3. read each per-service function for its **tag ids** (the actual modelling work)

## The rule for reading a handler (this is the part that works)

Read the group handler and then each per-service function in the IDA GUI. The
first automated attempt — scanning for tag-id-sized immediates — was a *lower
bound* and reported lengths and offsets as service ids (the giveaway was a tail
of multiples of four: 0x0c, 0x10, 0x14, 0x18…). Do not trust that output.

1. **Service ids** are the `case` labels of `switch (*(_WORD *)(req + 6))` at the
   top of the group handler. One read of `sub_EBF300` yielded all nine CmpAppBP
   service ids.
2. **`default: return <small>` is that group's "no such service" code**, and it
   is *per group*: CmpAppBP and CmpAppForce return `24`, most groups return
   `770`. So "a non-770 status means the service exists" is **wrong** — find the
   group's own fallback first, then a status equal to it means "no such service"
   and anything else means the handler is present.
3. **Tag ids** are the `case` labels of the *inner* switch — the one over the
   value returned by `sub_ECA400`, reached after `if (tagid == 129)`, i.e.
   inside container `0x81`.
4. Values are fetched by `sub_ECA510(parser, &ptr, &len)`; the first dword at
   `*ptr` is the value.
5. **A tag id may be an output, not a request field.** `sub_EC1790` writes tags
   `0x82, 0x21, 0x14, 0x16` into the *response* via `sub_EC9750`/`sub_EC9A20`.
   The tell: `sub_ECA510` reads the request, `sub_EC9750`+`sub_EC9A20` write the
   response.

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

Container `0x81` here is the same convention as CmpTraceMgr's `0x86`/`0x83`: the
raw id byte has bit 7 set and the LEB128 encoding is `81 01`.

## Done

| group | component | models | source |
|---|---|---|---|
| 0x12 | CmpAppBP | `appbp_0x13_setbp`, `appbp_0x15_delbp`, `appbp_0x16`, `appbp_0x19`, `appbp_0x39` | `sub_EBF300` (ids) + `sub_EC2060`/`sub_EC11F0`/`sub_EC1790`/`sub_EC2AA0` (tags) |
| 0x13 | CmpAppForce | `appforce_0x81_11` | `sub_EC5D80`, `sub_EC6060` |

CmpAppBP's remaining service ids — read but **not yet modelled**: `0x22`, `0x32`,
`0x33`, `0x40` (functions `sub_EC2E60`, `sub_EC0970`, `sub_EC1D30`,
`sub_EC06C0`).

Models live in `services.py` under the "Derived from decompilation" heading, and
are registered in `REQUESTS`.

## Not verified yet

**None of the six has been confirmed against a live runtime.** The check is
cheap and worth doing first: `--dry-run --send` for each, and confirm the reply
is *not* group 0x12's `default: return 24`. A `24` means the service id was
misread. The runtime was stopped when this was written.

## Remaining work

17 groups, roughly 150–250 function reads:

| group | component | own functions | notes |
|---|---|---|---|
| 0x01 | CmpDevice | 0 (handler is a `loc_`, needs the enclosing function) | |
| 0x02 | CmpApp | 1 | partly covered by existing models (0x01 lookup) |
| 0x03 | **undocumented** | 28 | 3 services confirmed by the service map: 0x01, 0x02, 0x03 |
| 0x04 | CmpVisuServer | 1 | |
| 0x05 | CmpLog | 11 | tag-stream driven |
| 0x06 | CmpSettings | 9 | |
| 0x07 | SysEthernet | 5 | |
| 0x08 | CmpFileTransfer | 45 | tag-stream driven, largest |
| 0x09 | CmpIecVarAccess | 22 | partly covered (register/read/write) |
| 0x0B | CmpIoMgr | 9 | |
| 0x0C | CmpUserMgr | 23 | tag-stream driven |
| 0x0F | CmpTraceMgr | 23 | covered by the captured template |
| 0x11 | PlcShell | 7 | tag-stream driven |
| 0x14 | **undocumented** | 16 | no public documentation at all |
| 0x18 | CmpAlarmManager | 3 | small, good next target |
| 0x1B | CmpMonitor | 1 | small |
| 0x1D | CmpCodeMeter | 9 | |
| 0x1F | CmpCoreDump | 2 | small |
| 0x22 | CmpOpenSSL | 12 | |

**Suggested order** — the three functions that both parse a tag stream and call
`memcpy` are the ones matching the known CmpTraceMgr bug shape, so model them
first even though they are not the smallest:

1. `0x03` / `sub_FC0E10` (undocumented, the largest handler, memcpy + tag stream)
2. `0x09` / `sub_FAAC70`
3. `0x0F` / `TraceMgrServiceHandler` (already known — use it to sanity-check the method)
4. then the small handlers: `0x18` (3), `0x1F` (2), `0x1B` (1), `0x04` (1), `0x02` (1)
5. then the rest

## Practical notes

* The MCP tools make this cheap: one `analyze_batch` of 3–4 functions per round
  trip, `include_decompile` only (drop xrefs/constants/blocks) to keep output
  small.
* IDA is rebased **+0x5F0000** against the running process, so `sub_EC2060` is
  runtime `0x008D2060`.
* `test_framing.py` picks up new models automatically — its "every model builds
  and renders" case asserts each one builds and has mutations, so a malformed
  new model fails the suite.
