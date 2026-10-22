# CODESYS V3 network fuzzer

A generation-based fuzzer for the CODESYS V3 protocol, built on
[boofuzz](https://github.com/jtpereyda/boofuzz) over `CmpBlkDrvTcp` (TCP 11740).

Modelled after Claroty's OPC UA fuzzer (`references/opcua_network_fuzzer`), which
the FreeBuf article *Codesys V3协议漏洞挖掘方法* recommends adapting:

> 推荐采用 boofuzz 框架，可以参考 claroty 开源的 OPC UA 模糊测试程序来适配 Codesys V3
> 协议的模糊测试

The framing, tag codec and login crypto are **not** reimplemented: they are
imported from the existing, capture-verified `codesys_tcp.py`, so the fuzzer
mutates requests that are byte-for-byte known to be real. `codesys_tcp.py` itself
is untouched.

## Install and run

```
pip install -r codesysfuzzer/requirements.txt

python codesysfuzzer/codesys_fuzzer.py --list-requests
python codesysfuzzer/codesys_fuzzer.py 192.168.125.129 -r trace_configure --dry-run --send
python codesysfuzzer/codesys_fuzzer.py 192.168.125.129 -r trace_configure --cases 2000
```

Run the offline framing tests with `python codesysfuzzer/test_framing.py`.

There is no `__init__.py`: these are scripts that import each other by bare name,
so run them as scripts (`python codesysfuzzer/codesys_fuzzer.py ...`), not with
`-m`.

## How it works

The interesting problem is that a CODESYS request carries its length and CRC in
four nested places, all computed over bytes the fuzzer is about to change:

```
block driver   magic | len(datagram) + 8                 <- per frame
datagram       20-byte CmpRouter header                  <- per frame
channel        BLK frame: blk_id, ack_id,               <- per frame
                           message length + CRC32        <- first frame only
services       proto | hdrsize | group | service | session | content_size | tags
body           [tag id][LEB128 length][value] ...
```

boofuzz already solves consistent lengths (`s_size`) and has a crc32
`s_checksum`, but two things it cannot express are handled here:

* **`Leb128Size`** — boofuzz renders sizes as fixed-width little endian; CODESYS
  wants LEB128, and *two different widths of it*: 3 bytes for a leaf tag length
  (`84 80 00` for 4) and 2 for a container (`e0 00` for 96). Reproducing the
  captured request byte-for-byte depends on that distinction.
* **`FrameEncoder`** — a block `encoder` that runs after boofuzz has rendered the
  services block, and slices it into real BLK frames with the right sizes, CRC32
  and block counters. Because boofuzz's `Size` resolves a target by *rendering*
  it, a size placed in an outer header sees the encoder's output while one inside
  the encoded block sees the pre-framing bytes — which is exactly what the
  protocol wants. This also gives automatic fragmentation, so a mutation that
  grows a tag to several KB is still deliverable.

Values that only exist once a connection is up (endpoints, channel id, token,
block counters, session id) are stamped in at render time from a shared
`SessionState`.

## Graded black-box modes

`--group` / `--service` control how much you tell the fuzzer about the target.
Each accepts a value (`0x0f`), a range (`0x00-0x13`), or `sweep`:

```
-r trace_configure                              modelled body, one known pair
-r generic_sweep --group 0x0f --service 0x02    generic body, one known pair
-r generic_sweep --group 0x0f                   group known, dispatch swept
-r generic_sweep                                group and dispatch both swept
-r generic_sweep --raw-body                     ...and the body is unstructured
```

`--raw-body` matters on its own: every other model sends a *well-formed* tag
stream, so they exercise the handlers' field logic but never the tag walker's
robustness. Unstructured bytes of fuzzed length are what probe the parser —
truncated tags, lengths that overrun, container bits with nothing behind them.

The flags also work on a modelled request, turning it into a **shape router**:
`-r trace_configure --group sweep` sends the captured TraceMgr body to every
other component's handler, which is a cheap way to look for a second consumer of
the same parsing code.

## The service surface (the reachability oracle)

There is no coverage instrumentation, so the only ground truth available is the
runtime's own reply. That turns out to be enough to be useful, and the sweep
modes log it as they go. Every case is classified:

| verdict | meaning |
|---|---|
| `accepted` | replied with status 0 (or no status tag) — the pair exists and the body was acceptable |
| `refused` | replied with a non-zero status — **the pair exists**; the arguments were rejected. The more interesting one: it separates "no such service" from "that service, wrong request", and it is the state a handler is in right before it is driven with the right shape |
| `no-reply` | nothing came back — dropped before dispatch, so not a service |

### Pair files

The recorder writes **pairs, not cases** — a run produces hundreds of cases over a
handful of pairs, and what the next run needs is the pair list, not the history.
Three rules make the file usable as an input rather than a report:

* **`--surface global` (default)** — one cumulative file,
  `logs/service_surface.jsonl`, shared across runs. A pair is written the first
  time it is seen and then not again, and existing pairs are loaded at startup,
  so successive runs *extend* the file instead of repeating it. A pair whose
  verdict later improves (a `refused` that turns out to be `replied`) is appended
  again; the best entry wins when read back.
* **`--surface separate`** — one file per run, stamped, for when a single run's
  findings are wanted in isolation.
* **Nothing is written until a pair actually replies.** The file is created on
  the first write, never upfront, so a run against a dead target or a run that
  finds nothing leaves no file — a directory of empty files is otherwise
  indistinguishable from one of runs that found nothing. `--surface off` writes
  no file at all.

### Reproducibility: one seed per run, recorded

boofuzz's `RandomData` hardcodes `random.Random(0)` in `mutations()`, commented
as being for reproducible test cases. That is not reproducibility, it is a fixed
corpus: **run the same model twice and byte-for-byte identical payloads go out
the second time.** The seed belongs to the run, so this fuzzer draws from a
per-run seed (`RunRandom`), mixed with each primitive's name so two primitives in
one run do not move together:

```
[seed] 4242  (pass --seed 4242 to reproduce this run exactly)
```

`--seed` pins it; otherwise one is generated and written to the run state file.
Same seed reproduces a run exactly, a different seed explores different bytes.

### Resuming an interrupted run

`--state` (default `<log-dir>/<request>.state.json`) records the request, the
group/service, **the seed**, and the last case reached, saved every
`--state-every` cases (default 25) and once more when the run ends:

```
python codesysfuzzer/codesys_fuzzer.py <target> -r trace_configure --cases 5000
    ... interrupted ...
python codesysfuzzer/codesys_fuzzer.py <target> --resume logs/trace_configure.state.json
```

It continues at the first case that has not run, with the recorded seed, instead
of repeating what already ran. Resuming with a *different* model is refused
rather than silently resuming into the middle of an unrelated enumeration — a
mutant index only means something against the same request. The file is written
to a temp sibling and replaced, so an interrupt cannot leave a half-written index
behind.

This is deliberately **not** boofuzz's `session_filename`: that is an opaque
zlib+pickle blob which sets `_index_start` to whatever it finds, and pointing it
at the wrong path silently turns a run into "0 cases, no error" — see
*Findings* below.

### Per-run depth-1 case count

Every run prints, and records in the state file, how many single-field test
cases boofuzz has for the request it is about to build:

```
  depth 1  : 620 single-field case(s)
```

The same number is written to the run state as `depth1_cases`. Indices
`1..N` are the depth-1 cases (one field mutated, everything else at its
default); boofuzz then continues into multi-field combinations, whose count is
far too large to enumerate. The count is request-shape dependent, so it changes
with `--group`/`--service`/`--raw-body` just as the body does.

### Recording a block per case

`--record-block NAME` writes the rendered bytes of a chosen block for each
request actually handed to the socket, one JSON object per line (appended):

```
python codesysfuzzer/codesys_fuzzer.py <target> -r trace_configure \
    --record-block body --record-file logs/trace_body.jsonl
```

`NAME` may be the full qualified name or a unique trailing component (`body`,
`t13`, `t13_data`); repeat the flag to record several. The default file is
`<log-dir>/<request>_blocks_<stamp>.jsonl`.

Recording hooks `Request.render`, not the pre-send callback: the callback runs
before rendering, so it cannot see mutated bytes. A block is re-rendered from
the same mutation context, which is safe here because the renderers are pure
(`FrameEncoder` advances no counters). Note that a model's named block is its
*value* block: `t13` records the tag's content only — to see the whole tag
stream including ids and lengths, record `body`. Each line carries the case
index, seed, the mutated element names, and `{length, hex}` per block.

### Body seeds: what the runtime actually accepted

A pair file that says "0x12/0x39 answered" is a lead; one that says "0x12/0x39
answered when the body carried container 0x81 holding tags 0x11 and 0x18" is a
*seed*. So each recorded pair also carries the tag structure of the request that
drew the reply:

```json
{"group": "0x0012", "service": "0x0039", "verdict": "replied",
 "tag_tree": [{"id": "0x81", "children": [{"id": "0x11", "children": []},
                                          {"id": "0x18", "children": []}]}]}
```

Nesting is kept and container ids keep bit 7, because a flat list of ids cannot
rebuild a body — `parse_tags` masks bit 7, so container `0x81` reads back as
`0x01` and rebuilding from that emits it as a *leaf*, producing a body the
handler never walks into.

`--from-pairs` then uses them, in this order of preference: **a model if one
exists**, else **a body rebuilt from the recorded structure**, else an
unstructured blob. Nothing is recorded for a dropped packet, since the body says
nothing about what was accepted.

### Fuzzing a pair list

`--from-pairs FILE` turns a pair file back into work:

```
python codesysfuzzer/codesys_fuzzer.py <target> --from-pairs logs/service_surface.jsonl
python codesysfuzzer/codesys_fuzzer.py <target> --from-pairs pairs.jsonl --pairs-only implemented
```

Each pair gets its own session. **If the pair already has a request model it is
fuzzed with that model** — the captured and decompilation-derived models carry
the real field shapes, so mutations land on fields the handler reads instead of
being rejected at the first unknown tag — and only pairs with no model fall back
to a fixed pair with an unstructured body. `--pairs-only implemented` restricts
to pairs whose reply carried content, which (calibrated against CmpTraceMgr's
`trace_list`) is what a service that really exists looks like.

The run ends with a table:

```
========== service surface discovered ==========
  cases   : accepted 0, refused 123, replied 77, empty 0, no-reply 0, incomplete 0
  live (group, service) pairs: 39

  group    service   verdict   last status
  0x0003   0x0001    replied   None
  0x0003   0x0004    refused   770
  ...

  pair record: logs/service_surface.jsonl (12 pair(s) written this run, 39 total)
```

The verdicts only mean something against a known-good reply, so read
`tools/README.md` before acting on them. In short: **`replied` (content, no status
tag) is what a real service looks like**; `refused` with the group's *own*
fallback code — which is per group, `770` for most but `24` for `0x12`/`0x13` —
means "no such service"; and anything else means a handler ran and decided.

### Request models

`trace_configure` reproduces the captured `TRACE_CFG_TEMPLATE`
(trace2.pcapng pkt#1564) exactly, and grows the five tags `trace_poc.py`
identified as unchecked `memcpy` destinations in `TraceMgrServiceHandler`:

| tag | destination | bytes to the saved return address |
|---|---|---|
| `0x13` | `v26[4]` @ ebp-0xBC0 | 3012 |
| `0x14` | `v27[4]` @ ebp-0xBBC | 3008 |
| `0x15` | `v28[20]` @ ebp-0xBB8 | 3004 |
| `0x30` | `v34[8]` @ ebp-0x1C | **32** (inside container `0x86`) |
| `0x33` | `v35` u32 @ ebp-0x14 | **24** (inside container `0x86`) |

All five appear legitimately in the captured template, so the model grows real
fields rather than guessing at tag ids. `--list-requests` shows all 17 models;
`generic_sweep` fuzzes group id × service id × tag id × declared length for the
components no one has modelled.

## Findings that shaped the design

**`CLOSE_CHANNEL` does not release a channel.** Measured against Control Win V3
3.5.18.20: four handshakes succeed and the fifth is refused until the runtime
reaps idle channels roughly 20 s later. The existing `codesys_tcp.py` hits the
same ceiling — this is a runtime property, not a client bug. A
fresh-connection-per-test-case design therefore tops out at ~4 cases per 20
seconds. The fuzzer instead holds **one** channel open for the whole run and
re-handshakes only after a case breaks it: a 64-case run performs **one**
handshake.

**When its channel table is full the runtime stops answering — it does not say
so.** It resets new connections instead (`WinError 10053`), which is
indistinguishable from a crash unless you also check whether the listener is
still accepting. `CodesysConnection.open` probes before concluding anything:
a refused *connect* means the runtime is gone, while a live listener plus a
refused *handshake* is channel-table backpressure, so it waits ~20 s for the
reaper and retries instead of aborting the run.

That also means **back-to-back runs need a gap.** A run holds one channel for its
whole duration and `CLOSE_CHANNEL` does not free it, so several runs in quick
succession leave all four slots held and the runtime will reset the next
run's handshake until it has been idle ~20 s. If a run starts and reports
`handshake failed` with the listener alive, wait half a minute and start again.

**The runtime keepalives a held channel, and a reply reader must echo them
without burning its timeout budget.** This is the one that made every test case
look like it opened its own channel. The reply loop was bounded by *frame count*,
and only BLK frames counted — so keepalive frames reached `continue` without
advancing anything and the loop ran its full 32 iterations, each costing a socket
timeout. At the default that is ~64 s per case, spent holding the channel slot
the runtime was waiting on, and a second timeout fired mid-frame, discarding
bytes already read, desynchronising the stream and forcing a re-handshake — so
the next case began with GET_CHANNEL. Bounding the loop by wall clock as well as
by frame count fixes it; a 20-case sweep now holds **one** channel and echoes 45
keepalives (`handshake : 1`).

**A short reply timeout is a false economy.** A timeout that fires mid-frame is
not a clean "no reply" — `_recv_exact` throws away the bytes it had already
consumed, so the stream is left misaligned and the only safe recovery is a new
channel. `--reply-timeout` therefore defaults to a generous 2 s; dropping it to
0.4 s is what produced a GET_CHANNEL per case in testing.

**boofuzz swallows exceptions raised in a pre-send callback.** The
`CallbackMonitor` logs the traceback and then lets the test case proceed, so a
failed re-handshake shows up as a confusing mid-run traceback followed by a case
being sent on a dead socket, rather than as a clean error. Worth knowing when
reading the log.

**boofuzz's `session_filename` is a resume file, not the case database.** It
writes the current mutant index there after every test case, and a later run
reading it silently skips everything up to that index — a second run reports
"0 cases, no error". It is left unset; the sqlite case database is configured
with `db_filename`.

## Verified

* `test_framing.py` — 58 offline assertions, including that the unmutated
  `trace_configure` body is byte-identical to `TRACE_CFG_TEMPLATE`, that the
  whole rendered TCP frame equals what `CodesysTcpClient` builds, that
  fragmentation matches `send_blk` frame-for-frame (per-frame datagram and
  block-driver headers included), that rendering is deterministic, and that
  every model builds and has mutations.
* Live, against Control Win V3 3.5.18.20: `--dry-run --send` for both
  `trace_list` and `trace_configure` is **accepted by the runtime** — the latter
  creates a trace and returns a handle, so the modelled packet is one the real
  implementation parses.
* Live: a 64-case `trace_list` run with 64 replies, 1 handshake, no errors.

**Not yet verified:** the crash path. `trace_configure` is expected to rediscover
the known overflow (the tag `0x30`/`0x33` growth), but no run has been taken far
enough to crash the runtime — that needs a runtime you are willing to lose and
restart by hand.

## Limitations

* **UDP is not supported.** `CmpBlkDrvUdp` caps a services block at ~472 bytes
  and refuses fragmented requests from a non-Gateway port, so most tags could
  not be delivered at all.
* **The crash probe cannot see a hung runtime.** A process that is wedged but
  still listening reads as alive. Detecting that needs an in-guest check.
* **Restart is manual.** `CodesysMonitor.start_target()` returns `False`, so a
  crash ends the run and is recorded rather than being recovered from.
* **The session id is not fuzzed** — an invalid one is rejected before the
  interesting parsers run, so a mutated packet would mostly measure the
  rejection path.
* Fuzzing `trace_configure` **creates traces on the runtime** as a side effect
  (that is what the service does); clean up with
  `codesys_tcp.py --trace-delete <name>`.
* Blind RCE is out of scope. As `poc_tcp.py` documents, the `/GS` cookie needs an
  info leak, so EIP control is where a find stops being directly exploitable.

## Files

| File | Contents |
|---|---|
| `proto.py` | `sys.path` bootstrap + re-export of `codesys_tcp`'s protocol layer |
| `utils.py` | `Leb128Size`, `LyingLeb128Size`, `FrameEncoder`, request skeleton, value tables |
| `services.py` | the 17 request models and the `REQUESTS` registry |
| `transport.py` | `SessionState`, the handshake, reply reading, keepalive echo |
| `monitor.py` | liveness probe, crash synopsis |
| `fuzzer.py` | boofuzz harness (target, session, pre-send injection) |
| `codesys_fuzzer.py` | CLI |
| `test_framing.py` | offline byte-exactness tests |
