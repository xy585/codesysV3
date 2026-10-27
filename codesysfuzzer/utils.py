#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
boofuzz primitives and value tables for CODESYS V3.

The one idea this module exists for
-----------------------------------
A CODESYS request is a tag stream: ``[tag id][LEB128 length][value]``, wrapped in
a services header, wrapped in channel frames, wrapped in a datagram, wrapped in a
block-driver header.  Three of those layers carry a *length* and one carries a
*CRC32*, and every one of them is computed over bytes the fuzzer is about to
mutate.

boofuzz already solves the consistent-length problem with ``s_size`` and
``s_checksum``, but it has no LEB128 output format — hence :class:`Leb128Size`.
And the framing is not expressible as primitives at all, because a mutated body
may no longer fit in one channel frame — hence :class:`FrameEncoder`, which
rebuilds the real frame sequence from the rendered services bytes.  It is the
same split ``CodesysTcpClient.send_blk`` performs, minus the sending.

Verified against boofuzz 0.4.2 source:
  * ``Block.encode`` runs its encoder *after* ``get_child_data()``, so boofuzz
    primitives model the *unframed* services bytes and the encoder frames them.
  * ``Size`` resolves its target by calling ``.render()`` on the named block, so
    a size in an outer header sees the encoder's output, while a size whose
    target sits inside the encoded block sees the pre-framing bytes.  Both are
    used below and both are what the protocol wants.
"""

import random
import struct
import zlib

from boofuzz import (
    Fuzzable, blocks, s_block, s_group, s_initialize, s_random, s_static,
)
from boofuzz.blocks import Size
from boofuzz.primitives.random_data import RandomData

from mutator import mutate_seed, parse_seed

from proto import (
    DATAGRAM_HEADER, DATAGRAM_MAGIC, HDR_PREFIX_WORDS, PKT_INFO, PROTO_TAG,
    SERVICE_CHANNEL, CodesysTcpClient, build_blk, build_block_frame,
    full_address, leb128, leb128_pad3,
)

#: LEB128 padded to three bytes carries 21 usable bits; the top bits of the
#: third byte are silently dropped, so clamp rather than emit a length the
#: runtime would decode as something else entirely.
LEB128_3_MAX = 0x1FFFFF

#: ceiling for a value encoded in two LEB128 bytes (14 bits)
LEB128_2_MAX = 0x3FFF


def leb128_pad(value, width):
    """LEB128 in exactly ``width`` bytes, continuation bit clear on the last.

    ``codesys_tcp.leb128_pad3`` is the ``width=3`` case, and it is what CODESYS
    uses for a *leaf* tag length (4 -> ``84 80 00``).  Container lengths are
    encoded differently — minimally, so 96 is ``e0 00`` and not ``e0 80 00`` —
    which is why the width has to be selectable rather than fixed at three.
    Reproducing the capture byte-for-byte depends on this distinction.
    """
    out = bytearray()
    v = int(value)
    for i in range(width):
        byte = v & 0x7F
        v >>= 7
        if i < width - 1:
            byte |= 0x80
        out.append(byte)
    if v:
        raise ValueError("value %d does not fit in %d LEB128 byte(s)"
                         % (value, width))
    return bytes(out)

#: what one BLK frame can carry inside a 512-byte datagram
FRAME_DATA_FIRST = CodesysTcpClient.MAX_FRAME_DATA_FIRST     # 468
FRAME_DATA_CONT = CodesysTcpClient.MAX_FRAME_DATA_CONT       # 476


# ============================================================
# LEB128 sizes
# ============================================================

class Leb128Size(Size):
    """``s_size`` that renders as fixed-width LEB128 instead of little endian.

    ``Size`` renders through an integer ``BitField``, i.e. fixed-width little
    endian; CODESYS wants LEB128 — 3 bytes for a leaf tag length (4 ->
    ``84 80 00``, 452 -> ``c4 83 00``) and 2 for a container (96 -> ``e0 00``).
    Only the encoding step changes, so the length bookkeeping, ``offset``,
    ``math`` and the recursion guard all behave exactly as upstream.

    ``length`` doubles as the encoded width, so ``Size``'s own offset arithmetic
    stays correct.
    """

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("length", 3)
        super().__init__(*args, **kwargs)
        if self.length not in (2, 3):
            raise ValueError("Leb128Size encodes in 2 or 3 bytes "
                             "(got length=%r)" % (self.length,))

    def _length_to_bytes(self, length):
        value = int(self.math(length))
        if self.length == 2:
            value &= LEB128_2_MAX
        else:
            value &= LEB128_3_MAX
        return leb128_pad(value, self.length)


class LyingLeb128Size(Leb128Size):
    """A tag length fuzzed *independently* of the content it describes.

    ``Leb128Size`` keeps the declared length equal to the real one, which is what
    a well-formed packet needs.  But the bug class this fuzzer is aimed at is a
    handler that trusts the declared length without checking it against the bytes
    actually present, so the declared length has to be fuzzable on its own.

    Mutations arrive as ints — ``BitField.mutations`` yields 140 boundary values
    for a 24-bit field — so they are re-encoded as LEB128 rather than through the
    stock fixed-width path.
    """

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("fuzzable", True)
        super().__init__(*args, **kwargs)

    def encode(self, value, mutation_context):
        if value is None:                       # primitive is not the mutant
            return super().encode(value, mutation_context)
        return leb128_pad(int(value) & LEB128_3_MAX, 3)


def s_leb_size(block_name, name=None, fuzzable=False, math=None, width=3):
    """``s_size`` in CODESYS' LEB128 form.  Sits *before* the sized block.

    ``width=3`` is a leaf tag length; ``width=2`` is a container length, which
    CODESYS encodes minimally.  ``block_name`` must name a block, not a
    primitive: a ``Size`` with no target resolves to zero, which would emit
    ``80 80 00`` for every tag.
    """
    blocks.CURRENT.push(Leb128Size(
        name=name, block_name=block_name, request=blocks.CURRENT,
        length=width, fuzzable=fuzzable, math=math))


# ============================================================
# Seeded randomness
# ============================================================
#
# boofuzz's RandomData hardcodes ``random.Random(0)`` in ``mutations()``, with a
# comment saying it is for reproducible test cases.  It is not reproducibility,
# it is a fixed corpus: run the same model twice and byte-for-byte identical
# payloads go out the second time.  The seed is a *property of the run*, so a run
# that wants to be repeatable should record the seed it used — not one primitive
# silently always reusing zero.
#
# So: one seed per run, mixed with the primitive's own name to give each
# primitive a distinct but reproducible stream.  Pass ``--seed`` to fix it, or
# read it out of the run state file afterwards.

_RUN_SEED = None


def set_run_seed(seed):
    """Pin the run's seed.  Recorded in the run state so a run is repeatable."""
    global _RUN_SEED
    _RUN_SEED = int(seed) & 0xFFFFFFFF
    return _RUN_SEED


def run_seed():
    """The run's seed, generated on first use if none was given."""
    global _RUN_SEED
    if _RUN_SEED is None:
        _RUN_SEED = random.SystemRandom().randrange(1 << 32)
    return _RUN_SEED


def stream_seed(name):
    """A stable per-primitive seed.

    ``crc32`` rather than ``hash()`` because ``hash`` is salted per process for
    strings, which would make the same run seed give different bytes on a rerun —
    exactly the property being fixed here.
    """
    return (run_seed() ^ (zlib.crc32(name.encode("utf-8")) & 0xFFFFFFFF)) \
        & 0xFFFFFFFF


class RunRandom(RandomData):
    """``RandomData`` seeded per run instead of per call site.

    Same mutation shape as upstream — ``max_mutations`` values whose length walks
    ``min_length + i * step`` when a ``step`` is given, or is drawn uniformly
    otherwise — but the bytes come from :func:`stream_seed`, so two runs of the
    same model send different payloads and the same run seed reproduces them.
    """

    def mutations(self, default_value):
        name = self.qualified_name or self.name or "?"
        rnd = random.Random(stream_seed(name))
        for i in range(self.get_num_mutations()):
            if self.step:
                length = self.min_length + i * self.step
            else:
                length = rnd.randint(self.min_length, self.max_length)
            yield bytes(rnd.randrange(256) for _ in range(length))


def s_run_random(default_value, min_length=0, max_length=1, max_mutations=25,
                 step=None, name=None):
    """``s_random`` with the run's seed.  Use this instead of ``s_random``."""
    # no request= here: RandomData forwards its kwargs to Fuzzable, which has no
    # such parameter (Size does, which is why the sizers above take one)
    blocks.CURRENT.push(RunRandom(
        name=name, default_value=default_value, min_length=min_length,
        max_length=max_length, max_mutations=max_mutations, step=step))


def s_lying_leb_size(block_name, name=None):
    """A fuzzable declared length that may disagree with the block it names."""
    blocks.CURRENT.push(LyingLeb128Size(
        name=name, block_name=block_name, request=blocks.CURRENT, length=3))


# ============================================================
# Seed-driven body
# ============================================================
#
# The models in services.py are grammar-driven: each field is a primitive and
# boofuzz gets one mutation per primitive.  A SeedBody is the data-driven
# counterpart — one primitive whose mutations are pre-mutated copies of real
# request bodies.  Because it is the *only* fuzzable primitive under ``body``
# (and therefore the only one in the whole request), boofuzz's depth-1
# enumeration is exactly "one mutant per case", and depth 2 immediately runs out
# of valid combinations (the one primitive cannot be mutated twice).

class SeedBody(Fuzzable):
    """A body built by mutating captured request bodies.

    ``seeds`` are :class:`corpus.Seed` objects for one (group, service) pair.
    The default value is the first seed's body; every mutation is derived
    deterministically from the run seed, the seed's sha1 and the case index.

    ``case_index`` inside :func:`mutator.mutate_seed` is local to the seed.  The
    order of ``seeds`` and the per-seed budget are fixed for a run, so the local
    index is recoverable from boofuzz's global mutant index — that is what
    :meth:`plan_for_case` does for the crash report.
    """

    def __init__(self, seeds, run_seed, mode="structured",
                 mutations_per_seed=256, max_body_size=65536,
                 order="contiguous", name="seed_body"):
        self.seeds = list(seeds)
        if not self.seeds:
            raise ValueError("SeedBody needs at least one seed")
        if order not in ("contiguous", "round-robin"):
            raise ValueError("order must be 'contiguous' or 'round-robin' "
                             "(got %r)" % (order,))
        if mode not in ("raw", "structured", "hybrid"):
            raise ValueError("mode must be raw, structured or hybrid "
                             "(got %r)" % (mode,))
        self.run_seed = int(run_seed) & 0xFFFFFFFF
        self.mode = mode
        self.mutations_per_seed = max(1, int(mutations_per_seed))
        self.max_body_size = int(max_body_size)
        self.order = order
        self._parsed = {}
        super().__init__(name=name, default_value=self.seeds[0].body,
                         fuzzable=True)

    # -- planning -------------------------------------------------
    def _tree(self, seed):
        if seed.sha1 not in self._parsed:
            self._parsed[seed.sha1] = parse_seed(seed.body)
        return self._parsed[seed.sha1]

    def _peer_bodies(self, seed):
        return [s.body for s in self.seeds if s.sha1 != seed.sha1]

    def _case(self, global_index):
        """Global 1-based case index -> ``(seed, local_index)``."""
        index = int(global_index) - 1
        per_seed = self.mutations_per_seed
        if self.order == "round-robin":
            count = len(self.seeds)
            return self.seeds[index % count], (index // count) + 1
        return (self.seeds[index // per_seed],
                (index % per_seed) + 1)

    def _mutate(self, seed, local_index):
        parsed = None if self.mode == "raw" else self._tree(seed)
        return mutate_seed(
            seed, local_index, self.run_seed, mode=self.mode,
            budget=self.mutations_per_seed, max_body_size=self.max_body_size,
            parsed=parsed, peer_bodies=self._peer_bodies(seed))

    # -- boofuzz interface ---------------------------------------
    def mutations(self, default_value):
        if self.order == "round-robin":
            groups = ((seed, local)
                      for local in range(1, self.mutations_per_seed + 1)
                      for seed in self.seeds)
        else:
            groups = ((seed, local)
                      for seed in self.seeds
                      for local in range(1, self.mutations_per_seed + 1))
        for seed, local in groups:
            body, _plan = self._mutate(seed, local)
            yield body

    def num_mutations(self, default_value=None):
        # Overridden deliberately: Fuzzable's default exhausts mutations(),
        # which for a large corpus means building every mutant just to count it.
        return len(self.seeds) * self.mutations_per_seed

    def body_for_case(self, global_index):
        """``(body, plan)`` for a global case index, or ``None``.

        The case index is the same one boofuzz reports and ``--case`` takes.
        Used by the case-report generator: a crash report names the case that
        was confirmed by hand, and the body for it may not be in the recent
        trail (the trigger can be outside those ten).
        """
        if global_index is None:
            return None
        index = int(global_index)
        if index < 1 or index > self.num_mutations():
            return None
        seed, local = self._case(index)
        return self._mutate(seed, local)

    def plan_for_case(self, global_index):
        """The mutation plan the crash report should record, or ``None``."""
        result = self.body_for_case(global_index)
        return None if result is None else result[1]


def s_tagged(tag_id, block_name, filler=b"\x00", min_length=0, max_length=None,
             name=None):
    """A well-formed tag: id, LEB128 length, then a fuzzable value block.

    The length always tracks the real content, so however far a mutation grows
    the value the packet stays parseable and the request reaches the handler
    instead of being dropped by the tag walker.
    """
    s_static(bytes([tag_id]))
    s_leb_size(block_name, name=name)
    with s_block(block_name):
        if max_length is None:
            s_static(filler)
        else:
            s_run_random(filler, min_length=min_length,
                         max_length=max_length, name=block_name + "_data")


def s_u32_tag(tag_id, value, name=None):
    """A fixed 4-byte tag — the shape most CODESYS scalar fields take."""
    s_tagged(tag_id, name or ("tag_%02x" % tag_id),
             filler=struct.pack("<I", value), max_length=None)


def s_container(tag_id, body_fn):
    """A parent tag.  Its LEB128 id has bit 7 set, and its length is computed.

    The id is the LEB128 CODESYS itself uses for ids above 0x7f (0x86 ->
    ``86 01``), and the length is a two-byte LEB128 over a block wrapping the
    children.  Two bytes covers container lengths up to 16383, comfortably above
    anything the size sweeps reach.
    """
    s_static(_leb128_id(tag_id))
    s_leb_size("c_%02x" % tag_id, width=2)
    with s_block("c_%02x" % tag_id):
        body_fn()


def _leb128_id(tag_id):
    """LEB128 of ``tag_id | 0x80`` — the container form, matching parent_tag."""
    return leb128(tag_id | 0x80)


# ============================================================
# Framing
# ============================================================

class FrameEncoder(object):
    """Turns rendered *services* bytes into the real channel-frame sequence.

    Bound to the live connection so it can stamp in the channel id, the channel
    token and the block counters, none of which exist until the handshake has
    run.  Being an encoder rather than a builder is what makes mutation safe: it
    is handed whatever boofuzz rendered, however long that turned out to be, and
    it always emits a frame sequence the runtime will reassemble.

    Emits **whole** block-driver frames, not just the channel layer: over TCP
    every BLK frame is carried by its own datagram behind its own 8-byte block
    driver header (``CodesysTcpClient.send_raw`` is called once per frame), so
    the datagram header and the block-driver length repeat per frame rather than
    appearing once for the message.  Both lengths are computed here from the
    byte count, which is why the skeleton carries no size field for them.

    Mirrors ``CodesysTcpClient.send_blk`` exactly — including that the first
    frame declares the size and CRC32 of the *whole* message rather than of the
    chunk it carries.

    Deliberately **pure**: it reads the state and returns bytes, and advances no
    counter.  boofuzz renders a block more than once per test case (a ``Size``
    resolves its target by rendering it, and then the block renders again on its
    own), so an encoder that mutated ``tx_blk`` would emit a different BLK id on
    each pass and the packet actually sent would not be the packet the sizes and
    CRC were computed for.  ``CodesysConnection.send`` advances the counter
    instead, once per frame actually written.
    """

    def __init__(self, state):
        self.state = state

    def __call__(self, services_bytes):
        total = len(services_bytes)
        crc = zlib.crc32(services_bytes) & 0xFFFFFFFF
        state = self.state
        channel_id = state.channel_id or 0
        token = state.token or b"\x00\x00"
        ack_id = state.rx_blk or 0
        dg_head = datagram_header(state)

        out = b""
        off = 0
        first = True
        blk_id = (state.tx_blk or 0) + 1
        while first or off < total:
            room = FRAME_DATA_FIRST if first else FRAME_DATA_CONT
            chunk = services_bytes[off:off + room]
            frame = build_blk(channel_id, token, blk_id, ack_id, chunk,
                              first=first, total=total, crc=crc)
            out += build_block_frame(dg_head + frame)
            off += len(chunk)
            blk_id += 1
            first = False
        return out


def datagram_header(state):
    """The 20-byte CmpRouter header, with the endpoints taken from the socket.

    Only the field *sizes* are load-bearing — the block driver overwrites both
    addresses on receive — but the header must be regenerated per connection
    because the client's port is whatever the OS handed out.
    """
    local_port = state.local_port or 0
    local_ip = state.local_ip or "0.0.0.0"
    remote_port = state.remote_port or 0
    remote_ip = state.remote_ip or "0.0.0.0"

    sender = full_address(remote_port, remote_ip)
    receiver = full_address(local_port, local_ip)
    total = 6 + len(sender) + len(receiver)
    pad = (-total) % 4
    hop_info = ((14 & 0x1F) << 3) | HDR_PREFIX_WORDS
    lengths = ((len(receiver) // 2) << 4) | (len(sender) // 2)
    head = (bytes([DATAGRAM_MAGIC, hop_info, PKT_INFO, SERVICE_CHANNEL, 0,
                   lengths]) + sender + receiver + b"\x00" * pad)
    assert len(head) == DATAGRAM_HEADER, (len(head), DATAGRAM_HEADER)
    return head


# ============================================================
# Request skeleton
# ============================================================

def request_skeleton(name, state, group, service_id, body_fn):
    """Build a complete fuzzable CODESYS request.

    boofuzz only has to model the *services* layer; everything below it is
    produced by :class:`FrameEncoder` at render time::

        services   proto | hdrsize | group | service_id | session | len | add
        body       whatever ``body_fn`` pushes
        - - - - - - below this line: FrameEncoder - - - - - -
        channel    BLK frames, first 468 bytes of data then 476 per continuation
        datagram   20-byte CmpRouter header, repeated per frame
        block drv  magic | len(datagram) + 8, repeated per frame

    The two lower lengths are not boofuzz ``Size`` primitives because they are
    internal to each frame rather than a field at a fixed offset: the encoder
    knows the byte count, so it writes them.

    ``group``/``service_id`` may be an int (fixed) or a list of ints (fuzzed).
    ``state`` supplies the live channel/session values at render time and must
    already exist — the connection object that owns it is created before the
    request is defined, so it does.
    """
    # s_initialize refuses to redefine a name, and boofuzz keeps requests in a
    # module-global registry, so rebuilding one (as the tests do) has to start
    # by dropping the old definition.
    blocks.REQUESTS.pop(name, None)
    s_initialize(name)

    with s_block("frames", encoder=FrameEncoder(state)):
        with s_block("services"):
            s_static(struct.pack("<H", PROTO_TAG), name="svc_proto")
            s_static(struct.pack("<H", 16), name="svc_hdrsize")
            _s_id(group, "service_group")
            _s_id(service_id, "service_id")
            s_static(b"\x00" * 4, name="session_id")
            # content_size describes the body; "body" lives inside the encoded
            # block, so this resolves *before* framing.
            blocks.CURRENT.push(Size(
                name="content_size", block_name="body",
                request=blocks.CURRENT, length=4, endian="<", fuzzable=False))
            s_static(b"\x00" * 4, name="services_add")
            with s_block("body"):
                body_fn()

    # return the request so callers can inject live values by name without
    # depending on blocks.CURRENT
    return blocks.CURRENT


def _s_id(value, name):
    """Emit a 2-byte id, fixed or as a fuzzable group."""
    if isinstance(value, (list, tuple, set)):
        values = [v if isinstance(v, bytes) else int(v).to_bytes(2, "little")
                  for v in value]
        s_group(values=values, name=name)
    else:
        s_static((value if isinstance(value, bytes)
                  else int(value).to_bytes(2, "little")), name=name)


# ============================================================
# Live value injection
# ============================================================

def _s_update(name, value, request=None):
    """Set a primitive's default so the next render emits ``value``.

    ``request`` should be passed explicitly.  The OPC UA fuzzer relies on
    ``blocks.CURRENT``, which ``s_initialize`` leaves pointing at the last request
    defined — true here too, but only by accident of there being exactly one
    request, and it would break silently the moment a second model were built.

    Returns the number of primitives touched.  A 0 means a typo'd name and a
    packet that would go out with placeholder bytes, so callers assert on it.
    """
    req = request if request is not None else blocks.CURRENT
    if isinstance(value, str):
        value = value.encode("latin-1")
    hits = [n for n in req.names if n.rsplit(".")[-1] == name]
    for n in hits:
        req.names[n]._default_value = value
    return len(hits)


# ============================================================
# Value tables
# ============================================================

#: Service groups, recovered from the binary rather than copied from a write-up.
#:
#: Every component registers through ``sub_106BFA0(group_id, handler)`` in
#: CODESYSControlService_dump1.exe.i64; enumerating its 22 call sites yields the
#: runtime's own dispatch table.  Group ids were read from the ``push``
#: immediately before each call, and the component names cross-check against the
#: Kaspersky ICS-CERT table exactly where they overlap.
#:
#: Two groups here are absent from that table — 0x03 and 0x14 — and are worth
#: fuzzing precisely because they are undocumented.  Two of the 22 registrations
#: are duplicate ids (0x02 and 0x06 register twice, for start and stop), so 22
#: calls yield 21 distinct groups.
#:
#: handler addresses are IDA-side; the image is rebased +0x5F0000 against the
#: running process (so CmpTraceMgr's handler is IDA 0x1077280 = runtime
#: 0x00A88580).
GROUP_NAMES = {
    0x01: "CmpDevice",        # loc_F82A40
    0x02: "CmpApp",           # sub_EB1720
    0x03: "unknown_03",       # sub_FBF8A0  <- not in the published table
    0x04: "CmpVisuServer",    # sub_1099700
    0x05: "CmpLog",           # sub_FBAF50
    0x06: "CmpSettings",      # sub_106B600
    0x07: "SysEthernet",      # sub_10A3210
    0x08: "CmpFileTransfer",  # sub_F8D1D0
    0x09: "CmpIecVarAccess",  # sub_FA4A40
    0x0B: "CmpIoMgr",         # sub_FB20A0
    0x0C: "CmpUserMgr",       # sub_108CDE0
    0x0F: "CmpTraceMgr",      # sub_1077280
    0x11: "PlcShell",         # sub_10247B0
    0x12: "CmpAppBP",         # sub_EBF830
    0x13: "CmpAppForce",      # sub_EC5900
    0x14: "unknown_14",       # sub_102C950  <- not in the published table
    0x18: "CmpAlarmManager",  # sub_E9E4C0
    0x1B: "CmpMonitor",       # sub_FC34B0
    0x1D: "CmpCodeMeter",     # sub_F7D430
    0x1F: "CmpCoreDump",      # sub_F7E9D0
    0x22: "CmpOpenSSL",       # sub_101CFF0
}
GROUP_IDS = sorted(GROUP_NAMES)

#: Groups whose handler reaches the *shared* tag-stream reader (``sub_ECA510``,
#: which returns the content pointer and the parsed length), recovered the same
#: way.  This is the reason the generic tag-stream and ``--raw-body`` modes are
#: the highest-leverage thing the fuzzer does rather than a fallback for
#: un-modelled services: those seven groups run their requests through one
#: parser, so a bug in it is reachable from any of them — and equally, a
#: modelled body for one of them is exercising the same code the others do.
#:
#: The two undocumented groups are both here, and both are among the largest
#: handlers in the image (0x03 has 44 direct callees, 0x14 has 28), which makes
#: them the most attractive unmodelled targets.  Groups absent from this set
#: either do not take tag streams at all (CmpApp, CmpAppBP, CmpAppForce,
#: CmpCoreDump, CmpAlarmManager — 2-4 callees, simple request/reply) or parse
#: their own fields.
TAG_STREAM_GROUPS = (0x03, 0x05, 0x08, 0x09, 0x0C, 0x11, 0x14)

#: rough handler size in direct callees, as a proxy for how many service ids the
#: group has and hence how much of the surface a sweep has to cover
GROUP_CALLEE_COUNT = {
    0x03: 44, 0x08: 38, 0x0C: 35, 0x09: 34, 0x14: 28, 0x05: 27, 0x0B: 24,
    0x11: 22, 0x07: 18, 0x22: 15, 0x06: 13, 0x1D: 13, 0x1B: 8, 0x18: 4,
    0x13: 3, 0x1F: 3, 0x02: 2, 0x04: 2, 0x12: 2,
}

#: CmpTraceMgr funnels ids 1..0x13 through one sub-dispatcher (``sub_1077280``);
#: 0x02 is the only one that reaches the vulnerable handler.
SERVICE_IDS_SWEEP = list(range(0x01, 0x28))

#: tag ids as they appear on the wire.  Bit 7 set marks a container, so this is
#: the leaf range; containers are built explicitly where a model needs one.
TAG_VALUES = [bytes([i]) for i in range(0x01, 0x60)]

#: interesting declared lengths: the confirmed overflow offsets from
#: trace_poc.py (24 and 32 bytes to the saved return address for the nested
#: triggers, 3004/3008/3012 for the flat ones) plus round boundaries.
LENGTH_VALUES = [b"\x00", b"\x01", b"\x02", b"\x04", b"\x08", b"\x0f",
                 b"\x10", b"\x1f", b"\x20", b"\x3f", b"\x40", b"\x7f",
                 b"\x80", b"\xff"]
OVERSIZE_VALUES = [leb128_pad3(n) for n in
                   (32, 64, 128, 256, 472, 512, 1024, 2048, 3004, 3008, 3012,
                    4096, 8192)]


#: re-exported so services.py and the tests share one definition
__all__ = [
    "Leb128Size", "LyingLeb128Size", "FrameEncoder", "SeedBody", "s_leb_size",
    "s_lying_leb_size", "s_tagged",
    "s_u32_tag", "s_container", "s_initialize", "s_block", "s_group",
    "s_random", "s_run_random", "RunRandom", "set_run_seed", "run_seed",
    "stream_seed", "s_static", "request_skeleton", "datagram_header",
    "_s_update", "GROUP_NAMES", "GROUP_IDS", "SERVICE_IDS_SWEEP", "TAG_VALUES",
    "LENGTH_VALUES", "OVERSIZE_VALUES", "datagram_header", "leb128_pad",
    "FRAME_DATA_FIRST", "FRAME_DATA_CONT", "LEB128_3_MAX", "LEB128_2_MAX",
]
