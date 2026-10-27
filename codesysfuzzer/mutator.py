#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mutation of real CODESYS request bodies.

This is the data-driven half of the fuzzer: the models in ``services.py`` say
what a request *should* look like, while this module starts from a request that
actually went out and changes its bytes.  The two operate on the same unit — the
services-layer body — so everything below it (``content_size``, channel frames,
CRC32) is repaired by the existing skeleton and ``FrameEncoder``.

Two families of mutation
------------------------
``raw``
    Byte-level havoc: flips, interesting values, integer overwrites, block
    deletion/insertion/duplication, truncation, extension, splice.  It can break
    the tag structure, which is the point — it is what exercises the parser's
    own robustness.

``structured``
    Parse the body as a tag tree first, then mutate the fields a handler reads:
    tag id, declared length, value.  Re-encoding uses CODESYS' own conventions
    (three-byte LEB128 leaf lengths, two-byte container lengths), so the result
    is still a walkable tag stream unless the mutation is deliberately a length
    lie.

``hybrid`` does both.

Determinism
-----------
Every case is a pure function of ``(run seed, seed sha1, case index)``: the
havoc PRNG is seeded from those three values.  Nothing depends on how many cases
ran before, so ``--case N``, ``--seed`` and ``--resume`` all reproduce a case
without replaying the run.  The returned ``plan`` is the mutation's description
— offsets, ids, values — and is what the crash report records.
"""

import copy
import hashlib
import random
import struct
import zlib

from proto import leb128, leb128_pad3, read_leb128

MODES = ("raw", "structured", "hybrid")

#: exactly the ceilings the wire format has, not guesses: leaf lengths are
#: three LEB128 bytes (21 usable bits) and container lengths two (14 bits).
LEAF_LENGTH_MAX = 0x1FFFFF
CONTAINER_LENGTH_MAX = 0x3FFF

INTERESTING_BYTES = (0x00, 0x01, 0x02, 0x03, 0x04, 0x7E, 0x7F, 0x80, 0x81,
                     0x82, 0x83, 0x86, 0xFE, 0xFF)
INTERESTING_16 = (0, 1, 2, 4, 0x10, 0x20, 0x3F, 0x40, 0x7F, 0x80, 0xFF,
                  0x100, 0x3FFF, 0xFFFF)
INTERESTING_32 = (0, 1, 2, 4, 0x10, 0x20, 0x3F, 0x40, 0x7F, 0x80, 0xFF,
                  0x100, 0x3FF, 0x1000, 0x3FFF, 0x7FFFFFFF, 0xFFFFFFFF,
                  24, 32, 64, 128, 256, 512, 1024, 2048, 3004, 3008, 3012,
                  4096, 8192)
INTERESTING_TAG_IDS = (0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x18, 0x19,
                       0x1A, 0x20, 0x21, 0x25, 0x26, 0x30, 0x31, 0x33, 0x34,
                       0x40, 0x4A, 0x4D, 0x4E)
INTERESTING_CONTAINER_IDS = (0x81, 0x82, 0x83, 0x86)
GROW_SIZES = (4, 8, 24, 32, 64, 128, 256, 512, 1024, 2048, 3004, 3012, 4096)
LIE_LENGTHS = (0, 1, 2, 4, 8, 16, 24, 32, 64, 128, 256, 512, 1024,
               3004, 3012, 4096, 0x3FFF)

#: tokens worth inserting.  These are not random: every one is a boundary the
#: protocol or a known handler cares about.
TOKENS = (
    b"\x00", b"\x01", b"\x7f", b"\x80", b"\xff",
    b"\x86\x01", b"\x83\x01", b"\x81\x01",
    b"App.Trace\x00\x00\x00", b"App\x00", b"Task\x00\x00\x00\x00",
    leb128_pad3(0), leb128_pad3(4), leb128_pad3(24), leb128_pad3(32),
    leb128_pad3(3004), leb128_pad3(3008), leb128_pad3(3012),
    leb128_pad3(4096),
)

BIT_MASKS = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80)

_HAVOC_KINDS = ("flip_bits", "set_byte", "set_int16", "set_int32",
                "delete", "insert", "duplicate", "truncate", "extend", "splice")
_HAVOC_WEIGHTS = (6, 5, 2, 3, 3, 4, 2, 1, 2, 2)

_UNSET = object()


# ============================================================
# Deterministic case seeds
# ============================================================

def case_seed(run_seed, sha1, case_index):
    """The PRNG seed for one case.

    ``crc32`` rather than ``hash`` because string hashing is salted per process;
    a resumed run must produce the same bytes in a new process.
    """
    return zlib.crc32(("%d:%s:%d" % (int(run_seed), sha1, int(case_index)))
                      .encode("ascii")) & 0xFFFFFFFF


# ============================================================
# Tag codec (strict)
# ============================================================
#
# ``codesys_tcp.parse_tags`` is deliberately forgiving: when a container's
# children fail to parse it returns ``children=[]``, and re-encoding that turns
# the container into a leaf.  For mutation the distinction matters, so this
# parser raises instead and the caller falls back to raw byte mutation.

def _parse_region(data):
    nodes = []
    pos = 0
    while pos < len(data):
        tid, pos = read_leb128(data, pos)
        size, pos = read_leb128(data, pos)
        if pos + size > len(data):
            raise ValueError("tag 0x%02x claims %d byte(s), %d left"
                             % (tid & 0x7F, size, len(data) - pos))
        value = data[pos:pos + size]
        pos += size
        if tid & 0x80:
            children = _parse_region(value)
            nodes.append({"wire_id": tid, "value": value,
                          "children": children})
        else:
            nodes.append({"wire_id": tid, "value": value, "children": None})
    return nodes


def parse_wire_tags(data):
    """Strict recursive parse.  Raises ``ValueError`` on any malformed tag."""
    return _parse_region(bytes(data))


def parse_seed(body):
    """The parsed tree for ``body``, or ``None`` if it is not a tag stream."""
    try:
        return parse_wire_tags(body)
    except (ValueError, IndexError):
        return None


def _leb128_2(value):
    """Two-byte LEB128, the form CODESYS uses for container lengths.

    This is ``utils.leb128_pad(value, 2)``; duplicated to avoid importing
    ``utils`` (which imports this module for ``SeedBody``).
    """
    value = int(value) & CONTAINER_LENGTH_MAX
    return bytes([(value & 0x7F) | 0x80, (value >> 7) & 0x7F])


def encode_wire_tags(nodes, lie=None):
    """Re-encode a tag tree.

    ``lie`` maps a node path to a declared length that is written instead of the
    real one.  Everything else is encoded the way CODESYS encodes it: a leaf id
    is minimal LEB128 (one byte below 0x80), a leaf length is three bytes, a
    container id carries bit 7 and its length is two bytes.
    """
    lie = lie or {}
    return _encode(nodes, (), lie)


def _encode(nodes, prefix, lie):
    out = []
    for index, node in enumerate(nodes):
        path = prefix + (index,)
        out.append(leb128(int(node["wire_id"])))
        if node["children"] is not None:
            payload = _encode(node["children"], path, lie)
            declared = lie.get(path, len(payload))
            declared = max(0, int(declared))
            if declared <= CONTAINER_LENGTH_MAX:
                out.append(_leb128_2(declared))
            else:
                # A container larger than the two-byte form (a real app
                # download can be) needs a longer LEB128.  The parser reads by
                # value, so this is still well formed; clamping would turn an
                # honest length into an accidental lie.
                out.append(leb128(declared))
            out.append(payload)
        else:
            value = node["value"]
            declared = lie.get(path, len(value))
            declared = max(0, min(int(declared), LEAF_LENGTH_MAX))
            out.append(leb128_pad3(declared))
            out.append(value)
    return b"".join(out)


def walk(nodes, prefix=()):
    """Depth-first ``(path, node)`` over a parsed tree."""
    for index, node in enumerate(nodes):
        path = prefix + (index,)
        yield path, node
        if node["children"] is not None:
            for item in walk(node["children"], path):
                yield item


def _node_at(nodes, path):
    node = nodes[path[0]]
    for index in path[1:]:
        node = node["children"][index]
    return node


# ============================================================
# Structured targets
# ============================================================

def tag_targets(tree):
    """A deterministic list of field-level mutations for a parsed tree.

    Each entry is a description, not a closure, so it is cheap to build, easy to
    put in a crash report, and replayable.  Six per leaf and two per container;
    the caller truncates the list to its budget.
    """
    targets = []
    for index, (path, node) in enumerate(walk(tree)):
        if node["children"] is None:
            current = node["wire_id"] & 0x7F
            new_id = INTERESTING_TAG_IDS[index % len(INTERESTING_TAG_IDS)]
            if new_id == current:
                new_id = ((new_id + 1) & 0x7F) or 1
            targets.append({"kind": "tag_id", "path": path, "value": new_id})
            targets.append({"kind": "value_ff", "path": path})
            targets.append({"kind": "value_int", "path": path,
                            "value": INTERESTING_32[index % len(INTERESTING_32)]})
            targets.append({"kind": "value_grow", "path": path,
                            "value": GROW_SIZES[index % len(GROW_SIZES)]})
            targets.append({"kind": "len_lie", "path": path,
                            "value": LIE_LENGTHS[index % len(LIE_LENGTHS)]})
        else:
            current = node["wire_id"]
            new_id = INTERESTING_CONTAINER_IDS[
                index % len(INTERESTING_CONTAINER_IDS)]
            if new_id == current:
                new_id = INTERESTING_CONTAINER_IDS[
                    (index + 1) % len(INTERESTING_CONTAINER_IDS)]
            targets.append({"kind": "tag_id", "path": path, "value": new_id})
            targets.append({"kind": "len_lie", "path": path,
                            "value": LIE_LENGTHS[index % len(LIE_LENGTHS)]})
    return targets


def _plan_op(target):
    op = {"kind": target["kind"], "path": list(target["path"])}
    if "value" in target:
        op["value"] = target["value"]
    return op


def apply_tag_target(tree, target, max_body_size):
    """Apply one structured target.  Returns ``(body, plan)`` or ``None``.

    ``None`` means the mutation would exceed ``max_body_size``; the caller falls
    back to a havoc mutation rather than sending a truncated game-over body.
    """
    mutated = copy.deepcopy(tree)
    node = _node_at(mutated, target["path"])
    kind = target["kind"]
    lie = {}

    if kind == "tag_id":
        node["wire_id"] = int(target["value"])
    elif kind == "value_ff":
        node["value"] = b"\xff" * max(len(node["value"]), 4)
    elif kind == "value_int":
        packed = struct.pack("<I", int(target["value"]) & 0xFFFFFFFF)
        if len(node["value"]) >= 4:
            node["value"] = packed + node["value"][4:]
        else:
            node["value"] = packed
    elif kind == "value_grow":
        node["value"] = b"A" * int(target["value"])
    elif kind == "len_lie":
        lie[target["path"]] = int(target["value"])
    else:
        raise ValueError("unknown tag target %r" % (kind,))

    body = encode_wire_tags(mutated, lie)
    if len(body) > max_body_size:
        return None
    return body, {"stage": "tag", "ops": [_plan_op(target)]}


# ============================================================
# Byte targets
# ============================================================

def _byte_target(body, slot, slots, max_body_size):
    """One systematic single-byte mutation.

    The offsets are spread over the whole body (``slot * len / slots``) rather
    than taken from the front, so a budget smaller than the body still covers
    every region of it.
    """
    if not body:
        return b"\x00", {"stage": "byte",
                         "ops": [{"kind": "insert", "offset": 0,
                                  "value": "0x00"}]}

    index = (slot * len(body)) // max(1, slots)
    if index >= len(body):
        index = len(body) - 1
    data = bytearray(body)
    if slot % 2 == 0:
        mask = BIT_MASKS[(slot // 2) % len(BIT_MASKS)]
        data[index] ^= mask
        op = {"kind": "flip_bit", "offset": index,
              "mask": "0x%02x" % mask}
    else:
        value = INTERESTING_BYTES[(slot // 2) % len(INTERESTING_BYTES)]
        data[index] = value
        op = {"kind": "set_byte", "offset": index,
              "value": "0x%02x" % value}
    return bytes(data), {"stage": "byte", "ops": [op]}


# ============================================================
# Havoc
# ============================================================

def _one_havoc(data, rng, max_body_size, peer_bodies):
    """Apply one havoc operator in place and return its description."""
    kind = rng.choices(_HAVOC_KINDS, weights=_HAVOC_WEIGHTS, k=1)[0]
    size = len(data)

    if kind == "flip_bits" and size:
        offset = rng.randrange(size)
        mask = rng.choice(BIT_MASKS)
        data[offset] ^= mask
        return {"kind": kind, "offset": offset, "mask": "0x%02x" % mask}

    if kind == "set_byte" and size:
        offset = rng.randrange(size)
        value = rng.choice(INTERESTING_BYTES)
        data[offset] = value
        return {"kind": kind, "offset": offset, "value": "0x%02x" % value}

    if kind == "set_int16" and size >= 2:
        offset = rng.randrange(size - 1)
        value = rng.choice(INTERESTING_16)
        data[offset:offset + 2] = struct.pack("<H", value)
        return {"kind": kind, "offset": offset,
                "value": "0x%04x" % value}

    if kind == "set_int32" and size >= 4:
        offset = rng.randrange(size - 3)
        value = rng.choice(INTERESTING_32)
        data[offset:offset + 4] = struct.pack("<I", value)
        return {"kind": kind, "offset": offset,
                "value": "0x%08x" % value}

    if kind == "delete" and size >= 2:
        offset = rng.randrange(size)
        length = rng.randint(1, min(32, size - offset))
        del data[offset:offset + length]
        return {"kind": kind, "offset": offset, "length": length}

    if kind == "duplicate" and size >= 2:
        offset = rng.randrange(size)
        length = rng.randint(1, min(64, size - offset))
        chunk = bytes(data[offset:offset + length])
        at = rng.randrange(len(data) + 1)
        data[at:at] = chunk
        return {"kind": kind, "offset": offset, "length": length, "at": at}

    if kind == "truncate" and size >= 2:
        at = rng.randrange(1, size)
        del data[at:]
        return {"kind": kind, "at": at}

    if kind == "extend":
        extra = bytes(rng.randrange(256) for _ in range(rng.randint(1, 32)))
        data.extend(extra)
        return {"kind": kind, "length": len(extra)}

    if kind == "splice" and peer_bodies:
        peer = rng.choice(peer_bodies)
        if peer:
            cut = rng.randrange(size + 1)
            peer_cut = rng.randrange(len(peer) + 1)
            data[:] = data[:cut] + peer[peer_cut:]
            return {"kind": kind, "at": cut, "peer_cut": peer_cut}

    # insert is also the fallback for every operator that could not apply
    token = (rng.choice(TOKENS) if rng.random() < 0.5
             else bytes(rng.randrange(256)
                        for _ in range(rng.randint(1, 16))))
    offset = rng.randrange(len(data) + 1)
    data[offset:offset] = token
    if len(data) > max_body_size:
        del data[max_body_size:]
    return {"kind": "insert", "offset": offset, "hex": token.hex()}


def _havoc(body, run_seed, sha1, case_index, max_body_size, peer_bodies):
    rng = random.Random(case_seed(run_seed, sha1, case_index))
    data = bytearray(body)
    ops = [_one_havoc(data, rng, max_body_size, peer_bodies)
           for _ in range(rng.randint(1, 4))]
    if len(data) > max_body_size:
        del data[max_body_size:]
    return bytes(data), {"stage": "havoc", "ops": ops}


# ============================================================
# Entry point
# ============================================================

def mutate_seed(seed, case_index, run_seed, mode="structured", budget=256,
                max_body_size=65536, parsed=_UNSET, peer_bodies=()):
    """Mutate one seed for one case index.

    ``seed`` is anything with ``body`` and ``sha1`` (a :class:`corpus.Seed`).
    ``case_index`` is 1-based *within this seed*.  Returns ``(body, plan)``.

    The stage split is deterministic and depends only on the case index:

    * byte stage  — ``min(len(body), budget)`` single-byte mutations,
    * tag stage   — up to half the budget, field-level mutations,
    * havoc stage — the remainder, a random 1-4 operator stack.

    ``parsed`` lets the caller pass a cached tree; pass ``None`` explicitly to
    say "this body did not parse" and force the raw fallback.
    """
    if mode not in MODES:
        raise ValueError("mode must be one of %s (got %r)" % (MODES, mode))
    case_index = int(case_index)
    if case_index < 1:
        raise ValueError("case_index is 1-based (got %r)" % case_index)
    budget = max(1, int(budget))

    body = bytes(seed.body)
    sha1 = getattr(seed, "sha1", None) or hashlib.sha1(body).hexdigest()
    if parsed is _UNSET:
        parsed = parse_seed(body) if mode in ("structured", "hybrid") else None
    tree = parsed if mode in ("structured", "hybrid") else None
    targets = tag_targets(tree) if tree is not None else []

    if mode == "raw" or tree is None:
        byte_slots = min(len(body), budget)
        tag_slots = 0
    elif mode == "structured":
        byte_slots = 0
        tag_slots = min(len(targets), max(1, budget // 2))
    else:                                        # hybrid
        byte_slots = min(len(body), max(1, budget // 3))
        tag_slots = min(len(targets), max(0, (budget - byte_slots) // 2))

    if case_index <= byte_slots:
        mutated, plan = _byte_target(body, case_index - 1, byte_slots,
                                     max_body_size)
    elif case_index <= byte_slots + tag_slots:
        result = apply_tag_target(tree, targets[case_index - byte_slots - 1],
                                  max_body_size)
        if result is not None:
            mutated, plan = result
        else:
            mutated, plan = _havoc(body, run_seed, sha1, case_index,
                                   max_body_size, peer_bodies)
    else:
        mutated, plan = _havoc(body, run_seed, sha1, case_index,
                               max_body_size, peer_bodies)

    # A byte mutation cannot grow, but the *seed* may already be above the
    # configured ceiling; honour the cap for every stage.
    if len(mutated) > max_body_size:
        mutated = mutated[:max_body_size]

    plan = dict(plan)
    plan.update({"seed": sha1, "case": case_index, "mode": mode})
    return mutated, plan
