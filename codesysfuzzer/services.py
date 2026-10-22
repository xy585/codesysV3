#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Request models for the CODESYS V3 services layer.

Each model is a function that pushes boofuzz primitives into the ``body`` block
of :func:`utils.request_skeleton`.  ``REQUESTS`` maps a CLI name to
``(group, service_id, builder)``.

What the models are aiming at
-----------------------------
``TraceMgrServiceHandler`` (CmpTraceMgr service 0x0002) hands five tag payloads
straight to ``memcpy`` with the *declared* tag length and a small stack buffer as
the destination — the parser proves the bytes are present in the body, never that
they fit.  From ``trace_poc.py``, measured on the live runtime image:

    tag 0x13  ->  v26[4]   @ ebp-0xBC0     3012 bytes to the saved return address
    tag 0x14  ->  v27[4]   @ ebp-0xBBC     3008
    tag 0x15  ->  v28[20]  @ ebp-0xBB8     3004
    tag 0x30  ->  v34[8]   @ ebp-0x1C        32   (inside container 0x86)
    tag 0x33  ->  v35 u32  @ ebp-0x14        24   (inside container 0x86)

The captured ``TRACE_CFG_TEMPLATE`` (trace2.pcapng pkt#1564) legitimately carries
all five: 0x13/0x14/0x15 as top-level 4-byte u32s, and 0x30/0x33 inside container
0x86.  So ``trace_configure`` below reproduces that template byte-for-byte and
grows exactly those five values — which is why it should rediscover the bug
rather than needing to stumble onto the tag ids.

The length sweep
----------------
``s_random`` with a ``step`` walks lengths deterministically (``min + i*step``)
instead of picking random ones, so the sweep is reproducible and reaches past
each threshold in a predictable number of cases.  A 4-byte value growing to
several KB is still deliverable: ``FrameEncoder`` fragments it into as many BLK
frames as it takes, which is the ceiling the UDP PoC could not get past.
"""

import struct

from boofuzz import s_group, s_static

from proto import tag
from utils import (
    GROUP_IDS, SERVICE_IDS_SWEEP, TAG_VALUES, request_skeleton, s_block,
    s_container, s_leb_size, s_lying_leb_size, s_run_random,
)

#: deterministic growth sweep for the memcpy destinations.  Step 64 means the
#: second case (68 bytes) already clears the 32-byte nested threshold, while the
#: stride still reaches 4036 for the ~3012-byte flat ones.
SIZE_SWEEP = dict(min_length=4, max_length=4096, step=64)


def _s_static_tag(tag_id, value):
    """A byte-for-byte tag, for the parts of a captured body that never vary."""
    s_static(tag(tag_id, value))


def _s_value_tag(tag_id, block_name, default, max_length=None):
    """A tag whose *content* is fuzzed at a fixed length."""
    s_static(bytes([tag_id]))
    s_leb_size(block_name)
    with s_block(block_name):
        s_run_random(default, min_length=len(default),
                 max_length=max_length if max_length is not None else len(default),
                 name=block_name + "_data")

def _s_value_tag_random(block_name, default, max_length=None):
    """A tag whose *content* is fuzzed at a fixed length."""
    with s_block(block_name):
        s_static(bytes([0x86, 0x01]))
        # s_run_random(b"\x86", min_length=1, max_length=1, name=block_name+"_tag")
        s_leb_size(block_name)
        s_run_random(default, min_length=len(default),
                         max_length=max_length if max_length is not None else len(default),
                         name=block_name + "_data")

def _s_body_container_tag_random():
    block_name = "tagrandom"
    default = b"App.Trace\x00\x00\x00"
    max_length = 12
    with s_block(block_name):
        # s_static(bytes([0x30]))
        s_run_random(b"\x30", min_length=1, max_length=1, name=block_name+"_tag")
        s_leb_size(block_name)
        s_run_random(default, min_length=len(default),
                         max_length=max_length if max_length is not None else len(default),
                         name=block_name + "_data")

def _s_grow_tag(tag_id, block_name, default, sweep=None):
    """A tag whose content is fuzzed *and* grown — a memcpy-destination candidate.

    The length field is kept in step with the content (via ``s_leb_size``) so the
    packet stays well formed: this targets buffers that are too small, not
    lengths that lie about the bytes present.  ``trace_configure_liar`` covers
    that other case.
    """
    sweep = sweep or SIZE_SWEEP
    s_static(bytes([tag_id]))
    s_leb_size(block_name)
    with s_block(block_name):
        s_run_random(default, min_length=len(default),
                 max_length=sweep["max_length"], step=sweep["step"],
                 name=block_name + "_data")


# ============================================================
# CmpTraceMgr (group 0x000F)
# ============================================================

def body_trace_configure():
    """The captured TRACE_CONFIGURE body, reproduced and grown.

    Unmutated this renders byte-for-byte identical to ``TRACE_CFG_TEMPLATE``
    (asserted by ``test_framing.py``), so the modelled packet is one the runtime
    is known to accept — and the fuzzer is modifying a real request rather than a
    guess at one.
    """
    # --- flat prologue: trace name, then the app/task and its scalars ---
    _s_value_tag(0x10, "trace_name", b"App.Trace\x00\x00\x00", max_length=12)
    _s_value_tag(0x16, "t16", b"\x00\x00\x00\x00", max_length=8)
    _s_value_tag(0x11, "app_name", b"App\x00", max_length=8)
    _s_value_tag(0x12, "task_name", b"Task\x00\x00\x00\x00", max_length=12)

    # --- the three flat memcpy destinations (the article's tags 19/20/21) ---
    _s_grow_tag(0x13, "t13", b"\x01\x00\x00\x00")
    _s_grow_tag(0x14, "t14", b"\x65\x00\x00\x00")
    _s_grow_tag(0x15, "t15", b"\x10\x00\x00\x00")

    s_container(0x86, _body_container_86)

def body_trace_configure_random_tag():
    #s_container(0x86, _s_body_container_tag_random)
    _s_value_tag_random("tagrandom", b"\x00", max_length=12)
    
    # for i in range(256):
    #     _s_value_tag(i, "s"+str(i), b"\x00\x00\x00\x00", max_length=8)
    #     _s_grow_tag(i, "g"+str(i), b"\x00\x00\x00\x00")

def _body_container_86():
    """Container 0x86 — the short path to EIP (tags 0x30 and 0x33)."""
    _s_grow_tag(0x30, "t30", b"\x0a\x00\x00\x00")
    _s_value_tag(0x31, "t31", b"\x01\x00\x00\x00", max_length=8)
    _s_value_tag(0x34, "t34", b"\x33\x00\x00\x00", max_length=8)
    _s_grow_tag(0x33, "t33", b"\x05\x00\x00\x00")
    s_container(0x83, _body_container_83)


def _body_container_83():
    """Inner container 0x83 — the recorded variable descriptor.

    Tag 0x4d is the client-supplied variable address; ``trace_poc.py`` notes that
    if the runtime uses it unvalidated, service 0x0007 becomes an arbitrary read.
    """
    _s_value_tag(0x21, "t21", b"\x01\x02\x00\x00", max_length=8)
    _s_value_tag(0x4e, "t4e", b"\x05\x00\x00\x00", max_length=8)
    _s_value_tag(0x4d, "t4d", b"\x02\x9e\x3b\x06\x00\x00\x00\x00", max_length=16)
    _s_value_tag(0x20, "t20", b"POU.iTest\x00\x00\x00", max_length=16)
    _s_value_tag(0x25, "t25", b"\x07\x00\x00\x00", max_length=8)
    _s_value_tag(0x26, "t26", b"\x02\x00\x00\x00", max_length=8)


def body_trace_configure_flat():
    """Minimal body: only the three top-level memcpy destinations, grown.

    The article's shape.  A real trace name is kept in front so the handler gets
    far enough to walk the rest, but nothing else is sent — reaching the large
    triggers with the smallest possible packet.
    """
    _s_value_tag(0x10, "trace_name", b"App.Trace\x00\x00\x00", max_length=12)
    _s_grow_tag(0x13, "t13", b"\x01\x00\x00\x00")
    _s_grow_tag(0x14, "t14", b"\x65\x00\x00\x00")
    _s_grow_tag(0x15, "t15", b"\x10\x00\x00\x00")


def body_trace_configure_liar():
    """Declared length disagrees with the bytes actually present.

    Everywhere else the declared length tracks the content.  Here the length is
    its own fuzzable primitive (``s_lying_leb_size``), so the handler is told a
    tag is 3000 bytes long while only four follow — the other half of the
    "length is trusted, not checked" bug class.
    """
    _s_value_tag(0x10, "trace_name", b"App.Trace\x00\x00\x00", max_length=12)

    for tag_id, block_name, default in ((0x13, "t13", b"\x01\x00\x00\x00"),
                                        (0x14, "t14", b"\x65\x00\x00\x00"),
                                        (0x15, "t15", b"\x10\x00\x00\x00"),
                                        (0x30, "t30", b"\x0a\x00\x00\x00")):
        s_static(bytes([tag_id]))
        s_lying_leb_size(block_name)
        with s_block(block_name):
            s_run_random(default, min_length=len(default), max_length=64,
                     name=block_name + "_data")


def body_trace_list():
    """0x0001 takes an empty body.  One optional tag is added so a fuzz run has
    something to vary — an unexpected tag is itself a legitimate input."""
    _s_grow_tag(0x10, "extra", b"\x00\x00\x00\x00")


def body_trace_by_name():
    """0x0005 open — tag 0x10 is the trace name, NUL-padded to a multiple of 4."""
    _s_value_tag(0x10, "trace_name", b"App.Trace\x00\x00\x00", max_length=12)


def body_trace_by_handle():
    """0x0003/0x0006/0x0009 — tag 0x40 is a handle from a trace_open reply.

    The default is an invalid handle: a handle is only valid within the session
    that obtained it, and the fuzzer opens a fresh session per case, so no
    default could be valid.  The runtime answers with an error status and the
    handler still parses the tag.
    """
    _s_value_tag(0x40, "handle", b"\x00" * 8, max_length=16)


def body_trace_read():
    """0x0007 — handle plus the sample offset."""
    _s_value_tag(0x40, "handle", b"\x00" * 8, max_length=16)
    _s_value_tag(0x4a, "offset", b"\x00\x00\x00\x00", max_length=8)


# ============================================================
# CmpIecVarAccess (group 0x0009)
# ============================================================

VAR_NAME = b"App.PLC_PRG.iTest\x00"


def body_iecvar_register():
    """0x0001 — flags, count, then one tag 0x19 per name.

    The name encoding is ``u16(length incl. NUL) + name [+ suffix]``
    (``CodesysTcpClient.encode_var_name``); there is no generateSuffix in this
    project, so the suffix is empty.
    """
    _s_value_tag(0x13, "flags", struct.pack("<I", 0x00010048), max_length=8)
    _s_value_tag(0x18, "count", struct.pack("<I", 1), max_length=8)
    _s_value_tag(0x19, "names",
                 struct.pack("<H", len(VAR_NAME)) + VAR_NAME, max_length=64)


def body_iecvar_read():
    """0x0003 — the handle from register."""
    _s_value_tag(0x10, "handle", b"\x00" * 4, max_length=16)


def body_iecvar_write():
    """0x0004 — tag 0x21 for the name (no length prefix, unlike register) and
    0x1e for the value."""
    _s_value_tag(0x13, "flags", struct.pack("<I", 0), max_length=8)
    _s_value_tag(0x21, "name", VAR_NAME, max_length=64)
    _s_value_tag(0x1e, "value", struct.pack("<i", 0), max_length=64)


# ============================================================
# CmpApp (group 0x0002) / CmpDevice (group 0x0001)
# ============================================================

def body_app_lookup():
    """0x0001 — tag 0x01 is "<ApplicationName>\\0"."""
    _s_value_tag(0x01, "app_name", b"App\x00", max_length=32)


def body_generic_tags():
    """A fuzzable tag stream, for services with no captured body.

    Two tags whose id, content and — for the second — declared length are all
    fuzzable.  Paired with a fuzzed service id this is how components nobody has
    modelled get exercised at all.
    """
    # tag 0: fuzzable id, length kept honest
    s_group(values=TAG_VALUES, name="tag0_id")
    s_leb_size("tag0")
    with s_block("tag0"):
        s_run_random(b"\x00\x00\x00\x00", min_length=0, max_length=256,
                 name="tag0_data")

    # tag 1: fuzzable id, and a declared length free to disagree with the content
    s_group(values=TAG_VALUES, name="tag1_id")
    s_lying_leb_size("tag1")
    with s_block("tag1"):
        s_run_random(b"\x00\x00\x00\x00", min_length=0, max_length=64,
                 name="tag1_data")


# ============================================================
# Derived from decompilation (see tools/README.md for the method)
# ============================================================
#
# These are not captured and not guessed: the service id and the tags each one
# reads were read out of the handler's decompilation.  The rule that makes this
# work, and which the immediate-scanning extractor could not express:
#
#   * the service id is ``*(WORD *)(req + 6)``, switched on in the group handler
#   * a tag id is never compared as a bare immediate — it is compared against the
#     *return value of the tag iterator* (``sub_ECA400`` / ``sub_ECA910`` /
#     ``sub_ECAA50``), so it appears as ``if (vN == 0x11)`` where ``vN`` came from
#     that call.  Scanning for immediates instead collects lengths and offsets,
#     which is why the automated pass reported service ids like 0x0c, 0x10, 0x14
#     (multiples of four — those are lengths).
#   * ``default: return <small>`` is that group's "no such service" code.  It is
#     per-group, not global: 0x12 and 0x13 answer 24, most groups answer 770.

#: The shape every CmpAppBP service function shares, straight from the
#: decompilation: parse the body, then walk top-level tags looking for container
#: ``0x81``, then dispatch on the child tag id with a ``switch``.  The ``case``
#: labels are the tag ids and each value is fetched with ``sub_ECA510``.  Nothing
#: here is inferred — the ids below are the case labels of each function.
#:
#:     sub_EC93E0(resp, req, len)      build the response
#:     sub_ECA2F0(parser, body, len)   parse the tag stream
#:     sub_ECA400(parser, &tagid)      next tag id
#:     if (tagid == 129) {             container 0x81
#:         while (!sub_ECA340(parser)) {
#:             sub_ECA400(parser, &tagid);
#:             switch (tagid) { case 17: /* tag 0x11 */ ... }
APPBP_CONTAINER = 0x81


def _appbp_container(tags, prefix):
    """Container 0x81 holding ``tags``, each a 4-byte fuzzable value."""
    def body():
        for tid in tags:
            _s_value_tag(tid, "%s_%02x" % (prefix, tid), bytes(4), max_length=8)
    s_container(APPBP_CONTAINER, body)


def body_appbp_0x13():
    """CmpAppBP (0x12) service 0x13 — ``sub_EC2060``, "Set BP".

    Container 0x81 carrying tags 0x11, 0x12, 0x13, 0x15, 0x16, 0x17, 0x19, 0x1a.
    The handler bounds-checks two of them (``v41 < 0x12C``, ``v43 < 0x3E8``), so
    those lengths are worth mutating past the limit.
    """
    _appbp_container((0x11, 0x12, 0x13, 0x15, 0x16, 0x17, 0x19, 0x1A), "setbp")


def body_appbp_0x15():
    """CmpAppBP (0x12) service 0x15 — ``sub_EC11F0``, "Del BP".

    Container 0x81 carrying 0x11, 0x12, 0x17, 0x19, 0x1a.
    """
    _appbp_container((0x11, 0x12, 0x17, 0x19, 0x1A), "delbp")


def body_appbp_0x16():
    """CmpAppBP (0x12) service 0x16 — ``sub_EC1790``.

    Container 0x81 carrying 0x11 and 0x1a only.  The response side of this
    function emits tags 0x82, 0x21, 0x14 and 0x16, which is a useful reminder
    that a tag id seen in a handler may be an *output* — those are not request
    fields.
    """
    _appbp_container((0x11, 0x1A), "s16")


def body_appbp_0x19():
    """CmpAppBP (0x12) service 0x19 — ``sub_EC2AA0``.

    Container 0x81 carrying 0x11, 0x12, 0x13.
    """
    _appbp_container((0x11, 0x12, 0x13), "s19")


def body_appbp_39():
    """CmpAppBP (0x12) service 0x39.

    From ``sub_EBF300`` @ 0xebf3fd (IDA; runtime 0x008CF3FD), the group's single
    service function.  Its case 0x39 parses the body with ``sub_ECA2F0`` and then
    iterates the top-level tags, keeping two of them by id::

        if ( v12 == 17 ) v6 = *i;        // tag 0x11, value read as an int
        else if ( v12 == 24 ) v7 = *i;   // tag 0x18, value read as an int

    Both are plain 4-byte values at the top level — no container wraps them — and
    the two are then handed to ``sub_EB9BE0`` and stored at +948 and +952 of the
    object it returns.  Sibling ids 0x13/0x15/0x16/0x19/0x22/0x32/0x33/0x40 exist
    in the same switch; ``default`` returns 24.
    """
    _s_value_tag(0x11, "appbp_39_a", bytes(4), max_length=8)
    _s_value_tag(0x18, "appbp_39_b", bytes(4), max_length=8)


def body_appforce_81_11():
    """CmpAppForce (0x13), the container 0x81 / tag 0x11 path.

    From ``sub_EC5D80`` @ 0xec5d80 (runtime 0x008D5D80) and its near-twin
    ``sub_EC6060``: both walk the body looking for container ``0x81`` and, inside
    it, tag ``0x11``::

        if ( v14 == 0x81 ) { ... if ( v14 == 0x11 ) { ... } }
        if ( v45 == 129 )  { ... if ( v45 == 17 )  { ... } }

    0x81 is the container id *before* the bit-7 marking is stripped, i.e. the
    same nesting convention as CmpTraceMgr's 0x86/0x83.
    """
    s_container(0x81, _body_appforce_11)


def _body_appforce_11():
    _s_value_tag(0x11, "appforce_11", bytes(4), max_length=8)


def body_device_identify():
    """0x0001 — tag 0x01 carries a version/feature block, 12 bytes as captured."""
    _s_value_tag(0x01, "identify",
                 bytes.fromhex("00 10 00 00 00 00 00 00 00 00 00 00"),
                 max_length=32)


def body_device_auth():
    """0x0002 — crypt type and auth step.

    Step 1 is the key exchange; step 2 is the login, whose body is the tag 0x01
    container holding 0x10 (user name) and 0x11 (the RSA-OAEP blob).  Both shapes
    are modelled here since a mutated step field makes the runtime take either
    branch.
    """
    _s_value_tag(0x22, "crypt_type", struct.pack("<I", 2), max_length=8)
    _s_value_tag(0x25, "auth_step", struct.pack("<I", 1), max_length=8)


# ============================================================
# Registry
# ============================================================

GRP_TRACE_ID = 0x0F
GRP_IECVAR_ID = 0x09
GRP_APP_ID = 0x02
GRP_DEVICE_ID = 0x01

def body_from_tags(tree):
    """A body rebuilt from the tag structure a previous run saw accepted.

    The generic body sends two tags drawn from a wide candidate list, which for
    a handler that wants specific ids is mostly rejected at the first unknown
    tag.  Given the structure a reply actually came back for, the same pair can
    be probed with a body the parser will walk into — which is the whole point of
    recording it.

    ``tree`` is ``[{"id": wire_id, "children": [...]}, ...]`` with container ids
    carrying bit 7, so a container is rebuilt as a container rather than as a
    leaf that merely looks like its id.
    """
    def emit(nodes):
        for node in nodes:
            tid = node["id"]
            if node.get("children"):
                # s_container writes the id itself, so pass the masked id back
                s_container(tid & 0x7F, _child_builder(node["children"]))
            else:
                _s_value_tag(tid, "seeded_%02x" % tid, bytes(4), max_length=8)

    def _child_builder(children):
        def body():
            emit(children)
        return body

    def body():
        emit(tree)
    return body


def body_raw():
    """Unstructured bytes — the most black-box body there is.

    Every other model sends a *well-formed* tag stream, so they all exercise the
    handlers' field logic but never the tag walker's own robustness.  This sends
    an opaque blob whose length is fuzzed too, which is what actually probes the
    parser: truncated tags, lengths that overrun the buffer, ids with the
    container bit set and nothing behind them.

    ``content_size`` still tracks it, so the packet is accepted by the services
    layer and the garbage is what the tag parser has to deal with.
    """
    with s_block("raw"):
        s_run_random(b"\x00" * 8, min_length=0, max_length=512, name="raw_data")


REQUESTS = {
    # --- CmpTraceMgr: the known-vulnerable surface ---
    "trace_configure": (GRP_TRACE_ID, 0x0002, body_trace_configure),
    "trace_configure2": (GRP_TRACE_ID, 0x0002, body_trace_configure_random_tag),
    "trace_configure_flat": (GRP_TRACE_ID, 0x0002, body_trace_configure_flat),
    "trace_configure_liar": (GRP_TRACE_ID, 0x0002, body_trace_configure_liar),
    "trace_list": (GRP_TRACE_ID, 0x0001, body_trace_list),
    "trace_open": (GRP_TRACE_ID, 0x0005, body_trace_by_name),
    "trace_info": (GRP_TRACE_ID, 0x0009, body_trace_by_handle),
    "trace_read": (GRP_TRACE_ID, 0x0007, body_trace_read),
    "trace_delete": (GRP_TRACE_ID, 0x0003, body_trace_by_handle),
    "trace_close": (GRP_TRACE_ID, 0x0006, body_trace_by_handle),

    # --- CmpIecVarAccess ---
    "iecvar_register": (GRP_IECVAR_ID, 0x0001, body_iecvar_register),
    "iecvar_read": (GRP_IECVAR_ID, 0x0003, body_iecvar_read),
    "iecvar_write": (GRP_IECVAR_ID, 0x0004, body_iecvar_write),

    # --- derived from decompilation ---
    "appbp_0x13_setbp": (0x12, 0x0013, body_appbp_0x13),
    "appbp_0x15_delbp": (0x12, 0x0015, body_appbp_0x15),
    "appbp_0x16": (0x12, 0x0016, body_appbp_0x16),
    "appbp_0x19": (0x12, 0x0019, body_appbp_0x19),
    "appbp_0x39": (0x12, 0x0039, body_appbp_39),
    # CmpAppForce's real ids, from the switch in sub_EC5900: 0x20, 0x21, 0x41.
    # An earlier version used 0x0001 as a placeholder and the runtime answered
    # with the group's `default: return 24` — the check that caught it was
    # --dry-run --send, which is worth running for any newly derived id.
    "appforce_0x20": (0x13, 0x0020, body_appforce_81_11),
    "appforce_0x21": (0x13, 0x0021, body_appforce_81_11),
    "appforce_0x41": (0x13, 0x0041, body_appforce_81_11),

    # --- CmpApp / CmpDevice ---
    "app_lookup": (GRP_APP_ID, 0x0001, body_app_lookup),
    "app_read_state": (GRP_APP_ID, 0x0025, body_generic_tags),
    "device_identify": (GRP_DEVICE_ID, 0x0001, body_device_identify),
    "device_auth": (GRP_DEVICE_ID, 0x0002, body_device_auth),

    # --- everything else ---
    "generic_sweep": (None, None, body_generic_tags),
}

#: requests whose default (unmutated) body is knowable and tested byte-for-byte
FIDELITY_CHECKED = ("trace_configure",)


def resolve_id_spec(spec, sweep_values, what):
    """Turn a CLI id specification into what ``request_skeleton`` wants.

    Returns ``None`` to mean "use the model's own value", an ``int`` for a fixed
    id, or a list of ints for a fuzzed one.  Accepts:

        None | ""        use the model default
        "sweep" | "*"    every value in ``sweep_values``
        "0x00-0x0f"      that inclusive range
        "0x0f" | "15"    a single fixed value
    """
    if spec is None:
        return None
    if isinstance(spec, (int, list, tuple)):
        return spec
    text = str(spec).strip()
    if not text:
        return None
    if text.lower() in ("sweep", "*", "all", "any"):
        return list(sweep_values)
    for sep in ("-", ":", ".."):
        if sep in text:
            lo, _, hi = text.partition(sep)
            lo, hi = int(lo, 0), int(hi, 0)
            if hi < lo:
                raise ValueError("%s range %r is backwards" % (what, text))
            return list(range(lo, hi + 1))
    return int(text, 0)


#: how a model's dimensions behave when the CLI says nothing: a modelled request
#: pins its own (group, service) because its body only means anything there;
#: generic_sweep leaves both open, which is its entire purpose.
MODEL_DIMENSIONS = {
    "generic_sweep": ("sweep", "sweep"),
}


def build_request(name, state, group=None, service=None, raw_body=False,
                  seed_tags=None):
    """Define request ``name`` on the current boofuzz request stack.

    ``group``/``service`` override the model's own ids, which is what gives the
    graded black-box modes.  With ``-r generic_sweep`` (bodies unknown, generic
    tag stream) the tiers are:

        --group 0x0f --service 0x02   one known pair, unknown body
        --group 0x0f --service sweep  group known, dispatch swept
        (nothing)                     group and dispatch both swept

    and on a modelled request the same flags turn it into a *shape* router —
    ``-r trace_configure --group sweep`` sends the captured TraceMgr body to every
    other component's handler, which is a cheap way to look for a second consumer
    of the same parsing code.

    ``raw_body`` replaces the model's body with unstructured bytes.
    """
    if name not in REQUESTS:
        raise KeyError("unknown request %r (have: %s)"
                       % (name, ", ".join(sorted(REQUESTS))))
    model_group, model_service, builder = REQUESTS[name]

    default_group, default_service = MODEL_DIMENSIONS.get(
        name, (model_group, model_service))

    # resolve the CLI override, and fall back to the model's own dimension —
    # which goes through the same parser, so a model may default to a sweep or a
    # range just as a user can ask for one
    if group is None:
        group = default_group
    if service is None:
        service = default_service
    group = resolve_id_spec(group, GROUP_IDS, "group")
    service = resolve_id_spec(service, SERVICE_IDS_SWEEP, "service")
    if group is None or service is None:
        raise ValueError(
            "request %r leaves group/service unspecified and no default applies; "
            "pass --group/--service (use 'sweep' to fuzz a dimension)" % name)
    if raw_body:
        builder = body_raw
    elif seed_tags:
        # only for the generic model: a modelled request has its own real shape
        # and replacing it with a seeded one would throw that away
        builder = body_from_tags(seed_tags)

    return request_skeleton(name, state, group, service, builder)


def request_names():
    return sorted(REQUESTS)
