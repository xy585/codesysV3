#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CODESYS V3 TCP client — open channel -> create session -> login.

Same protocol stack as codesys_udp_ds.py, carried by CmpBlkDrvTcp instead of
CmpBlkDrvUdp.  Everything from the channel layer up (GET_CHANNEL, BLK/ACK/
KEEPALIVE, the 0xCD55 services header, the tags, the RSA-OAEP + XOR login blob)
is byte-for-byte identical — those layers never see the transport.  Only the
two bottom layers change.

1. Block Driver layer
---------------------
CmpBlkDrvTcp prepends an 8-byte header to *every* datagram:

    magic  (4) : 00 01 17 e8   constant 0xE8170100, little endian
    length (4) : total bytes of magic + length + datagram

CmpBlkDrvUdp has no such header — a UDP datagram *is* the datagram layer, so
the UDP client starts straight at 0xc5.  The runtime validates both fields
before handing the payload to the router, and it rejects a datagram outside
6..512 bytes (the receiver tests the length field against 520 = 512 + 8) —
a hard limit UDP does not impose, so send_blk() has to fragment anything
larger into continuation frames.  Fragmentation then still has to declare the
whole message in the first frame: data_size and the CRC32 both describe all
the frames concatenated, not the chunk the first frame carries.

2. Datagram layer addresses
---------------------------
The sender/receiver fields are opaque to CmpRouter: each block driver fills
them in its own format, and the lengths nibbles follow the field widths.

    CmpBlkDrvUdp : relative — (port index, last byte of IPv4)              2 B
    CmpBlkDrvTcp : full     — (port, big-endian u16) + IPv4                6 B

So a TCP datagram header is 20 bytes (6 fixed + 6 + 6 + 2 padding) where UDP's
is 12 (6 + 2 + 2 + 2).  The port in these fields is a real port number, not an
index: byte pattern 2ddc c0a80058 is port 11740 at 192.168.0.88 (Kaspersky's
example).

Note that hop_info's low three bits are *not* the header length in dwords.
CmpRouter locates the address fields at 2 * (hop_info & 7) - the size of the
six-byte fixed prefix in 16-bit words - and sizes them from the lengths
nibbles.  The UDP client's formula lands on the same value by coincidence
(12 bytes / 4 == 6 bytes / 2), which is why a value derived from the total
header size silently misparses here: the addresses shift four bytes and the
router reads the channel layer from the wrong offset, dropping the packet with
no reply at all.

Packet_info bit 4 is the relative-address flag, read as (packet_info >> 4) & 1;
full addresses leave it clear, giving 0x40 - the same byte the UDP capture
carries.  --pkt-info overrides it if a runtime disagrees.

The values in sender/receiver are advisory.  On receive CmpBlkDrvTcp parses the
two fields, checks each is at least as wide as the address it really knows (the
listening endpoint and the TCP peer), then overwrites both before handing the
datagram to CmpRouter.  Only the *sizes* are load-bearing, and a wrong size is
fatal: two-byte fields make the connection fail the check and get torn down.

Which port
----------
CmpBlkDrvTcp listens on TCP 11740 in the runtime (CODESYSControlService.exe);
TCP 1217 belongs to the Gateway (GatewayService.exe), which fronts the runtime
on behalf of the IDE.  Talking to 11740 goes straight to the runtime and
sidesteps the Gateway's four-channel bookkeeping, so there is no client-port
dance like UDP's 1741/1742/1743 and no "channel table full" dance with the
Gateway holding a slot.

Sources: 1.pcapng (the UDP handshake, for the layers above the transport),
the CODESYS 3 Wireshark dissector (ports and the 0xE8170100 magic), the
Kaspersky ICS-CERT report "Security research: CODESYS Runtime, a PLC control
framework. Part 2" (block driver validation, address formats, 512-byte cap),
and CODESYSControlService_dump.exe for the points none of them pin down —
CmpBlkDrvTcp's Receive path (sub_ED2C90) and CmpRouter's datagram parser
(sub_1038FE0), which is where hop_info's real meaning and the address-field
overwrite are visible.

Dependencies:
    pip install pycryptodome
"""

import argparse
import hashlib
import socket
import struct
import sys
import time
import zlib

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256


# ============================================================
# Constants
# ============================================================

TCP_PORT       = 11740
GATEWAY_PORT   = 1217
DATAGRAM_MAGIC = 0xC5

#: CmpBlkDrvTcp's constant, little endian on the wire as 00 01 17 e8
BD_MAGIC       = 0xE8170100
BD_HEADER_LEN  = 8

#: a datagram may not exceed 512 bytes; the block driver checks the length
#: field against 520 (= 512 + the 8-byte header) before accepting a packet.
MAX_PDU        = 512

#: 6 bytes fixed + 6 sender + 6 receiver, padded to a dword
DATAGRAM_HEADER = 20

#: hop_info's low three bits are the *offset of the address fields* measured in
#: 16-bit words, not the size of the whole header: CmpRouter reads them at
#: 2 * (hop_info & 7) and rejects anything below 6 bytes.  The fixed prefix
#: (magic + hop_info + packet_info + service_id + message_id + lengths) is six
#: bytes, so the value is 3 for both block drivers.
HDR_PREFIX_WORDS = 3

#: packet_info bit 4 is CmpRouter's relative-address flag, read as
#: (packet_info >> 4) & 1.  CmpBlkDrvTcp deals in full addresses so the bit
#: stays clear - 0x40, the value the UDP capture shows as well.
PKT_INFO = 0x40

SERVICE_CHANNEL = 0x40

PKT_BLK       = 0x01
PKT_ACK       = 0x02
PKT_KEEPALIVE = 0x03

CH_GET_REQ    = 0xC3
CH_GET_RESP   = 0x83
CH_CLOSE_REQ  = 0xC4
CH_CLOSE_RESP = 0x84

PROTO_TAG     = 0xCD55
GRP_DEVICE    = 0x0001
GRP_APP       = 0x0002      # CmpApp
GRP_IECVAR    = 0x0009      # CmpIecVarAccess

DEV_IDENTIFY  = 0x0001
DEV_AUTH      = 0x0002
DEV_SESSION   = 0x000A

APP_LOOKUP    = 0x0001      # CmpApp: resolve/bind to a named application
APP_READ_STATE = 0x0025     # CmpApp: application status

GRP_TRACE     = 0x000F      # CmpTraceMgr

# CmpTraceMgr sub-commands (from trace.pcapng)
TRACE_LIST    = 0x0001      # empty body -> list of trace names
TRACE_CONFIGURE = 0x0002    # name + config + variable list -> handle.
                            # Name is behavioural, not symbolic.  This is the
                            # only id that reaches TraceMgrServiceHandler - the
                            # function carrying the 5 unchecked memcpys (see
                            # trace_poc.py); the group's other 18 sub-functions
                            # (ids 1..0x13, dispatched by sub_1077280) have none.
TRACE_START   = 0x0004      # handle -> status  (starts recording; this is the
                            #   one the IDE issues in trace2.pcapng)
TRACE_DELETE  = 0x0003      # handle -> status  (deletes the trace - calling it
                            #   made a trace vanish from the list)
TRACE_OPEN    = 0x0005      # name -> handle
TRACE_CLOSE   = 0x0006      # handle -> status
TRACE_READ    = 0x0007      # handle + offset -> sample data
TRACE_INFO    = 0x0009      # handle -> trace description incl. variables
TRACE_0A      = 0x000A
TRACE_0B      = 0x000B
TRACE_0D      = 0x000D

TAG_TRACE_NAME   = 0x10
TAG_TRACE_HANDLE = 0x40
TAG_TRACE_OFFSET = 0x4A
TAG_TRACE_DATA   = 0x42

# CmpTraceMgr answers with `ff fe 03 | 82 80 00 | <u16 status>`.  The LEB128
# id decodes to 0xFF7F, whose bit 7 is clear, so it is a *data* tag holding a
# 2-byte status code (0 = ok) - not the parent container it first resembles.
TAG_TRACE_STATUS = 0xFF7F

# CmpIecVarAccess sub-commands
VAR_REGISTER  = 0x0001
VAR_RELEASE   = 0x0002
VAR_READ      = 0x0003
VAR_WRITE     = 0x0004

VAR_REGISTER_FLAGS = 0x00010048

TAG_PROTO_VER = 0x01
TAG_USERNAME  = 0x10
TAG_PASSWORD  = 0x11
TAG_STATUS    = 0x20
TAG_SESSION   = 0x21
TAG_CRYPTTYPE = 0x22
TAG_DEVICE_SETTINGS = 0x24
TAG_AUTHSTEP  = 0x25
TAG_CHALLENGE = 0x26
TAG_PUBKEY    = 0x27
TAG_PRIVILEGE = 0x46

# CmpIecVarAccess tags
TAG_VAR_HANDLE   = 0x10      # register response: handle; read/release request
TAG_VAR_FLAGS    = 0x13      # 0x00010048 = read, 0 = write
TAG_VAR_COUNT    = 0x18
TAG_VAR_NAMES    = 0x19      # register: u16(len+1) + name [+ suffix]
TAG_VAR_RESULT   = 0x1D      # read response: one per variable, 4-byte prefix
TAG_VAR_VALUE    = 0x1E      # write request: payload
TAG_VAR_STATUS   = 0x20
TAG_VAR_NAME     = 0x21      # write request: name [+ suffix]

VAR_STATUS_OK          = 0x0000
VAR_STATUS_NOT_FOUND   = 0x0014

# scrypt parameters taken from the runtime's UserDatabase
SCRYPT_SALT  = bytes.fromhex("15b4f8994b3126f8")
SCRYPT_N     = 32768
SCRYPT_R     = 8
SCRYPT_P     = 1
SCRYPT_DKLEN = 64

LOGIN_PLAINTEXT_LEN = 64
CRYPT_TYPE          = 2

STATUS_KEY_EXCHANGE = 0x000A   # step 1 accepted
STATUS_OK           = 0x0000   # login accepted
STATUS_BAD_PASSWORD = 0x000F
STATUS_BAD_USER     = 0x0019


# ============================================================
# Varints and tags
# ============================================================

def leb128(value):
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value & 0x7F)
    return bytes(out)


def leb128_pad3(value):
    """LEB128 padded to three bytes, the form CODESYS uses for sizes >= 4
    (4 -> 84 80 00, 12 -> 8c 80 00, 256 -> 80 82 00, 452 -> c4 83 00)."""
    return bytes([(value & 0x7F) | 0x80,
                  ((value >> 7) & 0x7F) | 0x80,
                  (value >> 14) & 0x7F])


def read_leb128(data, pos):
    value = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        if not (b & 0x80):
            return value, pos
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")
    raise ValueError("truncated varint")


def tag(tag_id, value, size=None):
    return bytes([tag_id]) + (size or leb128_pad3(len(value))) + value


def parent_tag(tag_id, children):
    return leb128(tag_id | 0x80) + leb128(len(children)) + children


def parse_tags(data):
    out = []
    pos = 0
    while pos < len(data):
        tid, pos = read_leb128(data, pos)
        size, pos = read_leb128(data, pos)
        if pos + size > len(data):
            raise ValueError(f"tag 0x{tid & 0x7f:02x} claims {size} bytes, "
                             f"only {len(data) - pos} left")
        value = data[pos:pos + size]
        pos += size
        if tid & 0x80:
            try:
                kids = parse_tags(value)
            except ValueError:
                kids = []
            out.append({"id": tid & 0x7F, "value": value, "children": kids})
        else:
            out.append({"id": tid, "value": value, "children": None})
    return out


def find_tag(tags, tag_id):
    for t in tags:
        if t["id"] == tag_id:
            return t
    return None


def status_of(tags):
    """Read the 2-byte CODESYS status code (tag 0xFF7F).  0 = success."""
    t = find_tag_deep(tags, TAG_TRACE_STATUS)
    if t and len(t["value"]) >= 2:
        return struct.unpack("<H", t["value"][:2])[0]
    return None


def find_tag_deep(tags, tag_id):
    for t in tags:
        if t["id"] == tag_id:
            return t
        if t["children"]:
            r = find_tag_deep(t["children"], tag_id)
            if r is not None:
                return r
    return None


def _flatten(tags):
    """Depth-first walk over parsed tags (containers included)."""
    for t in tags:
        yield t
        if t["children"]:
            yield from _flatten(t["children"])


def dump_tags(tags, indent=4):
    for t in tags:
        pad = " " * indent
        if t["children"]:
            print(f"{pad}[container 0x{t['id']:02x}]")
            dump_tags(t["children"], indent + 4)
        else:
            v = t["value"]
            asc = "".join(chr(c) if 32 <= c < 127 else "." for c in v[:48])
            print(f"{pad}tag 0x{t['id']:02x} ({len(v):4d}B) {v[:40].hex(' ')}  |{asc}|")


# ============================================================
# Block Driver layer (CmpBlkDrvTcp)
# ============================================================

def build_block_frame(datagram):
    """magic + total length, then the datagram layer packet."""
    return struct.pack("<II", BD_MAGIC, len(datagram) + BD_HEADER_LEN) + datagram


def parse_block_frame(head, body):
    """Validate the 8-byte block driver header and return the datagram."""
    magic, length = struct.unpack("<II", head)
    if magic != BD_MAGIC:
        raise ValueError(f"bad block driver magic 0x{magic:08x} "
                         f"(expected 0x{BD_MAGIC:08x})")
    if length != len(body) + BD_HEADER_LEN:
        raise ValueError(f"block driver length {length} does not match "
                         f"{len(body) + BD_HEADER_LEN} bytes received")
    return body


# ============================================================
# Datagram layer (CmpRouter)
# ============================================================

def full_address(port, ip):
    """CmpBlkDrvTcp endpoint: port as a big-endian u16, then the IPv4 address.
    11740 at 192.168.0.88 is the byte pattern 2ddc c0a80058."""
    return struct.pack(">H", port) + socket.inet_aton(ip)


def build_datagram(payload, local_port, remote_port, local_ip, remote_ip,
                   mid=0x00, hop_count=14, pkt_info=PKT_INFO):
    """
    sender   = the endpoint the packet is *for* (the runtime);
    receiver = the endpoint a reply must go to (this client).

    Both are given as full addresses because that is what CmpBlkDrvTcp puts in
    these fields - the UDP client's two-byte (port index, address byte) form is
    a CmpBlkDrvUdp convention and CmpRouter would read 6 bytes of it as an
    address plus 4 bytes of the channel layer.

    The values are advisory: on receive CmpBlkDrvTcp parses the fields (using
    the lengths nibbles for their sizes), checks that each is at least as large
    as the real local/peer address, and then overwrites both with the addresses
    it actually knows - the listening endpoint and the TCP peer.  What it does
    *not* forgive is a wrong field size or a wrong hop_info, either of which
    desynchronises the parse and makes the packet vanish without a reply.
    """
    sender   = full_address(remote_port, remote_ip)
    receiver = full_address(local_port, local_ip)
    total = 6 + len(sender) + len(receiver)
    pad = (-total) % 4
    hop_info = ((hop_count & 0x1F) << 3) | HDR_PREFIX_WORDS
    lengths = ((len(receiver) // 2) << 4) | (len(sender) // 2)
    return (bytes([DATAGRAM_MAGIC, hop_info, pkt_info, SERVICE_CHANNEL, mid, lengths])
            + sender + receiver + b"\x00" * pad + payload)


def parse_datagram(data):
    """Split a datagram the way CmpRouter does: the address fields begin at
    2 * (hop_info & 7) and are sized by the lengths nibbles; the payload starts
    at the next dword boundary after them."""
    if len(data) < 6 or data[0] != DATAGRAM_MAGIC:
        return None
    prefix = (data[1] & 0x07) * 2
    if prefix < 6 or prefix > len(data):
        return None
    body = prefix + (data[5] & 0x0F) * 2 + (data[5] >> 4) * 2
    hdr_len = body + (-body) % 4
    if hdr_len > len(data):
        return None
    return {"payload": data[hdr_len:], "svc": data[3], "mid": data[4],
            "hdr_len": hdr_len}


# ============================================================
# Channel layer (CmpChannelMgr)
# ============================================================

def build_get_channel(correlation=0x0690C4DE, client_token=0x22125B11,
                      recv_buffer=0x001F4000):
    """cc3 00 02 01 | de c4 90 06 | 11 5b 12 22 | 00 40 1f 00 | 04 00 00 00
    The runtime echoes the second word back, so it identifies the request."""
    return (bytes([CH_GET_REQ, 0x00]) + struct.pack("<H", 0x0102)
            + struct.pack("<I", correlation)
            + struct.pack("<I", client_token)
            + struct.pack("<I", recv_buffer)
            + struct.pack("<I", 0x00000004))


def build_blk(channel_id, token, blk_id, ack_id, data, first=True,
              total=None, crc=None):
    """
    A first frame carries, after the block ids, the size of the *whole* message
    and the CRC32 of the whole message - not of the chunk it is carrying.  The
    captured 544-byte response proves it: its first frame holds 472 data bytes
    but declares 544, and 0xd43601ab is crc32 over all 544.  A single-frame
    message makes the two readings identical, which is why the UDP client never
    had to care.
    """
    flags = 0x81 if first else 0x80
    head = bytes([PKT_BLK, flags]) + token + struct.pack("<III", channel_id, blk_id, ack_id)
    if first:
        head += struct.pack("<II",
                            len(data) if total is None else total,
                            (zlib.crc32(data) & 0xFFFFFFFF) if crc is None else crc)
    return head + data


def build_ack(channel_id, token, blk_id):
    return bytes([PKT_ACK, 0x80]) + token + struct.pack("<II", channel_id, blk_id)


def build_keepalive(channel_id, token):
    return bytes([PKT_KEEPALIVE, 0x80]) + token + struct.pack("<I", channel_id)


def build_close_channel(channel_id, token, correlation=None):
    """
    c4 00 02 01 | e1 3f 82 56 | a4 e0 | 00 00 | 03 35 96 14
                                                ^ channel id
                                       ^ token
    The runtime does not answer CLOSE_CHANNEL.
    """
    if correlation is None:
        correlation = int.from_bytes(hashlib.sha256(
            struct.pack("<I", channel_id)).digest()[:4], "little")
    return (bytes([CH_CLOSE_REQ, 0x00]) + struct.pack("<H", 0x0102)
            + struct.pack("<I", correlation) + token + b"\x00\x00"
            + struct.pack("<I", channel_id))


def parse_channel(ch):
    if len(ch) < 2:
        return {"type": "short"}
    pt, flags = ch[0], ch[1]
    if pt == PKT_BLK:
        if flags & 0x01:
            return {"type": "blk_first",
                    "channel_id": struct.unpack_from("<I", ch, 4)[0],
                    "blk_id": struct.unpack_from("<I", ch, 8)[0],
                    "ack_id": struct.unpack_from("<I", ch, 12)[0],
                    "data_size": struct.unpack_from("<I", ch, 16)[0],
                    "crc": struct.unpack_from("<I", ch, 20)[0],
                    "data": ch[24:]}
        return {"type": "blk_cont",
                "channel_id": struct.unpack_from("<I", ch, 4)[0],
                "blk_id": struct.unpack_from("<I", ch, 8)[0],
                "data": ch[16:]}
    if pt == PKT_ACK:
        return {"type": "ack",
                "channel_id": struct.unpack_from("<I", ch, 4)[0],
                "blk_id": struct.unpack_from("<I", ch, 8)[0]}
    if pt == PKT_KEEPALIVE:
        return {"type": "keepalive",
                "channel_id": struct.unpack_from("<I", ch, 4)[0] if len(ch) >= 8 else None}
    if pt == CH_GET_RESP:
        return {"type": "open_resp",
                "channel_id": struct.unpack_from("<I", ch, 24)[0],
                "token": ch[14:16]}
    if pt == 0x84:
        return {"type": "close", "channel_id": struct.unpack_from("<I", ch, 12)[0]}
    return {"type": f"unknown_{pt:#04x}", "raw": ch}


# ============================================================
# Services layer
# ============================================================

def build_services(group, service_id, session_id, body):
    return (struct.pack("<HHHHII", PROTO_TAG, 16, group, service_id,
                        session_id, len(body))
            + struct.pack("<I", 0) + body)


def parse_services(data):
    if len(data) < 20:
        raise ValueError(f"services block too short: {len(data)}")
    proto, hsize, group, sid, session, csize, add = struct.unpack_from("<HHHHIII", data, 0)
    if proto != PROTO_TAG:
        raise ValueError(f"bad protocol id {proto:#06x}")
    return ({"group": group, "service_id": sid, "session_id": session,
             "content_size": csize},
            data[20:20 + csize])


# ============================================================
# Crypto
# ============================================================

def password_hash(password, salt=SCRYPT_SALT, dklen=SCRYPT_DKLEN):
    """The runtime's stored credential: scrypt of the password."""
    return hashlib.scrypt(password.encode("utf-8"), salt=salt,
                          n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=dklen,
                          maxmem=512 * 1024 * 1024)


def build_password_blob(password, challenge):
    """
    plain[i] = password_padded[i] ^ challenge[i % 32]      (64 bytes)
    blob     = RSA-OAEP(SHA-256) of plain
    """
    plain = bytearray(password.encode("utf-8").ljust(LOGIN_PLAINTEXT_LEN, b"\x00"))
    for i in range(LOGIN_PLAINTEXT_LEN):
        plain[i] ^= challenge[i % len(challenge)]
    return bytes(plain)


def rsa_encrypt(pem, plaintext):
    key = RSA.import_key(pem)
    return PKCS1_OAEP.new(key, hashAlgo=SHA256).encrypt(plaintext)


# ============================================================
# Login request body (byte-for-byte as captured)
# ============================================================

def build_login_body(username, password_blob, crypt_type=CRYPT_TYPE, step=2):
    """
    22 84 80 00 <u32 crypt_type>
    25 84 80 00 <u32 step>
    81 01 <leb size>                  container tag 1
      10 06 74 65 73 74 00 00         tag 0x10 user name, NUL padded to even
      11 80 82 00 <256 bytes>         tag 0x11 RSA-OAEP password blob
    """
    u = username.encode("utf-8")
    u += b"\x00" * (2 if len(u) % 2 == 0 else 1)

    inner = tag(TAG_USERNAME, u, size=leb128(len(u)))
    inner += tag(TAG_PASSWORD, password_blob)
    return (tag(TAG_CRYPTTYPE, struct.pack("<I", crypt_type))
            + tag(TAG_AUTHSTEP, struct.pack("<I", step))
            + parent_tag(0x01, inner))


# ============================================================
# Client
# ============================================================

class ChannelUnavailable(RuntimeError):
    """The runtime had no free channel slot (it only has four)."""


class CodesysTcpClient:
    #: client information block copied verbatim from the capture
    CLIENT_INFO = bytes.fromhex(
        "83 01 fc 00 "
        "40 84 80 00 50 51 de c0 "
        "41 88 80 00 43 4f 44 45 53 59 53 00 "
        "42 9c 80 00 43 4f 44 45 53 59 53 20 44 65 76 65 6c 6f 70 6d 65 6e 74 "
        "20 47 6d 62 48 00 00 00 00 "
        "44 9c 80 00 43 4f 44 45 53 59 53 20 56 33 2e 35 20 53 50 31 38 20 50 "
        "61 74 63 68 20 32 00 00 00 "
        "43 94 80 00 44 45 53 4b 54 4f 50 2d 47 4e 34 49 50 36 4d 2e 00 00 00 00 "
        "45 8c 80 00 33 2e 35 2e 31 38 2e 32 30 00 00 00 "
        "46 84 80 00 03 00 00 00")

    #: room the datagram layer leaves for one channel frame
    MAX_FRAME_DATA_FIRST = MAX_PDU - DATAGRAM_HEADER - 24   # 468
    MAX_FRAME_DATA_CONT  = MAX_PDU - DATAGRAM_HEADER - 16   # 476

    def __init__(self, host, port=TCP_PORT, timeout=5.0, verbose=True,
                 pkt_info=PKT_INFO):
        self.host, self.port = host, port
        self.verbose = verbose
        self.pkt_info = pkt_info
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        # The datagram layer carries real ports, and CmpBlkDrvTcp fills in the
        # socket's own endpoint, so take ours from the connection.
        self.local_ip, self.local_port = self.sock.getsockname()[:2]
        self.channel_id = None
        self.token = b"\xa4\xe0"
        self.session_id = 0
        self.app_key = None
        self.app_name = None         # set by app_login()
        self.tx_blk = 0
        self.rx_blk = 0

    # ---------- io ----------
    def _log(self, *a):
        if self.verbose:
            print(*a)

    def _recv_exact(self, n):
        """TCP is a stream: read exactly n bytes, coalescing whatever arrives."""
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError(
                    "runtime closed the TCP connection mid-frame")
            buf += chunk
        return bytes(buf)

    def send_raw(self, payload):
        dg = build_datagram(payload, self.local_port, self.port,
                            self.local_ip, self.host, pkt_info=self.pkt_info)
        if len(dg) > MAX_PDU:
            raise ValueError(f"datagram {len(dg)}B exceeds the {MAX_PDU}B cap")
        frame = build_block_frame(dg)
        self._log(f"[>] {len(frame):4d}B  {frame.hex(' ')}")
        self.sock.sendall(frame)

    def recv_raw(self, timeout=None):
        old = self.sock.gettimeout()
        if timeout is not None:
            self.sock.settimeout(timeout)
        try:
            head = self._recv_exact(BD_HEADER_LEN)
            magic, length = struct.unpack("<II", head)
            if magic != BD_MAGIC:
                raise ValueError(f"bad block driver magic 0x{magic:08x}")
            if length < BD_HEADER_LEN or length > MAX_PDU + BD_HEADER_LEN:
                raise ValueError(f"implausible block driver length {length}")
            body = self._recv_exact(length - BD_HEADER_LEN)
        finally:
            self.sock.settimeout(old)
        self._log(f"[<] {length:4d}B  {(head + body).hex(' ')}")
        return parse_datagram(parse_block_frame(head, body))

    # ---------- 1. open channel ----------
    def open_channel(self):
        self._log("\n========== 1. GET_CHANNEL ==========")
        self.send_raw(build_get_channel())
        while True:
            dg = self.recv_raw()
            if dg is None:
                continue
            ch = parse_channel(dg["payload"])
            if ch["type"] == "keepalive":
                continue
            if ch["type"] == "open_resp":
                if ch["channel_id"] in (0, 0xFFFFFFFF):
                    # the runtime has no free slot in its channel table
                    raise ChannelUnavailable(
                        "runtime refused GET_CHANNEL (channel table full / "
                        "stale channels still held)")
                self.channel_id = ch["channel_id"]
                self.token = ch["token"]
                self._log(f"[+] channel_id = 0x{self.channel_id:08x}   "
                          f"token = {self.token.hex(' ')}")
                return self.channel_id
            self._log(f"    (ignoring {ch['type']})")

    # ---------- channel plumbing ----------
    def send_blk(self, services_bytes):
        """
        Fragment across BLK frames so that no datagram exceeds 512 bytes - the
        limit CmpBlkDrvTcp enforces, and the reason a fat login body or a long
        variable list cannot go out as a single frame over TCP the way it can
        over UDP.
        """
        total = len(services_bytes)
        crc = zlib.crc32(services_bytes) & 0xFFFFFFFF
        off = 0
        first = True
        while first or off < total:
            room = (self.MAX_FRAME_DATA_FIRST if first
                    else self.MAX_FRAME_DATA_CONT)
            chunk = services_bytes[off:off + room]
            self.tx_blk += 1
            self._log(f"    -> BLK blk={self.tx_blk} ack={self.rx_blk} "
                      f"{'first' if first else 'cont '} data={len(chunk)}B "
                      f"of {total}B")
            self.send_raw(build_blk(self.channel_id, self.token, self.tx_blk,
                                    self.rx_blk, chunk, first=first,
                                    total=total, crc=crc))
            off += len(chunk)
            first = False

    def recv_services(self):
        buf = bytearray()
        declared = None
        frames = 0
        while True:
            dg = self.recv_raw()
            if dg is None:
                continue
            ch = parse_channel(dg["payload"])
            t = ch["type"]
            if t == "keepalive":
                if ch["channel_id"] == self.channel_id:
                    self._log("    -> KEEPALIVE")
                    self.send_raw(build_keepalive(self.channel_id, self.token))
                continue
            if t in ("blk_first", "blk_cont"):
                if ch["channel_id"] != self.channel_id:
                    continue
                if t == "blk_first":
                    declared = ch["data_size"]
                buf += ch["data"]
                self.rx_blk = ch["blk_id"]
                frames += 1
                if declared is not None and len(buf) >= declared:
                    got = zlib.crc32(bytes(buf[:declared])) & 0xFFFFFFFF
                    if t == "blk_first" and got != ch["crc"]:
                        self._log(f"    [!] crc mismatch {got:08x} != {ch['crc']:08x}")
                    break
            elif t == "ack":
                continue
            elif t == "close":
                # the runtime also reaps abandoned channels we no longer use
                if ch["channel_id"] == self.channel_id:
                    raise RuntimeError("runtime closed our channel (0x84)")
                self._log(f"    (0x84 for a stale channel 0x{ch['channel_id']:08x}, ignored)")
                continue
            else:
                self._log(f"    [!] unexpected frame {t}")
                continue
        if frames > 1:
            self._log(f"    -> ACK blk={self.rx_blk}")
            self.send_raw(build_ack(self.channel_id, self.token, self.rx_blk))
        return bytes(buf[:declared])

    def call(self, group, service_id, body, session_id=None):
        if session_id is None:
            session_id = self.session_id
        self.send_blk(build_services(group, service_id, session_id, body))
        hdr, resp = parse_services(self.recv_services())
        return hdr, resp

    # ---------- 2. identify ----------
    def identify(self):
        self._log("\n========== 2. CmpDevice 0x0001 (identify) ==========")
        body = tag(TAG_PROTO_VER, bytes.fromhex("00 10 00 00 00 00 00 00 00 00 00 00"))
        hdr, resp = self.call(GRP_DEVICE, DEV_IDENTIFY, body, session_id=0)
        tags = parse_tags(resp)
        self._log(f"    <- group=0x{hdr['group']:04x} service=0x{hdr['service_id']:04x}")
        if self.verbose:
            dump_tags(tags)
        return tags

    # ---------- 3. session ----------
    def create_session(self):
        self._log("\n========== 3. CmpDevice 0x000A (session) ==========")
        hdr, resp = self.call(GRP_DEVICE, DEV_SESSION, self.CLIENT_INFO,
                              session_id=0x00000011)
        tags = parse_tags(resp)
        self._log(f"    <- group=0x{hdr['group']:04x} service=0x{hdr['service_id']:04x}")
        t = find_tag(tags, TAG_SESSION)
        if t is None:
            raise RuntimeError("session response has no tag 0x21")
        self.session_id = struct.unpack("<I", t["value"][:4])[0]
        self._log(f"[+] session_id = 0x{self.session_id:08x}")
        return self.session_id

    # ---------- 4. public key + challenge ----------
    def get_public_key(self):
        self._log("\n========== 4. CmpDevice 0x0002 step 1 (public key) ==========")
        body = (tag(TAG_CRYPTTYPE, struct.pack("<I", CRYPT_TYPE))
                + tag(TAG_AUTHSTEP, struct.pack("<I", 1)))
        hdr, resp = self.call(GRP_DEVICE, DEV_AUTH, body)
        tags = parse_tags(resp)
        st = find_tag_deep(tags, TAG_STATUS)
        status = struct.unpack("<H", st["value"][:2])[0] if st else None
        if status != STATUS_KEY_EXCHANGE:
            raise RuntimeError(f"key exchange refused (status={status})")

        pem = find_tag_deep(tags, TAG_PUBKEY)
        cha = find_tag_deep(tags, TAG_CHALLENGE)
        if pem is None or cha is None:
            raise RuntimeError("response has no public key (0x27) / challenge (0x26)")
        challenge = cha["value"]
        self._log(f"[+] challenge ({len(challenge)}B) = {challenge.hex()}")
        return pem["value"].rstrip(b"\x00\r\n").decode("ascii"), challenge

    # ---------- 5. login ----------
    def login(self, pem, challenge, username, password):
        self._log("\n========== 5. CmpDevice 0x0002 step 2 (LOGIN) ==========")
        plain = build_password_blob(password, challenge)
        blob = rsa_encrypt(pem, plain)
        self._log(f"    password blob: plain={len(plain)}B -> rsa={len(blob)}B")
        hdr, resp = self.call(GRP_DEVICE, DEV_AUTH, build_login_body(username, blob))
        tags = parse_tags(resp)
        self._log(f"    <- group=0x{hdr['group']:04x} service=0x{hdr['service_id']:04x}")
        if self.verbose:
            dump_tags(tags)

        st = find_tag_deep(tags, TAG_STATUS)
        status = struct.unpack("<H", st["value"][:2])[0] if st else None
        key = find_tag_deep(tags, TAG_SESSION)
        if key is not None:
            self.app_key = struct.unpack("<I", key["value"][:4])[0]
            # The login reply hands back an "app key" which then becomes the
            # Services-layer session_id for every later request - the capture
            # shows the IDE using it for CmpIecVarAccess.  Without this the
            # runtime rejects variable access even for valid names.
            self.session_id = self.app_key
        if self.rx_blk:
            self._log(f"    -> ACK blk={self.rx_blk}")
            self.send_raw(build_ack(self.channel_id, self.token, self.rx_blk))
        return status, tags

    # ---------- 5b. application login (CmpApp) ----------
    #
    # The device login authenticates the *device*; services that act on the
    # PLC program need the session bound to an *application* as well.  The IDE
    # issues CmpApp 0x0001 with tag 0x01 = "<ApplicationName>\0"; the runtime
    # records it as "App [<name>] Login successful" in .Audit.log.  Without it
    # only device-scoped services work.

    def app_login(self, name):
        """Returns (ok, tags).  A successful lookup answers with a ~116-byte
        structure carrying tag 0x10 = 0x26 bytes of application info; an
        unknown name answers with 8 bytes holding tag 0x10 = 2 bytes."""
        hdr, resp = self.call(GRP_APP, APP_LOOKUP, tag(0x01, name.encode() + b"\x00"))
        tags = parse_tags(resp)
        ok = any(t["id"] == TAG_VAR_HANDLE and len(t["value"]) >= 0x20
                 for t in _flatten(tags))
        self._log(f"    app login {name!r}: grp=0x{hdr['group']:04x} "
                  f"content={len(resp)}B {'OK' if ok else 'REJECTED'}")
        if not ok:
            self._log(f"      (runtime said: no such application)")
        else:
            self.app_name = name
        return ok, tags

    # ---------- 5c. CmpTraceMgr ----------
    #
    # Sequence seen in trace.pcapng:
    #   0x0001 (empty)              -> trace names
    #   0x0005 + tag 0x10 = name    -> tag 0x40 = handle
    #   0x0009 + tag 0x40 = handle  -> trace description (task, variables, addr)
    #   0x0007 + tag 0x40 + 0x4a    -> tag 0x42 = sample block
    # The trace name is NUL-padded to a multiple of 4 ("App.Trace" -> 12 bytes).

    @staticmethod
    def _name4(name):
        # latin-1 so that names read back as raw bytes still round-trip
        b = name.encode("latin-1")
        return b + b"\x00" * ((-len(b)) % 4)

    def trace_list(self):
        """-> (names, raw response).  Trace names known to the runtime.

        Each name arrives as a container holding one leaf tag 0x01, so only
        leaves are collected.
        """
        hdr, resp = self.call(GRP_TRACE, TRACE_LIST, b"")
        names = []
        for t in _flatten(parse_tags(resp)):
            if t["id"] != 0x01 or t["children"] or not t["value"]:
                continue
            s = t["value"].rstrip(b"\x00").decode("latin-1")
            if s and s not in names:
                names.append(s)
        return names, resp

    def trace_open(self, name):
        """-> (handle_bytes or None, status)."""
        hdr, resp = self.call(GRP_TRACE, TRACE_OPEN, tag(TAG_TRACE_NAME, self._name4(name)))
        tags = parse_tags(resp)
        h = find_tag_deep(tags, TAG_TRACE_HANDLE)
        return (h["value"] if h else None), status_of(tags)

    def trace_info(self, handle):
        hdr, resp = self.call(GRP_TRACE, TRACE_INFO, tag(TAG_TRACE_HANDLE, handle))
        return parse_tags(resp), resp

    def trace_read(self, handle, offset=0):
        body = (tag(TAG_TRACE_HANDLE, handle)
                + tag(TAG_TRACE_OFFSET, struct.pack("<I", offset)))
        hdr, resp = self.call(GRP_TRACE, TRACE_READ, body)
        return parse_tags(resp), resp

    def trace_ctl(self, service_id, handle):
        """start (0x04) / stop (0x0B) / close (0x06) etc."""
        hdr, resp = self.call(GRP_TRACE, service_id, tag(TAG_TRACE_HANDLE, handle))
        return status_of(parse_tags(resp)), resp

    # ---------- 6. CmpIecVarAccess ----------
    #
    # register -> handle, read(handle) -> values, release(handle).
    #
    # Names are fully qualified and include the *application* name, e.g.
    # "App.PLC_PRG.iTest" - captured byte-for-byte from the CODESYS IDE and
    # reproduced identically by encode_var_name().  There is no extra suffix.
    #
    # The runtime answers reads with status 0x0014 unless the project has a
    # Symbol Configuration covering the variables; the IDE itself gets the
    # same status for the same name, and it reads live values over CmpMonitor
    # (group 0x1b) instead.

    @staticmethod
    def encode_var_name(name, suffix=b""):
        """Register form: u16(length including NUL) + name [+ suffix]."""
        b = name.encode("ascii")
        return struct.pack("<H", len(b) + 1) + b + suffix

    def var_register(self, names, flags=VAR_REGISTER_FLAGS, suffix=b""):
        body = tag(TAG_VAR_FLAGS, struct.pack("<I", flags))
        body += tag(TAG_VAR_COUNT, struct.pack("<I", len(names)))
        for n in names:
            body += tag(TAG_VAR_NAMES, self.encode_var_name(n, suffix))
        hdr, resp = self.call(GRP_IECVAR, VAR_REGISTER, body)
        tags = parse_tags(resp)
        h = find_tag_deep(tags, TAG_VAR_HANDLE)
        return (h["value"] if h else None), tags

    def var_read(self, handle):
        hdr, resp = self.call(GRP_IECVAR, VAR_READ, tag(TAG_VAR_HANDLE, handle))
        return resp, parse_tags(resp)

    def var_release(self, handle):
        hdr, resp = self.call(GRP_IECVAR, VAR_RELEASE, tag(TAG_VAR_HANDLE, handle))
        return resp, parse_tags(resp)

    def var_write(self, name, payload, suffix=b""):
        """Write form uses tag 0x21 for the name (no length prefix)."""
        body = tag(TAG_VAR_FLAGS, struct.pack("<I", 0))
        body += tag(TAG_VAR_NAME, name.encode("ascii") + suffix)
        body += tag(TAG_VAR_VALUE, payload)
        hdr, resp = self.call(GRP_IECVAR, VAR_WRITE, body)
        return resp, parse_tags(resp)

    @staticmethod
    def var_status(tags):
        t = find_tag_deep(tags, TAG_VAR_STATUS)
        if t and len(t["value"]) >= 2:
            return struct.unpack("<H", t["value"][:2])[0]
        return None

    def close(self):
        """Release the channel so the runtime's (small) channel table does not
        fill up across runs, then drop the TCP connection."""
        if self.channel_id is not None:
            try:
                self.send_raw(build_close_channel(self.channel_id, self.token))
            except (OSError, ValueError):
                pass
        try:
            self.sock.close()
        except OSError:
            pass


# ============================================================
# Driver
# ============================================================

STATUS_NAMES = {
    STATUS_OK: "LOGIN ACCEPTED",
    STATUS_BAD_PASSWORD: "wrong password",
    STATUS_BAD_USER: "unknown user / bad request",
}


def main():
    ap = argparse.ArgumentParser(
        description="CODESYS V3 TCP client: open channel -> create session -> login")
    ap.add_argument("target", help="runtime IPv4 address, e.g. 192.168.125.129")
    ap.add_argument("--port", type=int, default=TCP_PORT,
                    help=f"TCP port; {TCP_PORT} is CmpBlkDrvTcp in the runtime, "
                         f"while {GATEWAY_PORT} is the Gateway. Default {TCP_PORT}")
    ap.add_argument("--user", default="test")
    ap.add_argument("--password", default="test")
    ap.add_argument("--app-name", default="App",
                    help="application to log into after the device login "
                         "(CmpApp 0x0001); use --no-app-login to skip")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--pkt-info", type=lambda s: int(s, 0), default=PKT_INFO,
                    help="datagram packet_info byte (default 0x40: normal "
                         "priority, bit 4 clear = full addresses). Setting "
                         "bit 4 marks the addresses relative and the runtime "
                         "ignores the packet")
    ap.add_argument("--no-app-login", action="store_true")
    ap.add_argument("--quiet", action="store_true", help="only print the summary")
    ap.add_argument("--show-hash", action="store_true",
                    help="also print scrypt(password) from the UserDatabase salt")
    ap.add_argument("--var-read", metavar="NAME", action="append", default=[],
                    help="after login, register+read a PLC variable (repeatable). "
                         "Use the fully qualified name incl. the application: "
                         "App.PLC_PRG.iTest")
    ap.add_argument("--var-write", metavar="NAME=VALUE", action="append", default=[],
                    help="after login, write a PLC variable, e.g. "
                         "--var-write App.PLC_PRG.iTest=42")
    ap.add_argument("--var-suffix", default="",
                    help="name suffix appended by CODESYS' generateSuffix (hex or raw)")
    ap.add_argument("--trace-list", action="store_true",
                    help="list the traces known to the runtime")
    ap.add_argument("--trace-read", metavar="NAME",
                    help="open a trace, print its recorded variables, read samples")
    ap.add_argument("--trace-create", metavar="NAME",
                    help="create a trace from the captured TRACE_CONFIGURE "
                         "template (needs --trace-var)")
    ap.add_argument("--trace-var", default="POU.iTest",
                    help="variable to record when using --trace-create")
    ap.add_argument("--trace-start", action="store_true",
                    help="with --trace-read/--trace-create: start recording")
    ap.add_argument("--trace-delete", metavar="NAME", action="append", default=[],
                    help="delete a trace from the runtime (repeatable). "
                         "Uses CmpTraceMgr 0x0003; the trace is gone afterwards")
    ap.add_argument("--trace-delete-all", action="store_true",
                    help="delete every trace except the built-in CpuCoreLoad / "
                         "PlcLoad ones")
    args = ap.parse_args()

    if args.show_hash:
        print(f"[*] salt = {SCRYPT_SALT.hex()}  N={SCRYPT_N} r={SCRYPT_R} "
              f"p={SCRYPT_P} dklen={SCRYPT_DKLEN}")
        print(f"[*] scrypt({args.password!r}) = {password_hash(args.password).hex()}")

    # Unlike UDP, port 11740 is not contended: the Gateway owns 1217 and never
    # takes a channel in the runtime's table on our behalf.
    c = None
    errors = []
    for attempt in range(4):
        try:
            c = CodesysTcpClient(args.target, args.port, args.timeout,
                                 verbose=True, pkt_info=args.pkt_info)
            c.open_channel()
            break
        except Exception as e:
            errors.append(f"  TCP {args.target}:{args.port}: {e}")
            if c is not None:
                c.close()
            c = None
            # a full channel table only clears once the runtime reaps idle
            # channels, which takes tens of seconds; a socket-level failure is
            # usually instantaneous to retry.
            time.sleep(10 if isinstance(e, ChannelUnavailable) else 1)
    if c is None:
        print("[-] could not reach the runtime:")
        for line in dict.fromkeys(errors):
            print(line)
        print(f"\n    {TCP_PORT} is CmpBlkDrvTcp in the runtime itself; "
              f"{GATEWAY_PORT} is the Gateway.\n"
              "    'channel table full' means the runtime still holds channels\n"
              "    from earlier runs; they are reaped after a short idle period.")
        return 1
    c.verbose = not args.quiet

    try:
        print(f"[*] client endpoint: {c.local_ip}:{c.local_port} -> "
              f"{args.target}:{args.port} (TCP)")
        c.create_session()
        pem, challenge = c.get_public_key()
        status, _ = c.login(pem, challenge, args.user, args.password)
        if status == STATUS_OK and not args.no_app_login:
            # Bind the session to an application.  The device login only
            # authenticates the device; the IDE additionally performs this
            # CmpApp call, which the runtime logs as "App [<n>] Login".
            c.app_login(args.app_name)
    except Exception as e:
        print(f"\n[-] FAILED: {e}")
        c.close()
        return 1

    print("\n========== RESULT ==========")
    print(f"  channel_id : 0x{c.channel_id:08x}")
    print(f"  session_id : 0x{c.session_id:08x}")
    print(f"  login      : status={status} "
          f"({STATUS_NAMES.get(status, 'unexpected status')})")
    if c.app_key is not None:
        print(f"  app key    : 0x{c.app_key:08x}")
    if status != STATUS_OK:
        c.close()
        return 1

    # ---- optional variable access ----
    suffix = args.var_suffix
    if suffix:
        try:
            suffix = bytes.fromhex(suffix)
        except ValueError:
            suffix = suffix.encode("ascii")
    else:
        suffix = b""

    rc = 0

    if args.var_write:
        print("\n========== CmpIecVarAccess: write ==========")
        for item in args.var_write:
            if "=" not in item:
                print(f"  {item!r}: expected NAME=VALUE")
                rc = 1
                continue
            vname, raw = item.split("=", 1)
            try:
                payload = struct.pack("<i", int(raw, 0)) if raw.lstrip("-").isdigit() \
                    else raw.encode("ascii")
            except (ValueError, struct.error):
                payload = raw.encode("ascii")
            resp, tags = c.var_write(vname, payload, suffix)
            st = CodesysTcpClient.var_status(tags)
            print(f"  write {vname} = {raw!r} -> status={st}"
                  + ("  (not found in the running application)"
                     if st == VAR_STATUS_NOT_FOUND else ""))
            if st != VAR_STATUS_OK:
                rc = 1

    if args.var_read:
        print("\n========== CmpIecVarAccess: read ==========")
        handle, tags = c.var_register(args.var_read, suffix=suffix)
        if handle is None:
            print("  register refused; response:")
            dump_tags(tags)
            rc = 1
        else:
            print(f"  registered {len(args.var_read)} name(s), handle = {handle.hex(' ')}")
            resp, rtags = c.var_read(handle)
            st = CodesysTcpClient.var_status(rtags)
            vals = [t for t in _flatten(rtags) if t["id"] == TAG_VAR_RESULT]
            if vals:
                for n, t in zip(args.var_read, vals):
                    body = t["value"][4:]
                    print(f"  {n:32} = {body.hex(' ')}")
            else:
                print(f"  read status = {st}"
                      + ("  (runtime refused: the project likely has no "
                         "Symbol Configuration covering this variable)"
                         if st == VAR_STATUS_NOT_FOUND else ""))
                rc = 1
            c.var_release(handle)

    # ---- optional CmpTraceMgr operations ----
    if want_trace(args):
        rc = trace_cli(c, args, rc)

    c.close()
    return rc


#: TRACE_CONFIGURE body captured verbatim from the IDE (trace2.pcapng pkt#1564).
#: The trace name occupies exactly 12 bytes, so replacements must keep that
#: length or the whole body shifts and the runtime stores a mangled name.
TRACE_CFG_TEMPLATE = bytes.fromhex(
    "108c80004170702e547261636500000016848000000000001184800041707000"
    "128880005461736b000000001384800001000000148480006500000015848000"
    "100000008601e000308480000a00000031848000010000003484800033000000"
    "33848000050000008301bc0021848000010200004e848000050000004d888000"
    "029e3b0600000000208c8000504f552e69546573740000002584800007000000"
    "2684800002000000")


def parse_trace_samples(blob):
    """
    Decode a tag 0x42 sampling block (layout confirmed against trace_save /
    trace_delete captures):

        u32 start_index | N x (u16 timestamp + u32 value) | u32 end_index

    Returns (start, end, [(timestamp, value), ...]).
    """
    if len(blob) < 8:
        return None, None, []
    start = struct.unpack_from("<I", blob, 0)[0]
    end = struct.unpack_from("<I", blob, len(blob) - 4)[0]
    body = blob[4:len(blob) - 4]
    if len(body) % 6:
        body = body[:len(body) - (len(body) % 6)]
    out = [(struct.unpack_from("<H", body, k)[0],
            struct.unpack_from("<I", body, k + 2)[0])
           for k in range(0, len(body), 6)]
    return start, end, out


def want_trace(args):
    return bool(args.trace_list or args.trace_read or args.trace_create
                or args.trace_delete or args.trace_delete_all)


#: traces the runtime provides itself; --trace-delete-all leaves them alone
BUILTIN_TRACES = ("CpuCoreLoad", "PlcLoad")


def trace_cli(c, args, rc):
    """--trace-list / --trace-read / --trace-create / --trace-delete."""
    names, _ = c.trace_list()
    print("\n========== CmpTraceMgr ==========")
    print(f"  runtime traces: {names}")

    # --- delete (0x0003)，按抓包顺序: open -> 0x0003 -> close ---
    to_delete = list(args.trace_delete)
    if args.trace_delete_all:
        to_delete += [n for n in names if n not in BUILTIN_TRACES]

    for name in to_delete:
        if name not in names:
            print(f"  delete {name!r}: not present, skipped")
            rc = 1
            continue
        handle, st = c.trace_open(name)
        if handle is None:
            print(f"  delete {name!r}: open failed (status={st})")
            rc = 1
            continue
        s, resp = c.trace_ctl(TRACE_DELETE, handle)
        c.trace_ctl(TRACE_CLOSE, handle)
        left, _ = c.trace_list()
        gone = name not in left
        print(f"  delete {name!r}: status={s} "
              f"{'-> removed' if gone else '-> STILL PRESENT'}")
        if not gone:
            rc = 1
        names = left

    if not (args.trace_list or args.trace_read or args.trace_create):
        return rc

    if args.trace_create:
        body = TRACE_CFG_TEMPLATE.replace(b"App.Trace\x00\x00\x00",
                                          args.trace_create.encode().ljust(12, b"\x00"))
        if len(body) != len(TRACE_CFG_TEMPLATE):
            print("  [!] trace name must fit in 12 bytes"); return 1
        hdr, resp = c.call(GRP_TRACE, TRACE_CONFIGURE, body)
        tags = parse_tags(resp)
        h = find_tag_deep(tags, TAG_TRACE_HANDLE)
        st = status_of(tags)
        print(f"  create {args.trace_create!r}: status={st} "
              f"handle={h['value'].hex(' ') if h else None}")
        if h is None:
            return 1

    if not args.trace_read:
        return rc

    handle, st = c.trace_open(args.trace_read)
    print(f"  open {args.trace_read!r}: handle="
          f"{handle.hex(' ') if handle else None} status={st}")
    if handle is None:
        return 1

    tags, _ = c.trace_info(handle)
    varnames = [t["value"].rstrip(b"\x00").decode("latin-1")
                for t in _flatten(tags) if t["id"] == 0x20 and t["value"]]
    print(f"  recorded variables: {varnames}")

    if args.trace_start:
        s, _ = c.trace_ctl(TRACE_START, handle)
        print(f"  start -> status={s}")

    print("  samples:")
    for k in range(10):
        tags, resp = c.trace_read(handle, 0)
        cnt = find_tag_deep(tags, 0x52)
        n = struct.unpack("<I", cnt["value"][:4])[0] if cnt else None
        st50 = find_tag_deep(tags, 0x50)
        state = struct.unpack("<I", st50["value"][:4])[0] if st50 else None
        pairs = [(t["value"], None) for t in _flatten(tags) if t["id"] == 0x41]
        datas = [t["value"] for t in _flatten(tags) if t["id"] == 0x42]
        print(f"    [{k}] state={state} samples={n} status={status_of(tags)} "
              f"blocks={len(datas)}")
        got = False
        for d in datas:
            s0, s1, samples = parse_trace_samples(d)
            if not samples:
                continue
            got = True
            print(f"        索引 {s0}..{s1}  {len(samples)} 个样本")
            print(f"        时间戳/值: {samples[:10]}")
            vals = [v for _, v in samples]
            print(f"        最小值={min(vals)} 最大值={max(vals)}")
        if got:
            print("        *** 读到采样值 ***")
            break
        if state == 3:
            break
        time.sleep(1)
    return rc


if __name__ == "__main__":
    sys.exit(main())
