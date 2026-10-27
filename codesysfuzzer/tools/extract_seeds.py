#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Extract request bodies from a TCP capture and write them as seed corpus files.

This closes the loop from "we captured the IDE doing something" to "the seed
mutator can start from that exact request".  It reads the block-driver framing
the same way ``transport.py`` does, reassembles multi-frame messages (an
application download or a large configure request spans many frames), and keeps
only requests: a reply is identified by bit 7 of the group, which the runtime
sets in every answer.

Only the **services body** is written.  Channel token, block ids and session id
belong to the captured TCP session and are dead by the next run; the request
skeleton injects a live session and ``FrameEncoder`` rebuilds the framing.

Usage
    python tools/extract_seeds.py trace2.pcapng -o seeds/
    python tools/extract_seeds.py *.pcapng -o seeds/ --group 0x0f
    python tools/extract_seeds.py trace.pcapng -o seeds/ --jsonl all-seeds.jsonl

``scapy`` is needed for capture input.  It is optional for the fuzzer itself:
``--save-seed`` and ``--capture-seeds`` do not use it.
"""

import argparse
import json
import os
import struct
import sys

_PKG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PKG not in sys.path:
    sys.path.insert(0, _PKG)

from proto import (                                         # noqa: E402
    BD_MAGIC, BD_HEADER_LEN, MAX_PDU, TCP_PORT, parse_channel, parse_datagram,
    parse_services,
)
from corpus import write_seed                               # noqa: E402


def _frames(payload, buffer):
    """Yield complete block-driver frames from a per-direction byte buffer.

    A capture can start mid-frame or contain something that is not a frame at
    all, so a bad header drops one byte and retries instead of giving up on the
    whole flow.
    """
    buffer.extend(payload)
    while len(buffer) >= BD_HEADER_LEN:
        magic, length = struct.unpack_from("<II", buffer, 0)
        if (magic != BD_MAGIC or length < BD_HEADER_LEN
                or length > MAX_PDU + BD_HEADER_LEN):
            del buffer[0]
            continue
        if len(buffer) < length:
            return
        frame = bytes(buffer[:length])
        del buffer[:length]
        yield frame


def _messages(frames):
    """Reassemble channel messages across ``blk_first``/``blk_cont`` frames.

    Returns the services bytes of each complete message.  A new first-frame
    abandons an incomplete message rather than mixing two of them.
    """
    pending = None
    declared = 0
    for frame in frames:
        try:
            datagram = parse_datagram(frame[BD_HEADER_LEN:])
        except (ValueError, struct.error, IndexError):
            continue
        if datagram is None:
            continue
        try:
            channel = parse_channel(datagram["payload"])
        except (ValueError, KeyError, IndexError):
            continue
        kind = channel.get("type")
        if kind == "blk_first":
            pending = bytearray(channel["data"])
            declared = channel.get("data_size") or 0
        elif kind == "blk_cont" and pending is not None:
            pending.extend(channel["data"])
        else:
            continue
        if pending is not None and declared and len(pending) >= declared:
            yield bytes(pending[:declared])
            pending = None
            declared = 0


class _Reassembler(object):
    """Shared ``blk_first``/``blk_cont`` state for one direction of a flow."""

    def __init__(self):
        self.pending = None
        self.declared = 0

    def feed(self, channel):
        kind = channel.get("type")
        if kind == "blk_first":
            self.pending = bytearray(channel["data"])
            self.declared = channel.get("data_size") or 0
        elif kind == "blk_cont" and self.pending is not None:
            self.pending.extend(channel["data"])
        else:
            return None
        if self.pending is not None and self.declared \
                and len(self.pending) >= self.declared:
            message = bytes(self.pending[:self.declared])
            self.pending = None
            self.declared = 0
            return message
        return None


def _udp_parsers():
    """The UDP framing lives in ``codesys_udp_ds``; import it only if needed.

    ``codesys_tcp`` and ``codesys_udp_ds`` are separate reverse-engineered
    clients, and the captures in this repository are the UDP/flash gateway
    variant.  Reusing its parsers avoids a second copy that could drift.
    """
    root = os.path.dirname(_PKG)
    if root not in sys.path:
        sys.path.insert(0, root)
    from codesys_udp_ds import (
        parse_channel as udp_parse_channel,
        parse_datagram as udp_parse_datagram,
    )
    return udp_parse_datagram, udp_parse_channel


def extract(paths, outdir, port=0, group=None, service=None,
            min_body=1, max_body=65536, jsonl=None):
    try:
        from scapy.all import IP, IPv6, Raw, TCP, UDP, TCPSession, sniff
    except ImportError:
        print("[!] scapy is required to read captures: pip install scapy")
        return 2, []

    def endpoint(packet):
        if packet.haslayer(IP):
            return packet[IP].src, packet[IP].dst
        if packet.haslayer(IPv6):
            return packet[IPv6].src, packet[IPv6].dst
        return None, None

    buffers = {}         # tcp flow -> partial block-driver bytes
    assemblers = {}      # flow -> _Reassembler
    written = []
    accepted = 0

    def handle(message, source):
        nonlocal accepted
        try:
            header, body = parse_services(message)
        except (ValueError, KeyError, struct.error):
            return
        # bit 7 of the group marks a reply; requests carry the plain id
        if header["group"] & 0x0080:
            return
        if group is not None and header["group"] != group:
            return
        if service is not None and header["service_id"] != service:
            return
        if not (min_body <= len(body) <= max_body):
            return
        accepted += 1
        written.append({"group": header["group"],
                        "service": header["service_id"],
                        "body": body, "source": source})

    udp_parsers = None
    for path in paths:
        print("[pcap] %s" % path)
        try:
            # sniff(offline=...) is the entry point that still takes a session
            # in scapy 2.7; rdpcap no longer does.  TCPSession drops
            # retransmissions and hands the payload over in stream order.
            packets = sniff(offline=path, session=TCPSession)
        except Exception as e:                     # noqa: BLE001 - scapy raises many
            print("       cannot read: %s" % e)
            continue
        for index, packet in enumerate(packets):
            if not packet.haslayer(Raw):
                continue
            payload = bytes(packet[Raw].load)
            if not payload:
                continue
            src, dst = endpoint(packet)
            if src is None:
                continue

            # ---- TCP block driver: one datagram per 8-byte BD frame ----
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                if port and port not in (tcp.sport, tcp.dport):
                    continue
                key = ("tcp", src, tcp.sport, dst, tcp.dport)
                buffer = buffers.setdefault(key, bytearray())
                for message in _messages(
                        list(_frames(payload, buffer))):
                    handle(message, "%s#pkt%d"
                           % (os.path.basename(path), index + 1))
                continue

            # ---- UDP block driver: the datagram is the packet ----
            if packet.haslayer(UDP):
                udp = packet[UDP]
                if port and port not in (udp.sport, udp.dport):
                    continue
                if payload[0] != 0xC5:            # CmpBlkDrvUdp magic
                    continue
                if udp_parsers is None:
                    udp_parsers = _udp_parsers()
                udp_parse_datagram, udp_parse_channel = udp_parsers
                try:
                    datagram = udp_parse_datagram(payload)
                    if datagram is None:
                        continue
                    channel = udp_parse_channel(datagram["payload"])
                except (ValueError, KeyError, IndexError, struct.error):
                    continue
                key = ("udp", src, udp.sport, dst, udp.dport)
                message = assemblers.setdefault(
                    key, _Reassembler()).feed(channel)
                if message is not None:
                    handle(message, "%s#pkt%d"
                           % (os.path.basename(path), index + 1))

    # dedupe by content before touching the filesystem
    unique = {}
    for row in written:
        key = (row["group"], row["service"], row["body"])
        if key in unique:
            continue
        unique[key] = write_seed(outdir, row["group"], row["service"],
                                 row["body"], source=row["source"],
                                 verdict="captured")
    new = [p for p in unique.values() if p]
    print("[pcap] %d request(s) parsed, %d new seed(s) written, %d duplicate(s)"
          % (accepted, len(new), accepted - len(new)))
    if jsonl:
        with open(jsonl, "w", encoding="utf-8") as fh:
            for row in written:
                fh.write(json.dumps({
                    "group": "0x%04x" % row["group"],
                    "service": "0x%04x" % row["service"],
                    "body": row["body"].hex(),
                    "source": row["source"],
                    "verdict": "captured",
                }) + "\n")
        print("[jsonl] %d row(s) -> %s" % (len(written), jsonl))
    return 0, written


def main():
    ap = argparse.ArgumentParser(
        prog="extract_seeds.py",
        description="Extract CODESYS request bodies from pcap/pcapng files.")
    ap.add_argument("captures", nargs="+", help="pcap/pcapng file(s)")
    ap.add_argument("-o", "--out", default="seeds",
                    help="seed directory (default seeds/)")
    ap.add_argument("--port", type=lambda s: int(s, 0), default=0,
                    help="only this TCP/UDP port (default 0 = inspect every "
                         "stream; the block-driver magic is the real filter).  "
                         "The device service listens on %d and the gateway on "
                         "another port, so a capture may use either" % TCP_PORT)
    ap.add_argument("--group", type=lambda s: int(s, 0), default=None,
                    help="only this service group")
    ap.add_argument("--service", type=lambda s: int(s, 0), default=None,
                    help="only this service id")
    ap.add_argument("--min-body", type=int, default=1)
    ap.add_argument("--max-body", type=int, default=65536)
    ap.add_argument("--jsonl", default=None,
                    help="also write every parsed request as JSONL")
    args = ap.parse_args()
    rc, written = extract(args.captures, args.out, port=args.port,
                          group=args.group, service=args.service,
                          min_body=args.min_body, max_body=args.max_body,
                          jsonl=args.jsonl)
    if written:
        pairs = sorted({(row["group"], row["service"]) for row in written})
        print("[pcap] pairs: %s"
              % " ".join("0x%02x/0x%04x" % p for p in pairs))
    return rc


if __name__ == "__main__":
    sys.exit(main())
