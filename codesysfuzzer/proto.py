#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bootstrap for the CODESYS V3 protocol library.

The framing, tag codec, login crypto and constants all already exist, tested
byte-for-byte against the captures, in ``codesys_tcp.py`` at the repository root.
Nothing here re-implements any of it: this module only puts the repository root
on ``sys.path`` so the fuzzer package can live in its own directory, and then
re-exports the pieces the fuzzer needs.

``codesys_tcp.py`` is a working PoC and is deliberately left untouched.
"""

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from codesys_tcp import (                                        # noqa: E402
    # ---- constants: transport framing ----
    TCP_PORT, GATEWAY_PORT, DATAGRAM_MAGIC, BD_MAGIC, BD_HEADER_LEN,
    MAX_PDU, DATAGRAM_HEADER, HDR_PREFIX_WORDS, PKT_INFO, SERVICE_CHANNEL,
    PKT_BLK, PKT_ACK, PKT_KEEPALIVE, CH_GET_REQ, CH_GET_RESP,
    CH_CLOSE_REQ, CH_CLOSE_RESP,
    # ---- constants: services layer ----
    PROTO_TAG, GRP_DEVICE, GRP_APP, GRP_IECVAR, GRP_TRACE,
    DEV_IDENTIFY, DEV_AUTH, DEV_SESSION,
    APP_LOOKUP, APP_READ_STATE,
    TRACE_LIST, TRACE_CONFIGURE, TRACE_DELETE, TRACE_START, TRACE_OPEN,
    TRACE_CLOSE, TRACE_READ, TRACE_INFO,
    TAG_TRACE_NAME, TAG_TRACE_HANDLE, TAG_TRACE_OFFSET, TAG_TRACE_DATA,
    TAG_TRACE_STATUS,
    VAR_REGISTER, VAR_RELEASE, VAR_READ, VAR_WRITE, VAR_REGISTER_FLAGS,
    TAG_PROTO_VER, TAG_USERNAME, TAG_PASSWORD, TAG_STATUS, TAG_SESSION,
    TAG_CRYPTTYPE, TAG_DEVICE_SETTINGS, TAG_AUTHSTEP, TAG_CHALLENGE,
    TAG_PUBKEY, TAG_PRIVILEGE,
    TAG_VAR_HANDLE, TAG_VAR_FLAGS, TAG_VAR_COUNT, TAG_VAR_NAMES,
    TAG_VAR_RESULT, TAG_VAR_VALUE, TAG_VAR_STATUS, TAG_VAR_NAME,
    VAR_STATUS_OK, VAR_STATUS_NOT_FOUND,
    CRYPT_TYPE, STATUS_OK, STATUS_KEY_EXCHANGE, STATUS_BAD_PASSWORD,
    STATUS_BAD_USER,
    # ---- codec ----
    leb128, leb128_pad3, read_leb128, tag, parent_tag, parse_tags,
    find_tag, find_tag_deep, _flatten, dump_tags, status_of,
    # ---- framing builders / parsers ----
    build_block_frame, parse_block_frame, full_address, build_datagram,
    parse_datagram, build_get_channel, build_blk, build_ack, build_keepalive,
    build_close_channel, parse_channel, build_services, parse_services,
    password_hash, build_password_blob, rsa_encrypt, build_login_body,
    # ---- client (reused for the handshake; see transport.py) ----
    ChannelUnavailable, CodesysTcpClient,
    # ---- captured material ----
    TRACE_CFG_TEMPLATE,
)

#: explicit rather than computed: a literal list is what makes these read as
#: re-exports (to a reader and to a linter) instead of as unused imports.
__all__ = [
    # transport framing
    "TCP_PORT", "GATEWAY_PORT", "DATAGRAM_MAGIC", "BD_MAGIC", "BD_HEADER_LEN",
    "MAX_PDU", "DATAGRAM_HEADER", "HDR_PREFIX_WORDS", "PKT_INFO",
    "SERVICE_CHANNEL", "PKT_BLK", "PKT_ACK", "PKT_KEEPALIVE",
    "CH_GET_REQ", "CH_GET_RESP", "CH_CLOSE_REQ", "CH_CLOSE_RESP",
    # services layer
    "PROTO_TAG", "GRP_DEVICE", "GRP_APP", "GRP_IECVAR", "GRP_TRACE",
    "DEV_IDENTIFY", "DEV_AUTH", "DEV_SESSION", "APP_LOOKUP", "APP_READ_STATE",
    "TRACE_LIST", "TRACE_CONFIGURE", "TRACE_DELETE", "TRACE_START",
    "TRACE_OPEN", "TRACE_CLOSE", "TRACE_READ", "TRACE_INFO",
    "TAG_TRACE_NAME", "TAG_TRACE_HANDLE", "TAG_TRACE_OFFSET", "TAG_TRACE_DATA",
    "TAG_TRACE_STATUS",
    "VAR_REGISTER", "VAR_RELEASE", "VAR_READ", "VAR_WRITE", "VAR_REGISTER_FLAGS",
    "TAG_PROTO_VER", "TAG_USERNAME", "TAG_PASSWORD", "TAG_STATUS",
    "TAG_SESSION", "TAG_CRYPTTYPE", "TAG_DEVICE_SETTINGS", "TAG_AUTHSTEP",
    "TAG_CHALLENGE", "TAG_PUBKEY", "TAG_PRIVILEGE",
    "TAG_VAR_HANDLE", "TAG_VAR_FLAGS", "TAG_VAR_COUNT", "TAG_VAR_NAMES",
    "TAG_VAR_RESULT", "TAG_VAR_VALUE", "TAG_VAR_STATUS", "TAG_VAR_NAME",
    "VAR_STATUS_OK", "VAR_STATUS_NOT_FOUND",
    "CRYPT_TYPE", "STATUS_OK", "STATUS_KEY_EXCHANGE", "STATUS_BAD_PASSWORD",
    "STATUS_BAD_USER",
    # codec
    "leb128", "leb128_pad3", "read_leb128", "tag", "parent_tag", "parse_tags",
    "find_tag", "find_tag_deep", "_flatten", "dump_tags", "status_of",
    # framing builders / parsers
    "build_block_frame", "parse_block_frame", "full_address", "build_datagram",
    "parse_datagram", "build_get_channel", "build_blk", "build_ack",
    "build_keepalive", "build_close_channel", "parse_channel", "build_services",
    "parse_services", "password_hash", "build_password_blob", "rsa_encrypt",
    "build_login_body",
    # client, reused for the handshake
    "ChannelUnavailable", "CodesysTcpClient",
    # captured material
    "TRACE_CFG_TEMPLATE",
]
