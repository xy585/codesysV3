#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
The boofuzz connection for a CODESYS V3 runtime.

``ITargetConnection`` needs only ``open``/``close``/``send``/``recv``/``info``,
so instead of reaching into boofuzz's socket (``target.connection._sock``) this
module owns one.  That matters because the protocol needs *exact-length* reads:
every frame is length-prefixed, and boofuzz's ``recv(max_bytes)`` returns
whatever happens to have arrived, which cannot be reassembled without buffering
the framing by hand.

``open()`` also has to do real work.  A CODESYS services request is meaningless
on its own: it is only accepted on an open channel, under a session id that has
been through the RSA-OAEP login, and (for anything touching the PLC program)
bound to an application.  All of that is re-run here for every test case by
calling the existing, capture-verified ``CodesysTcpClient`` methods rather than
reimplementing them — see ``CodesysTransport``.

Open on every test case is deliberate.  boofuzz's default is a fresh connection
per case, which keeps the TCP stream free of a previous case's half-read reply,
and the runtime's four-slot channel table is kept clean by always sending
CLOSE_CHANNEL in ``close()``.
"""

import socket
import sys
import time

from boofuzz import exception
from boofuzz.connections import ITargetConnection

from proto import (
    PKT_INFO, STATUS_OK, TCP_PORT, ChannelUnavailable, CodesysTcpClient,
    build_ack, build_close_channel, build_keepalive, parse_channel,
)


def count_frames(data):
    """Number of length-prefixed block-driver frames in ``data``.

    Each frame declares its own total length, so walking them is exact and needs
    no knowledge of how the message was split.
    """
    import struct as _struct
    n, off = 0, 0
    while off + 8 <= len(data):
        _, length = _struct.unpack_from("<II", data, off)
        if length < 8 or off + length > len(data):
            break
        off += length
        n += 1
    return n


class SessionState(object):
    """Everything about the wire that only exists once a channel is open.

    Shared, not copied: :class:`CodesysTransport` proxies its attributes onto
    this object, ``FrameEncoder`` reads and writes it at render time, and
    ``CodesysConnection.open()`` refreshes it per test case.  One mutable
    instance means there is exactly one source of truth for the channel id, the
    per-channel token and the block counters, rather than three copies that can
    drift apart.
    """

    __slots__ = ("channel_id", "token", "session_id", "tx_blk", "rx_blk",
                 "app_key", "app_name", "local_ip", "local_port",
                 "remote_ip", "remote_port")

    def __init__(self):
        self.channel_id = None
        self.token = None
        self.session_id = 0
        self.tx_blk = 0
        self.rx_blk = 0
        self.app_key = None
        self.app_name = None
        self.local_ip = "0.0.0.0"
        self.local_port = 0
        self.remote_ip = "0.0.0.0"
        self.remote_port = 0

    def reset_channel(self):
        """Forget everything scoped to one channel.

        Must run whenever a new TCP connection is dialled.  The channel id, the
        per-channel token and both block counters belong to *that* channel; the
        runtime numbers blocks from 1 on a fresh one, and carries the token in
        every frame.  Leaving a stale ``tx_blk`` in place makes the handshake
        open a new channel but number its blocks from wherever the previous one
        stopped, which the runtime answers by dropping the connection — and the
        half-opened channel it had already allocated is then leaked, filling the
        four-slot table within a few test cases.
        """
        self.channel_id = None
        self.token = None
        self.session_id = 0
        self.tx_blk = 0
        self.rx_blk = 0
        self.app_key = None

    def describe(self):
        return ("channel=0x%08x token=%s session=0x%08x tx_blk=%d rx_blk=%d"
                % (self.channel_id or 0, (self.token or b"??").hex(" "),
                   self.session_id or 0, self.tx_blk, self.rx_blk))


class CodesysTransport(CodesysTcpClient):
    """``CodesysTcpClient`` bound to a socket and a :class:`SessionState`.

    Subclassing rather than importing keeps ``open_channel``, ``create_session``,
    ``get_public_key``, ``login``, ``app_login``, ``send_blk``, ``recv_services``
    and ``build_close_channel`` usable byte-for-byte as captured.  Those methods
    are written against ``self.channel_id`` / ``self.token`` / ``self.tx_blk`` /
    ``self.rx_blk``, so the only thing this class has to do is make those names
    read and write the shared state instead of instance attributes.

    ``__init__`` is deliberately not called — it dials the target, and the socket
    is already connected by the time this object exists.
    """

    def __init__(self, sock, state, host, port, timeout=5.0, verbose=False,
                 pkt_info=PKT_INFO):
        self.sock = sock
        self.state = state
        self.host, self.port = host, port
        self.verbose = verbose
        self.pkt_info = pkt_info
        try:
            self.local_ip, self.local_port = sock.getsockname()[:2]
        except OSError:
            self.local_ip, self.local_port = "0.0.0.0", 0
        self.state.local_ip = self.local_ip
        self.state.local_port = self.local_port
        self.state.remote_ip = host
        self.state.remote_port = port
        sock.settimeout(timeout)

    # ---- the shared state, under the names CodesysTcpClient uses ----
    @property
    def channel_id(self):
        return self.state.channel_id

    @channel_id.setter
    def channel_id(self, value):
        self.state.channel_id = value

    @property
    def token(self):
        return self.state.token

    @token.setter
    def token(self, value):
        self.state.token = value

    @property
    def session_id(self):
        return self.state.session_id

    @session_id.setter
    def session_id(self, value):
        self.state.session_id = value

    @property
    def tx_blk(self):
        return self.state.tx_blk

    @tx_blk.setter
    def tx_blk(self, value):
        self.state.tx_blk = value

    @property
    def rx_blk(self):
        return self.state.rx_blk

    @rx_blk.setter
    def rx_blk(self, value):
        self.state.rx_blk = value

    @property
    def app_key(self):
        return self.state.app_key

    @app_key.setter
    def app_key(self, value):
        self.state.app_key = value

    @property
    def app_name(self):
        return self.state.app_name

    @app_name.setter
    def app_name(self, value):
        self.state.app_name = value

    def drain(self, quiet=0.2, limit=64):
        """Read and discard anything still queued, until the socket goes quiet.

        Needed before a handshake: TCP is a stream, and one stray frame left from
        a previous test case would be consumed as if it were the reply to
        GET_CHANNEL, desynchronising every read after it.
        """
        dropped = 0
        old = self.sock.gettimeout()
        self.sock.settimeout(quiet)
        try:
            while dropped < limit:
                try:
                    if not self.sock.recv(4096):
                        break
                    dropped += 1
                except (TimeoutError, socket.timeout):
                    break
                except OSError:
                    break
        finally:
            try:
                self.sock.settimeout(old)
            except OSError:
                pass
        return dropped


class CodesysConnection(ITargetConnection):
    """One TCP connection to CmpBlkDrvTcp, fully handshaken.

    ``state`` is public and stable for the lifetime of the object — it is the
    object ``FrameEncoder`` and ``datagram_header`` are bound to, so it must
    exist before the request is defined, which is why it is created in
    ``__init__`` rather than in ``open()``.
    """

    def __init__(self, host, port=TCP_PORT, user="test", password="test",
                 app_name="App", timeout=5.0, verbose=False, app_login=True,
                 max_channel_waits=6, channel_wait=20.0):
        self.host, self.port = host, port
        self.user, self.password = user, password
        self.app_name = app_name
        self.timeout = timeout
        self.verbose = verbose
        self.app_login = app_login
        self.max_channel_waits = max_channel_waits
        self.channel_wait = channel_wait

        self.state = SessionState()
        self.state.remote_ip = host
        self.state.remote_port = port

        self._sock = None
        self._t = None
        self.last_handshake_error = None
        self.broken = False
        self.handshakes = 0
        self.replies = 0
        self.keepalives = 0
        self.channel_closes = 0
        self.recv_errors = 0
        self.truncated_replies = 0
        self.oversize_replies = 0
        self.break_reason = None
        self.last_case = None

    # ------------------------------------------------------------
    # session lifetime
    # ------------------------------------------------------------
    @property
    def is_open(self):
        return self._sock is not None and not self.broken

    def ensure_open(self):
        """Handshake if there is no usable session, otherwise do nothing.

        This is what makes fuzzing at any useful rate possible.  The runtime's
        channel table holds four entries and ``CLOSE_CHANNEL`` does **not**
        release one — measured: four handshakes succeed and the fifth is refused
        until the runtime reaps the idle channels ~20 s later.  So a
        fresh-connection-per-test-case design tops out at roughly four cases per
        20 seconds.  Holding one channel open and re-handshaking only after a
        failure turns that into thousands per minute.
        """
        if self.is_open:
            return
        if self._sock is not None or self._t is not None:
            self.close()
        self.broken = False
        self.open()

    def service_reply(self, max_frames=4096, timeout=2.0, ack_every=8,
                      max_total=8.0):
        """Read the runtime's reply, keeping the stream and the channel healthy.

        Bounded rather than a ``while True``: the runtime starts ping-ponging
        keepalives in some states, and ``CodesysTcpClient.recv_services`` echoes
        each one forever, so a reply read that never returns is a real failure
        mode this protocol has.  A bound plus a socket timeout turns it into a
        clean "no reply".

        Echoing keepalives is not optional on a long-lived channel: the runtime
        closes a channel it has pinged too many times without an answer.

        Any error sets ``broken``, so the next case re-handshakes on a fresh
        socket rather than trying to resynchronise a half-read stream.

        Returns ``(body, complete)``:

            ``(bytes, True)``   a whole reply
            ``(None, True)``    nothing arrived — a clean "no reply"
            ``(b"", True)``     the runtime closed the channel
            ``(_, False)``      incomplete, and the stream is now desynchronised

        The flag matters because a partial read and a short reply look alike:
        without it a truncated body gets parsed as if it were whole, which can
        turn a broken reply into a bogus ``status=None`` and hence a false
        "accepted".
        """
        t = self._t
        if t is None:
            return None, True
        old = None
        try:
            old = self._sock.gettimeout()
            self._sock.settimeout(timeout)
        except OSError:
            return None, False

        buf = bytearray()
        declared = None
        frames = 0
        got_anything = False
        # Bound the read by *silence*, not by total elapsed time.  Two things
        # make a fixed deadline wrong.  Only BLK frames increment `frames`, so
        # keepalives and unparseable datagrams reach `continue` without
        # advancing anything — a frame-count-only bound lets such a stream spin
        # the loop `max_frames` times, each costing a full socket timeout, which
        # at the default is ~64 s of holding a channel the runtime wants back.
        # And the size is not bounded either: measured replies reach 35 KB and
        # 95 KB (~200 frames), so any fixed deadline long enough for a small
        # reply truncates a large one — and a truncated reply desynchronises the
        # stream and costs a channel.
        #
        # So: keep reading while frames keep arriving, and give up once nothing
        # has arrived for `timeout` seconds.  `hard_cap` only exists to bound
        # the damage from a runtime that streams forever.
        # Two caps, because they catch different failures.  Silence catches "the
        # runtime has nothing more to say".  The total cap catches a reply that
        # keeps trickling: CmpVisuServer and CmpIecVarAccess answer a garbage
        # sweep request with 35 KB and 95 KB replies (~200 frames) and deliver
        # them at roughly 590 B/s, so a silence-only bound holds one channel
        # open for minutes per case.  A fuzzer does not need to read those, and
        # abandoning them costs one re-handshake instead of the whole run's
        # budget spent on three groups.
        hard_cap = time.monotonic() + max_total
        last_progress = time.monotonic()
        try:
            while (frames < max_frames
                   and time.monotonic() - last_progress < timeout
                   and time.monotonic() < hard_cap):
                dg = t.recv_raw()
                if dg is None:
                    continue
                ch = parse_channel(dg["payload"])
                kind = ch["type"]

                if kind == "keepalive":
                    self.keepalives += 1
                    if ch["channel_id"] == self.state.channel_id:
                        t.send_raw(build_keepalive(self.state.channel_id,
                                                   self.state.token))
                    continue

                if kind in ("blk_first", "blk_cont"):
                    # Only real data counts as progress.  A keepalive proves the
                    # channel is alive but says nothing about whether a reply is
                    # still coming, so counting it would let a keepalive-active
                    # channel hold this loop open until the hard cap — every case
                    # costing two minutes instead of the reply's actual latency.
                    last_progress = time.monotonic()
                    got_anything = True
                    if ch["channel_id"] != self.state.channel_id:
                        continue
                    if kind == "blk_first":
                        declared = ch["data_size"]
                    buf += ch["data"]
                    self.state.rx_blk = ch["blk_id"]
                    frames += 1
                    if declared is not None and len(buf) >= declared:
                        break
                    # Acknowledge as the stream flows rather than once at the
                    # end.  Measured: a 95 KB reply (~200 frames) advanced at
                    # ~590 B/s when it was only ACKed at the end — two minutes of
                    # holding a channel — which is what a sliding window waiting
                    # for acknowledgement looks like.  Small replies never
                    # noticed because they are one or two frames.
                    if frames % ack_every == 0:
                        try:
                            t.send_raw(build_ack(self.state.channel_id,
                                                 self.state.token,
                                                 self.state.rx_blk))
                        except (OSError, ValueError):
                            self.broken = True
                            return None, False
                    continue

                if kind == "close":
                    if ch["channel_id"] == self.state.channel_id:
                        # the runtime killed our channel — this is the event
                        # that forces a re-handshake, so count it and say so
                        self.channel_closes += 1
                        self.break_reason = (
                            "runtime closed our channel (0x84) after case %s"
                            % self.last_case)
                        self.broken = True
                        return b"", True
                    continue

                if kind == "ack":
                    continue
        except (TimeoutError, socket.timeout):
            # A timeout on a clean stream is just "no reply" — most of a sweep's
            # packets are answered with nothing at all, and treating that as a
            # broken session would cost a re-handshake per case.  A timeout after
            # part of a frame has been consumed is different: the stream is now
            # misaligned and the only safe recovery is a fresh channel.
            if got_anything or buf:
                self.break_reason = ("timed out mid-frame after case %s "
                                     "(stream desynchronised)" % self.last_case)
                self.broken = True
                return None, False
        except (OSError, ValueError, ConnectionError) as e:
            self.recv_errors += 1
            self.break_reason = ("socket error while reading the reply after "
                                 "case %s: %s" % (self.last_case, e))
            self.broken = True
            return None, False
        finally:
            try:
                self._sock.settimeout(old)
            except OSError:
                pass

        # A reply that stopped short of its declared length is not a short
        # reply — it is an unfinished one.  Returning it anyway would be doubly
        # wrong: the partial body can misparse into a bogus status (a truncated
        # tag stream raises inside parse_tags, `status` ends up None, and None
        # reads as "accepted"), and the bytes still sitting in the socket would
        # be read as the *next* case's reply.  So the stream is desynchronised by
        # definition here: report incomplete and force a fresh channel.
        if declared is not None and len(buf) < declared:
            if time.monotonic() >= hard_cap:
                # Gave up on a reply that was still trickling, rather than one
                # that went quiet — a different failure with a different fix.
                self.oversize_replies += 1
                self.break_reason = (
                    "abandoned a %d-byte reply after case %s: %d bytes in %gs, "
                    "the runtime trickles large replies"
                    % (declared, self.last_case, len(buf), max_total))
            else:
                self.truncated_replies += 1
                self.break_reason = (
                    "reply incomplete after case %s: %d of %d bytes before %gs "
                    "of silence"
                    % (self.last_case, len(buf), declared, timeout))
            self.broken = True
            return None, False

        # a multi-frame reply must be acknowledged or the runtime retransmits
        if frames > 1:
            try:
                t.send_raw(build_ack(self.state.channel_id, self.state.token,
                                     self.state.rx_blk))
            except (OSError, ValueError):
                self.broken = True

        if not got_anything:
            return None, True
        self.replies += 1
        return bytes(buf[:declared]) if declared is not None else bytes(buf), True

    # ------------------------------------------------------------
    # ITargetConnection
    # ------------------------------------------------------------
    def open(self):
        """Idempotent: opening an open connection is a no-op.

        ``Fuzzer.fuzz`` handshakes before the run so that a failure is
        reportable, and boofuzz then calls ``open`` again from its own loop;
        without this that second call would cost another handshake and another
        channel slot out of the four the runtime has.
        """
        if self.is_open:
            return
        self._open_until_usable()

    def _open_until_usable(self):
        """Dial and complete the handshake, or raise boofuzz's connection error.

        The two failure modes want opposite treatment.  A refused or reset
        socket is the crash signal, so it is retried exactly once (a single
        retry absorbs a transient) and then reported — retrying harder would
        only delay the crash report.  A full channel table, by contrast, is
        transient by construction: the runtime reaps idle channels after tens of
        seconds, so that one is worth waiting out, exactly as
        ``codesys_tcp.main()`` does.
        """
        refusals = 0
        while True:
            try:
                self._open_once()
                self.broken = False
                self.handshakes += 1
                return
            except (ChannelUnavailable,
                    exception.BoofuzzTargetConnectionFailedError,
                    OSError, socket.timeout) as e:
                self.last_handshake_error = "%s: %s" % (type(e).__name__, e)
            except Exception as e:
                self.last_handshake_error = "%s: %s" % (type(e).__name__, e)

            # A failed handshake means one of two very different things, and the
            # difference matters: if the listener is still accepting TCP then the
            # runtime is alive and merely refusing — its four-slot channel table
            # is full and it resets new connections until it has been idle long
            # enough to reap (~20 s).  Treating that as a crash would abort a run
            # against a perfectly healthy runtime, and retrying it fast is what
            # *keeps* the table full, so the wait has to be long enough to let
            # the reaper run.  Only a refused connect means the runtime is gone.
            self.close()
            # Classify once, on the first failure: a refused connect means the
            # runtime is gone, anything else is it declining to serve us.
            if refusals == 0:
                alive, why = self.probe()
                if not alive:
                    # "did not accept" rather than "is gone": a *refused*
                    # connect means the process is gone, but the probe can also
                    # time out against a merely busy listener, and the error
                    # type carried in `why` is what tells the two apart.
                    self.last_handshake_error += (
                        " (the listener did not accept a connection: %s)" % why)
                    break
            refusals += 1
            if refusals >= self.max_channel_waits:
                self.last_handshake_error += (
                    " (listener alive throughout, so this looks like the runtime "
                    "declining to serve rather than a crash — try restarting it)")
                break
            # Wait quietly.  Every retry is itself network activity, so poking
            # the runtime every few seconds is the one thing guaranteed to stop
            # it reaping whatever it is holding.
            time.sleep(self.channel_wait)

        # boofuzz reports only "cannot connect", which is useless for telling a
        # dead runtime from a refused login from a full channel table, so the
        # real reason goes to stderr where a fuzzing run's operator will see it.
        sys.stderr.write("[!] handshake failed for %s:%d: %s\n"
                         % (self.host, self.port, self.last_handshake_error))
        sys.stderr.flush()
        raise exception.BoofuzzTargetConnectionFailedError(
            "CODESYS handshake failed for %s:%d (%s)"
            % (self.host, self.port, self.last_handshake_error))

    def _open_once(self):
        try:
            sock = socket.create_connection((self.host, self.port),
                                            timeout=self.timeout)
        except (OSError, socket.timeout) as e:
            raise exception.BoofuzzTargetConnectionFailedError(
                "cannot reach %s:%d (%s)" % (self.host, self.port, e))
        # a new socket is a new channel: the id, token and block counters of the
        # previous one must not leak into this handshake
        self.state.reset_channel()
        self._sock = sock
        self._t = CodesysTransport(sock, self.state, self.host, self.port,
                                   timeout=self.timeout, verbose=self.verbose)

        self._t.drain()
        self._t.open_channel()
        self._t.create_session()
        pem, challenge = self._t.get_public_key()
        status, _ = self._t.login(pem, challenge, self.user, self.password)
        if status != STATUS_OK:
            raise exception.BoofuzzTargetConnectionFailedError(
                "device login rejected (status=%s)" % (status,))
        if self.app_login:
            self._t.app_login(self.app_name)

    def close(self):
        """Release the channel, then drop the connection.

        CLOSE_CHANNEL matters: the runtime's channel table has four slots and an
        abandoned channel is not reaped for tens of seconds, so without this a
        fuzzing run stalls on "channel table full" within a handful of cases.
        The runtime does not answer it, so nothing is read back.

        Draining before closing is not tidiness, it is what makes the
        CLOSE_CHANNEL arrive.  A socket closed while data is still unread in its
        receive buffer makes the stack send RST instead of FIN, and an RST can
        discard data that was already written but not yet delivered — so the
        CLOSE_CHANNEL is thrown away, the channel is leaked, and the run dies a
        few cases later on a full channel table.  A fuzzed request's reply is
        routinely not fully read.
        """
        if self._t is not None:
            if self._t.channel_id is not None:
                try:
                    self._t.send_raw(build_close_channel(self._t.channel_id,
                                                         self._t.token))
                except (OSError, ValueError, AttributeError):
                    pass
            # Half-close first: the FIN goes out *after* the CLOSE_CHANNEL, so
            # the runtime sees an orderly shutdown and reads what we wrote
            # instead of resetting.  Then read to EOF.
            try:
                self._sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            try:
                self._t.drain(quiet=0.05)
            except (OSError, AttributeError):
                pass
        self._t = None
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def send(self, data):
        """Write the rendered frame sequence.

        The blob is a concatenation of complete length-prefixed frames, which is
        exactly the sequence ``send_blk`` emits today, so a plain ``sendall`` is
        right — and unlike boofuzz's single ``socket.send`` it cannot
        short-write a multi-frame message.

        This is also where ``tx_blk`` advances.  ``FrameEncoder`` is pure because
        boofuzz renders a block several times per test case; counting the frames
        actually written, here, is the only place the number is known exactly.
        """
        if self._sock is None:
            raise exception.BoofuzzTargetConnectionFailedError(
                "send on a closed connection")
        try:
            self._sock.sendall(data)
        except OSError as e:
            raise exception.BoofuzzTargetConnectionReset(str(e))
        self.state.tx_blk = (self.state.tx_blk or 0) + count_frames(data)
        return len(data)

    def recv(self, max_bytes=4096):
        """Read whatever is pending.  A timeout is not an error here.

        boofuzz calls this after every test case; its only jobs are to drain the
        runtime's reply and to notice a reset, which is the crash signal.
        """
        if self._sock is None:
            return b""
        try:
            return self._sock.recv(max_bytes)
        except (TimeoutError, socket.timeout):
            return b""
        except OSError as e:
            raise exception.BoofuzzTargetConnectionReset(str(e))

    @property
    def info(self):
        return "%s:%d" % (self.host, self.port)

    # ------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------
    @property
    def session_id(self):
        return self.state.session_id

    @property
    def transport(self):
        """The live ``CodesysTransport``, or None when closed.

        Exposed because reading a reply needs the length-prefixed frame reader
        (``recv_raw``); boofuzz's ``recv`` cannot reassemble a frame on its own.
        """
        return self._t

    def probe(self, timeout=2.0):
        """Is the runtime still accepting connections on its block driver?

        A refused connect means the process is gone.  A *successful* connect is
        weaker evidence than it looks — it only proves something is listening —
        so a hung runtime reads as alive; see the Readme.
        """
        try:
            s = socket.create_connection((self.host, self.port), timeout=timeout)
        except (OSError, socket.timeout) as e:
            return False, "%s: %s" % (type(e).__name__, e)
        try:
            s.close()
        except OSError:
            pass
        return True, ""
