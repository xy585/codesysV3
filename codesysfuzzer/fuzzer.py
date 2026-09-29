#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
The boofuzz harness, adapted from the OPC UA fuzzer in
``references/opcua_network_fuzzer/fuzzer.py``.

The shape is the same — one target, one connection object, one request model
built per run — with two CODESYS-specific differences:

* the connection is a :class:`~transport.CodesysConnection`, which performs the
  whole channel/session/login handshake inside ``open()``, so boofuzz's per-case
  connect is what establishes the session and no callback has to;
* a :class:`~monitor.CodesysMonitor` is attached to the target, because boofuzz's
  built-in connection-failure detection alone cannot tell a runtime that died
  mid-case from one that is merely slow to answer.

The pre-send callback exists only to inject values that are not known until the
connection is up — the datagram endpoints and the session id.  Everything else in
the frame (channel id, token, block counters, sizes, CRC32) is filled in at
render time by ``FrameEncoder``.
"""

import struct

from boofuzz import Session, Target

from monitor import CodesysMonitor
from services import build_request, request_names
from transport import CodesysConnection
from utils import _s_update


class Fuzzer(object):

    def __init__(self, target_ip, target_port, request_name,
                 user="test", password="test", app_name="App",
                 timeout=5.0, probe_every=1, probe=True, verbose=False,
                 sleep_time=0.0, restart_threshold=1,
                 group=None, service=None, raw_body=False, surface_path=None,
                 surface_mode="global",
                 reply_timeout=2.0, **connection_kwargs):
        self.target_ip = target_ip
        self.target_port = target_port
        self.request_name = request_name
        self.user = user
        self.password = password
        self.app_name = app_name
        self.timeout = timeout
        self.probe_every = probe_every
        self.probe = probe
        self.verbose = verbose
        self.sleep_time = sleep_time
        self.restart_threshold = restart_threshold
        self.group = group
        self.service = service
        self.raw_body = raw_body
        self.surface_path = surface_path
        self.surface_mode = surface_mode
        self.reply_timeout = reply_timeout
        self.connection_kwargs = connection_kwargs

        self.session = None
        self.target = None
        self.connection = None
        self.request = None
        self.monitor = None

    # ------------------------------------------------------------
    # wiring
    # ------------------------------------------------------------
    def _init_target_connection(self):
        """Build the connection, its monitor and the target.

        boofuzz 0.4.2 takes its monitors as a constructor argument — there is no
        ``add_monitor`` — so the monitor has to exist before the Target does.
        """
        self.connection = CodesysConnection(
            self.target_ip, self.target_port, user=self.user,
            password=self.password, app_name=self.app_name,
            timeout=self.timeout, verbose=self.verbose)
        self.monitor = CodesysMonitor(self.connection,
                                      probe_every=self.probe_every,
                                      enabled=self.probe,
                                      verbose=self.verbose,
                                      surface_path=self.surface_path,
                                      surface_mode=self.surface_mode,
                                      reply_timeout=self.reply_timeout)
        self.target = Target(connection=self.connection,
                             monitors=[self.monitor])

    def _init_session(self, db_filename=None, index_start=1, index_end=None,
                      web_port=26000):
        """One long-lived channel, many test cases.

        ``reuse_target_connection`` is essential, not an optimisation: the
        runtime's channel table holds four entries and closing a channel does not
        free one — the fifth handshake is refused until idle channels are reaped
        ~20 s later.  Reconnecting per test case therefore caps the whole fuzzer
        at a few cases per minute.  boofuzz opens the connection once before the
        loop and closes it once after; ``CodesysConnection.ensure_open``
        re-handshakes from the pre-send callback only when a case has broken the
        session.

        ``receive_data_after_each_request`` is off because boofuzz reads with a
        single un-framed ``recv``, which cannot reassemble a length-prefixed
        CODESYS reply and would leave partial frames in the buffer.  The monitor
        reads replies properly instead — see ``CodesysMonitor.post_send``.
        """
        # db_filename is the sqlite case database.  session_filename is a
        # *different* thing — boofuzz's resume file — and is deliberately left
        # unset: boofuzz writes the current mutant index there after every test
        # case and a later run reading it silently skips everything before that
        # point, which turns a second run into "0 cases, no error".
        # web_port=None must go in here, not be assigned afterwards: Session.__init__
        # starts the web thread, so clearing the port later leaves it running.
        self.session = Session(
            db_filename=db_filename,
            index_start=index_start,
            index_end=index_end,
            web_port=web_port,
            keep_web_open=False,
            pre_send_callbacks=[self.session_pre_send],
            restart_threshold=self.restart_threshold,
            ignore_connection_reset=True,
            ignore_connection_aborted=True,
            sleep_time=self.sleep_time,
            fuzz_db_keep_only_n_pass_cases=1000,
            reuse_target_connection=True,
            receive_data_after_each_request=False,
            check_data_received_each_request=False,
        )
        self.session.add_target(self.target)

    def _init_protocol_structure(self):
        self.request = build_request(self.request_name, self.connection.state,
                                     group=self.group, service=self.service,
                                     raw_body=self.raw_body)

    def init(self):
        self._init_target_connection()
        self._init_session()
        self._init_protocol_structure()

    # ------------------------------------------------------------
    # callbacks
    # ------------------------------------------------------------
    def session_pre_send(self, target, fuzz_data_logger, session, sock=None,
                         **kwargs):
        """Refresh the values that only the live connection knows.

        Runs before the request is rendered (so the injected default is what gets
        rendered) and after the session is known good — the ordering
        ``_pre_send`` guarantees.  With a reused connection boofuzz does not call
        ``open()`` per case, so this is also where a session broken by the
        previous case gets re-established.

        Only the session id needs injecting.  The channel id, the channel token,
        the block counters, the datagram endpoints and both framing lengths are
        all stamped in by ``FrameEncoder`` at render time, straight from the live
        connection state.
        """
        self.connection.ensure_open()
        state = self.connection.state
        if _s_update("session_id", struct.pack("<I", state.session_id),
                     request=self.request) != 1:
            raise RuntimeError(
                "request %r has no unique 'session_id' field — the packet would "
                "go out with placeholder bytes" % self.request_name)

    def pre_actions(self):
        return True

    def post_actions(self, target, fuzz_data_logger, session, sock=None,
                     **kwargs):
        return True

    def start_actions(self):
        return True

    # ------------------------------------------------------------
    # run
    # ------------------------------------------------------------
    def fuzz(self):
        from boofuzz import s_get
        self.session.connect(s_get(self.request_name))

        # Handshake here rather than leaving it to session.fuzz().  boofuzz's
        # _main_fuzz_loop catches BoofuzzTargetConnectionFailedError with a bare
        # `pass`, so an initial handshake failure — a runtime that is wedged, or
        # a wrong port — is reported as "0 cases run, no crash detected, exit 0",
        # which reads like a clean run of a target with nothing to fuzz.  Opening
        # here puts the exception where it can be reported.  CodesysConnection's
        # open() is idempotent, so boofuzz's own open() is then a no-op rather
        # than a second handshake.
        self.connection.open()
        self.session.fuzz()


__all__ = ["Fuzzer", "request_names"]
