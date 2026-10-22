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

import json
import os
import struct

from boofuzz import FuzzLoggerText, Session, Target

from monitor import CodesysMonitor
from services import build_request, request_names
from transport import CodesysConnection
from utils import _s_update


class NoPayloadLogger(FuzzLoggerText):
    """``FuzzLoggerText`` that logs how big a payload was, not what it was.

    Subclassed rather than configured because boofuzz's ``bytes_to_str``
    parameter is dead in 0.4.2: ``_print_log_msg`` calls
    ``helpers.format_log_msg`` without passing it, so the value is stored on the
    logger and never used.  Overriding the two methods that carry payload is the
    honest way to get the behaviour the parameter advertises.

    The line is kept so a run trace is still readable — it says a request went
    out and how big it was — while the bytes themselves are not written anywhere
    except the crash report, where they are actually needed.
    """

    @staticmethod
    def _summary(data):
        try:
            return "%d bytes, not logged (see the crash report)" % len(data)
        except TypeError:
            return "payload not logged"

    def log_send(self, data):
        self._print_log_msg(msg=self._summary(data), msg_type="info")

    def log_recv(self, data):
        self._print_log_msg(msg=self._summary(data), msg_type="info")


class BlockRecorder(object):
    """Write selected blocks of the requests boofuzz actually renders.

    Hooked onto ``Request.render`` rather than the pre-send callback, because
    that callback runs *before* rendering: it can inject live values but cannot
    see the mutated bytes.  ``Session.transmit_fuzz`` renders the request and
    hands exactly that byte string to ``Target.send``, so the top-level render
    is the last point where "what was sent" (before framing is undone by the
    connection) is observable.

    A block is re-rendered from the same ``MutationContext``.  Every renderer
    here is pure -- ``FrameEncoder`` deliberately advances no counters, and
    mutations are already materialised values -- so the re-render is the exact
    byte string that was framed and sent, not a second, different draw.
    """

    def __init__(self, request, request_name, block_names, path, seed=None):
        self.request = request
        self.request_name = request_name
        self.path = path
        self.seed = seed
        self.targets = [self._resolve(wanted) for wanted in block_names]

    def _resolve(self, wanted):
        """Map a CLI name to a qualified name in ``request.names``.

        Accepts either the full qualified name or a unique trailing component
        (``body``, ``t13``, ``t13_data``).  Ambiguity is an error rather than a
        guess: silently recording the wrong block would produce a file that
        looks right and is useless for replay.
        """
        names = self.request.names
        if wanted in names:
            if names[wanted] is self.request:
                raise KeyError("cannot record the request itself (%r): "
                               "recording it would re-enter the render hook"
                               % wanted)
            return wanted
        matches = [n for n, node in names.items()
                   if node is not self.request
                   and n.rsplit(".", 1)[-1] == wanted]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise KeyError(
                "no block or element named %r in request %r (have: %s)"
                % (wanted, self.request_name,
                   ", ".join(sorted(n.rsplit(".", 1)[-1] for n in names))))
        raise KeyError("block name %r is ambiguous in request %r: %s"
                       % (wanted, self.request_name,
                          ", ".join(sorted(matches))))

    def record(self, mutation_context, case_index):
        if mutation_context is None:
            return
        entry = {"case": case_index,
                 "request": self.request_name,
                 "seed": self.seed,
                 "mutations": sorted(mutation_context.mutations),
                 "blocks": {}}
        for qualified in self.targets:
            data = self.request.names[qualified].render(
                mutation_context=mutation_context)
            entry["blocks"][qualified] = {"length": len(data), "hex": data.hex()}

        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        # Append per case: a crash leaves every request up to the crash on
        # disk, which is the point of the option.
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, separators=(",", ":")) + "\n")


class Fuzzer(object):

    def __init__(self, target_ip, target_port, request_name,
                 user="test", password="test", app_name="App",
                 timeout=5.0, probe_every=1, probe=True, verbose=False,
                 sleep_time=0.0, restart_threshold=1,
                 group=None, service=None, raw_body=False, surface_path=None,
                 surface_mode="global", state=None, state_every=25, seed_tags=None,
                 crash_dir=None, seed=None, db_path=None,
                 log_payloads=False, record_blocks=None, record_path=None,
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
        self.seed_tags = seed_tags
        self.seed = seed
        self.db_path = db_path
        self.crash_dir = crash_dir
        self.log_payloads = log_payloads
        self.record_blocks = record_blocks or []
        self.record_path = record_path
        self.recorder = None
        self.state = state
        self.state_every = max(1, state_every)
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
                                      crash_dir=self.crash_dir,
                                      request_name=self.request_name,
                                      target=self.target_ip,
                                      seed=self.seed,
                                      db_path=self.db_path,
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
        # Payloads are NOT logged by default.  boofuzz's text logger prints the
        # full hex of every transmitted request, and the sqlite database stores
        # the first 512 bytes of each; over a long run that is a copy of the
        # entire corpus, which nothing here needs.  What needs to be kept is the
        # one request that caused a crash, and that is written by the monitor
        # when it happens.  --log-payloads restores the full hex for debugging.
        loggers = None
        if not self.log_payloads:
            loggers = [NoPayloadLogger()]

        self.session = Session(
            fuzz_loggers=loggers,
            db_filename=db_filename,
            index_start=index_start,
            index_end=index_end,
            web_port=web_port,
            keep_web_open=False,
            pre_send_callbacks=[self.session_pre_send],
            post_test_case_callbacks=[self.session_post_test_case],
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

        # the sqlite logger keeps the first 512 bytes of every send and receive
        # by default, which over a run is the whole corpus; zeroing the limit
        # leaves the case/pass/fail record, which is what the database is for
        if not self.log_payloads:
            db_logger = getattr(self.session, "_db_logger", None)
            if db_logger is not None and hasattr(db_logger,
                                                 "_data_truncate_length"):
                db_logger._data_truncate_length = 0

    def _init_protocol_structure(self):
        self.request = build_request(self.request_name, self.connection.state,
                                     group=self.group, service=self.service,
                                     raw_body=self.raw_body,
                                     seed_tags=self.seed_tags)
        self._install_block_recorder()

    def _install_block_recorder(self):
        """Wrap ``Request.render`` so selected blocks are written per case.

        ``self.session`` does not exist yet when the request is built (the
        session needs the db path, which the CLI picks later), so the wrapper
        checks for it at call time.  That also keeps ``--dry-run`` from writing
        a line for its one unmutated render.
        """
        if not self.record_blocks:
            return
        if not self.record_path:
            raise ValueError("--record-block needs a file to write to")
        self.recorder = BlockRecorder(self.request, self.request_name,
                                      self.record_blocks, self.record_path,
                                      seed=self.seed)
        render = self.request.render

        def render_and_record(mutation_context=None):
            data = render(mutation_context=mutation_context)
            if self.session is not None:
                self.recorder.record(
                    mutation_context,
                    getattr(self.session, "total_mutant_index", None))
            return data

        self.request.render = render_and_record

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

    def session_post_test_case(self, target, fuzz_data_logger, session,
                               sock=None, **kwargs):
        """Record progress so an interrupted run can resume.

        boofuzz's ``total_mutant_index`` is the same numbering ``--cases`` and
        ``--case`` use, so it is what gets written.  Saving every case would
        dominate the cost of a fast model, hence the interval; the state is also
        written once when the run ends, in ``fuzz`` and in the CLI's error paths.
        """
        if self.state is None:
            return
        self.state.cases_run += 1
        self.state.last_case = getattr(session, "total_mutant_index",
                                       self.state.last_case)
        if self.state.cases_run % self.state_every == 0:
            self.state.save()

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
        try:
            self.session.fuzz()
        finally:
            if self.state is not None:
                self.state.save()


__all__ = ["Fuzzer", "request_names"]
