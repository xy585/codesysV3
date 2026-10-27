#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Run state, so an interrupted run resumes instead of starting over.

What this is not
----------------
Not boofuzz's ``session_filename``.  That is a zlib+pickle blob written by
``export_file`` after every test case and read back by ``import_file``, which
sets ``_index_start`` to whatever it finds — and because it is opaque, pointing
it at the wrong path silently turns a run into "0 cases, no error".  That cost a
debugging session earlier; see the Readme.  This is a small readable JSON file
whose meaning is explicit, and which is only ever consulted when ``--resume``
says to.

What is recorded, and why each field is there
---------------------------------------------
``request``/``group``/``service``/``raw_body``
    the shape being fuzzed.  A mutant index only means something against the
    same model, so resuming with a different one is refused rather than silently
    resuming into the middle of an unrelated enumeration.
``seed``
    the run's random seed.  Without it a resumed run sends different payloads
    from the original past the resume point, which defeats resuming.
``index_start``/``index_end``/last_case/cases_run
    the position.  ``last_case`` is boofuzz's ``total_mutant_index``, which is
    the same numbering ``--cases`` and ``--case`` speak.
``depth1_cases``
    how many single-field test cases boofuzz has for this request.  The run
    itself keeps going into multi-field combinations, so this is the one
    finite, meaningful count the state file can carry: indices 1..N are depth
    1, and everything past N mutates two or more fields at once.
``mode``/``corpus_digest``/``corpus_manifest``/``mutation_mode``/
``mutations_per_seed``/``max_body_size``/``seed_order``/``corpus_path``
    seed-mode identity.  A data-driven case index is ``(seed, local mutation)``
    under a fixed corpus order and a fixed per-seed budget, so resuming against
    a different corpus, budget or seed order would send a different packet while
    claiming to continue the same run.  The recorded values are used on resume
    and the corpus digest is checked.  ``corpus_path`` is what lets ``--resume``
    find the same corpus without the operator having to remember it.
"""

import json
import os
import tempfile
import time

VERSION = 2


class RunState(object):

    def __init__(self, path=None, **fields):
        self.path = path
        self.version = VERSION
        self.request = None
        self.group = None
        self.service = None
        self.raw_body = False
        self.mode = "model"          # "model" (grammar) or "seed" (data-driven)
        self.seed = None
        self.index_start = 1
        self.index_end = None
        self.depth1_cases = None
        self.last_case = 0
        self.cases_run = 0
        self.started = time.strftime("%Y-%m-%dT%H:%M:%S")
        self.updated = self.started
        self.db_file = None
        self.surface_file = None
        #: seed-mode only: which corpus and mutation schedule this index means.
        #: A case index is only reproducible against the same corpus, so a
        #: resume with a changed corpus is refused rather than silently
        #: continuing into a different mutation.
        self.corpus_digest = None
        self.corpus_manifest = None
        self.corpus_path = None
        self.mutation_mode = None
        self.mutations_per_seed = None
        #: body ceiling: a tag mutation that would exceed it falls back to
        #: havoc, so the value changes which mutation a given case index names.
        self.max_body_size = None
        #: seed-mode only: how cases are allocated across a pair's seeds.
        #: Part of what an index means, so a resume must not silently change it.
        self.seed_order = None
        for k, v in fields.items():
            if hasattr(self, k):
                setattr(self, k, v)

    # ------------------------------------------------------------
    def as_dict(self):
        return {k: getattr(self, k) for k in (
            "version", "request", "group", "service", "raw_body", "mode",
            "seed", "index_start", "index_end", "depth1_cases", "last_case",
            "cases_run", "started", "updated", "db_file", "surface_file",
            "corpus_digest", "corpus_manifest", "corpus_path", "mutation_mode",
            "mutations_per_seed", "max_body_size", "seed_order")}

    @classmethod
    def load(cls, path):
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        st = cls(path=path)
        for k, v in data.items():
            if hasattr(st, k):
                setattr(st, k, v)
        # Version 1 predates seed mode.  It is safe to read: every v1 field has
        # the same meaning, and a model run is exactly mode="model".  Writing it
        # back upgrades the file to v2.
        if st.version not in (1, VERSION):
            raise ValueError("run state %s is version %r, this build writes %r"
                             % (path, st.version, VERSION))
        if st.version == 1:
            st.mode = "model"
            st.version = VERSION
        return st

    def save(self):
        """Write atomically.

        A state file truncated by an interrupt is worse than none: it would
        resume from a half-written index.  So write a sibling and replace.
        """
        if not self.path:
            return
        self.updated = time.strftime("%Y-%m-%dT%H:%M:%S")
        d = os.path.dirname(self.path)
        if d:
            os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d or ".", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self.as_dict(), fh, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    # ------------------------------------------------------------
    def describe(self):
        return ("%s mode=%s group=%s service=%s raw_body=%s seed=%s depth1=%s "
                "case %s/%s (%s run)"
                % (self.request, self.mode, self.group, self.service,
                   self.raw_body, self.seed, self.depth1_cases, self.last_case,
                   self.index_end, self.cases_run))

    def conflicts_with(self, request, group, service, raw_body, mode=None,
                       corpus_digest=None):
        """Whether the CLI asks for something other than what was recorded."""
        for name, recorded, asked in (("request", self.request, request),
                                      ("group", self.group, group),
                                      ("service", self.service, service),
                                      ("raw_body", self.raw_body, raw_body),
                                      ("mode", self.mode, mode)):
            if asked is not None and asked != recorded:
                return ("%s: state has %r, this command asks for %r"
                        % (name, recorded, asked))
        # A seed-mode case index is (seed, local mutation) under a fixed corpus
        # order.  A different corpus means index N is a different packet.
        if (corpus_digest is not None and self.corpus_digest is not None
                and corpus_digest != self.corpus_digest):
            return ("corpus: state has %s, this command loads %s"
                    % (self.corpus_digest[:12], corpus_digest[:12]))
        return None

    def resume_index(self):
        """The first case that has *not* run, or None if the run is finished."""
        nxt = (self.last_case or 0) + 1
        if self.index_end is not None and nxt > self.index_end:
            return None
        return nxt
