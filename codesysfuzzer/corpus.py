#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Seed corpus for data-driven fuzzing.

What a seed is
--------------
One **body** — the services-layer tag stream of a request that the runtime is
known to have accepted, or at least answered.  Not the block-driver/datagram/
channel framing, and not the session id: those are live connection state and are
stamped in by ``FrameEncoder`` and ``pre_send`` at render time.  Storing a whole
frame would only capture one TCP session's counters and a session id that is
dead by the next run.

Where seeds come from
---------------------
* ``--save-seed DIR`` on a ``--dry-run`` render: any model's unmutated body is a
  real, accepted request, so no capture is needed to start.
* ``--capture-seeds DIR``: bodies of cases the runtime accepted during a run.
* ``tools/extract_seeds.py``: bodies pulled out of a pcap/pcapng.
* Hand-written JSON/JSONL, or ``<group>_<service>_<name>.bin`` raw bodies.

File format
-----------
JSON or JSONL, one object per seed::

    {"group": "0x000f", "service": "0x0002",
     "body": "108c80004170702e...",       // hex, spaces allowed
     "source": "trace2.pcapng#1564", "verdict": "accepted"}

``sha1`` is derived, never trusted from the file.  The key is
``sha1(group || service || body)``, so the same body for two different pairs is
two seeds and the same body twice is one.
"""

import hashlib
import json
import os
import struct


class Seed(object):
    """One real request body plus the pair it was captured for."""

    __slots__ = ("group", "service", "body", "source", "verdict", "sha1")

    def __init__(self, group, service, body, source="", verdict=None):
        if not isinstance(body, (bytes, bytearray)):
            raise TypeError("seed body must be bytes, got %s"
                            % type(body).__name__)
        self.group = int(group)
        self.service = int(service)
        self.body = bytes(body)
        self.source = source or ""
        self.verdict = verdict
        self.sha1 = hashlib.sha1(
            struct.pack("<HH", self.group & 0xFFFF, self.service & 0xFFFF)
            + self.body).hexdigest()

    @property
    def pair(self):
        return (self.group, self.service)

    def to_dict(self):
        return {"group": "0x%04x" % self.group,
                "service": "0x%04x" % self.service,
                "body": self.body.hex(),
                "source": self.source,
                "verdict": self.verdict,
                "sha1": self.sha1}

    def __repr__(self):
        return "<Seed 0x%04x/0x%04x %dB %s>" % (
            self.group, self.service, len(self.body), self.sha1[:12])


def _as_int(value, what):
    """Accept 15, "15", "0x0f", or a bare hex string like a surface file."""
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    if text.startswith("0x"):
        return int(text, 16)
    try:
        return int(text, 0)
    except ValueError:
        return int(text, 16)


def _as_body(value):
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return bytes.fromhex(value.replace(" ", "").replace(":", ""))
    raise TypeError("seed body must be hex text or bytes")


def from_dict(row):
    """One seed object -> :class:`Seed`.  Raises on a malformed row."""
    body = row.get("body", row.get("body_hex"))
    if body is None:
        raise ValueError("seed row has no body/body_hex")
    return Seed(_as_int(row["group"], "group"),
                _as_int(row["service"], "service"),
                _as_body(body),
                source=row.get("source", ""),
                verdict=row.get("verdict"))


def write_seed(dirpath, group, service, body, source="", verdict=None):
    """Write one seed as ``<group>_<service>_<sha1>.json``.

    Returns the path written, or ``None`` when the identical seed is already
    there.  Deduplicating on the content hash is what makes it safe to call this
    from every accepted case of a long run.
    """
    seed = Seed(group, service, body, source=source, verdict=verdict)
    os.makedirs(dirpath, exist_ok=True)
    path = os.path.join(
        dirpath, "%04x_%04x_%s.json"
        % (seed.group, seed.service, seed.sha1[:16]))
    if os.path.exists(path):
        return None
    # Write a sibling and replace, the same rule the run state uses: a capture
    # interrupted mid-write must not leave a half JSON file that makes the whole
    # corpus unreadable.
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(seed.to_dict(), fh, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


# ============================================================
# Loading
# ============================================================

def _iter_json(path):
    with open(path, encoding="utf-8") as fh:
        text = fh.read().strip()
    if not text:
        return
    data = json.loads(text)
    if isinstance(data, list):
        for row in data:
            yield row
    elif isinstance(data, dict):
        # a corpus object ("seeds": [...]) is convenient to hand-edit
        for row in data.get("seeds", [data]):
            yield row
    else:
        raise ValueError("%s: expected a seed object or a list of them" % path)


def _iter_jsonl(path):
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if isinstance(row, list):
                for item in row:
                    yield item
            else:
                yield row


def _bin_meta(path):
    """Metadata for a raw ``.bin`` body.

    Either a sibling ``.json`` with ``group``/``service``, or a filename
    starting ``<group>_<service>_``.  Both are hex.
    """
    sidecar = os.path.splitext(path)[0] + ".json"
    if os.path.exists(sidecar):
        with open(sidecar, encoding="utf-8") as fh:
            return json.load(fh)
    parts = os.path.basename(path).split("_")
    if len(parts) >= 2:
        try:
            return {"group": parts[0], "service": parts[1]}
        except ValueError:
            pass
    raise ValueError(
        "%s: cannot tell which pair this body belongs to; name it "
        "<group>_<service>_<name>.bin or add a %s sidecar"
        % (path, os.path.basename(sidecar)))


def _iter_file(path):
    lower = path.lower()
    if lower.endswith(".jsonl") or lower.endswith(".ndjson"):
        for row in _iter_jsonl(path):
            yield row
    elif lower.endswith(".json"):
        for row in _iter_json(path):
            yield row
    elif lower.endswith(".bin"):
        with open(path, "rb") as fh:
            body = fh.read()
        meta = _bin_meta(path)
        row = dict(meta)
        row["body"] = body
        row.setdefault("source", path)
        yield row
    # anything else is ignored: a log directory holds databases and state too


def _iter_entries(path):
    if os.path.isdir(path):
        for name in sorted(os.listdir(path)):
            full = os.path.join(path, name)
            try:
                if os.path.isdir(full):
                    # ``--capture-seeds DIR`` writes to DIR/candidates.  Those
                    # are deliberately *not* part of the active corpus: folding
                    # them in on the next load would change the digest and make
                    # every interrupted run unresumable.  Pass the subdirectory
                    # explicitly to import them.
                    if os.path.basename(full) == "candidates":
                        continue
                    for row in _iter_entries(full):
                        yield row
                elif os.path.isfile(full):
                    for row in _iter_file(full):
                        yield row
            except (OSError, ValueError):
                # one unreadable file in a directory of artefacts is not a
                # reason to abandon the seeds that did load
                continue
    else:
        for row in _iter_file(path):
            yield row


class Corpus(object):
    """A deduplicated, deterministically ordered set of seeds.

    The order is ``(group, service, sha1)``, not file order.  A run's case index
    is meaningful only against a stable corpus, so the order must not depend on
    which directory entry the filesystem happened to return first.
    """

    def __init__(self, seeds):
        by_sha = {}
        for seed in seeds:
            by_sha.setdefault(seed.sha1, seed)
        self.seeds = sorted(by_sha.values(),
                            key=lambda s: (s.group, s.service, s.sha1))

    @classmethod
    def load(cls, path):
        seeds = []
        for row in _iter_entries(path):
            try:
                seeds.append(from_dict(row))
            except (KeyError, TypeError, ValueError):
                # A directory may also hold surface files, run state, crash
                # reports and sqlite databases.  Rows that are not seeds are
                # skipped, so pointing --from-seeds at logs/ does not explode
                # on the first unrelated JSON object.
                continue
        return cls(seeds)

    def __len__(self):
        return len(self.seeds)

    def __iter__(self):
        return iter(self.seeds)

    def manifest(self):
        """One line per seed — the identity of this exact corpus."""
        return ["0x%04x:0x%04x:%s" % (s.group, s.service, s.sha1)
                for s in self.seeds]

    def digest(self):
        return hashlib.sha1(
            "\n".join(self.manifest()).encode("utf-8")).hexdigest()

    def pairs(self):
        return sorted({s.pair for s in self.seeds})

    def by_pair(self):
        out = {}
        for seed in self.seeds:
            out.setdefault(seed.pair, []).append(seed)
        return out

    def select(self, group=None, service=None):
        """The subset for one pair (or for whatever the filters name)."""
        return [s for s in self.seeds
                if (group is None or s.group == group)
                and (service is None or s.service == service)]

    def describe(self):
        pairs = self.by_pair()
        return ("%d seed(s) for %d pair(s): %s"
                % (len(self.seeds), len(pairs),
                   ", ".join("0x%02x/0x%04x" % p for p in sorted(pairs))))
