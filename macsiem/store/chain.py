"""Append-only hash chaining for the SQLite store.

Each chained table carries ``seq``, ``chain_hash`` and the canonical record the
hash was computed over.  Appending is serialized by a lock so two sensor threads
cannot interleave and fork the chain.
"""

from __future__ import annotations

import threading

from ..util import hashing


class ChainWriter:
    """Maintains the tip of one chain and produces the next link."""

    def __init__(self, genesis_hash, tip=None, seq=0):
        self.genesis = genesis_hash
        self.tip = tip or genesis_hash
        self.seq = seq
        self._lock = threading.Lock()

    def append(self, record):
        """Return ``(seq, chain_hash, canonical_record_json)`` for a record."""
        with self._lock:
            self.seq += 1
            self.tip = hashing.chain_next(self.tip, record)
            return self.seq, self.tip, hashing.canonical_json(record).decode("utf-8")

    def snapshot(self):
        return {"genesis": self.genesis, "tip": self.tip, "seq": self.seq}


def verify_rows(rows, genesis_hash):
    """Verify ``[{seq, record, chain_hash}, ...]`` ordered by seq.

    Detects mutation *and* deletion: a missing row shifts every subsequent hash,
    and a gap in ``seq`` is reported even if the remaining links are consistent
    among themselves.
    """
    previous = genesis_hash
    expected_seq = 0
    for index, row in enumerate(rows):
        expected_seq += 1
        if row.get("seq") != expected_seq:
            return False, index, "sequence gap: expected seq %d, found %s" % (
                expected_seq, row.get("seq"))
        expected_hash = hashing.chain_next(previous, row["record"])
        if expected_hash != row["chain_hash"]:
            return False, index, "hash mismatch at seq %s (record altered)" % row.get("seq")
        previous = row["chain_hash"]
    return True, -1, "chain intact (%d records)" % len(rows)
