"""Hashing, canonical JSON, and the tamper-evident hash chain.

Two places need to be tamper-evident: the SQLite event store (an adversary who
gets root should not be able to quietly delete the row that incriminates them)
and the evidence bundle manifest (a bundle handed to someone else should be
verifiable without trusting the host it came from).

Both use the same construction::

    chain_hash[n] = sha256(chain_hash[n-1] || canonical_json(record[n]))

with a genesis hash derived from the host identity and an install-time nonce.
See docs/SAFETY.md for an honest statement of what this does and does not
defend against.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid

GENESIS_PREFIX = "macsiem/v1/genesis"
CHUNK = 1024 * 1024


def canonical_json(record) -> bytes:
    """Deterministic JSON bytes: sorted keys, no incidental whitespace.

    Canonicalization is what makes the chain reproducible on a different
    machine, so this must never be "prettified".
    """
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8", "replace"))


def sha256_file(path, chunk=CHUNK) -> str:
    """Stream a file through sha256 -- evidence artifacts can be large."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(chunk)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def genesis(host_id: str, nonce: str = "") -> str:
    """First link of a chain.  Bound to the host so chains are not splicable."""
    return sha256_text("%s|%s|%s" % (GENESIS_PREFIX, host_id, nonce or ""))


def chain_next(previous: str, record) -> str:
    """Compute the next chain hash from the previous one and a record."""
    digest = hashlib.sha256()
    digest.update((previous or "").encode("ascii"))
    digest.update(b"|")
    digest.update(canonical_json(record))
    return digest.hexdigest()


def verify_chain(rows, record_key="record", hash_key="chain_hash", genesis_hash=None):
    """Walk a sequence of chained rows.

    Returns ``(ok, index, detail)``.  ``index`` is the position of the first
    divergence, or ``-1`` when the chain is intact.  A chain is broken by
    mutation *and* by deletion -- both show up as the same divergence, which is
    the point.
    """
    previous = genesis_hash
    for index, row in enumerate(rows):
        record = row[record_key] if isinstance(row, dict) else getattr(row, record_key)
        stored = row[hash_key] if isinstance(row, dict) else getattr(row, hash_key)
        if previous is None:  # Chain start not pinned: adopt and keep walking.
            previous = stored
            continue
        expected = chain_next(previous, record)
        if expected != stored:
            return False, index, "expected %s, stored %s" % (expected[:16], stored[:16])
        previous = stored
    return True, -1, "chain intact (%d records)" % len(rows)


def new_id(prefix: str = "") -> str:
    """Chronologically sortable identifier: ``<epoch_ms>-<8 hex>``."""
    import time

    stamp = int(time.time() * 1000)
    suffix = uuid.uuid4().hex[:8]
    core = "%013d-%s" % (stamp, suffix)
    return "%s-%s" % (prefix, core) if prefix else core


def host_identity() -> dict:
    """Stable-ish host identity used to bind chains and label bundles.

    Falls back cleanly off macOS so the test suite and offline selftest work.
    """
    info = {
        "hostname": os.uname().nodename,
        "platform": os.uname().sysname,
        "release": os.uname().release,
        "machine": os.uname().machine,
    }
    info["host_uuid"] = _hardware_uuid() or sha256_text(info["hostname"])[:36]
    return info


def _hardware_uuid():
    """Read the IOPlatformUUID without importing the process layer.

    Kept dependency-free on purpose: hashing is imported by the safety tests,
    which must not drag in anything that can spawn a process.
    """
    for path in ("/var/db/macsiem/host_uuid", "/etc/machine-id"):
        try:
            with open(path, "r") as handle:
                value = handle.read().strip()
                if value:
                    return value
        except OSError:
            continue
    return None
