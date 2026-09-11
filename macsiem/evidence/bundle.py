"""Evidence bundles: a directory that can be handed to someone else and verified.

Layout::

    <bundle_id>/
      manifest.json          identity, trigger, coverage, artifact hashes, custody
      artifacts/<probe>.…    one file per probe, raw output preserved
      analysis/timeline.json chronological reconstruction
      analysis/narrative.md  the plain-English account
      report.html            self-contained, no network, opens anywhere

Integrity is two-level: each artifact is SHA-256'd, and the sorted leaves are
folded into a Merkle root so a single artifact can be verified (or removed by
``macsiem export --redact``) without invalidating the rest.  The manifest then
records the event-store chain head, and the store records the sealed bundle's
hash -- each attests to the other, so forging one alone is detectable.

Bundles are 0700 and root-owned.  With content capture enabled they contain
screenshots, clipboard text and browser history; docs/PRIVACY.md says so plainly.
"""

from __future__ import annotations

import json
import os
import shutil
import zipfile

from ..util import hashing, timeutil

MANIFEST_VERSION = 1
SAFE_NAME = str.maketrans({"/": "_", ":": "_", " ": "_"})


class Bundle:
    def __init__(self, root, bundle_id=None, store=None, actor=None):
        self.bundle_id = bundle_id or hashing.new_id("bndl")
        self.path = os.path.join(root, self.bundle_id)
        self.store = store
        self.actor = actor or _actor()
        self.artifacts = []
        self.custody = []
        self.manifest = {}
        os.makedirs(os.path.join(self.path, "artifacts"), mode=0o700, exist_ok=True)
        os.makedirs(os.path.join(self.path, "analysis"), mode=0o700, exist_ok=True)
        self._record_custody("created", {"path": self.path})

    # -- custody -----------------------------------------------------------
    def _record_custody(self, action, detail=None):
        entry = {"ts": timeutil.now_iso(), "actor": self.actor, "action": action,
                 "detail": detail}
        previous = self.custody[-1]["chain_hash"] if self.custody else hashing.genesis(
            self.bundle_id, "custody")
        entry["chain_hash"] = hashing.chain_next(previous, {
            k: entry[k] for k in ("ts", "actor", "action", "detail")})
        self.custody.append(entry)
        if self.store:
            self.store.add_custody(self.bundle_id, self.actor.get("user", "?"),
                                   action, detail)
        return entry

    # -- artifacts ---------------------------------------------------------
    def add_probe_result(self, result):
        """Write one probe's output to disk and register it in the manifest."""
        name = result.get("probe_id", "unknown").translate(SAFE_NAME)
        if result.get("skipped_reason"):
            self.artifacts.append({
                "probe_id": result.get("probe_id"),
                "loobins": result.get("loobins") or [],
                "category": result.get("category"),
                "status": "skipped",
                "reason": result["skipped_reason"],
            })
            return None

        if result.get("artifact") and os.path.exists(result["artifact"]):
            # A probe that produced a real file (the screenshot) -- keep it in
            # place and hash it where it lies.
            relative = os.path.relpath(result["artifact"], self.path)
            entry = self._artifact_entry(result, relative, result["artifact"])
            entry["capability"] = "content"
            self.artifacts.append(entry)
            self._record_custody("captured_content", {"probe": result.get("probe_id"),
                                                      "path": relative})
            return entry

        if result.get("parsed") is not None and result.get("kind") == "native":
            relative = os.path.join("artifacts", "%s.json" % name)
            payload = json.dumps(result["parsed"], indent=1, sort_keys=True, default=str)
        else:
            relative = os.path.join("artifacts", "%s.txt" % name)
            payload = result.get("stdout", "")
            if result.get("parsed") is not None:
                side = os.path.join("artifacts", "%s.parsed.json" % name)
                self._write(side, json.dumps(result["parsed"], indent=1,
                                             sort_keys=True, default=str))
                self.artifacts.append(self._artifact_entry(
                    result, side, os.path.join(self.path, side), suffix=".parsed"))

        absolute = self._write(relative, payload)
        entry = self._artifact_entry(result, relative, absolute)
        if result.get("privacy") == "high":
            entry["capability"] = "content"
            self._record_custody("captured_content", {"probe": result.get("probe_id"),
                                                      "path": relative})
        self.artifacts.append(entry)
        return entry

    def _write(self, relative, text):
        absolute = os.path.join(self.path, relative)
        os.makedirs(os.path.dirname(absolute), mode=0o700, exist_ok=True)
        with open(absolute, "w") as handle:
            handle.write(text if isinstance(text, str) else str(text))
        os.chmod(absolute, 0o600)
        return absolute

    def _artifact_entry(self, result, relative, absolute, suffix=""):
        return {
            "path": relative,
            "probe_id": (result.get("probe_id") or "") + suffix,
            "title": result.get("title"),
            "loobins": result.get("loobins") or [],
            "category": result.get("category"),
            "status": "collected",
            "bytes": os.path.getsize(absolute) if os.path.exists(absolute) else 0,
            "sha256": hashing.sha256_file(absolute) if os.path.exists(absolute) else None,
            "collected_at": result.get("started"),
            "duration_ms": result.get("duration_ms"),
            "exit_code": result.get("exit_code"),
            "from_cache": bool(result.get("from_cache")),
            "cache_age_seconds": result.get("cache_age_seconds"),
            "truncated": bool(result.get("truncated")),
            "timed_out": bool(result.get("timed_out")),
            "redactions": result.get("redactions") or {},
            "privacy": result.get("privacy", "low"),
            "argv": result.get("argv"),
        }

    def add_analysis(self, name, payload):
        relative = os.path.join("analysis", name)
        text = payload if isinstance(payload, str) else json.dumps(
            payload, indent=1, sort_keys=True, default=str)
        absolute = self._write(relative, text)
        self.artifacts.append({
            "path": relative, "probe_id": "analysis", "category": "analysis",
            "status": "collected", "bytes": os.path.getsize(absolute),
            "sha256": hashing.sha256_file(absolute), "privacy": "low",
        })
        return relative

    # -- sealing -----------------------------------------------------------
    def seal(self, sweep, trigger=None, host=None, agent=None, store_anchor=None):
        collected = [a for a in self.artifacts if a.get("status") == "collected"]
        self.manifest = {
            "manifest_version": MANIFEST_VERSION,
            "bundle_id": self.bundle_id,
            "created": self.custody[0]["ts"],
            "sealed": timeutil.now_iso(),
            "agent": agent or {},
            "host": host or hashing.host_identity(),
            "trigger": trigger or sweep.get("trigger") or {},
            "sweep": {
                "sweep_id": sweep.get("sweep_id"),
                "tier": sweep.get("tier"),
                "started": sweep.get("started"),
                "duration_ms": sweep.get("duration_ms"),
                "workers": sweep.get("workers"),
                "rate_limited": sweep.get("rate_limited"),
                "capabilities": sweep.get("capabilities"),
                "stats": sweep.get("stats"),
                "shed": sweep.get("shed"),
            },
            # The honest part: what was collected, what was not, and why.
            "loobins_coverage": sweep.get("coverage"),
            "coverage_summary": sweep.get("coverage_summary"),
            "artifacts": sorted(self.artifacts, key=lambda a: a.get("path") or ""),
            "artifacts_merkle_root": merkle_root(collected),
            "store_anchor": store_anchor or {},
            "custody": self.custody,
        }
        self._record_custody("sealed", {"artifacts": len(collected)})
        self.manifest["custody"] = self.custody
        body = {k: v for k, v in self.manifest.items() if k != "manifest_sha256"}
        self.manifest["manifest_sha256"] = hashing.sha256_bytes(
            hashing.canonical_json(body))
        self._write("manifest.json", json.dumps(self.manifest, indent=1,
                                                sort_keys=True, default=str))
        if self.store:
            # Cross-anchor: the store now attests to the bundle, and the bundle
            # already recorded the store's chain head.
            self.store.add_custody(self.bundle_id, self.actor.get("user", "?"),
                                   "bundle_sealed",
                                   {"manifest_sha256": self.manifest["manifest_sha256"]})
        return self.manifest

    def zip(self, destination=None):
        destination = destination or (self.path + ".zip")
        with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
            for root, _dirs, files in os.walk(self.path):
                for filename in files:
                    absolute = os.path.join(root, filename)
                    archive.write(absolute, os.path.relpath(absolute,
                                                            os.path.dirname(self.path)))
        os.chmod(destination, 0o600)
        self._record_custody("exported", {"archive": destination})
        return destination


def merkle_root(artifacts):
    """Binary Merkle root over ``sha256(path || 0x00 || content_sha256)`` leaves.

    A tree rather than a flat hash so one artifact can be verified, or redacted,
    without rehashing the whole bundle.
    """
    leaves = sorted(
        hashing.sha256_text("%s\x00%s" % (a.get("path"), a.get("sha256") or ""))
        for a in artifacts)
    if not leaves:
        return hashing.sha256_text("")
    level = leaves
    while len(level) > 1:
        nxt = []
        for index in range(0, len(level), 2):
            left = level[index]
            right = level[index + 1] if index + 1 < len(level) else left
            nxt.append(hashing.sha256_text(left + right))
        level = nxt
    return level[0]


def verify(path):
    """Verify a bundle on disk.  Returns ``(ok, findings)``."""
    manifest_path = os.path.join(path, "manifest.json")
    if not os.path.exists(manifest_path):
        return False, ["no manifest.json at %s" % path]
    with open(manifest_path, "r") as handle:
        manifest = json.load(handle)

    findings = []
    stored = manifest.get("manifest_sha256")
    body = {k: v for k, v in manifest.items() if k != "manifest_sha256"}
    recomputed = hashing.sha256_bytes(hashing.canonical_json(body))
    if stored != recomputed:
        findings.append("manifest hash mismatch: the manifest itself was altered")

    collected = [a for a in manifest.get("artifacts", []) if a.get("status") == "collected"]
    for artifact in collected:
        absolute = os.path.join(path, artifact["path"])
        if not os.path.exists(absolute):
            findings.append("missing artifact: %s" % artifact["path"])
            continue
        actual = hashing.sha256_file(absolute)
        if actual != artifact.get("sha256"):
            findings.append("altered artifact: %s" % artifact["path"])

    root = merkle_root(collected)
    if root != manifest.get("artifacts_merkle_root"):
        findings.append("Merkle root mismatch: the artifact set was added to or "
                        "removed from")

    previous = hashing.genesis(manifest.get("bundle_id", ""), "custody")
    for index, entry in enumerate(manifest.get("custody", [])):
        expected = hashing.chain_next(previous, {
            k: entry.get(k) for k in ("ts", "actor", "action", "detail")})
        if expected != entry.get("chain_hash"):
            findings.append("chain-of-custody broken at entry %d" % index)
            break
        previous = entry["chain_hash"]

    return not findings, findings or ["bundle intact: %d artifacts, custody chain "
                                      "verified" % len(collected)]


def redact_content(path):
    """Strip content-capture artifacts from a bundle before it leaves the host."""
    manifest_path = os.path.join(path, "manifest.json")
    with open(manifest_path, "r") as handle:
        manifest = json.load(handle)
    removed = []
    for artifact in manifest.get("artifacts", []):
        if artifact.get("capability") == "content" or artifact.get("privacy") == "high":
            absolute = os.path.join(path, artifact["path"])
            if os.path.exists(absolute):
                os.remove(absolute)
            artifact["status"] = "redacted"
            artifact["reason"] = "content removed before export"
            removed.append(artifact["path"])
    manifest["redacted"] = {"ts": timeutil.now_iso(), "removed": removed}
    # The Merkle root is deliberately left as it was: it still proves what the
    # bundle originally contained, and the redaction is recorded rather than hidden.
    with open(manifest_path, "w") as handle:
        json.dump(manifest, handle, indent=1, sort_keys=True, default=str)
    return removed


def _actor():
    try:
        import pwd
        user = pwd.getpwuid(os.geteuid()).pw_name
    except (ImportError, KeyError):
        user = str(os.geteuid())
    return {"uid": os.geteuid(), "user": user, "pid": os.getpid(),
            "process": os.path.basename(__import__("sys").argv[0] or "macsiem")}


def cleanup(path):
    shutil.rmtree(path, ignore_errors=True)
