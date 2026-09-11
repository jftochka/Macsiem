"""Tamper evidence: the event chain and the evidence bundle."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from macsiem.evidence import bundle as bundle_mod
from macsiem.store.db import Store
from macsiem.util import hashing


def make_store():
    return Store(os.path.join(tempfile.mkdtemp(), "t.db"), host_id="TEST-HOST")


class TestEventChain(unittest.TestCase):
    def setUp(self):
        self.store = make_store()
        for index in range(6):
            self.store.add_event({
                "sensor": "eslogger", "kind": "exec", "pid": 100 + index,
                "user": "alice", "binary_path": "/usr/bin/csrutil",
                "argv": ["/usr/bin/csrutil", "status"]})

    def test_intact_chain_verifies(self):
        ok, index, detail = self.store.verify("events")
        self.assertTrue(ok, detail)
        self.assertEqual(index, -1)

    def test_modification_is_detected_at_the_right_row(self):
        self.store.conn.execute(
            "UPDATE events SET record = replace(record, 'alice', 'mallory') "
            "WHERE seq = 4")
        self.store.conn.commit()
        ok, index, detail = self.store.verify("events")
        self.assertFalse(ok)
        self.assertEqual(index, 3)
        self.assertIn("record altered", detail)

    def test_deletion_is_detected(self):
        self.store.conn.execute("DELETE FROM events WHERE seq = 3")
        self.store.conn.commit()
        ok, _index, detail = self.store.verify("events")
        self.assertFalse(ok)
        self.assertIn("sequence gap", detail)

    def test_custody_is_chained_too(self):
        self.store.add_custody("b1", "root", "created", {"n": 1})
        self.store.add_custody("b1", "root", "sealed", {"n": 2})
        self.assertTrue(self.store.verify("custody")[0])
        self.store.conn.execute("UPDATE custody SET record = '{}' WHERE seq = 1")
        self.store.conn.commit()
        self.assertFalse(self.store.verify("custody")[0])

    def test_chains_are_bound_to_the_host(self):
        """A chain from another Mac cannot be spliced in unnoticed."""
        other = make_store()
        self.assertNotEqual(self.store.meta("genesis_events"),
                            other.meta("genesis_events"))

    def test_retention_records_its_own_deletions(self):
        removed = self.store.prune(events_days=0)
        self.assertGreater(removed, 0)
        rows = self.store.conn.execute(
            "SELECT action FROM custody").fetchall()
        self.assertIn("prune_events", [row["action"] for row in rows])


class TestBundle(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.bundle = bundle_mod.Bundle(self.root, store=make_store())
        for index in range(5):
            self.bundle.add_probe_result({
                "probe_id": "probe.%d" % index, "category": "host",
                "loobins": ["sw_vers"], "stdout": "output %d\n" % index,
                "started": "2026-09-11T21:00:00.000000Z", "exit_code": 0,
                "privacy": "low", "kind": "exec"})
        self.bundle.add_probe_result({
            "probe_id": "probe.skipped", "category": "host",
            "skipped_reason": "requires root"})
        self.manifest = self.bundle.seal(
            {"sweep_id": "s1", "tier": "full", "coverage": {}, "stats": {},
             "coverage_summary": {}})

    def test_sealed_bundle_verifies(self):
        ok, findings = bundle_mod.verify(self.bundle.path)
        self.assertTrue(ok, findings)

    def test_bundle_directory_is_not_world_readable(self):
        mode = os.stat(self.bundle.path).st_mode & 0o777
        self.assertEqual(mode, 0o700)

    def test_altered_artifact_is_detected(self):
        target = os.path.join(self.bundle.path, "artifacts", "probe.0.txt")
        with open(target, "a") as handle:
            handle.write("tampered")
        ok, findings = bundle_mod.verify(self.bundle.path)
        self.assertFalse(ok)
        self.assertTrue(any("altered artifact" in f for f in findings))

    def test_removed_artifact_is_detected(self):
        os.remove(os.path.join(self.bundle.path, "artifacts", "probe.1.txt"))
        ok, findings = bundle_mod.verify(self.bundle.path)
        self.assertFalse(ok)
        self.assertTrue(any("missing artifact" in f for f in findings))

    def test_edited_manifest_is_detected(self):
        path = os.path.join(self.bundle.path, "manifest.json")
        with open(path, "r") as handle:
            manifest = json.load(handle)
        manifest["host"]["hostname"] = "somewhere-else"
        with open(path, "w") as handle:
            json.dump(manifest, handle)
        ok, findings = bundle_mod.verify(self.bundle.path)
        self.assertFalse(ok)
        self.assertTrue(any("manifest hash mismatch" in f for f in findings))

    def test_merkle_root_changes_when_the_artifact_set_changes(self):
        collected = [a for a in self.manifest["artifacts"]
                     if a.get("status") == "collected"]
        root = bundle_mod.merkle_root(collected)
        self.assertEqual(root, self.manifest["artifacts_merkle_root"])
        self.assertNotEqual(root, bundle_mod.merkle_root(collected[:-1]))

    def test_skipped_probes_are_recorded_not_omitted(self):
        skipped = [a for a in self.manifest["artifacts"]
                   if a.get("status") == "skipped"]
        self.assertEqual(len(skipped), 1)
        self.assertEqual(skipped[0]["reason"], "requires root")

    def test_custody_records_creation_and_sealing(self):
        actions = [entry["action"] for entry in self.manifest["custody"]]
        self.assertIn("created", actions)
        self.assertIn("sealed", actions)

    def test_content_redaction_removes_files_and_says_so(self):
        bundle = bundle_mod.Bundle(tempfile.mkdtemp())
        bundle.add_probe_result({
            "probe_id": "content.clipboard", "category": "content",
            "loobins": ["pbpaste"], "stdout": "secret clipboard text",
            "privacy": "high", "kind": "exec", "exit_code": 0})
        bundle.seal({"sweep_id": "s", "tier": "full", "coverage": {},
                     "coverage_summary": {}, "stats": {}})
        removed = bundle_mod.redact_content(bundle.path)
        self.assertEqual(len(removed), 1)
        self.assertFalse(os.path.exists(os.path.join(bundle.path, removed[0])))
        with open(os.path.join(bundle.path, "manifest.json")) as handle:
            manifest = json.load(handle)
        self.assertIn("redacted", manifest)

    def test_manifest_hash_is_reproducible(self):
        body = {k: v for k, v in self.manifest.items() if k != "manifest_sha256"}
        self.assertEqual(self.manifest["manifest_sha256"],
                         hashing.sha256_bytes(hashing.canonical_json(body)))


if __name__ == "__main__":
    unittest.main()
