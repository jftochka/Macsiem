"""Detection quality: the true positives must fire and the noise must not."""

from __future__ import annotations

import unittest

from macsiem import config as config_mod
from macsiem.rules import engine as engine_mod, loader

BASE = {"ts": "2026-09-11T14:00:00.000000Z", "pid": 501, "ppid": 500, "uid": 501,
        "user": "alice", "fidelity": "high", "is_platform": True, "session_id": 1}


def event(argv, **overrides):
    record = dict(BASE, binary_path=argv[0], argv=argv,
                  event_id="e-%d" % abs(hash(tuple(argv))))
    record.update(overrides)
    return record


class EngineCase(unittest.TestCase):
    def setUp(self):
        self.rulepack = loader.load()
        self.config = config_mod.load(environ={})
        self.config.set_path("detection.business_hours",
                             {"start": 0, "end": 24, "timezone_offset": 0})
        self.engine = engine_mod.Engine(
            self.rulepack, self.config,
            ancestry_provider=lambda e: e.get("_ancestry", []))

    def alerts(self, argv, **overrides):
        return self.engine.evaluate(event(argv, **overrides))

    def top(self, argv, **overrides):
        found = self.alerts(argv, **overrides)
        self.assertTrue(found, "expected an alert for %s" % " ".join(argv))
        return found[0]


class TestTruePositives(EngineCase):
    def test_sip_disable_is_critical(self):
        alert = self.top(["/usr/bin/csrutil", "disable"])
        self.assertEqual(alert["severity"], "critical")
        self.assertEqual(alert["loobin"], "csrutil")

    def test_log_erase_is_critical(self):
        self.assertEqual(self.top(["/usr/bin/log", "erase", "--all"])["severity"],
                         "critical")

    def test_gatekeeper_disable_is_critical(self):
        self.assertEqual(self.top(["/usr/sbin/spctl", "--master-disable"])["severity"],
                         "critical")

    def test_keychain_dump_is_critical(self):
        alert = self.top(["/usr/bin/security", "dump-keychain", "-d", "login.keychain"])
        self.assertEqual(alert["severity"], "critical")

    def test_killing_security_tooling_is_detected(self):
        alert = self.top(["/usr/bin/pkill", "-f", "syslog|auditd|osqueryd|esensor|nessusd"])
        self.assertEqual(alert["loobin"], "pkill")
        self.assertGreaterEqual(alert["severity_value"], 80)

    def test_undocumented_variant_of_a_critical_operation_still_fires(self):
        """`tccutil reset All` is not in the corpus; the curated rule catches it."""
        alert = self.top(["/usr/bin/tccutil", "reset", "All"])
        self.assertEqual(alert["signature_id"], "loobin.tccutil.critical.reset")

    def test_quarantine_removal_is_detected(self):
        alert = self.top(["/usr/bin/xattr", "-d", "com.apple.quarantine",
                          "/Users/alice/Downloads/x"])
        self.assertEqual(alert["loobin"], "xattr")

    def test_proxy_redirection_is_detected(self):
        alert = self.top(["/usr/sbin/networksetup", "-setwebproxy", "Wi-Fi",
                          "198.51.100.9", "8080"])
        self.assertGreaterEqual(alert["severity_value"], 80)

    def test_osascript_shell_escape_is_detected(self):
        alert = self.top(["/usr/bin/osascript", "-e", 'do shell script "whoami"'])
        self.assertEqual(alert["loobin"], "osascript")


class TestFalsePositives(EngineCase):
    def test_version_check_is_silent(self):
        self.assertEqual(self.alerts(["/usr/bin/sw_vers", "-productVersion"]), [])

    def test_developer_pkill_is_silent(self):
        self.assertEqual(self.alerts(["/usr/bin/pkill", "-f", "node server.js"]), [])

    def test_management_tooling_is_suppressed(self):
        alerts = self.alerts(
            ["/usr/bin/profiles", "show"],
            _ancestry=[{"binary_path": "/usr/local/jamf/bin/jamf",
                        "signing_id": "com.jamf.management.daemon", "pid": 300}])
        self.assertEqual(alerts, [])

    def test_single_indicator_does_not_alert(self):
        self.assertEqual(self.alerts(["/usr/sbin/screencapture", "-x", "/tmp/a.png"]), [])

    def test_directory_listing_alone_does_not_alert(self):
        """Several rules match one `dscl` command; that is one observation."""
        self.assertEqual(self.alerts(["/usr/bin/dscl", ".", "-list", "/Users"]), [])

    def test_benign_baseline_is_quiet(self):
        """A stretch of ordinary Mac activity must produce nothing."""
        baseline = [
            ["/usr/bin/sw_vers"], ["/usr/bin/sw_vers", "-buildVersion"],
            ["/usr/sbin/sysctl", "-n", "hw.model"],
            ["/usr/bin/defaults", "read", "com.apple.dock"],
            ["/usr/bin/mdfind", "kMDItemDisplayName", "report.pdf"],
            ["/usr/bin/plutil", "-p", "/tmp/Info.plist"],
            ["/usr/bin/open", "/Applications/Safari.app"],
            ["/usr/bin/codesign", "-dv", "/Applications/Safari.app"],
            ["/usr/bin/last", "-5"],
            ["/usr/sbin/system_profiler", "SPHardwareDataType"],
        ]
        noisy = []
        for index, argv in enumerate(baseline):
            # Distinct sessions: ordinary unrelated activity, not one process tree.
            for alert in self.alerts(argv, session_id=1000 + index,
                                     event_id="benign-%d" % index):
                noisy.append((" ".join(argv), alert["severity"]))
        self.assertEqual(noisy, [], "benign baseline produced alerts: %s" % noisy)


class TestContextAndCorrelation(EngineCase):
    def test_context_raises_severity(self):
        plain = self.top(["/usr/bin/osascript", "-e", 'do shell script "id"'],
                         session_id=11)
        with_context = self.top(
            ["/usr/bin/osascript", "-e", 'do shell script "id"'], session_id=12,
            _ancestry=[{"binary_path": "/bin/zsh", "pid": 500},
                       {"binary_path": "/Applications/Safari.app/Contents/MacOS/Safari",
                        "pid": 400, "is_platform": False}])
        self.assertGreater(with_context["score"], plain["score"])
        self.assertTrue(any("ancestor_is_user_facing_app" in line
                            for line in with_context["rationale"]))

    def test_indicators_corroborate_across_events(self):
        self.assertEqual(
            self.alerts(["/usr/sbin/screencapture", "-x", "/tmp/a.png"],
                        session_id=42, event_id="i1"), [])
        alerts = self.alerts(["/usr/bin/dscl", ".", "-read", "/Users/alice"],
                             session_id=42, event_id="i2")
        self.assertTrue(alerts)
        self.assertEqual(alerts[0]["kind"], "composite")

    def test_degraded_telemetry_lowers_confidence(self):
        high = self.top(["/usr/bin/csrutil", "disable"], session_id=21)
        low = self.top(["/usr/bin/csrutil", "disable"], session_id=22, fidelity="low")
        self.assertLess(low["confidence"], high["confidence"])
        # Severity describes the act, so it does not move with telemetry quality.
        self.assertEqual(low["severity"], high["severity"])

    def test_self_attribution_is_suppressed(self):
        """The sweep runs LOOBins; it must not alert on itself."""
        self.engine.mark_self(4242)
        self.assertEqual(
            self.alerts(["/usr/bin/csrutil", "disable"], ppid=4242), [])
        self.engine.unmark_self(4242)
        self.assertTrue(self.alerts(["/usr/bin/csrutil", "disable"], ppid=4242))

    def test_configured_suppression(self):
        self.config.set_path("detection.suppressions",
                             [{"loobin": "csrutil", "reason": "test rig"}])
        engine = engine_mod.Engine(self.rulepack, self.config,
                                   ancestry_provider=lambda e: [])
        self.assertEqual(engine.evaluate(event(["/usr/bin/csrutil", "disable"])), [])


class TestMatcher(unittest.TestCase):
    def test_flags_may_be_reordered(self):
        rule = {"rule_id": "t", "exec_basenames": ["xattr"], "min_argc": 3,
                "flags_required": ["-d"], "positional": [{"idx": 2, "eq": "com.apple.quarantine"}]}
        match = engine_mod.match_rule(
            rule, ["/usr/bin/xattr", "-r", "-d", "com.apple.quarantine", "/tmp/x"])
        self.assertIsNotNone(match)
        self.assertTrue(match.loose)

    def test_missing_required_flag_does_not_match(self):
        rule = {"rule_id": "t", "exec_basenames": ["xattr"], "min_argc": 2,
                "flags_required": ["-d"], "positional": []}
        self.assertIsNone(engine_mod.match_rule(rule, ["/usr/bin/xattr", "-l", "/tmp/x"]))

    def test_contains_any_matches_variants(self):
        rule = {"rule_id": "t", "exec_basenames": ["pkill"], "min_argc": 2,
                "positional": [{"idx": 2, "contains_any": ["Falcon", "osqueryd"]}]}
        self.assertIsNotNone(engine_mod.match_rule(
            rule, ["/usr/bin/pkill", "-f", "CrowdStrike Falcon Sensor"]))
        self.assertIsNone(engine_mod.match_rule(
            rule, ["/usr/bin/pkill", "-f", "my-dev-server"]))


if __name__ == "__main__":
    unittest.main()
