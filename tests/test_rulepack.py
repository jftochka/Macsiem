"""The rulepack compiled from the LOOBins corpus."""

from __future__ import annotations

import unittest

from macsiem.rules import loader

EXPECTED_BINARIES = 62


class TestRulepack(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rp = loader.load()

    def test_all_loobins_present(self):
        self.assertEqual(len(self.rp.binaries), EXPECTED_BINARIES)

    def test_every_binary_has_at_least_one_rule(self):
        covered = {rule["loobin"] for rule in self.rp.rules}
        missing = sorted(set(self.rp.binaries) - covered)
        self.assertEqual(missing, [], "binaries with no detection rule: %s" % missing)

    def test_rules_are_tiered(self):
        tiers = {}
        for rule in self.rp.rules:
            tiers[rule["tier"]] = tiers.get(rule["tier"], 0) + 1
        self.assertGreater(tiers.get("signature", 0), 100)
        self.assertGreater(tiers.get("indicator", 0), 20)
        # Telemetry-tier rules exist on purpose: things every Mac does.
        self.assertGreater(tiers.get("telemetry", 0), 0)

    def test_every_rule_is_structurally_matchable(self):
        for rule in self.rp.rules:
            self.assertTrue(rule.get("exec_basenames"), rule["rule_id"])
            self.assertIn(rule["tier"], ("signature", "indicator", "telemetry"))
            self.assertGreaterEqual(rule.get("severity_base", 0), 1)
            self.assertLessEqual(rule.get("severity_base", 0), 100)
            for constraint in rule.get("positional") or []:
                self.assertTrue(
                    set(constraint) & {"eq", "contains", "contains_any",
                                       "startswith", "re"},
                    "%s has an unusable constraint %r" % (rule["rule_id"], constraint))

    def test_critical_operations_are_signature_tier(self):
        """The decisive operations must never need corroboration."""
        critical = [r for r in self.rp.rules if r.get("critical_operation")]
        self.assertGreater(len(critical), 40)
        for rule in critical:
            self.assertEqual(rule["tier"], "signature", rule["rule_id"])
            self.assertGreaterEqual(rule["severity_base"], 55, rule["rule_id"])

    def test_index_resolves_documented_paths(self):
        """Binaries reachable under more than one path still index correctly."""
        for name in ("safaridriver", "tftp", "snmptrap", "lsregister"):
            self.assertTrue(self.rp.candidates(name),
                            "no rules indexed for %s" % name)

    def test_no_rule_carries_an_executable_string(self):
        for rule in self.rp.rules:
            for key in ("code", "cmd", "command", "script"):
                self.assertNotIn(key, rule, rule["rule_id"])


class TestExtraction(unittest.TestCase):
    """The corpus->pattern pipeline, on the shapes the corpus actually contains."""

    @classmethod
    def setUpClass(cls):
        import os
        import sys
        sys.path.insert(0, os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
        import extract
        cls.extract = extract
        cls.names = {"osascript", "xattr", "pkill", "log", "csrutil", "screencapture",
                     "sqlite3", "tccutil", "say", "pbpaste", "curl"} - {"curl"}

    def patterns(self, code):
        return self.extract.extract(code, self.names)[0]

    def test_loop_keywords_are_peeled_not_rejected(self):
        found = self.patterns(
            'while true; do screencapture -x /tmp/s/$(date +%s).jpg; sleep 60; done')
        self.assertEqual([p["binary"] for p in found], ["screencapture"])

    def test_command_substitution_is_recursed_into(self):
        found = self.patterns(
            "while true; do echo $(osascript -e 'return (the clipboard)') "
            ">> loot.txt; sleep 10; done")
        self.assertIn("osascript", [p["binary"] for p in found])

    def test_heredoc_body_is_extracted_separately(self):
        found = self.patterns(
            "ssh -i key.pem user@<TARGET_IP> 'bash -s' <<'EOF'\n"
            "osascript -e 'do shell script \"id\"'\nEOF")
        self.assertIn("osascript", [p["binary"] for p in found])

    def test_globs_do_not_become_literal_tokens(self):
        found = self.patterns("xattr -d -r com.apple.quarantine *")
        tokens = [c.get("eq") for c in found[0]["positional"]]
        self.assertNotIn("*", tokens)

    def test_alternations_are_preserved(self):
        found = self.patterns('pkill -f "Little Snitch|ESET|osqueryd|Falcon"')
        constraints = found[0]["positional"]
        self.assertTrue(any("contains_any" in c for c in constraints),
                        "the EDR process list was lost during tokenization")

    def test_shell_keywords_never_become_binaries(self):
        for code in ("while true; do :; done", "if [ -f /tmp/x ]; then echo hi; fi",
                     "for i in 1 2 3; do echo $i; done"):
            for pattern in self.patterns(code):
                self.assertNotIn(pattern["binary"],
                                 self.extract.SHELL_KEYWORDS)

    def test_sudo_is_peeled_and_flagged(self):
        found = self.patterns("sudo log erase --all")
        self.assertEqual(found[0]["binary"], "log")
        self.assertTrue(found[0]["privileged"])

    def test_unparseable_code_does_not_raise(self):
        for code in ("osascript -e 'unterminated", "\x00\x01garbage",
                     "$(((((", "a" * 5000):
            self.extract.extract(code, self.names)


if __name__ == "__main__":
    unittest.main()
