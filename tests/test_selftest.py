"""The end-to-end pipeline, on Linux, with no Mac present."""

from __future__ import annotations

import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from macsiem import cli
from macsiem.selftest import run_selftest


class TestSelftest(unittest.TestCase):
    def test_recorded_incident_runs_end_to_end(self):
        out = io.StringIO()
        directory = tempfile.mkdtemp()
        with redirect_stdout(out):
            code = run_selftest(offline=True, out_dir=directory)
        text = out.getvalue()
        self.assertEqual(code, 0, text)
        self.assertIn("selftest PASSED", text)

        bundles = os.path.join(directory, "bundles")
        produced = os.listdir(bundles)
        self.assertEqual(len(produced), 1)
        bundle = os.path.join(bundles, produced[0])
        for expected in ("manifest.json", "report.html",
                         os.path.join("analysis", "narrative.md"),
                         os.path.join("analysis", "timeline.json")):
            self.assertTrue(os.path.exists(os.path.join(bundle, expected)), expected)

    def test_report_is_self_contained(self):
        """An incident report must not phone home when it is opened."""
        directory = tempfile.mkdtemp()
        with redirect_stdout(io.StringIO()):
            run_selftest(offline=True, out_dir=directory)
        bundles = os.path.join(directory, "bundles")
        bundle = os.path.join(bundles, os.listdir(bundles)[0])
        with open(os.path.join(bundle, "report.html")) as handle:
            html = handle.read()
        # Evidence text legitimately contains URLs (the incident fetched one),
        # and it is HTML-escaped. What must not appear is anything that *loads*
        # a resource when the report is opened.
        for forbidden in ('<script', '<link ', '<iframe', '<img ', 'src="http',
                          "src='http", "@import", "url(http", "<object", "<embed"):
            self.assertNotIn(forbidden, html,
                             "report contains a resource reference: %s" % forbidden)
        self.assertIn("LOOBins coverage", html)


class TestCli(unittest.TestCase):
    def run_cli(self, argv):
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli.main(argv)
        return code, out.getvalue()

    def test_version(self):
        code, text = self.run_cli(["version"])
        self.assertEqual(code, 0)
        self.assertIn("rulepack", text)

    def test_probe_coverage_accounts_for_every_binary(self):
        code, text = self.run_cli(["probes", "--coverage"])
        self.assertEqual(code, 0)
        self.assertIn("observational_only", text)
        self.assertEqual(len([line for line in text.splitlines()
                              if line and not line.startswith("{")]), 62)

    def test_rules_listing(self):
        code, text = self.run_cli(["rules"])
        self.assertEqual(code, 0)
        self.assertIn("signature", text)

    def test_show_unknown_probe_fails_cleanly(self):
        code, text = self.run_cli(["probes", "--show", "no.such.probe"])
        self.assertEqual(code, 1)
        self.assertIn("no such probe", text)


if __name__ == "__main__":
    unittest.main()
