"""Command-line interface.

    macsiem doctor                 what this host can and cannot collect
    macsiem sweep --full           run the 360 sweep now
    macsiem investigate <id>       build an evidence bundle for an alert/event
    macsiem verify                 check the event-store chain or a bundle
    macsiem selftest --offline     replay a recorded incident end to end
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__, config as config_mod, investigate as investigate_mod
from .evidence import orchestrator as orch_mod, probes as probes_mod, runner as runner_mod
from .evidence import safety
from .evidence.bundle import verify as verify_bundle, redact_content
from .rules import engine as engine_mod, loader as rules_loader
from .store.db import Store, SEVERITY_ORDER
from .util import proc, timeutil

OK, WARN, BAD = "ok", "warn", "fail"
MARK = {OK: "  ok  ", WARN: " warn ", BAD: " FAIL "}


def _out(text=""):
    sys.stdout.write(str(text) + "\n")


def _context(args):
    config = config_mod.load(getattr(args, "config", None))
    if getattr(args, "offline", False):
        proc.set_default_runner(_offline_runner())
    rulepack = rules_loader.load()
    store = None
    if getattr(args, "needs_store", True):
        config_mod.ensure_dirs(config)
        store = Store(config.db_path)
    return config, rulepack, store


def _offline_runner():
    """Fixture runner used by --offline and the test suite."""
    from .util.proc import FixtureRunner
    fixtures_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "tests", "fixtures", "cmdout")
    runner = FixtureRunner(default={"stdout": "(no fixture recorded)\n", "returncode": 0})
    if os.path.isdir(fixtures_dir):
        for name in sorted(os.listdir(fixtures_dir)):
            if not name.endswith(".txt"):
                continue
            with open(os.path.join(fixtures_dir, name), "r") as handle:
                content = handle.read()
            key = name[:-4].replace("__", "/").replace("_", " ")
            runner.fixtures["/" + key] = {"stdout": content, "returncode": 0}
    return runner


# -- commands ---------------------------------------------------------------
def cmd_version(args):
    _out("macsiem %s" % __version__)
    rulepack = rules_loader.load()
    _out("rulepack %s  %s" % (rulepack.generated_at, rulepack.digest[:16]))
    _out("  %s" % json.dumps(rulepack.counts))
    _out("probes %d (%d exec, %d native)" % (
        len(probes_mod.CATALOG),
        sum(1 for p in probes_mod.CATALOG if p.kind == "exec"),
        sum(1 for p in probes_mod.CATALOG if p.kind == "native")))
    return 0


def cmd_doctor(args):
    """Everything an operator needs to know before trusting this agent."""
    config, rulepack, store = _context(args)
    caps = runner_mod.capabilities()
    rows = []

    rows.append((OK if caps["macos"] else WARN, "platform",
                 "%s %s" % (os.uname().sysname, os.uname().release)))
    rows.append((OK if caps["root"] else WARN, "privileges",
                 "running as uid %d%s" % (os.geteuid(),
                                          "" if caps["root"] else " (not root: "
                                          "root-only probes will be skipped)")))
    rows.append((OK if caps["fda"] else WARN, "full disk access",
                 "TCC.db readable" if caps["fda"] else
                 "not granted - TCC, BTM, browser and unified-log probes will skip"))
    rows.append((OK if caps["eslogger"] else WARN, "endpoint security",
                 "/usr/bin/eslogger present" if caps["eslogger"] else
                 "eslogger missing - falling back to unified log + ps polling "
                 "(lower fidelity)"))
    rows.append((OK if caps["session"] else WARN, "session agent",
                 "connected" if caps["session"] else
                 "not connected - clipboard and screenshot probes will skip"))

    audit = safety.self_audit(probes_mod.CATALOG, strict_paths=caps["macos"])
    rows.append((OK if audit["ok"] else BAD, "probe catalog",
                 "%d probes validated read-only" % audit["probes"]
                 if audit["ok"] else "; ".join(audit["failures"][:3])))
    rows.append((OK, "rulepack", "%d rules over %d binaries (digest %s)"
                 % (len(rulepack.rules), len(rulepack.binaries), rulepack.digest[:12])))

    if store:
        ok, index, detail = store.verify("events")
        rows.append((OK if ok else BAD, "event chain", detail))
        stats = store.stats()
        rows.append((OK, "store", "%d events, %d alerts, %d sweeps, %.1f MB"
                     % (stats["events"], stats["alerts"], stats["sweeps"],
                        stats["db_bytes"] / 1048576.0)))
        beat = stats.get("last_heartbeat")
        if beat:
            age = (timeutil.now() - timeutil.parse(beat, timeutil.now())).total_seconds()
            rows.append((OK if age < 300 else BAD, "daemon",
                         "last heartbeat %ds ago" % age))
        else:
            rows.append((WARN, "daemon", "no heartbeat recorded - agent not running"))

    privacy = config.get_path("privacy") or {}
    rows.append((WARN if privacy.get("capture_content") else OK, "privacy",
                 "content capture ENABLED (clipboard, screenshots, browser data)"
                 if privacy.get("capture_content") else "metadata only"))

    for status, label, detail in rows:
        _out("[%s] %-18s %s" % (MARK[status], label, detail))

    if audit["exceptions"] and args.verbose:
        _out("")
        _out("Declared safety exceptions (%d):" % len(audit["exceptions"]))
        for entry in audit["exceptions"]:
            _out("  %-26s %s" % (entry["probe"], entry["why"]))

    failures = [row for row in rows if row[0] == BAD]
    _out("")
    _out("%d check(s) failed, %d warning(s)" % (
        len(failures), len([r for r in rows if r[0] == WARN])))
    return 1 if failures else 0


def cmd_probes(args):
    if args.coverage:
        rulepack = rules_loader.load()
        caps = runner_mod.capabilities()
        config = config_mod.load(getattr(args, "config", None))
        report = probes_mod.coverage(rulepack.binary_names(), caps,
                                     config.get_path("privacy"))
        width = max(len(name) for name in report)
        for name, entry in sorted(report.items()):
            detail = ", ".join(entry.get("probes") or entry.get("artifact_state") or [])
            _out("%-*s  %-19s %s" % (width, name, entry["status"], detail[:80]))
        _out("")
        _out(json.dumps(probes_mod.summarize_coverage(report)))
        missing = [n for n, e in report.items() if e["status"] not in (
            "covered", "observational_only", "policy_excluded", "unavailable")]
        return 1 if missing else 0
    if args.show:
        probe = probes_mod.BY_ID.get(args.show)
        if not probe:
            _out("no such probe: %s" % args.show)
            return 1
        _out(json.dumps(probe.to_dict(), indent=2))
        return 0
    for probe in probes_mod.CATALOG:
        flags = "".join([
            "R" if probe.needs_root else "-", "F" if probe.needs_fda else "-",
            "S" if probe.needs_session else "-",
            "C" if probe.privacy == probes_mod.HIGH else "-"])
        _out("%-32s %-5s %-11s %-8s %s" % (probe.id, flags, probe.category,
                                           probe.cost, probe.title))
    _out("")
    _out("flags: R=root F=full-disk-access S=gui-session C=content-capture")
    return 0


def cmd_rules(args):
    rulepack = rules_loader.load()
    if args.show:
        matches = [r for r in rulepack.rules
                   if r["rule_id"] == args.show or r.get("loobin") == args.show]
        if not matches:
            _out("no rule or binary named %s" % args.show)
            return 1
        for rule in matches:
            _out(json.dumps(rule, indent=2))
        return 0
    if args.test:
        return _rules_test(rulepack, args)
    counts = rulepack.counts
    _out("rulepack generated %s  digest %s" % (rulepack.generated_at,
                                               rulepack.digest[:16]))
    _out("%d rules: %d signature, %d indicator, %d telemetry, %d custom"
         % (counts.get("rules", 0), counts.get("signature", 0),
            counts.get("indicator", 0), counts.get("telemetry", 0),
            counts.get("custom", 0)))
    _out("")
    by_binary = {}
    for rule in rulepack.rules:
        by_binary.setdefault(rule["loobin"], []).append(rule)
    for binary in sorted(by_binary):
        group = by_binary[binary]
        _out("%-16s %3d rules  max severity %3d  %s" % (
            binary, len(group), max(r.get("severity_base", 0) for r in group),
            ", ".join(sorted({t for r in group for t in r.get("tactics") or []}))[:60]))
    return 0


def _rules_test(rulepack, args):
    """Replay a JSONL file of events through the engine."""
    config = config_mod.load(getattr(args, "config", None))
    engine = engine_mod.Engine(rulepack, config,
                               ancestry_provider=lambda e: e.get("ancestry", []))
    total = alerts = 0
    with open(args.test, "r") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            event = json.loads(line)
            total += 1
            for alert in engine.evaluate(event):
                alerts += 1
                _out("%-9s %-6.1f %-34s %s" % (
                    alert["severity"], alert["score"], alert["signature_id"],
                    " ".join(event.get("argv") or [])[:60]))
    _out("")
    _out("%d events -> %d alerts  %s" % (total, alerts, json.dumps(engine.stats)))
    return 0


def cmd_sweep(args):
    config, rulepack, store = _context(args)
    runner = proc.default_runner()
    tier = orch_mod.TIER_FULL if args.full else orch_mod.TIER_SCOPED
    event = {}
    if args.target_pid:
        event["pid"] = int(args.target_pid)
    if args.target_path:
        event["binary_path"] = args.target_path
    bundle, manifest = investigate_mod.investigate(
        config, store, rulepack, runner, event=event or None, tier=tier,
        window=args.window, reason=args.reason or "manual sweep")
    _print_bundle(manifest, bundle)
    return 0


def cmd_investigate(args):
    config, rulepack, store = _context(args)
    alert = store.alert(args.id)
    event = None
    if alert is None:
        event = store.event(args.id)
        if event is None:
            _out("no alert or event with id %s" % args.id)
            return 1
    bundle, manifest = investigate_mod.investigate(
        config, store, rulepack, proc.default_runner(), alert=alert, event=event,
        tier=orch_mod.TIER_FULL, window=args.window)
    _print_bundle(manifest, bundle)
    return 0


def _print_bundle(manifest, bundle):
    stats = (manifest.get("sweep") or {}).get("stats") or {}
    _out("bundle   %s" % bundle.path)
    _out("probes   %d run, %d cached, %d skipped, %d failed in %.1fs"
         % (stats.get("ran", 0), stats.get("from_cache", 0), stats.get("skipped", 0),
            stats.get("failed", 0),
            (manifest.get("sweep") or {}).get("duration_ms", 0) / 1000.0))
    _out("coverage %s" % json.dumps(manifest.get("coverage_summary")))
    _out("merkle   %s" % manifest.get("artifacts_merkle_root"))
    _out("report   %s" % os.path.join(bundle.path, "report.html"))


def cmd_alerts(args):
    config, rulepack, store = _context(args)
    rows = store.recent_alerts(limit=args.limit, min_severity=args.min_severity)
    if not rows:
        _out("no alerts")
        return 0
    for alert in rows:
        _out("%-26s %-9s %-6s %-16s %s" % (
            alert["alert_id"], alert["severity"], alert.get("confidence"),
            alert.get("loobin"), (alert.get("use_case") or "")[:52]))
    return 0


def cmd_verify(args):
    if args.bundle:
        path = args.bundle
        if not os.path.isdir(path):
            config = config_mod.load(getattr(args, "config", None))
            path = os.path.join(config.get_path("paths.bundle_dir"), args.bundle)
        ok, findings = verify_bundle(path)
        for finding in findings:
            _out(("[  ok  ] " if ok else "[ FAIL ] ") + finding)
        return 0 if ok else 1
    config, rulepack, store = _context(args)
    failed = 0
    for table in ("events", "custody"):
        ok, index, detail = store.verify(table)
        _out("[%s] %-9s %s" % (MARK[OK if ok else BAD], table, detail))
        failed += 0 if ok else 1
    return 1 if failed else 0


def cmd_export(args):
    config = config_mod.load(getattr(args, "config", None))
    path = args.bundle if os.path.isdir(args.bundle) else os.path.join(
        config.get_path("paths.bundle_dir"), args.bundle)
    if args.redact:
        removed = redact_content(path)
        _out("removed %d content artifact(s)" % len(removed))
    from .evidence.bundle import Bundle
    bundle = Bundle.__new__(Bundle)
    bundle.path, bundle.bundle_id = path, os.path.basename(path)
    bundle.custody, bundle.store = [], None
    bundle.actor = {"user": "cli"}
    archive = bundle.zip(args.out)
    _out(archive)
    return 0


def cmd_daemon(args):
    from .agent.daemon import Daemon
    config, rulepack, store = _context(args)
    Daemon(config, store, rulepack).run()
    return 0


def cmd_session_agent(args):
    from .agent.sessionagent import SessionAgent
    config = config_mod.load(getattr(args, "config", None))
    return SessionAgent(config).run()


def cmd_install(args):
    from .launchd import plists
    return plists.install(config_mod.load(getattr(args, "config", None)),
                          uninstall=args.uninstall, dry_run=args.dry_run)


def cmd_selftest(args):
    from .selftest import run_selftest
    return run_selftest(offline=True, verbose=args.verbose, out_dir=args.out)


# -- parser -----------------------------------------------------------------
def build_parser():
    parser = argparse.ArgumentParser(
        prog="macsiem",
        description="24/7 macOS monitoring and 360-degree evidence collection, "
                    "built on the LOOBins corpus (https://loobins.io)")
    parser.add_argument("--config", help="path to config.json")
    parser.add_argument("--offline", action="store_true",
                        help="use recorded fixtures instead of running commands")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("version").set_defaults(func=cmd_version, needs_store=False)

    doctor = sub.add_parser("doctor", help="check what this host can collect")
    doctor.set_defaults(func=cmd_doctor)

    probes = sub.add_parser("probes", help="the read-only probe catalog")
    probes.add_argument("--coverage", action="store_true",
                        help="per-LOOBin coverage accounting")
    probes.add_argument("--show", metavar="PROBE_ID")
    probes.set_defaults(func=cmd_probes, needs_store=False)

    rules = sub.add_parser("rules", help="detection rules derived from LOOBins")
    rules.add_argument("--show", metavar="RULE_OR_BINARY")
    rules.add_argument("--test", metavar="EVENTS.JSONL",
                       help="replay events through the engine")
    rules.set_defaults(func=cmd_rules, needs_store=False)

    sweep = sub.add_parser("sweep", help="run an evidence sweep now")
    sweep.add_argument("--full", action="store_true", help="run the whole catalog")
    sweep.add_argument("--target-pid")
    sweep.add_argument("--target-path")
    sweep.add_argument("--window", default="30m")
    sweep.add_argument("--reason")
    sweep.set_defaults(func=cmd_sweep)

    investigate = sub.add_parser("investigate",
                                 help="build a 360 bundle for an alert or event")
    investigate.add_argument("id")
    investigate.add_argument("--window", default="30m")
    investigate.set_defaults(func=cmd_investigate)

    alerts = sub.add_parser("alerts", help="recent alerts")
    alerts.add_argument("--limit", type=int, default=30)
    alerts.add_argument("--min-severity", choices=SEVERITY_ORDER)
    alerts.set_defaults(func=cmd_alerts)

    verify = sub.add_parser("verify", help="verify the event chain or a bundle")
    verify.add_argument("--bundle")
    verify.set_defaults(func=cmd_verify)

    export = sub.add_parser("export", help="zip a bundle, optionally redacted")
    export.add_argument("bundle")
    export.add_argument("--out")
    export.add_argument("--redact", action="store_true",
                        help="strip clipboard, screenshots and browser data first")
    export.set_defaults(func=cmd_export, needs_store=False)

    daemon = sub.add_parser("daemon", help="run the agent in the foreground")
    daemon.set_defaults(func=cmd_daemon)

    session = sub.add_parser("session-agent",
                             help="run the per-user session agent (launchd uses this)")
    session.set_defaults(func=cmd_session_agent, needs_store=False)

    install = sub.add_parser("install", help="install or remove the launchd jobs")
    install.add_argument("--uninstall", action="store_true")
    install.add_argument("--dry-run", action="store_true")
    install.set_defaults(func=cmd_install, needs_store=False)

    selftest = sub.add_parser("selftest",
                              help="replay a recorded incident end to end")
    selftest.add_argument("--offline", action="store_true", default=True)
    selftest.add_argument("--out")
    selftest.set_defaults(func=cmd_selftest, needs_store=False)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    if not hasattr(args, "needs_store"):
        args.needs_store = True
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except safety.UnsafeProbe as exc:
        _out("macsiem: refusing to run: %s" % exc)
        return 78          # EX_CONFIG: a safety failure is never a soft warning
    except BrokenPipeError:
        return 0
