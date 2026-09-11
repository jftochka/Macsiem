"""End-to-end self test: replay a recorded intrusion with no Mac present.

``macsiem selftest --offline`` runs the whole platform -- sensor normalization,
detection, tiering, correlation, the 360 sweep, bundling, hashing and the HTML
report -- against ``tests/fixtures/``.  It is the demo, and it is also the
regression test that CI runs on Linux.

The replayed incident is deliberately a realistic chain rather than a single
command: browser -> shell -> osascript -> quarantine strip -> LaunchAgent
persistence -> screenshot loop -> EDR kill -> log erase, with two benign events
(``sw_vers``, and Jamf running ``profiles show``) mixed in to prove they stay
quiet.
"""

from __future__ import annotations

import json
import os
import tempfile

from . import config as config_mod, investigate as investigate_mod
from .evidence import orchestrator as orch_mod
from .evidence.bundle import verify as verify_bundle
from .rules import engine as engine_mod, loader as rules_loader
from .store.db import Store, severity_rank
from .util.proc import FixtureRunner

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "..", "tests", "fixtures")


def load_runner(fixtures_dir=None):
    """Build a FixtureRunner from the recorded command output."""
    directory = os.path.join(fixtures_dir or FIXTURES, "cmdout")
    runner = FixtureRunner(default={"stdout": "(no fixture recorded for this probe)\n",
                                    "returncode": 0})
    if os.path.isdir(directory):
        for name in sorted(os.listdir(directory)):
            if not name.endswith(".txt"):
                continue
            with open(os.path.join(directory, name), "r") as handle:
                body = handle.read()
            key = "/" + name[:-4].replace("__", "/")
            runner.fixtures[key] = {"stdout": body, "returncode": 0}
    return runner


def load_events(path=None):
    path = path or os.path.join(FIXTURES, "incident.jsonl")
    events = []
    with open(path, "r") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if "_note" in record:
                continue
            events.append(record)
    return events


def run_selftest(offline=True, verbose=False, out_dir=None, fixtures_dir=None):
    out_dir = out_dir or tempfile.mkdtemp(prefix="macsiem-selftest-")
    os.makedirs(out_dir, exist_ok=True)

    config = config_mod.load()
    config.set_path("paths.data_dir", out_dir)
    config.set_path("paths.bundle_dir", os.path.join(out_dir, "bundles"))
    config.set_path("paths.log_dir", os.path.join(out_dir, "log"))
    config.set_path("forward.jsonl.path", os.path.join(out_dir, "log", "events.jsonl"))
    config_mod.ensure_dirs(config)

    store = Store(os.path.join(out_dir, "macsiem.db"), host_id="SELFTEST-HOST")
    rulepack = rules_loader.load()
    runner = load_runner(fixtures_dir)

    ancestry_index = {}

    def ancestry(event):
        chain, current = [], event.get("ppid")
        for _ in range(8):
            parent = ancestry_index.get(current)
            if not parent:
                break
            chain.append(parent)
            current = parent.get("ppid")
        return chain

    engine = engine_mod.Engine(rulepack, config, ancestry_provider=ancestry)

    print("MacSIEM selftest (offline) -> %s" % out_dir)
    print("rulepack %s: %d rules over %d binaries"
          % (rulepack.digest[:12], len(rulepack.rules), len(rulepack.binaries)))
    print("")
    print("Replaying recorded incident:")
    print("")

    alerts = []
    for event in load_events():
        event_id = store.add_event(event)
        event["event_id"] = event_id
        if event.get("pid"):
            ancestry_index[event["pid"]] = event
        produced = engine.evaluate(event)
        for alert in produced:
            alert["event_id"] = event_id
            store.add_alert(alert)
            alerts.append((alert, event))
        command = " ".join(event.get("argv") or []) or event.get("key") or event.get("kind")
        if produced:
            top = produced[0]
            print("  %-9s %-5.1f  %s" % (top["severity"], top["score"], command[:74]))
            if verbose:
                for line in top["rationale"]:
                    print("            - %s" % line)
        else:
            print("  %-9s %-5s  %s" % ("-", "", command[:74]))

    print("")
    print("%d events -> %d alerts  (%s)" % (
        len(load_events()), len(alerts), json.dumps(engine.stats)))

    if not alerts:
        print("FAIL: the recorded incident produced no alerts")
        return 1

    alerts.sort(key=lambda pair: (-severity_rank(pair[0]["severity"]),
                                  -pair[0]["score"]))
    top_alert, top_event = alerts[0]
    print("")
    print("Investigating the most severe alert: %s (%s)"
          % (top_alert["signature_id"], top_alert["severity"]))

    bundle, manifest = investigate_mod.investigate(
        config, store, rulepack, runner, alert=top_alert, event=top_event,
        tier=orch_mod.TIER_FULL, window="30m", engine=engine)

    stats = manifest["sweep"]["stats"]
    print("")
    print("  bundle     %s" % bundle.path)
    print("  probes     %d planned, %d ran, %d skipped in %.2fs"
          % (stats["planned"], stats["ran"], stats["skipped"],
             manifest["sweep"]["duration_ms"] / 1000.0))
    print("  coverage   %s" % json.dumps(manifest["coverage_summary"]))
    print("  artifacts  %d" % len([a for a in manifest["artifacts"]
                                   if a.get("status") == "collected"]))
    print("  merkle     %s" % manifest["artifacts_merkle_root"][:32])
    print("  chain      events=%s custody=%s"
          % (store.verify("events")[0], store.verify("custody")[0]))

    ok, findings = verify_bundle(bundle.path)
    print("  verify     %s - %s" % ("ok" if ok else "FAILED", findings[0]))
    print("  report     %s" % os.path.join(bundle.path, "report.html"))

    checks = _assertions(manifest, alerts, store, bundle)
    print("")
    for passed, label in checks:
        print("  [%s] %s" % ("ok" if passed else "FAIL", label))
    failures = [label for passed, label in checks if not passed]
    print("")
    print("selftest %s" % ("PASSED" if not failures and ok
                           else "FAILED: " + "; ".join(failures)))
    return 0 if not failures and ok else 1


def _assertions(manifest, alerts, store, bundle):
    """The properties that actually matter, checked rather than assumed."""
    signatures = {alert["signature_id"] for alert, _ in alerts}
    loobins = {alert["loobin"] for alert, _ in alerts}
    commands = [" ".join(event.get("argv") or []) for _, event in alerts]
    coverage = manifest["loobins_coverage"]
    return [
        (any("log" == alert["loobin"] and alert["severity"] == "critical"
             for alert, _ in alerts), "`log erase --all` alerts at critical"),
        ("pkill" in loobins, "killing the EDR is detected"),
        ("xattr" in loobins, "quarantine removal is detected"),
        (not any("sw_vers" in command for command in commands),
         "`sw_vers` in an unrelated session does not alert"),
        (any(alert["kind"] == "composite" for alert, _ in alerts),
         "discovery inside the intrusion's own session correlates into a "
         "composite alert"),
        (not any("profiles show" in command for command in commands),
         "Jamf running `profiles show` is suppressed"),
        (len(coverage) == 62, "all 62 LOOBins are accounted for in the manifest"),
        (all(entry["status"] in ("covered", "observational_only", "policy_excluded",
                                 "unavailable") for entry in coverage.values()),
         "every binary has an explicit coverage status"),
        (manifest["artifacts_merkle_root"] and manifest["manifest_sha256"],
         "bundle is hash-sealed"),
        (store.verify("events")[0], "event chain verifies"),
        (os.path.exists(os.path.join(bundle.path, "report.html")),
         "HTML report was written"),
        (os.path.exists(os.path.join(bundle.path, "analysis", "narrative.md")),
         "narrative was generated"),
    ]
