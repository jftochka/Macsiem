"""End-to-end investigation: one event in, one 360-degree evidence bundle out.

This is the pipeline the daemon calls on an alert and the analyst calls from the
CLI.  Order matters: the sweep is targeted at the subject, correlation runs over
both the sweep output and the event store, and the bundle is sealed last so its
manifest can anchor to the store's chain head.
"""

from __future__ import annotations

import os

from . import __version__
from .correlate import narrative as narrative_mod
from .correlate import proctree, timeline as timeline_mod
from .evidence import orchestrator as orch_mod
from .evidence.bundle import Bundle
from .report import html as html_mod
from .util import hashing, timeutil


def context_for(event, window="30m"):
    """Build the slot context a sweep needs from the triggering event."""
    event = event or {}
    center = timeutil.parse(event.get("ts"), timeutil.now())
    start, end = timeutil.window(center, window)
    target_path = event.get("binary_path")
    argv = event.get("argv") or []
    # For a script interpreter the interesting file is usually the argument, not
    # the interpreter itself.
    if os.path.basename(target_path or "") in ("osascript", "python3", "swift",
                                               "tclsh", "sh", "bash", "zsh"):
        for candidate in argv[1:]:
            if candidate.startswith("/") and not candidate.startswith("-"):
                target_path = candidate
                break
    return {
        "target_path": target_path,
        "target_pid": str(event["pid"]) if event.get("pid") else None,
        "target_user": event.get("user"),
        # `log show` wants local-naive "YYYY-MM-DD HH:MM:SS".
        "window_start": start.strftime("%Y-%m-%d %H:%M:%S"),
        "window_end": end.strftime("%Y-%m-%d %H:%M:%S"),
    }


def investigate(config, store, rulepack, runner, alert=None, event=None,
                tier=orch_mod.TIER_FULL, window="30m", engine=None,
                bundle_root=None, reason=None):
    """Run a sweep for one alert/event and return ``(bundle, manifest)``."""
    if event is None and alert and store:
        event = store.event(alert.get("event_id")) or {}
    event = event or {}
    ctx = context_for(event, window)

    bundle_root = bundle_root or config.get_path("paths.bundle_dir")
    os.makedirs(bundle_root, mode=0o700, exist_ok=True)
    bundle = Bundle(bundle_root, store=store)

    orchestrator = orch_mod.Orchestrator(config, store=store, rulepack=rulepack,
                                         runner=runner, engine=engine)
    trigger = {
        "kind": "alert" if alert else "manual",
        "id": (alert or {}).get("alert_id") or (event or {}).get("event_id"),
        "reason": reason or (alert or {}).get("use_case") or "on-demand sweep",
        "severity": (alert or {}).get("severity"),
        "rule_ids": (alert or {}).get("rule_ids") or [],
    }
    sweep = orchestrator.sweep(tier=tier, trigger=trigger, ctx=ctx,
                               bundle_dir=bundle.path,
                               dedupe_key=(alert or {}).get("dedupe_key"))

    for result in sweep["results"]:
        bundle.add_probe_result(result)

    # -- correlation -------------------------------------------------------
    center = timeutil.parse(event.get("ts"), timeutil.now())
    start, end = timeutil.window(center, window)
    events = store.events_between(timeutil.to_iso(start), timeutil.to_iso(end)) \
        if store else []
    alerts = store.recent_alerts(limit=200) if store else []
    alerts = [a for a in alerts
              if timeutil.to_iso(start) <= (a.get("ts") or "") <= timeutil.to_iso(end)]

    ps_result = next((r for r in sweep["results"]
                      if r.get("probe_id") == "process.snapshot"), None)
    ps_table = proctree.parse_ps((ps_result or {}).get("stdout", ""))
    by_pid = proctree.index_events(events)
    subject_pid = event.get("pid")
    chain = proctree.ancestry(subject_pid, by_pid, ps_table) if subject_pid else []
    kids = proctree.descendants(subject_pid, by_pid, ps_table) if subject_pid else []
    subject = by_pid.get(subject_pid) or ps_table.get(subject_pid) or {
        "pid": subject_pid, "user": event.get("user"),
        "command": " ".join(event.get("argv") or []) or event.get("binary_path")}
    tree_text = proctree.tree_text(subject, chain, kids) if subject_pid else ""

    timeline = timeline_mod.build(events=events, alerts=alerts,
                                  results=sweep["results"])
    markdown, facts = narrative_mod.build(alert=alert, event=event, sweep=sweep,
                                          timeline=timeline, tree_text=tree_text,
                                          ancestry=chain)

    bundle.add_analysis("timeline.json", timeline)
    bundle.add_analysis("process_tree.txt", tree_text or "(no process tree available)")
    bundle.add_analysis("narrative.md", markdown)
    bundle.add_analysis("facts.json", facts)
    if alert:
        bundle.add_analysis("alert.json", alert)

    report = html_mod.render(
        {**{"bundle_id": bundle.bundle_id, "sealed": timeutil.now_iso(),
            "host": hashing.host_identity(), "agent": {"version": __version__},
            "coverage_summary": sweep["coverage_summary"],
            "loobins_coverage": sweep["coverage"],
            "artifacts": bundle.artifacts,
            "sweep": {"duration_ms": sweep["duration_ms"], "stats": sweep["stats"]},
            "custody": bundle.custody}},
        narrative_md=markdown, timeline=timeline, alert=alert)
    report_path = os.path.join(bundle.path, "report.html")
    with open(report_path, "w") as handle:
        handle.write(report)
    os.chmod(report_path, 0o600)

    store_anchor = {}
    if store:
        store_anchor = {
            "db": os.path.basename(store.path),
            "chain_head": store.events_chain.tip,
            "chain_seq": store.events_chain.seq,
            "host_id": store.host_id,
        }
    manifest = bundle.seal(sweep, trigger=trigger, agent={
        "version": __version__,
        "rulepack_digest": rulepack.digest if rulepack else None,
        "rulepack_generated": rulepack.generated_at if rulepack else None,
    }, store_anchor=store_anchor)

    # Re-render the report now that the manifest carries the integrity fields.
    report = html_mod.render(manifest, narrative_md=markdown, timeline=timeline,
                             alert=alert)
    with open(report_path, "w") as handle:
        handle.write(report)

    if store:
        store.finish_sweep(sweep["sweep_id"], bundle_id=bundle.bundle_id,
                           bundle_path=bundle.path)
        if alert and alert.get("alert_id"):
            store.add_alert({**alert, "sweep_id": sweep["sweep_id"]})
    return bundle, manifest
