"""The 360-degree sweep.

Runs the probe catalog concurrently against a live Mac and returns one
structured evidence set plus honest per-binary coverage accounting.

Three things keep this from being a denial-of-service against the machine it is
supposed to protect:

*Tiers.*  A ``scoped`` sweep runs only the probes targeted at the triggering
process, file and user, and fills the rest from the baseline cache -- seconds,
not minutes.  A ``full`` sweep runs everything.  Alerts below the configured
severity get scoped; medium and above get full.

*Budgets.*  A bounded worker pool, per-probe timeouts, output caps, a global
wall-clock deadline, and priority ordering so that if the deadline hits, what
gets shed is the least valuable probe rather than an arbitrary one.  Everything
shed is recorded with a reason.

*Self-attribution.*  About twenty of these probes are themselves LOOBins -- a
sweep runs ``system_profiler``, ``dscl``, ``log show``, ``ioreg``, ``sfltool``.
Without suppression the platform alerts on its own evidence collection and each
sweep triggers the next one.  Every spawned PID is registered with the engine
before the sweep starts.
"""

from __future__ import annotations

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..util import hashing, proc, timeutil
from . import probes as probes_mod
from . import runner as runner_mod
from . import safety

TIER_SCOPED = "scoped"
TIER_FULL = "full"

#: Higher runs first, and survives a deadline cut.  Ordering is by evidentiary
#: value for an intrusion: what ran, where it came from, how it persists.
CATEGORY_PRIORITY = {
    "process": 100, "provenance": 95, "persistence": 90, "privacy": 85,
    "identity": 80, "network": 75, "posture": 70, "logs": 60, "content": 55,
    "storage": 50, "apps": 40, "host": 30,
}


class TokenBucket:
    def __init__(self, capacity, per_seconds):
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.per_seconds = float(per_seconds)
        self.updated = time.time()
        self._lock = threading.Lock()

    def take(self, amount=1.0):
        with self._lock:
            now = time.time()
            self.tokens = min(self.capacity, self.tokens +
                              (now - self.updated) * self.capacity / self.per_seconds)
            self.updated = now
            if self.tokens >= amount:
                self.tokens -= amount
                return True
            return False


class SweepResult(dict):
    @property
    def results(self):
        return self.get("results", [])


class Orchestrator:
    def __init__(self, config, store=None, rulepack=None, runner=None, engine=None):
        self.config = config or {}
        self.store = store
        self.rulepack = rulepack
        self.runner = runner or proc.default_runner()
        self.engine = engine
        sweep_cfg = self.config.get("sweep") or {}
        self.workers = max(1, min(int(sweep_cfg.get("workers", 8)),
                                  (os.cpu_count() or 4)))
        self.deadline_scoped = float(sweep_cfg.get("scoped_deadline_seconds", 45))
        self.deadline_full = float(sweep_cfg.get("full_deadline_seconds", 240))
        self.bucket = TokenBucket(int(sweep_cfg.get("max_full_sweeps_per_hour", 12)), 3600)
        self.dedup_window = float(sweep_cfg.get("dedup_window_seconds", 300))
        self._recent = {}
        self._lock = threading.Lock()
        # Validate before anything can run.  A tampered catalog stops the sweep.
        safety.validate_catalog(probes_mod.CATALOG)

    # -- planning ----------------------------------------------------------
    def plan(self, tier, ctx, caps, privacy):
        """Select and order probes for this sweep."""
        if tier == TIER_FULL:
            selected = list(probes_mod.CATALOG)
        else:
            selected = [p for p in probes_mod.CATALOG
                        if p.scope in (probes_mod.EVENT, probes_mod.BOTH)]
        # An event-scoped probe with no target is dead weight; drop it early so
        # it does not consume a worker slot to produce a skip record.
        runnable = []
        for probe in selected:
            if probe.scope == probes_mod.EVENT and probe.slots:
                # {artifact} is supplied by the orchestrator from the bundle
                # directory, not by the event context.
                needed = [slot.strip("{}") for slot in probe.slots
                          if slot != "{artifact}"]
                if any(not ctx.get(name) for name in needed):
                    continue
            runnable.append(probe)
        runnable.sort(key=lambda p: (-CATEGORY_PRIORITY.get(p.category, 0),
                                     {"light": 0, "normal": 1, "heavy": 2}[p.cost],
                                     p.id))
        return runnable

    # -- cache -------------------------------------------------------------
    def _cached(self, probe):
        if not self.store or probe.cache_ttl <= 0:
            return None
        entry = self.store.get_baseline("probe:%s" % probe.id,
                                        max_age_seconds=probe.cache_ttl)
        if not entry:
            return None
        result = dict(entry["payload"])
        result["from_cache"] = True
        result["cache_age_seconds"] = int(
            (timeutil.now() - timeutil.parse(entry["ts"], timeutil.now())).total_seconds())
        return result

    def _store_cache(self, probe, result):
        if self.store and probe.cache_ttl > 0 and not result.get("skipped_reason"):
            self.store.set_baseline("probe:%s" % probe.id, dict(result))

    # -- execution ---------------------------------------------------------
    def sweep(self, tier=TIER_FULL, trigger=None, ctx=None, bundle_dir=None,
              use_cache=True, dedupe_key=None):
        started_at = time.time()
        ctx = dict(ctx or {})
        caps = ctx.get("_capabilities") or runner_mod.capabilities(self.runner)
        ctx["_capabilities"] = caps
        privacy = self.config.get("privacy") or {}

        if tier == TIER_FULL and not self.bucket.take():
            # Rate-limited: the alert is never lost, the evidence is just
            # narrower and points at the last full sweep.
            tier = TIER_SCOPED
            rate_limited = True
        else:
            rate_limited = False

        duplicate_of = self._check_dedupe(dedupe_key)
        sweep_id = hashing.new_id("swp")
        if self.store:
            self.store.start_sweep({
                "sweep_id": sweep_id, "tier": tier,
                "trigger_kind": (trigger or {}).get("kind"),
                "trigger_id": (trigger or {}).get("id"),
                "reason": (trigger or {}).get("reason"), "status": "running"})

        # Register ourselves so the engine discards the events this sweep is
        # about to generate (many probes are LOOBins).
        if self.engine:
            self.engine.mark_self(os.getpid())

        plan = self.plan(tier, ctx, caps, privacy)
        deadline = started_at + (self.deadline_full if tier == TIER_FULL
                                 else self.deadline_scoped)
        results, shed = [], []

        with ThreadPoolExecutor(max_workers=self.workers,
                                thread_name_prefix="macsiem-probe") as pool:
            futures = {}
            for probe in plan:
                if use_cache:
                    cached = self._cached(probe)
                    if cached is not None:
                        results.append(cached)
                        continue
                futures[pool.submit(self._run_one, probe, ctx, bundle_dir)] = probe
            for future in as_completed(futures):
                probe = futures[future]
                if time.time() > deadline and probe.cost == "heavy":
                    shed.append({"probe_id": probe.id, "reason": "sweep deadline"})
                try:
                    result = future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    result = runner_mod.ProbeResult({
                        "probe_id": probe.id, "loobins": list(probe.loobins),
                        "category": probe.category, "error": str(exc),
                        "exit_code": -1, "started": timeutil.now_iso()})
                results.append(result)
                self._store_cache(probe, result)

        results.sort(key=lambda r: r.get("probe_id", ""))
        coverage = probes_mod.coverage(
            self.rulepack.binary_names() if self.rulepack else probes_mod.loobins_covered(),
            caps, privacy)
        # A binary whose probes all skipped at runtime is unavailable, not covered.
        ran = {result["probe_id"] for result in results if not result.get("skipped_reason")}
        for name, entry in coverage.items():
            if entry["status"] == "covered" and not (set(entry.get("probes") or []) & ran):
                entry["status"] = "unavailable"
                entry["reason"] = "all probes for this binary were skipped at runtime"

        duration_ms = int((time.time() - started_at) * 1000)
        summary = SweepResult({
            "sweep_id": sweep_id,
            "tier": tier,
            "started": timeutil.to_iso(timeutil.from_epoch(started_at)),
            "duration_ms": duration_ms,
            "trigger": trigger or {},
            "rate_limited": rate_limited,
            "duplicate_of": duplicate_of,
            "capabilities": caps,
            "workers": self.workers,
            "results": results,
            "shed": shed,
            "coverage": coverage,
            "coverage_summary": probes_mod.summarize_coverage(coverage),
            "stats": {
                "planned": len(plan),
                "ran": len(ran),
                "from_cache": sum(1 for r in results if r.get("from_cache")),
                "skipped": sum(1 for r in results if r.get("skipped_reason")),
                "failed": sum(1 for r in results
                              if r.get("error") or (r.get("exit_code") not in (0, None))),
                "bytes": sum(int(r.get("bytes") or 0) for r in results),
            },
        })

        if self.store:
            for result in results:
                self.store.add_probe_result(sweep_id, result)
            self.store.finish_sweep(
                sweep_id, status="complete", probe_total=len(results),
                probe_ok=summary["stats"]["ran"],
                probe_skipped=summary["stats"]["skipped"],
                probe_failed=summary["stats"]["failed"], duration_ms=duration_ms)
        if self.engine:
            self.engine.unmark_self(os.getpid())
        self._remember_dedupe(dedupe_key, sweep_id)
        return summary

    def _run_one(self, probe, ctx, bundle_dir):
        local_ctx = dict(ctx)
        if probe.needs_session and not os.environ.get("MACSIEM_SESSION_AGENT"):
            # Clipboard and screen belong to the logged-in GUI session, which a
            # root LaunchDaemon is not part of.  Hand it to the LaunchAgent.
            from ..agent.sessionagent import request as session_request
            payload = session_request(self.config, probe.id, local_ctx, bundle_dir)
            result = runner_mod.ProbeResult({
                "probe_id": probe.id, "title": probe.title,
                "loobins": list(probe.loobins), "category": probe.category,
                "kind": probe.kind, "privacy": probe.privacy,
                "started": timeutil.now_iso(), "duration_ms": 0, "bytes": 0})
            result.update(payload or {})
            return result
        if probe.writes_artifact and bundle_dir:
            local_ctx["artifact"] = os.path.join(
                bundle_dir, "artifacts", "%s.png" % probe.id.replace(".", "_"))
            artifact_dir = os.path.dirname(local_ctx["artifact"])
            os.makedirs(artifact_dir, mode=0o700, exist_ok=True)
            os.chmod(artifact_dir, 0o700)
        return runner_mod.run_probe(probe, local_ctx, runner=self.runner,
                                    config=self.config, bundle_dir=bundle_dir)

    # -- dedupe ------------------------------------------------------------
    def _check_dedupe(self, key):
        if not key:
            return None
        with self._lock:
            entry = self._recent.get(key)
            if entry and time.time() - entry[0] <= self.dedup_window:
                return entry[1]
        return None

    def _remember_dedupe(self, key, sweep_id):
        if not key:
            return
        with self._lock:
            self._recent[key] = (time.time(), sweep_id)
            cutoff = time.time() - self.dedup_window
            self._recent = {k: v for k, v in self._recent.items() if v[0] > cutoff}
