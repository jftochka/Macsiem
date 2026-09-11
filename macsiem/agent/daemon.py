"""The 24/7 supervisor.

Sensors feed a bounded queue; one worker drains it into the store, through the
detection engine, out to the forwarders, and -- when something fires -- into the
sweep scheduler.  Sweeps run on their own serialized thread so a burst of alerts
queues rather than forking a hundred ``system_profiler`` processes.

Design decisions that matter for something meant to run for a year:

* The queue is bounded and drops oldest-first, with the drop counted and
  reported.  An unbounded queue turns a telemetry spike into an OOM kill.
* Every drop, sensor death and telemetry gap is itself an event, so a gap in
  monitoring is provable after the fact rather than invisible.
* The daemon marks its own PID with the engine before starting anything.  About
  twenty probes are LOOBins; without this the agent alerts on itself forever.
"""

from __future__ import annotations

import os
import queue
import signal
import threading
import time

from .. import investigate as investigate_mod
from ..evidence import orchestrator as orch_mod, probes as probes_mod, safety
from ..evidence import runner as runner_mod
from ..forward import build as build_forwarders
from ..rules import engine as engine_mod
from ..sensors.state import registry
from ..store.db import severity_rank
from ..util import proc, timeutil


class Daemon:
    def __init__(self, config, store, rulepack, runner=None):
        self.config = config
        self.store = store
        self.rulepack = rulepack
        self.runner = runner or proc.default_runner()
        self.started = time.time()
        self.stop_event = threading.Event()

        agent_cfg = config.get("agent") or {}
        self.queue = queue.Queue(maxsize=int(agent_cfg.get("queue_max", 20000)))
        self.dropped = 0
        self.heartbeat_seconds = float(agent_cfg.get("heartbeat_seconds", 60))

        self.engine = engine_mod.Engine(
            rulepack, config, ancestry_provider=self._ancestry,
            known_hashes=set())
        self.forwarders = build_forwarders(config)
        self.sensors = []
        self.sweep_queue = queue.Queue(maxsize=32)
        self._threads = []
        self._recent_events = {}
        self._lock = threading.Lock()

    # -- startup -----------------------------------------------------------
    def _preflight(self):
        """Fail closed.  A daemon that cannot prove its probes are read-only
        does not get to start."""
        report = safety.self_audit(probes_mod.CATALOG)
        if not report["ok"]:
            raise SystemExit("macsiem: probe catalog failed validation:\n  " +
                             "\n  ".join(report["failures"]))
        ok, _index, detail = self.store.verify("events")
        if not ok:
            # Loud, but not fatal: refusing to monitor because history was
            # tampered with would hand an attacker an off switch.
            self._emit_internal("chain_broken", {"detail": detail})
        return report

    def _select_sensors(self):
        caps = runner_mod.capabilities()
        classes = registry()
        chosen = []
        settings = self.config.get("sensors") or {}

        eslogger_ok = caps["eslogger"] and caps["root"]
        for name, cls in classes.items():
            if not (settings.get(name) or {}).get("enabled", True):
                continue
            if name == "eslogger" and not eslogger_ok:
                self._emit_internal("sensor_unavailable", {
                    "sensor": name,
                    "reason": "eslogger requires root and macOS 13+; falling back "
                              "to unified log and ps polling at lower fidelity"})
                continue
            if name == "procpoll" and eslogger_ok:
                continue          # redundant when Endpoint Security is available
            chosen.append(cls(self.config, self._enqueue, self.runner))
        return chosen

    # -- event plumbing ----------------------------------------------------
    def _enqueue(self, event):
        try:
            self.queue.put_nowait(event)
        except queue.Full:
            with self._lock:
                self.dropped += 1
            try:                    # make room, oldest first
                self.queue.get_nowait()
                self.queue.put_nowait(event)
            except (queue.Empty, queue.Full):
                pass

    def _emit_internal(self, kind, detail):
        self._enqueue({"sensor": "macsiem", "kind": kind, "detail": detail,
                       "macsiem_origin": True, "ts": timeutil.now_iso()})

    def _ancestry(self, event):
        """Parent chain for context scoring, from recently seen exec events."""
        chain, current = [], event.get("ppid")
        with self._lock:
            for _ in range(8):
                parent = self._recent_events.get(current)
                if not parent:
                    break
                chain.append(parent)
                current = parent.get("ppid")
        if not chain and event.get("parent_path"):
            chain.append({"binary_path": event["parent_path"],
                          "signing_id": event.get("parent_signing_id"),
                          "pid": event.get("ppid")})
        return chain

    def _remember(self, event):
        if event.get("pid") and event.get("kind") in ("exec", "fork"):
            with self._lock:
                self._recent_events[event["pid"]] = event
                if len(self._recent_events) > 4000:
                    for pid in list(self._recent_events)[:1000]:
                        self._recent_events.pop(pid, None)

    # -- worker ------------------------------------------------------------
    def _worker(self):
        while not self.stop_event.is_set():
            try:
                event = self.queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._handle(event)
            except Exception as exc:      # one bad event must not stop the loop
                self._emit_internal("worker_error", {"error": str(exc)[:300]})
            finally:
                self.queue.task_done()

    def _handle(self, event):
        self._remember(event)
        event_id = self.store.add_event(event)
        event["event_id"] = event_id
        for forwarder in self.forwarders:
            forwarder.send(event, "event")

        if event.get("macsiem_origin"):
            return
        alerts = self.engine.evaluate(event)
        for alert in alerts:
            alert["event_id"] = event_id
            self.store.add_alert(alert)
            for forwarder in self.forwarders:
                forwarder.send(alert, "alert")
        if alerts:
            # One command line often matches several rules (`csrutil disable`
            # matches both its documented use case and the curated critical-
            # operation rule).  That is one observation, so it gets one sweep,
            # attributed to the most severe alert.
            self._maybe_sweep(alerts[0], event)

    def _maybe_sweep(self, alert, event):
        floor = (self.config.get("sweep") or {}).get("full_sweep_min_severity", "medium")
        tier = (orch_mod.TIER_FULL
                if severity_rank(alert["severity"]) >= severity_rank(floor)
                else orch_mod.TIER_SCOPED)
        try:
            self.sweep_queue.put_nowait((alert, event, tier))
        except queue.Full:
            # Never lose the alert; only decline to collect for it right now.
            self._emit_internal("sweep_queue_full", {"alert_id": alert["alert_id"]})

    def _sweeper(self):
        while not self.stop_event.is_set():
            try:
                alert, event, tier = self.sweep_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                bundle, manifest = investigate_mod.investigate(
                    self.config, self.store, self.rulepack, self.runner,
                    alert=alert, event=event, tier=tier, engine=self.engine)
                self._emit_internal("sweep_complete", {
                    "alert_id": alert.get("alert_id"), "tier": tier,
                    "bundle": bundle.bundle_id,
                    "coverage": manifest.get("coverage_summary")})
            except Exception as exc:
                self._emit_internal("sweep_error", {
                    "alert_id": alert.get("alert_id"), "error": str(exc)[:300]})
            finally:
                self.sweep_queue.task_done()

    # -- periodic ----------------------------------------------------------
    def _heartbeat(self):
        while not self.stop_event.wait(self.heartbeat_seconds):
            self.store.heartbeat(
                pid=os.getpid(), uptime_s=int(time.time() - self.started),
                sensors=[sensor.health() for sensor in self.sensors],
                queue_depth=self.queue.qsize(), dropped=self.dropped,
                note="engine=%s" % self.engine.stats)

    def _baseline_refresh(self):
        interval = float((self.config.get("sweep") or {}).get(
            "baseline_refresh_seconds", 3600))
        orchestrator = orch_mod.Orchestrator(self.config, store=self.store,
                                             rulepack=self.rulepack,
                                             runner=self.runner, engine=self.engine)
        while not self.stop_event.wait(interval):
            try:
                # Pre-warming is what lets a "full" sweep finish in seconds when
                # it matters: most expensive probes are already cached.
                orchestrator.sweep(tier=orch_mod.TIER_FULL,
                                   trigger={"kind": "schedule",
                                            "reason": "baseline refresh"},
                                   ctx={}, use_cache=False)
            except Exception as exc:
                self._emit_internal("baseline_error", {"error": str(exc)[:300]})

    def _retention(self):
        while not self.stop_event.wait(3600):
            retention = self.config.get("retention") or {}
            try:
                removed = self.store.prune(
                    events_days=int(retention.get("events_days", 30)))
                if removed:
                    self._emit_internal("retention", {"events_removed": removed})
            except Exception as exc:
                self._emit_internal("retention_error", {"error": str(exc)[:300]})

    # -- lifecycle ---------------------------------------------------------
    def run(self):
        self._preflight()
        # Suppress our own descendants before any probe can run.
        self.engine.mark_self(os.getpid())

        for handler_signal in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(handler_signal, lambda *_: self.stop_event.set())
            except ValueError:
                pass          # not on the main thread (tests)

        self.sensors = self._select_sensors()
        for sensor in self.sensors:
            sensor.start()

        for target, name in ((self._worker, "worker"), (self._sweeper, "sweeper"),
                             (self._heartbeat, "heartbeat"),
                             (self._baseline_refresh, "baseline"),
                             (self._retention, "retention")):
            thread = threading.Thread(target=target, name="macsiem-%s" % name,
                                      daemon=True)
            thread.start()
            self._threads.append(thread)

        self._emit_internal("agent_start", {
            "pid": os.getpid(), "version": __import__("macsiem").__version__,
            "sensors": [sensor.name for sensor in self.sensors],
            "rulepack": self.rulepack.digest[:16],
            "probes": len(probes_mod.CATALOG)})

        while not self.stop_event.wait(1.0):
            pass
        return self.shutdown()

    def shutdown(self):
        self.stop_event.set()
        for sensor in self.sensors:
            sensor.stop()
        for forwarder in self.forwarders:
            forwarder.close()
        self.store.heartbeat(pid=os.getpid(),
                             uptime_s=int(time.time() - self.started),
                             sensors=[s.health() for s in self.sensors],
                             queue_depth=self.queue.qsize(), dropped=self.dropped,
                             note="stopped")
        return 0

    def status(self):
        return {
            "pid": os.getpid(),
            "uptime_s": int(time.time() - self.started),
            "queue_depth": self.queue.qsize(),
            "dropped": self.dropped,
            "sensors": [sensor.health() for sensor in self.sensors],
            "engine": self.engine.stats,
        }
