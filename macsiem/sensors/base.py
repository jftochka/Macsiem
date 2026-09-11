"""Sensor supervision.

A sensor that dies is not a neutral event.  One of the documented LOOBins use
cases is ``pkill -f "syslog|auditd|osqueryd|esensor|nessusd"`` -- killing the
monitoring is the technique.  So every sensor restarts with backoff, and every
death emits an event of its own.
"""

from __future__ import annotations

import threading
import time
import traceback

from ..util import timeutil


class Sensor:
    name = "sensor"
    #: How much to trust events from this source: drives alert confidence.
    fidelity = "high"

    def __init__(self, config, emit, runner=None):
        self.config = config or {}
        self.emit = emit
        self.runner = runner
        self.stop_event = threading.Event()
        self.thread = None
        self.started_at = None
        self.restarts = 0
        self.last_error = None
        self.events_emitted = 0

    # -- lifecycle ---------------------------------------------------------
    @property
    def enabled(self):
        return bool((self.config.get("sensors") or {}).get(self.name, {}).get(
            "enabled", True))

    def settings(self):
        return (self.config.get("sensors") or {}).get(self.name, {}) or {}

    def start(self):
        if self.thread and self.thread.is_alive():
            return self
        self.stop_event.clear()
        self.started_at = time.time()
        self.thread = threading.Thread(target=self._supervise, name="sensor-%s" % self.name,
                                       daemon=True)
        self.thread.start()
        return self

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=10)

    def _supervise(self):
        backoff = list((self.config.get("agent") or {}).get(
            "sensor_restart_backoff", [1, 2, 5, 15, 30, 60]))
        attempt = 0
        while not self.stop_event.is_set():
            try:
                self.run()
                if self.stop_event.is_set():
                    return
                self.last_error = "sensor exited without being asked to"
            except Exception:
                self.last_error = traceback.format_exc(limit=3)
            self.restarts += 1
            self.emit({
                "sensor": "macsiem", "kind": "sensor_down", "ts": timeutil.now_iso(),
                "detail": {"sensor": self.name, "restarts": self.restarts,
                           "error": (self.last_error or "")[-400:]},
                "macsiem_origin": True,
            })
            delay = backoff[min(attempt, len(backoff) - 1)]
            attempt += 1
            if self.stop_event.wait(delay):
                return

    def run(self):
        raise NotImplementedError

    # -- helpers -----------------------------------------------------------
    def publish(self, event):
        event.setdefault("sensor", self.name)
        event.setdefault("ts", timeutil.now_iso())
        event.setdefault("fidelity", self.fidelity)
        self.events_emitted += 1
        self.emit(event)

    def health(self):
        return {
            "name": self.name,
            "alive": bool(self.thread and self.thread.is_alive()),
            "uptime_s": int(time.time() - self.started_at) if self.started_at else 0,
            "restarts": self.restarts,
            "events": self.events_emitted,
            "fidelity": self.fidelity,
            "last_error": (self.last_error or "")[-200:] or None,
        }


class PollingSensor(Sensor):
    """Snapshot a surface on an interval and emit what changed.

    Diffs rather than full snapshots: a LaunchDaemon that has been there for a
    year is not news, the one that appeared four seconds ago is.
    """

    interval = 60

    def run(self):
        previous = None
        while not self.stop_event.is_set():
            try:
                current = self.snapshot()
            except Exception as exc:
                self.last_error = str(exc)
                current = None
            if current is not None:
                if previous is not None:
                    for change in self.diff(previous, current):
                        self.publish(change)
                previous = current
            interval = float(self.settings().get("interval_seconds", self.interval))
            if self.stop_event.wait(interval):
                return

    def snapshot(self):
        raise NotImplementedError

    def diff(self, previous, current):
        """Default: key-by-key added/removed/changed."""
        changes = []
        for key in sorted(set(current) - set(previous)):
            changes.append({"kind": self.change_kind, "change": "added", "key": key,
                            "detail": current[key]})
        for key in sorted(set(previous) - set(current)):
            changes.append({"kind": self.change_kind, "change": "removed", "key": key,
                            "detail": previous[key]})
        for key in sorted(set(previous) & set(current)):
            if previous[key] != current[key]:
                changes.append({"kind": self.change_kind, "change": "modified",
                                "key": key, "detail": current[key],
                                "previous": previous[key]})
        return changes

    change_kind = "state_change"
