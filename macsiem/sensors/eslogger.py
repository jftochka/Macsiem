"""Endpoint Security via ``/usr/bin/eslogger``.

The primary process sensor on macOS 13+.  ``eslogger`` ships entitled for
Endpoint Security, so it needs no system extension and no Apple entitlement of
our own -- but it does need root *and* Full Disk Access for the responsible
process, and Apple documents its output schema as unstable.  Both facts are
handled here: the parser is defensive about shape, and ``macsiem doctor``
reports when the sensor is unavailable so nobody assumes coverage they do not
have.

Endpoint Security sequence numbers are tracked so that dropped events become
visible.  A gap in monitoring that nobody notices is worse than no monitoring.
"""

from __future__ import annotations

import json
import os

from ..util import timeutil
from .base import Sensor

DEFAULT_EVENTS = ["exec", "fork", "exit", "btm_launch_item_add", "signal",
                  "setextattr", "deleteextattr", "mount", "login_login"]


class EsloggerSensor(Sensor):
    name = "eslogger"
    fidelity = "high"

    def available(self):
        path = self.settings().get("path", "/usr/bin/eslogger")
        return os.path.exists(path) and os.geteuid() == 0

    def run(self):
        settings = self.settings()
        path = settings.get("path", "/usr/bin/eslogger")
        events = settings.get("events") or DEFAULT_EVENTS
        argv = [path] + list(events)
        self._last_seq = {}
        stderr = []
        code = self.runner.stream(argv, self._on_line, self.stop_event, stderr)
        if code not in (0, None) and not self.stop_event.is_set():
            raise RuntimeError("eslogger exited %s: %s" % (code, " ".join(stderr[-3:])))

    def _on_line(self, line):
        try:
            payload = json.loads(line)
        except ValueError:
            return
        event = normalize(payload)
        if not event:
            return
        self._check_sequence(payload, event)
        self.publish(event)

    def _check_sequence(self, payload, event):
        """Report Endpoint Security drops rather than silently losing events."""
        kind = event.get("kind")
        seq = payload.get("seq_num")
        if seq is None:
            return
        previous = self._last_seq.get(kind)
        self._last_seq[kind] = seq
        if previous is not None and seq > previous + 1:
            self.publish({
                "sensor": "macsiem", "kind": "telemetry_gap", "macsiem_origin": True,
                "detail": {"event_type": kind, "missed": seq - previous - 1,
                           "from_seq": previous, "to_seq": seq}})


def normalize(payload):
    """Map an eslogger message onto the MacSIEM event schema.

    Written defensively on purpose: the schema moves between macOS releases, and
    a KeyError in a sensor is a monitoring outage.
    """
    if not isinstance(payload, dict):
        return None
    body = payload.get("event") or {}
    if not isinstance(body, dict) or not body:
        return None
    kind = next(iter(body))
    detail = body.get(kind) or {}
    process = payload.get("process") or {}

    target = detail.get("target") if isinstance(detail, dict) else None
    subject = target if isinstance(target, dict) else process

    event = {
        "kind": kind,
        "ts": timeutil.to_iso(timeutil.parse(payload.get("time"), timeutil.now())),
        "pid": _pid(subject) or _pid(process),
        "ppid": subject.get("ppid") or process.get("ppid"),
        "uid": _audit(subject, "euid", _audit(process, "euid")),
        "user": _audit(subject, "username", _audit(process, "username")),
        "binary_path": _path(subject) or _path(process),
        "argv": _argv(detail),
        "cwd": (subject.get("cwd") or {}).get("path") if isinstance(
            subject.get("cwd"), dict) else subject.get("cwd"),
        "signing_id": subject.get("signing_id") or process.get("signing_id"),
        "team_id": subject.get("team_id") or process.get("team_id"),
        "cdhash": subject.get("cdhash") or process.get("cdhash"),
        "is_platform": subject.get("is_platform_binary",
                                   process.get("is_platform_binary")),
        "session_id": _audit(subject, "asid", _audit(process, "asid")),
        "es_seq": payload.get("seq_num"),
        "es_version": payload.get("version"),
    }
    if not event["binary_path"] and not event["pid"]:
        return None   # nothing identifiable: a schema change, not an event
    parent_path = _path(process)
    if parent_path and parent_path != event["binary_path"]:
        event["parent_path"] = parent_path
        event["parent_signing_id"] = process.get("signing_id")
    if kind in ("setextattr", "deleteextattr"):
        event["xattr"] = detail.get("extattr")
        event["target_path"] = _path(detail.get("target") or {})
    if kind == "btm_launch_item_add":
        item = detail.get("item") or {}
        event["launch_item"] = {
            "type": item.get("item_type"), "path": item.get("item_url"),
            "app": item.get("app_url"), "legacy": item.get("legacy"),
            "managed": item.get("managed")}
    return event


def _pid(node):
    if not isinstance(node, dict):
        return None
    token = node.get("audit_token") or {}
    return token.get("pid") if isinstance(token, dict) else node.get("pid")


def _audit(node, key, default=None):
    if not isinstance(node, dict):
        return default
    token = node.get("audit_token") or {}
    if isinstance(token, dict) and key in token:
        return token[key]
    return node.get(key, default)


def _path(node):
    if not isinstance(node, dict):
        return None
    executable = node.get("executable")
    if isinstance(executable, dict):
        return executable.get("path")
    if isinstance(node.get("path"), str):
        return node["path"]
    return None


def _argv(detail):
    if not isinstance(detail, dict):
        return []
    args = detail.get("args") or detail.get("argv")
    if isinstance(args, list):
        return [str(a) for a in args]
    return []
