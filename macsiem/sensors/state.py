"""Snapshot-and-diff sensors for the surfaces that have no event stream.

Persistence, network exposure and security posture do not emit Endpoint
Security events when they change in every case, so they are polled and diffed.
A change here is often the *consequence* of the LOOBin execution seen elsewhere:
``launchctl load`` shows up as a new job, ``spctl --master-disable`` shows up as
Gatekeeper flipping to disabled.  Correlating the two is what makes the bundle
tell a story.
"""

from __future__ import annotations

import glob
import os

from ..evidence import native
from .base import PollingSensor

PERSISTENCE_GLOBS = [
    "/Library/LaunchDaemons/*.plist", "/Library/LaunchAgents/*.plist",
    "/Users/*/Library/LaunchAgents/*.plist", "/Library/StartupItems/*",
    "/etc/periodic/*/*", "/usr/lib/cron/tabs/*",
]


class PersistenceSensor(PollingSensor):
    name = "persistence"
    fidelity = "high"
    interval = 60
    change_kind = "persistence"

    def snapshot(self):
        state = {}
        for pattern in PERSISTENCE_GLOBS:
            for path in sorted(glob.glob(pattern))[:400]:
                try:
                    info = os.lstat(path)
                except OSError:
                    continue
                state[path] = {"bytes": info.st_size, "mtime": int(info.st_mtime),
                               "uid": info.st_uid, "mode": info.st_mode}
        return state

    def diff(self, previous, current):
        changes = super().diff(previous, current)
        for change in changes:
            path = change["key"]
            change["binary_path"] = path
            change["argv"] = []
            if path.endswith(".plist") and change["change"] in ("added", "modified"):
                parsed = native.read_plists({"paths": [path]})
                files = parsed.get("files") or [{}]
                plist = files[0].get("plist") or {}
                if isinstance(plist, dict):
                    change["launch_item"] = {
                        "label": plist.get("Label"),
                        "program": plist.get("Program"),
                        "arguments": plist.get("ProgramArguments"),
                        "run_at_load": plist.get("RunAtLoad"),
                        "keep_alive": plist.get("KeepAlive"),
                        "start_interval": plist.get("StartInterval"),
                    }
        return changes


class NetworkSensor(PollingSensor):
    name = "network"
    fidelity = "high"
    interval = 60
    change_kind = "network"

    def snapshot(self):
        result = self.runner.run(["/usr/sbin/netstat", "-an"], timeout=20)
        if not result.ok:
            return None
        listeners = {}
        for line in result.stdout.splitlines():
            if "LISTEN" in line:
                fields = line.split()
                if len(fields) >= 4:
                    listeners[fields[3]] = {"proto": fields[0], "line": line.strip()}
        return listeners


class PostureSensor(PollingSensor):
    """SIP, Gatekeeper, FileVault and firewall state.

    A change here is high severity by construction: these do not move on their
    own.  ``csrutil disable`` requires a reboot from Recovery, so seeing SIP
    flip while the agent is running is, by itself, an incident.
    """

    name = "posture"
    fidelity = "high"
    interval = 300
    change_kind = "posture"

    CHECKS = [
        ("sip", ["/usr/bin/csrutil", "status"]),
        ("gatekeeper", ["/usr/sbin/spctl", "--status"]),
        ("filevault", ["/usr/bin/fdesetup", "status"]),
    ]

    def snapshot(self):
        state = {}
        for label, argv in self.CHECKS:
            result = self.runner.run(argv, timeout=15)
            state[label] = result.stdout.strip() if result.ok else "unavailable"
        firewall = native.read_plists(
            {"paths": ["/Library/Preferences/com.apple.alf.plist"]})
        for entry in firewall.get("files", []):
            plist = entry.get("plist")
            if isinstance(plist, dict):
                state["firewall_globalstate"] = plist.get("globalstate")
        return state

    def diff(self, previous, current):
        changes = super().diff(previous, current)
        for change in changes:
            change["binary_path"] = "macsiem:posture"
            change["argv"] = []
            change["severity_hint"] = "critical"
        return changes


SENSORS = {}


def registry():
    """Built lazily so importing a sensor module never pulls in the rest."""
    if not SENSORS:
        from .eslogger import EsloggerSensor
        from .procpoll import ProcPollSensor
        from .unifiedlog import UnifiedLogSensor
        SENSORS.update({
            "eslogger": EsloggerSensor,
            "unified_log": UnifiedLogSensor,
            "procpoll": ProcPollSensor,
            "persistence": PersistenceSensor,
            "network": NetworkSensor,
            "posture": PostureSensor,
        })
    return SENSORS
