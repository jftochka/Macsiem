"""Apple Unified Logging sensor.

Secondary to Endpoint Security, and honest about it: the unified log does not
reliably carry process arguments, so events from here are stamped
``fidelity: medium`` and the engine discounts their confidence accordingly.

What it is genuinely good for is the things Endpoint Security does not report:
TCC prompts and grants, sudo, sshd, XProtect and Gatekeeper decisions.
"""

from __future__ import annotations

import json

from ..util import timeutil
from .base import Sensor

DEFAULT_PREDICATES = [
    'subsystem == "com.apple.TCC"',
    'process == "sudo" OR process == "sshd" OR process == "loginwindow"',
    'process == "XProtect" OR process == "XProtectRemediatorService"',
]


class UnifiedLogSensor(Sensor):
    name = "unified_log"
    fidelity = "medium"

    def run(self):
        predicates = self.settings().get("predicates") or DEFAULT_PREDICATES
        predicate = " OR ".join("(%s)" % p for p in predicates)
        argv = ["/usr/bin/log", "stream", "--style", "ndjson", "--info",
                "--predicate", predicate]
        stderr = []
        code = self.runner.stream(argv, self._on_line, self.stop_event, stderr)
        if code not in (0, None) and not self.stop_event.is_set():
            raise RuntimeError("log stream exited %s: %s" % (code, " ".join(stderr[-3:])))

    def _on_line(self, line):
        line = line.strip().rstrip(",")
        if not line.startswith("{"):
            return
        try:
            row = json.loads(line)
        except ValueError:
            return
        message = row.get("eventMessage") or ""
        if not message:
            return
        self.publish({
            "kind": "log",
            "ts": timeutil.to_iso(timeutil.parse(row.get("timestamp"), timeutil.now())),
            "pid": row.get("processID"),
            "binary_path": row.get("processImagePath"),
            "argv": [],
            "subsystem": row.get("subsystem"),
            "category": row.get("category"),
            "message": message[:2000],
        })
