"""Process polling: the fallback when Endpoint Security is unavailable.

Deliberately labelled ``fidelity: low``.  A 5-second poll misses short-lived
processes, which is exactly what LOOBins abuse looks like -- ``csrutil
disable`` is over in milliseconds.  This exists so a host without root or
Full Disk Access still produces *some* telemetry, not so anyone can pretend it
is equivalent.
"""

from __future__ import annotations

import os

from ..correlate.proctree import parse_ps
from .base import PollingSensor


class ProcPollSensor(PollingSensor):
    name = "procpoll"
    fidelity = "low"
    interval = 5
    change_kind = "exec"

    def snapshot(self):
        result = self.runner.run(
            ["/bin/ps", "-Ao", "pid,ppid,uid,user,%cpu,%mem,lstart,tty,stat,command"],
            timeout=20)
        if not result.ok:
            return None
        return parse_ps(result.stdout)

    def diff(self, previous, current):
        events = []
        for pid in sorted(set(current) - set(previous)):
            record = current[pid]
            events.append({
                "kind": "exec",
                "pid": pid,
                "ppid": record.get("ppid"),
                "uid": record.get("uid"),
                "user": record.get("user"),
                "binary_path": record.get("binary_path"),
                "argv": _argv(record.get("command")),
            })
        return events


def _argv(command):
    """`ps` gives one string; split on spaces and accept the imprecision.

    Arguments containing spaces are mis-split here.  That is a real limitation
    of ps-based collection and another reason this sensor is low fidelity.
    """
    if not command:
        return []
    parts = command.split(" ")
    return [part for part in parts if part]
