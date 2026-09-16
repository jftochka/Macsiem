"""Process ancestry reconstruction.

Two sources, because neither is sufficient alone: the event store knows about
processes that have already exited (the interesting ones usually have), and a
live ``ps`` snapshot knows about processes that started before the agent did.
"""

from __future__ import annotations

import os
import re

_PS_LINE = re.compile(
    r"^\s*(?P<pid>\d+)\s+(?P<ppid>\d+)\s+(?P<uid>\d+)\s+(?P<user>\S+)\s+"
    r"(?P<rest>.*)$")


def parse_ps(text):
    """Parse ``ps -Ao pid,ppid,uid,user,...,command`` output."""
    processes = {}
    for line in (text or "").splitlines()[1:]:
        match = _PS_LINE.match(line)
        if not match:
            continue
        rest = match.group("rest")
        # The command is everything from the first absolute path or last field
        # group; ps pads lstart with spaces, so anchor on the path.
        command_at = rest.find("/")
        command = rest[command_at:] if command_at >= 0 else rest.split()[-1]
        pid = int(match.group("pid"))
        processes[pid] = {
            "pid": pid,
            "ppid": int(match.group("ppid")),
            "uid": int(match.group("uid")),
            "user": match.group("user"),
            "command": command.strip(),
            "binary_path": command.strip().split(" ")[0],
            "source": "ps",
        }
    return processes


def index_events(events):
    """Latest exec event per PID, for ancestry lookups."""
    by_pid = {}
    for event in events:
        pid = event.get("pid")
        if pid is None or event.get("kind") not in ("exec", "fork", "process"):
            continue
        existing = by_pid.get(pid)
        if not existing or (event.get("ts") or "") >= (existing.get("ts") or ""):
            by_pid[pid] = event
    return by_pid


def ancestry(pid, by_pid, ps=None, limit=12):
    """Walk parents.  Stops at launchd, at an unknown PID, or at ``limit``."""
    ps = ps or {}
    chain = []
    seen = set()
    current = pid
    while current and current not in seen and len(chain) < limit:
        seen.add(current)
        record = by_pid.get(current) or ps.get(current)
        if not record:
            break
        parent = record.get("ppid")
        if current != pid:
            chain.append(_normalize(record))
        if parent in (0, 1) or parent is None:
            if parent == 1 and current != pid:
                break
            if parent in (0, 1):
                break
        current = parent
    return chain


def descendants(pid, by_pid, ps=None, limit=200):
    """Everything spawned by a PID, breadth-first."""
    ps = ps or {}
    combined = dict(ps)
    combined.update(by_pid)
    children = {}
    for record in combined.values():
        children.setdefault(record.get("ppid"), []).append(record)
    found, queue = [], [pid]
    while queue and len(found) < limit:
        current = queue.pop(0)
        for child in children.get(current, []):
            if child.get("pid") == current:
                continue
            found.append(_normalize(child))
            queue.append(child.get("pid"))
    return found


def tree_text(root, chain, kids, indent="  "):
    """A readable tree for the narrative and the HTML report."""
    lines = []
    for depth, node in enumerate(reversed(chain)):
        lines.append("%s%s [%s] %s" % (indent * depth, node.get("pid"),
                                       node.get("user") or "?",
                                       node.get("command") or node.get("binary_path")))
    depth = len(chain)
    lines.append("%s%s [%s] %s   <-- subject" % (
        indent * depth, root.get("pid"), root.get("user") or "?",
        root.get("command") or root.get("binary_path")))
    for child in kids[:25]:
        lines.append("%s%s [%s] %s" % (indent * (depth + 1), child.get("pid"),
                                       child.get("user") or "?",
                                       child.get("command") or child.get("binary_path")))
    return "\n".join(lines)


def _normalize(record):
    command = record.get("command")
    if not command and record.get("argv"):
        command = " ".join(record["argv"])
    return {
        "pid": record.get("pid"),
        "ppid": record.get("ppid"),
        "uid": record.get("uid"),
        "user": record.get("user"),
        "binary_path": record.get("binary_path"),
        "name": os.path.basename(record.get("binary_path") or ""),
        "command": command or record.get("binary_path"),
        "ts": record.get("ts"),
        "signing_id": record.get("signing_id"),
        "is_platform": record.get("is_platform"),
        "source": record.get("source", "event"),
    }
