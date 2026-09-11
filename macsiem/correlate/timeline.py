"""Merge everything time-stamped into one chronological account.

The point of a 360 sweep is not 92 files, it is a single ordering.  Sensor
events, alerts, quarantine records, login history, TCC grant changes, file
timestamps and unified-log lines all carry a time; this puts them on one axis so
"what happened around 21:04" has an answer.
"""

from __future__ import annotations

import os

from ..util import timeutil


def from_events(events):
    entries = []
    for event in events:
        argv = event.get("argv") or []
        entries.append({
            "ts": event.get("ts"),
            "source": "sensor:%s" % event.get("sensor", "?"),
            "kind": event.get("kind", "event"),
            "summary": " ".join(argv) if argv else (event.get("binary_path") or ""),
            "pid": event.get("pid"),
            "user": event.get("user"),
            "ref": event.get("event_id"),
        })
    return entries


def from_alerts(alerts):
    return [{
        "ts": alert.get("ts"),
        "source": "detection",
        "kind": "alert",
        "severity": alert.get("severity"),
        "summary": "%s: %s" % (alert.get("loobin"), alert.get("use_case")
                               or alert.get("signature_id")),
        "ref": alert.get("alert_id"),
    } for alert in alerts]


def from_probe_results(results):
    """Pull time-stamped facts out of probe output.

    Each extractor is deliberately narrow: it is better to contribute nothing
    than to invent a timestamp.
    """
    entries = []
    for result in results:
        probe_id = result.get("probe_id")
        parsed = result.get("parsed")
        if probe_id == "provenance.quarantine_events" and isinstance(parsed, dict):
            for database in parsed.get("databases", []):
                for row in database.get("rows") or []:
                    stamp = row.get("LSQuarantineTimeStamp")
                    when = timeutil.from_epoch(float(stamp) + 978307200) if stamp else None
                    entries.append({
                        "ts": timeutil.to_iso(when) if when else None,
                        "source": "probe:%s" % probe_id, "kind": "download",
                        "summary": "downloaded via %s from %s" % (
                            row.get("LSQuarantineAgentName") or "?",
                            row.get("LSQuarantineDataURLString")
                            or row.get("LSQuarantineOriginURLString") or "?"),
                    })
        elif probe_id in ("tcc.system_db", "tcc.user_db") and isinstance(parsed, dict):
            for database in parsed.get("databases", []):
                for row in database.get("rows") or []:
                    stamp = row.get("last_modified")
                    when = timeutil.from_epoch(float(stamp)) if stamp else None
                    entries.append({
                        "ts": timeutil.to_iso(when) if when else None,
                        "source": "probe:%s" % probe_id, "kind": "tcc_grant",
                        "summary": "%s -> %s (auth=%s)" % (
                            row.get("client"), row.get("service"), row.get("auth_value")),
                    })
        elif probe_id == "identity.logins":
            for line in (result.get("stdout") or "").splitlines()[:50]:
                if line.strip() and not line.startswith("wtmp"):
                    entries.append({"ts": None, "source": "probe:%s" % probe_id,
                                    "kind": "login", "summary": line.strip()})
        elif probe_id in ("storage.tmp_recent", "storage.recent_downloads") \
                and isinstance(parsed, dict):
            for entry in (parsed.get("files") or [])[:100]:
                entries.append({
                    "ts": entry.get("mtime"), "source": "probe:%s" % probe_id,
                    "kind": "file_write",
                    "summary": "%s (%s bytes)" % (entry.get("path"), entry.get("bytes"))})
        elif probe_id == "persistence.launchd_plists" and isinstance(parsed, dict):
            for entry in parsed.get("files") or []:
                plist = entry.get("plist") or {}
                if not isinstance(plist, dict):
                    continue
                arguments = plist.get("ProgramArguments") or []
                entries.append({
                    "ts": entry.get("mtime"), "source": "probe:%s" % probe_id,
                    "kind": "persistence",
                    "summary": "%s -> %s" % (
                        os.path.basename(entry.get("path", "")),
                        " ".join(arguments) if isinstance(arguments, list)
                        else plist.get("Program", ""))})
        elif result.get("parser") == "ndjson" and isinstance(parsed, list):
            for row in parsed[:400]:
                entries.append({
                    "ts": timeutil.to_iso(timeutil.parse(row.get("timestamp"),
                                                         timeutil.now())),
                    "source": "probe:%s" % probe_id, "kind": "log",
                    "summary": "%s: %s" % (row.get("processImagePath")
                                           or row.get("process") or "?",
                                           (row.get("eventMessage") or "")[:200])})
    return entries


def build(events=None, alerts=None, results=None, limit=5000):
    entries = []
    entries.extend(from_events(events or []))
    entries.extend(from_alerts(alerts or []))
    entries.extend(from_probe_results(results or []))
    dated = [entry for entry in entries if entry.get("ts")]
    undated = [entry for entry in entries if not entry.get("ts")]
    dated.sort(key=lambda entry: entry["ts"])
    return {"entries": dated[:limit], "undated": undated[:500],
            "count": len(dated), "undated_count": len(undated)}


def window_slice(timeline, center, before="30m", after="30m"):
    start, end = timeutil.window(center, before, after)
    start_iso, end_iso = timeutil.to_iso(start), timeutil.to_iso(end)
    return [entry for entry in timeline.get("entries", [])
            if start_iso <= entry["ts"] <= end_iso]
