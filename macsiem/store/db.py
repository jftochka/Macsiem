"""SQLite event store.

One file, WAL mode, append-only in spirit: the only DELETEs are retention
sweeps, and those are recorded in the custody chain so a gap in history is
itself evidence.

Thread-safety: a single connection guarded by a lock.  Sensors are I/O-bound
and the write volume (thousands of rows/minute at worst) is nowhere near where
a connection pool would earn its complexity.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading

from ..util import hashing, timeutil
from .chain import ChainWriter, verify_rows

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY,
    event_id TEXT UNIQUE NOT NULL,
    ts TEXT NOT NULL,
    sensor TEXT NOT NULL,
    kind TEXT NOT NULL,
    pid INTEGER, ppid INTEGER, uid INTEGER, user TEXT,
    binary_path TEXT, argv TEXT, cwd TEXT,
    signing_id TEXT, team_id TEXT, cdhash TEXT, is_platform INTEGER,
    record TEXT NOT NULL,
    chain_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_binary ON events(binary_path);
CREATE INDEX IF NOT EXISTS idx_events_pid ON events(pid);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    ts TEXT NOT NULL,
    loobin TEXT NOT NULL,
    use_case TEXT,
    signature_id TEXT,
    tactics TEXT, tags TEXT,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    rationale TEXT,
    sweep_id TEXT,
    acknowledged INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_loobin ON alerts(loobin);

CREATE TABLE IF NOT EXISTS sweeps (
    sweep_id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    tier TEXT NOT NULL,
    trigger_kind TEXT, trigger_id TEXT, reason TEXT,
    status TEXT NOT NULL,
    probe_total INTEGER DEFAULT 0,
    probe_ok INTEGER DEFAULT 0,
    probe_skipped INTEGER DEFAULT 0,
    probe_failed INTEGER DEFAULT 0,
    duration_ms INTEGER DEFAULT 0,
    bundle_id TEXT, bundle_path TEXT
);
CREATE INDEX IF NOT EXISTS idx_sweeps_ts ON sweeps(ts);

CREATE TABLE IF NOT EXISTS probe_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sweep_id TEXT NOT NULL,
    probe_id TEXT NOT NULL,
    loobin TEXT, category TEXT,
    started TEXT, duration_ms INTEGER,
    exit_code INTEGER, bytes INTEGER,
    stdout_sha256 TEXT, truncated INTEGER, timed_out INTEGER,
    skipped_reason TEXT, artifact TEXT, parsed TEXT, redactions TEXT
);
CREATE INDEX IF NOT EXISTS idx_probe_sweep ON probe_results(sweep_id);

CREATE TABLE IF NOT EXISTS baselines (
    key TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS custody (
    seq INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    bundle_id TEXT,
    actor TEXT, action TEXT, detail TEXT,
    record TEXT NOT NULL,
    chain_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_custody_bundle ON custody(bundle_id);

CREATE TABLE IF NOT EXISTS heartbeats (
    ts TEXT PRIMARY KEY,
    pid INTEGER, uptime_s INTEGER,
    sensors TEXT, queue_depth INTEGER, dropped INTEGER, note TEXT
);
"""


class Store:
    def __init__(self, path, host_id=None):
        self.path = path
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, mode=0o700, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.commit()
        self.host_id = host_id or hashing.host_identity()["host_uuid"]
        self._init_meta()
        self.events_chain = self._load_chain("events")
        self.custody_chain = self._load_chain("custody")

    # ---- lifecycle -------------------------------------------------------
    def _init_meta(self):
        with self._lock:
            existing = dict(
                (row["key"], row["value"])
                for row in self.conn.execute("SELECT key, value FROM meta"))
            if "genesis_events" not in existing:
                nonce = hashing.new_id()
                self.conn.executemany(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                    [("schema_version", str(SCHEMA_VERSION)),
                     ("host_id", self.host_id),
                     ("install_nonce", nonce),
                     ("installed_at", timeutil.now_iso()),
                     ("genesis_events", hashing.genesis(self.host_id, nonce + "/events")),
                     ("genesis_custody", hashing.genesis(self.host_id, nonce + "/custody"))])
                self.conn.commit()

    def meta(self, key, default=None):
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def _load_chain(self, table):
        genesis = self.meta("genesis_%s" % table)
        row = self.conn.execute(
            "SELECT seq, chain_hash FROM %s ORDER BY seq DESC LIMIT 1" % table).fetchone()
        if row:
            return ChainWriter(genesis, tip=row["chain_hash"], seq=row["seq"])
        return ChainWriter(genesis)

    def close(self):
        with self._lock:
            self.conn.commit()
            self.conn.close()

    # ---- writes ----------------------------------------------------------
    def add_event(self, event):
        """Append a normalized sensor event.  Returns the event_id."""
        event = dict(event)
        event.setdefault("event_id", hashing.new_id("evt"))
        event.setdefault("ts", timeutil.now_iso())
        with self._lock:
            seq, chain_hash, record = self.events_chain.append(event)
            self.conn.execute(
                """INSERT INTO events (seq, event_id, ts, sensor, kind, pid, ppid, uid,
                                       user, binary_path, argv, cwd, signing_id, team_id,
                                       cdhash, is_platform, record, chain_hash)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (seq, event["event_id"], event["ts"], event.get("sensor", "?"),
                 event.get("kind", "?"), event.get("pid"), event.get("ppid"),
                 event.get("uid"), event.get("user"), event.get("binary_path"),
                 json.dumps(event.get("argv") or []), event.get("cwd"),
                 event.get("signing_id"), event.get("team_id"), event.get("cdhash"),
                 1 if event.get("is_platform") else 0, record, chain_hash))
            self.conn.commit()
        return event["event_id"]

    def add_alert(self, alert):
        alert = dict(alert)
        alert.setdefault("alert_id", hashing.new_id("alrt"))
        alert.setdefault("ts", timeutil.now_iso())
        with self._lock:
            self.conn.execute(
                """INSERT OR REPLACE INTO alerts (alert_id, event_id, ts, loobin, use_case,
                        signature_id, tactics, tags, severity, confidence, rationale,
                        sweep_id, acknowledged)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (alert["alert_id"], alert.get("event_id", ""), alert["ts"],
                 alert.get("loobin", ""), alert.get("use_case"), alert.get("signature_id"),
                 json.dumps(alert.get("tactics") or []), json.dumps(alert.get("tags") or []),
                 alert.get("severity", "info"), float(alert.get("confidence", 0.0)),
                 json.dumps(alert.get("rationale") or []), alert.get("sweep_id"),
                 1 if alert.get("acknowledged") else 0))
            self.conn.commit()
        return alert["alert_id"]

    def start_sweep(self, sweep):
        sweep = dict(sweep)
        sweep.setdefault("sweep_id", hashing.new_id("swp"))
        sweep.setdefault("ts", timeutil.now_iso())
        with self._lock:
            self.conn.execute(
                """INSERT OR REPLACE INTO sweeps (sweep_id, ts, tier, trigger_kind,
                        trigger_id, reason, status)
                   VALUES (?,?,?,?,?,?,?)""",
                (sweep["sweep_id"], sweep["ts"], sweep.get("tier", "scoped"),
                 sweep.get("trigger_kind"), sweep.get("trigger_id"), sweep.get("reason"),
                 sweep.get("status", "running")))
            self.conn.commit()
        return sweep["sweep_id"]

    def finish_sweep(self, sweep_id, **fields):
        allowed = ("status", "probe_total", "probe_ok", "probe_skipped", "probe_failed",
                   "duration_ms", "bundle_id", "bundle_path")
        sets = [(k, v) for k, v in fields.items() if k in allowed]
        if not sets:
            return
        with self._lock:
            self.conn.execute(
                "UPDATE sweeps SET %s WHERE sweep_id = ?" % ", ".join(
                    "%s = ?" % k for k, _ in sets),
                [v for _, v in sets] + [sweep_id])
            self.conn.commit()

    def add_probe_result(self, sweep_id, result):
        with self._lock:
            self.conn.execute(
                """INSERT INTO probe_results (sweep_id, probe_id, loobin, category, started,
                        duration_ms, exit_code, bytes, stdout_sha256, truncated, timed_out,
                        skipped_reason, artifact, parsed, redactions)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (sweep_id, result.get("probe_id"), result.get("loobin"),
                 result.get("category"), result.get("started"), result.get("duration_ms", 0),
                 result.get("exit_code"), result.get("bytes", 0),
                 result.get("stdout_sha256"), 1 if result.get("truncated") else 0,
                 1 if result.get("timed_out") else 0, result.get("skipped_reason"),
                 result.get("artifact"),
                 json.dumps(result.get("parsed")) if result.get("parsed") is not None else None,
                 json.dumps(result.get("redactions") or {})))
            self.conn.commit()

    def set_baseline(self, key, payload):
        blob = json.dumps(payload, sort_keys=True, default=str)
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO baselines(key, ts, sha256, payload) VALUES (?,?,?,?)",
                (key, timeutil.now_iso(), hashing.sha256_text(blob), blob))
            self.conn.commit()

    def get_baseline(self, key, max_age_seconds=None):
        row = self.conn.execute(
            "SELECT ts, sha256, payload FROM baselines WHERE key = ?", (key,)).fetchone()
        if not row:
            return None
        if max_age_seconds is not None:
            age = (timeutil.now() - timeutil.parse(row["ts"], timeutil.now())).total_seconds()
            if age > max_age_seconds:
                return None
        return {"ts": row["ts"], "sha256": row["sha256"], "payload": json.loads(row["payload"])}

    def add_custody(self, bundle_id, actor, action, detail=None):
        """Chain-of-custody record.  Chained, so entries cannot be quietly dropped."""
        entry = {"ts": timeutil.now_iso(), "bundle_id": bundle_id, "actor": actor,
                 "action": action, "detail": detail}
        with self._lock:
            seq, chain_hash, record = self.custody_chain.append(entry)
            self.conn.execute(
                """INSERT INTO custody (seq, ts, bundle_id, actor, action, detail,
                                        record, chain_hash)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (seq, entry["ts"], bundle_id, actor, action,
                 json.dumps(detail) if detail is not None else None, record, chain_hash))
            self.conn.commit()
        return chain_hash

    def heartbeat(self, pid, uptime_s, sensors, queue_depth=0, dropped=0, note=None):
        with self._lock:
            self.conn.execute(
                """INSERT OR REPLACE INTO heartbeats (ts, pid, uptime_s, sensors,
                        queue_depth, dropped, note) VALUES (?,?,?,?,?,?,?)""",
                (timeutil.now_iso(), pid, uptime_s, json.dumps(sensors), queue_depth,
                 dropped, note))
            self.conn.commit()

    # ---- reads -----------------------------------------------------------
    def events_between(self, start, end, limit=5000):
        rows = self.conn.execute(
            "SELECT record FROM events WHERE ts >= ? AND ts <= ? ORDER BY ts LIMIT ?",
            (start, end, limit)).fetchall()
        return [json.loads(row["record"]) for row in rows]

    def event(self, event_id):
        row = self.conn.execute(
            "SELECT record FROM events WHERE event_id = ?", (event_id,)).fetchone()
        return json.loads(row["record"]) if row else None

    def alert(self, alert_id):
        row = self.conn.execute(
            "SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        return _alert_row(row) if row else None

    def recent_alerts(self, limit=50, min_severity=None):
        query = "SELECT * FROM alerts"
        params = []
        if min_severity:
            ranked = SEVERITY_ORDER.index(min_severity)
            query += " WHERE severity IN (%s)" % ",".join("?" * len(SEVERITY_ORDER[ranked:]))
            params.extend(SEVERITY_ORDER[ranked:])
        query += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        return [_alert_row(row) for row in self.conn.execute(query, params).fetchall()]

    def sweep(self, sweep_id):
        row = self.conn.execute(
            "SELECT * FROM sweeps WHERE sweep_id = ?", (sweep_id,)).fetchone()
        return dict(row) if row else None

    def probe_results(self, sweep_id):
        return [dict(row) for row in self.conn.execute(
            "SELECT * FROM probe_results WHERE sweep_id = ? ORDER BY probe_id",
            (sweep_id,)).fetchall()]

    def stats(self):
        counts = {}
        for table in ("events", "alerts", "sweeps", "probe_results", "custody"):
            counts[table] = self.conn.execute(
                "SELECT COUNT(*) AS n FROM %s" % table).fetchone()["n"]
        counts["db_bytes"] = os.path.getsize(self.path) if os.path.exists(self.path) else 0
        last = self.conn.execute(
            "SELECT ts FROM heartbeats ORDER BY ts DESC LIMIT 1").fetchone()
        counts["last_heartbeat"] = last["ts"] if last else None
        return counts

    # ---- integrity -------------------------------------------------------
    def verify(self, table="events"):
        rows = [{"seq": row["seq"], "record": json.loads(row["record"]),
                 "chain_hash": row["chain_hash"]}
                for row in self.conn.execute(
                    "SELECT seq, record, chain_hash FROM %s ORDER BY seq" % table)]
        return verify_rows(rows, self.meta("genesis_%s" % table))

    def prune(self, events_days=30, bundles_days=90):
        """Retention.  Deletions are themselves recorded in the custody chain."""
        cutoff = timeutil.to_iso(timeutil.now() - timeutil.parse_duration("%dd" % events_days))
        with self._lock:
            removed = self.conn.execute(
                "SELECT COUNT(*) AS n FROM events WHERE ts < ?", (cutoff,)).fetchone()["n"]
            if removed:
                self.conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
                self.conn.commit()
        if removed:
            self.add_custody(None, "retention", "prune_events",
                             {"cutoff": cutoff, "removed": removed})
        return removed


SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def severity_rank(name):
    try:
        return SEVERITY_ORDER.index(name)
    except ValueError:
        return 0


def _alert_row(row):
    alert = dict(row)
    for key in ("tactics", "tags", "rationale"):
        try:
            alert[key] = json.loads(alert.get(key) or "[]")
        except ValueError:
            alert[key] = []
    return alert
