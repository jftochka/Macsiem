"""Configuration: layered defaults -> file -> environment -> flags.

Defaults are chosen so that ``macsiem install`` on a fresh Mac produces a
working 24/7 agent with no config file at all.  Everything here is documented
in docs/DEPLOY.md.
"""

from __future__ import annotations

import copy
import json
import os

CONFIG_PATHS = ("/etc/macsiem/config.json", os.path.expanduser("~/.config/macsiem/config.json"))
ENV_PREFIX = "MACSIEM_"

DEFAULTS = {
    "agent": {
        "enabled": True,
        "heartbeat_seconds": 60,
        "queue_max": 20000,
        "sensor_restart_backoff": [1, 2, 5, 15, 30, 60],
    },
    "paths": {
        # Overridden to ~/.macsiem when not running as root (see resolve_paths).
        "data_dir": "/var/db/macsiem",
        "log_dir": "/var/log/macsiem",
        "bundle_dir": "/var/db/macsiem/bundles",
        "socket": "/var/run/macsiem-session.sock",
    },
    "sensors": {
        "eslogger": {
            "enabled": True,
            "path": "/usr/bin/eslogger",
            # Event set kept deliberately tight: every added event type is
            # continuous host load.  These cover LOOBins execution, persistence
            # installation, and anti-forensics.
            "events": [
                "exec", "fork", "exit", "open", "create", "rename", "unlink",
                "setextattr", "deleteextattr", "setmode", "setowner", "link",
                "mount", "signal", "cs_invalidated", "remote_thread_create",
                "btm_launch_item_add", "btm_launch_item_remove",
                "login_login", "login_logout", "screensharing_attach",
                "su", "sudo", "profile_add", "xp_malware_detected",
            ],
        },
        "unified_log": {
            "enabled": True,
            "predicates": [
                'subsystem == "com.apple.TCC"',
                'subsystem == "com.apple.securityd"',
                'process == "XProtect" OR process == "XProtectRemediatorService"',
                'eventMessage CONTAINS[c] "Gatekeeper"',
                'process == "sudo" OR process == "sshd" OR process == "loginwindow"',
            ],
        },
        "procpoll": {"enabled": True, "interval_seconds": 5},
        "persistence": {"enabled": True, "interval_seconds": 60},
        "network": {"enabled": True, "interval_seconds": 60},
        "posture": {"enabled": True, "interval_seconds": 300},
    },
    "detection": {
        "min_alert_severity": "low",
        "telemetry_only_tactics": ["Reconnaissance"],
        "suppressions": [],
        "business_hours": {"start": 8, "end": 19, "timezone_offset": 0},
    },
    "sweep": {
        # Tiered execution: every alert gets a scoped record; a full 62-binary
        # sweep fires at this severity and above, on demand, or on a stale cache.
        "full_sweep_min_severity": "medium",
        "workers": 8,
        "default_timeout": 15,
        "expensive_timeout": 90,
        "max_output_bytes": 4194304,
        "max_full_sweeps_per_hour": 12,
        "dedup_window_seconds": 300,
        "baseline_ttl_seconds": 3600,
        "baseline_refresh_seconds": 3600,
        "nice": 10,
    },
    "privacy": {
        # User decision: content capture is ON.  Every capture is written to the
        # bundle's chain-of-custody log, bundles are 0700, and this one switch
        # turns the whole class off.  See docs/PRIVACY.md.
        "capture_content": True,
        "capture_screenshot": True,
        "capture_clipboard": True,
        "capture_browser_data": True,
        "redact_secrets": True,
    },
    "retention": {
        "events_days": 30,
        "bundles_days": 90,
        "max_store_mb": 2048,
        "max_bundles_mb": 20480,
        "protect_unacknowledged": True,
    },
    "forward": {
        "jsonl": {"enabled": True, "path": "/var/log/macsiem/events.jsonl", "max_mb": 256},
        "syslog": {"enabled": False, "host": "127.0.0.1", "port": 514, "protocol": "udp"},
        "webhook": {"enabled": False, "url": "", "auth_header": "", "timeout": 10,
                    "batch": 50},
    },
}


def _deep_merge(base, overlay):
    result = copy.deepcopy(base)
    for key, value in (overlay or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _coerce(text):
    lowered = text.strip().lower()
    if lowered in ("true", "yes", "on"):
        return True
    if lowered in ("false", "no", "off"):
        return False
    if lowered in ("null", "none"):
        return None
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    if text.startswith(("[", "{")):
        try:
            return json.loads(text)
        except ValueError:
            pass
    return text


def _env_overlay(environ):
    """``MACSIEM_SWEEP__WORKERS=4`` -> ``{"sweep": {"workers": 4}}``."""
    overlay = {}
    for key, value in environ.items():
        if not key.startswith(ENV_PREFIX):
            continue
        path = key[len(ENV_PREFIX):].lower().split("__")
        cursor = overlay
        for part in path[:-1]:
            cursor = cursor.setdefault(part, {})
        cursor[path[-1]] = _coerce(value)
    return overlay


class Config(dict):
    """A plain dict with dotted lookup, so callers stay readable."""

    def get_path(self, dotted, default=None):
        cursor = self
        for part in dotted.split("."):
            if not isinstance(cursor, dict) or part not in cursor:
                return default
            cursor = cursor[part]
        return cursor

    def set_path(self, dotted, value):
        parts = dotted.split(".")
        cursor = self
        for part in parts[:-1]:
            cursor = cursor.setdefault(part, {})
        cursor[parts[-1]] = value
        return self

    @property
    def data_dir(self):
        return self.get_path("paths.data_dir")

    @property
    def bundle_dir(self):
        return self.get_path("paths.bundle_dir")

    @property
    def db_path(self):
        return os.path.join(self.data_dir, "macsiem.db")


def resolve_paths(config):
    """Relocate state under ``~/.macsiem`` when not root.

    An analyst running ``macsiem investigate`` as themselves should not fail on
    ``/var/db``; the daemon runs as root and uses the system paths.
    """
    if os.geteuid() == 0:
        return config
    home = os.path.expanduser("~/.macsiem")
    if config.get_path("paths.data_dir") == DEFAULTS["paths"]["data_dir"]:
        config.set_path("paths.data_dir", home)
        config.set_path("paths.bundle_dir", os.path.join(home, "bundles"))
    if config.get_path("paths.log_dir") == DEFAULTS["paths"]["log_dir"]:
        config.set_path("paths.log_dir", os.path.join(home, "log"))
    if config.get_path("forward.jsonl.path") == DEFAULTS["forward"]["jsonl"]["path"]:
        config.set_path("forward.jsonl.path", os.path.join(home, "log", "events.jsonl"))
    if config.get_path("paths.socket") == DEFAULTS["paths"]["socket"]:
        config.set_path("paths.socket", os.path.join(home, "session.sock"))
    return config


def load(path=None, overlay=None, environ=None):
    """Build the effective configuration."""
    config = copy.deepcopy(DEFAULTS)
    candidates = [path] if path else list(CONFIG_PATHS)
    loaded_from = []
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            try:
                with open(candidate, "r") as handle:
                    config = _deep_merge(config, json.load(handle))
                loaded_from.append(candidate)
            except (OSError, ValueError) as exc:
                # A broken config file must not silently revert to defaults.
                raise SystemExit("macsiem: bad config %s: %s" % (candidate, exc))
    config = _deep_merge(config, _env_overlay(
        os.environ if environ is None else environ))
    config = _deep_merge(config, overlay or {})
    result = Config(config)
    result["_loaded_from"] = loaded_from
    return resolve_paths(result)


def ensure_dirs(config, mode=0o700):
    """Create state directories.  0700 because bundles carry captured content."""
    for key in ("data_dir", "log_dir", "bundle_dir"):
        directory = config.get_path("paths.%s" % key)
        if directory:
            os.makedirs(directory, mode=mode, exist_ok=True)
            try:
                os.chmod(directory, mode)
            except OSError:
                pass
    return config
