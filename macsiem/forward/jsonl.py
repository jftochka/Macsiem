"""Append-only JSONL on disk, size-capped with one rotation."""

from __future__ import annotations

import json
import os
import threading


class JsonlForwarder:
    name = "jsonl"

    def __init__(self, settings):
        self.path = settings.get("path", "/var/log/macsiem/events.jsonl")
        self.max_bytes = int(settings.get("max_mb", 256)) * 1024 * 1024
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)

    def send(self, record, kind="event"):
        line = json.dumps({"type": kind, **record}, sort_keys=True, default=str)
        with self._lock:
            try:
                if os.path.exists(self.path) and os.path.getsize(self.path) > self.max_bytes:
                    os.replace(self.path, self.path + ".1")
                with open(self.path, "a") as handle:
                    handle.write(line + "\n")
            except OSError:
                return False
        return True

    def close(self):
        pass
