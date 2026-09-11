"""RFC 5424 syslog over UDP or TCP."""

from __future__ import annotations

import json
import socket
import threading

from ..util import timeutil

SEVERITY_TO_PRI = {"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6}
FACILITY = 13   # log audit


class SyslogForwarder:
    name = "syslog"

    def __init__(self, settings):
        self.host = settings.get("host", "127.0.0.1")
        self.port = int(settings.get("port", 514))
        self.protocol = settings.get("protocol", "udp").lower()
        self.timeout = float(settings.get("timeout", 5))
        self._lock = threading.Lock()
        self._socket = None

    def _connect(self):
        if self._socket:
            return self._socket
        if self.protocol == "tcp":
            self._socket = socket.create_connection((self.host, self.port),
                                                    timeout=self.timeout)
        else:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return self._socket

    def send(self, record, kind="event"):
        severity = SEVERITY_TO_PRI.get(record.get("severity", "info"), 6)
        priority = FACILITY * 8 + severity
        message = "<%d>1 %s %s macsiem - %s %s" % (
            priority, timeutil.now_iso(), socket.gethostname(), kind.upper(),
            json.dumps(record, sort_keys=True, default=str))
        data = message.encode("utf-8", "replace")[:8192]
        with self._lock:
            try:
                sock = self._connect()
                if self.protocol == "tcp":
                    sock.sendall(data + b"\n")
                else:
                    sock.sendto(data, (self.host, self.port))
                return True
            except OSError:
                # Drop the socket so the next send reconnects; never raise into
                # the sensor path.
                self._socket = None
                return False

    def close(self):
        with self._lock:
            if self._socket:
                try:
                    self._socket.close()
                except OSError:
                    pass
                self._socket = None
