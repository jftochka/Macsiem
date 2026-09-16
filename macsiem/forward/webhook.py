"""HTTP webhook forwarder (Splunk HEC, Elastic, or anything that takes JSON).

Batched, non-blocking, and bounded: if the endpoint is down the queue drops
oldest-first rather than growing without limit.  urllib only -- no requests.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from collections import deque


class WebhookForwarder:
    name = "webhook"

    def __init__(self, settings):
        self.url = settings.get("url", "")
        self.auth_header = settings.get("auth_header", "")
        self.timeout = float(settings.get("timeout", 10))
        self.batch_size = int(settings.get("batch", 50))
        self.queue = deque(maxlen=int(settings.get("max_queue", 5000)))
        self.dropped = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="macsiem-webhook",
                                        daemon=True)
        if self.url:
            self._thread.start()

    def send(self, record, kind="event"):
        if not self.url:
            return False
        with self._lock:
            if len(self.queue) == self.queue.maxlen:
                self.dropped += 1
            self.queue.append({"type": kind, **record})
        return True

    def _loop(self):
        while not self._stop.wait(2.0):
            self._flush()

    def _flush(self):
        with self._lock:
            batch = [self.queue.popleft() for _ in range(min(self.batch_size,
                                                             len(self.queue)))]
        if not batch:
            return
        body = json.dumps({"records": batch}, sort_keys=True,
                          default=str).encode("utf-8")
        request = urllib.request.Request(self.url, data=body, method="POST")
        request.add_header("Content-Type", "application/json")
        if self.auth_header:
            name, _, value = self.auth_header.partition(":")
            request.add_header(name.strip(), value.strip())
        try:
            urllib.request.urlopen(request, timeout=self.timeout).close()
        except (urllib.error.URLError, OSError, ValueError):
            with self._lock:      # put them back at the front, oldest first
                for record in reversed(batch):
                    self.queue.appendleft(record)

    def close(self):
        self._stop.set()
        self._flush()
