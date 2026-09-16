"""Event forwarding.  Local-first: the store is the source of truth, forwarders
are best-effort copies, and a forwarder that fails must never block a sensor.
"""

from __future__ import annotations


def build(config):
    forwarders = []
    settings = config.get("forward") or {}
    if (settings.get("jsonl") or {}).get("enabled"):
        from .jsonl import JsonlForwarder
        forwarders.append(JsonlForwarder(settings["jsonl"]))
    if (settings.get("syslog") or {}).get("enabled"):
        from .syslog import SyslogForwarder
        forwarders.append(SyslogForwarder(settings["syslog"]))
    if (settings.get("webhook") or {}).get("enabled"):
        from .webhook import WebhookForwarder
        forwarders.append(WebhookForwarder(settings["webhook"]))
    return forwarders
