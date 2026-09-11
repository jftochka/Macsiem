"""Context factors -- the part that decides whether a match is worth waking someone.

``sw_vers`` run by the MDM agent at 3am is noise; ``sw_vers`` run by a shell
whose grandparent is an unsigned binary in ~/Downloads is the second command of
an intrusion.  The rule matched identically in both cases.  These factors are
the difference, and every one that fires is written into the alert's rationale
so an analyst can see exactly why it scored what it scored.
"""

from __future__ import annotations

import os
import re

from ..util import timeutil

#: Parents that make a LOOBin execution more interesting, not less.
INTERACTIVE_SHELLS = {"bash", "zsh", "sh", "dash", "ksh", "csh", "tcsh", "fish"}
SCRIPT_HOSTS = {"osascript", "python3", "python", "perl", "ruby", "node", "swift",
                "tclsh", "php", "java", "osacompile"}
#: Anything spawned by these has a plausible phishing/drive-by origin.
DOCUMENT_APPS = {"Microsoft Word", "Microsoft Excel", "Microsoft PowerPoint",
                 "Safari", "Google Chrome", "Firefox", "Microsoft Edge", "Mail",
                 "Slack", "Preview", "Messages", "WhatsApp", "Telegram", "Arc",
                 "Brave Browser", "zoom.us", "Adobe Acrobat", "Adobe Reader"}
#: Well-known management/security tooling.  These legitimately run LOOBins.
MANAGEMENT_SIGNERS = {
    "com.jamf.management.daemon", "com.jamfsoftware.jamf", "com.microsoft.intune",
    "com.kandji.agent", "com.addigy.agent", "com.mosyle.agent", "com.workspaceone",
    "com.crowdstrike.falcon", "com.sentinelone.agent", "com.elastic.endpoint",
    "com.paloaltonetworks.cortex", "osqueryd", "com.apple.MDMClient",
    "com.vmware.hub", "com.watchman.monitoring",
}
VOLATILE_DIRS = ("/tmp/", "/private/tmp/", "/var/folders/", "/Volumes/",
                 "/Users/Shared/", "/private/var/tmp/")
DOWNLOAD_DIRS = ("/Downloads/", "/Desktop/", "/Library/Caches/")

_USER_DIR = re.compile(r"^/Users/[^/]+")


class Context:
    """Derived facts about one event, computed once and reused by every rule."""

    def __init__(self, event, ancestry=None, config=None, known_hashes=None):
        self.event = event or {}
        self.ancestry = ancestry or []
        self.config = config or {}
        self.known_hashes = known_hashes if known_hashes is not None else set()
        self.factors = []

    # -- individual factors ------------------------------------------------
    def _add(self, name, delta, detail=None):
        self.factors.append({"factor": name, "delta": delta, "detail": detail})
        return delta

    def parent(self):
        return self.ancestry[0] if self.ancestry else {}

    def evaluate(self):
        """Return ``(total_delta, factors)``.  Positive means more suspicious."""
        self.factors = []
        event = self.event
        total = 0
        parent = self.parent()
        parent_name = os.path.basename(parent.get("binary_path") or "")

        if parent_name in INTERACTIVE_SHELLS:
            total += self._add("parent_is_shell", 10, parent_name)
        if parent_name in SCRIPT_HOSTS:
            total += self._add("parent_is_script_host", 15, parent_name)

        for ancestor in self.ancestry:
            app = _app_name(ancestor.get("binary_path") or "")
            if app in DOCUMENT_APPS:
                total += self._add("ancestor_is_user_facing_app", 20, app)
                break

        responsible = (event.get("responsible_signing_id")
                       or parent.get("signing_id") or "")
        if responsible in MANAGEMENT_SIGNERS:
            total += self._add("responsible_is_management_tool", -35, responsible)
        elif event.get("signing_id", "").startswith("com.apple.") and event.get("is_platform"):
            # Apple's own binary doing Apple's own thing: still recorded, just calmer.
            total += self._add("platform_binary", -5, event.get("signing_id"))

        for ancestor in self.ancestry:
            if ancestor.get("is_platform") is False and not ancestor.get("team_id"):
                total += self._add("unsigned_ancestor", 12,
                                   ancestor.get("binary_path"))
                break

        path = event.get("binary_path") or ""
        if path and not _is_canonical(path):
            total += self._add("binary_outside_system_paths", 20, path)
        for ancestor in self.ancestry:
            ancestor_path = ancestor.get("binary_path") or ""
            if ancestor_path.startswith(VOLATILE_DIRS):
                total += self._add("ancestor_runs_from_temp", 18, ancestor_path)
                break
            if any(marker in ancestor_path for marker in DOWNLOAD_DIRS):
                total += self._add("ancestor_from_download_dir", 15, ancestor_path)
                break

        if event.get("quarantined") or any(a.get("quarantined") for a in self.ancestry):
            total += self._add("quarantine_xattr_present", 15)

        if event.get("uid") == 0:
            total += self._add("running_as_root", 8)
        if event.get("via_sudo"):
            total += self._add("elevated_via_sudo", 8)

        cdhash = event.get("cdhash")
        if cdhash and self.known_hashes and cdhash not in self.known_hashes:
            total += self._add("first_seen_binary_on_host", 8, cdhash[:16])

        if event.get("ssh_session") or (event.get("tty") or "").startswith("/dev/ttys") \
                and event.get("remote_login"):
            total += self._add("remote_session", 12)

        hours = (self.config.get("detection") or {}).get("business_hours") or {}
        if hours:
            timestamp = timeutil.parse(event.get("ts"))
            if timestamp is not None:
                hour = (timestamp.hour + int(hours.get("timezone_offset", 0))) % 24
                if not (int(hours.get("start", 8)) <= hour < int(hours.get("end", 19))):
                    total += self._add("outside_business_hours", 6, "%02d:00" % hour)

        fidelity = event.get("fidelity", "high")
        if fidelity != "high":
            total += self._add("degraded_telemetry", -5, fidelity)
        return total, list(self.factors)


def _app_name(path):
    match = re.search(r"/([^/]+)\.app/", path or "")
    return match.group(1) if match else os.path.basename(path or "")


CANONICAL_PREFIXES = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/libexec/",
                      "/System/", "/Library/Apple/", "/Applications/",
                      "/opt/homebrew/", "/usr/local/")


def _is_canonical(path):
    return path.startswith(CANONICAL_PREFIXES)


def fidelity_factor(fidelity):
    """Confidence multiplier for the sensor that produced an event."""
    return {"high": 1.0, "medium": 0.85, "low": 0.7}.get(fidelity or "high", 0.85)
