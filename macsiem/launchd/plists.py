"""launchd integration: the "24/7/365" part.

Two jobs:

``com.macsiem.agent`` (LaunchDaemon, root)
    The sensors, detection engine and sweeps.  ``RunAtLoad`` + ``KeepAlive`` so
    it survives crashes and reboots, ``ThrottleInterval`` so a crash loop does
    not become a fork bomb, ``ProcessType: Background`` and low-priority I/O so
    it yields to the user's work.

``com.macsiem.sessionagent`` (LaunchAgent, per GUI user)
    Session-scoped probes only.

Two macOS facts this has to handle, and both are easy to get wrong:

1. ``/usr/bin/python3`` is a *stub* that requires Xcode Command Line Tools. On a
   clean Mac it tries to open a GUI installer dialog and fails -- fatal for a
   LaunchDaemon. ``preflight()`` checks for a real interpreter and refuses to
   install without one.
2. Full Disk Access is granted to the *responsible executable*. If that is
   ``/usr/bin/python3`` then FDA is being granted to system Python globally,
   which is not something anyone should do. The supported answer for a managed
   fleet is an MDM PPPC profile keyed to this job; ``preflight()`` says so.
"""

from __future__ import annotations

import os
import plistlib
import sys

DAEMON_LABEL = "com.macsiem.agent"
AGENT_LABEL = "com.macsiem.sessionagent"
DAEMON_PLIST = "/Library/LaunchDaemons/%s.plist" % DAEMON_LABEL
AGENT_PLIST = "/Library/LaunchAgents/%s.plist" % AGENT_LABEL
INSTALL_ROOT = "/usr/local/macsiem"


def daemon_plist(python=None, root=None, config_path=None):
    python = python or sys.executable
    root = root or INSTALL_ROOT
    arguments = [python, "-m", "macsiem"]
    if config_path:
        arguments += ["--config", config_path]
    arguments.append("daemon")
    return {
        "Label": DAEMON_LABEL,
        "ProgramArguments": arguments,
        "RunAtLoad": True,
        # Restart on crash, but not on a clean stop, and never faster than
        # every 10 seconds.
        "KeepAlive": {"SuccessfulExit": False, "Crashed": True},
        "ThrottleInterval": 10,
        "ProcessType": "Background",
        "LowPriorityIO": True,
        "LowPriorityBackgroundIO": True,
        "Nice": 5,
        "WorkingDirectory": root,
        "EnvironmentVariables": {"PYTHONPATH": root, "PYTHONUNBUFFERED": "1"},
        "StandardOutPath": "/var/log/macsiem/agent.out.log",
        "StandardErrorPath": "/var/log/macsiem/agent.err.log",
        "SoftResourceLimits": {"NumberOfFiles": 4096},
    }


def session_plist(python=None, root=None, config_path=None):
    python = python or sys.executable
    root = root or INSTALL_ROOT
    arguments = [python, "-m", "macsiem"]
    if config_path:
        arguments += ["--config", config_path]
    arguments.append("session-agent")
    return {
        "Label": AGENT_LABEL,
        "ProgramArguments": arguments,
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False, "Crashed": True},
        "ThrottleInterval": 10,
        "ProcessType": "Background",
        "LimitLoadToSessionType": "Aqua",
        "WorkingDirectory": root,
        "EnvironmentVariables": {"PYTHONPATH": root, "MACSIEM_SESSION_AGENT": "1"},
        "StandardOutPath": "/tmp/macsiem-session.out.log",
        "StandardErrorPath": "/tmp/macsiem-session.err.log",
    }


def preflight():
    """Checks that must pass before installing.  Returns ``(ok, messages)``."""
    messages = []
    ok = True
    if os.uname().sysname != "Darwin":
        return False, ["not macOS: launchd jobs can only be installed on a Mac"]
    if os.geteuid() != 0:
        ok = False
        messages.append("must be run as root (sudo) to write /Library/LaunchDaemons")

    interpreter = sys.executable
    if interpreter in ("/usr/bin/python3", "/usr/bin/python"):
        messages.append(
            "WARNING: %s is the Command Line Tools stub. If CLT is not installed "
            "the daemon will fail at launch with a GUI prompt no one will see. "
            "Install CLT (xcode-select --install) or point ProgramArguments at a "
            "real interpreter." % interpreter)
    messages.append(
        "Full Disk Access is granted to the responsible executable, which here is "
        "%s. For a managed fleet, deploy an MDM PPPC profile granting "
        "SystemPolicyAllFiles to this job rather than granting FDA to the "
        "interpreter by hand." % interpreter)
    return ok, messages


def install(config, uninstall=False, dry_run=False, python=None, root=None):
    ok, messages = preflight()
    for message in messages:
        sys.stdout.write(message + "\n")
    if not ok and not dry_run:
        return 1

    config_path = (config.get("_loaded_from") or [None])[0]
    jobs = [(DAEMON_PLIST, daemon_plist(python, root, config_path)),
            (AGENT_PLIST, session_plist(python, root, config_path))]

    if dry_run:
        for path, payload in jobs:
            sys.stdout.write("\n--- %s ---\n" % path)
            sys.stdout.write(plistlib.dumps(payload).decode("utf-8"))
        return 0

    from ..util import proc
    runner = proc.default_runner()
    if uninstall:
        for path, payload in jobs:
            domain = "system" if "LaunchDaemons" in path else "gui/%d" % os.getuid()
            runner.run(["/bin/launchctl", "bootout", "%s/%s" % (domain, payload["Label"])],
                       timeout=30)
            if os.path.exists(path):
                os.unlink(path)
                sys.stdout.write("removed %s\n" % path)
        return 0

    os.makedirs("/var/log/macsiem", mode=0o700, exist_ok=True)
    for path, payload in jobs:
        with open(path, "wb") as handle:
            plistlib.dump(payload, handle)
        os.chmod(path, 0o644)
        os.chown(path, 0, 0)
        sys.stdout.write("wrote %s\n" % path)
        domain = "system" if "LaunchDaemons" in path else "gui/%d" % os.getuid()
        runner.run(["/bin/launchctl", "bootout", "%s/%s" % (domain, payload["Label"])],
                   timeout=30)
        result = runner.run(["/bin/launchctl", "bootstrap", domain, path], timeout=30)
        if not result.ok:
            sys.stdout.write("  launchctl bootstrap: %s\n"
                             % (result.stderr.strip() or result.returncode))
    sys.stdout.write("\nNow run: macsiem doctor\n")
    return 0
