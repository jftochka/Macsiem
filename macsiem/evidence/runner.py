"""Execute one probe and normalize the result.

Slot substitution happens here, and every substituted value is untrusted (it
came from an event).  Values go into a single argv element, are re-validated by
:func:`macsiem.evidence.safety.validate_runtime_argv`, and never touch a shell.

Exec probes additionally run with ``RLIMIT_FSIZE = 0`` where the platform
supports it, so the kernel refuses any file write regardless of what the argv
says.  The one probe that is *meant* to write -- the opt-in screenshot -- is
exempted explicitly and its destination is forced inside the bundle directory.
"""

from __future__ import annotations

import json
import os
import re

from ..util import hashing, proc, redact, timeutil
from . import native, safety

SLOT_PATTERN = re.compile(r"\{(target_path|target_pid|target_user|window_start|"
                          r"window_end|artifact)\}")


class ProbeResult(dict):
    """A probe outcome.  Plain dict so it serializes into the manifest directly."""

    @property
    def ok(self):
        return not self.get("skipped_reason") and self.get("exit_code") in (0, None) \
            and not self.get("error")


def substitute(argv, ctx):
    """Replace declared slots.  A missing slot makes the probe unrunnable."""
    out, missing = [], []
    for element in argv:
        def _replace(match):
            key = match.group(1)
            value = ctx.get(key)
            if value is None or value == "":
                missing.append(key)
                return match.group(0)
            return str(value)
        out.append(SLOT_PATTERN.sub(_replace, element))
    return out, sorted(set(missing))


def capabilities(runner=None, geteuid=None):
    """What can this host actually do?  Drives skipping and coverage reporting."""
    geteuid = geteuid or os.geteuid
    root = geteuid() == 0
    caps = {
        "root": root,
        # Full Disk Access cannot be queried directly; reading a TCC-protected
        # path is the standard probe for it.
        "fda": os.access("/Library/Application Support/com.apple.TCC/TCC.db", os.R_OK),
        "session": bool(os.environ.get("MACSIEM_SESSION_AGENT")),
        "eslogger": os.path.exists("/usr/bin/eslogger"),
        "macos": os.uname().sysname == "Darwin",
    }
    return caps


def skip_reason(probe, caps, privacy):
    if probe.needs_root and not caps.get("root"):
        return "requires root"
    if probe.needs_fda and not caps.get("fda"):
        return "requires Full Disk Access"
    if probe.needs_session and not caps.get("session"):
        return "requires a GUI session (session agent not connected)"
    if probe.privacy == "high":
        if not privacy.get("capture_content", True):
            return "content capture disabled by configuration"
        toggles = {"content.screenshot": "capture_screenshot",
                   "content.clipboard": "capture_clipboard",
                   "content.browser_history": "capture_browser_data",
                   "content.recent_documents": "capture_browser_data"}
        key = toggles.get(probe.id)
        if key and not privacy.get(key, True):
            return "disabled by privacy.%s" % key
    if probe.kind == "exec" and not caps.get("macos", True) and probe.optional:
        return "not available on this platform"
    return None


def run_probe(probe, ctx=None, runner=None, config=None, bundle_dir=None,
              on_spawn=None):
    """Run one probe.  Never raises: a failure is a recorded result."""
    ctx = dict(ctx or {})
    config = config or {}
    sweep_cfg = config.get("sweep") or {}
    privacy = config.get("privacy") or {}
    runner = runner or proc.default_runner()
    caps = ctx.get("_capabilities") or capabilities()

    result = ProbeResult({
        "probe_id": probe.id,
        "title": probe.title,
        "loobins": list(probe.loobins),
        "category": probe.category,
        "kind": probe.kind,
        "privacy": probe.privacy,
        "started": timeutil.now_iso(),
        "duration_ms": 0,
        "exit_code": None,
        "bytes": 0,
    })

    reason = skip_reason(probe, caps, privacy)
    if reason:
        result["skipped_reason"] = reason
        return result

    if probe.kind == "native":
        return _run_native(probe, ctx, result, privacy)
    return _run_exec(probe, ctx, result, runner, sweep_cfg, privacy, bundle_dir,
                     on_spawn)


def _run_native(probe, ctx, result, privacy):
    started = timeutil.now()
    try:
        payload = native.run(probe, ctx)
        blob = json.dumps(payload, sort_keys=True, default=str)
        redacted, findings = redact.redact(blob, privacy.get("redact_secrets", True))
        result["parsed"] = json.loads(redacted) if findings else payload
        result["bytes"] = len(redacted)
        result["stdout_sha256"] = hashing.sha256_text(redacted)
        result["redactions"] = findings
        result["exit_code"] = 0
    except Exception as exc:  # a broken probe must not take down a sweep
        result["error"] = "%s: %s" % (type(exc).__name__, exc)
        result["exit_code"] = -1
    result["duration_ms"] = int((timeutil.now() - started).total_seconds() * 1000)
    return result


def _run_exec(probe, ctx, result, runner, sweep_cfg, privacy, bundle_dir, on_spawn):
    argv, missing = substitute(probe.argv, ctx)
    if missing:
        result["skipped_reason"] = "missing context for %s" % ", ".join(missing)
        return result
    try:
        safety.validate_runtime_argv(probe, argv, bundle_dir)
    except safety.UnsafeProbe as exc:
        # Fail closed and loudly: this means substitution produced something the
        # catalog did not sanction.
        result["skipped_reason"] = "blocked by safety guard: %s" % exc
        result["error"] = str(exc)
        return result

    timeout = probe.timeout
    if probe.cost == "heavy":
        timeout = max(timeout, int(sweep_cfg.get("expensive_timeout", 90)))
    max_bytes = int(sweep_cfg.get("max_output_bytes", 4 * 1024 * 1024))

    outcome = runner.run(argv, timeout=timeout, max_bytes=max_bytes)
    if on_spawn:
        on_spawn(outcome)

    stdout, findings = redact.redact(outcome.stdout, privacy.get("redact_secrets", True))
    result.update({
        "argv": argv,
        "exit_code": outcome.returncode,
        "duration_ms": outcome.duration_ms,
        "timed_out": outcome.timed_out,
        "truncated": outcome.truncated,
        "bytes": len(stdout),
        "stdout": stdout,
        "stdout_sha256": hashing.sha256_text(stdout),
        "stderr": outcome.stderr[:4096],
        "redactions": findings,
    })
    if outcome.error:
        result["error"] = outcome.error
    if probe.writes_artifact:
        result["artifact"] = argv[-1]
        if os.path.exists(argv[-1]):
            result["artifact_sha256"] = hashing.sha256_file(argv[-1])
            result["bytes"] = os.path.getsize(argv[-1])
    parsed = parse_output(probe.parser, stdout)
    if parsed is not None:
        result["parsed"] = parsed
    return result


def parse_output(parser, text):
    """Best-effort structuring.  The raw text is always kept regardless."""
    if not text:
        return None
    try:
        if parser == "json":
            return json.loads(text)
        if parser == "ndjson":
            rows = []
            for line in text.splitlines():
                line = line.strip().rstrip(",")
                if line.startswith("{"):
                    try:
                        rows.append(json.loads(line))
                    except ValueError:
                        continue
            return rows[:2000]
        if parser == "plist":
            import plistlib
            return native._jsonable(plistlib.loads(text.encode("utf-8", "replace")))
        if parser == "kv":
            pairs = {}
            for line in text.splitlines():
                if ":" in line:
                    key, _, value = line.partition(":")
                elif "=" in line:
                    key, _, value = line.partition("=")
                else:
                    continue
                pairs[key.strip()] = value.strip()
            return pairs
        if parser == "lines":
            return [line for line in text.splitlines() if line.strip()][:5000]
    except (ValueError, TypeError):
        return None
    return None
