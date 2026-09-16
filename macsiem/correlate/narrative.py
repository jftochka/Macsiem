"""The plain-English account that sits on top of the evidence.

Deterministic: this is generated from probe output by rule, not written by a
model, so the same bundle always produces the same narrative and every claim
points at the artifact it came from.  Where evidence is absent it says so
rather than guessing -- an investigator needs to know the difference between
"no persistence was installed" and "we could not read the persistence surface".
"""

from __future__ import annotations

import os

from ..util import timeutil


def _find(results, probe_id):
    for result in results:
        if result.get("probe_id") == probe_id:
            return result
    return None


def _parsed(results, probe_id, default=None):
    result = _find(results, probe_id)
    if not result or result.get("skipped_reason"):
        return default
    return result.get("parsed", default)


def _text(results, probe_id, default=""):
    result = _find(results, probe_id)
    if not result or result.get("skipped_reason"):
        return default
    return result.get("stdout", default)


def build(alert=None, event=None, sweep=None, timeline=None, tree_text=None,
          ancestry=None):
    """Return ``(markdown, facts)``."""
    sweep = sweep or {}
    results = sweep.get("results", [])
    facts = {}
    lines = []

    subject = (event or {}).get("binary_path") or (alert or {}).get("binary_path")
    argv = (event or {}).get("argv") or (alert or {}).get("argv") or []
    when = ((alert or {}).get("ts") or (event or {}).get("ts")
            or timeutil.now_iso())
    user = (event or {}).get("user") or (alert or {}).get("user") or "unknown"

    lines.append("# Evidence summary")
    lines.append("")
    if alert:
        lines.append("**%s severity** - %s (`%s`)" % (
            str(alert.get("severity", "?")).upper(),
            alert.get("use_case") or "detection", alert.get("signature_id")))
        if alert.get("description"):
            lines.append("")
            lines.append("> %s" % alert["description"])
        if alert.get("url"):
            lines.append("")
            lines.append("Reference: %s" % alert["url"])
    lines.append("")

    # -- what happened -----------------------------------------------------
    lines.append("## What ran")
    lines.append("")
    if argv:
        lines.append("```")
        lines.append(" ".join(argv))
        lines.append("```")
    lines.append("")
    lines.append("- **When**: %s" % when)
    lines.append("- **As**: %s (uid %s)" % (user, (event or {}).get("uid", "?")))
    lines.append("- **Binary**: %s" % (subject or "unknown"))
    facts["subject"] = subject
    facts["when"] = when
    facts["user"] = user

    signing = _text(results, "provenance.codesign")
    if signing:
        authority = [line for line in signing.splitlines()
                     if line.startswith(("Authority=", "TeamIdentifier=", "Identifier="))]
        if authority:
            lines.append("- **Signature**: %s" % "; ".join(authority[:3]))
            facts["signature"] = authority[:3]
    quarantine = _text(results, "provenance.xattr")
    if "com.apple.quarantine" in quarantine:
        lines.append("- **Quarantine**: present - this file was downloaded, not built here")
        facts["quarantined"] = True
    mdls = _text(results, "provenance.mdls")
    for line in mdls.splitlines():
        if "kMDItemWhereFroms" in line:
            lines.append("- **Origin metadata**: %s" % line.strip())
            facts["where_from"] = line.strip()
            break
    lines.append("")

    # -- how it got there --------------------------------------------------
    lines.append("## How it got there")
    lines.append("")
    if tree_text:
        lines.append("```")
        lines.append(tree_text)
        lines.append("```")
    elif ancestry:
        lines.append("Ancestry: " + " <- ".join(
            node.get("name") or "?" for node in ancestry))
    else:
        lines.append("_Process ancestry unavailable: no parent records were held "
                     "for this PID._")
    downloads = [entry for entry in (timeline or {}).get("entries", [])
                 if entry.get("kind") == "download"]
    if downloads:
        lines.append("")
        lines.append("Recent downloads recorded by LaunchServices quarantine:")
        for entry in downloads[-5:]:
            lines.append("- %s - %s" % (entry.get("ts"), entry.get("summary")))
        facts["downloads"] = len(downloads)
    lines.append("")

    # -- persistence -------------------------------------------------------
    lines.append("## Persistence")
    lines.append("")
    plists = _parsed(results, "persistence.launchd_plists")
    if plists is None:
        lines.append("_Not collected._")
    else:
        files = plists.get("files", [])
        recent = sorted([f for f in files if f.get("mtime")],
                        key=lambda f: f["mtime"], reverse=True)[:8]
        lines.append("%d launchd property lists present. Most recently modified:"
                     % len(files))
        lines.append("")
        for entry in recent:
            plist = entry.get("plist") or {}
            program = plist.get("ProgramArguments") or plist.get("Program") or ""
            if isinstance(program, list):
                program = " ".join(str(p) for p in program)
            lines.append("- `%s` (%s) -> %s" % (
                os.path.basename(entry.get("path", "")), entry.get("mtime"),
                str(program)[:120] or "(no program)"))
        facts["launchd_count"] = len(files)
    btm = _find(results, "persistence.btm")
    if btm and btm.get("skipped_reason"):
        lines.append("")
        lines.append("_Background Task Management database not read: %s._"
                     % btm["skipped_reason"])
    lines.append("")

    # -- security posture --------------------------------------------------
    lines.append("## Security posture at collection time")
    lines.append("")
    posture = [
        ("System Integrity Protection", _text(results, "posture.sip").strip()),
        ("Gatekeeper", _text(results, "posture.gatekeeper").strip()),
        ("FileVault", _text(results, "posture.filevault").strip()),
    ]
    for label, value in posture:
        lines.append("- **%s**: %s" % (label, value or "_not collected_"))
    firewall = _parsed(results, "posture.firewall")
    if isinstance(firewall, dict):
        for entry in firewall.get("files", []):
            state = (entry.get("plist") or {}).get("globalstate")
            if state is not None:
                lines.append("- **Application firewall**: globalstate=%s (%s)" % (
                    state, "off" if state == 0 else "on"))
                facts["firewall_state"] = state
    tcc = _parsed(results, "tcc.system_db")
    if isinstance(tcc, dict):
        grants = [row for database in tcc.get("databases", [])
                  for row in (database.get("rows") or [])
                  if row.get("auth_value")]
        fda = [row["client"] for row in grants
               if row.get("service") == "kTCCServiceSystemPolicyAllFiles"]
        lines.append("- **Full Disk Access granted to**: %s"
                     % (", ".join(fda[:10]) if fda else "nothing"))
        facts["fda_clients"] = fda
    lines.append("")

    # -- network -----------------------------------------------------------
    lines.append("## Network")
    lines.append("")
    proxy = _text(results, "network.proxies").strip()
    if proxy:
        enabled = [line.strip() for line in proxy.splitlines()
                   if "Enable" in line and ": 1" in line]
        lines.append("- **Proxy configuration**: %s"
                     % ("; ".join(enabled) if enabled else "no proxies enabled"))
        facts["proxies_enabled"] = bool(enabled)
    listeners = _text(results, "network.listeners")
    if listeners:
        count = max(0, len(listeners.splitlines()) - 1)
        lines.append("- **Listening sockets**: %d" % count)
        facts["listeners"] = count
    lines.append("")

    # -- data --------------------------------------------------------------
    content = [result for result in results
               if result.get("privacy") == "high" and not result.get("skipped_reason")]
    if content:
        lines.append("## Content captured")
        lines.append("")
        lines.append("Content capture is enabled on this host. The bundle contains:")
        for result in content:
            lines.append("- %s (`%s`)" % (result.get("title"), result.get("probe_id")))
        lines.append("")
        lines.append("These artifacts are listed under `capability: content` in the "
                     "manifest and can be stripped with `macsiem export --redact`.")
        lines.append("")

    # -- what we could not see --------------------------------------------
    coverage = sweep.get("coverage") or {}
    gaps = {name: entry for name, entry in coverage.items()
            if entry.get("status") in ("unavailable", "policy_excluded")}
    lines.append("## Collection gaps")
    lines.append("")
    if gaps:
        for name, entry in sorted(gaps.items()):
            lines.append("- **%s**: %s (%s)" % (name, entry.get("status"),
                                                entry.get("reason", "")))
    else:
        lines.append("None: every binary in the corpus was either probed directly "
                     "or covered by artifact state.")
    summary = sweep.get("coverage_summary") or {}
    lines.append("")
    lines.append("Coverage: " + ", ".join("%d %s" % (count, status)
                                          for status, count in sorted(summary.items())))
    skipped = [result for result in results if result.get("skipped_reason")]
    if skipped:
        lines.append("")
        lines.append("%d probes were skipped:" % len(skipped))
        reasons = {}
        for result in skipped:
            reasons.setdefault(result["skipped_reason"], []).append(result["probe_id"])
        for reason, ids in sorted(reasons.items()):
            lines.append("- %s: %s" % (reason, ", ".join(sorted(ids)[:6])
                                       + (" ..." if len(ids) > 6 else "")))
    lines.append("")
    return "\n".join(lines), facts
