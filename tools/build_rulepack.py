#!/usr/bin/env python3
"""Compile the LOOBins corpus into ``macsiem/rules/data/rulepack.json``.

Build-time only.  May use PyYAML; the agent itself never parses YAML and never
sees a command string from the corpus.

    python3 tools/build_rulepack.py --loobins-dir /path/to/LOOBins
    python3 tools/build_rulepack.py --json /path/to/loobins.json

The second form is what ``macsiem rules refresh`` uses against
https://loobins.io/loobins.json, so a site update does not require this repo.
"""

from __future__ import annotations

import argparse
import datetime
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import extract as E  # noqa: E402

SCHEMA_VERSION = 1
LOOBIN_URL = "https://www.loobins.io/binaries/%s/"

# Severity floor by ATT&CK tactic.  Discovery is deliberately low: 79 of the
# corpus's 183 use cases are Discovery, and most of them are things a Mac does
# to itself all day.
SEVERITY_BY_TACTIC = {
    "Impact": 85, "Credential Access": 85, "Exfiltration": 80, "Defense Evasion": 75,
    "Persistence": 70, "Privilege Escalation": 70, "Lateral Movement": 65,
    "Command and Control": 65, "Initial Access": 60, "Execution": 55,
    "Collection": 50, "Resource Development": 35, "Reconnaissance": 30, "Discovery": 25,
}

# Tag modifiers.  bash/zsh/oneliner carry no risk signal (115 of 337 tag
# occurrences) and are dropped rather than scored.
TAG_MODIFIERS = {
    "genieo": 12, "shlayer": 12, "xcsset": 12, "cleanmaster": 12,
    "requires-root": 10, "privilege-escalation": 10,
    "covert-channel": 10, "c2": 10, "exfiltration-timing": 10, "covert-storage": 10,
    "password": 8, "cookie-theft": 8, "authentication": 8, "credential": 8,
    "payload": 8, "payload-execution": 8, "dylib": 8,
    "proxy": 6, "dns": 6, "remote-apple-events": 6, "eppc": 6, "lateral-movement": 6,
    "surveillance": 5, "monitoring": 5, "clipboard": 5, "geolocation": 5,
    "gatekeeper": 5, "quarantine": 5, "evasion": 5, "sigkill": 5, "logging": 5,
    "delete": 4, "system-reset": 4, "backup": 4, "restore": 4,
    "system-info": -5, "systeminfo": -5, "enumeration": -5, "vmcheck": -10,
}
IGNORED_TAGS = {"bash", "zsh", "oneliner", "sh"}

# Binaries an attacker reaches for that a Mac rarely runs on its own.  A small
# hand-labelled nudge; the heavy lifting is still specificity.
RARE_IN_BENIGN_USE = {
    "tccutil", "sfltool", "csrutil", "spctl", "dsexport", "odutil", "nscurl",
    "snmptrap", "streamzip", "funzip", "tftp", "safaridriver", "osacompile",
    "dsconfigad", "notifyutil", "sysadminctl", "tclsh", "lsregister",
}

TIER_SIGNATURE, TIER_INDICATOR, TIER_TELEMETRY = "signature", "indicator", "telemetry"

# Operations that are unambiguous on their own, whatever the rest of the command
# line looks like.  Specificity scoring undervalues these -- `spctl
# --master-disable` is one short token and turns Gatekeeper off -- so they force
# the signature tier and a severity floor, and each one additionally yields a
# synthetic binary+token rule so undocumented variants (`tccutil reset All`) are
# still caught.  Derived from the destructive-command audit in docs/SAFETY.md.
CRITICAL_TOKENS = {
    "csrutil": {"disable": 95, "netboot": 85},
    "spctl": {"--master-disable": 95, "--global-disable": 95},
    "log": {"erase": 95},
    "tccutil": {"reset": 85},
    "sfltool": {"resetbtm": 90},
    "lsregister": {"-delete": 80},
    "tmutil": {"disable": 80, "delete": 85, "addexclusion": 70},
    "security": {"dump-keychain": 95, "add-trusted-cert": 90},
    "sysadminctl": {"-deleteUser": 85, "-addUser": 75, "-resetPasswordFor": 90,
                    "-guestAccount": 70, "-smbGuestAccess": 75, "-afpGuestAccess": 75},
    "dscl": {"-passwd": 85, "passwd": 85, "-create": 70},
    "networksetup": {"-setwebproxy": 85, "-setsecurewebproxy": 85,
                     "-setautoproxyurl": 85, "-setautoproxystate": 75},
    "systemsetup": {"-setremotelogin": 80, "-setremoteappleevents": 80},
    "xattr": {"com.apple.quarantine": 75, "-c": 70},
    "profiles": {"remove": 85},
    "safaridriver": {"--enable": 70},
    "ssh-keygen": {"-D": 90},
    "nvram": {"-d": 80, "-c": 85},
    "chflags": {"schg": 70},
}
# Deliberately NOT critical: `pkill -f`, `defaults write`, `launchctl load`,
# `hdiutil attach`, `chflags hidden`.  All four are everyday developer and
# installer behaviour; the specific documented use cases still cover the
# malicious spellings, and blanket-flagging them buries the operator.

# Reading these means reading something that should not casually be read.
SENSITIVE_TARGETS = (
    ("tcc.db", 25), ("cookies.sqlite", 25), ("cookies.binarycookies", 25),
    ("login.keychain", 30), ("system.keychain", 30), ("history.db", 15),
    ("/etc/passwd", 20), ("/etc/shadow", 25), ("keychains", 20),
    ("com.apple.launchservices.quarantineeventsv2", 20), ("knowledgec.db", 20),
    ("id_rsa", 25), (".ssh", 15), ("loginwindow", 10),
)


def load_corpus_from_yaml(directory):
    try:
        import yaml
    except ImportError:
        sys.exit("PyYAML is required for --loobins-dir (build-time only).\n"
                 "Use --json with a loobins.json export instead.")
    corpus = []
    for path in sorted(glob.glob(os.path.join(directory, "*.yml"))):
        with open(path, "r") as handle:
            data = yaml.safe_load(handle)
        data["_source_file"] = os.path.basename(path)
        corpus.append(data)
    return corpus


def load_corpus_from_json(path):
    with open(path, "r") as handle:
        data = json.load(handle)
    entries = data if isinstance(data, list) else data.get("loobins", [])
    for entry in entries:
        entry.setdefault("_source_file", "%s.yml" % entry.get("name", "unknown"))
    return entries


def tier_for(specificity, binary):
    if binary in RARE_IN_BENIGN_USE:
        specificity *= 1.15
    if specificity >= 3.0:
        return TIER_SIGNATURE, specificity
    if specificity >= 1.0:
        return TIER_INDICATOR, specificity
    return TIER_TELEMETRY, specificity


def critical_hit(binary, tokens):
    """Highest-scoring critical operation present in a rule's required tokens."""
    table = CRITICAL_TOKENS.get(binary, {})
    hits = [(score, token) for token, score in table.items() if token in tokens]
    return max(hits) if hits else None


def sensitive_bonus(tokens):
    bonus = 0
    joined = " ".join(tokens).lower()
    for needle, points in SENSITIVE_TARGETS:
        if needle in joined:
            bonus = max(bonus, points)
    return bonus


def severity_for(tactics, tags, privileged):
    tactics = [t.strip() for t in (tactics or []) if isinstance(t, str)]
    known = [SEVERITY_BY_TACTIC[t] for t in tactics if t in SEVERITY_BY_TACTIC]
    severity = max(known) if known else 30
    severity += 4 * max(0, len(known) - 1)
    for tag in tags or []:
        clean = str(tag).strip().lower()
        if clean in IGNORED_TAGS:
            continue
        severity += TAG_MODIFIERS.get(clean, 0)
    if privileged:
        severity += 6
    return max(1, min(100, severity))


def build(corpus):
    binary_names = set()
    for entry in corpus:
        binary_names.add(entry["name"])
        for path in entry.get("paths") or []:
            for piece in str(path).split(";"):
                piece = piece.strip()
                if piece:
                    binary_names.add(os.path.basename(piece))

    binaries, rules, skipped = {}, [], []
    for entry in corpus:
        name = entry["name"]
        paths = []
        for path in entry.get("paths") or []:
            paths.extend(p.strip() for p in str(path).split(";") if p.strip())
        binaries[name] = {
            "name": name,
            "short_description": entry.get("short_description", ""),
            "paths": paths,
            "basenames": sorted({os.path.basename(p) for p in paths} | {name}),
            "url": LOOBIN_URL % name,
            "use_cases": len(entry.get("example_use_cases") or []),
            "tactics": [], "tags": [],
            # detections[] is 45% "N/A" upstream -- reference links only.
            "references": [d for d in (entry.get("detections") or [])
                           if d.get("url") and d.get("url") != "N/A"],
        }

        for position, use_case in enumerate(entry.get("example_use_cases") or [], start=1):
            code = use_case.get("code")
            tactics = [t.strip() for t in (use_case.get("tactics") or []) if isinstance(t, str)]
            tags = [str(t).strip().lower() for t in (use_case.get("tags") or [])]
            binaries[name]["tactics"] = sorted(set(binaries[name]["tactics"]) | set(tactics))
            binaries[name]["tags"] = sorted(set(binaries[name]["tags"]) | set(tags))
            if not code:
                skipped.append((name, position, "no code"))
                continue

            patterns, context_tokens, tokenization = E.extract(code, binary_names)
            if not patterns:
                skipped.append((name, position, "no extractable invocation"))
                continue

            seen = set()
            for ordinal, pattern in enumerate(patterns, start=1):
                fingerprint = json.dumps(
                    [pattern["binary"], pattern["positional"], pattern["flags_required"]],
                    sort_keys=True)
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)

                specificity = pattern["specificity"]
                if tokenization == "lenient":
                    specificity *= 0.6
                if pattern["nested"]:
                    specificity *= 0.7
                tier, adjusted = tier_for(specificity, pattern["binary"])
                severity = severity_for(tactics, tags, pattern["privileged"])

                required = ([c.get("eq") for c in pattern["positional"] if c.get("eq")]
                            + pattern["flags_required"]
                            + [c.get("contains") or c.get("startswith") or ""
                               for c in pattern["positional"]])
                required = [t for t in required if t]
                critical = critical_hit(pattern["binary"], required)
                if critical:
                    tier = TIER_SIGNATURE
                    severity = max(severity, critical[0])
                elif tier == TIER_SIGNATURE and severity <= 30 and set(tactics) <= {
                        "Discovery", "Reconnaissance"}:
                    # Pure host enumeration.  Real tradecraft, but every Mac and
                    # every inventory agent does it hourly, so it has to be
                    # corroborated rather than alerted on.
                    tier = TIER_INDICATOR
                severity = min(100, severity + sensitive_bonus(required))

                rules.append({
                    "rule_id": "loobin.%s.uc%02d.%02d" % (name, position, ordinal),
                    "loobin": pattern["binary"],
                    "documented_under": name,
                    "use_case": use_case.get("name", "").strip(),
                    # Prose only.  The corpus `code` never leaves the build.
                    "description": (use_case.get("description") or "").strip(),
                    "url": LOOBIN_URL % name,
                    "exec_basenames": sorted(
                        set(binaries.get(pattern["binary"], {}).get(
                            "basenames", [pattern["binary"]]))),
                    "exec_path_hint": pattern["exec_path_hint"],
                    "subcommand": pattern["subcommand"],
                    "positional": pattern["positional"],
                    "flags_required": pattern["flags_required"],
                    "min_argc": pattern["min_argc"],
                    "wildcards": pattern["wildcards"],
                    "specificity": round(adjusted, 2),
                    "tier": tier,
                    "severity_base": severity,
                    "critical_operation": critical[1] if critical else None,
                    "tactics": tactics,
                    "tags": [t for t in tags if t not in IGNORED_TAGS],
                    "privileged": pattern["privileged"],
                    "tokenization": tokenization,
                    "nested": pattern["nested"],
                    "context_tokens": context_tokens,
                    "code_sha256": E.sha256_text(code),
                    "source_file": entry.get("_source_file"),
                })

    # Synthetic rules for decisive operations.  These match on binary + a single
    # token appearing anywhere in argv, so variants the corpus never wrote down
    # (`tccutil reset All`, `csrutil disable --no-internal`) are still caught.
    documented = {r["loobin"] for r in rules}
    for binary, table in sorted(CRITICAL_TOKENS.items()):
        if binary not in documented and binary not in binaries:
            continue
        basenames = sorted(binaries.get(binary, {}).get("basenames", [binary]))
        for token, score in sorted(table.items()):
            rules.append({
                "rule_id": "loobin.%s.critical.%s" % (binary, token.lstrip("-").lower()),
                "loobin": binary,
                "documented_under": binary,
                "use_case": "Critical operation: %s %s" % (binary, token),
                "description": ("Decisive operation derived from the LOOBins corpus. "
                                "Matches wherever the token appears in argv, so "
                                "variants of the documented example are still caught."),
                "url": LOOBIN_URL % binary,
                "exec_basenames": basenames,
                "exec_path_hint": None,
                "subcommand": None,
                "positional": [],
                "flags_required": [],
                "any_token_required": [token],
                "min_argc": 2,
                "wildcards": 0,
                "specificity": 4.0,
                "tier": TIER_SIGNATURE,
                "severity_base": score,
                "critical_operation": token,
                "tactics": sorted(set(binaries.get(binary, {}).get("tactics", []))),
                "tags": [],
                "privileged": False,
                "tokenization": "curated",
                "nested": False,
                "context_tokens": [],
                "code_sha256": None,
                "source_file": "curated",
            })

    # Fill in basenames for rules whose binary is documented under another file.
    for rule in rules:
        if not rule["exec_basenames"]:
            rule["exec_basenames"] = [rule["loobin"]]

    index = {}
    for rule in rules:
        for basename in rule["exec_basenames"]:
            index.setdefault(basename, []).append(rule["rule_id"])

    rulepack = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"),
        "source": {
            "project": "LOOBins (https://loobins.io)",
            "feed": "https://loobins.io/loobins.json",
            "binaries": len(binaries),
            "use_cases": sum(b["use_cases"] for b in binaries.values()),
        },
        "counts": {
            "rules": len(rules),
            "signature": sum(1 for r in rules if r["tier"] == TIER_SIGNATURE),
            "indicator": sum(1 for r in rules if r["tier"] == TIER_INDICATOR),
            "telemetry": sum(1 for r in rules if r["tier"] == TIER_TELEMETRY),
            "skipped_use_cases": len(skipped),
        },
        "binaries": binaries,
        "rules": sorted(rules, key=lambda r: r["rule_id"]),
        "index": {k: sorted(v) for k, v in sorted(index.items())},
    }
    return rulepack, skipped


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--loobins-dir", help="directory of LOOBins *.yml files")
    group.add_argument("--json", help="a loobins.json export")
    parser.add_argument("--out", default="macsiem/rules/data/rulepack.json")
    parser.add_argument("--report", default="docs/RULEPACK.md")
    args = parser.parse_args()

    corpus = (load_corpus_from_yaml(args.loobins_dir) if args.loobins_dir
              else load_corpus_from_json(args.json))
    rulepack, skipped = build(corpus)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as handle:
        json.dump(rulepack, handle, indent=1, sort_keys=True)
        handle.write("\n")

    _write_report(args.report, rulepack, skipped)
    counts = rulepack["counts"]
    print("%s: %d binaries, %d rules (%d signature / %d indicator / %d telemetry), "
          "%d use cases without an extractable invocation"
          % (args.out, len(rulepack["binaries"]), counts["rules"], counts["signature"],
             counts["indicator"], counts["telemetry"], counts["skipped_use_cases"]))


def _write_report(path, rulepack, skipped):
    """Human-reviewable summary -- tier changes should show up in code review."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lines = [
        "# Rulepack report", "",
        "Generated from the LOOBins corpus by `tools/build_rulepack.py`.",
        "This file is a review aid: a diff here means detection behaviour moved.",
        "",
        "| metric | value |", "| --- | --- |",
        "| binaries | %d |" % len(rulepack["binaries"]),
        "| use cases | %d |" % rulepack["source"]["use_cases"],
        "| rules | %d |" % rulepack["counts"]["rules"],
        "| signature tier (alerts alone) | %d |" % rulepack["counts"]["signature"],
        "| indicator tier (needs corroboration) | %d |" % rulepack["counts"]["indicator"],
        "| telemetry tier (never alerts) | %d |" % rulepack["counts"]["telemetry"],
        "| use cases with no extractable invocation | %d |" % len(skipped),
        "", "## Rules by binary", "",
        "| binary | rules | sig | ind | tel | max severity | tactics |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    by_binary = {}
    for rule in rulepack["rules"]:
        by_binary.setdefault(rule["loobin"], []).append(rule)
    for binary in sorted(by_binary):
        group = by_binary[binary]
        tactics = sorted({t for r in group for t in r["tactics"]})
        lines.append("| %s | %d | %d | %d | %d | %d | %s |" % (
            binary, len(group),
            sum(1 for r in group if r["tier"] == TIER_SIGNATURE),
            sum(1 for r in group if r["tier"] == TIER_INDICATOR),
            sum(1 for r in group if r["tier"] == TIER_TELEMETRY),
            max(r["severity_base"] for r in group),
            ", ".join(tactics) or "-"))
    if skipped:
        lines += ["", "## Use cases without an extractable invocation", "",
                  "Prose-only entries, or examples whose commands are all "
                  "non-LOOBin helpers. Covered observationally, not by a rule.", ""]
        for name, position, reason in skipped:
            lines.append("- `%s` use case %d - %s" % (name, position, reason))
    with open(path, "w") as handle:
        handle.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
