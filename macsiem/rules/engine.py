"""Detection engine: event in, alerts out.

Three tiers, because 258 rules over 62 binaries that macOS itself runs all day
would otherwise be a pager that never stops:

``signature``
    Specific enough to stand alone (``tccutil reset``, ``spctl
    --master-disable``, ``log erase``).  Alerts immediately.
``indicator``
    Real but ambiguous (``screencapture -x``, ``pkill -f``).  Never alerts by
    itself.  Needs a second, different indicator in the same process tree
    inside the correlation window, or a strongly suspicious context.
``telemetry``
    Things every Mac does (``sw_vers``, ``last``).  Recorded and searchable,
    never alerted on.

Matching is argv-array against argv-array.  The observed command line is never
re-joined into a string -- that is where quoting bugs and trivial evasions live.
"""

from __future__ import annotations

import math
import os
import threading
import time

from ..util import hashing, timeutil
from . import context as context_mod
from .loader import TIER_INDICATOR, TIER_SIGNATURE, TIER_TELEMETRY

SEVERITY_LABELS = [(85, "critical"), (65, "high"), (40, "medium"), (20, "low"), (0, "info")]


def severity_label(score):
    for threshold, label in SEVERITY_LABELS:
        if score >= threshold:
            return label
    return "info"


class Match:
    __slots__ = ("rule", "matched", "loose", "missing")

    def __init__(self, rule, matched, loose=False, missing=None):
        self.rule = rule
        self.matched = matched
        self.loose = loose
        self.missing = missing or []


def match_rule(rule, argv, binary_path=None):
    """Structured argv match.  Returns a :class:`Match` or ``None``.

    ``loose`` marks a match where required tokens were present but not at the
    documented positions -- still a match, at reduced confidence, because flag
    order is not stable across real-world invocations.
    """
    if not argv:
        return None
    if len(argv) < rule.get("min_argc", 1):
        return None

    hint = rule.get("exec_path_hint")
    if hint and binary_path and binary_path != hint and os.path.basename(hint) != \
            os.path.basename(binary_path):
        return None

    rest = argv[1:]
    matched, loose = [], False

    for token in rule.get("flags_required") or []:
        if token in rest:
            matched.append(token)
        elif any(element.startswith(token + "=") for element in rest):
            matched.append(token)
        else:
            return None

    any_required = rule.get("any_token_required") or []
    if any_required:
        hit = next((token for token in any_required
                    if token in rest or any(e.startswith(token + "=") for e in rest)), None)
        if hit is None:
            return None
        matched.append(hit)

    for constraint in rule.get("positional") or []:
        index = constraint.get("idx", 0)
        candidate = argv[index] if 0 <= index < len(argv) else None
        if _satisfies(constraint, candidate):
            matched.append(candidate)
            continue
        # Positional miss: accept the token anywhere in argv, at a penalty.
        alternative = next((element for element in rest if _satisfies(constraint, element)),
                           None)
        if alternative is None:
            return None
        matched.append(alternative)
        loose = True

    subcommand = rule.get("subcommand")
    if subcommand and subcommand not in rest:
        return None

    return Match(rule, matched, loose)


def _satisfies(constraint, value):
    if value is None:
        return False
    if "eq" in constraint:
        return value == constraint["eq"]
    if "contains" in constraint:
        return constraint["contains"].lower() in value.lower()
    if "contains_any" in constraint:
        lowered = value.lower()
        return any(str(option).lower() in lowered for option in constraint["contains_any"])
    if "startswith" in constraint:
        return value.startswith(constraint["startswith"])
    if "re" in constraint:
        import re
        return re.search(constraint["re"], value) is not None
    return False


class Engine:
    def __init__(self, rulepack, config=None, ancestry_provider=None,
                 known_hashes=None, clock=None):
        self.rulepack = rulepack
        self.config = config or {}
        self.ancestry_provider = ancestry_provider or (lambda event: [])
        self.known_hashes = known_hashes if known_hashes is not None else set()
        self.clock = clock or time.time
        self._indicators = []          # [(monotonic_ts, key, rule_id, event)]
        self._lock = threading.Lock()
        self._self_pids = set()
        self._suppressions = list((self.config.get("detection") or {}).get("suppressions") or [])
        self.stats = {"events": 0, "matches": 0, "alerts": 0, "suppressed": 0,
                      "self_suppressed": 0, "telemetry": 0}

    # -- self-attribution --------------------------------------------------
    def mark_self(self, pid):
        """Register a PID we spawned.

        Roughly 20 of the sweep's probes are themselves LOOBins -- a sweep runs
        ``system_profiler``, ``dscl``, ``log show``, ``ioreg``, ``sfltool`` --
        so without this the platform alerts on its own evidence collection and
        each sweep triggers the next one.
        """
        with self._lock:
            self._self_pids.add(int(pid))

    def unmark_self(self, pid):
        with self._lock:
            self._self_pids.discard(int(pid))

    def _is_self(self, event, ancestry):
        pids = {event.get("pid"), event.get("ppid")}
        pids.update(a.get("pid") for a in ancestry)
        with self._lock:
            if self._self_pids & {p for p in pids if p is not None}:
                return True
        return bool(event.get("macsiem_origin"))

    # -- suppression -------------------------------------------------------
    def _suppressed_by_config(self, event, rule):
        for entry in self._suppressions:
            if entry.get("rule_id") and entry["rule_id"] != rule["rule_id"]:
                continue
            if entry.get("loobin") and entry["loobin"] != rule.get("loobin"):
                continue
            if entry.get("signing_id") and entry["signing_id"] != event.get("signing_id"):
                continue
            if entry.get("parent_signing_id"):
                parent = (self.ancestry_provider(event) or [{}])[0]
                if entry["parent_signing_id"] != parent.get("signing_id"):
                    continue
            if entry.get("argv_contains") and entry["argv_contains"] not in \
                    " ".join(event.get("argv") or []):
                continue
            return entry.get("reason", "config suppression")
        return None

    # -- main entry point --------------------------------------------------
    def evaluate(self, event):
        """Return a list of alert dicts (possibly empty) for one event."""
        self.stats["events"] += 1
        argv = event.get("argv") or []
        binary_path = event.get("binary_path") or (argv[0] if argv else "")
        basename = os.path.basename(binary_path or "")
        if not basename:
            return []

        candidates = self.rulepack.candidates(basename)
        if not candidates:
            return []

        ancestry = self.ancestry_provider(event) or []
        if self._is_self(event, ancestry):
            self.stats["self_suppressed"] += 1
            return []

        matches = []
        for rule in candidates:
            match = match_rule(rule, argv or [binary_path], binary_path)
            if match:
                matches.append(match)
        if not matches:
            return []
        self.stats["matches"] += len(matches)

        ctx = context_mod.Context(event, ancestry, self.config, self.known_hashes)
        context_delta, factors = ctx.evaluate()

        alerts = []
        indicator_matches = []
        for match in matches:
            rule = match.rule
            reason = self._suppressed_by_config(event, rule)
            if reason:
                self.stats["suppressed"] += 1
                continue
            tier = rule.get("tier", TIER_SIGNATURE)
            if tier == TIER_TELEMETRY:
                self.stats["telemetry"] += 1
                continue
            if tier == TIER_INDICATOR:
                indicator_matches.append(match)
                continue
            alerts.append(self._build_alert(event, [match], context_delta, factors,
                                            kind="signature"))

        if indicator_matches:
            alerts.extend(self._handle_indicators(event, indicator_matches,
                                                  context_delta, factors))

        floor = (self.config.get("detection") or {}).get("min_alert_severity", "low")
        ranks = {label: index for index, (_, label) in enumerate(reversed(SEVERITY_LABELS))}
        minimum = ranks.get(floor, 1)
        alerts = [a for a in alerts
                  if ranks.get(a["severity"], 0) >= minimum or a["kind"] == "composite"]

        # Highest severity first: an operator reads the top of the list.
        alerts.sort(key=lambda a: -a["score"])
        self.stats["alerts"] += len(alerts)
        return alerts

    # -- indicator corroboration ------------------------------------------
    def _handle_indicators(self, event, matches, context_delta, factors):
        window = float((self.config.get("detection") or {}).get(
            "indicator_window_seconds", 300))
        key = _tree_key(event)
        now = self.clock()
        alerts = []
        with self._lock:
            self._indicators = [entry for entry in self._indicators
                                if now - entry[0] <= window]
            prior = [entry for entry in self._indicators if entry[1] == key]
            for match in matches:
                self._indicators.append((now, key, match.rule["rule_id"], event))

        # Corroboration must come from a *different* event.  Several indicator
        # rules firing on one command line (`dscl . -list /Users` matches three)
        # is one observation, not three, and treating it as corroboration turns
        # every directory listing into an alert.
        prior_other = [entry for entry in prior
                       if entry[3].get("event_id") != event.get("event_id")]
        distinct = {entry[2] for entry in prior_other} | {m.rule["rule_id"] for m in matches}
        if prior_other and len(distinct) >= 2:
            corroborating = [entry[3] for entry in prior_other]
            alerts.append(self._build_alert(
                event, matches, context_delta, factors, kind="composite",
                # A chain of techniques is worth more than its loudest link.
                severity_boost=min(25, 8 * (len(distinct) - 1)),
                extra_rationale=["%d distinct indicators in the same process tree "
                                 "within %ds" % (len(distinct), int(window))],
                related_events=[e.get("event_id") for e in corroborating if e.get("event_id")]))
        elif context_delta >= 25:
            alerts.append(self._build_alert(
                event, matches, context_delta, factors, kind="indicator_in_context",
                extra_rationale=["single indicator, but execution context scored "
                                 "+%d" % context_delta]))
        return alerts

    # -- alert construction ------------------------------------------------
    def _build_alert(self, event, matches, context_delta, factors, kind,
                     extra_rationale=None, related_events=None, severity_boost=0):
        primary = max(matches, key=lambda m: m.rule.get("severity_base", 0))
        rule = primary.rule

        severity_value = (rule.get("severity_base", 50) + severity_boost
                          + max(-25, min(25, context_delta)))
        severity_value = max(1, min(100, severity_value))

        specificity = float(rule.get("specificity", 1.0))
        confidence = 100.0 * (1.0 - math.exp(-specificity / 3.0))
        confidence *= {"strict": 1.0, "curated": 1.0, "lenient": 0.6}.get(
            rule.get("tokenization", "strict"), 0.85)
        if rule.get("nested"):
            confidence *= 0.8
        if primary.loose:
            confidence *= 0.85
        confidence *= context_mod.fidelity_factor(event.get("fidelity"))
        confidence = max(5.0, min(99.0, confidence + context_delta * 0.4))

        score = severity_value * confidence / 100.0
        rationale = ["matched %s (%s tier, specificity %.1f)" % (
            rule["rule_id"], rule.get("tier"), specificity)]
        if rule.get("critical_operation"):
            rationale.append("decisive operation: %s %s" % (
                rule.get("loobin"), rule["critical_operation"]))
        if primary.loose:
            rationale.append("required tokens present but not at documented positions")
        rationale.extend(extra_rationale or [])
        for factor in factors:
            rationale.append("context %s %+d%s" % (
                factor["factor"], factor["delta"],
                " (%s)" % factor["detail"] if factor.get("detail") else ""))

        return {
            "alert_id": hashing.new_id("alrt"),
            "ts": event.get("ts") or timeutil.now_iso(),
            "event_id": event.get("event_id"),
            "kind": kind,
            "loobin": rule.get("loobin"),
            "rule_ids": sorted({m.rule["rule_id"] for m in matches}),
            "signature_id": rule["rule_id"],
            "use_case": rule.get("use_case"),
            "description": rule.get("description"),
            "url": rule.get("url"),
            "tactics": sorted({t for m in matches for t in (m.rule.get("tactics") or [])}),
            "tags": sorted({t for m in matches for t in (m.rule.get("tags") or [])}),
            "severity_value": severity_value,
            # Severity describes the act; confidence describes how sure we are.
            # Keeping them on separate axes means `csrutil disable` reads as
            # critical even when telemetry is degraded, and an operator can sort
            # by either.
            "severity": severity_label(severity_value),
            "confidence": round(confidence / 100.0, 3),
            "score": round(score, 1),
            "rationale": rationale,
            "context_delta": context_delta,
            "related_events": related_events or [],
            "binary_path": event.get("binary_path"),
            "argv": event.get("argv"),
            "pid": event.get("pid"),
            "user": event.get("user"),
            "dedupe_key": hashing.sha256_text("|".join([
                rule["rule_id"], str(event.get("session_id") or event.get("ppid") or ""),
                " ".join(event.get("argv") or [])]))[:32],
        }


def _tree_key(event):
    """Correlation key for indicator corroboration."""
    return str(event.get("session_id") or event.get("ppid") or event.get("pid") or "?")
