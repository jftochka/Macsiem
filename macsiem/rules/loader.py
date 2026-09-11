"""Rulepack loading.

The rulepack is a build artifact (``tools/build_rulepack.py``); the agent only
reads JSON.  Site-local rules and allowlists are merged from
``macsiem/rules/custom/*.json`` so upgrading the rulepack never clobbers them.
"""

from __future__ import annotations

import glob
import json
import os

from ..util import hashing

DATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "rulepack.json")
CUSTOM_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "custom")

TIER_SIGNATURE = "signature"
TIER_INDICATOR = "indicator"
TIER_TELEMETRY = "telemetry"


class Rulepack:
    def __init__(self, data, custom=None, digest=None):
        self.data = data
        self.rules = list(data.get("rules") or [])
        self.binaries = data.get("binaries") or {}
        self.custom = list(custom or [])
        self.rules.extend(self.custom)
        self.digest = digest or hashing.sha256_bytes(hashing.canonical_json(data))
        self.by_id = {rule["rule_id"]: rule for rule in self.rules}
        self.index = {}
        for rule in self.rules:
            for basename in rule.get("exec_basenames") or [rule.get("loobin")]:
                if basename:
                    self.index.setdefault(basename, []).append(rule["rule_id"])

    @property
    def generated_at(self):
        return self.data.get("generated_at")

    @property
    def counts(self):
        counts = dict(self.data.get("counts") or {})
        counts["custom"] = len(self.custom)
        return counts

    def candidates(self, basename):
        return [self.by_id[rule_id] for rule_id in self.index.get(basename, [])]

    def binary_names(self):
        return sorted(self.binaries)

    def loobin_paths(self):
        """Every documented path across the corpus -> its LOOBin name."""
        mapping = {}
        for name, entry in self.binaries.items():
            for path in entry.get("paths") or []:
                mapping[path] = name
        return mapping


def load(path=None, custom_dir=None):
    path = path or DATA_PATH
    with open(path, "r") as handle:
        data = json.load(handle)
    custom = []
    for candidate in sorted(glob.glob(os.path.join(custom_dir or CUSTOM_DIR, "*.json"))):
        try:
            with open(candidate, "r") as handle:
                payload = json.load(handle)
            entries = payload if isinstance(payload, list) else payload.get("rules", [])
            for rule in entries:
                rule.setdefault("tier", TIER_SIGNATURE)
                rule.setdefault("severity_base", 50)
                rule.setdefault("specificity", 3.0)
                rule.setdefault("source_file", os.path.basename(candidate))
                rule.setdefault("tactics", [])
                rule.setdefault("tags", [])
                custom.append(rule)
        except (OSError, ValueError) as exc:
            raise SystemExit("macsiem: bad custom rule file %s: %s" % (candidate, exc))
    return Rulepack(data, custom)
