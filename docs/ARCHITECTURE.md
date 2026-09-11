# Architecture

```
                      ┌──────────────────────────────────────────┐
  LOOBins corpus  ──▶  │ tools/build_rulepack.py  (build time)    │
  62 yml / 183 use     │ code strings ─▶ argv patterns            │
  cases                └──────────────────┬───────────────────────┘
                                          │ rulepack.json (no command strings)
                                          ▼
 ┌─────────────┐   events   ┌────────────────────┐  alerts  ┌──────────────────┐
 │  sensors    │──────────▶ │ detection engine   │ ───────▶ │ sweep scheduler  │
 │ eslogger    │            │ 253 rules, 3 tiers │          │ tiered, rate-    │
 │ unified log │            │ context scoring    │          │ limited, deduped │
 │ ps poll     │            │ self-suppression   │          └────────┬─────────┘
 │ persistence │            └─────────┬──────────┘                   │
 │ network     │                      │                              ▼
 │ posture     │                      │                   ┌────────────────────┐
 └─────────────┘                      │                   │ orchestrator       │
        │                             ▼                   │ 92 probes, workers,│
        │                   ┌──────────────────┐          │ cache, deadline    │
        └──────────────────▶│ SQLite store     │◀─────────┤ session agent IPC  │
                            │ hash-chained     │          └─────────┬──────────┘
                            └────────┬─────────┘                    │
                                     │                              ▼
                          ┌──────────▼────────┐          ┌────────────────────┐
                          │ forwarders        │          │ correlate + bundle │
                          │ jsonl/syslog/http │          │ proctree, timeline,│
                          └───────────────────┘          │ narrative, Merkle, │
                                                         │ custody, report.html│
                                                         └────────────────────┘
```

## Layout

| Path | Responsibility |
| --- | --- |
| `macsiem/util/proc.py` | **The only** process-execution path. argv lists only, scrubbed env, own process group, timeouts, output caps. `Runner` is an interface; `FixtureRunner` makes everything testable without a Mac. |
| `macsiem/util/hashing.py` | Canonical JSON, SHA-256, hash-chain primitives |
| `macsiem/util/redact.py` | Secret scrubbing on probe output |
| `macsiem/util/timeutil.py` | Normalizes the five time formats macOS emits |
| `macsiem/config.py` | Defaults → file → environment → flags |
| `macsiem/store/` | SQLite (WAL), hash-chained events and custody, retention |
| `macsiem/rules/loader.py` | Loads `rulepack.json` plus site-local rules |
| `macsiem/rules/engine.py` | argv-array matching, tiering, severity/confidence, correlation, suppression |
| `macsiem/rules/context.py` | Execution-context factors (parent, provenance, timing) |
| `macsiem/evidence/probes.py` | The probe catalog and the coverage model |
| `macsiem/evidence/safety.py` | The guard (see docs/SAFETY.md) |
| `macsiem/evidence/native.py` | In-process readers: plistlib, read-only immutable SQLite, scandir |
| `macsiem/evidence/runner.py` | One probe: slot substitution, gating, parsing, redaction |
| `macsiem/evidence/orchestrator.py` | The sweep: workers, tiers, cache, deadline, coverage |
| `macsiem/evidence/bundle.py` | Bundle layout, manifest, Merkle root, custody, verification |
| `macsiem/correlate/` | Process tree, timeline merge, deterministic narrative |
| `macsiem/report/html.py` | Self-contained HTML report |
| `macsiem/sensors/` | eslogger, unified log, ps poll, persistence/network/posture diffs |
| `macsiem/agent/daemon.py` | The supervisor |
| `macsiem/agent/sessionagent.py` | Per-user LaunchAgent for GUI-session probes |
| `macsiem/launchd/plists.py` | launchd job generation and install |
| `tools/` | Build-time only; may use PyYAML. Nothing in `macsiem/` imports it. |

## Key decisions

**Standard library only.** The agent must run on a stock macOS `python3` with no
network and no `pip install`. That rules out PyYAML at runtime, which is why the
corpus is compiled into JSON at build time — a diffable, reviewable, tested
artifact rather than a parse at startup.

**argv arrays end to end.** Observed command lines are never re-joined into a
string for matching. That is where quoting bugs and trivial evasions live.

**Severity and confidence are separate axes.** Severity describes the act,
confidence describes how sure the telemetry makes us. `csrutil disable` stays
critical when the only sensor available is `ps` polling; its confidence drops.

**Sensor fidelity is labelled, not papered over.** Endpoint Security is `high`;
the unified log is `medium` (it does not reliably carry argv); `ps` polling is
`low` (a 5-second poll misses short-lived processes, which is exactly what
LOOBins abuse looks like). The engine multiplies confidence accordingly and
`doctor` reports degraded mode prominently.

**The sweep suppresses itself.** About twenty probes are LOOBins. The daemon
registers its PID with the engine before anything starts; without that, every
sweep generates the alerts that trigger the next sweep.

**Gaps are evidence.** Dropped Endpoint Security sequence numbers, dead sensors,
queue drops and retention deletions are all recorded as events. A gap in
monitoring that nobody can prove is worse than no monitoring.

**Two processes.** A root LaunchDaemon has no GUI session, so clipboard and
screen capture run in a per-user LaunchAgent. Only probe *ids* cross the socket.

## Data flow for one alert

1. A sensor emits a normalized event onto a bounded queue.
2. The worker appends it to the hash-chained store and forwards it.
3. The engine matches argv against the rulepack index (basename lookup, so most
   events cost one dict miss), applies tiering, scores context, and either
   alerts, holds the observation as an indicator, or records it as telemetry.
4. An alert enqueues one sweep — per event, not per matching rule.
5. The orchestrator plans probes for the tier, fills from the baseline cache,
   runs the rest across a worker pool with per-probe timeouts, and records
   per-binary coverage against the host's real capabilities.
6. Correlation reconstructs the process tree from store events plus the live
   `ps` snapshot, merges everything time-stamped onto one timeline, and
   generates the narrative deterministically.
7. The bundle is written, hashed, Merkle-rooted, custody-logged and sealed, with
   a self-contained HTML report alongside.
