# MacSIEM

A 24/7/365 macOS monitoring platform built on the **LOOBins** corpus
([loobins.io](https://loobins.io)) — 62 native macOS binaries that adversaries
live off, and 183 documented ways they abuse them.

MacSIEM does two things with that corpus:

1. **Detects** abuse of all 62 binaries continuously, using 253 detection
   patterns compiled from every documented use case.
2. **Aggregates all 62 at once** when something fires, producing a single
   end-to-end, 360-degree evidence bundle: who, what, when, where it came from,
   how it persisted, what it touched, what it talked to, and what the host's
   security posture was — correlated onto one timeline, hash-sealed, and
   rendered as a self-contained report.

```
$ macsiem selftest --offline

  critical  81.6   /usr/bin/osascript -e do shell script "mkdir -p ~/Library/LaunchAgents"
  critical  92.0   /usr/bin/xattr -d com.apple.quarantine /Users/alice/.../helper
  critical  46.7   /usr/sbin/screencapture -x /tmp/.cache/s1.jpg
  critical  88.0   /usr/bin/pkill -f osqueryd|Falcon|LittleSnitch
  critical  98.4   /usr/bin/log erase --all
  high      74.2   /usr/bin/dscl . -list /Users
  -                /usr/bin/sw_vers -productVersion
  -                /usr/bin/profiles show

  probes     92 planned, 58 ran, 34 skipped in 0.05s
  coverage   {"covered": 31, "observational_only": 13, "unavailable": 18}
  verify     ok - bundle intact: 65 artifacts, custody chain verified
```

## The one thing to understand first

**The LOOBins corpus is offence.** About 40 of its 183 example commands destroy
evidence or disable security controls: `log erase --all`, `csrutil disable`,
`spctl --master-disable`, `tccutil reset`, `sfltool resetbtm`,
`lsregister -delete`, `security dump-keychain`, `pkill -f "osqueryd|Falcon"`.

A tool that naively "runs all the listed commands to gather evidence" would
wipe the unified log, turn off SIP and kill the EDR. So MacSIEM splits the
corpus at the build boundary and never lets the halves meet:

| | |
| --- | --- |
| **Detection patterns** | Every `code` string becomes a structured argv pattern. **Never executed.** A test asserts no corpus command string appears in the shipped artifact. |
| **Evidence probes** | A separate, hand-curated catalog of 92 read-only probes. **Only these run.** |

Each of the 62 binaries is then accounted for in exactly one of four ways, and
that accounting is restated per binary in every bundle:

- **covered** (49) — a read-only invocation, or a native in-process reader
- **observational_only** (13) — the binary only *acts*, so it is covered by its
  execution history plus the artifact state it would have changed (TCC.db for
  `tccutil`, the BTM database for `sfltool`, quarantine xattrs for `xattr`, the
  process table for `pkill`)
- **policy_excluded** — switched off by privacy configuration
- **unavailable** — the host lacks root, Full Disk Access or a GUI session

That is what makes "360-degree" an auditable claim rather than a slogan. See
[docs/PROBES.md](docs/PROBES.md) for the full table.

## Install

Requires macOS 13+ (for `eslogger`) and Python 3.9+. No third-party packages —
the agent is standard library only, because it has to run on a stock system
`python3` with no `pip install`.

```sh
sudo ./install.sh          # copies to /usr/local/macsiem, loads the launchd jobs
sudo macsiem doctor        # what this host can and cannot collect
```

`doctor` is the first command to run and the one to trust: it reports root,
Full Disk Access, `eslogger` availability, session-agent connectivity, the
probe-catalog audit and the event-chain state. Anything it cannot do, it says
so rather than silently collecting less.

## Use

```sh
macsiem alerts                       # recent detections
macsiem investigate <alert_id>       # build the 360 bundle for one alert
macsiem sweep --full                 # run the whole catalog now
macsiem verify                       # check the event chain
macsiem verify --bundle <id>         # check a bundle, on any machine
macsiem export <id> --redact         # zip it, stripping captured content
macsiem probes --coverage            # per-binary coverage accounting
macsiem rules --show osascript       # what we detect, and why
macsiem selftest --offline           # replay a recorded intrusion, no Mac needed
```

## How it works

```
 eslogger ─┐
 log stream ├─> queue ─> detection engine ─> alert ─> sweep ─> evidence bundle
 ps poll   │              (253 rules,               (92 probes,   (manifest,
 persistence│               3 tiers,                 tiered,       Merkle root,
 network    │               context scoring)         cached)      custody chain,
 posture   ─┘                                                     timeline,
                                                                  narrative,
                                                                  report.html)
```

**Detection is tiered**, because 62 binaries that macOS itself runs all day
would otherwise be a pager that never stops:

- `signature` (128) — specific enough to stand alone
- `indicator` (107) — needs a second, different indicator in the same process
  tree within 5 minutes, or a strongly suspicious execution context
- `telemetry` (18) — recorded and searchable, never alerted on

Severity and confidence are scored on separate axes: `csrutil disable` is
critical even when telemetry is degraded, and the confidence number says how
sure we are. Every alert carries a plain-English rationale listing exactly which
rule and which context factors produced its score.

**Sweeps are tiered too.** Every alert gets a scoped record built from
event-targeted probes plus a pre-warmed baseline cache (seconds). A full
all-62 sweep fires at medium severity and above, on demand, and on a schedule.
Sweeps are rate-limited, deduplicated, deadline-bounded and priority-ordered, so
a burst queues instead of forking a hundred `system_profiler` processes.

**The sweep does not alert on itself.** About twenty of the probes are
themselves LOOBins — a sweep runs `system_profiler`, `dscl`, `log show`,
`ioreg`, `sfltool` — so the daemon registers its own PID with the engine before
anything runs. Without that, every sweep triggers the next one.

## Evidence integrity

Both the event store and the bundle manifest are hash-chained; modification and
deletion each show up as a divergence, and `macsiem verify` names the first bad
record. Artifacts are folded into a Merkle root so one file can be verified — or
redacted before export — without invalidating the rest. The manifest records the
store's chain head and the store records the sealed bundle's hash, so each
attests to the other.

This is honest about its limits: root at time-of-write can forge a consistent
chain. It detects post-hoc and non-root tampering and offline edits of an
exported bundle. Real tamper-*proofing* needs off-host forwarding.
[docs/SAFETY.md](docs/SAFETY.md) says so plainly.

## Privacy

This deployment has **content capture enabled**: sweeps collect clipboard
contents, a screenshot, and browser history alongside metadata. That makes the
agent itself a high-value target and a surveillance capability, so: bundles are
`0700`, every capture is written to the chain-of-custody log, content artifacts
are tagged `capability: content` in the manifest, `macsiem export --redact`
strips them before a bundle leaves the host, and one config switch
(`privacy.capture_content: false`) turns the whole class off — reported in the
manifest as `policy_excluded` rather than silently skipped. See
[docs/PRIVACY.md](docs/PRIVACY.md).

## Development

```sh
make test        # 99 tests, all on Linux, no Mac required
make rulepack    # rebuild detection rules from the LOOBins corpus
make docs        # regenerate the generated documentation
make selftest    # replay the recorded intrusion end to end
```

The whole platform is testable without a Mac: command execution goes through a
`Runner` interface, and `FixtureRunner` replays recorded output.

## Documentation

- [docs/SAFETY.md](docs/SAFETY.md) — why this cannot change your Mac
- [docs/PRIVACY.md](docs/PRIVACY.md) — what it collects and how to limit it
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — components and data flow
- [docs/DEPLOY.md](docs/DEPLOY.md) — install, Full Disk Access, launchd
- [docs/PROBES.md](docs/PROBES.md) — the probe catalog and coverage table
- [docs/RULEPACK.md](docs/RULEPACK.md) — the compiled detection rules

## Credit

The LOOBins project ([loobins.io](https://loobins.io),
[infosecB/LOOBins](https://github.com/infosecB/LOOBins)) is the research this is
built on. MacSIEM consumes its corpus; it does not redistribute it.

## Not in scope

No central server, no kernel or system extension (`eslogger` covers Endpoint
Security without an Apple entitlement), and no automated response: MacSIEM
observes, records and proves. It does not act on the host.
