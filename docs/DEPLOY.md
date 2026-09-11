# Deployment

## Requirements

- macOS 13 (Ventura) or later for `eslogger`. Older versions run in degraded
  mode: unified log plus `ps` polling, at reduced fidelity.
- Python 3.9+ (macOS ships 3.9.6). No third-party packages.
- Root, for the daemon.
- Full Disk Access, for the probes that need it.

## Install

```sh
sudo ./install.sh
sudo macsiem doctor
```

`install.sh` copies the package to `/usr/local/macsiem`, writes the two launchd
jobs and bootstraps them:

| Job | Kind | Runs |
| --- | --- | --- |
| `com.macsiem.agent` | LaunchDaemon, root | sensors, detection, sweeps |
| `com.macsiem.sessionagent` | LaunchAgent, per GUI user | session-scoped probes |

The daemon has `RunAtLoad`, `KeepAlive` on crash, a 10-second
`ThrottleInterval` so a crash loop cannot become a fork bomb, and
`ProcessType: Background` with low-priority I/O so it yields to the user's work.

## Two macOS facts that will bite you

**`/usr/bin/python3` is a stub.** It requires Xcode Command Line Tools. On a
clean Mac it tries to open a GUI installer dialog — fatal for a LaunchDaemon,
which has no one to click it. `macsiem install` warns when the interpreter is
the stub. Either run `xcode-select --install` first, or point
`ProgramArguments[0]` at a real interpreter.

**Full Disk Access attaches to the responsible executable.** If that is
`/usr/bin/python3`, then granting FDA grants it to system Python globally, which
is not something to do to a machine. The options, in order of preference:

1. **MDM PPPC profile** (the supported path for a managed fleet): grant
   `SystemPolicyAllFiles` to the `com.macsiem.agent` job, keyed to its code
   requirement. Nothing else on the host gains access.
2. **A small signed launcher** that `exec`s the module, so FDA attaches to your
   own binary rather than to the interpreter.
3. **Grant FDA to `python3` by hand** — development only. Do not ship this.

`macsiem doctor` reports which state the host is in.

## Without Full Disk Access

MacSIEM still runs. These are skipped, and reported as `unavailable` in every
bundle rather than silently dropped:

- `eslogger` (so process telemetry falls back to unified log + `ps`)
- TCC databases, the BTM/`sfltool dumpbtm` persistence database
- browser history, quarantine events, `log show`
- user `authorized_keys` and download directories

## Configuration

`/etc/macsiem/config.json`, merged over the defaults in `macsiem/config.py`.
Environment overrides use double underscores: `MACSIEM_SWEEP__WORKERS=4`.

The settings worth reviewing before deployment:

```json
{
  "privacy":   { "capture_content": true },
  "sweep":     { "full_sweep_min_severity": "medium",
                 "max_full_sweeps_per_hour": 12,
                 "workers": 8 },
  "detection": { "min_alert_severity": "low",
                 "business_hours": { "start": 8, "end": 19, "timezone_offset": 0 },
                 "suppressions": [] },
  "retention": { "events_days": 30, "bundles_days": 90, "max_store_mb": 2048 },
  "forward":   { "syslog": { "enabled": false, "host": "siem.example", "port": 514 } }
}
```

`privacy.capture_content` is the one to think hardest about — see
[PRIVACY.md](PRIVACY.md).

## Tuning out false positives

Site-local suppressions, by rule, binary, code-signing identity, responsible
process or argv substring:

```json
{ "detection": { "suppressions": [
  { "loobin": "profiles", "parent_signing_id": "com.jamf.management.daemon",
    "reason": "MDM inventory runs hourly" }
] } }
```

Management tooling (Jamf, Intune, Kandji, Addigy, Mosyle, CrowdStrike,
SentinelOne, Elastic, osquery) is already discounted by the context scorer.

Custom rules go in `macsiem/rules/custom/*.json` and survive a rulepack rebuild.

Validate changes before deploying them:

```sh
macsiem rules --test my-events.jsonl
```

## Updating the corpus

```sh
curl -o /tmp/loobins.json https://loobins.io/loobins.json
python3 tools/build_rulepack.py --json /tmp/loobins.json
make test
```

The rulepack is a committed artifact, so a corpus change shows up as a
reviewable diff in `docs/RULEPACK.md` — a tier change is visible in code review
rather than arriving silently in production.

## Operating

```sh
sudo launchctl print system/com.macsiem.agent   # is it loaded
macsiem doctor                                  # is it healthy
macsiem alerts --min-severity high
macsiem verify                                  # is the history intact
tail -f /var/log/macsiem/agent.err.log
```

The daemon writes a heartbeat every 60 seconds; `doctor` fails if the most
recent one is older than five minutes, which is how you find out it stopped.

## Uninstall

```sh
sudo macsiem install --uninstall
sudo rm -rf /usr/local/macsiem /var/db/macsiem /var/log/macsiem
```

Evidence bundles live in `/var/db/macsiem/bundles`. Export anything you need
before removing it.
