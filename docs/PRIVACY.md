# Privacy

A root agent with Full Disk Access on someone's Mac is, by construction, a
surveillance capability. This document states exactly what MacSIEM collects, so
that deploying it is a deliberate decision.

## Default posture on this deployment

**Content capture is enabled.** Sweeps collect, in addition to metadata:

| Probe | What it collects | LOOBin |
| --- | --- | --- |
| `content.clipboard` | the current clipboard contents | `pbpaste` |
| `content.screenshot` | a screenshot of the active display | `screencapture` |
| `content.browser_history` | Safari, Chrome and Firefox history and downloads | `sqlite3` |
| `content.recent_documents` | recently opened documents per user | `sfltool` |

Everything else is metadata: process arguments, file paths and timestamps,
persistence configuration, network state, security posture, TCC grant *lists*
(which app has which permission — not the data those permissions protect),
keychain item *names* (never contents; `security dump-keychain` is denylisted).

## Controls

**One switch turns off the whole class:**

```json
{ "privacy": { "capture_content": false } }
```

Per-class switches: `capture_screenshot`, `capture_clipboard`,
`capture_browser_data`.

When disabled, the affected binaries are reported in the manifest as
`policy_excluded` with the reason, rather than silently skipped. A reader of the
bundle can always tell the difference between "nothing was found" and "we did
not look".

**Everything else already in place:**

- Bundles and every file in them are `0700`/`0600` and root-owned. (The
  directory permission is set explicitly — `os.makedirs` only applies its mode
  to the leaf directory, which would have left bundle roots world-readable.)
- Every content capture appends a `captured_content` entry to the bundle's
  chain-of-custody log, naming the probe and the file.
- Content artifacts are tagged `capability: content` in the manifest and marked
  in the HTML report.
- `macsiem export <bundle> --redact` deletes every content artifact and records
  the removal in the manifest before the bundle leaves the host. The Merkle root
  is deliberately left intact, so the redaction is visible rather than hidden.
- Probe output passes through secret scrubbing (private keys, JWTs, AWS/GitHub/
  Slack tokens, `password:`/`token=` pairs) before it is written, and the count
  of redactions per probe is recorded.

## If you are deploying this to other people's machines

Content capture is appropriate for a dedicated incident-response host, a lab
machine, or a Mac whose user has been told. On a fleet of employee laptops it is
a different proposition, and the honest default there is
`capture_content: false` — metadata-only still answers what ran, where it came
from, how it persisted and what it talked to.

Whatever you choose, `macsiem doctor` prints the current privacy posture as a
warning line, so it cannot be enabled by accident and forgotten.

## What MacSIEM never collects

- Keychain item contents (`security dump-keychain` is on the denylist)
- Keystrokes, audio, or camera
- File *contents* generally — only metadata, except the content probes above
- Anything from another user's session that the session agent cannot reach

## Where it goes

Nowhere, by default. The store and bundles stay on the host. Forwarders
(JSONL / syslog / webhook) are opt-in per destination; the webhook forwarder
sends whatever you point it at, so redact before forwarding if your destination
is less trusted than the host.
