"""Self-contained HTML report for an evidence bundle.

No CDN, no fonts, no network of any kind: an incident report has to open on a
machine that is off the network, and a report that phones out is a report that
leaks which incidents you are looking at.  Everything is inlined and the whole
thing is one file.
"""

from __future__ import annotations

import html
import json

SEVERITY_COLORS = {
    "critical": "#b3261e", "high": "#c2410c", "medium": "#a16207",
    "low": "#3f6212", "info": "#3f5a73",
}
STATUS_COLORS = {
    "covered": "#166534", "observational_only": "#3f5a73",
    "policy_excluded": "#a16207", "unavailable": "#b3261e",
}

CSS = """
:root{--bg:#fbfaf9;--fg:#1b1a19;--muted:#6b6763;--line:#e3e0dc;--card:#ffffff;
--accent:#3f5a73;--code:#f4f2f0}
@media (prefers-color-scheme:dark){:root{--bg:#16181c;--fg:#e8e6e3;--muted:#9b9691;
--line:#2c3036;--card:#1d2025;--accent:#8ab4d8;--code:#22262c}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 -apple-system,
BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:32px 20px 80px}
h1{font-size:26px;margin:0 0 4px} h2{font-size:18px;margin:36px 0 12px;
padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:15px;margin:22px 0 8px;color:var(--muted);text-transform:uppercase;
letter-spacing:.06em}
.sub{color:var(--muted);margin:0 0 24px;font-size:13px}
.badge{display:inline-block;padding:3px 10px;border-radius:999px;color:#fff;
font-size:12px;font-weight:600;letter-spacing:.03em}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.card .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
.card .v{font-size:22px;font-weight:650;margin-top:4px}
pre{background:var(--code);border:1px solid var(--line);border-radius:8px;padding:12px;
overflow-x:auto;font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
code{background:var(--code);padding:1px 5px;border-radius:4px;
font:12.5px ui-monospace,SFMono-Regular,Menlo,monospace}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);
vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;
letter-spacing:.05em}
tbody tr:hover{background:var(--code)}
.scroll{max-height:460px;overflow:auto;border:1px solid var(--line);border-radius:8px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px}
.mono{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--muted)}
.tl{border-left:2px solid var(--line);margin-left:8px;padding-left:16px}
.tl .row{position:relative;padding:6px 0;border-bottom:1px solid var(--line)}
.tl .row:before{content:"";position:absolute;left:-21px;top:13px;width:8px;height:8px;
border-radius:50%;background:var(--accent)}
.tl .t{color:var(--muted);font:11.5px ui-monospace,Menlo,monospace}
details{margin:8px 0}summary{cursor:pointer;color:var(--accent);font-size:13px}
.note{background:var(--code);border-left:3px solid var(--accent);padding:10px 14px;
border-radius:0 8px 8px 0;font-size:13px;margin:12px 0}
.md h1{font-size:20px}.md h2{font-size:16px;border:0;margin:20px 0 6px}
.md blockquote{margin:8px 0;padding:6px 14px;border-left:3px solid var(--line);
color:var(--muted)}
"""


def _e(value):
    return html.escape(str(value if value is not None else ""))


def _markdown_lite(text):
    """Just enough Markdown for the generated narrative -- no dependencies."""
    out, in_code, in_list = [], False, False
    for line in (text or "").splitlines():
        if line.startswith("```"):
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append("</pre>" if in_code else "<pre>")
            in_code = not in_code
            continue
        if in_code:
            out.append(_e(line))
            continue
        stripped = line.strip()
        if stripped.startswith("- "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append("<li>%s</li>" % _inline(stripped[2:]))
            continue
        if in_list:
            out.append("</ul>")
            in_list = False
        if stripped.startswith("### "):
            out.append("<h3>%s</h3>" % _inline(stripped[4:]))
        elif stripped.startswith("## "):
            out.append("<h2>%s</h2>" % _inline(stripped[3:]))
        elif stripped.startswith("# "):
            out.append("<h1>%s</h1>" % _inline(stripped[2:]))
        elif stripped.startswith("> "):
            out.append("<blockquote>%s</blockquote>" % _inline(stripped[2:]))
        elif stripped:
            out.append("<p>%s</p>" % _inline(stripped))
    if in_list:
        out.append("</ul>")
    if in_code:
        out.append("</pre>")
    return "\n".join(out)


def _inline(text):
    escaped = _e(text)
    for marker, tag in (("**", "strong"), ("`", "code"), ("_", "em")):
        parts = escaped.split(marker)
        if len(parts) >= 3:
            rebuilt = parts[0]
            for index in range(1, len(parts)):
                rebuilt += ("<%s>" % tag if index % 2 else "</%s>" % tag) + parts[index]
            if len(parts) % 2 == 0:      # unbalanced marker: put it back
                rebuilt = escaped
            escaped = rebuilt
    return escaped


def render(manifest, narrative_md="", timeline=None, alert=None):
    timeline = timeline or {}
    summary = manifest.get("coverage_summary") or {}
    sweep = manifest.get("sweep") or {}
    stats = sweep.get("stats") or {}
    severity = (alert or {}).get("severity", "info")

    parts = ["<!-- MacSIEM evidence report; self-contained, no network -->",
             "<style>%s</style>" % CSS, "<div class=wrap>"]

    title = (alert or {}).get("use_case") or "Evidence bundle"
    parts.append("<h1>%s</h1>" % _e(title))
    parts.append('<p class=sub><span class="badge" style="background:%s">%s</span> '
                 "&nbsp; %s &nbsp;&middot;&nbsp; host <code>%s</code> "
                 "&nbsp;&middot;&nbsp; bundle <code>%s</code></p>"
                 % (SEVERITY_COLORS.get(severity, "#3f5a73"), _e(severity.upper()),
                    _e(manifest.get("sealed")),
                    _e((manifest.get("host") or {}).get("hostname")),
                    _e(manifest.get("bundle_id"))))

    cards = [
        ("Probes run", stats.get("ran", 0)),
        ("From cache", stats.get("from_cache", 0)),
        ("Skipped", stats.get("skipped", 0)),
        ("LOOBins covered", "%d/%d" % (summary.get("covered", 0), sum(summary.values()) or 62)),
        ("Sweep time", "%.1fs" % ((sweep.get("duration_ms") or 0) / 1000.0)),
        ("Artifacts", len([a for a in manifest.get("artifacts", [])
                           if a.get("status") == "collected"])),
    ]
    parts.append("<div class=grid>")
    for label, value in cards:
        parts.append("<div class=card><div class=k>%s</div><div class=v>%s</div></div>"
                     % (_e(label), _e(value)))
    parts.append("</div>")

    if narrative_md:
        parts.append("<h2>Analysis</h2><div class=md>%s</div>"
                     % _markdown_lite(narrative_md))

    entries = timeline.get("entries") or []
    if entries:
        parts.append("<h2>Timeline</h2>")
        parts.append("<div class='scroll'><div class=tl>")
        for entry in entries[-300:]:
            parts.append("<div class=row><div class=t>%s &middot; %s</div>%s</div>"
                         % (_e(entry.get("ts")), _e(entry.get("kind")),
                            _e(entry.get("summary"))[:400]))
        parts.append("</div></div>")

    parts.append("<h2>LOOBins coverage</h2>")
    parts.append('<div class=note>Every binary in the corpus is accounted for. '
                 '<strong>observational_only</strong> means the binary has no safe '
                 'read-only invocation, so it is covered by its execution history '
                 'and by the system state it would have changed - it was never run '
                 'by this platform.</div>')
    parts.append("<div class=scroll><table><thead><tr><th>binary</th><th>status</th>"
                 "<th>evidence</th></tr></thead><tbody>")
    for name, entry in sorted((manifest.get("loobins_coverage") or {}).items()):
        status = entry.get("status", "?")
        evidence = ", ".join(entry.get("probes") or entry.get("artifact_state") or [])
        note = entry.get("note") or entry.get("reason") or ""
        parts.append("<tr><td><code>%s</code></td><td><span class=dot style='background:%s'>"
                     "</span>%s</td><td>%s<div class=mono>%s</div></td></tr>"
                     % (_e(name), STATUS_COLORS.get(status, "#888"), _e(status),
                        _e(evidence), _e(note)))
    parts.append("</tbody></table></div>")

    parts.append("<h2>Artifacts</h2>")
    parts.append("<div class=scroll><table><thead><tr><th>file</th><th>probe</th>"
                 "<th>bytes</th><th>sha256</th></tr></thead><tbody>")
    for artifact in manifest.get("artifacts", []):
        if artifact.get("status") != "collected":
            continue
        parts.append("<tr><td><code>%s</code>%s</td><td>%s</td><td>%s</td>"
                     "<td class=mono>%s</td></tr>"
                     % (_e(artifact.get("path")),
                        " <span class=badge style='background:#a16207'>content</span>"
                        if artifact.get("capability") == "content" else "",
                        _e(artifact.get("probe_id")), _e(artifact.get("bytes")),
                        _e((artifact.get("sha256") or "")[:24])))
    parts.append("</tbody></table></div>")

    skipped = [a for a in manifest.get("artifacts", []) if a.get("status") == "skipped"]
    if skipped:
        parts.append("<details><summary>%d probes skipped</summary><table><tbody>"
                     % len(skipped))
        for artifact in skipped:
            parts.append("<tr><td><code>%s</code></td><td>%s</td></tr>"
                         % (_e(artifact.get("probe_id")), _e(artifact.get("reason"))))
        parts.append("</tbody></table></details>")

    parts.append("<h2>Integrity</h2>")
    parts.append("<table><tbody>")
    for label, value in (
            ("Manifest SHA-256", manifest.get("manifest_sha256")),
            ("Artifacts Merkle root", manifest.get("artifacts_merkle_root")),
            ("Event store chain head",
             (manifest.get("store_anchor") or {}).get("chain_head")),
            ("Custody entries", len(manifest.get("custody") or []))):
        parts.append("<tr><th>%s</th><td class=mono>%s</td></tr>" % (_e(label), _e(value)))
    parts.append("</tbody></table>")
    parts.append("<p class=sub style='margin-top:24px'>Verify with "
                 "<code>macsiem verify --bundle %s</code>. Generated by MacSIEM "
                 "%s from the LOOBins corpus.</p>"
                 % (_e(manifest.get("bundle_id")),
                    _e((manifest.get("agent") or {}).get("version", ""))))
    parts.append("</div>")
    return "<title>%s - MacSIEM</title>\n" % _e(title) + "\n".join(parts)
