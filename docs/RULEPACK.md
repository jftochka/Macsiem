# Rulepack report

Generated from the LOOBins corpus by `tools/build_rulepack.py`.
This file is a review aid: a diff here means detection behaviour moved.

| metric | value |
| --- | --- |
| binaries | 62 |
| use cases | 183 |
| rules | 249 |
| signature tier (alerts alone) | 126 |
| indicator tier (needs corroboration) | 106 |
| telemetry tier (never alerts) | 17 |
| use cases with no extractable invocation | 5 |

## Rules by binary

| binary | rules | sig | ind | tel | max severity | tactics |
| --- | --- | --- | --- | --- | --- | --- |
| GetFileInfo | 2 | 0 | 0 | 2 | 79 | Defense Evasion, Discovery, Persistence |
| SetFile | 2 | 0 | 2 | 0 | 79 | Defense Evasion, Persistence |
| caffeinate | 2 | 0 | 2 | 0 | 79 | Defense Evasion, Execution |
| chflags | 3 | 1 | 2 | 0 | 75 | Defense Evasion |
| codesign | 1 | 1 | 0 | 0 | 75 | Defense Evasion |
| csrutil | 7 | 6 | 1 | 0 | 95 | Defense Evasion, Discovery, Reconnaissance |
| defaults | 6 | 4 | 2 | 0 | 86 | Defense Evasion, Discovery, Persistence |
| disown | 1 | 0 | 0 | 1 | 70 | Persistence |
| ditto | 4 | 4 | 0 | 0 | 92 | Collection, Defense Evasion, Exfiltration, Lateral Movement, Persistence |
| dns-sd | 4 | 0 | 4 | 0 | 25 | Discovery |
| dscacheutil | 2 | 0 | 2 | 0 | 25 | Discovery |
| dscl | 38 | 8 | 30 | 0 | 85 | Discovery, Persistence |
| dsconfigad | 2 | 0 | 2 | 0 | 25 | Discovery |
| dsexport | 2 | 2 | 0 | 0 | 34 | Discovery, Reconnaissance |
| funzip | 1 | 0 | 0 | 1 | 55 | Execution |
| hdiutil | 6 | 2 | 4 | 0 | 55 | Collection, Execution |
| ioreg | 4 | 1 | 3 | 0 | 44 | Collection, Discovery |
| last | 3 | 0 | 1 | 2 | 25 | Discovery |
| launchctl | 4 | 4 | 0 | 0 | 83 | Defense Evasion, Execution, Lateral Movement, Persistence |
| log | 3 | 3 | 0 | 0 | 95 | Credential Access, Defense Evasion |
| lsregister | 4 | 2 | 2 | 0 | 85 | Discovery, Impact |
| mdfind | 2 | 1 | 0 | 1 | 34 | Discovery, Reconnaissance |
| mdls | 2 | 2 | 0 | 0 | 100 | Collection, Defense Evasion, Execution |
| mktemp | 1 | 0 | 1 | 0 | 83 | Defense Evasion |
| networksetup | 15 | 11 | 4 | 0 | 85 | Command and Control, Discovery |
| notifyutil | 9 | 4 | 5 | 0 | 100 | Collection, Command and Control, Defense Evasion, Discovery, Privilege Escalation |
| nscurl | 3 | 1 | 2 | 0 | 79 | Command and Control, Defense Evasion |
| nvram | 3 | 2 | 1 | 0 | 85 | Discovery |
| odutil | 4 | 0 | 4 | 0 | 25 | Discovery |
| open | 3 | 0 | 2 | 1 | 70 | Execution, Privilege Escalation |
| osacompile | 1 | 1 | 0 | 0 | 81 | Command and Control, Resource Development |
| osascript | 11 | 4 | 5 | 2 | 94 | Collection, Credential Access, Defense Evasion, Discovery, Execution, Lateral Movement, Privilege Escalation, Reconnaissance |
| pbpaste | 3 | 0 | 0 | 3 | 94 | Collection, Credential Access, Defense Evasion, Discovery, Reconnaissance |
| pkill | 6 | 4 | 2 | 0 | 89 | Defense Evasion, Impact, Persistence |
| plutil | 1 | 1 | 0 | 0 | 75 | Defense Evasion |
| profiles | 3 | 3 | 0 | 0 | 85 | Discovery, Impact |
| safaridriver | 2 | 2 | 0 | 0 | 90 | Command and Control, Exfiltration |
| say | 2 | 2 | 0 | 0 | 92 | Collection, Defense Evasion, Discovery, Reconnaissance |
| screencapture | 1 | 0 | 1 | 0 | 50 | Collection |
| scutil | 4 | 0 | 4 | 0 | 25 | Discovery |
| security | 5 | 5 | 0 | 0 | 100 | Credential Access, Defense Evasion |
| sfltool | 3 | 2 | 1 | 0 | 90 | Defense Evasion, Discovery |
| snmptrap | 2 | 2 | 0 | 0 | 98 | Command and Control, Exfiltration, Lateral Movement |
| snmptrapd | 1 | 0 | 1 | 0 | 100 | Command and Control, Exfiltration, Lateral Movement |
| softwareupdate | 2 | 0 | 2 | 0 | 20 | Discovery |
| spctl | 3 | 3 | 0 | 0 | 95 | Defense Evasion |
| sqlite3 | 2 | 0 | 2 | 0 | 97 | Collection, Credential Access, Discovery |
| ssh-keygen | 2 | 2 | 0 | 0 | 90 | Defense Evasion, Execution |
| streamzip | 1 | 1 | 0 | 0 | 84 | Collection, Exfiltration |
| sw_vers | 4 | 0 | 3 | 1 | 25 | Discovery |
| swift | 3 | 0 | 3 | 0 | 79 | Defense Evasion, Execution |
| sysadminctl | 13 | 13 | 0 | 0 | 91 | Exfiltration, Impact, Initial Access, Persistence |
| sysctl | 1 | 0 | 1 | 0 | 25 | Discovery |
| system_profiler | 5 | 0 | 4 | 1 | 25 | Discovery |
| systemsetup | 4 | 4 | 0 | 0 | 80 | Lateral Movement |
| tccutil | 3 | 3 | 0 | 0 | 85 | Defense Evasion |
| tclsh | 1 | 0 | 0 | 1 | 63 | Execution |
| textutil | 2 | 2 | 0 | 0 | 94 | Collection, Credential Access, Defense Evasion |
| tftp | 1 | 0 | 0 | 1 | 65 | Lateral Movement |
| tmutil | 10 | 9 | 1 | 0 | 89 | Collection, Defense Evasion, Impact, Privilege Escalation |
| xattr | 4 | 4 | 0 | 0 | 84 | Defense Evasion, Execution |

## Use cases without an extractable invocation

Prose-only entries, or examples whose commands are all non-LOOBin helpers. Covered observationally, not by a rule.

- `kextstat` use case 1 - no extractable invocation
- `mdfind` use case 3 - no extractable invocation
- `mdls` use case 2 - no extractable invocation
- `mktemp` use case 2 - no extractable invocation
- `sqlite3` use case 2 - no extractable invocation
