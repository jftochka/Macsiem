"""The probe catalog: the allowlist of everything MacSIEM is permitted to run.

This file is the answer to "aggregate all the listed commands at once".  It is
*not* the LOOBins commands -- roughly 40 of those destroy evidence or disable
security controls (``log erase --all``, ``csrutil disable``, ``spctl
--master-disable``, ``tccutil reset``, ``sfltool resetbtm``, ``pkill -f
"osqueryd|Falcon"``).  Running them to "collect evidence" would be the single
most destructive thing this platform could do.

So every one of the 62 binaries is accounted for in exactly one of four ways,
and the bundle manifest states which, per binary, for every sweep:

``covered``
    A read-only invocation (or a native, no-exec reader) exists and ran.
``observational_only``
    The binary has no safe read-only mode -- it only acts.  Covered instead by
    (a) every execution of it in the event store within the incident window and
    (b) the *artifact state* it would have changed: TCC.db for ``tccutil``, the
    BTM database for ``sfltool``, quarantine xattrs for ``xattr``, the process
    table for ``pkill``.
``policy_excluded``
    Disabled by configuration (privacy tier).
``unavailable``
    The host lacks the capability (no root, no Full Disk Access, wrong macOS).

That accounting is what makes "360-degree" an auditable claim instead of a
slogan.  ``macsiem probes --coverage`` prints it; a test fails the build if any
LOOBin falls out of all four buckets.
"""

from __future__ import annotations

import os

# Scopes -------------------------------------------------------------------
BASELINE = "baseline"   # host-wide, cacheable, refreshed on a schedule
EVENT = "event"         # targeted at the triggering process/file/user
BOTH = "both"

# Costs --------------------------------------------------------------------
LIGHT, NORMAL, HEAVY = "light", "normal", "heavy"

# Privacy tiers ------------------------------------------------------------
LOW, MEDIUM, HIGH = "low", "medium", "high"


class Probe:
    """One read-only evidence collection step.

    ``argv`` is a literal list.  Runtime values arrive only through declared
    ``slots`` (``{target_path}``, ``{target_pid}``, ``{target_user}``,
    ``{window_start}``, ``{window_end}``, ``{artifact}``), each substituted into
    a single argv element and never shell-interpolated.
    """

    __slots__ = ("id", "title", "loobins", "category", "kind", "argv", "native",
                 "args", "scope", "cost", "timeout", "needs_root", "needs_fda",
                 "needs_session", "privacy", "parser", "answers", "cache_ttl",
                 "writes_artifact", "exception", "optional")

    def __init__(self, id, title, category, loobins=(), kind="exec", argv=None,
                 native=None, args=None, scope=BASELINE, cost=LIGHT, timeout=15,
                 needs_root=False, needs_fda=False, needs_session=False,
                 privacy=LOW, parser="text", answers=(), cache_ttl=600,
                 writes_artifact=False, exception=None, optional=False):
        self.id = id
        self.title = title
        self.category = category
        self.loobins = tuple(loobins)
        self.kind = kind
        self.argv = list(argv or [])
        self.native = native
        self.args = dict(args or {})
        self.scope = scope
        self.cost = cost
        self.timeout = timeout
        self.needs_root = needs_root
        self.needs_fda = needs_fda
        self.needs_session = needs_session
        self.privacy = privacy
        self.parser = parser
        self.answers = tuple(answers)
        self.cache_ttl = cache_ttl
        self.writes_artifact = writes_artifact
        # A documented, reviewable exemption from a denylist term.  Every one
        # is enumerated by tests/test_safety.py.
        self.exception = exception
        self.optional = optional

    @property
    def slots(self):
        found = []
        for element in self.argv:
            for slot in ("{target_path}", "{target_pid}", "{target_user}",
                         "{window_start}", "{window_end}", "{artifact}"):
                if slot in element and slot not in found:
                    found.append(slot)
        return found

    def to_dict(self):
        return {
            "id": self.id, "title": self.title, "category": self.category,
            "loobins": list(self.loobins), "kind": self.kind, "argv": list(self.argv),
            "native": self.native, "args": self.args, "scope": self.scope,
            "cost": self.cost, "timeout": self.timeout, "needs_root": self.needs_root,
            "needs_fda": self.needs_fda, "needs_session": self.needs_session,
            "privacy": self.privacy, "parser": self.parser,
            "answers": list(self.answers), "writes_artifact": self.writes_artifact,
            "exception": self.exception,
        }

    def __repr__(self):
        return "<Probe %s>" % self.id


P = Probe
CATALOG = [
    # -- host identity & posture ------------------------------------------
    P("host.sw_vers", "macOS product version and build", "host", ["sw_vers"],
      argv=["/usr/bin/sw_vers"], parser="kv", cache_ttl=86400,
      answers=["what OS is this host running"]),
    P("host.sysctl_summary", "Kernel/hardware identity", "host", ["sysctl"],
      argv=["/usr/sbin/sysctl", "hw.model", "hw.ncpu", "hw.memsize", "kern.osversion",
            "kern.osrelease", "kern.boottime", "kern.hostname", "machdep.cpu.brand_string"],
      parser="kv", cache_ttl=86400,
      answers=["what hardware is this", "when did it last boot"]),
    P("host.system_profiler", "Hardware, software and profile inventory", "host",
      ["system_profiler"],
      argv=["/usr/sbin/system_profiler", "-json", "-detailLevel", "mini",
            "SPHardwareDataType", "SPSoftwareDataType", "SPConfigurationProfileDataType",
            "SPFirewallDataType", "SPInstallHistoryDataType"],
      cost=HEAVY, timeout=90, parser="json", cache_ttl=21600,
      answers=["what is installed", "what profiles are enforced"]),
    P("host.ioreg_platform", "IOKit platform and USB device tree", "host", ["ioreg"],
      argv=["/usr/sbin/ioreg", "-c", "IOPlatformExpertDevice", "-d", "2", "-a"],
      cost=NORMAL, timeout=30, parser="plist", cache_ttl=3600,
      answers=["is this a VM", "what is the platform UUID"]),
    P("host.ioreg_usb", "Attached USB devices", "host", ["ioreg"],
      argv=["/usr/sbin/ioreg", "-p", "IOUSB", "-l", "-w", "0"],
      cost=NORMAL, timeout=30, cache_ttl=600,
      answers=["what was plugged in"]),
    P("host.kext_list", "Loaded kernel extensions", "host", ["kextstat"],
      argv=["/usr/bin/kmutil", "showloaded", "--no-kernel-components"],
      cost=NORMAL, timeout=45, cache_ttl=3600, optional=True,
      answers=["what kernel code is loaded"]),
    P("host.kextstat_legacy", "Loaded kexts (pre-Apple-Silicon tooling)", "host",
      ["kextstat"], argv=["/usr/sbin/kextstat", "-l"], cost=LIGHT, timeout=20,
      cache_ttl=3600, optional=True, answers=["what kernel code is loaded"]),
    P("host.nvram", "NVRAM variables", "host", ["nvram"],
      argv=["/usr/sbin/nvram", "-p"], cache_ttl=3600,
      answers=["was a boot argument or netboot entry added"]),
    P("host.uptime_load", "Uptime and load average", "host",
      argv=["/usr/bin/uptime"], cache_ttl=60),

    # -- security posture --------------------------------------------------
    P("posture.sip", "System Integrity Protection status", "posture", ["csrutil"],
      argv=["/usr/bin/csrutil", "status"], cache_ttl=600,
      answers=["is SIP enabled"]),
    P("posture.sip_authenticated_root", "Authenticated-root (signed system volume)",
      "posture", ["csrutil"], argv=["/usr/bin/csrutil", "authenticated-root", "status"],
      cache_ttl=600, optional=True),
    P("posture.gatekeeper", "Gatekeeper assessment status", "posture", ["spctl"],
      argv=["/usr/sbin/spctl", "--status"], cache_ttl=600,
      answers=["is Gatekeeper enabled"]),
    P("posture.filevault", "FileVault status", "posture",
      argv=["/usr/bin/fdesetup", "status"], cache_ttl=3600),
    P("posture.firewall", "Application firewall state", "posture", ["defaults"],
      kind="native", native="read_plist",
      args={"path": "/Library/Preferences/com.apple.alf.plist"}, cache_ttl=600,
      answers=["is the firewall on", "what is allowed through it"]),
    P("posture.xprotect_version", "XProtect and MRT definition versions", "posture",
      kind="native", native="read_plists",
      args={"paths": [
          "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
          "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist",
          "/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"]},
      cache_ttl=21600, answers=["are malware definitions current"]),
    P("posture.software_update_history", "Installed update history", "posture",
      ["softwareupdate"], argv=["/usr/sbin/softwareupdate", "--history"],
      cost=NORMAL, timeout=30, cache_ttl=21600),
    P("posture.profiles", "Configuration profiles installed", "posture", ["profiles"],
      argv=["/usr/bin/profiles", "show"], needs_root=True, cache_ttl=1800,
      answers=["what MDM policy applies", "was a rogue profile installed"]),
    P("posture.profiles_enrollment", "MDM enrollment status", "posture", ["profiles"],
      argv=["/usr/bin/profiles", "status", "-type", "enrollment"], cache_ttl=1800),
    P("posture.trusted_certs", "Certificates in the system keychain", "posture",
      ["security"],
      argv=["/usr/bin/security", "find-certificate", "-a", "-Z",
            "/Library/Keychains/System.keychain"],
      cost=NORMAL, timeout=30, cache_ttl=3600,
      answers=["was a rogue root CA installed"]),
    P("posture.keychain_list", "Keychain search list", "posture", ["security"],
      argv=["/usr/bin/security", "list-keychains"], cache_ttl=3600),

    # -- identity & access -------------------------------------------------
    P("identity.users", "Local user accounts", "identity", ["dscl"],
      argv=["/usr/bin/dscl", ".", "-list", "/Users"], cache_ttl=600,
      answers=["what accounts exist", "was an account created"]),
    P("identity.users_detail", "Local user records with UID and shell", "identity",
      ["dscl"], argv=["/usr/bin/dscl", ".", "-readall", "/Users",
                      "RecordName", "UniqueID", "PrimaryGroupID", "NFSHomeDirectory",
                      "UserShell", "AuthenticationAuthority"],
      cost=NORMAL, timeout=30, cache_ttl=600),
    P("identity.admins", "Members of the admin group", "identity", ["dscl"],
      argv=["/usr/bin/dscl", ".", "-read", "/Groups/admin", "GroupMembership"],
      cache_ttl=600, answers=["who has admin rights"]),
    P("identity.target_user", "Directory record for the user in the event",
      "identity", ["dscl"],
      argv=["/usr/bin/dscl", ".", "-read", "/Users/{target_user}"],
      scope=EVENT, cache_ttl=0),
    P("identity.directory_stats", "Directory Services cache statistics", "identity",
      ["dscacheutil"], argv=["/usr/bin/dscacheutil", "-statistics"], cache_ttl=600),
    P("identity.opendirectory", "OpenDirectory session and node state", "identity",
      ["odutil"], argv=["/usr/bin/odutil", "show", "sessions"], cache_ttl=600,
      optional=True),
    P("identity.ad_binding", "Active Directory binding configuration", "identity",
      ["dsconfigad"], argv=["/usr/sbin/dsconfigad", "-show"], cache_ttl=3600,
      optional=True),
    P("identity.logins", "Recent logins and reboots", "identity", ["last"],
      argv=["/usr/bin/last", "-50"], cache_ttl=300,
      answers=["who logged in and when"]),
    P("identity.current_sessions", "Currently logged-in users", "identity",
      argv=["/usr/bin/who", "-a"], cache_ttl=60),
    P("identity.guest_account", "Guest account status", "identity", ["sysadminctl"],
      argv=["/usr/sbin/sysadminctl", "-guestAccount", "status"], needs_root=True,
      cache_ttl=1800, optional=True,
      exception="`-guestAccount status` reads state; the mutating spellings are "
                "`on`/`off` and are rejected by the argument validator",
      answers=["is the guest account enabled"]),
    P("identity.sudoers", "sudo configuration", "identity", kind="native",
      native="read_text_files",
      args={"paths": ["/etc/sudoers"], "globs": ["/etc/sudoers.d/*"]},
      needs_root=True, cache_ttl=1800,
      answers=["can anyone escalate without a password"]),
    P("identity.ssh_authorized_keys", "SSH authorized keys per user", "identity",
      kind="native", native="read_text_files",
      args={"globs": ["/Users/*/.ssh/authorized_keys", "/var/root/.ssh/authorized_keys"]},
      needs_fda=True, cache_ttl=600,
      answers=["can someone log in with a key they added"]),
    P("identity.ssh_key_fingerprints", "Fingerprints of SSH public keys", "identity",
      ["ssh-keygen"],
      argv=["/usr/bin/ssh-keygen", "-l", "-f", "{target_path}"], scope=EVENT,
      cache_ttl=0, optional=True),

    # -- persistence -------------------------------------------------------
    P("persistence.launchd_plists", "LaunchAgent and LaunchDaemon property lists",
      "persistence", ["launchctl"], kind="native", native="read_plists_in_dirs",
      args={"dirs": ["/Library/LaunchDaemons", "/Library/LaunchAgents",
                     "/System/Library/LaunchDaemons", "/System/Library/LaunchAgents"],
            "globs": ["/Users/*/Library/LaunchAgents/*.plist"]},
      cache_ttl=300,
      answers=["what runs at boot or login", "who installed it and when"]),
    P("persistence.launchctl_list", "Loaded launchd jobs", "persistence", ["launchctl"],
      argv=["/bin/launchctl", "list"], cache_ttl=300,
      answers=["what is loaded right now"]),
    P("persistence.launchctl_print_system", "launchd system domain detail",
      "persistence", ["launchctl"], argv=["/bin/launchctl", "print", "system"],
      cost=HEAVY, timeout=60, needs_root=True, cache_ttl=1800, optional=True),
    P("persistence.btm", "Background Task Management database (login/background items)",
      "persistence", ["sfltool"], argv=["/usr/bin/sfltool", "dumpbtm"],
      cost=NORMAL, timeout=45, needs_root=True, needs_fda=True, cache_ttl=600,
      optional=True,
      answers=["what background items are registered", "was one hidden"]),
    P("persistence.login_items", "Per-user login item preferences", "persistence",
      ["sfltool", "defaults"], kind="native", native="read_plists",
      args={"globs": [
          "/Users/*/Library/Preferences/com.apple.loginitems.plist",
          "/Users/*/Library/Application Support/com.apple.backgroundtaskmanagementagent/*"]},
      cache_ttl=600),
    P("persistence.loginwindow", "Login/logout hooks and loginwindow policy",
      "persistence", ["defaults"], kind="native", native="read_plists",
      args={"paths": ["/Library/Preferences/com.apple.loginwindow.plist",
                      "/var/root/Library/Preferences/com.apple.loginwindow.plist"],
            "globs": ["/Users/*/Library/Preferences/com.apple.loginwindow.plist"]},
      cache_ttl=600, answers=["is there a LoginHook"]),
    P("persistence.cron_periodic", "cron tables, periodic scripts and rc files",
      "persistence", kind="native", native="read_text_files",
      args={"globs": ["/usr/lib/cron/tabs/*", "/etc/periodic/*/*", "/etc/rc.common",
                      "/etc/emond.d/rules/*"],
            "paths": ["/etc/crontab"]},
      cache_ttl=600),
    P("persistence.launchservices", "Launch Services registration database",
      "persistence", ["lsregister"],
      argv=["/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/"
            "LaunchServices.framework/Versions/A/Support/lsregister", "-dump"],
      cost=HEAVY, timeout=90, cache_ttl=21600, optional=True,
      answers=["what handles which URL scheme or file type"]),
    P("persistence.dir_flags", "BSD flags on persistence directories", "persistence",
      ["chflags", "GetFileInfo"],
      argv=["/bin/ls", "-lOd", "/Library/LaunchDaemons", "/Library/LaunchAgents",
            "/Library/StartupItems", "/private/etc/periodic"],
      cache_ttl=600, answers=["was something made immutable or hidden"]),

    # -- process ----------------------------------------------------------
    P("process.snapshot", "Full process table with arguments", "process",
      ["pkill", "disown", "caffeinate"],
      argv=["/bin/ps", "-Ao", "pid,ppid,uid,user,%cpu,%mem,lstart,tty,stat,command"],
      cost=NORMAL, timeout=30, cache_ttl=0, scope=BOTH,
      answers=["what is running", "what was killed", "what was orphaned"]),
    P("process.tree_target", "Process detail for the triggering PID", "process",
      argv=["/bin/ps", "-o", "pid,ppid,uid,user,lstart,stat,command", "-p",
            "{target_pid}"],
      scope=EVENT, cache_ttl=0),
    P("process.open_files_target", "Files and sockets held open by the target",
      "process", argv=["/usr/sbin/lsof", "-n", "-P", "-p", "{target_pid}"],
      scope=EVENT, cost=NORMAL, timeout=30, cache_ttl=0, needs_root=True,
      answers=["what is it reading", "what is it talking to"]),
    P("process.power_assertions", "Power assertions (sleep prevention)", "process",
      ["caffeinate"], argv=["/usr/bin/pmset", "-g", "assertions"], cache_ttl=300,
      answers=["is something holding the machine awake"]),

    # -- binary provenance -------------------------------------------------
    P("provenance.codesign", "Code signature and entitlements of the target binary",
      "provenance", ["codesign"],
      argv=["/usr/bin/codesign", "-dvvv", "--entitlements", ":-", "{target_path}"],
      scope=EVENT, cache_ttl=0,
      answers=["who signed it", "what entitlements does it claim"]),
    P("provenance.codesign_verify", "Signature validity of the target binary",
      "provenance", ["codesign"],
      argv=["/usr/bin/codesign", "--verify", "--verbose=4", "{target_path}"],
      scope=EVENT, cache_ttl=0),
    P("provenance.gatekeeper_assess", "Gatekeeper assessment of the target",
      "provenance", ["spctl"],
      argv=["/usr/sbin/spctl", "--assess", "--type", "execute", "-vv", "{target_path}"],
      scope=EVENT, cache_ttl=0, optional=True),
    P("provenance.xattr", "Extended attributes, including quarantine", "provenance",
      ["xattr"], argv=["/usr/bin/xattr", "-l", "{target_path}"], scope=EVENT,
      cache_ttl=0,
      exception="`-l` lists; the mutating spellings are -d/-c/-w and are rejected",
      answers=["where did this file come from"]),
    P("provenance.mdls", "Spotlight metadata, including download URL", "provenance",
      ["mdls"], argv=["/usr/bin/mdls", "{target_path}"], scope=EVENT, cache_ttl=0,
      answers=["what URL did this arrive from"]),
    P("provenance.finder_info", "Finder attributes and comment", "provenance",
      ["GetFileInfo", "SetFile"],
      argv=["/usr/bin/GetFileInfo", "{target_path}"], scope=EVENT, cache_ttl=0,
      optional=True),
    P("provenance.file_type", "File type and architecture", "provenance",
      argv=["/usr/bin/file", "-b", "{target_path}"], scope=EVENT, cache_ttl=0),
    P("provenance.stat", "Inode metadata and timestamps", "provenance",
      kind="native", native="stat_paths", args={"slot": "target_path"},
      scope=EVENT, cache_ttl=0),
    P("provenance.textutil_info", "Document metadata for a text/rich-text target",
      "provenance", ["textutil"],
      argv=["/usr/bin/textutil", "-info", "{target_path}"], scope=EVENT,
      cache_ttl=0, optional=True),
    P("provenance.quarantine_events", "LaunchServices quarantine event database",
      "provenance", ["sqlite3"], kind="native", native="read_sqlite",
      args={"globs": ["/Users/*/Library/Preferences/com.apple.LaunchServices."
                      "QuarantineEventsV2"],
            "query": "SELECT LSQuarantineTimeStamp, LSQuarantineAgentName, "
                     "LSQuarantineDataURLString, LSQuarantineOriginURLString "
                     "FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC "
                     "LIMIT 200"},
      needs_fda=True, cache_ttl=300,
      answers=["what was downloaded, by what app, from where"]),

    # -- privacy / TCC -----------------------------------------------------
    P("tcc.system_db", "System TCC grants", "privacy", ["sqlite3", "tccutil"],
      kind="native", native="read_sqlite",
      args={"paths": ["/Library/Application Support/com.apple.TCC/TCC.db"],
            "query": "SELECT service, client, client_type, auth_value, auth_reason, "
                     "last_modified FROM access ORDER BY last_modified DESC"},
      needs_root=True, needs_fda=True, cache_ttl=300,
      answers=["what has Full Disk Access", "what can record the screen"]),
    P("tcc.user_db", "Per-user TCC grants", "privacy", ["sqlite3", "tccutil"],
      kind="native", native="read_sqlite",
      args={"globs": ["/Users/*/Library/Application Support/com.apple.TCC/TCC.db"],
            "query": "SELECT service, client, client_type, auth_value, auth_reason, "
                     "last_modified FROM access ORDER BY last_modified DESC"},
      needs_fda=True, cache_ttl=300),

    # -- network -----------------------------------------------------------
    P("network.services", "Configured network services", "network", ["networksetup"],
      argv=["/usr/sbin/networksetup", "-listallnetworkservices"], cache_ttl=600),
    P("network.proxies", "HTTP/HTTPS/SOCKS/auto proxy configuration", "network",
      ["scutil", "networksetup"], argv=["/usr/sbin/scutil", "--proxy"], cache_ttl=300,
      answers=["is traffic being redirected through a proxy"]),
    P("network.dns", "Resolver configuration", "network", ["scutil", "dscacheutil"],
      argv=["/usr/sbin/scutil", "--dns"], cache_ttl=300,
      answers=["who resolves DNS for this host"]),
    P("network.computer_name", "Bonjour/SMB host identity", "network", ["scutil"],
      argv=["/usr/sbin/scutil", "--get", "ComputerName"], cache_ttl=3600,
      optional=True),
    P("network.listeners", "Listening sockets and their owners", "network",
      argv=["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], cost=NORMAL,
      timeout=30, needs_root=True, cache_ttl=120,
      answers=["what is accepting connections"]),
    P("network.connections", "Established network connections", "network",
      argv=["/usr/sbin/netstat", "-an"], cost=NORMAL, timeout=30, cache_ttl=120,
      answers=["what is this host talking to"]),
    P("network.arp", "ARP cache (local network neighbours)", "network",
      argv=["/usr/sbin/arp", "-a"], cache_ttl=300),
    P("network.interfaces", "Interface addresses and state", "network",
      argv=["/sbin/ifconfig", "-a"], cache_ttl=300),
    P("network.shares", "File sharing points", "network", ["sharing"],
      argv=["/usr/sbin/sharing", "-l"], cache_ttl=600, optional=True,
      answers=["is anything being shared out"]),
    P("network.remote_login", "Remote login (SSH) enabled state", "network",
      ["systemsetup"], argv=["/usr/sbin/systemsetup", "-getremotelogin"],
      needs_root=True, cache_ttl=600, optional=True),
    P("network.remote_appleevents", "Remote Apple Events enabled state", "network",
      ["systemsetup"], argv=["/usr/sbin/systemsetup", "-getremoteappleevents"],
      needs_root=True, cache_ttl=600, optional=True),
    P("network.hosts_file", "Static host overrides", "network", kind="native",
      native="read_text_files", args={"paths": ["/etc/hosts"]}, cache_ttl=600,
      answers=["was a domain redirected locally"]),
    P("network.ssh_config", "SSH client and daemon configuration", "network",
      kind="native", native="read_text_files",
      args={"paths": ["/etc/ssh/sshd_config", "/etc/ssh/ssh_config"],
            "globs": ["/Users/*/.ssh/config"]},
      cache_ttl=1800),
    P("network.snmp_config", "SNMP trap handler configuration", "network",
      ["snmptrap"], kind="native", native="read_text_files",
      args={"globs": ["/etc/snmp/*.conf", "/usr/local/etc/snmp/*.conf"]},
      cache_ttl=3600, optional=True),

    # -- storage & backup --------------------------------------------------
    P("storage.mounts", "Mounted filesystems", "storage", ["hdiutil"],
      argv=["/sbin/mount"], cache_ttl=120),
    P("storage.disk_images", "Attached disk images", "storage", ["hdiutil"],
      argv=["/usr/bin/hdiutil", "info"], cost=NORMAL, timeout=30, cache_ttl=300,
      answers=["what DMG/ISO is mounted and from where"]),
    P("storage.timemachine_status", "Time Machine status", "storage", ["tmutil"],
      argv=["/usr/bin/tmutil", "status"], cache_ttl=300, optional=True),
    P("storage.timemachine_destinations", "Backup destinations", "storage", ["tmutil"],
      argv=["/usr/bin/tmutil", "destinationinfo"], cache_ttl=1800, optional=True,
      answers=["where do backups go", "was a destination added"]),
    P("storage.local_snapshots", "APFS local snapshots", "storage", ["tmutil"],
      argv=["/usr/bin/tmutil", "listlocalsnapshots", "/"], cache_ttl=600,
      optional=True,
      answers=["is there a snapshot to compare against"]),
    P("storage.tmp_recent", "Recently modified files in temp directories", "storage",
      ["mktemp", "ditto"], kind="native", native="recent_files",
      args={"dirs": ["/tmp", "/private/tmp", "/var/tmp", "/Users/Shared"],
            "max_age_seconds": 86400, "limit": 500},
      cache_ttl=120, answers=["what was staged in a temp directory"]),
    P("storage.recent_downloads", "Recently written files in user download folders",
      "storage", kind="native", native="recent_files",
      args={"globs": ["/Users/*/Downloads", "/Users/*/Desktop"],
            "max_age_seconds": 604800, "limit": 300},
      needs_fda=True, cache_ttl=600),
    P("storage.spotlight_recent", "Spotlight: files created in the incident window",
      "storage", ["mdfind"],
      argv=["/usr/bin/mdfind", "-onlyin", "/Users",
            "kMDItemFSCreationDate >= $time.now(-86400)"],
      cost=NORMAL, timeout=45, cache_ttl=600, optional=True,
      exception="`mdfind` takes a query expression containing `$time.now(-N)`; "
                "validated by the Spotlight-query validator, never a shell",
      answers=["what appeared on disk recently"]),

    # -- logs --------------------------------------------------------------
    P("logs.unified_window", "Unified log slice around the event", "logs", ["log"],
      argv=["/usr/bin/log", "show", "--style", "ndjson", "--start", "{window_start}",
            "--end", "{window_end}", "--info",
            "--predicate", "eventMessage != \"\""],
      scope=EVENT, cost=HEAVY, timeout=120, needs_fda=True, cache_ttl=0,
      parser="ndjson",
      exception="`log show --predicate` is the one argument that may contain "
                "quoting; it is checked by the predicate validator",
      answers=["what else happened at that moment"]),
    P("logs.unified_security", "Security-relevant unified log entries", "logs", ["log"],
      argv=["/usr/bin/log", "show", "--style", "ndjson", "--last", "1h", "--info",
            "--predicate",
            "subsystem == \"com.apple.TCC\" OR process == \"sudo\" OR "
            "process == \"sshd\" OR process == \"XProtect\" OR "
            "process == \"loginwindow\" OR process == \"securityd\""],
      cost=HEAVY, timeout=120, needs_fda=True, cache_ttl=300, parser="ndjson",
      exception="predicate argument, as above"),
    P("logs.install_log", "Installer and package history", "logs", kind="native",
      native="read_text_files",
      args={"paths": ["/var/log/install.log"], "tail_bytes": 262144},
      needs_fda=True, cache_ttl=1800),
    P("logs.system_log_dirs", "Log file inventory with sizes and timestamps", "logs",
      kind="native", native="dir_listing",
      args={"dirs": ["/var/log", "/Library/Logs"], "limit": 400},
      cache_ttl=600, answers=["were logs truncated or deleted"]),
    P("logs.audit_state", "OpenBSM audit trail inventory", "logs", kind="native",
      native="dir_listing", args={"dirs": ["/var/audit"], "limit": 100},
      needs_root=True, cache_ttl=600, optional=True),

    # -- content (privacy tier: high; see docs/PRIVACY.md) -----------------
    P("content.clipboard", "Current clipboard contents", "content", ["pbpaste"],
      argv=["/usr/bin/pbpaste"], scope=BOTH, needs_session=True, privacy=HIGH,
      cache_ttl=0, optional=True,
      answers=["what was staged for exfiltration"]),
    P("content.screenshot", "Screenshot of the active display", "content",
      ["screencapture"],
      argv=["/usr/sbin/screencapture", "-x", "-t", "png", "{artifact}"],
      scope=EVENT, needs_session=True, privacy=HIGH, writes_artifact=True,
      cache_ttl=0, optional=True,
      exception="writes exactly one file, and the path is forced to be inside "
                "the bundle directory by the artifact-slot validator",
      answers=["what was on screen when this fired"]),
    P("content.browser_history", "Browser history and download records", "content",
      ["sqlite3"], kind="native", native="read_sqlite",
      args={"globs": ["/Users/*/Library/Safari/History.db",
                      "/Users/*/Library/Application Support/Google/Chrome/*/History",
                      "/Users/*/Library/Application Support/Firefox/Profiles/*/places.sqlite"],
            "query_by_file": {
                "History.db": "SELECT datetime(visit_time+978307200,'unixepoch') AS t, "
                              "url FROM history_visits JOIN history_items ON "
                              "history_items.id = history_visits.history_item "
                              "ORDER BY visit_time DESC LIMIT 300",
                "History": "SELECT datetime(last_visit_time/1000000-11644473600,"
                           "'unixepoch') AS t, url, title FROM urls "
                           "ORDER BY last_visit_time DESC LIMIT 300",
                "places.sqlite": "SELECT datetime(last_visit_date/1000000,'unixepoch') "
                                 "AS t, url, title FROM moz_places "
                                 "ORDER BY last_visit_date DESC LIMIT 300"}},
      needs_fda=True, privacy=HIGH, cache_ttl=300, optional=True,
      answers=["where did the user browse before this happened"]),
    P("content.recent_documents", "Recently opened documents per user", "content",
      ["sfltool"], kind="native", native="read_plists",
      args={"globs": ["/Users/*/Library/Application Support/com.apple.sharedfilelist/"
                      "com.apple.LSSharedFileList.RecentDocuments.sfl*"]},
      needs_fda=True, privacy=HIGH, cache_ttl=600, optional=True),

    # -- application state -------------------------------------------------
    P("apps.safari_prefs", "Safari preferences, including WebDriver state", "apps",
      ["defaults", "safaridriver"], kind="native", native="read_plists",
      args={"globs": ["/Users/*/Library/Preferences/com.apple.Safari.plist",
                      "/Users/*/Library/Preferences/com.apple.Safari.SandboxBroker.plist"]},
      needs_fda=True, cache_ttl=600, optional=True,
      answers=["was remote browser automation enabled"]),
    P("apps.global_prefs", "Security-relevant global preference domains", "apps",
      ["defaults", "plutil"], kind="native", native="read_plists",
      args={"paths": ["/Library/Preferences/com.apple.security.plist",
                      "/Library/Preferences/com.apple.SoftwareUpdate.plist",
                      "/Library/Preferences/com.apple.TimeMachine.plist",
                      "/Library/Preferences/com.apple.screensharing.plist",
                      "/Library/Preferences/com.apple.RemoteManagement.plist"]},
      cache_ttl=600),
    P("apps.installed", "Installed applications with versions and signatures", "apps",
      kind="native", native="dir_listing",
      args={"dirs": ["/Applications", "/Applications/Utilities"],
            "globs": ["/Users/*/Applications"], "limit": 500},
      cache_ttl=21600),
]


#: Binaries with no safe read-only invocation.  Each one names the evidence that
#: substitutes for it, and the bundle manifest reproduces this verbatim so a
#: reader can see exactly why a binary was not run.
OBSERVATIONAL_ONLY = {
    "SetFile": ("Only writes Finder attributes.",
                ["provenance.finder_info", "provenance.stat"]),
    "ditto": ("Only copies. Copies leave artifacts, not state to read.",
              ["storage.tmp_recent", "storage.recent_downloads", "process.snapshot"]),
    "dns-sd": ("Browse/register modes stream until killed and registration mutates "
               "mDNS state.", ["network.dns", "network.connections"]),
    "disown": ("Shell builtin; it has no state of its own.",
               ["process.snapshot"]),
    "dsexport": ("Requires an output file, so every invocation writes.",
                 ["identity.users_detail", "identity.admins"]),
    "funzip": ("A stdin filter with no queryable state.",
               ["storage.tmp_recent", "process.snapshot"]),
    "mktemp": ("Creating a temp file is its only function.",
               ["storage.tmp_recent"]),
    "notifyutil": ("Watch mode blocks forever; post mode writes Darwin notifications.",
                   ["process.snapshot", "logs.unified_security"]),
    "nscurl": ("Any invocation performs network I/O.",
               ["network.connections", "provenance.quarantine_events"]),
    "open": ("Launches applications.",
             ["persistence.launchservices", "process.snapshot"]),
    "osacompile": ("Compiles a script to a file.",
                   ["storage.tmp_recent", "provenance.stat"]),
    "osascript": ("Executes AppleScript/JXA.",
                  ["tcc.system_db", "tcc.user_db", "process.snapshot"]),
    "pkill": ("Signals processes.",
              ["process.snapshot", "persistence.launchctl_list"]),
    "say": ("Speaks text or writes an audio file.", ["process.snapshot"]),
    "snmptrap": ("Sends SNMP traps over the network.",
                 ["network.snmp_config", "network.connections"]),
    "streamzip": ("A stdin filter used for fileless staging.",
                  ["process.snapshot", "network.connections"]),
    "swift": ("Executes Swift code.", ["process.snapshot", "storage.tmp_recent"]),
    "tclsh": ("Executes Tcl code.", ["process.snapshot", "storage.tmp_recent"]),
    "tccutil": ("Only resets privacy permissions; there is no read verb.",
                ["tcc.system_db", "tcc.user_db"]),
    "tftp": ("Transfers files over the network.",
             ["network.listeners", "network.connections", "persistence.launchd_plists"]),
    "sysadminctl": ("Account management; only `-guestAccount status` reads, and that "
                    "is covered.", ["identity.guest_account", "identity.users_detail"]),
    "safaridriver": ("`--enable` mutates; there is no status verb.",
                     ["apps.safari_prefs", "process.snapshot"]),
    "systemsetup": ("Mostly setters; the `-get*` readers used here are covered.",
                    ["network.remote_login", "network.remote_appleevents"]),
    "tmutil": ("Snapshot/restore verbs mutate; the status readers are covered.",
               ["storage.timemachine_status", "storage.local_snapshots"]),
    "plutil": ("Reading is done natively with plistlib instead of exec.",
               ["apps.global_prefs", "persistence.launchd_plists"]),
    "sqlite3": ("Reading is done natively with a read-only, immutable URI instead "
                "of exec.", ["tcc.system_db", "provenance.quarantine_events"]),
    "defaults": ("Reading is done natively with plistlib instead of exec.",
                 ["apps.global_prefs", "posture.firewall"]),
    "chflags": ("Only sets flags; the flags themselves are read with `ls -lO`.",
                ["persistence.dir_flags"]),
    "caffeinate": ("Only asserts; assertions are read with `pmset -g assertions`.",
                   ["process.power_assertions"]),
    "security": ("Keychain dumping is never performed; inventory verbs are covered.",
                 ["posture.trusted_certs", "posture.keychain_list"]),
    "csrutil": ("Only `status` is read-only, and it is covered.", ["posture.sip"]),
    "spctl": ("Only `--status`/`--assess` are read-only, and both are covered.",
              ["posture.gatekeeper", "provenance.gatekeeper_assess"]),
    "log": ("`erase` is destructive; `show` is covered.",
            ["logs.unified_window", "logs.unified_security"]),
    "xattr": ("Only `-l`/`-p` read, and they are covered.", ["provenance.xattr"]),
    "networksetup": ("`-set*` verbs mutate; the `-get*`/`-list*` readers are covered.",
                     ["network.services", "network.proxies"]),
    "profiles": ("`remove` mutates; `show`/`status` are covered.",
                 ["posture.profiles", "posture.profiles_enrollment"]),
    "sfltool": ("`resetbtm` is destructive; `dumpbtm` is covered.",
                ["persistence.btm", "persistence.login_items"]),
    "lsregister": ("`-delete` is destructive; `-dump` is covered.",
                   ["persistence.launchservices"]),
    "dscl": ("Write verbs mutate the directory; read verbs are covered.",
             ["identity.users", "identity.users_detail"]),
    "hdiutil": ("`attach`/`create` mutate; `info` is covered.",
                ["storage.disk_images", "storage.mounts"]),
    "launchctl": ("`load`/`bootstrap` mutate; `list`/`print` are covered.",
                  ["persistence.launchctl_list", "persistence.launchd_plists"]),
    "ssh-keygen": ("`-D` loads a dylib; `-l` fingerprinting is covered.",
                   ["identity.ssh_key_fingerprints", "identity.ssh_authorized_keys"]),
    "nvram": ("`-d`/`-c` mutate; `-p` is covered.", ["host.nvram"]),
    "screencapture": ("Writes an image; covered only as an opt-in content probe.",
                      ["content.screenshot"]),
    "pbpaste": ("Reads the clipboard; covered only as an opt-in content probe.",
                ["content.clipboard"]),
    "textutil": ("Conversion writes files; `-info` is covered.",
                 ["provenance.textutil_info"]),
    "GetFileInfo": ("Read-only and covered.", ["provenance.finder_info"]),
    "mdfind": ("Read-only and covered.", ["storage.spotlight_recent"]),
    "mdls": ("Read-only and covered.", ["provenance.mdls"]),
    "softwareupdate": ("Install verbs mutate; `--history` is covered.",
                       ["posture.software_update_history"]),
    "sharing": ("Share creation mutates; `-l` is covered.", ["network.shares"]),
    "odutil": ("`set` mutates; `show` is covered.", ["identity.opendirectory"]),
    "dsconfigad": ("Binding changes mutate; `-show` is covered.", ["identity.ad_binding"]),
    "dscacheutil": ("`-flushcache` mutates; `-statistics` is covered.",
                    ["identity.directory_stats"]),
    "system_profiler": ("Read-only and covered.", ["host.system_profiler"]),
    "sysctl": ("Write form mutates kernel state; the read form is covered.",
               ["host.sysctl_summary"]),
    "sw_vers": ("Read-only and covered.", ["host.sw_vers"]),
    "ioreg": ("Read-only and covered.", ["host.ioreg_platform", "host.ioreg_usb"]),
    "kextstat": ("Read-only and covered.", ["host.kext_list", "host.kextstat_legacy"]),
    "last": ("Read-only and covered.", ["identity.logins"]),
    "codesign": ("Signing mutates; verification is covered.",
                 ["provenance.codesign", "provenance.codesign_verify"]),
    "scutil": ("`--set` mutates; the read verbs are covered.",
               ["network.dns", "network.proxies"]),
}

BY_ID = {probe.id: probe for probe in CATALOG}


def all_probes():
    return list(CATALOG)


def by_scope(scope):
    return [p for p in CATALOG if p.scope == scope or p.scope == BOTH]


def loobins_covered():
    """LOOBins that have at least one probe collecting evidence for them."""
    covered = set()
    for probe in CATALOG:
        covered.update(probe.loobins)
    return covered


def coverage(known_loobins, capabilities=None, privacy=None):
    """Per-binary coverage status for a sweep.

    ``known_loobins`` is the rulepack's binary list, so coverage is measured
    against the real corpus rather than against a hardcoded copy of it.
    """
    capabilities = capabilities or {}
    privacy = privacy or {}
    allow_content = privacy.get("capture_content", True)
    report = {}
    for name in sorted(known_loobins):
        probes = [p for p in CATALOG if name in p.loobins]
        runnable = []
        excluded = []
        for probe in probes:
            if probe.privacy == HIGH and not allow_content:
                excluded.append(probe.id)
                continue
            if probe.needs_root and not capabilities.get("root", True):
                continue
            if probe.needs_fda and not capabilities.get("fda", True):
                continue
            if probe.needs_session and not capabilities.get("session", True):
                continue
            runnable.append(probe.id)
        if runnable:
            entry = {"status": "covered", "probes": runnable}
            if name in OBSERVATIONAL_ONLY:
                # The binary itself was never executed.  Say so: the evidence is
                # the state it would have changed, not the tool's own output.
                note, _ = OBSERVATIONAL_ONLY[name]
                entry["note"] = ("binary not executed; covered by artifact state. "
                                 + note)
            report[name] = entry
        elif excluded:
            report[name] = {"status": "policy_excluded",
                            "reason": "content capture disabled by configuration",
                            "probes": excluded}
        elif probes:
            report[name] = {"status": "unavailable",
                            "reason": "host capability missing (root/FDA/GUI session)",
                            "probes": [p.id for p in probes]}
        else:
            note, substitutes = OBSERVATIONAL_ONLY.get(
                name, ("No read-only invocation defined.", []))
            report[name] = {"status": "observational_only", "reason": note,
                            "artifact_state": substitutes}
    return report


def summarize_coverage(report):
    summary = {}
    for entry in report.values():
        summary[entry["status"]] = summary.get(entry["status"], 0) + 1
    return summary
