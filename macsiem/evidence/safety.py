"""The guard: independent validation that nothing MacSIEM runs can change the host.

Layered deliberately, because the input corpus for this whole project is a
catalogue of attack commands and one check is not enough:

1. **Structural** -- :mod:`macsiem.util.proc` takes argv lists only and there is
   no ``shell=True`` in the tree (``tests/test_safety.py`` greps for it).
2. **Allowlist** -- only probes in :mod:`macsiem.evidence.probes` can execute.
   The orchestrator takes probe *ids*; an event field can never become a command.
3. **Denylist** (this module) -- every probe is validated at import, again at
   daemon start, and once more immediately before it is spawned.
4. **Corpus firewall** -- LOOBins ``code`` strings never reach an argv.
5. **OS-level** -- probe children run with ``RLIMIT_FSIZE = 0`` so the kernel
   refuses any write, whatever the argv says (see :mod:`macsiem.evidence.runner`).

Validation is fail-closed: a violation raises, the daemon refuses to start, and
``macsiem doctor`` prints exactly which probe failed and why.
"""

from __future__ import annotations

import os
import re

#: argv[0] must live somewhere the system owns.
ALLOWED_PREFIXES = (
    "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/",
    "/System/Library/", "/System/Cryptexes/",
)

#: Tokens that change state.  Matched case-insensitively against every argv
#: element of every probe.  Derived from the destructive-command audit of the
#: LOOBins corpus recorded in docs/SAFETY.md.
DENY_TOKENS = {
    "disable", "enable", "erase", "delete", "remove", "rm", "unlink", "destroy",
    "reset", "resetbtm", "format", "eject", "detach", "unmount", "umount",
    "load", "unload", "bootstrap", "bootout", "kickstart", "kill", "stop",
    "start", "restart", "reboot", "shutdown", "halt",
    "install", "uninstall", "update", "upgrade", "downgrade",
    "create", "add", "new", "write", "edit", "modify", "set", "put", "import",
    "restore", "revert", "rollback", "rename", "move", "mv", "copy", "cp",
    "chmod", "chown", "chgrp", "touch", "mkdir", "ln",
    "dump-keychain", "add-trusted-cert", "delete-keychain", "unlock-keychain",
    "--master-disable", "--global-disable", "netboot", "addexclusion",
    "-addUser", "-deleteUser", "-resetPasswordFor", "-secureTokenOn",
    "-secureTokenOff", "-adminUser", "-smbGuestAccess", "-afpGuestAccess",
    "-passwd", "passwd", "-delete",
    "localsnapshot", "deletelocalsnapshots", "startbackup", "stopbackup",
    "-setwebproxy", "-setsecurewebproxy", "-setautoproxyurl",
    "-setremotelogin", "-setremoteappleevents", "-setcomputername",
}

#: Short flags are ambiguous across binaries -- `-c` clears attributes for
#: `xattr`, selects a class for `ioreg` and reads a plist for `nvram` -- so they
#: are denied per binary rather than globally.
DENY_FLAGS_BY_BINARY = {
    "xattr": {"-d", "-c", "-w", "--delete", "--clear", "--write"},
    "nvram": {"-d", "-c"},
    "ssh-keygen": {"-D", "-R", "-p", "-P", "-N", "-A", "-I"},
    "security": {"-D", "-d"},
    "sysctl": {"-w"},
    "codesign": {"-s", "--sign", "-f", "--force", "--remove-signature"},
    "tmutil": {"-d", "-p"},
    "pmset": {"-a", "-b", "-c", "-u"},
    "networksetup": {"-setv6off", "-setv6automatic"},
    "csrutil": {"--no-internal"},
    "mdfind": {"-live"},
}

#: Flag shapes that assign rather than read.
DENY_PATTERNS = (
    re.compile(r"^--?set[A-Za-z-]", re.I),
    re.compile(r"^--?(add|del|new|write|create|remove|enable|disable)[A-Za-z-]*$", re.I),
    re.compile(r"^--force$", re.I),
)

#: Characters that only matter to a shell.  Nothing here ever runs under one, so
#: no probe needs them -- their presence means an argv was built wrong.
SHELL_METACHARS = set(";|&$`<>\n\r\x00\\")

#: Per-binary verb allowlists.  The catalog is already an allowlist; this is the
#: independent second opinion, so it is written from the man pages rather than
#: generated from the catalog.
VERB_ALLOWLIST = {
    "csrutil": {"status", "authenticated-root"},
    "spctl": {"--status", "--assess", "--type", "execute", "-vv", "--verbose"},
    "tmutil": {"status", "destinationinfo", "listlocalsnapshots", "listbackups",
               "latestbackup", "machinedirectory", "/"},
    "log": {"show", "stats", "--style", "ndjson", "--start", "--end", "--last",
            "--info", "--debug", "--predicate"},
    "dscl": {".", "-list", "-read", "-readall", "-search", "list", "read", "cat"},
    "sysadminctl": {"-guestAccount", "status"},
    "xattr": {"-l", "-p", "-r"},
    "launchctl": {"list", "print", "system", "procinfo", "dumpjpcategory"},
    "sfltool": {"dumpbtm"},
    "lsregister": {"-dump"},
    "profiles": {"show", "status", "-type", "enrollment", "list"},
    "security": {"find-certificate", "list-keychains", "-a", "-Z", "-p"},
    "hdiutil": {"info", "imageinfo", "-plist"},
    "networksetup": {"-listallnetworkservices", "-listallhardwareports", "-getinfo",
                     "-getwebproxy", "-getsecurewebproxy", "-getautoproxyurl",
                     "-getdnsservers", "-getproxybypassdomains"},
    "systemsetup": {"-getremotelogin", "-getremoteappleevents", "-getcomputername",
                    "-gettimezone", "-getusingnetworktime"},
    "scutil": {"--dns", "--proxy", "--get", "--nc", "ComputerName", "LocalHostName",
               "HostName", "list"},
    "softwareupdate": {"--history", "--list-full-installers", "--schedule"},
    "nvram": {"-p", "-x"},
    "odutil": {"show", "sessions", "statistics", "nodenames"},
    "dscacheutil": {"-statistics", "-configuration", "-q", "-a"},
    "dsconfigad": {"-show"},
    "ssh-keygen": {"-l", "-f", "-E"},
    "sharing": {"-l"},
    "codesign": {"-d", "-dv", "-dvv", "-dvvv", "--entitlements", ":-", "--verify",
                 "--verbose=4", "--display", "-r", "-"},
    "kmutil": {"showloaded", "--no-kernel-components"},
    "kextstat": {"-l", "-k"},
    "pmset": {"-g", "assertions", "custom", "ps"},
    "mdfind": {"-onlyin", "-count", "-name"},
    "textutil": {"-info"},
    "GetFileInfo": set(),
    "screencapture": {"-x", "-t", "png"},
}

#: Documented, reviewed exemptions.  A probe may carry an argument that trips a
#: generic check only if it declares ``exception`` and the argument passes a
#: purpose-built validator.  ``tests/test_safety.py`` enumerates every one.
ELEMENT_VALIDATORS = {}


class UnsafeProbe(Exception):
    """A probe failed validation.  Always fatal: the daemon will not start."""


def _validate_log_predicate(value):
    """Allow unified-log predicate syntax, nothing more."""
    if not re.fullmatch(r"[A-Za-z0-9_.\"'= !><()\[\]\-/:,*%@]+", value or ""):
        return False
    lowered = value.lower()
    banned = ("$(", "`", ";", "|", "&&", "\n")
    return not any(token in lowered for token in banned)


def _validate_spotlight_query(value):
    if not re.fullmatch(r"[A-Za-z0-9_.\"'= ()><\-$:,*/@]+", value or ""):
        return False
    return "`" not in value and ";" not in value


ELEMENT_VALIDATORS["log_predicate"] = _validate_log_predicate
ELEMENT_VALIDATORS["spotlight_query"] = _validate_spotlight_query

#: The complete set of free-form arguments in the entire product: three
#: strings, written out literally so that review is possible.  An element is
#: exempt from the metacharacter and verb checks only if it is *exactly* one of
#: these AND its validator passes -- so appending or substituting anything is
#: still caught.  tests/test_safety.py asserts each value really appears in the
#: probe that claims it, so this list cannot drift from the catalog.
_EXEMPT_ELEMENTS = {
    "logs.unified_window": ("log_predicate", frozenset([
        'eventMessage != ""'])),
    "logs.unified_security": ("log_predicate", frozenset([
        'subsystem == "com.apple.TCC" OR process == "sudo" OR '
        'process == "sshd" OR process == "XProtect" OR '
        'process == "loginwindow" OR process == "securityd"'])),
    "storage.spotlight_recent": ("spotlight_query", frozenset([
        "kMDItemFSCreationDate >= $time.now(-86400)"])),
}

SLOTS = ("{target_path}", "{target_pid}", "{target_user}", "{window_start}",
         "{window_end}", "{artifact}")


def _is_slot(element):
    return element in SLOTS


def validate_probe(probe, strict_paths=False):
    """Validate one probe.  Raises :class:`UnsafeProbe`, returns ``True`` on pass."""
    if probe.kind == "native":
        # Native probes never spawn anything; their file access goes through
        # read-only opens and immutable sqlite URIs (see native.py).
        if probe.argv:
            raise UnsafeProbe("%s: native probe must not declare argv" % probe.id)
        if not probe.native:
            raise UnsafeProbe("%s: native probe must name a handler" % probe.id)
        return True

    argv = probe.argv
    if not argv:
        raise UnsafeProbe("%s: exec probe has no argv" % probe.id)
    if isinstance(argv, str):
        raise UnsafeProbe("%s: argv is a string, not a list" % probe.id)

    binary = argv[0]
    if not binary.startswith("/"):
        raise UnsafeProbe("%s: argv[0] is not absolute: %r" % (probe.id, binary))
    if not binary.startswith(ALLOWED_PREFIXES):
        raise UnsafeProbe("%s: argv[0] outside allowed system paths: %s"
                          % (probe.id, binary))
    if strict_paths and not os.path.exists(binary):
        raise UnsafeProbe("%s: %s does not exist on this host" % (probe.id, binary))

    basename = os.path.basename(binary)
    allowed_verbs = VERB_ALLOWLIST.get(basename)
    denied_flags = {f.lower() for f in DENY_FLAGS_BY_BINARY.get(basename, ())}
    validator_name, exempt_values = _EXEMPT_ELEMENTS.get(probe.id, (None, frozenset()))
    seen_verb = False

    for index, element in enumerate(argv[1:], start=1):
        if not isinstance(element, str):
            raise UnsafeProbe("%s: argv[%d] is not a string" % (probe.id, index))
        if _is_slot(element):
            if element == "{artifact}" and not probe.writes_artifact:
                raise UnsafeProbe("%s: uses {artifact} without declaring "
                                  "writes_artifact" % probe.id)
            continue

        exempt = False
        if validator_name and element in exempt_values:
            if not ELEMENT_VALIDATORS[validator_name](element):
                raise UnsafeProbe("%s: argv[%d] failed the %s validator"
                                  % (probe.id, index, validator_name))
            exempt = True

        if not exempt:
            bad = set(element) & SHELL_METACHARS
            if bad:
                raise UnsafeProbe("%s: argv[%d] contains shell metacharacter(s) %r"
                                  % (probe.id, index, "".join(sorted(bad))))
            reason = _denied(element)
            if reason:
                raise UnsafeProbe("%s: argv[%d] %r is a mutating token (%s)"
                                  % (probe.id, index, element, reason))
            if element.lower() in denied_flags:
                raise UnsafeProbe("%s: argv[%d] %r is a mutating flag for %s"
                                  % (probe.id, index, element, basename))

        # Only the subcommand (first bare word) and the flags are verbs; tokens
        # after that are values -- `dscl . -readall /Users RecordName` asks for
        # an attribute, it does not invoke one.
        if allowed_verbs is not None and not exempt:
            is_flag = _looks_like_flag(element)
            is_subcommand = not is_flag and _looks_like_verb(element) and not seen_verb
            if not is_flag and _looks_like_verb(element):
                seen_verb = True
            if (is_flag or is_subcommand) and element not in allowed_verbs:
                raise UnsafeProbe("%s: %r is not in the read-only verb allowlist "
                                  "for %s" % (probe.id, element, basename))

    # A probe that writes must write to the bundle, and only through the slot:
    # a literal destination path would bypass the runtime containment check.
    if probe.writes_artifact and argv.count("{artifact}") != 1:
        raise UnsafeProbe("%s: declares writes_artifact but does not take exactly "
                          "one {artifact} slot" % probe.id)
    return True


def _looks_like_flag(element):
    return element.startswith("-")


def _looks_like_verb(element):
    """Verbs and flags are checked; free-form values (paths, queries) are not."""
    if element.startswith("/") or element.startswith("{"):
        return False
    if " " in element:
        return False
    return True


def _denied(element):
    lowered = element.lower()
    if lowered in {token.lower() for token in DENY_TOKENS}:
        return "denylisted token"
    for pattern in DENY_PATTERNS:
        if pattern.match(element):
            return "assignment-shaped flag %s" % pattern.pattern
    return None


def validate_catalog(catalog, strict_paths=False):
    """Validate every probe.  Returns the count; raises on the first failure."""
    seen = set()
    for probe in catalog:
        if probe.id in seen:
            raise UnsafeProbe("duplicate probe id: %s" % probe.id)
        seen.add(probe.id)
        validate_probe(probe, strict_paths=strict_paths)
    return len(catalog)


def validate_runtime_argv(probe, argv, bundle_dir=None):
    """Final check on the fully substituted argv, immediately before spawning.

    Substituted values come from events, so they are untrusted.  Nothing runs
    under a shell, but a path that escapes the bundle directory, or a NUL in an
    argument, is still refused here rather than passed to ``execve``.
    """
    if isinstance(argv, str) or not argv:
        raise UnsafeProbe("%s: runtime argv must be a non-empty list" % probe.id)
    if argv[0] != probe.argv[0]:
        raise UnsafeProbe("%s: argv[0] changed during substitution (%s -> %s)"
                          % (probe.id, probe.argv[0], argv[0]))
    if len(argv) != len(probe.argv):
        raise UnsafeProbe("%s: argv length changed during substitution" % probe.id)
    for index, element in enumerate(argv):
        if not isinstance(element, str):
            raise UnsafeProbe("%s: runtime argv[%d] is not a string" % (probe.id, index))
        if "\x00" in element:
            raise UnsafeProbe("%s: runtime argv[%d] contains NUL" % (probe.id, index))
    if probe.writes_artifact:
        if not bundle_dir:
            raise UnsafeProbe("%s: writes an artifact but no bundle directory "
                              "was given" % probe.id)
        target = argv[-1]
        resolved = os.path.realpath(target)
        root = os.path.realpath(bundle_dir)
        if not (resolved == root or resolved.startswith(root + os.sep)):
            raise UnsafeProbe("%s: artifact path %s escapes the bundle directory %s"
                              % (probe.id, resolved, root))
    return True


def self_audit(catalog, strict_paths=False):
    """Run at daemon start and by ``macsiem doctor``.  Returns a report dict."""
    report = {"probes": len(catalog), "failures": [], "exceptions": []}
    for probe in catalog:
        try:
            validate_probe(probe, strict_paths=strict_paths)
        except UnsafeProbe as exc:
            report["failures"].append(str(exc))
        if probe.exception:
            report["exceptions"].append({"probe": probe.id, "why": probe.exception})
    report["ok"] = not report["failures"]
    return report
