"""The one and only process-execution path in MacSIEM.

Every rule in docs/SAFETY.md hangs off this module:

* ``run()`` and ``stream()`` accept an **argv list**, never a command string.
  There is no ``shell=True`` in this file, and ``tests/test_safety.py`` fails
  the build if one appears anywhere in the tree.
* Children get a scrubbed environment (no ``DYLD_*``/``LD_*`` inheritance), a
  fresh session so a runaway process group can be killed as a unit, a wall-clock
  timeout, an output cap, and a lowered scheduling priority.
* ``Runner`` is an interface.  ``SubprocessRunner`` really executes;
  ``FixtureRunner`` replays recorded output so the whole platform -- detection,
  sweep, correlation, bundling -- is testable on Linux with no Mac present.
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time

from . import timeutil

DEFAULT_TIMEOUT = 15.0
DEFAULT_MAX_BYTES = 4 * 1024 * 1024
DEFAULT_NICE = 10

#: Environment handed to children.  Deliberately tiny: a sweep must not inherit
#: dynamic-linker variables or a locale that reshapes command output.
BASE_ENV = {
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "LANG": "C",
    "LC_ALL": "C",
    "TZ": "UTC",
    "HOME": "/var/empty",
}


class ArgvError(ValueError):
    """Raised when something that is not a safe argv list reaches the runner."""


def assert_argv(argv):
    """Validate an argv list.  Raises :class:`ArgvError`; never returns falsy.

    This is a type/shape gate, not the policy gate -- policy (is this command
    read-only?) lives in :mod:`macsiem.evidence.safety`.  Both must pass.
    """
    if isinstance(argv, (str, bytes)):
        raise ArgvError("argv must be a list of strings, not a command string: %r" % (argv,))
    if not isinstance(argv, (list, tuple)) or not argv:
        raise ArgvError("argv must be a non-empty list, got %r" % (argv,))
    for index, element in enumerate(argv):
        if not isinstance(element, str):
            raise ArgvError("argv[%d] is %s, expected str" % (index, type(element).__name__))
        if "\x00" in element:
            raise ArgvError("argv[%d] contains a NUL byte" % index)
    if not argv[0].startswith("/"):
        raise ArgvError("argv[0] must be an absolute path, got %r" % argv[0])
    return list(argv)


class ProcResult:
    """Outcome of one command.  Always returned -- failures are data, not raises."""

    __slots__ = (
        "argv", "returncode", "stdout", "stderr", "duration_ms", "timed_out",
        "truncated", "error", "started_at", "source",
    )

    def __init__(self, argv, returncode=None, stdout="", stderr="", duration_ms=0,
                 timed_out=False, truncated=False, error=None, started_at=None,
                 source="subprocess"):
        self.argv = list(argv)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.duration_ms = duration_ms
        self.timed_out = timed_out
        self.truncated = truncated
        self.error = error
        self.started_at = started_at or timeutil.now_iso()
        self.source = source

    @property
    def ok(self):
        return self.returncode == 0 and not self.timed_out and self.error is None

    def to_dict(self, include_stdout=False):
        record = {
            "argv": self.argv,
            "returncode": self.returncode,
            "duration_ms": self.duration_ms,
            "timed_out": self.timed_out,
            "truncated": self.truncated,
            "error": self.error,
            "started_at": self.started_at,
            "source": self.source,
            "stderr": self.stderr[:4096],
        }
        if include_stdout:
            record["stdout"] = self.stdout
        return record

    def __repr__(self):
        return "<ProcResult rc=%s %dms %s>" % (
            self.returncode, self.duration_ms, " ".join(self.argv[:3]))


class Runner:
    """Execution interface.  Swap the implementation, keep the platform."""

    def run(self, argv, timeout=DEFAULT_TIMEOUT, stdin_data=None,
            max_bytes=DEFAULT_MAX_BYTES, cwd="/"):
        raise NotImplementedError

    def stream(self, argv, on_line, stop_event, stderr_lines=None):
        raise NotImplementedError

    def exists(self, path):
        raise NotImplementedError


class SubprocessRunner(Runner):
    """Real execution against the live host."""

    def __init__(self, nice=DEFAULT_NICE, env=None):
        self.nice = nice
        self.env = dict(env or BASE_ENV)

    def exists(self, path):
        return os.path.exists(path)

    def _deprioritize(self, pid):
        """Lower child priority after spawn.

        Done post-fork rather than via ``preexec_fn``: preexec_fn is documented
        as unsafe in the presence of threads, and the sweep orchestrator is a
        thread pool.
        """
        if not self.nice:
            return
        try:
            os.setpriority(os.PRIO_PGRP, os.getpgid(pid), self.nice)
        except (OSError, AttributeError, PermissionError):
            pass

    def run(self, argv, timeout=DEFAULT_TIMEOUT, stdin_data=None,
            max_bytes=DEFAULT_MAX_BYTES, cwd="/"):
        argv = assert_argv(argv)
        started = time.time()
        started_at = timeutil.now_iso()
        try:
            process = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
                cwd=cwd,
                env=self.env,
                start_new_session=True,   # own process group -> killable as a unit
                close_fds=True,
            )
        except (OSError, ValueError) as exc:
            return ProcResult(argv, returncode=None, error=str(exc),
                              duration_ms=int((time.time() - started) * 1000),
                              started_at=started_at)

        self._deprioritize(process.pid)
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        truncated = {"stdout": False, "stderr": False}
        caps = {"stdout": max_bytes, "stderr": min(max_bytes, 256 * 1024)}

        def drain(name, pipe):
            try:
                while True:
                    block = pipe.read(65536)
                    if not block:
                        break
                    room = caps[name] - len(buffers[name])
                    if room > 0:
                        buffers[name].extend(block[:room])
                    if len(block) > room:
                        truncated[name] = True
            except (OSError, ValueError):
                pass
            finally:
                try:
                    pipe.close()
                except OSError:
                    pass

        threads = []
        for name in ("stdout", "stderr"):
            thread = threading.Thread(
                target=drain, args=(name, getattr(process, name)), daemon=True)
            thread.start()
            threads.append(thread)

        if stdin_data is not None:
            try:
                process.stdin.write(stdin_data.encode() if isinstance(stdin_data, str)
                                    else stdin_data)
                process.stdin.close()
            except (OSError, BrokenPipeError):
                pass

        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._kill_group(process)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass

        for thread in threads:
            thread.join(timeout=2)

        return ProcResult(
            argv,
            returncode=process.returncode,
            stdout=bytes(buffers["stdout"]).decode("utf-8", "replace"),
            stderr=bytes(buffers["stderr"]).decode("utf-8", "replace"),
            duration_ms=int((time.time() - started) * 1000),
            timed_out=timed_out,
            truncated=truncated["stdout"] or truncated["stderr"],
            started_at=started_at,
        )

    @staticmethod
    def _kill_group(process):
        """SIGTERM the whole process group, then SIGKILL what survives.

        Group-wide because ``log stream`` and friends spawn helpers that outlive
        a bare ``process.kill()``.
        """
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(os.getpgid(process.pid), sig)
            except (OSError, ProcessLookupError):
                try:
                    process.kill()
                except OSError:
                    pass
                return
            if sig is signal.SIGTERM:
                time.sleep(0.5)
                if process.poll() is not None:
                    return

    def stream(self, argv, on_line, stop_event, stderr_lines=None):
        """Run a long-lived producer (``eslogger``, ``log stream``) line by line.

        Blocks until the child exits or ``stop_event`` is set.  Returns the exit
        code, which the sensor supervisor uses to decide whether to restart.
        """
        argv = assert_argv(argv)
        process = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            cwd="/",
            env=self.env,
            start_new_session=True,
            close_fds=True,
            bufsize=1,
            text=True,
            errors="replace",
        )
        self._deprioritize(process.pid)

        def watch_stop():
            while not stop_event.wait(0.5):
                if process.poll() is not None:
                    return
            self._kill_group(process)

        def drain_stderr():
            for line in process.stderr:
                if stderr_lines is not None:
                    stderr_lines.append(line.rstrip("\n"))

        threading.Thread(target=watch_stop, daemon=True).start()
        threading.Thread(target=drain_stderr, daemon=True).start()

        try:
            for line in process.stdout:
                if stop_event.is_set():
                    break
                line = line.rstrip("\n")
                if line:
                    on_line(line)
        except (OSError, ValueError):
            pass
        finally:
            if process.poll() is None:
                self._kill_group(process)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        return process.returncode


class FixtureRunner(Runner):
    """Replays recorded command output.  Runs nothing.

    Lets the full pipeline be exercised on Linux/CI.  Lookup is by exact argv
    first, then by a prefix match (so a probe that substitutes a target path
    still resolves to a generic fixture), then by argv[0] basename.
    """

    def __init__(self, fixtures=None, default=None, strict=False):
        self.fixtures = dict(fixtures or {})
        self.default = default
        self.strict = strict
        self.calls = []
        self.existing_paths = set()

    @staticmethod
    def key(argv):
        return " ".join(argv)

    def add(self, argv, stdout="", stderr="", returncode=0):
        self.fixtures[self.key(argv) if isinstance(argv, (list, tuple)) else argv] = {
            "stdout": stdout, "stderr": stderr, "returncode": returncode}
        return self

    def exists(self, path):
        return path in self.existing_paths or not self.strict

    def _lookup(self, argv):
        key = self.key(argv)
        if key in self.fixtures:
            return self.fixtures[key]
        for candidate, value in self.fixtures.items():
            if key.startswith(candidate) or candidate.startswith(key):
                return value
        basename = os.path.basename(argv[0])
        if basename in self.fixtures:
            return self.fixtures[basename]
        return None

    def run(self, argv, timeout=DEFAULT_TIMEOUT, stdin_data=None,
            max_bytes=DEFAULT_MAX_BYTES, cwd="/"):
        argv = assert_argv(argv)
        self.calls.append(list(argv))
        entry = self._lookup(argv)
        if entry is None:
            if self.strict:
                raise KeyError("no fixture for: %s" % self.key(argv))
            entry = self.default or {"stdout": "", "stderr": "no fixture", "returncode": 127}
        stdout = entry.get("stdout", "")
        truncated = len(stdout.encode("utf-8", "replace")) > max_bytes
        if truncated:
            stdout = stdout.encode("utf-8", "replace")[:max_bytes].decode("utf-8", "replace")
        return ProcResult(
            argv,
            returncode=entry.get("returncode", 0),
            stdout=stdout,
            stderr=entry.get("stderr", ""),
            duration_ms=entry.get("duration_ms", 1),
            timed_out=entry.get("timed_out", False),
            truncated=truncated,
            source="fixture",
        )

    def stream(self, argv, on_line, stop_event, stderr_lines=None):
        argv = assert_argv(argv)
        self.calls.append(list(argv))
        entry = self._lookup(argv) or {"stdout": ""}
        for line in entry.get("stdout", "").splitlines():
            if stop_event.is_set():
                break
            if line.strip():
                on_line(line)
        return entry.get("returncode", 0)


_DEFAULT_RUNNER = None


def default_runner():
    """Process-wide runner.  Swapped wholesale by tests and by --offline."""
    global _DEFAULT_RUNNER
    if _DEFAULT_RUNNER is None:
        _DEFAULT_RUNNER = SubprocessRunner()
    return _DEFAULT_RUNNER


def set_default_runner(runner):
    global _DEFAULT_RUNNER
    _DEFAULT_RUNNER = runner
    return runner
