"""Per-user LaunchAgent.

A root LaunchDaemon has no GUI session, so ``pbpaste`` returns nothing and
``screencapture`` captures nothing.  With content capture enabled -- which it is
by default on this deployment -- those probes have to run inside the logged-in
user's session, which is what this process is for.

It only ever runs probes that are (a) in the shipped catalog, (b) marked
``needs_session``, and (c) still pass the safety guard at request time.  The
daemon cannot ask it for anything else.
"""

from __future__ import annotations

import os
import socket
import threading

from ..evidence import probes as probes_mod, runner as runner_mod, safety
from ..util import proc, timeutil
from . import ipc

ALLOWED = {probe.id for probe in probes_mod.CATALOG if probe.needs_session}


class SessionAgent:
    def __init__(self, config, runner=None):
        self.config = config
        self.runner = runner or proc.default_runner()
        self.path = ipc.socket_path(config)
        self.stop_event = threading.Event()
        self.server = None

    def run(self):
        self.server = ipc.listen(self.path)
        os.environ["MACSIEM_SESSION_AGENT"] = "1"
        while not self.stop_event.is_set():
            try:
                self.server.settimeout(1.0)
                client, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(client,), daemon=True).start()
        return 0

    def _serve(self, client):
        try:
            uid = ipc.peer_uid(client)
            request = ipc.receive(client)
            if not request:
                return
            response = self._handle(request, uid)
            ipc.send(client, response)
        except (OSError, ValueError) as exc:
            try:
                ipc.send(client, {"error": str(exc)})
            except OSError:
                pass
        finally:
            try:
                client.close()
            except OSError:
                pass

    def _handle(self, request, uid):
        if uid not in (None, 0, os.geteuid()):
            return {"error": "peer uid %s is not permitted" % uid}
        probe_id = request.get("probe_id")
        if probe_id not in ALLOWED:
            # The whole point of passing ids rather than argv.
            return {"error": "probe %r is not a session probe" % probe_id}
        probe = probes_mod.BY_ID[probe_id]
        try:
            safety.validate_probe(probe)
        except safety.UnsafeProbe as exc:
            return {"error": "guard refused: %s" % exc}
        ctx = dict(request.get("ctx") or {})
        ctx["_capabilities"] = dict(ctx.get("_capabilities") or {}, session=True)
        result = runner_mod.run_probe(probe, ctx, runner=self.runner,
                                      config=self.config,
                                      bundle_dir=request.get("bundle_dir"))
        result["session_agent"] = {"uid": os.geteuid(), "ts": timeutil.now_iso()}
        return dict(result)


def request(config, probe_id, ctx=None, bundle_dir=None, timeout=30):
    """Client side, used by the orchestrator for session-scoped probes."""
    path = ipc.socket_path(config)
    if not os.path.exists(path):
        return {"probe_id": probe_id,
                "skipped_reason": "session agent not running (no socket at %s)" % path}
    try:
        sock = ipc.connect(path, timeout)
        try:
            ipc.send(sock, {"probe_id": probe_id, "ctx": ctx or {},
                            "bundle_dir": bundle_dir})
            return ipc.receive(sock) or {
                "probe_id": probe_id, "skipped_reason": "no response from session agent"}
        finally:
            sock.close()
    except (OSError, ValueError) as exc:
        return {"probe_id": probe_id,
                "skipped_reason": "session agent unreachable: %s" % exc}
