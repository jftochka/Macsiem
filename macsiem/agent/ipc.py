"""Unix-socket protocol between the root daemon and the per-user session agent.

Deliberately tiny.  The daemon sends a probe *id* from the catalog and a context
dict; the session agent refuses anything that is not a session-scoped probe in
its own copy of the catalog.  No argv crosses the socket, so a compromised
daemon still cannot make the session agent run an arbitrary command.

Peer credentials are checked with ``SO_PEERCRED`` where available (``LOCAL_PEERCRED``
on Darwin) so an unprivileged process cannot impersonate the daemon.
"""

from __future__ import annotations

import json
import os
import socket
import struct

MAX_MESSAGE = 8 * 1024 * 1024


def send(sock, payload):
    body = json.dumps(payload, default=str).encode("utf-8")
    sock.sendall(struct.pack("!I", len(body)) + body)


def receive(sock):
    header = _read_exactly(sock, 4)
    if not header:
        return None
    (length,) = struct.unpack("!I", header)
    if length > MAX_MESSAGE:
        raise ValueError("message too large: %d bytes" % length)
    body = _read_exactly(sock, length)
    if body is None:
        return None
    return json.loads(body.decode("utf-8"))


def _read_exactly(sock, count):
    chunks = []
    remaining = count
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def peer_uid(sock):
    """Return the connecting process's uid, or ``None`` if unavailable."""
    try:
        if hasattr(socket, "SO_PEERCRED"):      # Linux
            data = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                   struct.calcsize("3i"))
            _pid, uid, _gid = struct.unpack("3i", data)
            return uid
        LOCAL_PEERCRED = 0x001                  # Darwin
        data = sock.getsockopt(0, LOCAL_PEERCRED, 128)
        # struct xucred: version, uid, ngroups, groups[16]
        _version, uid = struct.unpack("2I", data[:8])
        return uid
    except (OSError, struct.error, ValueError):
        return None


def socket_path(config):
    return config.get_path("paths.socket", "/var/run/macsiem-session.sock")


def connect(path, timeout=30):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect(path)
    return sock


def listen(path, mode=0o660):
    if os.path.exists(path):
        os.unlink(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    os.chmod(path, mode)
    server.listen(8)
    return server
