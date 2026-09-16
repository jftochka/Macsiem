"""Native probes: evidence collected in-process, with no command execution.

Preferred over exec wherever possible.  Reading a plist with :mod:`plistlib` and
a SQLite database through a ``mode=ro&immutable=1`` URI is not merely safer than
shelling out to ``defaults``/``plutil``/``sqlite3`` -- it is *structurally
incapable* of writing, and it removes three LOOBins from the exec surface
altogether.

Every handler is read-only by construction: files are opened ``"rb"``, SQLite
connections are read-only and immutable, and nothing here creates, renames or
unlinks anything.
"""

from __future__ import annotations

import glob as globmod
import os
import plistlib
import sqlite3
import stat as statmod

from ..util import timeutil

MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_ROWS = 1000


class NativeError(Exception):
    pass


def _expand(paths=None, globs=None, limit=400):
    resolved = []
    for path in paths or []:
        if os.path.exists(path):
            resolved.append(path)
    for pattern in globs or []:
        resolved.extend(sorted(globmod.glob(pattern))[:limit])
    seen, unique = set(), []
    for path in resolved:
        if path not in seen:
            seen.add(path)
            unique.append(path)
    return unique[:limit]


def _file_meta(path):
    try:
        info = os.lstat(path)
    except OSError as exc:
        return {"path": path, "error": str(exc)}
    return {
        "path": path,
        "bytes": info.st_size,
        "mode": statmod.filemode(info.st_mode),
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mtime": timeutil.to_iso(timeutil.from_epoch(info.st_mtime)),
        "ctime": timeutil.to_iso(timeutil.from_epoch(info.st_ctime)),
        "birthtime": timeutil.to_iso(timeutil.from_epoch(
            getattr(info, "st_birthtime", info.st_ctime))),
        "symlink": statmod.S_ISLNK(info.st_mode),
    }


# -- handlers ---------------------------------------------------------------
def read_plist(args, ctx=None):
    return read_plists({"paths": [args["path"]]}, ctx)


def read_plists(args, ctx=None):
    """Parse property lists (binary or XML) into JSON-able structures."""
    results = []
    for path in _expand(args.get("paths"), args.get("globs")):
        entry = _file_meta(path)
        try:
            if entry.get("bytes", 0) > MAX_FILE_BYTES:
                entry["error"] = "larger than %d bytes; not parsed" % MAX_FILE_BYTES
            else:
                with open(path, "rb") as handle:
                    entry["plist"] = _jsonable(plistlib.load(handle))
        except (OSError, plistlib.InvalidFileException, ValueError) as exc:
            entry["error"] = str(exc)
        results.append(entry)
    return {"files": results, "count": len(results)}


def read_plists_in_dirs(args, ctx=None):
    """Every plist in a set of directories -- the persistence surface."""
    globs = list(args.get("globs") or [])
    for directory in args.get("dirs") or []:
        globs.append(os.path.join(directory, "*.plist"))
    return read_plists({"globs": globs}, ctx)


def read_text_files(args, ctx=None):
    """Read text files, optionally only their tail (for large logs)."""
    tail = args.get("tail_bytes")
    results = []
    for path in _expand(args.get("paths"), args.get("globs")):
        entry = _file_meta(path)
        try:
            with open(path, "rb") as handle:
                if tail and entry.get("bytes", 0) > tail:
                    handle.seek(-int(tail), os.SEEK_END)
                    entry["truncated_head"] = True
                data = handle.read(MAX_FILE_BYTES)
            entry["text"] = data.decode("utf-8", "replace")
        except OSError as exc:
            entry["error"] = str(exc)
        results.append(entry)
    return {"files": results, "count": len(results)}


def read_sqlite(args, ctx=None):
    """Query SQLite databases read-only and immutably.

    ``immutable=1`` additionally stops SQLite from touching the WAL or journal,
    which matters on TCC.db and browser databases that are open elsewhere: a
    forensic read must not modify the artifact it is reading.
    """
    query = args.get("query")
    by_file = args.get("query_by_file") or {}
    results = []
    for path in _expand(args.get("paths"), args.get("globs")):
        entry = _file_meta(path)
        statement = query
        if not statement:
            for suffix, candidate in by_file.items():
                if os.path.basename(path) == suffix or path.endswith(suffix):
                    statement = candidate
                    break
        if not statement:
            entry["error"] = "no query defined for this file"
            results.append(entry)
            continue
        try:
            uri = "file:%s?mode=ro&immutable=1" % _uri_escape(os.path.abspath(path))
            connection = sqlite3.connect(uri, uri=True, timeout=5)
            try:
                connection.row_factory = sqlite3.Row
                cursor = connection.execute(statement)
                rows = [dict(row) for row in cursor.fetchmany(MAX_ROWS)]
                entry["columns"] = [d[0] for d in (cursor.description or [])]
                entry["rows"] = _jsonable(rows)
                entry["row_count"] = len(rows)
            finally:
                connection.close()
        except sqlite3.Error as exc:
            entry["error"] = "sqlite: %s" % exc
        except OSError as exc:
            entry["error"] = str(exc)
        results.append(entry)
    return {"databases": results, "count": len(results)}


def stat_paths(args, ctx=None):
    """Inode metadata for the event target (or explicit paths)."""
    paths = list(args.get("paths") or [])
    if args.get("slot") and ctx:
        value = ctx.get(args["slot"])
        if value:
            paths.append(value)
    return {"files": [_file_meta(path) for path in _expand(paths, args.get("globs"))]}


def recent_files(args, ctx=None):
    """Files modified inside a window -- what was staged, and where."""
    max_age = float(args.get("max_age_seconds", 86400))
    limit = int(args.get("limit", 300))
    cutoff = timeutil.now().timestamp() - max_age
    directories = list(args.get("dirs") or [])
    for pattern in args.get("globs") or []:
        directories.extend(sorted(globmod.glob(pattern)))

    found = []
    for directory in directories:
        if not os.path.isdir(directory):
            continue
        for root, dirnames, filenames in os.walk(directory):
            # Bounded walk: an unbounded one over /Users is a self-inflicted DoS.
            if len(found) >= limit:
                break
            dirnames[:] = [d for d in dirnames if not d.startswith(".")][:50]
            for filename in filenames[:200]:
                path = os.path.join(root, filename)
                try:
                    info = os.lstat(path)
                except OSError:
                    continue
                if info.st_mtime >= cutoff:
                    found.append(_file_meta(path))
                    if len(found) >= limit:
                        break
    found.sort(key=lambda entry: entry.get("mtime") or "", reverse=True)
    return {"files": found, "count": len(found),
            "window_seconds": max_age, "truncated": len(found) >= limit}


def dir_listing(args, ctx=None):
    """Shallow directory inventory with sizes and timestamps."""
    limit = int(args.get("limit", 300))
    directories = list(args.get("dirs") or [])
    for pattern in args.get("globs") or []:
        directories.extend(sorted(globmod.glob(pattern)))
    entries = []
    for directory in directories:
        if not os.path.isdir(directory):
            continue
        try:
            names = sorted(os.listdir(directory))[:limit]
        except OSError as exc:
            entries.append({"path": directory, "error": str(exc)})
            continue
        for name in names:
            entries.append(_file_meta(os.path.join(directory, name)))
            if len(entries) >= limit:
                break
    return {"entries": entries, "count": len(entries)}


HANDLERS = {
    "read_plist": read_plist,
    "read_plists": read_plists,
    "read_plists_in_dirs": read_plists_in_dirs,
    "read_text_files": read_text_files,
    "read_sqlite": read_sqlite,
    "stat_paths": stat_paths,
    "recent_files": recent_files,
    "dir_listing": dir_listing,
}


def run(probe, ctx=None):
    handler = HANDLERS.get(probe.native)
    if handler is None:
        raise NativeError("unknown native handler: %r" % probe.native)
    return handler(probe.args, ctx or {})


def _uri_escape(path):
    return path.replace("?", "%3f").replace("#", "%23")


def _jsonable(value):
    """plistlib and sqlite hand back bytes, dates and sets; JSON does not."""
    import datetime
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (bytes, bytearray)):
        if len(value) > 4096:
            return {"__bytes__": len(value), "truncated": True}
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return {"__bytes__": len(value), "hex": value[:256].hex()}
    if isinstance(value, (datetime.datetime, datetime.date)):
        return str(value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)
