#!/bin/sh
# Install MacSIEM as a launchd daemon. Run with sudo on macOS.
set -eu

PREFIX="${PREFIX:-/usr/local/macsiem}"
BIN="${BIN:-/usr/local/bin/macsiem}"
PYTHON="${PYTHON:-/usr/bin/python3}"
SOURCE="$(cd "$(dirname "$0")" && pwd)"

if [ "$(uname -s)" != "Darwin" ]; then
    echo "macsiem: this installer targets macOS." >&2
    echo "On other systems you can still run: python3 -m macsiem selftest" >&2
    exit 1
fi

if [ "$(id -u)" != "0" ]; then
    echo "macsiem: run with sudo." >&2
    exit 1
fi

# The system python3 is a stub until Command Line Tools are installed; a
# LaunchDaemon that hits the stub fails at launch with a dialog nobody sees.
if ! "$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
        >/dev/null 2>&1; then
    echo "macsiem: $PYTHON is not a working Python 3.9+." >&2
    echo "  Install the Command Line Tools first:  xcode-select --install" >&2
    echo "  or set PYTHON=/path/to/python3 and re-run." >&2
    exit 1
fi

echo "Installing to $PREFIX"
mkdir -p "$PREFIX"
/usr/bin/rsync -a --delete \
    --exclude '__pycache__' --exclude '.git' --exclude '*.pyc' \
    "$SOURCE/macsiem" "$SOURCE/tools" "$SOURCE/tests" "$PREFIX/"
chown -R root:wheel "$PREFIX"
chmod -R go-w "$PREFIX"

mkdir -p /var/db/macsiem/bundles /var/log/macsiem /etc/macsiem
chmod 700 /var/db/macsiem /var/db/macsiem/bundles /var/log/macsiem

cat > "$BIN" <<WRAPPER
#!/bin/sh
# MacSIEM launcher
exec env PYTHONPATH="$PREFIX" "$PYTHON" -m macsiem "\$@"
WRAPPER
chmod 755 "$BIN"
echo "Installed launcher at $BIN"

PYTHONPATH="$PREFIX" "$PYTHON" -m macsiem install

echo
echo "Next:"
echo "  1. Grant Full Disk Access (see docs/DEPLOY.md - prefer an MDM PPPC profile)"
echo "  2. Run: sudo macsiem doctor"
echo "  3. Review privacy settings: content capture is ON by default"
echo "     (docs/PRIVACY.md, or set privacy.capture_content=false in"
echo "      /etc/macsiem/config.json)"
