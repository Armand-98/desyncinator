#!/bin/sh
# Link desyncinator onto PATH under both its full name and its short name.
#
#   tools/install.sh                  # link into /opt/homebrew/bin
#   tools/install.sh ~/.local/bin     # or anywhere else on PATH
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:-/opt/homebrew/bin}"

if [ ! -x "$ROOT/.venv/bin/desyncinator" ]; then
    echo "no venv yet. Build it first:" >&2
    echo "  cd $ROOT && python3 -m venv .venv && ./.venv/bin/pip install -e ." >&2
    exit 1
fi
[ -d "$BIN" ] || { echo "$BIN does not exist" >&2; exit 1; }

case ":$PATH:" in
    *":$BIN:"*) ;;
    *) echo "warning: $BIN is not on your PATH" >&2 ;;
esac

for name in desyncinator desync; do
    ln -sf "$ROOT/.venv/bin/$name" "$BIN/$name"
    echo "linked $BIN/$name"
done
