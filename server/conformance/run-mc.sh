#!/usr/bin/env bash
# Boots `matter-server --backend mc` on a random free port, runs the non-live conformance
# suite against it, then kills it. Used by `make test-mc`. Same pattern as run-mock.sh.
set -euo pipefail

cd "$(dirname "$0")"

SERVER_ROOT="$(cd .. && pwd)"
BIN="$SERVER_ROOT/target/debug/matter-server"

if [ ! -x "$BIN" ]; then
    echo "building matter-server..."
    (cd "$SERVER_ROOT" && cargo build -p matter-server)
fi

STORAGE_DIR="$(mktemp -d)"
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')

"$BIN" --backend mc --storage-path "$STORAGE_DIR" --port "$PORT" --log-level warn &
SERVER_PID=$!

cleanup() {
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    rm -rf "$STORAGE_DIR"
}
trap cleanup EXIT

# Wait for /health.
for _ in $(seq 1 100); do
    if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

export MATTER_SERVER_URL="ws://127.0.0.1:${PORT}/ws"
echo "matter-server (mc) listening on $MATTER_SERVER_URL"

uv run pytest -v -m "not live" tests/
