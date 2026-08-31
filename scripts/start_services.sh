#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_ROOT}"

# Locate Python / venv
if [ -f "${PROJECT_ROOT}/.venv/bin/crashwise" ]; then
    CRASHWISE_BIN="${PROJECT_ROOT}/.venv/bin/crashwise"
elif command -v uv >/dev/null 2>&1; then
    CRASHWISE_BIN="uv run python -m crashwise.cli"
else
    CRASHWISE_BIN="python3 -m crashwise.cli"
fi

echo "=== Stopping any running CrashWise processes ==="
pkill -9 -f 'crashwise.*api' 2>/dev/null || true
pkill -9 -f 'crashwise.*worker' 2>/dev/null || true
pkill -9 -f 'crashwise.cli.*api' 2>/dev/null || true
pkill -9 -f 'crashwise.cli.*worker' 2>/dev/null || true
sleep 2

echo "=== Launching CrashWise API server ==="
nohup ${CRASHWISE_BIN} api --host 0.0.0.0 --port 8001 > /tmp/crashwise-api.log 2>&1 < /dev/null &
API_PID=$!
echo "API launched (PID: ${API_PID}) on port 8001 -> log: /tmp/crashwise-api.log"

echo "=== Launching CrashWise Temporal Worker ==="
nohup ${CRASHWISE_BIN} worker > /tmp/crashwise-worker.log 2>&1 < /dev/null &
WORKER_PID=$!
echo "Worker launched (PID: ${WORKER_PID}) -> log: /tmp/crashwise-worker.log"

sleep 3
echo "=== Service Status ==="
ps aux | grep -E 'crashwise.*(api|worker)' | grep -v grep || true

echo "=== Testing Health Endpoint ==="
curl -s http://127.0.0.1:8001/health || echo "API starting up..."
echo ""
