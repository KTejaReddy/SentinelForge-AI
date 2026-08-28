#!/usr/bin/env bash
# Local development launcher for SentinelForge AI.
#   bash scripts/dev.sh            -> backend + frontend
#   bash scripts/dev.sh backend    -> backend only
#   bash scripts/dev.sh frontend   -> frontend only
set -euo pipefail
cd "$(dirname "$0")/.."

PY=".venv/Scripts/python"
[ -x "$PY" ] || PY=".venv/bin/python"

backend() {
  echo "==> Starting backend on http://127.0.0.1:8000"
  (cd backend && exec "$PY" -m uvicorn main:app --host 0.0.0.0 --port "${BACKEND_PORT:-8000}")
}

frontend() {
  echo "==> Starting frontend on http://127.0.0.1:5173"
  (cd frontend && exec npm run dev)
}

case "${1:-all}" in
  backend) backend ;;
  frontend) frontend ;;
  all)
    backend &
    FRONTEND_PID=$!
    trap 'kill $FRONTEND_PID 2>/dev/null || true' EXIT
    frontend
    ;;
esac
