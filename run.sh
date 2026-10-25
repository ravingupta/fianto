#!/usr/bin/env bash
# Start the Fianto dashboard on http://127.0.0.1:${PORT:-8000}
#   PORT=8642 ./run.sh      choose a port
#   RELOAD=1 ./run.sh       auto-restart when code changes (development only: a reload kills an in-progress run)
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -x venv/bin/uvicorn ]; then
  python3 -m venv venv && venv/bin/pip install -r requirements.txt
fi
extra=()
[ "${RELOAD:-0}" = "1" ] && extra+=(--reload --reload-dir app --reload-dir templates)
exec venv/bin/uvicorn app.main:app --host 127.0.0.1 --port "${PORT:-8000}" "${extra[@]}" "$@"
