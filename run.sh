#!/usr/bin/env bash
# Convenience launcher for the Email Header Analyzer.
#
#   ./run.sh setup     install dependencies
#   ./run.sh web       start the web interface on http://127.0.0.1:5000
#   ./run.sh demo      analyse the whole sample corpus (offline, no internet)
#   ./run.sh test      run the test suite
#   ./run.sh <file>    analyse one message

set -euo pipefail
cd "$(dirname "$0")"
PY=$(command -v python3 || command -v python)

case "${1:-web}" in
  setup)
    "$PY" -m pip install -r requirements.txt
    ;;
  web)
    shift || true
    exec "$PY" app.py "$@"
    ;;
  demo)
    exec "$PY" -m analyzer.cli --batch samples/ --summary --dns-mode offline
    ;;
  test)
    exec "$PY" -m pytest -v
    ;;
  *)
    exec "$PY" -m analyzer.cli "$@"
    ;;
esac
