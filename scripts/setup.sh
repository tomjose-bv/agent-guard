#!/usr/bin/env sh
# One-command setup for macOS/Linux:  sh scripts/setup.sh
set -eu
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
[ -d .venv ] || "$PY" -m venv .venv
if ! .venv/bin/python -m pip install --disable-pip-version-check -q -e ".[dev]"; then
  echo "pip failed; retrying with the system trust store (truststore)..."
  .venv/bin/python -m pip install -q truststore
  PIP_USE_FEATURE=truststore .venv/bin/python -m pip install --disable-pip-version-check -q -e ".[dev]"
fi
.venv/bin/agent-guard validate
[ "${SKIP_TESTS:-0}" = "1" ] || .venv/bin/python -m pytest -q
echo
echo "Done. Try the demo:  .venv/bin/python examples/demo_agent.py   then   .venv/bin/agent-guard ui"
