#!/usr/bin/env bash
# Build the report locally from a downloaded copy of the tracking spreadsheet.
#
# Usage:
#   scripts/run_local.sh /path/to/RHEL9-Konflux-migration.xlsx
#
# Optional env vars for Jira enrichment (skip them to build sheet-only):
#   JIRA_EMAIL, JIRA_API_TOKEN, JIRA_BASE (defaults to https://redhat.atlassian.net)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

XLSX_PATH="${1:-}"
if [[ -z "$XLSX_PATH" ]]; then
  echo "Usage: $0 /path/to/spreadsheet.xlsx" >&2
  exit 1
fi

PYTHON_BIN="${PYTHON_BIN:-python3}"

"$PYTHON_BIN" -m pip install --quiet -r "$SCRIPT_DIR/requirements.txt"

"$PYTHON_BIN" "$SCRIPT_DIR/build_report.py" \
  --xlsx "$XLSX_PATH" \
  --out "$REPO_ROOT/index.html"

echo "Done. Open $REPO_ROOT/index.html in a browser."
