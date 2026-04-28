#!/bin/bash
# Backward-compatible entrypoint for HTML analysis workflow.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/html/run_analysis_with_html.sh" "$@"
