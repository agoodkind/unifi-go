#!/usr/bin/env zsh

set -euo pipefail

typeset -gr SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/common.zsh"

function main() {
    local capture_pid

    if [[ ! -f "$ACTIVE_PID" ]]; then
        print -u2 -- "No active capture PID exists"
        return 1
    fi

    capture_pid="$(<"$ACTIVE_PID")"
    if ! kill -0 "$capture_pid" 2>/dev/null; then
        print -u2 -- "Capture PID $capture_pid is not running; run recover"
        return 1
    fi

    kill -TERM "$capture_pid"
    print -- "STOP_REQUESTED pid=$capture_pid"
}

main "$@"
