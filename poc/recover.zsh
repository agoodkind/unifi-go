#!/usr/bin/env zsh

set -euo pipefail

typeset -gr SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/common.zsh"

function main() {
    local attempt_count
    local capture_pid=""
    local response_code

    umask 077
    if [[ -f "$ACTIVE_PID" ]]; then
        capture_pid="$(<"$ACTIVE_PID")"
        if kill -0 "$capture_pid" 2>/dev/null; then
            print -u2 -- "Capture PID $capture_pid is still running; use stop"
            return 1
        fi
    fi

    if [[ -f "$ACTIVE_RUN" ]]; then
        RUN_DIR="$(<"$ACTIVE_RUN")"
    else
        RUN_DIR="$RUN_ROOT/recovery-$EPOCHSECONDS"
        mkdir -p "$RUN_DIR"
        chmod 700 "$RUN_DIR"
    fi

    capture_compose down
    normal_compose up -d

    response_code=""
    for attempt_count in {1..120}; do
        if response_code="$(curl --max-time 5 -kfsS -o /dev/null -w '%{http_code}' "https://localhost:8443" 2>>"$RUN_DIR/recover-readiness.stderr.log")"; then
            if [[ "$response_code" == "302" ]]; then
                break
            fi
        fi
        if ! sleep 1; then
            print -u2 -- "Recovery readiness wait was interrupted"
            return 1
        fi
    done
    if [[ "$response_code" != "302" ]]; then
        print -u2 -- "Recovered local controller returned HTTP $response_code, want 302"
        return 1
    fi

    if [[ -f "$ACTIVE_PID" ]]; then
        rm -f "$ACTIVE_PID"
    fi
    if [[ -f "$ACTIVE_RUN" ]]; then
        rm -f "$ACTIVE_RUN"
    fi
    print -- "RECOVERED http=$response_code"
}

main "$@"
