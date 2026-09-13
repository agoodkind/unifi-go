#!/usr/bin/env zsh

set -euo pipefail

typeset -gr SCRIPT_DIR="${0:A:h}"
typeset -gr REPO_ROOT="${SCRIPT_DIR:h}"

function main() {
    if (( $# != 3 )); then
        print -u2 -- "usage: sanitize_fixture.zsh <private-run> <family> <output-dir>"
        return 2
    fi

    local private_run="$1"
    local family="$2"
    local output_dir="$3"
    local capture="$private_run/reference.pcap"

    if [[ ! -f "$capture" ]]; then
        capture="$private_run/physical-tcpdump.pcap"
    fi
    if [[ ! -f "$capture" ]]; then
        print -u2 -- "private run has no reference.pcap or physical-tcpdump.pcap"
        return 1
    fi

    local -a arguments
    local provenance="$private_run/fixture-provenance.json"
    if [[ ! -f "$provenance" ]]; then
        print -u2 -- "private run has no fixture-provenance.json"
        return 1
    fi
    arguments=(run ./cmd/unifi-fixture -capture "$capture" -family "$family" -output "$output_dir" -provenance "$provenance")
    if [[ -n "${UNIFI_FIXTURE_KEY_FILE:-}" ]]; then
        arguments+=(-keys "$UNIFI_FIXTURE_KEY_FILE")
    fi
    cd "$REPO_ROOT"
    go "${arguments[@]}"
}

main "$@"
