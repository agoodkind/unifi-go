#!/usr/bin/env zsh

set -euo pipefail

typeset -gr SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/common.zsh"

function require_artifact() {
    local artifact="$1"

    if [[ ! -s "$artifact" ]]; then
        print -u2 -- "Required artifact is empty or absent: $artifact"
        return 1
    fi
}

function main() {
    local run_directory="${1:-}"
    local tcpdump_packets
    local dumpcap_packets
    local decoded_messages
    local transcript

    if [[ -z "$run_directory" || ! -d "$run_directory" ]]; then
        print -u2 -- "Usage: verify.zsh RUN_DIRECTORY"
        return 2
    fi
    RUN_DIR="${run_directory:A}"

    require_artifact "$RUN_DIR/physical-tcpdump.pcap"
    require_artifact "$RUN_DIR/physical-dumpcap.pcapng"
    require_artifact "$RUN_DIR/container.pcap"
    require_artifact "$RUN_DIR/inform.mitm"
    require_artifact "$RUN_DIR/pre-config.tar.gz"
    require_artifact "$RUN_DIR/pre-db.tar.gz"
    require_artifact "$RUN_DIR/post-config.tar.gz"
    require_artifact "$RUN_DIR/post-db.tar.gz"
    require_artifact "$RUN_DIR/post-db-authkey.txt"
    require_artifact "$RUN_DIR/pixiedust-with-db-key.jsonl"
    require_artifact "$RUN_DIR/SHA256SUMS"

    transcript="$RUN_DIR/pixiedust-with-db-key.jsonl"
    tcpdump_packets="$("$TSHARK" -r "$RUN_DIR/physical-tcpdump.pcap" -T fields -e frame.number | tail -1)"
    dumpcap_packets="$("$TSHARK" -r "$RUN_DIR/physical-dumpcap.pcapng" -T fields -e frame.number | tail -1)"
    if decoded_messages="$(grep -c '"_type"\|"model"' "$transcript")"; then
        :
    else
        local grep_status="$?"
        if [[ "$grep_status" == "1" ]]; then
            decoded_messages="0"
        else
            print -u2 -- "Unable to count decoded messages"
            return "$grep_status"
        fi
    fi

    if [[ -z "$tcpdump_packets" || -z "$dumpcap_packets" ]]; then
        print -u2 -- "One physical capture contains no packets"
        return 1
    fi
    if [[ "$decoded_messages" == "0" ]]; then
        print -u2 -- "pixiedust decoded no inform messages"
        return 1
    fi

    (
        cd "$RUN_DIR"
        shasum -a 256 -c SHA256SUMS >/dev/null
    )
    print -- "VERIFIED tcpdump_packets=$tcpdump_packets dumpcap_packets=$dumpcap_packets decoded_messages=$decoded_messages"
}

main "$@"
