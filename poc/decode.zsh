#!/usr/bin/env zsh

set -euo pipefail

typeset -gr SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/common.zsh"

typeset -g TEMP_CONTAINER=""
typeset -g TEMP_VOLUME=""

function cleanup() {
    if [[ -n "$TEMP_CONTAINER" ]]; then
        if docker container inspect "$TEMP_CONTAINER" >/dev/null 2>&1; then
            if ! docker stop "$TEMP_CONTAINER" >/dev/null; then
                print -u2 -- "Unable to stop temporary MongoDB container"
            fi
            if ! docker rm "$TEMP_CONTAINER" >/dev/null; then
                print -u2 -- "Unable to remove temporary MongoDB container"
            fi
        fi
    fi
    if [[ -n "$TEMP_VOLUME" ]]; then
        if docker volume inspect "$TEMP_VOLUME" >/dev/null 2>&1; then
            if ! docker volume rm "$TEMP_VOLUME" >/dev/null; then
                print -u2 -- "Unable to remove temporary MongoDB volume"
            fi
        fi
    fi
}

function wait_for_mongodb() {
    local attempt_count

    for attempt_count in {1..60}; do
        if docker exec "$TEMP_CONTAINER" mongosh --quiet --eval 'db.adminCommand({ping:1}).ok' >/dev/null 2>&1; then
            return 0
        fi
        if ! sleep 1; then
            print -u2 -- "MongoDB readiness wait was interrupted"
            return 1
        fi
    done
    print -u2 -- "Temporary MongoDB did not start within 60 seconds"
    return 1
}

function main() {
    local device_mac="${2:-}"
    local pixiedust="$SCRIPT_DIR/bin/pixiedust"
    local run_directory="${1:-}"

    trap cleanup EXIT INT TERM
    umask 077

    if [[ -z "$run_directory" || ! -d "$run_directory" ]]; then
        print -u2 -- "Usage: decode.zsh RUN_DIRECTORY DEVICE_MAC"
        return 2
    fi
    if [[ ! "$device_mac" =~ '^([0-9a-f]{2}:){5}[0-9a-f]{2}$' ]]; then
        print -u2 -- "DEVICE_MAC must use lowercase colon-separated hexadecimal"
        return 2
    fi
    if [[ ! -x "$pixiedust" ]]; then
        print -u2 -- "pixiedust is unavailable; run setup_prior_art.zsh"
        return 1
    fi

    RUN_DIR="${run_directory:A}"
    if [[ ! -s "$RUN_DIR/post-db.tar.gz" || ! -s "$RUN_DIR/physical-tcpdump.pcap" ]]; then
        print -u2 -- "The run lacks its post database archive or physical packet capture"
        return 1
    fi

    TEMP_VOLUME="unifi-capture-postdb-$EPOCHSECONDS"
    TEMP_CONTAINER="unifi-capture-postdb-$EPOCHSECONDS"
    docker volume create "$TEMP_VOLUME" >/dev/null
    docker run --rm \
        --mount "type=volume,src=$TEMP_VOLUME,dst=/restore" \
        --mount "type=bind,src=$RUN_DIR,dst=/capture,readonly" \
        "$ALPINE_IMAGE" \
        tar -xzf /capture/post-db.tar.gz -C /restore
    docker run -d \
        --name "$TEMP_CONTAINER" \
        --network none \
        --mount "type=volume,src=$TEMP_VOLUME,dst=/data/db" \
        mongo:7.0 \
        mongod --bind_ip_all >/dev/null
    wait_for_mongodb
    docker cp "$SCRIPT_DIR/extract_key.js" "$TEMP_CONTAINER:/tmp/extract_key.js"
    docker exec \
        --env "UNIFI_DEVICE_MAC=$device_mac" \
        "$TEMP_CONTAINER" \
        mongosh --quiet /tmp/extract_key.js \
        >"$RUN_DIR/post-db-authkey.txt"
    chmod 600 "$RUN_DIR/post-db-authkey.txt"

    "$pixiedust" \
        -in "$RUN_DIR/physical-tcpdump.pcap" \
        -keys "$RUN_DIR/post-db-authkey.txt" \
        -log-level=warn \
        >"$RUN_DIR/pixiedust-with-db-key.jsonl" \
        2>"$RUN_DIR/pixiedust-with-db-key.log"
    chmod 600 \
        "$RUN_DIR/pixiedust-with-db-key.jsonl" \
        "$RUN_DIR/pixiedust-with-db-key.log"
    if [[ ! -s "$RUN_DIR/pixiedust-with-db-key.jsonl" ]]; then
        print -u2 -- "pixiedust decoded no messages with the database key"
        return 1
    fi
    print -- "DECODED run=$RUN_DIR"
}

main "$@"
