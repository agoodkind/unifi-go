#!/usr/bin/env zsh

set -euo pipefail

typeset -gr SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/common.zsh"

typeset -gr BIN_DIR="$SCRIPT_DIR/bin"
typeset -gr VENDOR_DIR="$SCRIPT_DIR/vendor"
typeset -gr PIXIEDUST_DIR="$VENDOR_DIR/pixiedust"

function checkout_pixiedust() {
    if [[ ! -d "$PIXIEDUST_DIR/.git" ]]; then
        gh repo clone jda/pixiedust "$PIXIEDUST_DIR" -- --depth 1
    fi

    git -C "$PIXIEDUST_DIR" fetch origin "$PIXIEDUST_SHA"
    git -C "$PIXIEDUST_DIR" switch --detach "$PIXIEDUST_SHA"
    if git -C "$PIXIEDUST_DIR" diff --quiet -- httpstream.go main.go; then
        git -C "$PIXIEDUST_DIR" apply "$SCRIPT_DIR/patches/pixiedust-flush.patch"
    fi
    git -C "$PIXIEDUST_DIR" diff --check
}

function build_pixiedust() {
    (
        cd "$PIXIEDUST_DIR"
        go build -trimpath -o "$BIN_DIR/pixiedust" .
    )
    chmod 700 "$BIN_DIR/pixiedust"
}

function verify_pixiedust_fixture() {
    local key_file="$SCRIPT_DIR/pixiedust-fixture-key.txt"
    local log_file="$SCRIPT_DIR/pixiedust-fixture.log"

    "$BIN_DIR/pixiedust" \
        -in "$PIXIEDUST_DIR/unifi-fresh-usw.pcap" \
        -findkeys \
        -message=false \
        -log-level=error \
        >"$key_file" \
        2>"$log_file"

    chmod 600 "$key_file" "$log_file"
    if [[ ! -s "$key_file" ]]; then
        print -u2 -- "pixiedust produced no key for its published fixture"
        return 1
    fi
}

function main() {
    umask 077
    require_command gh
    require_command git
    require_command go
    require_command docker

    mkdir -p "$BIN_DIR" "$VENDOR_DIR"
    chmod 700 "$BIN_DIR" "$VENDOR_DIR"

    checkout_pixiedust
    build_pixiedust
    verify_pixiedust_fixture

    docker pull "$MITMPROXY_IMAGE"
    docker pull "$NETSHOOT_IMAGE"
    docker pull "$ALPINE_IMAGE"
    docker pull "$UNIFI_EMU_IMAGE"

    print -- "PRIOR_ART_READY pixiedust=$PIXIEDUST_SHA unifi_emu=$UNIFI_EMU_SHA"
}

main "$@"
