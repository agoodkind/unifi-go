#!/usr/bin/env zsh

set -euo pipefail

typeset -gr SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/common.zsh"

typeset -ga CHILD_PIDS=()
typeset -ga CHILD_NAMES=()
typeset -gi INTERRUPT_FLAG=0
typeset -gi EXIT_STATUS=0
typeset -gi CLEANUP_STARTED=0
typeset -gi CLEANUP_FAILURE=0
typeset -gr SELECTED_EMU_MODELS="${UNIFI_EMU_MODELS:-U7PG2}"

function on_interrupt() {
    local signal_status="$1"

    INTERRUPT_FLAG=1
    EXIT_STATUS="$signal_status"
}

function record_cleanup() {
    local message="$1"

    print -r -- "$message" >>"$RUN_DIR/cleanup.log"
}

function run_cleanup_step() {
    local description="$1"
    shift

    if "$@"; then
        record_cleanup "OK $description"
    else
        local command_status="$?"
        CLEANUP_FAILURE=1
        record_cleanup "FAILED status=$command_status $description"
    fi
}

function start_child() {
    local name="$1"
    shift

    "$@" \
        >"$RUN_DIR/$name.stdout.log" \
        2>"$RUN_DIR/$name.stderr.log" &
    CHILD_PIDS+=("$!")
    CHILD_NAMES+=("$name")
}

function stop_children() {
    local pid
    local child_index

    for pid in "${CHILD_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            if ! kill -TERM "$pid" 2>>"$RUN_DIR/cleanup.log"; then
                record_cleanup "FAILED signal pid=$pid"
                CLEANUP_FAILURE=1
            fi
        fi
    done

    for (( child_index = 1; child_index <= ${#CHILD_PIDS[@]}; child_index++ )); do
        pid="${CHILD_PIDS[$child_index]}"
        if wait "$pid" 2>>"$RUN_DIR/cleanup.log"; then
            record_cleanup "OK child=${CHILD_NAMES[$child_index]} pid=$pid"
        else
            local child_status="$?"
            record_cleanup "STOPPED child=${CHILD_NAMES[$child_index]} pid=$pid status=$child_status"
        fi
    done
}

function snapshot_volume() {
    local label="$1"
    local volume_name="$2"
    local archive_name="$3"

    docker run --rm \
        --mount "type=volume,src=$volume_name,dst=/source,readonly" \
        --mount "type=bind,src=$RUN_DIR,dst=/capture" \
        "$ALPINE_IMAGE" \
        tar -czf "/capture/$label-$archive_name.tar.gz" -C /source .
}

function snapshot_volumes() {
    local label="$1"

    snapshot_volume "$label" "unifi-docker_unifi-config" "config"
    snapshot_volume "$label" "unifi-docker_unifi-db" "db"
}

function protect_artifacts() {
    find "$RUN_DIR" -type d -exec chmod 700 {} +
    find "$RUN_DIR" -type f -exec chmod 600 {} +
}

function write_hashes() {
    local hash_file="$RUN_DIR/SHA256SUMS"
    local temporary_hash_file="$RUN_DIR/.SHA256SUMS.tmp"
    local artifact

    : >"$temporary_hash_file"
    while IFS= read -r artifact; do
        if [[ "$artifact" == "$hash_file" || "$artifact" == "$temporary_hash_file" ]]; then
            continue
        fi
        shasum -a 256 "$artifact" >>"$temporary_hash_file"
    done < <(find "$RUN_DIR" -type f | LC_ALL=C sort)
    mv "$temporary_hash_file" "$hash_file"
    chmod 600 "$hash_file"
}

function extract_prior_art() {
    local pixiedust="$SCRIPT_DIR/bin/pixiedust"

    if [[ ! -x "$pixiedust" || ! -f "$RUN_DIR/physical-tcpdump.pcap" ]]; then
        record_cleanup "SKIPPED pixiedust physical extraction"
        return 0
    fi

    if "$pixiedust" \
        -in "$RUN_DIR/physical-tcpdump.pcap" \
        -findkeys \
        -message=false \
        -log-level=error \
        >"$RUN_DIR/pixiedust-keys.txt" \
        2>"$RUN_DIR/pixiedust-keys.log"; then
        record_cleanup "OK pixiedust physical key extraction"
    else
        local key_status="$?"
        record_cleanup "FAILED status=$key_status pixiedust physical key extraction"
        CLEANUP_FAILURE=1
    fi

    if "$pixiedust" \
        -in "$RUN_DIR/physical-tcpdump.pcap" \
        -log-level=error \
        >"$RUN_DIR/pixiedust-transcript.jsonl" \
        2>"$RUN_DIR/pixiedust-transcript.log"; then
        record_cleanup "OK pixiedust physical transcript"
    else
        local transcript_status="$?"
        record_cleanup "FAILED status=$transcript_status pixiedust physical transcript"
        CLEANUP_FAILURE=1
    fi
}

function copy_controller_logs() {
    docker cp \
        unifi-network-application:/config/logs \
        "$RUN_DIR/unifi-application-logs"
    capture_compose logs --no-color --timestamps \
        >"$RUN_DIR/docker-compose.log" \
        2>"$RUN_DIR/docker-compose.stderr.log"
}

function decode_discovery() {
    "$TSHARK" \
        -r "$RUN_DIR/physical-tcpdump.pcap" \
        -Y ubdp \
        -V \
        >"$RUN_DIR/ubiquiti-discovery.txt" \
        2>"$RUN_DIR/ubiquiti-discovery.stderr.log"
}

function restore_and_verify() {
    local attempt_count
    local response_code

    normal_compose up -d
    response_code=""
    for attempt_count in {1..120}; do
        if response_code="$(curl --max-time 5 -kfsS -o /dev/null -w '%{http_code}' "https://localhost:8443" 2>>"$RUN_DIR/restore-readiness.stderr.log")"; then
            if [[ "$response_code" == "302" ]]; then
                break
            fi
        fi
        if ! sleep 1; then
            print -u2 -- "Restore readiness wait was interrupted"
            return 1
        fi
    done
    print -r -- "$response_code" >"$RUN_DIR/restored-http-status.txt"
    if [[ "$response_code" != "302" ]]; then
        print -u2 -- "Restored local controller returned HTTP $response_code, want 302"
        return 1
    fi
}

function cleanup() {
    if (( CLEANUP_STARTED )); then
        return
    fi
    CLEANUP_STARTED=1

    if [[ -z "$RUN_DIR" || ! -d "$RUN_DIR" ]]; then
        return
    fi

    stop_children
    run_cleanup_step "copy controller logs" copy_controller_logs
    run_cleanup_step "stop capture topology" capture_compose down
    run_cleanup_step "post config snapshot" snapshot_volume post "unifi-docker_unifi-config" config
    run_cleanup_step "post database snapshot" snapshot_volume post "unifi-docker_unifi-db" db
    run_cleanup_step "restore normal topology" restore_and_verify
    run_cleanup_step "decode discovery" decode_discovery
    extract_prior_art
    run_cleanup_step "protect artifacts" protect_artifacts
    run_cleanup_step "write artifact hashes" write_hashes

    if [[ -f "$ACTIVE_PID" ]]; then
        rm -f "$ACTIVE_PID"
    fi
    if [[ -f "$ACTIVE_RUN" ]]; then
        rm -f "$ACTIVE_RUN"
    fi

    if (( CLEANUP_FAILURE && EXIT_STATUS == 0 )); then
        EXIT_STATUS=1
    fi
    print -- "CAPTURE_STOPPED run=$RUN_DIR status=$EXIT_STATUS"
}

function on_exit() {
    local command_status="$1"

    if (( EXIT_STATUS == 0 && command_status != 0 )); then
        EXIT_STATUS="$command_status"
    fi
    cleanup
    return "$EXIT_STATUS"
}

function TRAPINT() {
    on_interrupt 130
    return 0
}

function TRAPTERM() {
    on_interrupt 143
    return 0
}

function TRAPEXIT() {
    on_exit "$?"
}

function validate_environment() {
    local interface_ip

    require_command docker
    require_command curl
    require_command ping
    require_command shasum
    require_command xxd
    require_command grep

    if [[ ! -x "$TSHARK" || ! -x "$DUMPCAP" ]]; then
        print -u2 -- "Wireshark command line tools are unavailable"
        return 1
    fi
    if [[ ! -f "$BASE_COMPOSE" || ! -f "$CAPTURE_COMPOSE" ]]; then
        print -u2 -- "A required compose file is unavailable"
        return 1
    fi
    if [[ -f "$ACTIVE_PID" || -f "$ACTIVE_RUN" ]]; then
        print -u2 -- "An earlier capture marker exists; run stop or recover"
        return 1
    fi
    interface_ip="$(ipconfig getifaddr "$PHYSICAL_INTERFACE")"
    if [[ "$interface_ip" != "$HOST_IP" ]]; then
        print -u2 -- "$PHYSICAL_INTERFACE has $interface_ip, want $HOST_IP"
        return 1
    fi
    if [[ "$(ifconfig "$PHYSICAL_INTERFACE")" != *"status: active"* ]]; then
        print -u2 -- "$PHYSICAL_INTERFACE is not active"
        return 1
    fi
}

function prepare_run() {
    local run_id="poc-$EPOCHSECONDS"

    umask 077
    mkdir -p "$RUN_ROOT"
    chmod 700 "$RUN_ROOT"
    RUN_DIR="$RUN_ROOT/$run_id"
    mkdir "$RUN_DIR" "$RUN_DIR/metadata"
    chmod 700 "$RUN_DIR" "$RUN_DIR/metadata"
    print -r -- "$$" >"$ACTIVE_PID"
    print -r -- "$RUN_DIR" >"$ACTIVE_RUN"
    chmod 600 "$ACTIVE_PID" "$ACTIVE_RUN"
    print -r -- "$PIXIEDUST_SHA" >"$RUN_DIR/metadata/pixiedust-revision.txt"
    print -r -- "$UNIFI_EMU_SHA" >"$RUN_DIR/metadata/unifi-emu-revision.txt"
    print -r -- "$SELECTED_EMU_MODELS" >"$RUN_DIR/metadata/unifi-emu-models.txt"
}

function start_physical_capture() {
    start_child physical-tcpdump \
        /usr/sbin/tcpdump \
        -i "$PHYSICAL_INTERFACE" -s 0 -U -n \
        -w "$RUN_DIR/physical-tcpdump.pcap"
    start_child physical-dumpcap \
        "$DUMPCAP" \
        -q -i "$PHYSICAL_INTERFACE" -s 0 \
        -w "$RUN_DIR/physical-dumpcap.pcapng"

    if ! sleep 2; then
        print -u2 -- "Capture startup wait was interrupted"
        return 1
    fi
    local pid
    for pid in "${CHILD_PIDS[@]}"; do
        if ! kill -0 "$pid" 2>/dev/null; then
            print -u2 -- "Physical capture process $pid exited during startup"
            return 1
        fi
    done
}

function collect_metadata() {
    date +"%Y-%m-%d %H:%M:%S %Z" >"$RUN_DIR/metadata/date.txt"
    ifconfig "$PHYSICAL_INTERFACE" >"$RUN_DIR/metadata/interface.txt"
    route -n get default >"$RUN_DIR/metadata/default-route.txt"
    arp -an >"$RUN_DIR/metadata/arp.txt"
    docker version >"$RUN_DIR/metadata/docker-version.txt"
    docker compose version >"$RUN_DIR/metadata/compose-version.txt"
    capture_compose config >"$RUN_DIR/metadata/rendered-compose.yaml"
    capture_compose ps >"$RUN_DIR/metadata/capture-services.txt"
    docker image inspect \
        "$MITMPROXY_IMAGE" "$NETSHOOT_IMAGE" "$ALPINE_IMAGE" "$UNIFI_EMU_IMAGE" \
        >"$RUN_DIR/metadata/image-inspect.json"
    df -h "$RUN_ROOT" >"$RUN_DIR/metadata/disk-free.txt"
}

function wait_for_controller() {
    local attempt_count
    local response_code

    for attempt_count in {1..120}; do
        if response_code="$(curl -kfsS -o /dev/null -w '%{http_code}' "https://$HOST_IP:8443" 2>>"$RUN_DIR/controller-readiness.stderr.log")"; then
            if [[ "$response_code" == "302" ]]; then
                print -r -- "$response_code" >"$RUN_DIR/controller-readiness-status.txt"
                return 0
            fi
        fi
        if ! sleep 1; then
            print -u2 -- "Controller readiness wait was interrupted"
            return 1
        fi
    done

    print -u2 -- "Controller did not return HTTP 302 within 120 seconds"
    return 1
}

function start_controller_logs() {
    start_child application-docker-log \
        docker logs --follow --timestamps unifi-network-application
    start_child database-docker-log \
        docker logs --follow --timestamps unifi-db
    start_child proxy-docker-log \
        docker logs --follow --timestamps unifi-inform-proxy
    start_child application-file-log \
        docker exec unifi-network-application tail -F \
        /config/logs/inform_request.log \
        /config/logs/server.log \
        /config/logs/state.log \
        /config/logs/startup.log
}

function run_physical_probe() {
    local probe_hex

    probe_hex="$(printf '%016x' "$EPOCHSECONDS")"
    print -r -- "$probe_hex" >"$RUN_DIR/metadata/physical-probe-hex.txt"
    ping -c 1 -S "$HOST_IP" -p "$probe_hex" "$GATEWAY_IP" \
        >"$RUN_DIR/metadata/physical-probe.txt" \
        2>"$RUN_DIR/metadata/physical-probe.stderr.txt"
    if ! sleep 1; then
        print -u2 -- "Physical probe flush wait was interrupted"
        return 1
    fi
    "$TSHARK" \
        -r "$RUN_DIR/physical-tcpdump.pcap" \
        -Y icmp \
        -T fields \
        -e data.data \
        >"$RUN_DIR/metadata/physical-probe-packets.txt"
    if ! grep -q "$probe_hex" "$RUN_DIR/metadata/physical-probe-packets.txt"; then
        print -u2 -- "The physical probe is absent from the en10 packet capture"
        return 1
    fi
}

function run_unifi_emu_probe() {
    local emulator_pid
    local emulator_output="$RUN_DIR/unifi-emu-probe.stdout.log"
    local emulator_error="$RUN_DIR/unifi-emu-probe.stderr.log"

    docker run --rm \
        --name unifi-poc-emulator \
        --network unifi-docker_default \
        --env SIM_CONTROLLER=http://unifi-inform-proxy:8080/inform \
        --env "SIM_MODELS=$SELECTED_EMU_MODELS" \
        --env SIM_MAC_BASE=02:27:22:e0:00:00 \
        --env SIM_IP_BASE=192.168.0.250 \
        "$UNIFI_EMU_IMAGE" \
        >"$emulator_output" \
        2>"$emulator_error" &
    emulator_pid="$!"

    if ! sleep 15; then
        print -u2 -- "unifi-emu probe wait was interrupted"
        return 1
    fi
    if kill -0 "$emulator_pid" 2>/dev/null; then
        kill -TERM "$emulator_pid"
    fi
    if wait "$emulator_pid"; then
        return 0
    else
        local emulator_status="$?"
        if [[ "$emulator_status" == "143" || "$emulator_status" == "130" ]]; then
            return 0
        fi
        print -u2 -- "unifi-emu probe exited with status $emulator_status"
        return 1
    fi
}

function run_proxy_probe() {
    local proxy_probe="capture-probe-$EPOCHSECONDS"
    local proxy_probe_hex

    proxy_probe_hex="$(printf '%s' "$proxy_probe" | xxd -p)"
    print -r -- "$proxy_probe" >"$RUN_DIR/metadata/proxy-probe.txt"
    docker exec unifi-container-capture curl \
        -sS \
        -o /capture/probe-response.bin \
        -w '%{http_code}\n' \
        -X POST \
        --data-binary "$proxy_probe" \
        http://unifi-inform-proxy:8080/capture-probe \
        >"$RUN_DIR/metadata/proxy-probe-status.txt" \
        2>"$RUN_DIR/metadata/proxy-probe.stderr.txt"

    if ! sleep 2; then
        print -u2 -- "Proxy probe flush wait was interrupted"
        return 1
    fi
    "$TSHARK" \
        -r "$RUN_DIR/container.pcap" \
        -Y tcp \
        -T fields \
        -e tcp.payload \
        >"$RUN_DIR/metadata/container-payloads.txt"
    if ! grep -q "$proxy_probe_hex" "$RUN_DIR/metadata/container-payloads.txt"; then
        print -u2 -- "The HTTP probe is absent from the container packet capture"
        return 1
    fi

    docker logs unifi-inform-proxy \
        >"$RUN_DIR/metadata/proxy-probe-log.txt" \
        2>"$RUN_DIR/metadata/proxy-probe-log.stderr.txt"
    if ! grep -q "$proxy_probe" "$RUN_DIR/metadata/proxy-probe-log.txt"; then
        print -u2 -- "The HTTP probe is absent from the mitmproxy log"
        return 1
    fi
}

function verify_pixiedust_probe() {
    local probe_capture="$RUN_DIR/probe-container.pcap"
    local pixiedust="$SCRIPT_DIR/bin/pixiedust"

    cp "$RUN_DIR/container.pcap" "$probe_capture"
    "$pixiedust" \
        -in "$probe_capture" \
        -log-level=error \
        >"$RUN_DIR/pixiedust-probe.jsonl" \
        2>"$RUN_DIR/pixiedust-probe.log"
    local model
    local -a selected_models
    selected_models=("${(@s:,:)SELECTED_EMU_MODELS}")
    for model in "${selected_models[@]}"; do
        if ! grep -q '"model":"'"$model"'"' "$RUN_DIR/pixiedust-probe.jsonl"; then
            print -u2 -- "pixiedust did not decode the selected unifi-emu model $model"
            return 1
        fi
    done
}

function main() {
    validate_environment
    if [[ ! -x "$SCRIPT_DIR/bin/pixiedust" ]]; then
        "$SCRIPT_DIR/setup_prior_art.zsh"
    fi
    prepare_run
    start_physical_capture

    normal_compose down
    snapshot_volumes pre
    capture_compose up -d
    wait_for_controller
    start_controller_logs
    collect_metadata
    run_physical_probe
    run_unifi_emu_probe
    run_proxy_probe
    verify_pixiedust_probe

    print -- "ARMED run=$RUN_DIR"
    while (( ! INTERRUPT_FLAG )); do
        if ! sleep 1; then
            continue
        fi
    done
    exit "$EXIT_STATUS"
}

main "$@"
