#!/bin/bash
set -euo pipefail

# relayctl — CLI utility for age-plugin-relay
#
# Usage:
#   relayctl <command> [options]
#
# Key Management:
#   keygen                              Generate a new X25519 key pair
#   keygen --yubikey [--slot N] ...     Generate a YubiKey identity
#   keygen --list                       List all connected YubiKey recipients
#   generate --recipient <age1...> --remote <name>
#                                       Generate relay recipient + identity
#   tag --recipient <age1...>           Compute routing tag for a recipient
#
# Services:
#   server  start|stop|status|logs      Manage relay-server
#   broker  start|stop|status|logs      Manage relay-broker
#   operator start|run|stop|status|logs  Manage relay-operator
#
# Encrypt / Decrypt:
#   encrypt -r <recipient> [-i infile] [-o outfile]
#   decrypt -i <identity-file> [-f ciphertext] [-o outfile] [--config <file>]
#
# Utilities:
#   status                              Show all running services
#   stop                                Stop all running services
#   clean                               Remove workspace + stop services
#   build                               Build all binaries into bin/
#
# Environment:
#   RELAYCTL_WORKSPACE    Workspace directory (default: ./workspace)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="${RELAYCTL_WORKSPACE:-${SCRIPT_DIR}/workspace}"

# ── Binary Discovery ─────────────────────────────────────────────────────────

AGE="${SCRIPT_DIR}/tools/bin/age"
AGE_KEYGEN="${SCRIPT_DIR}/tools/bin/age-keygen"
YUBIKEY_PLUGIN="${SCRIPT_DIR}/tools/bin/age-plugin-yubikey"
BIN_DIR="${SCRIPT_DIR}/bin"
PLUGIN_BIN="${BIN_DIR}/age-plugin-relay"
SERVER_BIN="${BIN_DIR}/relay-server"
BROKER_BIN="${BIN_DIR}/relay-broker"
OPERATOR_BIN="${BIN_DIR}/relay-operator"

# Fall back to PATH if tools/bin/ doesn't exist
[ -x "$AGE" ] || AGE="$(command -v age 2>/dev/null || true)"
[ -x "$AGE_KEYGEN" ] || AGE_KEYGEN="$(command -v age-keygen 2>/dev/null || true)"
[ -x "$YUBIKEY_PLUGIN" ] || YUBIKEY_PLUGIN="$(command -v age-plugin-yubikey 2>/dev/null || true)"

# ── Colors ───────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

info()  { echo -e "${CYAN}  ℹ ${NC}$1"; }
ok()    { echo -e "${GREEN}  ✓ ${NC}$1"; }
warn()  { echo -e "${YELLOW}  ⚠ ${NC}$1"; }
err()   { echo -e "${RED}  ✗ ${NC}$1" >&2; }
die()   { err "$1"; exit 1; }
header(){ echo -e "\n${BOLD}$1${NC}"; }
runcmd(){ echo -e "${DIM}  \$ $*${NC}"; }

# ── Workspace ────────────────────────────────────────────────────────────────

ensure_workspace() {
    mkdir -p "$WORKSPACE"
}

# ── Auto-build ───────────────────────────────────────────────────────────────

ensure_age() {
    [ -n "$AGE" ] && [ -x "$AGE" ] || die "age binary not found. Install age or place it in tools/bin/"
    [ -n "$AGE_KEYGEN" ] && [ -x "$AGE_KEYGEN" ] || die "age-keygen binary not found."
}

ensure_plugin() {
    if [ ! -x "$PLUGIN_BIN" ]; then
        info "Building age-plugin-relay..."
        mkdir -p "$BIN_DIR"
        go build -o "$PLUGIN_BIN" "${SCRIPT_DIR}/cmd/age-plugin-relay/" || die "Build failed"
    fi
}

ensure_server() {
    if [ ! -x "$SERVER_BIN" ]; then
        info "Building relay-server..."
        mkdir -p "$BIN_DIR"
        go build -o "$SERVER_BIN" "${SCRIPT_DIR}/cmd/relay-server/" || die "Build failed"
    fi
}

ensure_broker() {
    if [ ! -x "$BROKER_BIN" ]; then
        info "Building relay-broker..."
        mkdir -p "$BIN_DIR"
        go build -o "$BROKER_BIN" "${SCRIPT_DIR}/cmd/relay-broker/" || die "Build failed"
    fi
}

ensure_operator() {
    if [ ! -x "$OPERATOR_BIN" ]; then
        info "Building relay-operator..."
        mkdir -p "$BIN_DIR"
        go build -o "$OPERATOR_BIN" "${SCRIPT_DIR}/cmd/relay-operator/" || die "Build failed"
    fi
}

ensure_yubikey_plugin() {
    [ -n "$YUBIKEY_PLUGIN" ] && [ -x "$YUBIKEY_PLUGIN" ] || \
        die "age-plugin-yubikey not found. Place it in tools/bin/ or install: brew install age-plugin-yubikey"
}

# ── PID Management ───────────────────────────────────────────────────────────

start_daemon() {
    local name="$1"; shift
    local binary="$1"; shift

    ensure_workspace

    local pidfile="${WORKSPACE}/${name}.pid"
    local logfile="${WORKSPACE}/${name}.log"

    # Check if already running
    if [ -f "$pidfile" ]; then
        local pid
        pid=$(cat "$pidfile")
        if kill -0 "$pid" 2>/dev/null; then
            warn "${name} is already running (PID ${pid})"
            return 0
        fi
        rm -f "$pidfile"
    fi

    runcmd "$binary" "$@"
    "$binary" "$@" > "$logfile" 2>&1 &
    local pid=$!
    echo "$pid" > "$pidfile"

    # Wait for process to be ready (up to 3 seconds)
    local port=""
    for arg in "$@"; do
        if [[ "$arg" =~ ^:[0-9]+$ ]]; then
            port="${arg#:}"
            break
        fi
    done

    if [ -n "$port" ]; then
        local i
        for i in $(seq 1 30); do
            if ! kill -0 "$pid" 2>/dev/null; then
                rm -f "$pidfile"
                err "${name} exited immediately. Log:"
                tail -5 "$logfile" 2>/dev/null | while IFS= read -r line; do echo "    $line"; done
                return 1
            fi
            if curl -s -o /dev/null "http://127.0.0.1:${port}" 2>/dev/null; then
                break
            fi
            sleep 0.1
        done
    else
        sleep 0.3
        if ! kill -0 "$pid" 2>/dev/null; then
            rm -f "$pidfile"
            err "${name} exited immediately. Log:"
            tail -5 "$logfile" 2>/dev/null | while IFS= read -r line; do echo "    $line"; done
            return 1
        fi
    fi

    ok "${name} started (PID ${pid})"
    info "Log: ${logfile}"
}

stop_daemon() {
    local name="$1"
    local pidfile="${WORKSPACE}/${name}.pid"

    if [ ! -f "$pidfile" ]; then
        info "${name} is not running"
        return 0
    fi

    local pid
    pid=$(cat "$pidfile")
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        ok "${name} stopped (PID ${pid})"
    else
        info "${name} was not running (stale PID ${pid})"
    fi
    rm -f "$pidfile"
}

daemon_status() {
    local name="$1"
    local pidfile="${WORKSPACE}/${name}.pid"
    local logfile="${WORKSPACE}/${name}.log"

    if [ ! -f "$pidfile" ]; then
        echo -e "  ${name}: ${DIM}not running${NC}"
        return 1
    fi

    local pid
    pid=$(cat "$pidfile")
    if kill -0 "$pid" 2>/dev/null; then
        local uptime_info=""
        if [[ "$OSTYPE" == "darwin"* ]]; then
            uptime_info=$(ps -p "$pid" -o etime= 2>/dev/null | xargs)
        else
            uptime_info=$(ps -p "$pid" -o etimes= 2>/dev/null | awk '{printf "%dm%ds", $1/60, $1%60}')
        fi
        echo -e "  ${name}: ${GREEN}running${NC} (PID ${pid}, uptime ${uptime_info:-unknown})"
        return 0
    else
        echo -e "  ${name}: ${RED}dead${NC} (stale PID ${pid})"
        rm -f "$pidfile"
        return 1
    fi
}

daemon_logs() {
    local name="$1"
    local logfile="${WORKSPACE}/${name}.log"
    local lines="${2:-20}"

    if [ ! -f "$logfile" ]; then
        info "No log file for ${name}"
        return 0
    fi

    header "${name} logs (last ${lines} lines):"
    tail -n "$lines" "$logfile" | while IFS= read -r line; do echo "    $line"; done
}

# ── Commands ─────────────────────────────────────────────────────────────────

cmd_keygen() {
    local yubikey=false list_keys=false
    local yk_args=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --yubikey)       yubikey=true; shift ;;
            --list)          list_keys=true; shift ;;
            --slot)          yk_args+=("--slot" "$2"); shift 2 ;;
            --serial)        yk_args+=("--serial" "$2"); shift 2 ;;
            --name)          yk_args+=("--name" "$2"); shift 2 ;;
            --pin-policy)    yk_args+=("--pin-policy" "$2"); shift 2 ;;
            --touch-policy)  yk_args+=("--touch-policy" "$2"); shift 2 ;;
            *) die "Unknown option: $1" ;;
        esac
    done

    # List all connected YubiKey recipients.
    if [ "$list_keys" = true ]; then
        ensure_yubikey_plugin
        header "YubiKey recipients"
        "$YUBIKEY_PLUGIN" --list
        return
    fi

    # YubiKey key generation.
    if [ "$yubikey" = true ]; then
        ensure_yubikey_plugin
        ensure_workspace

        local output="${WORKSPACE}/identity.txt"
        local i=1
        while [ -f "$output" ]; do
            output="${WORKSPACE}/identity-${i}.txt"
            ((i++))
        done

        header "Generating YubiKey identity"
        runcmd "$YUBIKEY_PLUGIN" --generate "${yk_args[@]+"${yk_args[@]}"}"
        "$YUBIKEY_PLUGIN" --generate "${yk_args[@]+"${yk_args[@]}"}" > "$output" || die "YubiKey key generation failed"

        # Extract the recipient line (age1yubikey1q...).
        local pubkey
        pubkey=$(grep "^#.*recipient:" "$output" | awk '{print $NF}' || true)
        if [ -z "$pubkey" ]; then
            pubkey=$(grep "^age1yubikey1" "$output" || true)
        fi

        header "YubiKey identity generated"
        echo "  Recipient: ${pubkey:-<see identity file>}"
        echo "  Identity:  ${output}"
        echo ""
        info "Use this recipient with: relayctl generate --recipient ${pubkey:-age1yubikey1...} ..."
        return
    fi

    # Native X25519 key generation (default).
    ensure_age
    ensure_workspace

    local output="${WORKSPACE}/identity.txt"
    local i=1
    while [ -f "$output" ]; do
        output="${WORKSPACE}/identity-${i}.txt"
        ((i++))
    done

    runcmd "$AGE_KEYGEN" -o "$output"
    "$AGE_KEYGEN" -o "$output" 2>/dev/null

    local pubkey
    pubkey=$(grep "public key:" "$output" | awk '{print $NF}')

    header "Key pair generated"
    echo "  Public key:  ${pubkey}"
    echo "  Identity:    ${output}"
    echo ""
    info "Use this public key with: relayctl generate --recipient ${pubkey} ..."
}

cmd_generate() {
    ensure_plugin

    local recipient="" remote_name="" config=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --recipient|-r) recipient="$2"; shift 2 ;;
            --remote)       remote_name="$2"; shift 2 ;;
            --config)       config="$2"; shift 2 ;;
            *) die "Unknown option: $1" ;;
        esac
    done

    [ -n "$recipient" ] || die "Missing --recipient <age1...>"
    [ -n "$remote_name" ] || die "Missing --remote <name>"

    local args=("--generate" "--inner-recipient" "$recipient" "--remote" "$remote_name")

    ensure_workspace
    local err_file="${WORKSPACE}/generate-err.tmp"
    local output
    runcmd "$PLUGIN_BIN" "${args[@]}"
    if [ -n "$config" ]; then
        output=$(AGE_PLUGIN_RELAY_CONFIG="$config" "$PLUGIN_BIN" "${args[@]}" 2>"$err_file") || true
    else
        output=$("$PLUGIN_BIN" "${args[@]}" 2>"$err_file") || true
    fi

    local relay_recipient relay_identity
    relay_recipient=$(echo "$output" | grep "^age1relay1" || true)
    relay_identity=$(echo "$output" | grep "^AGE-PLUGIN-RELAY-1" || true)

    if [ -z "$relay_recipient" ] || [ -z "$relay_identity" ]; then
        local err_msg
        err_msg=$(cat "$err_file" 2>/dev/null || true)
        rm -f "$err_file"
        if [ -n "$err_msg" ]; then
            die "Failed to generate relay keys: ${err_msg}"
        else
            die "Failed to generate relay keys (no output from plugin)"
        fi
    fi
    rm -f "$err_file"

    # Save to workspace
    echo "$relay_recipient" > "${WORKSPACE}/relay-recipient.txt"
    echo "$relay_identity" > "${WORKSPACE}/relay-identity.txt"

    header "Relay keys generated"
    echo ""
    echo "  Relay recipient (for encryption):"
    echo "    ${relay_recipient}"
    echo ""
    echo "  Relay identity (for decryption):"
    echo "    ${relay_identity}"
    echo ""
    info "Saved to: workspace/relay-recipient.txt"
    info "Saved to: workspace/relay-identity.txt"
}

cmd_tag() {
    local recipient=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --recipient|-r) recipient="$2"; shift 2 ;;
            *) die "Unknown option: $1" ;;
        esac
    done

    [ -n "$recipient" ] || die "Missing --recipient <age1...>"

    # Compute tag the same way Go does: SHA256(recipient)[:16] → base64 raw std encoding.
    local hash tag
    hash=$(printf '%s' "$recipient" | shasum -a 256 | cut -d' ' -f1)
    # Take first 32 hex chars (16 bytes), decode to binary, base64 encode, strip padding
    tag=$(echo "$hash" | head -c 32 | xxd -r -p | base64 | tr -d '=')

    header "Routing tag"
    echo "  Recipient: ${recipient}"
    echo "  Tag:       ${tag}"
    echo ""
    info "Use with: relayctl operator start --tag ${tag} ..."
}

cmd_server() {
    local action="${1:-}"; shift || true

    case "$action" in
        start)
            ensure_server

            local identity="" port="19876" extra_args=()
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --identity|-i)   identity="$2"; shift 2 ;;
                    --port|-p)       port="$2"; shift 2 ;;
                    --auth-token)    extra_args+=("-auth-token" "$2"); shift 2 ;;
                    --tls-cert)      extra_args+=("-tls-cert" "$2"); shift 2 ;;
                    --tls-key)       extra_args+=("-tls-key" "$2"); shift 2 ;;
                    --tls-ca)        extra_args+=("-tls-ca" "$2"); shift 2 ;;
                    --stream)        extra_args+=("-stream"); shift ;;
                    *) die "Unknown option: $1" ;;
                esac
            done

            [ -n "$identity" ] || die "Missing --identity <file>"
            [ -f "$identity" ] || die "Identity file not found: ${identity}"

            header "Starting relay-server"
            info "Identity: ${identity}"
            info "Port:     ${port}"

            # Add plugin to PATH so relay-server can discover it
            export PATH="${BIN_DIR}:${SCRIPT_DIR}/tools/bin:${PATH}"

            start_daemon "relay-server" "$SERVER_BIN" \
                -identity "$identity" \
                -addr ":${port}" \
                "${extra_args[@]+"${extra_args[@]}"}"
            ;;
        stop)
            stop_daemon "relay-server"
            ;;
        status)
            daemon_status "relay-server"
            ;;
        logs)
            daemon_logs "relay-server" "${1:-20}"
            ;;
        *)
            die "Usage: relayctl server start|stop|status|logs"
            ;;
    esac
}

cmd_broker() {
    local action="${1:-}"; shift || true

    case "$action" in
        start)
            ensure_broker

            local port="8443" extra_args=()
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --port|-p)      port="$2"; shift 2 ;;
                    --auth-token)   extra_args+=("-auth-token" "$2"); shift 2 ;;
                    --max-ttl)      extra_args+=("-max-ttl" "$2"); shift 2 ;;
                    *) die "Unknown option: $1" ;;
                esac
            done

            header "Starting relay-broker"
            info "Port:    ${port}"

            start_daemon "relay-broker" "$BROKER_BIN" \
                -addr ":${port}" \
                "${extra_args[@]+"${extra_args[@]}"}"
            ;;
        stop)
            stop_daemon "relay-broker"
            ;;
        status)
            daemon_status "relay-broker"
            ;;
        logs)
            daemon_logs "relay-broker" "${1:-20}"
            ;;
        *)
            die "Usage: relayctl broker start|stop|status|logs"
            ;;
    esac
}

cmd_operator() {
    local action="${1:-}"; shift || true

    case "$action" in
        start)
            ensure_operator

            local broker_url="" identity="" tag="" extra_args=()
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --broker)         broker_url="$2"; shift 2 ;;
                    --identity|-i)    identity="$2"; shift 2 ;;
                    --tag)            tag="$2"; shift 2 ;;
                    --auth-token)     extra_args+=("--auth-token" "$2"); shift 2 ;;
                    --pull-interval)  extra_args+=("--pull-interval" "$2"); shift 2 ;;
                    *) die "Unknown option: $1" ;;
                esac
            done

            [ -n "$broker_url" ] || die "Missing --broker <url>"
            [ -n "$identity" ]   || die "Missing --identity <file>"
            [ -n "$tag" ]        || die "Missing --tag <tag>"
            [ -f "$identity" ]   || die "Identity file not found: ${identity}"

            header "Starting relay-operator"
            info "Broker:   ${broker_url}"
            info "Identity: ${identity}"
            info "Tag:      ${tag}"

            # Add plugin binaries to PATH so operator can discover age plugins
            export PATH="${BIN_DIR}:${SCRIPT_DIR}/tools/bin:${PATH}"

            start_daemon "relay-operator" "$OPERATOR_BIN" \
                --broker "$broker_url" \
                --identity "$identity" \
                --tag "$tag" \
                --loop \
                "${extra_args[@]+"${extra_args[@]}"}"
            ;;
        stop)
            stop_daemon "relay-operator"
            ;;
        run)
            ensure_operator

            local broker_url="" identity="" tag="" extra_args=()
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --broker)         broker_url="$2"; shift 2 ;;
                    --identity|-i)    identity="$2"; shift 2 ;;
                    --tag)            tag="$2"; shift 2 ;;
                    --auth-token)     extra_args+=("--auth-token" "$2"); shift 2 ;;
                    *) die "Unknown option: $1" ;;
                esac
            done

            [ -n "$broker_url" ] || die "Missing --broker <url>"
            [ -n "$identity" ]   || die "Missing --identity <file>"
            [ -n "$tag" ]        || die "Missing --tag <tag>"
            [ -f "$identity" ]   || die "Identity file not found: ${identity}"

            header "Running relay-operator (one-shot)"
            info "Broker:   ${broker_url}"
            info "Identity: ${identity}"
            info "Tag:      ${tag}"

            # Add plugin binaries to PATH so operator can discover age plugins
            export PATH="${BIN_DIR}:${SCRIPT_DIR}/tools/bin:${PATH}"

            runcmd "$OPERATOR_BIN" \
                --broker "$broker_url" \
                --identity "$identity" \
                --tag "$tag" \
                "${extra_args[@]+"${extra_args[@]}"}"
            "$OPERATOR_BIN" \
                --broker "$broker_url" \
                --identity "$identity" \
                --tag "$tag" \
                "${extra_args[@]+"${extra_args[@]}"}"
            ok "Operator completed"
            ;;
        status)
            daemon_status "relay-operator"
            ;;
        logs)
            daemon_logs "relay-operator" "${1:-20}"
            ;;
        *)
            die "Usage: relayctl operator start|run|stop|status|logs"
            ;;
    esac
}

cmd_encrypt() {
    ensure_age
    ensure_plugin

    local recipient="" infile="" outfile=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -r|--recipient) recipient="$2"; shift 2 ;;
            -i|--input)     infile="$2"; shift 2 ;;
            -o|--output)    outfile="$2"; shift 2 ;;
            *) die "Unknown option: $1" ;;
        esac
    done

    [ -n "$recipient" ] || die "Missing -r <recipient>"

    export PATH="${BIN_DIR}:${SCRIPT_DIR}/tools/bin:${PATH}"

    local age_args=("-r" "$recipient")
    [ -n "$outfile" ] && age_args+=("-o" "$outfile")

    if [ -n "$infile" ]; then
        runcmd "$AGE" "${age_args[@]}" "<" "$infile"
        "$AGE" "${age_args[@]}" < "$infile"
    else
        runcmd "$AGE" "${age_args[@]}"
        "$AGE" "${age_args[@]}"
    fi

    if [ -n "$outfile" ]; then
        ok "Encrypted → ${outfile} ($(wc -c < "$outfile" | tr -d ' ') bytes)"
    fi
}

cmd_decrypt() {
    ensure_age
    ensure_plugin

    local identity_file="" ciphertext="" outfile="" config=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -i|--identity)  identity_file="$2"; shift 2 ;;
            -f|--file)      ciphertext="$2"; shift 2 ;;
            -o|--output)    outfile="$2"; shift 2 ;;
            --config)       config="$2"; shift 2 ;;
            *) die "Unknown option: $1" ;;
        esac
    done

    [ -n "$identity_file" ] || die "Missing -i <identity-file>"
    [ -f "$identity_file" ] || die "Identity file not found: ${identity_file}"

    export PATH="${BIN_DIR}:${SCRIPT_DIR}/tools/bin:${PATH}"
    # Auto-discover config: explicit flag > env var > workspace default
    if [ -n "$config" ]; then
        export AGE_PLUGIN_RELAY_CONFIG="$(cd "$(dirname "$config")" && pwd)/$(basename "$config")"
    elif [ -z "${AGE_PLUGIN_RELAY_CONFIG:-}" ] && [ -f "${WORKSPACE}/relay-config.yaml" ]; then
        export AGE_PLUGIN_RELAY_CONFIG="${WORKSPACE}/relay-config.yaml"
    fi

    local age_args=("-d" "-i" "$identity_file")
    [ -n "$outfile" ] && age_args+=("-o" "$outfile")
    [ -n "$ciphertext" ] && age_args+=("$ciphertext")

    runcmd "$AGE" "${age_args[@]}"
    "$AGE" "${age_args[@]}"
}

cmd_status() {
    header "Service status"
    daemon_status "relay-server" || true
    daemon_status "relay-broker" || true
    daemon_status "relay-operator" || true
}

cmd_stop() {
    header "Stopping all services"
    stop_daemon "relay-operator"
    stop_daemon "relay-broker"
    stop_daemon "relay-server"
}

cmd_clean() {
    cmd_stop
    echo ""
    if [ -d "$WORKSPACE" ]; then
        rm -rf "$WORKSPACE"
        ok "Workspace removed: ${WORKSPACE}"
    else
        info "Workspace already clean"
    fi
}

cmd_build() {
    header "Building all binaries"

    mkdir -p "$BIN_DIR"

    local module_root="${SCRIPT_DIR}"
    local bins=("age-plugin-relay" "relay-server" "relay-broker" "relay-operator")
    local cmds=("./cmd/age-plugin-relay/" "./cmd/relay-server/" "./cmd/relay-broker/" "./cmd/relay-operator/")

    for i in "${!bins[@]}"; do
        local name="${bins[$i]}"
        local pkg="${cmds[$i]}"
        local output="${BIN_DIR}/${name}"

        info "Building ${name}..."
        runcmd go build -o "$output" "${module_root}/${pkg}"
        go build -o "$output" "${module_root}/${pkg}" || die "Failed to build ${name}"
        ok "${name} → ${output}"
    done
}

cmd_help() {
    echo -e "${BOLD}relayctl${NC} — CLI utility for age-plugin-relay"
    echo ""
    echo -e "${BOLD}Key Management:${NC}"
    echo "  keygen                                Generate a new X25519 key pair"
    echo "  keygen --yubikey [--slot N] [...]      Generate a YubiKey identity"
    echo "  keygen --list                          List all connected YubiKey recipients"
    echo "  generate --recipient <age1...> --remote <name> [--config <file>]"
    echo "                                        Generate relay recipient + identity"
    echo "  tag --recipient <age1...>             Compute routing tag for a recipient"
    echo ""
    echo -e "${BOLD}Services:${NC}"
    echo "  server  start|stop|status|logs        Manage relay-server"
    echo "  broker  start|stop|status|logs        Manage relay-broker"
    echo "  operator start|run|stop|status|logs  Manage relay-operator (start=daemon, run=one-shot)"
    echo ""
    echo -e "${BOLD}Encrypt / Decrypt:${NC}"
    echo "  encrypt -r <recipient> [-i infile] [-o outfile]"
    echo "  decrypt -i <identity-file> [-f ciphertext] [-o outfile] [--config <file>]"
    echo ""
    echo -e "${BOLD}Utilities:${NC}"
    echo "  status                                Show all running services"
    echo "  stop                                  Stop all running services"
    echo "  clean                                 Remove workspace + stop services"
    echo "  build                                 Build all binaries"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo ""
    echo -e "  ${DIM}# Sync flow: generate keys → start server → encrypt → decrypt${NC}"
    echo "  relayctl keygen"
    echo "  relayctl generate --recipient age1... --remote myserver"
    echo "  relayctl server start --identity workspace/identity.txt"
    echo "  echo 'hello' | relayctl encrypt -r age1relay1... -o secret.age"
    echo "  relayctl decrypt -i workspace/relay-identity.txt -f secret.age"
    echo "  relayctl server stop"
    echo ""
    echo -e "  ${DIM}# Async flow: broker + operator${NC}"
    echo "  relayctl broker start --port 8443"
    echo "  relayctl operator start --broker http://localhost:8443 \\"
    echo "    --identity keys.txt --tag QPg24ggKk7xKd2t3c5rL9A"
    echo "  echo 'hello' | relayctl encrypt -r age1relay1... -o secret.age"
    echo "  relayctl decrypt -i relay-id.txt -f secret.age --config relay-config.yaml"
    echo "  relayctl stop"
    echo ""
    echo -e "${BOLD}Environment:${NC}"
    echo "  RELAYCTL_WORKSPACE    Workspace directory (default: ./workspace)"
}

# ── Main Dispatch ────────────────────────────────────────────────────────────

command="${1:-help}"
shift || true

case "$command" in
    keygen)     cmd_keygen "$@" ;;
    generate)   cmd_generate "$@" ;;
    tag)        cmd_tag "$@" ;;
    server)     cmd_server "$@" ;;
    broker)     cmd_broker "$@" ;;
    operator)   cmd_operator "$@" ;;
    encrypt)    cmd_encrypt "$@" ;;
    decrypt)    cmd_decrypt "$@" ;;
    status)     cmd_status "$@" ;;
    stop)       cmd_stop "$@" ;;
    clean)      cmd_clean "$@" ;;
    build)      cmd_build "$@" ;;
    help|--help|-h)
                cmd_help ;;
    *)          die "Unknown command: ${command}. Run 'relayctl help' for usage." ;;
esac
