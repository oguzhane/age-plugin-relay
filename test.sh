#!/bin/bash
set -euo pipefail

# test.sh — End-to-end test for age-plugin-relay (step-by-step)
#
# Usage:
#   ./test.sh          Run all steps sequentially
#   ./test.sh 1        Run only step 1
#   ./test.sh 2        Run only step 2 (requires step 1 output in tmp/)
#   ...
#   ./test.sh 6        Run only step 6
#   ./test.sh clean    Remove tmp/ and built binaries
#
# Steps:
#   1  Generate remote X25519 key pair
#   2  Generate relay recipient + identity
#   3  Start relay-server
#   4  Encrypt test message via relay recipient
#   5  Decrypt via relay identity (plugin → relay-server → unwrap)
#   6  Verify plaintext matches
#
# All artifacts are written to ./tmp/ for inspection between steps.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Paths
AGE="${SCRIPT_DIR}/../bin/age"
AGE_KEYGEN="${SCRIPT_DIR}/../bin/age-keygen"
PLUGIN_BINARY="${SCRIPT_DIR}/age-plugin-relay"
RELAY_SERVER_BIN="${SCRIPT_DIR}/relay-server"
TMPDIR="${SCRIPT_DIR}/tmp"

RELAY_PORT=19876
RELAY_URL="http://127.0.0.1:${RELAY_PORT}/unwrap"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
NC='\033[0m'

pass()  { echo -e "${GREEN}  ✓ $1${NC}"; }
fail()  { echo -e "${RED}  ✗ $1${NC}"; exit 1; }
step()  { echo -e "\n${YELLOW}━━━ Step $1: $2 ━━━${NC}"; }
info()  { echo -e "${CYAN}  ℹ $1${NC}"; }
file()  { echo -e "${DIM}  📄 $1${NC}"; }

# ── Handle "clean" ───────────────────────────────────────────────────────────

if [ "${1:-}" = "clean" ]; then
    echo "Cleaning up..."
    rm -rf "$TMPDIR"
    # Kill any lingering relay-server on our port
    lsof -ti :${RELAY_PORT} 2>/dev/null | xargs kill 2>/dev/null || true
    echo "Done."
    exit 0
fi

# ── Determine which steps to run ─────────────────────────────────────────────

REQUESTED_STEP="${1:-all}"

should_run() {
    [ "$REQUESTED_STEP" = "all" ] || [ "$REQUESTED_STEP" = "$1" ]
}

# ── Prerequisites ────────────────────────────────────────────────────────────

echo ""
echo "=== age-plugin-relay end-to-end test ==="

[ -x "$AGE" ]        || fail "age binary not found at $AGE"
[ -x "$AGE_KEYGEN" ] || fail "age-keygen binary not found at $AGE_KEYGEN"

if [ ! -x "$PLUGIN_BINARY" ]; then
    info "Building age-plugin-relay..."
    go build -o "$PLUGIN_BINARY" .
fi
if [ ! -x "$RELAY_SERVER_BIN" ]; then
    info "Building relay-server..."
    go build -o "$RELAY_SERVER_BIN" ./cmd/relay-server/
fi

export PATH="${SCRIPT_DIR}:${PATH}"
mkdir -p "$TMPDIR"

# ── Step 1: Generate remote key pair ─────────────────────────────────────────

if should_run 1; then
    step 1 "Generate remote X25519 key pair"

    REMOTE_IDENTITY="${TMPDIR}/remote-identity.txt"
    rm -f "$REMOTE_IDENTITY"
    "$AGE_KEYGEN" -o "$REMOTE_IDENTITY" 2>/dev/null

    REMOTE_PUBKEY=$(grep "public key:" "$REMOTE_IDENTITY" | awk '{print $NF}')

    info "This simulates a key pair held by a remote user (e.g., your workstation in Germany)."
    info "The private key stays with the remote user. Only the public key is shared."
    echo ""
    echo "  Public key:  $REMOTE_PUBKEY"
    echo "  Private key: $(grep "^AGE-SECRET-KEY-" "$REMOTE_IDENTITY")"
    file "tmp/remote-identity.txt"
    echo ""
    pass "Remote key pair generated"

    if [ "$REQUESTED_STEP" = "1" ]; then
        echo ""
        info "Inspect: cat tmp/remote-identity.txt"
        info "Next:    ./test.sh 2"
        exit 0
    fi
fi

# ── Step 2: Generate relay recipient + identity ──────────────────────────────

if should_run 2; then
    step 2 "Generate relay recipient + identity"

    # Load remote public key from step 1
    REMOTE_IDENTITY="${TMPDIR}/remote-identity.txt"
    [ -f "$REMOTE_IDENTITY" ] || fail "Run step 1 first: ./test.sh 1"
    REMOTE_PUBKEY=$(grep "public key:" "$REMOTE_IDENTITY" | awk '{print $NF}')

    info "The relay recipient embeds the remote public key."
    info "The relay identity embeds a tag (for stanza matching) + relay URL."
    info "Neither contains any secret material."
    echo ""

    GENERATE_OUTPUT=$("$PLUGIN_BINARY" --generate \
        --inner-recipient "$REMOTE_PUBKEY" \
        --relay-url "$RELAY_URL" 2>/dev/null)

    RELAY_RECIPIENT=$(echo "$GENERATE_OUTPUT" | grep "^age1relay1")
    RELAY_IDENTITY_STR=$(echo "$GENERATE_OUTPUT" | grep "^AGE-PLUGIN-RELAY-1")

    [ -n "$RELAY_RECIPIENT" ]    || fail "Failed to extract relay recipient"
    [ -n "$RELAY_IDENTITY_STR" ] || fail "Failed to extract relay identity"

    # Save for later steps
    echo "$RELAY_RECIPIENT" > "${TMPDIR}/relay-recipient.txt"
    echo "$RELAY_IDENTITY_STR" > "${TMPDIR}/relay-identity.txt"

    echo "  Inner recipient: $REMOTE_PUBKEY"
    echo "  Relay URL:       $RELAY_URL"
    echo ""
    echo "  Relay recipient (for encryption):"
    echo "    $RELAY_RECIPIENT"
    echo ""
    echo "  Relay identity (for decryption):"
    echo "    $RELAY_IDENTITY_STR"
    echo ""
    file "tmp/relay-recipient.txt"
    file "tmp/relay-identity.txt"
    echo ""
    pass "Relay recipient and identity generated"

    if [ "$REQUESTED_STEP" = "2" ]; then
        echo ""
        info "Inspect: cat tmp/relay-recipient.txt"
        info "Inspect: cat tmp/relay-identity.txt"
        info "Next:    ./test.sh 3"
        exit 0
    fi
fi

# ── Step 3: Start relay-server ───────────────────────────────────────────────

if should_run 3; then
    step 3 "Start relay-server"

    REMOTE_IDENTITY="${TMPDIR}/remote-identity.txt"
    [ -f "$REMOTE_IDENTITY" ] || fail "Run step 1 first: ./test.sh 1"

    # Kill any existing relay-server on this port
    lsof -ti :${RELAY_PORT} 2>/dev/null | xargs kill 2>/dev/null || true
    sleep 0.2

    info "Starting relay-server on port ${RELAY_PORT}."
    info "It loads the remote private key and serves POST /unwrap."
    info "In production, this runs on the remote user's machine."
    echo ""

    RELAY_LOG="${TMPDIR}/relay-server.log"
    "$RELAY_SERVER_BIN" -identity "$REMOTE_IDENTITY" -addr ":${RELAY_PORT}" > "$RELAY_LOG" 2>&1 &
    RELAY_PID=$!
    echo "$RELAY_PID" > "${TMPDIR}/relay-server.pid"

    # Wait for server to accept connections
    for i in $(seq 1 30); do
        if curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${RELAY_PORT}/unwrap" 2>/dev/null | grep -q "405\|200\|404"; then
            break
        fi
        sleep 0.1
    done

    if ! kill -0 "$RELAY_PID" 2>/dev/null; then
        echo "  Server log:"
        cat "$RELAY_LOG" 2>/dev/null || true
        fail "Relay server failed to start"
    fi

    echo "  PID:       $RELAY_PID"
    echo "  Endpoint:  $RELAY_URL"
    echo "  Identity:  $REMOTE_IDENTITY"
    echo "  Log:       tmp/relay-server.log"
    file "tmp/relay-server.pid"
    file "tmp/relay-server.log"
    echo ""
    pass "Relay server running"

    if [ "$REQUESTED_STEP" = "3" ]; then
        echo ""
        info "Test it: curl -s http://127.0.0.1:${RELAY_PORT}/unwrap"
        info "Log:     cat tmp/relay-server.log"
        info "Stop:    kill \$(cat tmp/relay-server.pid)"
        info "Next:    ./test.sh 4"
        exit 0
    fi
fi

# ── Step 4: Encrypt ──────────────────────────────────────────────────────────

if should_run 4; then
    step 4 "Encrypt test message via relay recipient"

    RELAY_RECIPIENT_FILE="${TMPDIR}/relay-recipient.txt"
    [ -f "$RELAY_RECIPIENT_FILE" ] || fail "Run step 2 first: ./test.sh 2"
    RELAY_RECIPIENT=$(cat "$RELAY_RECIPIENT_FILE")

    PLAINTEXT="The quick brown fox jumps over the lazy dog — $(date +%s)"
    echo "$PLAINTEXT" > "${TMPDIR}/plaintext.txt"

    ENCRYPTED_FILE="${TMPDIR}/secret.age"

    info "Encrypting with: age -r <relay_recipient>"
    info "The plugin wraps the file key using the inner X25519 public key,"
    info "then re-tags the stanza as 'relay'. No network involved."
    echo ""

    echo "$PLAINTEXT" | "$AGE" -r "$RELAY_RECIPIENT" -o "$ENCRYPTED_FILE"

    echo "  Plaintext: $PLAINTEXT"
    echo "  Encrypted: $(wc -c < "$ENCRYPTED_FILE" | tr -d ' ') bytes"
    echo ""
    echo "  Encrypted file header:"
    while IFS= read -r line; do
        echo "    $line"
    done < <(head -4 "$ENCRYPTED_FILE")
    echo ""

    # Verify stanza format
    STANZA_LINE=$(sed -n '2p' "$ENCRYPTED_FILE")
    if [[ "$STANZA_LINE" == "-> relay "* ]]; then
        # Parse the relay stanza
        TAG=$(echo "$STANZA_LINE" | awk '{print $3}')
        INNER_TYPE=$(echo "$STANZA_LINE" | awk '{print $4}')
        info "Stanza type: relay"
        info "Tag (base64): $TAG"
        info "Inner type: $INNER_TYPE"
    else
        fail "Unexpected stanza: $STANZA_LINE"
    fi

    file "tmp/plaintext.txt"
    file "tmp/secret.age"
    echo ""
    pass "Encryption succeeded"

    if [ "$REQUESTED_STEP" = "4" ]; then
        echo ""
        info "Inspect: cat tmp/plaintext.txt"
        info "Inspect: head -5 tmp/secret.age"
        info "Inspect: xxd tmp/secret.age | head -20"
        info "Next:    ./test.sh 5   (requires relay-server from step 3)"
        exit 0
    fi
fi

# ── Step 5: Decrypt ──────────────────────────────────────────────────────────

if should_run 5; then
    step 5 "Decrypt via relay identity (plugin → relay-server → unwrap)"

    RELAY_IDENTITY_FILE="${TMPDIR}/relay-identity.txt"
    ENCRYPTED_FILE="${TMPDIR}/secret.age"
    [ -f "$RELAY_IDENTITY_FILE" ] || fail "Run step 2 first: ./test.sh 2"
    [ -f "$ENCRYPTED_FILE" ]      || fail "Run step 4 first: ./test.sh 4"

    # Check relay-server is running
    if [ -f "${TMPDIR}/relay-server.pid" ]; then
        RELAY_PID=$(cat "${TMPDIR}/relay-server.pid")
        kill -0 "$RELAY_PID" 2>/dev/null || fail "Relay server not running. Run step 3: ./test.sh 3"
    else
        fail "Relay server not running. Run step 3: ./test.sh 3"
    fi

    info "Decrypting with: age -d -i <relay_identity_file>"
    info "The plugin reads the relay identity → extracts tag + relay URL."
    info "Matches the 'relay' stanza by tag → reconstructs inner X25519 stanza."
    info "POSTs inner stanza to ${RELAY_URL} → relay-server unwraps → file key returned."
    echo ""

    DECRYPTED=$("$AGE" -d -i "$RELAY_IDENTITY_FILE" "$ENCRYPTED_FILE")
    echo "$DECRYPTED" > "${TMPDIR}/decrypted.txt"

    echo "  Decrypted: $DECRYPTED"
    echo ""

    # Show relay-server log
    RELAY_LOG="${TMPDIR}/relay-server.log"
    if [ -f "$RELAY_LOG" ] && [ -s "$RELAY_LOG" ]; then
        echo "  Relay server log:"
        while IFS= read -r line; do
            echo "    $line"
        done < "$RELAY_LOG"
        echo ""
    fi

    file "tmp/decrypted.txt"
    echo ""
    pass "Decryption succeeded"

    if [ "$REQUESTED_STEP" = "5" ]; then
        echo ""
        info "Inspect: cat tmp/decrypted.txt"
        info "Inspect: cat tmp/relay-server.log"
        info "Next:    ./test.sh 6"
        exit 0
    fi
fi

# ── Step 6: Verify ───────────────────────────────────────────────────────────

if should_run 6; then
    step 6 "Verify plaintext matches"

    PLAINTEXT_FILE="${TMPDIR}/plaintext.txt"
    DECRYPTED_FILE="${TMPDIR}/decrypted.txt"
    [ -f "$PLAINTEXT_FILE" ]  || fail "Run step 4 first: ./test.sh 4"
    [ -f "$DECRYPTED_FILE" ]  || fail "Run step 5 first: ./test.sh 5"

    PLAINTEXT=$(cat "$PLAINTEXT_FILE")
    DECRYPTED=$(cat "$DECRYPTED_FILE")

    echo ""
    echo "  Original:  $PLAINTEXT"
    echo "  Decrypted: $DECRYPTED"
    echo ""

    if [ "$DECRYPTED" = "$PLAINTEXT" ]; then
        pass "Plaintext matches!"
    else
        echo ""
        info "diff:"
        diff <(echo "$PLAINTEXT") <(echo "$DECRYPTED") || true
        fail "Plaintext mismatch"
    fi

    if [ "$REQUESTED_STEP" = "6" ]; then
        echo ""
        info "All done. Clean up: ./test.sh clean"
        exit 0
    fi
fi

# ── Cleanup relay-server if we ran all steps ─────────────────────────────────

if [ "$REQUESTED_STEP" = "all" ]; then
    if [ -f "${TMPDIR}/relay-server.pid" ]; then
        RELAY_PID=$(cat "${TMPDIR}/relay-server.pid")
        kill "$RELAY_PID" 2>/dev/null || true
        wait "$RELAY_PID" 2>/dev/null || true
    fi

    echo ""
    echo -e "${GREEN}=== All steps passed ===${NC}"
    echo ""
    info "Artifacts in tmp/ — inspect or run: ./test.sh clean"
fi
