# age-plugin-relay

An [age](https://age-encryption.org) plugin that decouples the **location** of age identities from the encryption/decryption process. It acts as a router — any age identity (X25519, YubiKey, hybrid PQ, or other plugins) can be used remotely through an HTTP relay endpoint.

## How It Works

```
ENCRYPTION (offline — no relay needed)        DECRYPTION (online — relay required)

  age1relay1<inner_recipient>                   AGE-PLUGIN-RELAY-1<tag + target>
    |                                             |
    v                                             v
  Extract inner recipient string                Receive relay stanzas from age header
    |                                             |
    v                                             v
  age.ParseRecipients() -> Wrap()               Match stanzas by tag, reconstruct inner stanzas
    |                                             |
    v                                             v
  Re-tag stanza: X25519 -> relay                Resolve target (URL or remote name from config)
    |                                             |
    v                                             v
  Done. No network. Identity-agnostic.          HTTP POST inner stanzas -> file key returned
```

**Encryption** uses only the inner recipient's public key — no relay, no network, no hardware. The plugin delegates to `age.ParseRecipients()`, so it works with any recipient type the `age` library (or plugins in `PATH`) can parse.

**Decryption** forwards the encrypted stanzas to a relay endpoint over HTTP(S). What serves that endpoint is not the plugin's concern — it could be a simple agent, a gateway with an approval UI, a serverless function, etc.

## Install

```bash
go build -o age-plugin-relay ./cmd/age-plugin-relay/
go build -o relay-server ./cmd/relay-server/        # optional: sync relay server
go build -o relay-broker ./cmd/relay-broker/        # optional: async broker
go build -o relay-operator ./cmd/relay-operator/    # optional: async operator
```

Place the binary in your `PATH` so `age` can discover it:

```bash
cp age-plugin-relay /usr/local/bin/
# or
export PATH="/path/to/age-plugin-relay:$PATH"
```

## Usage

### Generate a relay recipient and identity

**Legacy mode** (URL embedded in identity):

```bash
age-plugin-relay --generate \
  --inner-recipient "age1abc..." \
  --relay-url "https://relay.example:8443/unwrap"
```

**Config mode** (remote name, resolved from `relay-config.yaml`):

```bash
age-plugin-relay --generate \
  --inner-recipient "age1abc..." \
  --remote myserver
```

Config mode produces shorter identity strings and supports per-remote TLS and timeout. See [Config File](#config-file) below.

Output:

```
# Relay recipient (for encryption — add to .sops.yaml or age -r):
#   Inner: age1abc...
#   Relay: https://relay.example:8443/unwrap
age1relay1q...

# Relay identity (for decryption — add to identity file):
#   Relay: https://relay.example:8443/unwrap
AGE-PLUGIN-RELAY-1...
```

The inner recipient can be any age recipient type:

| Inner type | Example | Plugin needed in PATH? |
|---|---|---|
| X25519 | `age1abc...` | No (native) |
| Hybrid PQ | `age1pq1...` | No (native, age v1.3+) |
| YubiKey P-256 | `age1yubikey1q...` | Yes: `age-plugin-yubikey` |
| Any plugin | `age1NAME1...` | Yes: `age-plugin-NAME` |

If the inner recipient requires a plugin that is not in `PATH`, `--generate` prints a warning but proceeds.

### Encrypt

```bash
echo "secret" | age -r "age1relay1q..." -o secret.age
```

This wraps the file key using the inner recipient's public key and tags the stanza as `relay`. No network or relay endpoint is contacted.

### Decrypt

```bash
age -d -i identities.txt secret.age
```

Where `identities.txt` contains:

```
AGE-PLUGIN-RELAY-1...
```

The plugin sends the encrypted stanzas to the relay URL and returns the unwrapped file key.

### Use with SOPS key groups

SOPS [key groups](https://github.com/getsops/sops#key-groups) use Shamir's Secret Sharing to require multiple keys for decryption. Combine a local key with a relayed remote key:

```yaml
# .sops.yaml
creation_rules:
  - path_regex: \.enc\.yaml$
    key_groups:
      - age:
          - age1yubikey1q...    # Group 1: local YubiKey on server
      - age:
          - age1relay1q...      # Group 2: relayed to remote identity
    shamir_threshold: 2         # BOTH groups required
```

Identity file on the server:

```
# Group 1: local YubiKey
AGE-PLUGIN-YUBIKEY-1...

# Group 2: relay to remote
AGE-PLUGIN-RELAY-1...
```

SOPS splits the data encryption key into 2 Shamir shares. Group 1 is decrypted locally. Group 2 is forwarded through the relay plugin to the remote endpoint.

## Data Model

### Recipient: `age1relay1<bech32(inner_recipient_string)>`

The Bech32 data payload is the UTF-8 bytes of the inner age recipient string. The plugin extracts it, calls `age.ParseRecipients()`, and delegates `Wrap()` to the parsed recipient.

### Identity: `AGE-PLUGIN-RELAY-1<bech32(tag || target)>`

The target is either a full URL (legacy) or a remote name (config mode).

| Field | Size | Description |
|---|---|---|
| `tag` | 16 bytes | `SHA-256(inner_recipient_string)[:16]` — matches stanzas to this identity |
| `target` | variable | URL (`https://...`) or remote name (`myserver`) |

Not secret. Contains no key material — only routing information. Safe to commit to version control.

At decrypt time, the plugin detects the target type:
- Starts with `http://` or `https://` → use as relay URL directly (legacy)
- Anything else → look up in `relay-config.yaml` (config mode)

### Stanza format

```
-> relay <tag_b64> <inner_type> [inner_args...]
<body>
```

Example with an X25519 inner recipient:

```
-> relay QPg24g X25519 CKTwCgeHBEBFmdC7GJSffbto8y+8G8iPHhTeMnhxIg4
X0e7a90Lzp8lnpGBH7JdWnpW+WcH61T4obAXzVHa6N8
```

| Argument | Description |
|---|---|
| `QPg24g` | Base64-encoded 4-byte tag (for routing) |
| `X25519` | Original inner stanza type |
| `CKTw...` | Original inner stanza arguments (passed through) |

On decryption the plugin strips `relay` and the tag, reconstructs the original inner stanza, and forwards it to the relay endpoint.

## Relay Endpoint HTTP Contract

The plugin POSTs to the relay URL during decryption. What serves that URL is entirely decoupled from the plugin. The URL is opaque to the plugin — the intent is conveyed by the `action` field in the payload.

### Request

```http
POST / HTTP/1.1
Content-Type: application/json

{
  "version": 1,
  "action": "unwrap",
  "stream": true,
  "stanzas": [
    {
      "type": "X25519",
      "args": ["CKTwCgeHBEBFmdC7GJSffbto8y+8G8iPHhTeMnhxIg4"],
      "body": "X0e7a90Lzp8lnpGBH7JdWnpW+WcH61T4obAXzVHa6N8"
    }
  ]
}
```

- `version`: Protocol version (currently `1`).
- `action`: The operation to perform. Defined actions: `"unwrap"`, `"poll"`, `"pull"`, `"fulfill"`, `"reject"`. See [Control Tower (Async Flow)](#control-tower-async-flow) for the async actions.
- `stream`: Optional. If `true`, the client accepts SSE responses. See [Streaming (SSE)](#streaming-sse).
- `stanzas`: Array of inner stanzas with the relay wrapping stripped. The `body` field is base64 raw standard encoded.

### Response

**Success (200):**

```json
{
  "file_key": "dGVzdGtleS4uLi4uLi4u"
}
```

`file_key` is the 16-byte age file key, base64 raw standard encoded.

When [encrypted response](#encrypted-response-ephemeral-x25519) is active, the server returns `encrypted_file_key` instead:

```json
{
  "encrypted_file_key": "<base64: serverPub(32) || nonce(24) || NaCl box ciphertext>"
}
```

**Errors:**

| HTTP Status | Body | Meaning |
|---|---|---|
| 404 | `{"error": "no_matching_identity"}` | No identity can unwrap these stanzas |
| 408 | `{"error": "timeout"}` | Identity interaction timed out (e.g., YubiKey not touched) |
| 503 | `{"error": "unavailable"}` | Relay can't reach the identity |

### Streaming (SSE)

For long-running relay scenarios (approval flows, remote YubiKey touch), the server can respond with Server-Sent Events instead of a single JSON response. This keeps the connection alive through proxies and load balancers.

SSE is enabled per-remote via the `stream` field in `relay-config.yaml`. When enabled, the plugin sends `"stream": true` in the request payload. The client detects the response type from `Content-Type`:

- `application/json` → standard JSON (legacy, always works)
- `text/event-stream` → SSE stream

Servers that don't support SSE simply ignore the `stream` field and return JSON.

#### SSE events

| Event | Data | Meaning |
|---|---|---|
| `result` | `{"file_key": "..."}` | Unwrap succeeded — stream ends |
| `error` | `{"error": "..."}` | Unwrap failed — stream ends |
| `: comment` | (none) | Heartbeat — keeps connection alive |

Example SSE response:

```
: heartbeat

event: result
data: {"file_key": "dGVzdGtleS4uLi4uLi4u"}

```

Unknown event types are silently ignored for forward compatibility.

## Config File

For managing multiple remotes with per-remote TLS and timeout, create a `relay-config.yaml`:

```yaml
# relay-config.yaml
remotes:
  myserver:
    url: https://relay.example:8443/unwrap         # required
    tls_cert: /path/to/client.crt                  # optional (mTLS)
    tls_key: /path/to/client.key                   # optional (mTLS)
    tls_ca: /path/to/ca.crt                        # optional (custom CA)
    timeout: 5m                                    # optional (default: 5m)
    stream: true                                   # optional (SSE for long-running requests)
    auth_token: my-bearer-token                    # optional (Bearer token for simple auth)
    hmac_key: my-shared-secret                     # optional (HMAC-SHA256 request signing)
    encrypted_response: true                       # optional (ephemeral X25519 response encryption)

  backup:
    url: https://backup.example:9999/unwrap
```

The plugin looks for the config file at:
1. `AGE_PLUGIN_RELAY_CONFIG` env var (if set)
2. `$PWD/relay-config.yaml`

Config is optional — URL-based identities work without any config file.

### Resolution priority at decrypt time

Per-remote config takes priority over environment variables:

| Setting | Priority |
|---|---|
| TLS cert/key/CA | Remote config > env var (`AGE_PLUGIN_RELAY_TLS_*`) |
| Timeout | Remote config > env var (`AGE_PLUGIN_RELAY_TIMEOUT`) > default 5m |

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `AGE_PLUGIN_RELAY_CONFIG` | `$PWD/relay-config.yaml` | Path to config file |
| `AGE_PLUGIN_RELAY_TIMEOUT` | `5m` | HTTP timeout (fallback if not set per-remote). Supports Go duration format. |
| `AGE_PLUGIN_RELAY_TLS_CERT` | — | Client TLS certificate (fallback if not set per-remote) |
| `AGE_PLUGIN_RELAY_TLS_KEY` | — | Client TLS private key (fallback if not set per-remote) |
| `AGE_PLUGIN_RELAY_TLS_CA` | — | CA certificate for server verification (fallback if not set per-remote) |
| `AGE_PLUGIN_RELAY_AUTH_TOKEN` | — | Bearer token for relay server auth (fallback if not set per-remote) |
| `AGE_PLUGIN_RELAY_HMAC_KEY` | — | HMAC-SHA256 shared key for request signing (fallback if not set per-remote) |

## Architecture

```
age-plugin-relay/
├── relay/                              # Importable library (package relay)
│   ├── encoding.go                     # ComputeTag, EncodeRelayRecipient, EncodeRelayIdentity
│   ├── errors.go                       # Sentinel errors
│   ├── recipient.go                    # RelayRecipient, NewRelayRecipient, Wrap
│   ├── identity.go                     # RelayIdentity, NewRelayIdentity, Unwrap, ResolveRemote
│   ├── client.go                       # RelayRequest/Response/Stanza, PostToRelay, SSE parser, async polling
│   ├── config.go                       # Config, RemoteConfig, LoadConfig, LookupRemote, PollInterval
│   ├── hmac.go                         # HMAC-SHA256 request signing and verification
│   ├── envelope.go                     # Ephemeral X25519 response encryption (NaCl box)
│   ├── broker/                         # Broker queue package (package broker)
│   │   ├── types.go                    # Intent, Status, PluginHeaders, PullResponse, PollResponse
│   │   ├── queue.go                    # In-memory intent queue with TTL sweep
│   │   └── queue_test.go              # Broker queue unit tests (18 tests)
│   ├── relay_test.go                   # Unit tests (mock relay, SSE, HMAC, envelope)
│   ├── hmac_test.go                    # HMAC signing unit tests
│   ├── envelope_test.go                # Envelope seal/open unit tests
│   ├── async_test.go                   # Async (Control Tower) tests (12 tests)
│   ├── integration_test.go             # Integration tests (mock relay, config, errors)
│   └── e2e_test.go                     # E2E tests (real binaries, full user flow)
├── cmd/
│   ├── age-plugin-relay/
│   │   └── main.go                     # Plugin binary: flags, --generate, HandleRecipient/Identity
│   ├── relay-server/
│   │   └── main.go                     # Minimal relay HTTP server (sync flow)
│   ├── relay-broker/
│   │   └── main.go                     # Zero-trust broker HTTP server (async flow)
│   └── relay-operator/
│       └── main.go                     # Operator CLI: pull, verify HMAC, unwrap, seal, fulfill/reject
├── docs/
│   └── control-tower-spec.md           # Authoritative async flow spec
├── test.sh                             # Step-by-step CLI integration test
└── README.md
```

### Dependencies

- [`filippo.io/age`](https://pkg.go.dev/filippo.io/age) v1.3.1 — age types (`Recipient`, `Identity`, `Stanza`), recipient parsing
- [`filippo.io/age/plugin`](https://pkg.go.dev/filippo.io/age/plugin) — Plugin framework, Bech32 encoding helpers
- [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto) — X25519 and NaCl box for ephemeral response encryption
- [`gopkg.in/yaml.v3`](https://pkg.go.dev/gopkg.in/yaml.v3) — Config file parsing

## Testing

### Unit tests

```bash
go test -v ./relay/
```

| Test | What it validates |
|---|---|
| `TestComputeTagDeterministic` | Same input always produces same 16-byte tag |
| `TestComputeTagDifferent` | Different inputs produce different tags |
| `TestEncodeDecodeRecipient` | `age1relay1...` round-trips through Bech32 encode/decode |
| `TestEncodeDecodeIdentity` | `AGE-PLUGIN-RELAY-1...` round-trips with tag and target preserved |
| `TestWrapProducesRelayStanzas` | `Wrap()` produces stanzas with type `relay`, correct tag, inner type `X25519` |
| `TestEndToEndWithMockRelay` | Full flow: generate key pair, wrap via relay, mock HTTP server unwraps, file key matches |
| `TestUnwrapNoMatchingStanza` | Non-matching stanzas return `age.ErrIncorrectIdentity` |
| `TestEndToEndWithSSERelay` | Full wrap/unwrap flow over SSE (heartbeat + result event) |
| `TestSSERelayError` | Error event from SSE relay (wrong identity) |
| `TestEndToEndWithHMACRelay` | Full wrap/unwrap with HMAC-signed requests |
| `TestHMACRelayRejectsNoSignature` | Server rejects missing HMAC headers |
| `TestHMACRelayRejectsWrongKey` | Server rejects wrong HMAC key |
| `TestSignAndVerify` | HMAC sign + verify round-trip |
| `TestVerifyWrongKey` | HMAC rejects wrong key |
| `TestVerifyTamperedBody` | HMAC rejects tampered payload |
| `TestValidateTimestamp` | Timestamp within/outside 5m window |
| `TestNoncesAreUnique` | 100 nonces are all distinct |
| `TestEndToEndWithEnvelopeEncryption` | Full wrap/unwrap with HMAC + encrypted response |
| `TestEnvelopeRejectsSwappedEphemeralKey` | MITM swapping ephemeral key is rejected by HMAC |
| `TestSealOpenFileKey` | Envelope seal/open round-trip |
| `TestOpenWrongKey` | Envelope rejects wrong private key |
| `TestOpenTruncated` | Envelope rejects truncated sealed data |
| `TestSealDifferentEachTime` | Two seals of same file key produce different ciphertext |
| `TestEphemeralClear` | Private key is zeroed after Clear() |

### Broker queue tests

```bash
go test -v ./relay/broker/
```

| Test | What it validates |
|---|---|
| `TestSubmitAndPoll` | Submit intent, poll returns pending status |
| `TestSubmitDuplicateReturnsError` | Duplicate intent_id returns `duplicate_intent` error |
| `TestPollUnknownReturnsNil` | Polling nonexistent intent returns nil |
| `TestFulfillAndPoll` | Fulfill transitions intent to `fulfilled` with sealed key |
| `TestRejectAndPoll` | Reject transitions intent to `rejected` |
| `TestFulfillUnknownReturnsError` | Fulfilling unknown intent returns `unknown_intent` |
| `TestRejectUnknownReturnsError` | Rejecting unknown intent returns `unknown_intent` |
| `TestFulfillAlreadyFulfilledReturnsError` | Double-fulfill returns `intent_already_terminal` |
| `TestRejectAlreadyRejectedReturnsError` | Double-reject returns `intent_already_terminal` |
| `TestFulfillAfterRejectReturnsError` | Fulfill after reject returns error |
| `TestPullReturnsOnlyPendingForTag` | Pull filters by tag and returns only pending intents |
| `TestPullForwardsPluginHeaders` | Plugin HMAC headers forwarded verbatim through broker |
| `TestTTLExpiresIntents` | Intents expire after TTL, poll returns nil |
| `TestTTLExpiresPullResults` | Expired intents excluded from pull results |
| `TestFulfillAfterTTLReturnsUnknown` | Fulfilling expired intent returns `unknown_intent` |
| `TestRejectAfterTTLReturnsUnknown` | Rejecting expired intent returns `unknown_intent` |
| `TestSweepCleansExpiredIntents` | Background sweep removes expired intents, IDs freed for reuse |
| `TestMultipleTagsIsolation` | Different tags are fully isolated |

### Async (Control Tower) tests

```bash
go test -v ./relay/ -run TestAsync
```

| Test | What it validates |
|---|---|
| `TestAsyncEndToEnd` | Full flow: submit → pull → HMAC verify → unwrap → seal → fulfill → poll → decrypt |
| `TestAsyncRejectionFlow` | Operator rejection propagates to plugin poll |
| `TestAsyncDuplicateIntentReturns409` | Broker returns 409 on duplicate intent_id |
| `TestAsyncPollUnknownReturns404` | Polling nonexistent intent returns 404 |
| `TestAsyncFulfillAfterRejectReturns409` | Fulfill on already-terminal intent returns 409 |
| `TestAsyncPollAfterExpiry` | TTL expiry causes 404 on poll |
| `TestAsyncPluginPollingLoop` | Full `PostToRelay` async branch with background fulfill goroutine |
| `TestAsyncPluginPollingLoopRejected` | `PostToRelay` returns error on operator rejection |
| `TestAsyncBrokerDoesNotSeeFileKey` | Broker only stores sealed ciphertext, never plaintext file key |
| `TestAsyncHMACTamperDetection` | HMAC detects wrong key, tampered body, substituted ephemeral key |
| `TestPollIntervalDefault` | Default poll interval calculation: `min(timeout/60, 5s)` with 500ms floor |
| `TestGenerateIntentIDUniqueness` | 100 generated intent IDs are all unique |

### Integration tests

| Test | What it validates |
|---|---|
| `TestIntegrationLegacyURL` | Full `age.Encrypt` → `age.Decrypt` with URL in identity |
| `TestIntegrationConfigMode` | Full encrypt/decrypt with remote name resolved from config |
| `TestIntegrationConfigMissingRemote` | Clear error for non-existent remote (lists available) |
| `TestIntegrationNoConfigFile` | URL-based identities work without any config file |
| `TestIntegrationRelayServerDown` | Clean error when relay endpoint unreachable |
| `TestIntegrationWrongIdentity` | Clean error when relay has wrong key |

### E2E tests

| Test | What it validates |
|---|---|
| `TestE2ELegacyURL` | Full user flow with real `age` + `age-keygen` + plugin + relay-server binaries (URL mode) |
| `TestE2EConfigMode` | Same with config file: shorter identity, `--remote` flag, env var for config path |

### Integration test (CLI)

The integration test uses the `age` CLI binary, the plugin binary, and a minimal `relay-server` to test the full encrypt → relay → decrypt flow.

```bash
# Run all steps at once:
./test.sh

# Or step by step (artifacts in tmp/ for inspection):
./test.sh 1    # Generate remote X25519 key pair        → tmp/remote-identity.txt
./test.sh 2    # Generate relay recipient + identity     → tmp/relay-recipient.txt, tmp/relay-identity.txt
./test.sh 3    # Start relay-server on :19876            → tmp/relay-server.pid, tmp/relay-server.log
./test.sh 4    # Encrypt via relay recipient             → tmp/plaintext.txt, tmp/secret.age
./test.sh 5    # Decrypt via relay identity (HTTP POST)  → tmp/decrypted.txt
./test.sh 6    # Verify plaintext matches

# Clean up:
./test.sh clean
```

The `relay-server` (`cmd/relay-server/main.go`) is a minimal HTTP server that:
1. Loads an age identity file (X25519 private key)
2. Serves `POST /unwrap` — deserializes stanzas, calls `identity.Unwrap()`, returns the file key
3. Implements the same JSON contract the plugin expects

In production, the relay endpoint could be anything — an approval gateway, a WebSocket relay agent, a serverless function, etc.

## Authentication & Request Signing

Two optional, independent mechanisms protect the relay endpoint:

### Bearer Token (simple)

A shared token sent as `Authorization: Bearer <token>`. Quick to set up, no replay protection.

```yaml
# relay-config.yaml
remotes:
  myserver:
    url: https://relay.example:8443/unwrap
    auth_token: my-secret-token
```

Server: `relay-server -identity keys.txt -auth-token my-secret-token`

### HMAC-SHA256 Signing (recommended)

Each request is signed with HMAC-SHA256 over `timestamp.nonce.[ephemeral_key.]body`. Provides authentication **and** replay protection.

```yaml
# relay-config.yaml
remotes:
  myserver:
    url: https://relay.example:8443/unwrap
    hmac_key: my-shared-secret
```

Server: `relay-server -identity keys.txt -hmac-key my-shared-secret`

The client attaches three headers to every request:

| Header | Value |
|---|---|
| `X-Relay-Timestamp` | Unix timestamp (seconds) |
| `X-Relay-Nonce` | 16-byte random hex |
| `X-Relay-Signature` | `HMAC-SHA256(key, "{timestamp}.{nonce}.[{ephemeral_key}.]body")` hex |

When [encrypted response](#encrypted-response-ephemeral-x25519) is active, the client's ephemeral public key is included in the signed string (`timestamp.nonce.ephemeral_key.body`) to prevent key substitution attacks.

The server verifies the signature, rejects timestamps outside a 5-minute window, and rejects duplicate nonces.

Both mechanisms can be used together (Bearer is checked first, then HMAC).

### Encrypted Response (Ephemeral X25519)

When `encrypted_response: true` is set, the file key in the server's response is encrypted using an ephemeral X25519 key exchange. This provides **end-to-end payload encryption** independent of TLS — the file key is never plaintext on the wire, even if TLS is stripped, terminated by a proxy, or compromised.

**Requires `hmac_key`** — without HMAC signing, the ephemeral public key header cannot be authenticated, making it vulnerable to key substitution attacks.

```yaml
remotes:
  myserver:
    url: https://relay.example:8443/unwrap
    hmac_key: my-shared-secret
    encrypted_response: true
```

#### How it works

```
Client                              Network                Server
──────                              ───────                ──────
1. Generate ephemeral X25519 keypair
2. Sign(hmac_key, ts.nonce.eph_pub.body)
   ├─ X-Relay-Ephemeral-Key: <pub>  ────────►
   ├─ X-Relay-Signature: <hmac>     ────────►
   └─ body (already age-encrypted)  ────────►
                                                    3. Verify HMAC (incl. eph key)
                                                    4. Unwrap stanzas → file key
                                                    5. Generate server ephemeral keypair
                                                    6. NaCl box.Seal(file_key, client_pub)
                                        ◄────────  {"encrypted_file_key": "..."}
7. NaCl box.Open(sealed, server_pub, client_priv)
8. Discard ephemeral keypair
```

#### Wire format

The `encrypted_file_key` field contains base64-encoded:

```
serverPub (32 bytes) || nonce (24 bytes) || NaCl box ciphertext (16 + 16 bytes)
```

Total: 88 bytes raw, ~118 bytes base64.

| Component | Size | Description |
|---|---|---|
| Server public key | 32 bytes | One-time X25519 public key generated per response |
| Nonce | 24 bytes | Random XSalsa20-Poly1305 nonce |
| Ciphertext | 32 bytes | 16-byte file key + 16-byte Poly1305 tag |

#### Security properties

- **Transport-independent** — file key is encrypted end-to-end even over plaintext HTTP
- **Forward secrecy** — both client and server ephemeral keys are unique per request and discarded after use
- **Key substitution protection** — ephemeral public key is included in the HMAC signature; swapping it invalidates the signature
- **No pre-shared encryption key** — uses X25519 key agreement (NaCl box = X25519 + XSalsa20-Poly1305)
- **Works with SSE** — streaming responses also use `encrypted_file_key` when the ephemeral key header is present

#### Cryptographic construction

Uses Go's `golang.org/x/crypto/nacl/box` (NaCl `crypto_box`):

1. **Client** calls `box.GenerateKey()` → ephemeral X25519 keypair
2. **Server** calls `box.GenerateKey()` → one-time server keypair, then `box.Seal(fileKey, nonce, clientPub, serverPriv)`
3. **Client** calls `box.Open(ciphertext, nonce, serverPub, clientPriv)`

The server's one-time keypair ensures the sealed box is unique even for identical file keys (defense against deterministic ciphertext analysis).

## Control Tower (Async Flow)

When the relay endpoint cannot answer synchronously (e.g., the operator identity is offline, or approval is required), the protocol supports an async brokered flow. The plugin learns which mode it got from the HTTP response code: `200` = sync result, `202 Accepted` = async.

See [`docs/control-tower-spec.md`](docs/control-tower-spec.md) for the full specification.

### Actors

| Actor | Role | Holds |
|---|---|---|
| **Plugin** | Submits unwrap intents, polls for results | `hmac_key` (shared with operator), broker `auth_token` |
| **Broker** | Stateful queue and forwarder; **zero-trust** | broker `auth_token` only |
| **Operator** | Polls for pending intents, unwraps locally, fulfills or rejects | age private key, `hmac_key` (shared with plugin), broker `auth_token` |

The broker holds no `hmac_key`, no age identity, and no view into the cryptographic content.

### Flow

```
Plugin                       Broker                      Operator
──────                       ──────                      ────────
1. unwrap (HMAC-signed)  ──►  Queue intent (202)
                                                    ◄──  2. pull by tag
                              Return pending intents ──►
                                                         3. Verify plugin HMAC E2E
                                                         4. Unwrap stanzas locally
                                                         5. Seal file key → NaCl box
                                                    ◄──  6. fulfill (sealed key)
7. poll intent_id        ──►
   ◄── fulfilled + encrypted_file_key
8. Open NaCl box with ephemeral private key → file key
```

### Actions

| Action | Sender | Description |
|---|---|---|
| `unwrap` | Plugin | Submit stanzas + intent_id; returns `200` (sync) or `202` (async) |
| `poll` | Plugin | Check intent status: `pending`, `fulfilled`, `rejected`, or `404` |
| `pull` | Operator | Get all pending intents for a tag |
| `fulfill` | Operator | Submit sealed file key for an intent |
| `reject` | Operator | Decline an intent |

### Async config

```yaml
# relay-config.yaml (plugin)
remotes:
  approved-server:
    url: https://broker.example:8443/unwrap
    auth_token: broker-bearer-token
    hmac_key: shared-with-operator-only
    encrypted_response: true
    timeout: 10m
    poll_interval: 2s          # optional; default min(timeout/60, 5s)
```

### Relay Broker

The broker is a zero-trust stateful queue:

```bash
relay-broker -addr :8443 -auth-token my-token -max-ttl 10m
```

| Flag | Description |
|---|---|
| `-addr` | Listen address (default `:8443`) |
| `-auth-token` | Required Bearer token |
| `-max-ttl` | Intent TTL before silent deletion (default `5m`) |

### Relay Operator

The operator polls the broker, verifies plugin HMAC end-to-end, unwraps stanzas, and fulfills:

```bash
relay-operator \
  --broker https://broker.example:8443 \
  --identity keys.txt \
  --tag QPg24g \
  --hmac-key shared-with-plugin \
  --auth-token broker-bearer-token \
  --pull-interval 5s
```

| Flag | Env | Description |
|---|---|---|
| `--broker` | — | Broker URL (required) |
| `--identity` | — | Age identity file (required) |
| `--tag` | — | Routing tag to pull (required) |
| `--hmac-key` | — | Shared HMAC key with plugin (required) |
| `--auth-token` | `RELAY_BROKER_AUTH_TOKEN` | Broker Bearer token |
| `--pull-interval` | — | Polling interval (default `5s`) |

## Relay Server

The included `relay-server` supports TLS, mTLS, Bearer auth, and HMAC verification:

```bash
# Minimal (plaintext HTTP — testing only)
relay-server -identity keys.txt

# TLS
relay-server -identity keys.txt \
  -tls-cert server.crt -tls-key server.key

# mTLS (require client certificates)
relay-server -identity keys.txt \
  -tls-cert server.crt -tls-key server.key -tls-ca ca.crt

# With HMAC signing
relay-server -identity keys.txt \
  -tls-cert server.crt -tls-key server.key \
  -hmac-key my-shared-secret
```

Flags and environment variables:

| Flag | Env | Description |
|---|---|---|
| `-identity <file>` | — | Age identity file (required) |
| `-addr <addr>` | — | Listen address (default `:9876`) |
| `-tls-cert <file>` | — | TLS server certificate (enables HTTPS) |
| `-tls-key <file>` | — | TLS server private key |
| `-tls-ca <file>` | — | CA cert for client verification (enables mTLS) |
| `-auth-token <token>` | `RELAY_AUTH_TOKEN` | Required Bearer token |
| `-hmac-key <key>` | `RELAY_HMAC_KEY` | HMAC-SHA256 shared key |

## Security Properties

- **Encryption is offline** — uses only the inner recipient's public key. No network, no relay, no hardware.
- **No secrets in the plugin** — the recipient contains only a public key string; the identity contains only a tag and URL.
- **File key (16 bytes) travels over HTTPS** — use TLS/mTLS for transport security.
- **HMAC request signing** — prevents replay attacks and authenticates requests (optional, recommended).
- **Encrypted responses** — ephemeral X25519 encrypts the file key end-to-end, independent of TLS (optional, requires HMAC).
- **With SOPS key groups + Shamir** — intercepting one group's unwrapped share is information-theoretically useless without the other share(s).
- **Relay endpoint is the trust boundary** — it holds the actual private key or identity. The plugin itself holds no key material.

## Threat Model

| Scenario | Impact |
|---|---|
| Plugin binary compromised | Attacker could redirect relay URL, but still needs the remote identity to unwrap |
| Relay URL intercepted (no TLS) | Attacker sees encrypted stanzas (useless without identity) and file key (one Shamir share if using key groups). With `encrypted_response`, file key is also encrypted. |
| TLS-terminating proxy in path | File key visible between proxy and backend. With `encrypted_response`, file key remains encrypted end-to-end. |
| mTLS cert stolen | Attacker can talk to relay, but relay still requires the actual identity to unwrap |
| HMAC key compromised | Attacker can forge requests and replay. Does NOT compromise `encrypted_response` — ephemeral X25519 key agreement is independent of the HMAC key. |
| Relay endpoint compromised | Attacker gets file keys — mitigated by using SOPS key groups (need both shares) |
| Both relay + server compromised | Need physical access to all identity holders (geographic separation with YubiKeys) |
| Broker compromised (async) | Broker holds no `hmac_key` or age identity. Cannot forge plugin requests or decrypt stanzas. Can DoS (drop intents), detected by plugin timeout. |
| Ephemeral key substitution (async) | Prevented: ephemeral public key is bound in the HMAC signature. Operator re-verifies HMAC end-to-end on pull. |
| Fabricated intent (async) | Broker or auth_token holder can submit payloads, but without `hmac_key` the operator rejects on HMAC verification. |
