# age-plugin-relay

An [age](https://age-encryption.org) plugin that decouples the **location** of age identities from the encryption/decryption process. It acts as a router — any age identity (X25519, YubiKey, hybrid PQ, or other plugins) can be used remotely through an HTTP relay endpoint.

All payloads are encrypted end-to-end. The broker/relay sees only opaque ciphertext and routing metadata.

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
  Re-tag stanza: X25519 -> relay                Resolve target (remote name from config)
    |                                             |
    v                                             v
  Done. No network. Identity-agnostic.          Build encrypted payload → HTTP POST → decrypt response
```

**Encryption** uses only the inner recipient's public key — no relay, no network, no hardware. The plugin delegates to `age.ParseRecipients()`, so it works with any recipient type the `age` library (or plugins in `PATH`) can parse.

**Decryption** builds an encrypted inner payload (age-encrypted to the operator's recipient), sends it to the relay endpoint, and decrypts the age-encrypted response. The relay/broker never sees plaintext stanzas or file keys.

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

```bash
age-plugin-relay --generate \
  --inner-recipient "age1abc..." \
  --remote myserver
```

Config mode produces short identity strings and supports per-remote TLS, timeout, and `unwrap_recipient`. See [Config File](#config-file) below.

Output:

```
# Relay recipient (for encryption — add to .sops.yaml or age -r):
#   Inner: age1abc...
age1relay1q...

# Relay identity (for decryption — add to identity file):
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

The plugin builds an encrypted payload containing the stanzas and an ephemeral key, sends it to the relay endpoint, and decrypts the sealed response to recover the file key.

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

The target is a remote name resolved from `relay-config.yaml`.

| Field | Size | Description |
|---|---|---|
| `tag` | 16 bytes | `SHA-256(inner_recipient_string)[:16]` — matches stanzas to this identity |
| `target` | variable | Remote name (`myserver`) |

Not secret. Contains no key material — only routing information. Safe to commit to version control.

At decrypt time, the plugin looks up the target in `relay-config.yaml` to get the URL, `unwrap_recipient`, and other settings.

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

On decryption the plugin strips `relay` and the tag, reconstructs the original inner stanza, and forwards it (inside an encrypted payload) to the relay endpoint.

## Relay Endpoint HTTP Contract

The plugin POSTs to the relay URL during decryption. All payloads are encrypted end-to-end — the relay/broker only sees opaque ciphertext and routing metadata.

### Request (outer envelope)

```http
POST / HTTP/1.1
Content-Type: application/json

{
  "version": 1,
  "action": "unwrap",
  "intent_id": "a3f12c4e8b9d6f0a1b2c3d4e5f6a7b8c",
  "tag": "QPg24g",
  "expires_at": 1715350800,
  "stream": true,
  "encrypted_payload": "<base64: age-encrypted blob>"
}
```

- `version`: Protocol version (currently `1`).
- `action`: The operation to perform. Defined actions: `"unwrap"`, `"poll"`, `"pull"`, `"fulfill"`, `"reject"`. See [Control Tower (Async Flow)](#control-tower-async-flow) for the async actions.
- `intent_id`: Plugin-generated unique ID (16 random bytes, hex-encoded).
- `tag`: Routing tag derived from the inner recipient (`SHA-256(recipient)[:4]`, base64).
- `expires_at`: Unix timestamp (seconds) — intent expiry.
- `stream`: Optional. If `true`, the client accepts SSE responses. See [Streaming (SSE)](#streaming-sse).
- `encrypted_payload`: age-encrypted inner payload containing stanzas, ephemeral key, outer hash, and nonce. Opaque to the broker.

### Inner request payload (age-encrypted to operator's recipient)

```json
{
  "nonce": "<16 random bytes, hex>",
  "outer_hash": "<SHA-256(version.action.intent_id.tag.expires_at), hex>",
  "expires_at": 1715350800,
  "stanzas": [
    { "type": "X25519", "args": ["..."], "body": "..." }
  ],
  "ephemeral_key": "<age1... ephemeral recipient string>"
}
```

The `outer_hash` binds the encrypted payload to the cleartext routing fields. The operator recomputes it from the outer fields and rejects on mismatch (tamper detection).

### Response

**Success (200):**

```json
{
  "encrypted_payload": "<base64: age-encrypted inner response>"
}
```

The `encrypted_payload` contains an age-encrypted blob sealed to the plugin's ephemeral recipient. The inner response is:

```json
{
  "nonce": "<16 random bytes, hex>",
  "outer_hash": "<SHA-256(intent_id), hex>",
  "file_key": "<base64: 16-byte age file key>"
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

- `application/json` → standard JSON
- `text/event-stream` → SSE stream

Servers that don't support SSE simply ignore the `stream` field and return JSON.

#### SSE events

| Event | Data | Meaning |
|---|---|---|
| `result` | `{"encrypted_payload": "..."}` | Unwrap succeeded — stream ends |
| `error` | `{"error": "..."}` | Unwrap failed — stream ends |
| `: comment` | (none) | Heartbeat — keeps connection alive |

Example SSE response:

```
: heartbeat

event: result
data: {"encrypted_payload": "<age-encrypted blob>"}

```

Unknown event types are silently ignored for forward compatibility.

## Config File

Config mode is required for encrypted payload support. Create a `relay-config.yaml`:

```yaml
# relay-config.yaml
remotes:
  myserver:
    url: https://relay.example:8443/unwrap         # required
    unwrap_recipient: age1abc...                    # required: age recipient of the unwrapper
    tls_cert: /path/to/client.crt                  # optional (mTLS)
    tls_key: /path/to/client.key                   # optional (mTLS)
    tls_ca: /path/to/ca.crt                        # optional (custom CA)
    timeout: 5m                                    # optional (default: 5m)
    stream: true                                   # optional (SSE for long-running requests)
    auth_token: my-bearer-token                    # optional (Bearer token for simple auth)

  backup:
    url: https://backup.example:9999/unwrap
    unwrap_recipient: age1def...
```

The plugin looks for the config file at:
1. `AGE_PLUGIN_RELAY_CONFIG` env var (if set)
2. `$PWD/relay-config.yaml`

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
│   ├── payload.go                      # Encrypted payload: EncryptPayload, DecryptPayload, OuterHash, inner types
│   ├── envelope.go                     # Age response encryption: SealResponse, OpenResponse
│   ├── broker/                         # Broker queue package (package broker)
│   │   ├── types.go                    # Intent, Status, PullResponse, PollResponse
│   │   ├── queue.go                    # In-memory intent queue with TTL sweep
│   │   └── queue_test.go              # Broker queue unit tests
│   ├── helpers_test.go                # Shared test helpers (mock relay server)
│   ├── encoding_test.go               # Encoding unit tests (ComputeTag, Bech32 encode/decode)
│   ├── identity_test.go               # Identity/Unwrap tests (sync, SSE, errors, concurrency)
│   ├── client_test.go                 # Client tests (PostToRelay, extractFileKey, sanitizeErrorMsg, auth, SSE, async)
│   ├── config_test.go                 # Config tests (LoadConfig, LookupRemote, timeout, poll interval)
│   ├── payload_test.go                # Encrypted payload tests (outer hash, encrypt/decrypt, verify, tamper detection)
│   ├── envelope_test.go               # Envelope seal/open unit tests (age encryption)
│   ├── async_test.go                  # Async (Control Tower) tests (broker protocol, E2E)
│   ├── integration_test.go            # Integration tests (age.Encrypt/Decrypt E2E, broker blindness, tampering)
│   └── e2e_test.go                    # E2E tests (real binaries, full user flow)
├── cmd/
│   ├── age-plugin-relay/
│   │   └── main.go                     # Plugin binary: flags, --generate, HandleRecipient/Identity
│   ├── relay-server/
│   │   └── main.go                     # Sync relay server: decrypt, verify, unwrap, seal
│   ├── relay-broker/
│   │   └── main.go                     # Zero-trust broker: stores/forwards opaque encrypted payloads
│   └── relay-operator/
│       └── main.go                     # Operator CLI: pull, decrypt, verify, unwrap, seal, fulfill/reject
├── docs/
│   ├── control-tower-spec.md           # Async flow spec
│   └── encrypted-payload-spec.md       # Encrypted payload spec (authoritative)
├── test.sh                             # Step-by-step CLI integration test
└── README.md
```

### Dependencies

- [`filippo.io/age`](https://pkg.go.dev/filippo.io/age) v1.3.1 — age types (`Recipient`, `Identity`, `Stanza`), recipient parsing, encryption/decryption
- [`filippo.io/age/plugin`](https://pkg.go.dev/filippo.io/age/plugin) — Plugin framework, Bech32 encoding helpers
- [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto) — Cryptographic primitives
- [`gopkg.in/yaml.v3`](https://pkg.go.dev/gopkg.in/yaml.v3) — Config file parsing

## Testing

### Unit tests

```bash
go test -v ./relay/
```

#### Encoding tests (`encoding_test.go`)

| Test | What it validates |
|---|---|
| `TestComputeTagDeterministic` | Same input always produces same 16-byte tag |
| `TestComputeTagDifferent` | Different inputs produce different tags |
| `TestEncodeDecodeRecipient` | `age1relay1...` round-trips through Bech32 encode/decode |
| `TestEncodeDecodeIdentity` | `AGE-PLUGIN-RELAY-1...` round-trips with tag and target preserved |
| `TestWrapProducesRelayStanzas` | `Wrap()` produces stanzas with type `relay`, correct tag, inner type `X25519` |

#### Identity tests (`identity_test.go`)

| Test | What it validates |
|---|---|
| `TestEndToEndWithMockRelay` | Full flow: wrap, encrypted payload to mock server, server decrypts/verifies/unwraps/seals, file key matches |
| `TestEndToEndWithSSERelay` | Full wrap/unwrap flow over SSE with encrypted payload |
| `TestSSERelayError` | Error event from SSE relay (wrong identity) |
| `TestUnwrapNoMatchingStanza` | Non-matching stanzas return `age.ErrIncorrectIdentity` |
| `TestUnwrapMissingUnwrapRecipient` | Clear error when `unwrap_recipient` is not set |
| `TestResolveRemoteHTTPWarning` | HTTP URL resolves with warning |
| `TestResolveRemoteHTTPS` | HTTPS URL resolves directly |
| `TestResolveRemoteNamedNotFound` | Named remote without config returns error |
| `TestConcurrentUnwrapRequests` | 10 concurrent unwrap requests all succeed |

#### Client tests (`client_test.go`)

| Test | What it validates |
|---|---|
| `TestGenerateIntentIDFormat` | Intent ID is 32 lowercase hex chars |
| `TestGenerateIntentIDUniqueness` | 100 generated intent IDs are all unique |
| `TestSanitizeErrorMsgShort` | Short messages pass through unchanged |
| `TestSanitizeErrorMsgTruncation` | Messages > 256 chars truncated with `...` |
| `TestSanitizeErrorMsgControlChars` | Control chars stripped, tabs/newlines preserved |
| `TestSanitizeErrorMsgEmpty` | Empty string returns empty |
| `TestExtractFileKeyEmpty` | Empty response returns error |
| `TestExtractFileKeyBadBase64` | Invalid base64 returns error |
| `TestExtractFileKeyWrongKey` | Wrong ephemeral key returns error |
| `TestExtractFileKeyWrongIntentID` | Wrong intent_id detected via outer_hash mismatch |
| `TestFileKeyRecoveryVariousSizes` | Round-trip with 0, 1, 15, 16, 32, 64-byte file keys |
| `TestPostToRelay5xxError` | Server 500 returns error |
| `TestPostToRelayServerReturnsErrorInJSON` | Server 200 with error JSON returns error |
| `TestSSEHeartbeatOnly` | Heartbeat-only stream (no result) returns error |
| `TestSSEErrorEvent` | SSE error event propagates error message |
| `TestAuthTokenSentAsBearer` | Auth token sent as `Authorization: Bearer` header |
| `TestNoAuthTokenOmitsHeader` | No auth token omits header entirely |
| `TestWireFormatRequestFields` | Request has version, action, intent_id, tag, expires_at, encrypted_payload; no outer stanzas |
| `TestEncryptedPayloadAsyncE2E` | Full async flow: submit → 202 → poll → operator fulfills → plugin recovers file key |

#### Config tests (`config_test.go`)

| Test | What it validates |
|---|---|
| `TestLoadConfigInvalidYAML` | Invalid YAML returns parse error |
| `TestLoadConfigMissing` | Missing config file returns nil (not error) |
| `TestLookupRemoteEmptyURL` | Remote with empty URL returns error |
| `TestLookupRemoteNilConfig` | Nil config returns error |
| `TestLookupRemoteNotFound` | Missing remote name returns error with available list |
| `TestTimeoutDurationDefault` | Default timeout is 5 minutes |
| `TestTimeoutDurationInvalid` | Invalid duration falls back to 5 minutes |
| `TestTimeoutDurationCustom` | Custom duration `30s` parsed correctly |
| `TestPollIntervalDefault` | Default: `min(timeout/60, 5s)` with 500ms floor; explicit override works |

#### Payload encryption tests (`payload_test.go`)

| Test | What it validates |
|---|---|
| `TestOuterHashRequestDeterminism` | Same inputs produce same hash (known-answer test) |
| `TestOuterHashResponseDeterminism` | Same intent_id produces same hash (known-answer test) |
| `TestOuterHashRequestDifferentFields` | Different fields produce different hashes |
| `TestEncryptDecryptPayloadRoundTrip` | Encrypt → decrypt round-trip preserves inner payload |
| `TestDecryptPayloadWrongIdentityFails` | Decryption with wrong identity fails |
| `TestVerifyRequestPayloadValid` | Valid outer hash passes verification |
| `TestVerifyRequestPayloadTamperedHash` | Tampered outer fields detected |
| `TestVerifyRequestPayloadExpired` | Expired `expires_at` rejected |
| `TestVerifyResponsePayloadValid` | Valid response hash passes |
| `TestVerifyResponsePayloadTamperedHash` | Tampered response hash detected |
| `TestBuildRequestPayload` | Request payload has correct fields, 32-char hex nonce |
| `TestBuildResponsePayload` | Response payload has correct fields, base64-encoded file key |
| `TestNonceUniqueness` | Two encryptions of same payload produce different ciphertext |
| `TestEncryptDecryptFullFlow` | End-to-end: build → encrypt → decrypt → verify |
| `TestResponsePayloadFullFlow` | Build response → verify → decode file key |
| `TestParseRecipientStringValid` | Valid X25519 recipient parses successfully |
| `TestParseRecipientStringUnsupported` | Non-age recipient returns unsupported error |
| `TestParseRecipientStringInvalid` | Invalid age1 string returns parse error |
| `TestOuterHashTamperDetectionTag` | Encrypt → decrypt → verify with tampered tag fails |
| `TestOuterHashTamperDetectionIntentID` | Encrypt → decrypt → verify with tampered intent_id fails |
| `TestExpiresAtEnforcement` | Encrypt → decrypt → verify with expired timestamp fails |

#### Envelope tests (`envelope_test.go`)

| Test | What it validates |
|---|---|
| `TestSealOpenResponse` | Age seal/open round-trip with structured inner response |
| `TestOpenResponseWrongKey` | Envelope rejects wrong ephemeral identity |
| `TestOpenResponseTruncated` | Envelope rejects truncated sealed data |
| `TestOpenResponseBadBase64` | Invalid base64 returns error |
| `TestOpenResponseTamperedCiphertext` | Flipped byte in ciphertext detected |
| `TestSealResponseDifferentEachTime` | Two seals produce different ciphertext |
| `TestEphemeralClear` | Identity and recipient are nil after `Clear()` |
| `TestEphemeralKeypairsAreUnique` | 50 generated keypairs are all unique |
| `TestSealOpenResponseVariousSizes` | Round-trip with 0, 1, 15, 16, 32, 64-byte file keys |

### Broker queue tests

```bash
go test -v ./relay/broker/
```

| Test | What it validates |
|---|---|
| `TestSubmitAndPoll` | Submit intent, poll returns pending status |
| `TestSubmitDuplicateReturnsError` | Duplicate intent_id returns `duplicate_intent` error |
| `TestPollUnknownReturnsNil` | Polling nonexistent intent returns nil |
| `TestFulfillAndPoll` | Fulfill transitions intent to `fulfilled` with encrypted payload |
| `TestRejectAndPoll` | Reject transitions intent to `rejected` |
| `TestFulfillUnknownReturnsError` | Fulfilling unknown intent returns `unknown_intent` |
| `TestRejectUnknownReturnsError` | Rejecting unknown intent returns `unknown_intent` |
| `TestFulfillAlreadyFulfilledReturnsError` | Double-fulfill returns `intent_already_terminal` |
| `TestRejectAlreadyRejectedReturnsError` | Double-reject returns `intent_already_terminal` |
| `TestFulfillAfterRejectReturnsError` | Fulfill after reject returns error |
| `TestPullReturnsOnlyPendingForTag` | Pull filters by tag and returns only pending intents |
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
| `TestAsyncEndToEnd` | Full flow: submit encrypted → pull → decrypt → verify → unwrap → seal → fulfill → poll → decrypt response |
| `TestAsyncRejectionFlow` | Operator rejection propagates to plugin poll |
| `TestAsyncDuplicateIntentReturns409` | Broker returns 409 on duplicate intent_id |
| `TestAsyncPollUnknownReturns404` | Polling nonexistent intent returns 404 |
| `TestAsyncFulfillAfterRejectReturns409` | Fulfill on already-terminal intent returns 409 |
| `TestAsyncPollAfterExpiry` | TTL expiry causes 404 on poll |
| `TestAsyncPluginPollingLoop` | Full `PostToRelay` async branch with background operator fulfill |
| `TestAsyncPluginPollingLoopRejected` | `PostToRelay` returns error on operator rejection |
| `TestAsyncBrokerDoesNotSeeFileKey` | Broker only stores opaque encrypted payloads, never plaintext stanzas or file keys |
| `TestAsyncOuterHashTamperDetection` | Outer hash detects tampered intent_id, tag, and expires_at |

### Integration tests

| Test | What it validates |
|---|---|
| `TestIntegrationConfigMode` | Full encrypt/decrypt with remote name resolved from config |
| `TestIntegrationConfigMissingRemote` | Clear error for non-existent remote (lists available) |
| `TestIntegrationNoConfigFile` | URL-based identities work without config file |
| `TestIntegrationRelayServerDown` | Clean error when relay endpoint unreachable |
| `TestIntegrationWrongIdentity` | Clean error when relay has wrong key |
| `TestIntegrationEncryptedPayloadE2E` | Full encrypted payload end-to-end with mock server |
| `TestIntegrationMissingUnwrapRecipient` | Clear error when `unwrap_recipient` is not configured |
| `TestEncryptedPayloadSyncE2E` | Full `age.Encrypt` → `age.Decrypt` with encrypted payloads (JSON) |
| `TestEncryptedPayloadSyncE2EWithSSE` | Full `age.Encrypt` → `age.Decrypt` with encrypted payloads (SSE) |
| `TestBrokerBlindnessVerification` | Broker cannot parse or decrypt encrypted payloads; wrong identity fails |
| `TestResponseOuterHashTamperingE2E` | Server returning wrong intent_id in response detected via outer_hash |

### E2E tests

| Test | What it validates |
|---|---|
| `TestE2EConfigMode` | Full user flow with real `age` + `age-keygen` + plugin + relay-server binaries (config mode) |
| `TestE2ESSEStream` | Same with SSE streaming enabled |

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

## Authentication

### Bearer Token

A shared token sent as `Authorization: Bearer <token>`. Quick to set up.

```yaml
# relay-config.yaml
remotes:
  myserver:
    url: https://relay.example:8443/unwrap
    unwrap_recipient: age1abc...
    auth_token: my-secret-token
```

Server: `relay-server -identity keys.txt -auth-token my-secret-token`

## Encrypted Payload (End-to-End Confidentiality)

All requests and responses use mandatory encrypted payloads. There are no configuration flags — encrypted is the only mode.

### Request path (plugin → operator)

1. Plugin generates an ephemeral X25519 keypair
2. Plugin builds an inner payload: `{nonce, outer_hash, expires_at, stanzas, ephemeral_key}`
3. Plugin `age.Encrypt`s the inner payload to the operator's `unwrap_recipient`
4. Plugin sends the outer envelope with `encrypted_payload` (opaque to broker)

### Response path (operator → plugin)

1. Operator decrypts the inner payload with their age identity
2. Operator verifies `outer_hash` (tamper detection) and `expires_at`
3. Operator unwraps stanzas → file key
4. Operator builds inner response: `{nonce, outer_hash, file_key}`
5. Operator age-encrypts the response to the plugin's ephemeral recipient

### Wire format

The `encrypted_payload` in the response contains base64-encoded age ciphertext (same format as the request direction).

### Security properties

- **Broker blindness** — broker sees only `version`, `action`, `intent_id`, `tag`, and opaque ciphertext. Stanzas, ephemeral keys, and file keys are never visible.
- **Tamper detection** — `outer_hash` inside the encrypted payload binds it to the cleartext routing fields. Broker cannot modify any outer field without detection.
- **Forward secrecy** — ephemeral age keypairs per intent, discarded after use.
- **Transport-independent** — encrypted end-to-end even over plaintext HTTP.

See [`docs/encrypted-payload-spec.md`](docs/encrypted-payload-spec.md) for the full specification.

## Control Tower (Async Flow)

When the relay endpoint cannot answer synchronously (e.g., the operator identity is offline, or approval is required), the protocol supports an async brokered flow. The plugin learns which mode it got from the HTTP response code: `200` = sync result, `202 Accepted` = async.

See [`docs/control-tower-spec.md`](docs/control-tower-spec.md) for the full specification.

### Actors

| Actor | Role | Holds |
|---|---|---|
| **Plugin** | Submits encrypted unwrap intents, polls for results | `unwrap_recipient` (for age encryption), broker `auth_token` |
| **Broker** | Stateful queue and forwarder; **zero-trust** | broker `auth_token` only |
| **Operator** | Polls for pending intents, decrypts, unwraps locally, seals response, fulfills or rejects | age private key, broker `auth_token` |

The broker holds no age identity, no key material, and no view into the cryptographic content.

### Flow

```
Plugin                       Broker                      Operator
──────                       ──────                      ────────
1. Build encrypted payload
   age.Encrypt(inner,
   unwrap_recipient)     ──►  Queue intent (202)
                                                    ◄──  2. pull by tag
                              Return pending intents ──►
                                                         3. age.Decrypt(encrypted_payload)
                                                         4. Verify outer_hash + expires_at
                                                         5. Unwrap stanzas locally
                                                         6. Build + seal response → age.Encrypt
                                                    ◄──  7. fulfill (encrypted_payload)
8. poll intent_id        ──►
   ◄── fulfilled + encrypted_payload
9. age.Decrypt with ephemeral identity
10. Verify response outer_hash → file key
```

### Actions

| Action | Sender | Description |
|---|---|---|
| `unwrap` | Plugin | Submit encrypted payload + intent_id; returns `200` (sync) or `202` (async) |
| `poll` | Plugin | Check intent status: `pending`, `fulfilled`, `rejected`, or `404` |
| `pull` | Operator | Get all pending intents for a tag |
| `fulfill` | Operator | Submit sealed response for an intent |
| `reject` | Operator | Decline an intent |

### Async config

```yaml
# relay-config.yaml (plugin)
remotes:
  approved-server:
    url: https://broker.example:8443
    unwrap_recipient: age1abc...
    auth_token: broker-bearer-token
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

The operator polls the broker, decrypts encrypted payloads, unwraps stanzas, and fulfills:

```bash
relay-operator \
  --broker https://broker.example:8443 \
  --identity keys.txt \
  --tag QPg24g \
  --auth-token broker-bearer-token \
  --pull-interval 5s
```

| Flag | Env | Description |
|---|---|---|
| `--broker` | — | Broker URL (required) |
| `--identity` | — | Age identity file (required) |
| `--tag` | — | Routing tag to pull (required) |
| `--auth-token` | `RELAY_BROKER_AUTH_TOKEN` | Broker Bearer token |
| `--pull-interval` | — | Polling interval (default `5s`) |

## Relay Server

The included `relay-server` supports TLS, mTLS, and Bearer auth:

```bash
# Minimal (plaintext HTTP — testing only)
relay-server -identity keys.txt

# TLS
relay-server -identity keys.txt \
  -tls-cert server.crt -tls-key server.key

# mTLS (require client certificates)
relay-server -identity keys.txt \
  -tls-cert server.crt -tls-key server.key -tls-ca ca.crt

# With auth token
relay-server -identity keys.txt \
  -tls-cert server.crt -tls-key server.key \
  -auth-token my-secret-token
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

## Security Properties

- **Encryption is offline** — uses only the inner recipient's public key. No network, no relay, no hardware.
- **No secrets in the plugin** — the recipient contains only a public key string; the identity contains only a tag and remote name.
- **End-to-end encrypted payloads** — stanzas and file keys are never visible to the broker or any intermediary.
- **Tamper detection** — SHA-256 outer hash binds encrypted payloads to cleartext routing fields.
- **Forward secrecy** — ephemeral keypairs per intent, discarded after use.
- **With SOPS key groups + Shamir** — intercepting one group's unwrapped share is information-theoretically useless without the other share(s).
- **Relay endpoint is the trust boundary** — it holds the actual private key or identity. The plugin itself holds no key material.

## Threat Model

| Scenario | Impact |
|---|---|
| Plugin binary compromised | Attacker could redirect relay URL, but still needs the remote identity to unwrap |
| Relay URL intercepted (no TLS) | Attacker sees only opaque encrypted payloads (useless without identity). |
| TLS-terminating proxy in path | Payloads remain encrypted end-to-end — proxy sees only ciphertext. |
| mTLS cert stolen | Attacker can talk to relay, but relay still requires the actual identity to unwrap |
| Relay endpoint compromised | Attacker gets file keys — mitigated by using SOPS key groups (need both shares) |
| Both relay + server compromised | Need physical access to all identity holders (geographic separation with YubiKeys) |
| Broker compromised (async) | Broker holds no age identity. Cannot decrypt payloads or forge responses. Can DoS (drop intents), detected by plugin timeout. |
| Outer field tampering (broker) | Detected by outer_hash mismatch inside the encrypted payload. Operator/plugin rejects. |
| Fabricated intent (async) | Without the operator's age recipient, cannot create a valid encrypted_payload. Operator's age.Decrypt fails. |
