# Encrypted Payload — End-to-End Confidentiality Specification

Authoritative design for mandatory payload encryption in `age-plugin-relay`. This replaces all cleartext wire formats. The broker becomes a blind forwarder of opaque blobs in both directions.

---

## 1. Goals

- **Confidentiality**: the broker cannot read stanzas, ephemeral keys, or file keys.
- **Integrity**: the broker cannot tamper with any outer field without detection.
- **Simplicity**: no configuration flags — encrypted is the only mode.
- **Symmetry**: both request path (plugin → operator) and response path (operator → plugin) use the same `encrypted_payload` pattern.
- **Sync/async compatibility**: the same wire format works for both `relay-server` (sync) and `relay-broker` + `relay-operator` (async).

---

## 2. What this replaces

| Removed | Reason |
|---|---|
| `encrypted_response` config flag | Always encrypted — no flag |
| `encrypted_payload` config flag | Always encrypted — no flag |
| `file_key` response field | Only `encrypted_payload` exists |
| `encrypted_file_key` response field | Renamed to `encrypted_payload` |
| Cleartext `stanzas` in request body | Moved inside encrypted inner payload |
| `X-Relay-Ephemeral-Key` HTTP header | Ephemeral key moves inside encrypted payload |
| `EnvelopeHeader` constant | No longer needed |
| Plaintext response handling in client | Dead code |
| Conditional ephemeral key generation | Always generated |
| HMAC request signing (`hmac_key`) | Incompatible; out of scope (future work) |

---

## 3. Outer envelope — broker-visible fields

Every request to the broker/relay-server has at most these cleartext fields:

| Field | Present in | Purpose |
|---|---|---|
| `version` | all | Protocol version |
| `action` | all | Routing: `unwrap`, `poll`, `pull`, `fulfill`, `reject` |
| `intent_id` | unwrap, poll, fulfill, reject | Intent state machine |
| `tag` | unwrap, pull | Operator routing |
| `stream` | unwrap | Transport hint (SSE) |
| `expires_at` | unwrap | Unix timestamp (seconds). Plugin-defined intent expiry. |
| `encrypted_payload` | unwrap, fulfill | Opaque blob — broker stores and forwards |

No stanzas, no ephemeral keys, no file keys at the outer level.

---

## 4. Request path — plugin to operator

### 4.0. Unwrap recipient resolution

The plugin needs the operator's age recipient string to `age.Encrypt` the payload. At decrypt time, the identity only has a tag (irreversible hash) and a relay target. The inner recipient string is provided via the `unwrap_recipient` field in `relay-config.yaml`:

```yaml
remotes:
  myserver:
    url: https://broker.example:8443
    unwrap_recipient: age1abc...    # age recipient of the unwrapper
```

This is the same public key the relay recipient was created with. The identity format is unchanged (`tag || target`). Config mode is now required — legacy URL-only identities are not supported with encrypted payload.

### 4.1. Outer wire format

```json
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

### 4.2. Inner payload (age-encrypted to operator's recipient)

```json
{
  "nonce": "<16 random bytes, hex>",
  "outer_hash": "<SHA-256(version.action.intent_id.tag.expires_at), hex>",
  "stanzas": [
    { "type": "X25519", "args": ["..."], "body": "..." }
  ],
  "ephemeral_key": "<age1... ephemeral recipient string>"
}
```

| Field | Description |
|---|---|
| `nonce` | 16 random bytes, hex-encoded. Ensures ciphertext uniqueness at the protocol level. Discarded after decryption. |
| `outer_hash` | `SHA-256("version.action.intent_id.tag.expires_at")` — dot-separated, canonical. Binds the encrypted payload to the outer routing fields including expiry. |
| `stanzas` | Inner age stanzas (same format as today, base64 raw standard bodies). |
| `ephemeral_key` | Plugin's ephemeral age recipient string (`age1...`) for the response envelope. |

### 4.3. Encryption

- Primitive: `age.Encrypt` to the operator's inner recipient (same recipient string the plugin uses for `Wrap`).
- Works with any recipient type: X25519, YubiKey, PQ, any plugin.
- The age encryption layer adds its own ephemeral key and nonce internally.
- Output: base64-encoded standard age ciphertext.

### 4.4. Outer hash construction

Canonical string:

```
"{version}.{action}.{intent_id}.{tag}.{expires_at}"
```

Example:

```
SHA-256("1.unwrap.a3f12c4e8b9d6f0a1b2c3d4e5f6a7b8c.QPg24g.1715350800")
```

Dot separator. No JSON. No whitespace. `expires_at` as decimal string. Deterministic on both sides.

### 4.5. Operator verification

1. `age.Decrypt(encrypted_payload, identity)` → inner payload JSON.
2. Parse inner payload.
3. Check `expires_at` from the outer fields — if in the past, reject the intent (expired).
4. Recompute `SHA-256("version.action.intent_id.tag.expires_at")` from the outer fields.
5. Compare against `outer_hash` — mismatch = broker tampered = reject the intent.
6. Extract `stanzas` and `ephemeral_key`, proceed with unwrap.

---

## 5. Response path — operator to plugin

### 5.1. Fulfill outer wire format

```json
{
  "version": 1,
  "action": "fulfill",
  "intent_id": "a3f1...",
  "encrypted_payload": "<base64: age-encrypted inner response>"
}
```

### 5.2. Poll response (broker → plugin)

```json
{
  "status": "fulfilled",
  "encrypted_payload": "<base64: age-encrypted inner response>"
}
```

Other statuses unchanged:

| Status | Body |
|---|---|
| `pending` | `{"status": "pending"}` |
| `fulfilled` | `{"status": "fulfilled", "encrypted_payload": "..."}` |
| `rejected` | `{"status": "rejected"}` |

`404` for unknown/expired — unchanged.

### 5.3. Inner payload (age-encrypted to plugin's ephemeral recipient)

```json
{
  "nonce": "<16 random bytes, hex>",
  "outer_hash": "<SHA-256(intent_id), hex>",
  "file_key": "<base64: 16-byte age file key>"
}
```

| Field | Description |
|---|---|
| `nonce` | 16 random bytes, hex-encoded. Ensures ciphertext uniqueness. Discarded after decryption. |
| `outer_hash` | `SHA-256(intent_id)` — binds the sealed response to the specific intent. |
| `file_key` | The unwrapped age file key, base64 raw standard encoded. |

### 5.4. Encryption

- Primitive: `age.Encrypt` (X25519 + HKDF + ChaCha20-Poly1305).
- Sealed to the plugin's ephemeral age recipient (extracted from the inner request payload).
- age internally generates a one-time ephemeral key per encryption.

Wire format of the `encrypted_payload` value: base64-encoded standard age binary ciphertext (same format as the request direction).

Both directions now use the same cryptographic primitive (`age.Encrypt`/`age.Decrypt`), eliminating NaCl box entirely.

### 5.5. Outer hash construction

```
SHA-256("{intent_id}")
```

Example:

```
SHA-256("a3f12c4e8b9d6f0a1b2c3d4e5f6a7b8c")
```

### 5.6. Plugin verification

1. `age.Decrypt(encrypted_payload, ephemeral_identity)` → inner payload JSON.
2. Parse inner payload.
3. Recompute `SHA-256(intent_id)` from the plugin's own stored intent_id.
4. Compare against `outer_hash` — mismatch = tamper = fail.
5. Extract `file_key`.

---

## 6. Sync flow compatibility

The relay-server (sync flow) uses the identical wire format:

### Request

```json
{
  "version": 1,
  "action": "unwrap",
  "intent_id": "...",
  "tag": "...",
  "expires_at": 1715350800,
  "encrypted_payload": "<age-encrypted blob>"
}
```

### Processing (relay-server)

1. `age.Decrypt(encrypted_payload, identity)` — relay-server holds the age identity.
2. Check `expires_at` from outer fields — reject if expired.
3. Verify `outer_hash` (includes `expires_at`).
4. Extract stanzas + ephemeral_key.
5. Unwrap stanzas → file key.
6. Build response inner payload: `{nonce, outer_hash, file_key}`.
7. `age.Encrypt` response to plugin's ephemeral recipient.
8. Return response.

### Response

**JSON (200 OK):**

```json
{
  "encrypted_payload": "..."
}
```

**SSE:**

```
event: result
data: {"encrypted_payload": "..."}

```

The `stream` option is purely a transport concern (connection keep-alive). Orthogonal to encryption.

---

## 7. Config

```yaml
remotes:
  myserver:
    url: https://relay.example:8443/unwrap
    unwrap_recipient: age1abc...     # required: age recipient of the unwrapper
    auth_token: bearer-token         # optional: broker/relay auth
    timeout: 5m                      # optional: default 5m
    stream: true                     # optional: SSE transport
    poll_interval: 2s                # optional: async polling interval
```

No security flags. Encrypted payload is the only mode. Config mode is required — the `unwrap_recipient` field must be set for payload encryption.

---

## 8. Security properties

### 8.1. Confidentiality

- Broker sees only `version`, `action`, `intent_id`, `tag`, and opaque ciphertext.
- Stanzas, ephemeral keys, and file keys are never visible to the broker.
- Request payload: age-encrypted (recipient-agnostic).
- Response payload: age-encrypted (to ephemeral recipient).
- Both include a protocol-level nonce ensuring unique ciphertext per intent.

### 8.2. Integrity

- `outer_hash` inside both encrypted payloads binds the opaque blob to the cleartext routing fields.
- Broker cannot modify any outer field without causing a hash mismatch on the receiving side.
- Broker cannot forge a valid encrypted payload without the operator's private key (request) or the plugin's ephemeral private key (response).

### 8.3. Forward secrecy

- Plugin generates a fresh ephemeral age X25519 identity per intent.
- age internally generates fresh ephemeral keys per encryption.
- Both discarded after use.

### 8.4. What the broker can still do

| Attack | Impact | Mitigation |
|---|---|---|
| Drop intents (DoS) | Plugin times out | Plugin's local timeout bounds the loss |
| Return `rejected` instead of `fulfilled` | Plugin fails decryption | DoS only — no cryptographic compromise |
| Traffic analysis on `tag` | Learns per-operator volume | Future: tag blinding (out of scope) |
| Replay stored `encrypted_payload` | age.Decrypt fails (different ephemeral key per intent) | Cryptographically prevented |

### 8.5. HMAC compatibility

HMAC signing is **not compatible** with this feature in the current design. The HMAC signed over cleartext body; with encrypted payloads, the body is ciphertext. A future iteration may reintroduce HMAC over the outer envelope if additional broker-side authentication is needed. Out of scope for this spec.

---

## 9. Removed fields and constants

| Removed | Location |
|---|---|
| `file_key` | `RelayResponse`, JSON wire format |
| `encrypted_file_key` | `RelayResponse`, `RelayRequest`, `asyncPollResponse`, broker `PollResponse` |
| `stanzas` (top-level request) | `RelayRequest` JSON wire format |
| `encrypted_response` | `RemoteConfig` |
| `hmac_key` | `RemoteConfig`, env var `AGE_PLUGIN_RELAY_HMAC_KEY` |
| `EnvelopeHeader` | `envelope.go` |
| `X-Relay-Ephemeral-Key` header | HTTP wire format |
| `HMACHeader*` constants | `hmac.go` |
| `SignRequest`, `VerifySignature`, `ValidateTimestamp` | `hmac.go` |
| Plaintext `extractFileKey` branch | `client.go` |

---

## 10. Repo changes

### New files
- `relay/payload.go` — `EncryptPayload()`, `DecryptPayload()`, `OuterHash()`, inner payload types. Shared by relay-server and relay-operator.

### Modified files
- `relay/client.go` — always encrypt inner payload via `age.Encrypt`; always decrypt response via `age.Decrypt` with structured inner; remove plaintext branches; new `innerRecipient` parameter on `PostToRelay`.
- `relay/config.go` — remove `EncryptedResponse`, `HMACKey` fields; add `UnwrapRecipient` field to `RemoteConfig`.
- `relay/identity.go` — pass `Remote.UnwrapRecipient` to `PostToRelay`; validate `UnwrapRecipient` is set.
- `relay/envelope.go` — `SealResponse` / `OpenResponse` use `age.Encrypt`/`age.Decrypt`; `EphemeralKeypair` wraps `age.X25519Identity`/`age.X25519Recipient`; seal/open structured inner JSON (nonce + outer_hash + file_key).
- `cmd/relay-server/main.go` — decrypt `encrypted_payload`, verify `outer_hash` + `expires_at`, extract stanzas + ephemeral key, seal response.
- `cmd/relay-operator/main.go` — same decryption logic as relay-server; remove HMAC verification.
- `cmd/relay-broker/main.go` — rename `encrypted_file_key` to `encrypted_payload` in fulfill/poll paths; remove HMAC header extraction.
- `relay/broker/types.go` — rename `EncryptedFileKey` to `EncryptedPayload`; remove `PluginHeaders` struct.
- `relay/broker/queue.go` — field rename; remove `PluginHeaders` from `Submit`.

### Removed files
- `relay/hmac.go` — HMAC signing removed.

### Unchanged files
- `relay/encoding.go`, `relay/errors.go`, `relay/recipient.go`

---

## 11. Build order

1. `relay/payload.go` — `InnerRequestPayload` (with `expires_at`), `InnerResponsePayload`, `OuterHash()`, `EncryptPayload()`, `DecryptPayload()`
2. `relay/envelope.go` — rename `SealFileKey`/`OpenFileKey` → `SealResponse`/`OpenResponse` with structured inner JSON
3. `relay/config.go` — remove `EncryptedResponse`, `HMACKey` fields; add `UnwrapRecipient`
4. `relay/identity.go` — pass `UnwrapRecipient` to `PostToRelay`; validate it's set
5. `relay/client.go` — encrypt request, decrypt response, remove plaintext branches, add `innerRecipient` param
6. `relay/broker/types.go` — rename `EncryptedFileKey` → `EncryptedPayload`; remove `PluginHeaders`
7. `relay/broker/queue.go` — field rename; remove `PluginHeaders` from `Submit`
8. `cmd/relay-broker/main.go` — field rename in fulfill/poll; remove HMAC header extraction
9. `cmd/relay-server/main.go` — decrypt + verify + seal
10. `cmd/relay-operator/main.go` — decrypt + verify, remove HMAC verification
11. Remove `relay/hmac.go`
12. Tests: reorganized into per-source-file test files (`encoding_test.go`, `identity_test.go`, `client_test.go`, `config_test.go`, `payload_test.go`, `envelope_test.go`, `async_test.go`, `integration_test.go`, `e2e_test.go`, `helpers_test.go`)

---

## 12. Sequence diagrams

### 12.1. Sync flow — plugin → relay-server → plugin

```
Plugin                                          Relay-Server
──────                                          ────────────
  │                                                  │
  │  1. Generate ephemeral X25519 keypair            │
  │  2. Build InnerRequestPayload:                   │
  │     {nonce, outer_hash, stanzas, ephemeral_key}  │
  │  3. age.Encrypt(inner, unwrap_recipient)         │
  │  4. Build outer: {version, action, intent_id,    │
  │     tag, expires_at, encrypted_payload}          │
  │                                                  │
  │  POST {version:1, action:"unwrap",               │
  │        intent_id, tag, expires_at,               │
  │        encrypted_payload}                        │
  │ ──────────────────────────────────────────────►  │
  │                                                  │  5. age.Decrypt(encrypted_payload, identity)
  │                                                  │  6. Check expires_at
  │                                                  │  7. Verify outer_hash
  │                                                  │  8. Extract stanzas + ephemeral_key
  │                                                  │  9. identity.Unwrap(stanzas) → file_key
  │                                                  │ 10. Build InnerResponsePayload:
  │                                                  │     {nonce, outer_hash, file_key}
  │                                                  │ 11. age.Encrypt(inner, ephemeral_recipient)
  │                                                  │
  │  200 OK                                          │
  │  {"encrypted_payload": "<age-encrypted blob>"}   │
  │ ◄──────────────────────────────────────────────  │
  │                                                  │
  │ 12. age.Decrypt(encrypted_payload, eph_identity)  │
  │ 13. Verify outer_hash == SHA-256(intent_id)      │
  │ 14. Extract file_key                             │
  │ 15. Discard ephemeral keypair                    │
  │                                                  │
```

### 12.2. Async flow — plugin → broker → operator → broker → plugin

```
Plugin                          Broker                          Operator
──────                          ──────                          ────────
  │                               │                                │
  │  1. Generate ephemeral        │                                │
  │  2. Build inner payload       │                                │
  │  3. age.Encrypt(inner,        │                                │
  │     unwrap_recipient)         │                                │
  │                               │                                │
  │  POST {action:"unwrap",       │                                │
  │   intent_id, tag, expires_at, │                                │
  │   encrypted_payload}          │                                │
  │ ─────────────────────────────►│                                │
  │                               │  4. Store intent:              │
  │                               │     intent_id, tag,            │
  │                               │     expires_at,                │
  │                               │     encrypted_payload          │
  │                               │     (all opaque to broker)     │
  │  202 Accepted                 │                                │
  │ ◄─────────────────────────────│                                │
  │                               │                                │
  │                               │  POST {action:"pull", tag}     │
  │                               │ ◄──────────────────────────────│
  │                               │                                │
  │                               │  200 OK                        │
  │                               │  {intents: [{intent_id,        │
  │                               │    request: {version, action,  │
  │                               │    intent_id, tag, expires_at, │
  │                               │    encrypted_payload}}]}       │
  │                               │ ──────────────────────────────►│
  │                               │                                │
  │                               │                5. age.Decrypt(encrypted_payload, identity)
  │                               │                6. Check expires_at
  │                               │                7. Verify outer_hash
  │                               │                8. Extract stanzas + ephemeral_key
  │                               │                9. identity.Unwrap(stanzas) → file_key
  │                               │               10. Build InnerResponsePayload:
  │                               │                   {nonce, outer_hash, file_key}
  │                               │               11. age.Encrypt(inner, ephemeral_recipient)
  │                               │                                │
  │                               │  POST {action:"fulfill",       │
  │                               │   intent_id,                   │
  │                               │   encrypted_payload}           │
  │                               │ ◄──────────────────────────────│
  │                               │                                │
  │                               │  12. Store encrypted_payload   │
  │                               │      on intent (opaque)        │
  │                               │                                │
  │                               │  200 OK                        │
  │                               │ ──────────────────────────────►│
  │                               │                                │
  │  POST {action:"poll",         │                                │
  │   intent_id}                  │                                │
  │ ─────────────────────────────►│                                │
  │                               │                                │
  │  200 OK                       │                                │
  │  {status:"fulfilled",         │                                │
  │   encrypted_payload}          │                                │
  │ ◄─────────────────────────────│                                │
  │                               │                                │
  │ 13. age.Decrypt(             │                                │
  │     encrypted_payload,        │                                │
  │     eph_identity)             │                                │
  │ 14. Verify outer_hash         │                                │
  │     == SHA-256(intent_id)     │                                │
  │ 15. Extract file_key          │                                │
  │ 16. Discard ephemeral keypair │                                │
  │                               │                                │
```

### 12.3. Async rejection flow

```
Plugin                          Broker                          Operator
──────                          ──────                          ────────
  │                               │                                │
  │  POST {action:"unwrap", ...}  │                                │
  │ ─────────────────────────────►│                                │
  │  202 Accepted                 │                                │
  │ ◄─────────────────────────────│                                │
  │                               │                                │
  │                               │  POST {action:"pull", tag}     │
  │                               │ ◄──────────────────────────────│
  │                               │  200 OK {intents: [...]}       │
  │                               │ ──────────────────────────────►│
  │                               │                                │
  │                               │         1. age.Decrypt → OK    │
  │                               │         2. Unwrap fails        │
  │                               │            (no matching key)   │
  │                               │                                │
  │                               │  POST {action:"reject",        │
  │                               │   intent_id}                   │
  │                               │ ◄──────────────────────────────│
  │                               │  200 OK                        │
  │                               │ ──────────────────────────────►│
  │                               │                                │
  │  POST {action:"poll",         │                                │
  │   intent_id}                  │                                │
  │ ─────────────────────────────►│                                │
  │  200 OK                       │                                │
  │  {status:"rejected"}          │                                │
  │ ◄─────────────────────────────│                                │
  │                               │                                │
  │  Return error to caller       │                                │
  │                               │                                │
```

### 12.4. Broker blindness — what each actor sees

```
                    Plugin              Broker              Operator
                    ──────              ──────              ────────

version             ✓ (sets it)         ✓ (reads it)        ✓ (verifies via hash)
action              ✓ (sets it)         ✓ (routes on it)    ✓ (verifies via hash)
intent_id           ✓ (generates it)    ✓ (indexes on it)   ✓ (verifies via hash)
tag                 ✓ (computes it)     ✓ (routes on it)    ✓ (verifies via hash)
expires_at          ✓ (sets it)         ✓ (can use for TTL) ✓ (verifies via hash)
stanzas             ✓ (encrypts them)   ✗ (opaque)          ✓ (decrypts them)
ephemeral_key       ✓ (generates it)    ✗ (opaque)          ✓ (seals to it)
file_key            ✓ (decrypts it)     ✗ (opaque)          ✓ (unwraps it)
outer_hash          ✓ (computes it)     ✗ (opaque)          ✓ (verifies it)
nonce               ✓ (generates it)    ✗ (opaque)          ✓ (discards it)
```

---

## 13. Summary

Payload encryption is mandatory and unconditional. Both directions use `age.Encrypt`/`age.Decrypt` as the sole cryptographic primitive. The plugin age-encrypts request payloads to the operator's recipient. The operator age-encrypts response payloads to the plugin's ephemeral recipient. Both directions include a SHA-256 outer hash binding the encrypted blob to the cleartext routing fields. The broker stores and forwards opaque blobs — it sees only version, action, intent_id, and tag. No configuration flags — encrypted is the only mode. HMAC is removed; integrity is provided by the encryption layer itself.
