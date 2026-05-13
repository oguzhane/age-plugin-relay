# Architecture — age-plugin-relay

Authoritative technical reference for `age-plugin-relay`. Covers wire protocol, data model, encryption design, async flow, security model, and testing.

---

## 1. Overview

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

Both directions use `age.Encrypt`/`age.Decrypt` as the sole cryptographic primitive (X25519 + HKDF + ChaCha20-Poly1305 STREAM).

---

## 2. Data Model

### 2.1. Recipient: `age1relay1<bech32(inner_recipient_string)>`

The Bech32 data payload is the UTF-8 bytes of the inner age recipient string. The plugin extracts it, calls `age.ParseRecipients()`, and delegates `Wrap()` to the parsed recipient.

The inner recipient can be any age recipient type:

| Inner type | Example | Plugin needed in PATH? |
|---|---|---|
| X25519 | `age1abc...` | No (native) |
| Hybrid PQ | `age1pq1...` | No (native, age v1.3+) |
| YubiKey P-256 | `age1yubikey1q...` | Yes: `age-plugin-yubikey` |
| Any plugin | `age1NAME1...` | Yes: `age-plugin-NAME` |

### 2.2. Identity: `AGE-PLUGIN-RELAY-1<bech32(tag || target)>`

The target is a remote name resolved from `relay-config.yaml`.

| Field | Size | Description |
|---|---|---|
| `tag` | 16 bytes | `SHA-256(inner_recipient_string)[:16]` — matches stanzas to this identity |
| `target` | variable | Remote name (`myserver`) |

Not secret. Contains no key material — only routing information. Safe to commit to version control.

At decrypt time, the plugin looks up the target in `relay-config.yaml` to get the URL, `unwrap_recipient`, and other settings.

### 2.3. Stanza format

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

---

## 3. Encrypted Payload Design

Payload encryption is mandatory and unconditional — no configuration flags. Both directions use `age.Encrypt`/`age.Decrypt` as the sole cryptographic primitive (X25519 + HKDF + ChaCha20-Poly1305 STREAM), eliminating NaCl box entirely.

Design goals:
- **Confidentiality**: the broker cannot read stanzas, ephemeral keys, or file keys.
- **Integrity**: the broker cannot tamper with any outer field without detection.
- **Simplicity**: no configuration flags — encrypted is the only mode.
- **Symmetry**: both request path (plugin → operator) and response path (operator → plugin) use the same `encrypted_payload` pattern.
- **Sync/async compatibility**: the same wire format works for both `relay-server` (sync) and `relay-broker` + `relay-operator` (async).

All messages are JSON over `POST` to a single endpoint URL. Bearer auth uses `Authorization: Bearer <auth_token>`.

### 3.1. Unwrap Recipient Resolution

The plugin needs the operator's age recipient string to `age.Encrypt` the payload. At decrypt time, the identity only has a tag (irreversible hash) and a relay target. The inner recipient string is provided via the `unwrap_recipient` field in `relay-config.yaml`:

```yaml
remotes:
  myserver:
    url: https://broker.example:8443
    unwrap_recipient: age1abc...    # age recipient of the unwrapper
```

This is the same public key the relay recipient was created with. The identity format is unchanged (`tag || target`). Config mode is required — legacy URL-only identities are not supported with encrypted payload.

### 3.2. Outer Envelope

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

### 3.3. Inner Request Payload

age-encrypted to the operator's recipient. Contains the stanzas and ephemeral key the operator needs to unwrap.

```json
{
  "nonce": "<16 random bytes, hex>",
  "outer_hash": "<SHA-256(version.action.stream.intent_id.tag.expires_at), hex>",
  "stanzas": [
    { "type": "X25519", "args": ["..."], "body": "..." }
  ],
  "ephemeral_key": "<age1... ephemeral recipient string>"
}
```

| Field | Description |
|---|---|
| `nonce` | 16 random bytes, hex-encoded. Ensures ciphertext uniqueness at the protocol level. Discarded after decryption. |
| `outer_hash` | `SHA-256("version.action.stream.intent_id.tag.expires_at")` — dot-separated, canonical. `stream` is `"0"` or `"1"`. Binds the encrypted payload to all outer routing fields including expiry. |
| `stanzas` | Inner age stanzas (base64 raw standard bodies). |
| `ephemeral_key` | Plugin's ephemeral age recipient string (`age1...`) for the response envelope. |

**Encryption**: `age.Encrypt` to the operator's inner recipient (same recipient string the plugin uses for `Wrap`). Works with any recipient type: X25519, YubiKey, PQ, any plugin. The age encryption layer adds its own ephemeral key and nonce internally. Output: base64-encoded standard age ciphertext.

### 3.4. Inner Response Payload

age-encrypted to the plugin's ephemeral recipient. Contains the unwrapped file key.

```json
{
  "nonce": "<16 random bytes, hex>",
  "outer_hash": "<SHA-256(version.action.intent_id), hex>",
  "file_key": "<base64: 16-byte age file key>"
}
```

| Field | Description |
|---|---|
| `nonce` | 16 random bytes, hex-encoded. Ensures ciphertext uniqueness. Discarded after decryption. |
| `outer_hash` | `SHA-256(version.action.intent_id)` — binds the sealed response to all outer envelope fields. |
| `file_key` | The unwrapped age file key, base64 raw standard encoded. |

**Encryption**: `age.Encrypt` (X25519 + HKDF + ChaCha20-Poly1305) to the plugin's ephemeral age recipient (extracted from the inner request payload). age internally generates a one-time ephemeral key per encryption. Wire format: base64-encoded standard age binary ciphertext (same as request direction).

### 3.5. Outer Hash Construction

> **Fundamental Principle: Complete Outer Field Binding**
>
> The outer hash MUST include every field in the envelope that exists outside `encrypted_payload`. No exceptions. If a field is present in the cleartext JSON envelope, it MUST be an input to the outer hash. This is a non-negotiable protocol invariant.
>
> **Why:** The broker (or any network intermediary) can see and modify cleartext envelope fields. The outer hash — computed inside the encrypted payload before encryption, and recomputed by the verifier after decryption — is the only mechanism that detects such tampering. Any field omitted from the hash is a field the broker can silently alter without detection.
>
> **Rule:** When adding a new field to `RelayRequest`, you MUST also add it to the corresponding `OuterHash*` function in `relay/payload.go`. Failing to do so creates a silent security vulnerability where the broker can tamper with the new field undetected.

The outer hash binds the encrypted blob to the cleartext routing fields. Any modification by the broker is detected.

**Request envelope fields** (plugin → server/operator):

| Envelope field | Included in outer hash |
|---|---|
| `version` | ✓ |
| `action` | ✓ |
| `stream` | ✓ (as `"0"` or `"1"`) |
| `intent_id` | ✓ |
| `tag` | ✓ |
| `expires_at` | ✓ (as decimal string) |
| `encrypted_payload` | — (this IS the encrypted blob; the hash lives inside it) |

**Response envelope fields** (server/operator → plugin):

| Envelope field | Included in outer hash |
|---|---|
| `version` | ✓ |
| `action` | ✓ |
| `intent_id` | ✓ |
| `encrypted_payload` | — (this IS the encrypted blob; the hash lives inside it) |

**Request outer hash** (verified by operator):

```
SHA-256("{version}.{action}.{stream}.{intent_id}.{tag}.{expires_at}")
```

Example:

```
SHA-256("1.unwrap.0.a3f12c4e8b9d6f0a1b2c3d4e5f6a7b8c.QPg24g.1715350800")
```

Dot separator. No JSON. No whitespace. `expires_at` as decimal string. Deterministic on both sides.

**Response outer hash** (verified by plugin):

```
SHA-256("{version}.{action}.{intent_id}")
```

Example:

```
SHA-256("1.fulfill.a3f12c4e8b9d6f0a1b2c3d4e5f6a7b8c")
```

### 3.6. Streaming (SSE)

For long-running relay scenarios (approval flows, remote YubiKey touch), the server can respond with Server-Sent Events instead of a single JSON response. This keeps the connection alive through proxies and load balancers.

SSE is enabled per-remote via the `stream` field in `relay-config.yaml`. When enabled, the plugin sends `"stream": true` in the request payload. The client detects the response type from `Content-Type`:

- `application/json` → standard JSON
- `text/event-stream` → SSE stream

Servers that don't support SSE simply ignore the `stream` field and return JSON.

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

Unknown event types are silently ignored for forward compatibility. SSE is purely a transport concern (connection keep-alive), orthogonal to encryption.

---

## 4. Sync Flow

Two actors: **Plugin** and **Relay-Server**. The relay-server holds the age identity and answers immediately. Same wire format as the async flow — the plugin discovers sync via a `200` response (vs `202` for async).

### 4.1. Request (plugin → relay-server)

**Outer envelope:**

```http
POST / HTTP/1.1
Content-Type: application/json
Authorization: Bearer <auth_token>

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
- `action`: `"unwrap"`.
- `intent_id`: Plugin-generated unique ID (16 random bytes, hex-encoded, 32 chars).
- `tag`: Routing tag derived from the inner recipient (`SHA-256(recipient)[:4]`, base64).
- `expires_at`: Unix timestamp (seconds) — intent expiry.
- `stream`: Optional. If `true`, the client accepts SSE responses.
- `encrypted_payload`: age-encrypted inner request payload (see §3.3). Opaque to the broker.

**Plugin build steps:**

1. Generate ephemeral age X25519 identity (keypair).
2. Build inner request payload: `{nonce, outer_hash, stanzas, ephemeral_key}`.
3. `age.Encrypt(inner, unwrap_recipient)` → `encrypted_payload`.
4. Build outer envelope with `version`, `action`, `intent_id`, `tag`, `expires_at`, `encrypted_payload`.
5. POST to relay endpoint.

### 4.2. Processing (relay-server)

1. `age.Decrypt(encrypted_payload, identity)` → inner request payload JSON.
2. Parse inner payload.
3. Check `expires_at` from the outer fields — reject if in the past.
4. Recompute `SHA-256("version.action.stream.intent_id.tag.expires_at")` from the outer fields.
5. Compare against `outer_hash` — mismatch = tampered = reject.
6. Extract `stanzas` and `ephemeral_key`.
7. `identity.Unwrap(stanzas)` → file key.
8. Build inner response payload: `{nonce, outer_hash, file_key}` where `outer_hash = SHA-256("1.fulfill".intent_id)`.
9. `age.Encrypt(inner_response, ephemeral_recipient)` → response `encrypted_payload`.
10. Return response.

### 4.3. Response (relay-server → plugin)

**Success (200 OK) — JSON:**

```json
{
  "version": 1,
  "action": "fulfill",
  "intent_id": "a3f12c4e8b9d6f0a1b2c3d4e5f6a7b8c",
  "encrypted_payload": "<base64: age-encrypted inner response>"
}
```

The success response uses `action: "fulfill"` — the same `RelayRequest` envelope shape and action as the async flow's operator fulfill body.

**Success (200 OK) — SSE:**

```
event: result
data: {"version":1,"action":"fulfill","intent_id":"a3f1...","encrypted_payload":"<age-encrypted blob>"}

```

**Errors:**

| HTTP Status | Body | Meaning |
|---|---|---|
| 200 | `{"version":1,"action":"reject","intent_id":"...","encrypted_payload":"..."}` | No identity can unwrap (reject with outer hash verification) |
| 408 | `{"error": "timeout"}` | Identity interaction timed out (e.g., YubiKey not touched) |
| 503 | `{"error": "unavailable"}` | Relay can't reach the identity |

### 4.4. Plugin verification

1. Parse the `RelayRequest` envelope — extract `action` and `encrypted_payload`.
2. `age.Decrypt(encrypted_payload, ephemeral_identity)` → inner response payload JSON.
3. Parse inner payload.
4. Recompute `SHA-256("{version}.{action}".intent_id)` using the version and action from the envelope and the plugin's own stored intent_id.
5. Compare against `outer_hash` — mismatch = tamper = fail.
6. Extract `file_key`.
7. Discard ephemeral keypair.

### 4.5. Sequence Diagram

```
Plugin                                          Relay-Server
──────                                          ────────────
  │                                                  │
  │  1. Generate ephemeral age X25519 identity       │
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
  │  {version:1, action:"fulfill",                   │
  │   intent_id, encrypted_payload}                  │
  │ ◄──────────────────────────────────────────────  │
  │                                                  │
  │ 12. Parse envelope → extract action,             │
  │     encrypted_payload                            │
  │ 13. age.Decrypt(encrypted_payload, eph_identity) │
  │ 14. Verify outer_hash == SHA-256(version.action.intent_id) │
  │ 15. Extract file_key                             │
  │ 16. Discard ephemeral keypair                    │
  │                                                  │
```

---

## 5. Async Flow (Control Tower)

Three actors: **Plugin**, **Broker**, and **Operator**. The broker is a zero-trust stateful queue — it stores and forwards opaque encrypted payloads. It holds no age identity, no key material, and no view into the cryptographic content. The operator is a separate process that polls the broker, decrypts, unwraps, and fulfills.

### 5.1. Response-Code Branching

The plugin discovers async via the HTTP status code on its `unwrap` POST:

| Status | Body | Plugin behavior |
|---|---|---|
| `200 OK` | `{"encrypted_payload": ...}` | Sync result — done (see §4) |
| `202 Accepted` | `{}` | Async — switch to polling using the plugin's own `intent_id` |
| `409 Conflict` | `{"error":"duplicate_intent"}` | Retry with a freshly generated `intent_id` |
| `4xx/5xx` | as today | Errors |

The plugin does not need to know whether the endpoint is a `relay-server` or a `relay-broker`. The protocol is uniform; behavior is response-driven.

### 5.2. Submit (plugin → broker)

**Outer envelope** — identical to the sync request (§4.1):

```json
{
  "version": 1,
  "action": "unwrap",
  "intent_id": "a3f12c4e8b9d6f0a1b2c3d4e5f6a7b8c",
  "tag": "QPg24g",
  "expires_at": 1715350800,
  "encrypted_payload": "<base64: age-encrypted blob>"
}
```

**Inner request payload** — identical to §3.3. Contains `{nonce, outer_hash, stanzas, ephemeral_key}`, age-encrypted to the operator's `unwrap_recipient`.

- `intent_id` is **plugin-generated**: 16 random bytes, hex-encoded (32 chars).
- `expires_at` is the plugin-defined intent expiry (Unix timestamp, seconds).
- `encrypted_payload` is opaque to the broker.

**Response:** `202 Accepted` with empty body `{}`.

### 5.3. Pull (operator → broker)

```json
{
  "version": 1,
  "action": "pull",
  "tag": "QPg24g"
}
```

**Response** — the full original request, verbatim, for each pending intent matching the tag:

```json
{
  "intents": [
    {
      "intent_id": "a3f1...",
      "request": {
        "version": 1,
        "action": "unwrap",
        "intent_id": "a3f1...",
        "tag": "QPg24g",
        "expires_at": 1715350800,
        "encrypted_payload": "<age-encrypted blob>"
      }
    }
  ]
}
```

The response contains **no broker-asserted metadata** — no `created_at`, no broker timestamps. The `request` field is the **verbatim original** plugin POST body delivered as raw JSON (`json.RawMessage`). The broker stores the raw bytes and passes them through without parsing or restructuring.

### 5.4. Operator Processing

The operator receives the verbatim outer envelope from the broker and processes it identically to a relay-server:

1. `age.Decrypt(encrypted_payload, identity)` → inner request payload JSON.
2. Parse inner payload.
3. Check `expires_at` from the outer fields — reject if in the past.
4. Recompute `SHA-256("version.action.stream.intent_id.tag.expires_at")` from the outer fields.
5. Compare against `outer_hash` — mismatch = broker tampered = reject the intent.
6. Extract `stanzas` and `ephemeral_key`.
7. `identity.Unwrap(stanzas)` → file key.
8. Build inner response payload: `{nonce, outer_hash, file_key}` where `outer_hash = SHA-256("1.fulfill".intent_id)`.
9. `age.Encrypt(inner_response, ephemeral_recipient)` → response `encrypted_payload`.

### 5.5. Fulfill (operator → broker)

```json
{
  "version": 1,
  "action": "fulfill",
  "intent_id": "a3f1...",
  "encrypted_payload": "<base64: age-encrypted inner response>"
}
```

The `encrypted_payload` contains the inner response payload (§3.4) age-encrypted to the plugin's ephemeral recipient from the original request.

**Response:** `200 OK` on success, `404` if `intent_id` is unknown, `409` if already terminal.

### 5.6. Reject (operator → broker)

```json
{
  "version": 1,
  "action": "reject",
  "intent_id": "a3f1..."
}
```

**Response:** `200 OK` on success, `404`/`409` as for `fulfill`.

### 5.7. Poll (plugin → broker)

```json
{
  "version": 1,
  "action": "poll",
  "intent_id": "a3f1..."
}
```

| Status | Body | Meaning |
|---|---|---|
| `200 OK` | `{"status":"pending"}` | Keep polling |
| `200 OK` | `{"status":"fulfilled", "response": {...}}` | Plugin extracts `encrypted_payload` from response, decrypts with ephemeral identity, verifies outer_hash |
| `200 OK` | `{"status":"rejected", "response": {...}}` | Operator declined; `response` contains verbatim operator reject body; plugin returns failure |
| `404` | `{"error":"unknown_intent"}` | Expired, never existed, or broker forgot — plugin treats as failure |

The broker does not distinguish "expired" from "never existed." Both collapse to `404`.

### 5.8. Plugin Verification

On receiving a `fulfilled` poll response:

1. Parse `response` field (verbatim operator fulfill body) → extract `encrypted_payload`.
2. `age.Decrypt(encrypted_payload, ephemeral_identity)` → inner response payload JSON.
3. Parse inner payload.
4. Recompute `SHA-256("1.fulfill".intent_id)` from the plugin's own stored intent_id.
5. Compare against `outer_hash` — mismatch = tamper = fail.
6. Extract `file_key`.
7. Discard ephemeral keypair.

### 5.9. State Machine

```
                ┌──────────┐
                │ pending  │
                └────┬─────┘
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
    fulfilled    rejected     (deleted)
                              [silent TTL]
```

All states are terminal once entered. The broker silently deletes intents after its internal TTL; the plugin observes this as `404 unknown_intent` on `poll`.

### 5.10. Polling Cadence

The broker emits **no flow-control hints**. Cadence is a client-side concern.

**Plugin:**
- Configurable per-remote via `poll_interval` in `relay-config.yaml`.
- Default: `min(timeout / 60, 5s)`.
- The plugin polls until it observes `fulfilled`, `rejected`, `404`, or its local `timeout` elapses.

**Operator:**
- Configurable via the operator binary's flags (e.g., `--pull-interval 30s`).
- No coordination with the plugin or broker required.

### 5.11. Fulfillment Sequence Diagram

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
  │                               │    request: <verbatim plugin   │
  │                               │    POST body as raw JSON>}]}   │
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
  │                               │  12. Store verbatim fulfill    │
  │                               │      body on intent (opaque)   │
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
  │   response: <verbatim         │                                │
  │   operator fulfill body>}     │                                │
  │ ◄─────────────────────────────│                                │
  │                               │                                │
  │ 13. Parse response →          │                                │
  │     extract encrypted_payload │                                │
  │ 14. age.Decrypt(             │                                │
  │     encrypted_payload,        │                                │
  │     eph_identity)             │                                │
  │ 15. Verify outer_hash         │                                │
  │     == SHA-256("1.fulfill"  │                                │
  │       .intent_id)            │                                │
  │ 16. Extract file_key          │                                │
  │ 17. Discard ephemeral keypair │                                │
  │                               │                                │
```

### 5.12. Rejection Sequence Diagram

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

### 5.13. Idempotency, Replay, and Recovery

#### Intent ID collisions
- The broker enforces uniqueness: a second `unwrap` with an existing `intent_id` returns `409 Conflict`.
- Plugins MUST generate a fresh random `intent_id` on retry-after-`409`.

#### Network failure on submit
If the plugin's `unwrap` POST fails before receiving a response, the plugin SHOULD first `poll` with the existing `intent_id` to learn the broker's view:
- `200 OK { status: pending | fulfilled | rejected }` → continue normally.
- `404 unknown_intent` → broker did not store the intent; safe to retry with a fresh `intent_id`.

Plugins MUST NOT blindly retry `unwrap` with the same `intent_id` — that path returns `409` and obscures whether the original submission succeeded.

#### Replay protection
- **Encrypted payload:** age encryption uses unique ephemeral keys per encryption. Replaying a captured `unwrap` to the broker either collides (`409`) or, if the original was already cleaned up, creates a duplicate intent that the operator verifies via `expires_at` and outer hash.
- **Response payload:** age encryption uses unique ephemeral keys. Replaying a captured `fulfill` to a different intent fails because `outer_hash` inside the encrypted response is bound to the original `intent_id`.

---

## 6. Security Model

### 6.1. Properties

- **Encryption is offline** — uses only the inner recipient's public key. No network, no relay, no hardware.
- **No secrets in the plugin** — the recipient contains only a public key string; the identity contains only a tag and remote name.
- **End-to-end encrypted payloads** — stanzas and file keys are never visible to the broker or any intermediary.
- **Tamper detection** — SHA-256 outer hash binds encrypted payloads to cleartext routing fields. Every envelope field outside `encrypted_payload` is included in the hash — this is a fundamental protocol invariant (see §3.5).
- **Forward secrecy** — plugin generates a fresh ephemeral age X25519 identity per intent; age internally generates fresh ephemeral keys per encryption. Both discarded after use.
- **Transport-independent** — encrypted end-to-end even over plaintext HTTP.
- **With SOPS key groups + Shamir** — intercepting one group's unwrapped share is information-theoretically useless without the other share(s).
- **Relay endpoint is the trust boundary** — it holds the actual private key or identity. The plugin itself holds no key material.

#### Confidentiality

- Broker sees only `version`, `action`, `intent_id`, `tag`, and opaque ciphertext.
- Stanzas, ephemeral keys, and file keys are never visible to the broker.
- Request payload: age-encrypted (recipient-agnostic).
- Response payload: age-encrypted (to ephemeral recipient).
- Both include a protocol-level nonce ensuring unique ciphertext per intent.

#### Integrity

- `outer_hash` inside both encrypted payloads binds the opaque blob to the cleartext routing fields.
- Broker cannot modify any outer field without causing a hash mismatch on the receiving side.
- Broker cannot forge a valid encrypted payload without the operator's private key (request) or the plugin's ephemeral private key (response).

#### Forward secrecy

- Plugin generates a fresh ephemeral age X25519 identity per intent.
- age internally generates fresh ephemeral keys per encryption.
- Both discarded after use.

### 6.2. Broker Blindness

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

### 6.3. Threat Model

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

### 6.4. Threat Details (Async-Specific)

#### Broker compromise
- Broker holds no age identity. It cannot decrypt `encrypted_payload` and cannot forge valid encrypted payloads.
- Broker can read `tag` (already public; routing metadata) and `intent_id` (random, no semantic content).
- Broker cannot read stanzas, ephemeral keys, or file keys — all inside `encrypted_payload`.
- Broker cannot substitute or tamper with any outer field — `outer_hash` inside the encrypted payload detects this.
- Broker can DoS (drop intents, return `404`, return `409` falsely). Detected by the plugin's local timeout.

#### Ephemeral key substitution
- The plugin's ephemeral public key is inside the age-encrypted inner payload. The broker cannot read or modify it.
- A substituted ephemeral key would require forging a valid age-encrypted payload, which requires the operator's private key.

#### Fabricated intent
- Without the operator's age recipient public key, an attacker cannot create a valid `encrypted_payload` that the operator can decrypt.
- Even with the public key, the attacker cannot create a payload containing valid age-wrapped stanzas (those require the correct file key).

#### Operator response forgery
- The operator age-encrypts `encrypted_payload` to the plugin's ephemeral recipient from the original request.
- Only a holder of the matching ephemeral identity (the plugin) can decrypt it.
- A forged or tampered response fails `age.Decrypt`. The plugin MUST treat decryption failure as terminal.
- The response includes `outer_hash = SHA-256(version.action.intent_id)` — the plugin verifies this to ensure the response matches the original version, action, and intent.

### 6.5. What the Broker Can Still Do

| Attack | Impact | Mitigation |
|---|---|---|
| Drop intents (DoS) | Plugin times out | Plugin's local timeout bounds the loss |
| Return `rejected` instead of `fulfilled` | Plugin fails decryption | DoS only — no cryptographic compromise |
| Traffic analysis on `tag` | Learns per-operator volume | Future: tag blinding (out of scope) |
| Replay stored `encrypted_payload` | age.Decrypt fails (different ephemeral key per intent) | Cryptographically prevented |

### 6.6. Known Limitations

- **Metadata leakage to the broker.** The broker observes `tag` values and per-tag traffic timing. Mitigation: a future "blind tag index" extension can replace `tag` with `HMAC(operator_secret, tag)`. Out of scope.
- **Single shared `auth_token`.** All plugins and operators share one broker token. Compromise of any participant exposes broker access for all. Per-actor tokens are a future hardening step.
- **Broker DoS / denial-of-service.** A malicious broker can silently drop intents. The plugin's local timeout bounds the loss; cryptographic correctness is unaffected.
- **HMAC incompatibility.** HMAC signing is not compatible with encrypted payloads — the HMAC signed over cleartext body; with encrypted payloads, the body is ciphertext. Integrity is provided by the age encryption layer plus outer_hash binding.

---

## 7. Configuration

### 7.1. Plugin (`relay-config.yaml`)

```yaml
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
    poll_interval: 2s                              # optional; default min(timeout/60, 5s)

  backup:
    url: https://backup.example:9999/unwrap
    unwrap_recipient: age1def...
```

The plugin looks for the config file at:
1. `AGE_PLUGIN_RELAY_CONFIG` env var (if set)
2. `$PWD/relay-config.yaml`

No security flags. Encrypted payload is the only mode. Config mode is required — the `unwrap_recipient` field must be set for payload encryption.

#### Resolution priority at decrypt time

Per-remote config takes priority over environment variables:

| Setting | Priority |
|---|---|
| TLS cert/key/CA | Remote config > env var (`AGE_PLUGIN_RELAY_TLS_*`) |
| Timeout | Remote config > env var (`AGE_PLUGIN_RELAY_TIMEOUT`) > default 5m |

#### Environment variables

| Variable | Default | Description |
|---|---|---|
| `AGE_PLUGIN_RELAY_CONFIG` | `$PWD/relay-config.yaml` | Path to config file |
| `AGE_PLUGIN_RELAY_TIMEOUT` | `5m` | HTTP timeout (fallback if not set per-remote). Supports Go duration format. |
| `AGE_PLUGIN_RELAY_TLS_CERT` | — | Client TLS certificate (fallback if not set per-remote) |
| `AGE_PLUGIN_RELAY_TLS_KEY` | — | Client TLS private key (fallback if not set per-remote) |
| `AGE_PLUGIN_RELAY_TLS_CA` | — | CA certificate for server verification (fallback if not set per-remote) |
| `AGE_PLUGIN_RELAY_AUTH_TOKEN` | — | Bearer token for relay server auth (fallback if not set per-remote) |

### 7.2. Relay Server

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

| Flag | Env | Description |
|---|---|---|
| `-identity <file>` | — | Age identity file (required) |
| `-addr <addr>` | — | Listen address (default `:9876`) |
| `-tls-cert <file>` | — | TLS server certificate (enables HTTPS) |
| `-tls-key <file>` | — | TLS server private key |
| `-tls-ca <file>` | — | CA cert for client verification (enables mTLS) |
| `-auth-token <token>` | `RELAY_AUTH_TOKEN` | Required Bearer token |

### 7.3. Relay Broker

The broker is a zero-trust stateful queue:

```bash
relay-broker -addr :8443 -auth-token my-token -max-ttl 10m
```

| Flag | Description |
|---|---|
| `-addr` | Listen address (default `:8443`) |
| `-auth-token` | Required Bearer token |
| `-max-ttl` | Intent TTL before silent deletion (default `5m`) |

### 7.4. Relay Operator

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

---

## 8. Code Architecture

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
│   └── ARCHITECTURE.md                 # This file — authoritative technical reference
├── test.sh                             # Step-by-step CLI integration test
└── README.md                           # Usage, installation, quick start
```

### Dependencies

- [`filippo.io/age`](https://pkg.go.dev/filippo.io/age) v1.3.1 — age types (`Recipient`, `Identity`, `Stanza`), recipient parsing, encryption/decryption
- [`filippo.io/age/plugin`](https://pkg.go.dev/filippo.io/age/plugin) — Plugin framework, Bech32 encoding helpers
- [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto) — Cryptographic primitives
- [`gopkg.in/yaml.v3`](https://pkg.go.dev/gopkg.in/yaml.v3) — Config file parsing

---

## 9. Testing

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
