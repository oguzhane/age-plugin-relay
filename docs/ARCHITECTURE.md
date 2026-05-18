# Architecture — age-plugin-relay

Authoritative technical reference for `age-plugin-relay`. Covers wire protocol, data model, encryption design, async flow, security model, and testing.

---

## 1. Overview

```
ENCRYPTION (offline — no relay needed)        DECRYPTION (online — relay required)

  age1relay1<inner_recipient>                   AGE-PLUGIN-RELAY-1<tag + remote_name>
    |                                             |
    v                                             v
  Extract inner recipient string                Receive relay stanzas from age header
    |                                             |
    v                                             v
  Parse recipient (native or plugin) -> Wrap()  Match stanzas by tag, reconstruct inner stanzas
    |                                             |
    v                                             v
  Re-tag stanza: <inner_type> -> relay                Resolve remote name (from config)
    |                                             |
    v                                             v
  Done. No network. Identity-agnostic.          Build encrypted payload → HTTP POST → decrypt response
```

**Encryption** uses only the inner recipient's public key — no relay, no network, no hardware. The plugin parses the inner recipient (native or plugin — see §3.7), so it works with any recipient type age supports.

**Decryption** builds an encrypted inner payload (age-encrypted to the operator's recipient), sends it to the relay endpoint, and decrypts the age-encrypted response. The relay/broker never sees plaintext stanzas or file keys.

Both directions use `age.Encrypt`/`age.Decrypt` as the sole cryptographic primitive (X25519 + HKDF + ChaCha20-Poly1305 STREAM).

---

## 2. Data Model

### 2.1. Recipient: `age1relay1<bech32(inner_recipient_string)>`

The Bech32 data payload is the UTF-8 bytes of the inner age recipient string. The plugin extracts it, parses the recipient (native or plugin — see §3.7), and delegates `Wrap()` to the parsed recipient.

The inner recipient can be any age recipient type:

| Inner type | Example | Plugin needed in PATH? |
|---|---|---|
| X25519 | `age1abc...` | No (native) |
| Hybrid PQ | `age1pq1...` | No (native, age v1.3+) |
| YubiKey P-256 | `age1yubikey1q...` | Yes: `age-plugin-yubikey` |
| Any plugin | `age1NAME1...` | Yes: `age-plugin-NAME` |

### 2.2. Identity: `AGE-PLUGIN-RELAY-1<bech32(tag || remote_name)>`

The remote name is resolved from `relay-config.yaml`.

| Field | Size | Description |
|---|---|---|
| `tag` | 16 bytes | `SHA-256(inner_recipient_string)[:16]` — matches stanzas to this identity |
| `remote_name` | variable | Remote name (`myserver`) |

Not secret. Contains no key material — only routing information. Safe to commit to version control.

At decrypt time, the plugin looks up the remote name in `relay-config.yaml` to get the URL, `unwrap_recipient`, and other settings.

### 2.3. Stanza format

```
-> relay <tag_b64> <inner_type> [inner_args...]
<body>
```

Example with an X25519 inner recipient (any age recipient type works — YubiKey, hybrid PQ, or any plugin):

```
-> relay QPg24ggKk7xKd2t3c5rL9A X25519 CKTwCgeHBEBFmdC7GJSffbto8y+8G8iPHhTeMnhxIg4
X0e7a90Lzp8lnpGBH7JdWnpW+WcH61T4obAXzVHa6N8
```

| Argument | Description |
|---|---|
| `QPg24ggKk7xKd2t3c5rL9A...` | Base64-encoded 16-byte tag (for routing) |
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

The plugin needs the operator's age recipient string to `age.Encrypt` the payload. At decrypt time, the identity only has a tag (irreversible hash) and a remote name. The inner recipient string is provided via the `unwrap_recipient` field in `relay-config.yaml`:

```yaml
remotes:
  myserver:
    url: https://broker.example:8443
    unwrap_recipient: age1abc...    # age recipient of the unwrapper
```

This is the same public key the relay recipient was created with. The identity format is unchanged (`tag || remote_name`).

### 3.2. Outer Envelope

Every request to the broker/relay-server has at most these cleartext fields:

| Field | Present in | Purpose |
|---|---|---|
| `version` | all | Protocol version |
| `action` | all | Routing: `unwrap`, `poll`, `pull`, `fulfill`, `reject` |
| `intent_id` | unwrap, poll, fulfill, reject | Intent state machine |
| `tag` | unwrap, pull | Operator routing |
| `expires_at` | unwrap | Unix timestamp (seconds). Plugin-defined intent expiry. |
| `intent_claim_pub` | unwrap | Ed25519 public key (base64). Per-intent authorization — see [Intent Claim](INTENT-CLAIM.md) |
| `intent_claim_sig` | fulfill, reject | Ed25519 signature (base64). Proves operator decrypted the payload — see [Intent Claim](INTENT-CLAIM.md) |
| `encrypted_payload` | unwrap, fulfill | Opaque blob — broker stores and forwards |

No stanzas, no ephemeral keys, no file keys at the outer level.

### 3.3. Inner Request Payload

age-encrypted to the operator's recipient. Contains the stanzas and ephemeral key the operator needs to unwrap.

```json
{
  "nonce": "<16 random bytes, hex>",
  "outer_hash": "<SHA-256(version.action.intent_id.tag.expires_at.intent_claim_pub), hex>",
  "stanzas": [
    { "type": "X25519", "args": ["..."], "body": "..." }
  ],
  "ephemeral_key": "<age1... ephemeral recipient string>",
  "intent_claim_secret": "<Ed25519 private key seed, base64 raw std>"
}
```

Note: The stanza `type` reflects the original inner recipient type. Examples: `X25519` (native), `piv-p256` (YubiKey), or any other plugin stanza type.

| Field | Description |
|---|---|
| `nonce` | 16 random bytes, hex-encoded. Ensures ciphertext uniqueness at the protocol level. Discarded after decryption. |
| `outer_hash` | `SHA-256("version.action.intent_id.tag.expires_at.intent_claim_pub")` — dot-separated, canonical. Binds the encrypted payload to all outer routing fields including expiry and intent claim public key. |
| `stanzas` | Inner age stanzas (base64 raw standard bodies). |
| `ephemeral_key` | Plugin's ephemeral age recipient string (`age1...`) for the response envelope. |
| `intent_claim_secret` | Ed25519 private key seed (32 bytes, base64 raw standard). Only the operator (who decrypts) can extract this. See [Intent Claim](INTENT-CLAIM.md). |

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

> **Fundamental Principle: Sealed Action Binding**
>
> Every `action` value in the protocol MUST carry an `encrypted_payload` containing an outer hash that the recipient verifies. No action is exempt — fulfill, reject, and any future action MUST be sealed and verified. A cleartext-only envelope (without `encrypted_payload`) is never trustworthy because the broker can forge it.
>
> **Why:** Without an encrypted payload, the broker can fabricate any action (e.g., fake a reject to deny service). The outer hash inside the encrypted payload — sealed to the recipient's key — is the only proof that the action originated from the legitimate party (operator or server) and was not tampered with in transit.
>
> **Rule:** When adding a new `action` value to the protocol, you MUST ensure it includes an `encrypted_payload` with an outer hash computed over the envelope fields. The recipient MUST decrypt and verify before trusting the action.

The outer hash binds the encrypted blob to the cleartext routing fields. Any modification by the broker is detected.

**Request envelope fields** (plugin → server/operator):

| Envelope field | Included in outer hash |
|---|---|
| `version` | ✓ |
| `action` | ✓ |
| `intent_id` | ✓ |
| `tag` | ✓ |
| `expires_at` | ✓ (as decimal string) |
| `intent_claim_pub` | ✓ |
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
SHA-256("{version}.{action}.{intent_id}.{tag}.{expires_at}.{intent_claim_pub}")
```

Example:

```
SHA-256("1.unwrap.a3f12c4e8b9d6f0a1b2c3d4e5f6a7b8c.QPg24ggKk7xKd2t3c5rL9A.1715350800.AAAA...")
```

Dot separator. No JSON. No whitespace. `expires_at` as decimal string. `intent_claim_pub` as base64 raw standard (empty string if not set). Deterministic on both sides.

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

SSE is enabled on the server side via the `-stream` CLI flag (e.g., `relay-server -identity keys.txt -stream`). The plugin auto-detects the response format from the `Content-Type` header:

- `application/json` → standard JSON
- `text/event-stream` → SSE stream

No plugin-side configuration is needed. Servers that don't use `-stream` return JSON.

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

### 3.7. Plugin-Agnostic Recipient Dispatch

The relay supports any age recipient and identity type — native (X25519, hybrid PQ) or plugin-backed (YubiKey, any `age-plugin-*`).

**The problem:** The core age library's `age.ParseRecipients()` and `age.ParseIdentities()` only handle native types. Plugin recipients (`age1yubikey1q...`) and plugin identities (`AGE-PLUGIN-YUBIKEY-1...`) require the `filippo.io/age/plugin` package, which spawns an external binary via the age plugin protocol (stdin/stdout state machine).

**Dispatch pattern:** Implemented by `parseAnyRecipient()` and `ParseAnyIdentities()` in `relay/recipient_parse.go`. Try native parsing first. If that fails, detect the plugin name from the recipient/identity string (e.g., `age1yubikey1q...` → plugin name `yubikey`) and delegate to the age plugin framework. The framework spawns `age-plugin-<name>` via `--age-plugin=recipient-v1` (encryption) or `--age-plugin=identity-v1` (decryption). This is the same dispatch pattern the `age` CLI uses internally.

**Plugin binary requirement:** The external `age-plugin-<name>` binary must be in `PATH` wherever that recipient/identity type is used — the same requirement as using the recipient directly with `age`. Specifically:

| Machine | Needs plugin binary for |
|---|---|
| Encryption machine | Inner recipient's plugin (e.g., `age-plugin-yubikey` for `age1yubikey1q...`) |
| Relay-server / operator | Unwrap identity's plugin (e.g., `age-plugin-yubikey` for `AGE-PLUGIN-YUBIKEY-1...`) |
| Plugin (decrypt side) | `unwrap_recipient`'s plugin if it's a non-native type |

**Ephemeral keys are always X25519.** The ephemeral keypair used for response encryption is a transport concern internal to the relay protocol, independent of the inner recipient type. Even when the inner recipient is YubiKey P-256, the response envelope is encrypted to an ephemeral X25519 key generated per intent.

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
  "tag": "QPg24ggKk7xKd2t3c5rL9A",
  "expires_at": 1715350800,
  "intent_claim_pub": "<base64: Ed25519 public key>",
  "encrypted_payload": "<base64: age-encrypted blob>"
}
```

- `version`: Protocol version (currently `1`).
- `action`: `"unwrap"`.
- `intent_id`: Plugin-generated unique ID (16 random bytes, hex-encoded, 32 chars).
- `tag`: Routing tag derived from the inner recipient (`SHA-256(recipient)[:16]`, base64).
- `expires_at`: Unix timestamp (seconds) — intent expiry.
- `intent_claim_pub`: Ed25519 public key (base64 raw standard). Per-intent authorization. See [Intent Claim](INTENT-CLAIM.md).
- `encrypted_payload`: age-encrypted inner request payload (see §3.3). Opaque to the broker.

**Plugin build steps:**

1. Generate ephemeral age X25519 identity (keypair). *(Ephemeral keys are always X25519 in age, regardless of the inner recipient type.)*
2. Generate Ed25519 intent claim keypair.
3. Build inner request payload: `{nonce, outer_hash, stanzas, ephemeral_key, intent_claim_secret}`.
4. `age.Encrypt(inner, unwrap_recipient)` → `encrypted_payload`.
5. Build outer envelope with `version`, `action`, `intent_id`, `tag`, `expires_at`, `intent_claim_pub`, `encrypted_payload`.
6. POST to relay endpoint.

### 4.2. Processing (relay-server)

1. `age.Decrypt(encrypted_payload, identity)` → inner request payload JSON.
2. Parse inner payload.
3. Check `expires_at` from the outer fields — reject if in the past.
4. Recompute `SHA-256("version.action.intent_id.tag.expires_at.intent_claim_pub")` from the outer fields.
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

## 5. Async Flow (Broker)

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
  "tag": "QPg24ggKk7xKd2t3c5rL9A",
  "expires_at": 1715350800,
  "intent_claim_pub": "<base64: Ed25519 public key>",
  "encrypted_payload": "<base64: age-encrypted blob>"
}
```

**Inner request payload** — identical to §3.3. Contains `{nonce, outer_hash, stanzas, ephemeral_key, intent_claim_secret}`, age-encrypted to the operator's `unwrap_recipient`.

- `intent_id` is **plugin-generated**: 16 random bytes, hex-encoded (32 chars).
- `expires_at` is the plugin-defined intent expiry (Unix timestamp, seconds).
- `encrypted_payload` is opaque to the broker.

**Response:** `202 Accepted` with empty body `{}`.

### 5.3. Pull (operator → broker)

```json
{
  "version": 1,
  "action": "pull",
  "tag": "QPg24ggKk7xKd2t3c5rL9A"
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
        "tag": "QPg24ggKk7xKd2t3c5rL9A",
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
4. Recompute `SHA-256("version.action.intent_id.tag.expires_at.intent_claim_pub")` from the outer fields.
5. Compare against `outer_hash` — mismatch = broker tampered = reject the intent.
6. Extract `stanzas`, `ephemeral_key`, and `intent_claim_secret`.
7. Reconstruct Ed25519 private key from `intent_claim_secret`.
8. `identity.Unwrap(stanzas)` → file key.
9. Build inner response payload: `{nonce, outer_hash, file_key}` where `outer_hash = SHA-256("1.fulfill".intent_id)`.
10. `age.Encrypt(inner_response, ephemeral_recipient)` → response `encrypted_payload`.
11. Sign `"{version}.fulfill.{intent_id}.{SHA-256(encrypted_payload)}"` with claim private key → `intent_claim_sig`.

### 5.5. Fulfill (operator → broker)

```json
{
  "version": 1,
  "action": "fulfill",
  "intent_id": "a3f1...",
  "intent_claim_sig": "<base64: Ed25519 signature>",
  "encrypted_payload": "<base64: age-encrypted inner response>"
}
```

The `encrypted_payload` contains the inner response payload (§3.4) age-encrypted to the plugin's ephemeral recipient from the original request. The `intent_claim_sig` signs the canonical string `"{version}.fulfill.{intent_id}.{SHA-256(encrypted_payload)}"` — see [Intent Claim](INTENT-CLAIM.md).

**Response:** `200 OK` on success, `404` if `intent_id` is unknown, `409` if already terminal, `403` if `intent_claim_sig` is invalid.

### 5.6. Reject (operator → broker)

```json
{
  "version": 1,
  "action": "reject",
  "intent_id": "a3f1...",
  "intent_claim_sig": "<base64: Ed25519 signature>"
}
```

**Response:** `200 OK` on success, `404`/`409` as for `fulfill`, `403` if `intent_claim_sig` is invalid.

### 5.7. Poll (plugin → broker)

Poll requests are authenticated with `intent_claim_sig` — proving the caller is the intent creator.

```json
{
  "version": 1,
  "action": "poll",
  "intent_id": "a3f1...",
  "intent_claim_sig": "<base64: Ed25519 sig over '1.poll.{intent_id}.{SHA-256(\"\")}'>"
}
```

| Status | Body | Meaning |
|---|---|---|
| `200 OK` | `{"status":"pending"}` | Keep polling |
| `200 OK` | `{"status":"fulfilled", "response": {...}}` | Plugin extracts `encrypted_payload` from response, decrypts with ephemeral identity, verifies outer_hash |
| `200 OK` | `{"status":"rejected", "response": {...}}` | Operator declined; `response` contains verbatim operator reject body; plugin returns failure |
| `400` | `{"error":"missing intent_claim_sig"}` | Poll request missing required signature |
| `403` | `{"error":"invalid_claim_sig"}` | Signature verification failed — caller is not the intent creator |
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
  │  2. Generate intent claim     │                                │
  │     keypair (Ed25519)         │                                │
  │  3. Build inner payload       │                                │
  │     (includes claim secret)   │                                │
  │  4. age.Encrypt(inner,        │                                │
  │     unwrap_recipient)         │                                │
  │                               │                                │
  │  POST {action:"unwrap",       │                                │
  │   intent_id, tag, expires_at, │                                │
  │   intent_claim_pub,           │                                │
  │   encrypted_payload}          │                                │
  │ ─────────────────────────────►│                                │
  │                               │  5. Store intent:              │
  │                               │     intent_id, tag,            │
  │                               │     expires_at,                │
  │                               │     intent_claim_pub,          │
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
  │                               │                6. age.Decrypt(encrypted_payload, identity)
  │                               │                7. Check expires_at
  │                               │                8. Verify outer_hash
  │                               │                9. Extract stanzas + ephemeral_key
  │                               │                   + intent_claim_secret
  │                               │               10. identity.Unwrap(stanzas) → file_key
  │                               │               11. Build InnerResponsePayload:
  │                               │                   {nonce, outer_hash, file_key}
  │                               │               12. age.Encrypt(inner, ephemeral_recipient)
  │                               │               13. Sign with intent_claim_secret
  │                               │                   → intent_claim_sig
  │                               │                                │
  │                               │  POST {action:"fulfill",       │
  │                               │   intent_id,                   │
  │                               │   intent_claim_sig,            │
  │                               │   encrypted_payload}           │
  │                               │ ◄──────────────────────────────│
  │                               │                                │
  │                               │  14. Verify intent_claim_sig   │
  │                               │      against stored pub key    │
  │                               │  15. Store verbatim fulfill    │
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
  │ 16. Parse response →          │                                │
  │     extract encrypted_payload │                                │
  │ 17. age.Decrypt(             │                                │
  │     encrypted_payload,        │                                │
  │     eph_identity)             │                                │
  │ 18. Verify outer_hash         │                                │
  │     == SHA-256("1.fulfill"  │                                │
  │       .intent_id)            │                                │
  │ 19. Extract file_key          │                                │
  │ 20. Discard ephemeral keypair │                                │
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
  │                               │         2. Extract claim secret│
  │                               │         3. Unwrap fails        │
  │                               │            (no matching key)   │
  │                               │         4. Sign reject with    │
  │                               │            claim secret        │
  │                               │                                │
  │                               │  POST {action:"reject",        │
  │                               │   intent_id,                   │
  │                               │   intent_claim_sig}            │
  │                               │ ◄──────────────────────────────│
  │                               │                                │
  │                               │  5. Verify intent_claim_sig    │
  │                               │                                │
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
- **Sealed action binding** — every `action` value (fulfill, reject, etc.) carries an `encrypted_payload` with a verified outer hash. No cleartext-only envelopes are trusted. This prevents the broker from forging actions (e.g., fabricating a reject to deny service). See §3.5.
- **Intent claim authorization** — per-intent Ed25519 keypair ensures only the party who decrypted the inner payload (legitimate operator) can fulfill or reject. The broker holds only the public key and verifies signatures. See [Intent Claim](INTENT-CLAIM.md).
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
intent_claim_pub    ✓ (generates it)    ✓ (stores + verifies sig) ✓ (verifies via hash)
intent_claim_secret ✓ (encrypts it)     ✗ (opaque)          ✓ (decrypts, signs)
intent_claim_sig    — (plugin doesn't sign) ✓ (verifies it)  ✓ (signs it)
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

#### Fabricated fulfill/reject (mitigated by Intent Claim)
- Even if an attacker can send HTTP requests to the broker, they cannot fabricate a valid `fulfill` or `reject` because the broker requires a valid `intent_claim_sig`.
- The Ed25519 private key (seed) is inside the age-encrypted inner payload — only the legitimate operator who decrypted it can sign.
- See [Intent Claim](INTENT-CLAIM.md) for the full design.

#### Operator response forgery
- The operator age-encrypts `encrypted_payload` to the plugin's ephemeral recipient from the original request.
- Only a holder of the matching ephemeral identity (the plugin) can decrypt it.
- A forged or tampered response fails `age.Decrypt`. The plugin MUST treat decryption failure as terminal.
- The response includes `outer_hash = SHA-256(version.action.intent_id)` — the plugin verifies this to ensure the response matches the original version, action, and intent.

### 6.5. What the Broker Can Still Do

| Attack | Impact | Mitigation |
|---|---|---|
| Drop intents (DoS) | Plugin times out | Plugin's local timeout bounds the loss |
| Return `rejected` instead of `fulfilled` | Plugin fails decryption | DoS only — no cryptographic compromise. Broker cannot forge a valid reject (requires `intent_claim_sig`). |
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
| `-stream` | — | Respond with SSE (Server-Sent Events) instead of JSON. Useful for long-running unwrap operations (YubiKey touch, approval flows) |
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
  --tag QPg24ggKk7xKd2t3c5rL9A \
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
│   ├── claim.go                        # Intent Claim: Ed25519 keypair generation, signing, verification
│   ├── envelope.go                     # Age response encryption: SealResponse, OpenResponse
│   ├── recipient_parse.go              # Plugin-agnostic recipient/identity parsing dispatch
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
│   ├── claim_test.go                  # Intent Claim tests (Ed25519 sign/verify, round-trip, tampering)
│   ├── envelope_test.go               # Envelope seal/open unit tests (age encryption)
│   ├── async_test.go                  # Async (broker) tests (broker protocol, E2E)
│   ├── integration_test.go            # Integration tests (age.Encrypt/Decrypt E2E, broker blindness, tampering)
│   ├── e2e_test.go                    # E2E tests (real binaries, full user flow)
│   └── e2e_plugin_test.go             # E2E tests with non-X25519 plugin recipient (age-plugin-stub)
├── cmd/
│   ├── age-plugin-relay/
│   │   └── main.go                     # Plugin binary: flags, --generate, HandleRecipient/Identity
│   ├── relay-server/
│   │   └── main.go                     # Sync relay server: decrypt, verify, unwrap, seal
│   ├── relay-broker/
│   │   └── main.go                     # Zero-trust broker: stores/forwards opaque encrypted payloads
│   └── relay-operator/
│       └── main.go                     # Operator CLI: pull, decrypt, verify, unwrap, seal, fulfill/reject
│   age-plugin-stub/
│       └── main.go                     # Minimal test plugin binary (wraps X25519 under "stub" type for E2E tests)
├── docs/
│   ├── ARCHITECTURE.md                 # This file — authoritative technical reference
│   ├── ASYNC-WIRE-FORMAT.md            # Async wire format reference
│   ├── SYNC-WIRE-FORMAT.md             # Sync wire format reference
│   ├── INTENT-CLAIM.md                 # Intent Claim design (per-intent Ed25519 authorization)
│   └── TESTING.md                      # Test matrix (unit, integration, E2E)
└── README.md                           # Usage, installation, quick start
```

### Dependencies

- [`filippo.io/age`](https://pkg.go.dev/filippo.io/age) v1.3.1 — age types (`Recipient`, `Identity`, `Stanza`), recipient parsing, encryption/decryption
- [`filippo.io/age/plugin`](https://pkg.go.dev/filippo.io/age/plugin) — Plugin framework, Bech32 encoding helpers
- [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto) — Cryptographic primitives
- [`gopkg.in/yaml.v3`](https://pkg.go.dev/gopkg.in/yaml.v3) — Config file parsing
- `crypto/ed25519` (Go stdlib) — Intent Claim signing and verification

---

## 9. Testing

See [docs/TESTING.md](TESTING.md) for the complete test matrix.
