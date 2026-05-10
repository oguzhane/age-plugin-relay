# Control Tower — Async Relay Specification

Authoritative design for the async (brokered) decryption flow in `age-plugin-relay`. The async flow extends the existing sync flow with three new actions, a single response-code branch, and a stateful but zero-trust broker.

---

## 1. Goals

- Support approval-driven remote unwrap, where the holder of the operator identity is not online to answer synchronously.
- Add async without a parallel protocol: same endpoint, same request format, same crypto primitives.
- Treat the broker as **zero-trust** infrastructure. The broker stores and forwards opaque, encrypted payloads. It holds no key material, makes no policy decisions, and emits no metadata.

---

## 2. Inherited from the sync flow (unchanged)

| Property | Source |
|---|---|
| Plugin holds zero key material | Existing plugin design |
| Tag = `SHA-256(inner_recipient_string)[:16]` for routing | Existing identity format |
| Encrypted payloads (age-encrypted requests, age-encrypted responses) for E2E confidentiality | `payload.go`, `envelope.go` |
| Outer hash binding encrypted payload to cleartext routing fields | `payload.go` |
| `action`-driven, version-tagged JSON HTTP contract | Existing wire format |
| File-key confidentiality via age-wrapped stanzas | Existing recipient model |
| Trust boundary = the holder of the operator identity | Existing model |

The async flow adds nothing to these — it reuses every primitive verbatim.

---

## 3. Actors

| Actor | Role | Holds |
|---|---|---|
| **Plugin** | Submits encrypted unwrap intents, polls for results | `unwrap_recipient` (for age encryption), broker `auth_token` |
| **Broker** | Stateful queue and forwarder; zero-trust | broker `auth_token` only |
| **Operator** | Polls for pending intents, decrypts, unwraps locally, seals response, fulfills or rejects | age private key, broker `auth_token` |

The broker has no age identity, no view into the cryptographic content of any intent.

---

## 4. Sync vs Async — single endpoint, response-code branching

A relay endpoint may choose to answer an `unwrap` request synchronously (when the operator identity is online) or asynchronously (queue for later). The plugin learns which it got from the HTTP status code:

| Status | Body | Plugin behavior |
|---|---|---|
| `200 OK` | `{"encrypted_payload": ...}` | Sync result — done |
| `202 Accepted` | `{}` | Async — switch to polling using the plugin's own `intent_id` |
| `409 Conflict` | `{"error":"duplicate_intent"}` | Retry with a freshly generated `intent_id` |
| `4xx/5xx` | as today | Errors |

The plugin does not need to know whether the endpoint is a `relay-server` or a `relay-broker`. The protocol is uniform; behavior is response-driven.

---

## 5. Wire protocol

All messages are JSON over `POST` to a single endpoint URL. Bearer auth uses `Authorization: Bearer <auth_token>`. All request payloads containing stanzas are encrypted end-to-end via `encrypted_payload`.

### 5.1. Plugin → Broker

#### `unwrap` (extended; sync-compatible)

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

- `intent_id` is **plugin-generated**: 16 random bytes, hex-encoded (32 chars).
- `encrypted_payload` contains the age-encrypted inner payload (stanzas, ephemeral key, outer hash, nonce). Opaque to the broker.
- `expires_at` is the plugin-defined intent expiry (Unix timestamp, seconds).

Responses: see §4.

#### `poll`

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
| `200 OK` | `{"status":"fulfilled", "encrypted_payload": "..."}` | Plugin decrypts with its ephemeral identity, verifies outer_hash |
| `200 OK` | `{"status":"rejected"}` | Operator declined; plugin returns failure |
| `404` | `{"error":"unknown_intent"}` | Expired, never existed, or broker forgot — plugin treats as failure |

The broker does not distinguish "expired" from "never existed." Both collapse to `404`.

### 5.2. Operator → Broker

#### `pull`

```json
{
  "version": 1,
  "action": "pull",
  "tag": "QPg24g"
}
```

Response — the full request, verbatim, for each pending intent matching the tag:

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

The operator MUST:
1. `age.Decrypt(encrypted_payload, identity)` to obtain the inner payload.
2. Verify `outer_hash` matches the recomputed `SHA-256("version.action.intent_id.tag.expires_at")`.
3. Check `expires_at` — reject if in the past.
4. Extract stanzas and ephemeral key, proceed with unwrap.

The response contains **no broker-asserted metadata** — no `created_at`, no broker timestamps.

#### `fulfill`

```json
{
  "version": 1,
  "action": "fulfill",
  "intent_id": "a3f1...",
  "encrypted_payload": "<base64: age-encrypted inner response>"
}
```

- `encrypted_payload` format: `age.Encrypt` of `{nonce, outer_hash, file_key}` to the plugin's ephemeral recipient from the original request.

Response: `200 OK` on success, `404` if `intent_id` is unknown, `409` if already terminal.

#### `reject`

```json
{
  "version": 1,
  "action": "reject",
  "intent_id": "a3f1..."
}
```

Response: `200 OK` on success, `404`/`409` as for `fulfill`.

---

## 6. State machine

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

---

## 7. Polling cadence

The broker emits **no flow-control hints**. Cadence is a client-side concern.

### Plugin
- Configurable per-remote via `poll_interval` in `relay-config.yaml`.
- Default: `min(timeout / 60, 5s)`.
- The plugin polls until it observes `fulfilled`, `rejected`, `404`, or its local `timeout` elapses.

### Operator
- Configurable via the operator binary's flags (e.g., `--pull-interval 30s`).
- No coordination with the plugin or broker required.

---

## 8. Idempotency, replay, recovery

### 8.1. `intent_id` collisions
- The broker enforces uniqueness: a second `unwrap` with an existing `intent_id` returns `409 Conflict`.
- Plugins MUST generate a fresh random `intent_id` on retry-after-`409`.

### 8.2. Network failure on submit
If the plugin's `unwrap` POST fails before receiving a response, the plugin SHOULD first `poll` with the existing `intent_id` to learn the broker's view:
- `200 OK { status: pending | fulfilled | rejected }` → continue normally.
- `404 unknown_intent` → broker did not store the intent; safe to retry with a fresh `intent_id`.

Plugins MUST NOT blindly retry `unwrap` with the same `intent_id` — that path returns `409` and obscures whether the original submission succeeded.

### 8.3. Replay protection
- Encrypted payload: age encryption uses unique ephemeral keys per encryption. Replaying a captured `unwrap` to the broker either collides (`409`) or, if the original was already cleaned up, creates a duplicate intent that the operator verifies via `expires_at` and outer hash.
- Response payload: age encryption uses unique ephemeral keys. Replaying a captured `fulfill` to a different intent fails because `outer_hash` inside the encrypted response is bound to the original `intent_id`.

---

## 9. Security model

### 9.1. Threat: broker compromise
- Broker holds no age identity. It cannot decrypt `encrypted_payload` and cannot forge valid encrypted payloads.
- Broker can read `tag` (already public; routing metadata) and `intent_id` (random, no semantic content).
- Broker cannot read stanzas, ephemeral keys, or file keys — all inside `encrypted_payload`.
- Broker cannot substitute or tamper with any outer field — `outer_hash` inside the encrypted payload detects this.
- Broker can DoS (drop intents, return `404`, return `409` falsely). Detected by the plugin's local timeout.

### 9.2. Threat: ephemeral key substitution
- The plugin's ephemeral public key is inside the age-encrypted inner payload. The broker cannot read or modify it.
- A substituted ephemeral key would require forging a valid age-encrypted payload, which requires the operator's private key.

### 9.3. Threat: fabricated intent
- Without the operator's age recipient public key, an attacker cannot create a valid `encrypted_payload` that the operator can decrypt.
- Even with the public key, the attacker cannot create a payload containing valid age-wrapped stanzas (those require the correct file key).

### 9.4. Threat: operator response forgery
- The operator age-encrypts `encrypted_payload` to the plugin's ephemeral recipient from the original request.
- Only a holder of the matching ephemeral identity (the plugin) can decrypt it.
- A forged or tampered response fails `age.Decrypt`. The plugin MUST treat decryption failure as terminal.
- The response includes `outer_hash = SHA-256(intent_id)` — the plugin verifies this to ensure the response matches the original intent.

### 9.5. Known limitations
- **Metadata leakage to the broker.** The broker observes `tag` values and per-tag traffic timing. Mitigation: a future "blind tag index" extension can replace `tag` with `HMAC(operator_secret, tag)`. Out of scope for this spec.
- **Single shared `auth_token`.** All plugins and operators share one broker token. Compromise of any participant exposes broker access for all. Per-actor tokens are a future hardening step.
- **Broker DoS / denial-of-service.** A malicious broker can silently drop intents. The plugin's local timeout bounds the loss; cryptographic correctness is unaffected.

---

## 10. Configuration

### 10.1. Plugin (`relay-config.yaml`)

```yaml
remotes:
  approved-server:
    url: https://broker.example:8443
    unwrap_recipient: age1abc...             # required: age recipient of the unwrapper
    auth_token: broker-bearer-token          # required: broker access
    timeout: 10m                             # plugin's local deadline
    poll_interval: 2s                        # optional; default min(timeout/60, 5s)
```

No `flow:` field. The plugin discovers async via the `202` response.

### 10.2. Operator (CLI binary)

```bash
relay-operator \
  --broker https://broker.example:8443 \
  --identity /path/to/age/identity.txt \
  --tag QPg24g \
  --auth-token broker-bearer-token \
  --pull-interval 30s
```

### 10.3. Broker

```bash
relay-broker -addr :8443 -auth-token broker-bearer-token -max-ttl 10m
```

The broker has no age identity, no notion of `flow`.

---

## 11. Repo changes

### New files
- `cmd/relay-broker/main.go` — broker binary (single endpoint, action-based routing, Bearer auth only)
- `cmd/relay-operator/main.go` — operator CLI (pull, decrypt, verify, unwrap, seal, fulfill/reject)
- `relay/broker/queue.go` — in-memory intent queue with TTL sweep
- `relay/broker/types.go` — `Intent`, `Status`, `PullIntent`, `PullResponse`, `PollResponse`, `AsyncAccepted`
- `relay/broker/queue_test.go` — broker queue unit tests
- `relay/payload.go` — encrypted payload types and functions
- `relay/async_test.go` — async flow tests (Control Tower protocol E2E, broker blindness, tamper detection)

### Modified files
- `relay/client.go` — `PostToRelay` handles `202` → `pollForResult` loop, `409` conflict; always builds encrypted payload; exported `GenerateIntentID`
- `relay/config.go` — `UnwrapRecipient` field, `PollInterval` field and `PollIntervalDuration()` method
- `relay/envelope.go` — `SealResponse`/`OpenResponse` with structured inner JSON
- `relay/identity.go` — passes `UnwrapRecipient` to `PostToRelay`

### Unchanged files
- `relay/encoding.go`, `relay/errors.go`, `relay/recipient.go`

---

## 12. Build order

1. `relay/payload.go` — inner payload types, encrypt/decrypt, outer hash
2. `relay/envelope.go` — `SealResponse`/`OpenResponse` with structured inner
3. `relay/broker/types.go` — internal types
4. `relay/broker/queue.go` — in-memory queue + TTL sweep
5. `relay/broker/queue_test.go` — queue unit tests
6. `cmd/relay-broker/main.go` — HTTP handlers for `unwrap`, `poll`, `pull`, `fulfill`, `reject`
7. `cmd/relay-operator/main.go` — operator CLI with pull loop, decrypt, verify, unwrap, seal, fulfill/reject
8. `relay/client.go` — encrypted payload construction, `202`/`409`/`404` handling, polling loop
9. `relay/config.go` — `unwrap_recipient` and `poll_interval` fields
10. `relay/async_test.go` — async flow tests

---

## 13. Summary

The async flow is the sync flow plus a queue and a CLI. The plugin generates its own `intent_id`, chooses its own poll cadence, and discovers async through a `202` response. The broker stores opaque encrypted payloads keyed by plugin-supplied IDs, indexed by tag, and emits no policy or metadata. The operator pulls, decrypts the age-encrypted payload, verifies the outer hash, unwraps locally, and fulfills with an age-encrypted response. Every cryptographic primitive is inherited from the existing sync implementation. The broker is blind — it never sees stanzas, ephemeral keys, or file keys.
