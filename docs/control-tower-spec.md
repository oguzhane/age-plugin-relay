# Control Tower — Async Relay Specification

Authoritative design for the async (brokered) decryption flow in `age-plugin-relay`. The async flow extends the existing sync flow with three new actions, a single response-code branch, and a stateful but zero-trust broker.

---

## 1. Goals

- Support approval-driven remote unwrap, where the holder of the operator identity is not online to answer synchronously.
- Add async without a parallel protocol: same endpoint, same request format, same crypto primitives.
- Treat the broker as **zero-trust** infrastructure. The broker stores and forwards opaque, authenticated payloads. It holds no key material, makes no policy decisions, and emits no metadata.

---

## 2. Inherited from the sync flow (unchanged)

| Property | Source |
|---|---|
| Plugin holds zero key material | Existing plugin design |
| Tag = `SHA-256(inner_recipient_string)[:16]` for routing | Existing identity format |
| HMAC-SHA256 over `timestamp.nonce.[ephemeral_key.]body` for authenticity + replay protection | Existing `hmac.go` |
| NaCl box ephemeral X25519 envelope for response E2E encryption | Existing `envelope.go` |
| `action`-driven, version-tagged JSON HTTP contract | Existing wire format |
| File-key confidentiality via age-wrapped stanzas | Existing recipient model |
| Trust boundary = the holder of the operator identity | Existing model |

The async flow adds nothing to these — it reuses every primitive verbatim.

---

## 3. Actors

| Actor | Role | Holds |
|---|---|---|
| **Plugin** | Submits unwrap intents, polls for results | `hmac_key` (shared with operator), broker `auth_token` |
| **Broker** | Stateful queue and forwarder; zero-trust | broker `auth_token` only |
| **Operator** | Polls for pending intents, unwraps locally, fulfills or rejects | age private key, `hmac_key` (shared with plugin), broker `auth_token` |

The broker has no `hmac_key`, no age identity, no view into the cryptographic content of any intent.

---

## 4. Sync vs Async — single endpoint, response-code branching

A relay endpoint may choose to answer an `unwrap` request synchronously (when the operator identity is online) or asynchronously (queue for later). The plugin learns which it got from the HTTP status code:

| Status | Body | Plugin behavior |
|---|---|---|
| `200 OK` | `{"file_key": ...}` or `{"encrypted_file_key": ...}` | Sync result — done |
| `202 Accepted` | `{}` | Async — switch to polling using the plugin's own `intent_id` |
| `409 Conflict` | `{"error":"duplicate_intent"}` | Retry with a freshly generated `intent_id` |
| `4xx/5xx` | as today | Errors |

The plugin does not need to know whether the endpoint is a `relay-server` or a `relay-broker`. The protocol is uniform; behavior is response-driven.

---

## 5. Wire protocol

All messages are JSON over `POST` to a single endpoint URL. All authenticated messages carry the existing HMAC headers (`X-Relay-Timestamp`, `X-Relay-Nonce`, optionally `X-Relay-Ephemeral-Key`, `X-Relay-Signature`). Bearer auth uses `Authorization: Bearer <auth_token>`.

### 5.1. Plugin → Broker

#### `unwrap` (extended; sync-compatible)

```json
{
  "version": 1,
  "action": "unwrap",
  "intent_id": "a3f12c4e8b9d6f0a1b2c3d4e5f6a7b8c",
  "stanzas": [
    { "type": "X25519", "args": ["..."], "body": "..." }
  ]
}
```

- `intent_id` is **plugin-generated**: 16 random bytes, hex-encoded (32 chars). Covered by the HMAC.
- HMAC headers as today.

Responses: see §4.

#### `poll`

```json
{
  "version": 1,
  "action": "poll",
  "intent_id": "a3f1..."
}
```

- HMAC over `timestamp.nonce.body`. No `ephemeral_key` here — that was bound at submit time.

| Status | Body | Meaning |
|---|---|---|
| `200 OK` | `{"status":"pending"}` | Keep polling |
| `200 OK` | `{"status":"fulfilled", "encrypted_file_key": "..."}` | Plugin opens with its ephemeral private key |
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

- HMAC signed with the operator's `hmac_key`. (HMAC here authenticates the operator's request to the broker; not strictly required for E2E security, but consistent with the rest of the protocol.)

Response — the full plugin-signed payload, verbatim, for each pending intent matching the tag:

```json
{
  "intents": [
    {
      "intent_id": "a3f1...",
      "request": {
        "version": 1,
        "action": "unwrap",
        "intent_id": "a3f1...",
        "stanzas": [...]
      },
      "plugin_headers": {
        "X-Relay-Timestamp": "...",
        "X-Relay-Nonce": "...",
        "X-Relay-Ephemeral-Key": "...",
        "X-Relay-Signature": "..."
      }
    }
  ]
}
```

The operator MUST verify the plugin's HMAC over `request` + `plugin_headers` before acting on any intent. The broker is not trusted to have verified anything.

The response contains **no broker-asserted metadata** — no `created_at`, no `expires_at`, no broker timestamps. Any timing the operator needs is derived from the plugin's signed `X-Relay-Timestamp`.

#### `fulfill`

```json
{
  "version": 1,
  "action": "fulfill",
  "intent_id": "a3f1...",
  "encrypted_file_key": "<base64: serverPub(32) || nonce(24) || NaCl box ciphertext>"
}
```

- HMAC signed with operator's `hmac_key`.
- `encrypted_file_key` format: identical to the existing sync `encrypted_response` envelope (`serverPub || nonce || ciphertext`), sealed via NaCl `box.Seal` to the plugin's `X-Relay-Ephemeral-Key` from the original request.

Response: `200 OK` on success, `404` if `intent_id` is unknown, `409` if already terminal.

#### `reject`

```json
{
  "version": 1,
  "action": "reject",
  "intent_id": "a3f1..."
}
```

- HMAC signed with operator's `hmac_key`.

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
- Operator-side: existing nonce dedup + 5-minute timestamp window over the plugin's HMAC.
- Broker-side: none required. Replay of a captured `unwrap` to the broker either collides (`409`) or, if the original was already cleaned up, creates a duplicate intent that the operator will reject on nonce dedup.

---

## 9. Security model

### 9.1. Threat: broker compromise
- Broker holds no `hmac_key` and no age identity. It cannot forge plugin requests or operator responses.
- Broker can read `tag` (already public; identical to sync flow's wire format) and stanzas (already age-encrypted to the operator's identity; broker cannot decrypt).
- Broker can substitute neither `intent_id` nor `ephemeral_pub` — both are covered by the plugin's HMAC.
- Broker can DoS (drop intents, return `404`, return `409` falsely). Detected by the plugin's local timeout.

### 9.2. Threat: ephemeral key substitution
- The plugin's `X-Relay-Ephemeral-Key` is bound by the HMAC over `timestamp.nonce.ephemeral_key.body`.
- The broker forwards plugin headers verbatim; the operator re-verifies the HMAC.
- A substituted ephemeral key invalidates the HMAC. The operator MUST refuse to fulfill on HMAC failure.

### 9.3. Threat: fabricated intent
- The broker (or any holder of the broker `auth_token`) can submit `unwrap` payloads.
- Without `hmac_key`, those payloads have no valid plugin HMAC. The operator rejects them on pull-side verification.

### 9.4. Threat: operator response forgery
- The operator seals `encrypted_file_key` via NaCl box to the plugin's ephemeral pubkey from the original request.
- Only a holder of the matching ephemeral private key (the plugin) can open the box.
- A forged or tampered response fails `box.Open`. The plugin MUST treat open failure as terminal.

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
    url: https://broker.example:8443/unwrap
    auth_token: broker-bearer-token          # required: broker access
    hmac_key: shared-with-operator-only      # required: E2E with operator
    encrypted_response: true                 # required: ephemeral envelope
    timeout: 10m                             # plugin's local deadline
    poll_interval: 2s                        # optional; default min(timeout/60, 5s)
```

No `flow:` field. The plugin discovers async via the `202` response.

### 10.2. Operator (new binary)

```yaml
broker:
  url: https://broker.example:8443/unwrap
  auth_token: broker-bearer-token            # same shared token as plugin (per §9.5)
hmac_key: shared-with-operator-only          # same as plugin's
identity: /path/to/age/identity.txt
tag: QPg24g
pull_interval: 30s
```

### 10.3. Broker

```yaml
addr: :8443
auth_token: broker-bearer-token              # single shared token
max_ttl: 10m                                 # internal cleanup deadline
```

The broker has no `hmac_key`, no identity file, no notion of `flow`.

---

## 11. Repo changes

### New files
- `cmd/relay-broker/main.go` — broker binary (single endpoint, action-based routing, Bearer auth only)
- `cmd/relay-operator/main.go` — operator CLI (pull, HMAC verify, unwrap, seal, fulfill/reject, nonce dedup)
- `relay/broker/queue.go` — in-memory intent queue with TTL sweep
- `relay/broker/types.go` — `Intent`, `Status`, `PluginHeaders`, `PullIntent`, `PullResponse`, `PollResponse`, `AsyncAccepted`
- `relay/broker/queue_test.go` — 18 broker queue unit tests
- `relay/async_test.go` — 12 async flow tests (E2E, rejection, 409/404, polling loop, security, HMAC tamper detection)

### Modified files
- `relay/client.go` — added `intent_id`/`tag`/`encrypted_file_key` to `RelayRequest`; `PostToRelay` handles `202` → `pollForResult` loop, `409` conflict; exported `GenerateIntentID`; added `asyncPollResponse` struct
- `relay/config.go` — added `PollInterval` field to `RemoteConfig` and `PollIntervalDuration()` method (default `min(timeout/60, 5s)`, floor 500ms)

### Unchanged files
- `relay/hmac.go`, `relay/envelope.go`, `relay/identity.go`, `relay/recipient.go`, `relay/encoding.go`

---

## 12. Build order

1. `relay/broker/types.go` — internal types
2. `relay/broker/queue.go` — in-memory queue + TTL sweep
3. `relay/broker/queue_test.go` — 18 queue unit tests
4. `cmd/relay-broker/main.go` — HTTP handlers for `unwrap` (queue-only branch), `poll`, `pull`, `fulfill`, `reject`
5. `cmd/relay-operator/main.go` — operator CLI with pull loop, E2E HMAC verification, unwrap, seal, fulfill/reject
6. `relay/client.go` — async branch: `intent_id` generation, `202`/`409`/`404` handling, polling loop
7. `relay/config.go` — `poll_interval` field and `PollIntervalDuration()` method
8. `relay/async_test.go` — 12 async flow tests (E2E, security, tamper detection)

---

## 13. Summary

The async flow is the sync flow plus a queue and a CLI. The plugin generates its own `intent_id`, chooses its own poll cadence, and discovers async through a `202` response. The broker stores opaque HMAC-signed payloads keyed by plugin-supplied IDs, indexed by tag, and emits no policy or metadata. The operator pulls, verifies the plugin's HMAC end-to-end, unwraps locally, and fulfills with a NaCl-sealed file key. Every cryptographic primitive is inherited from the existing sync implementation.
