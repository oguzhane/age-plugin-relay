I created the feature branch: `feature/async-relay-broker-design-summary`

I can’t save the markdown file in the repo from this turn, but here’s the exact content to put into something like `docs/async-relay-broker-design.md` on that branch:

```markdown
# Async Relay Broker Design Summary

## Goal

Design an asynchronous, pull-based decryption flow where the plugin does not wait on a long-lived HTTP response and a broker acts as a bridge between the plugin and the human-operated key holder.

The main objective is to support approval-driven remote unwrap/decryption without requiring direct synchronous communication between the plugin and the operator.

---

## Agreed Naming

### Actors

- **Plugin**
  - Keep this name as-is because it is already clear in the current project context.
- **Relay Broker**
  - The intermediary component that receives requests, stores them, and brokers communication asynchronously.
- **Operator**
  - The human-operated client/tool that polls for pending work, approves or rejects it, and performs the unwrap operation locally.

---

## High-Level Flow

The system uses a **pull-based asynchronous workflow**:

1. The **Plugin** submits an unwrap intent to the **Relay Broker**.
2. The **Relay Broker** accepts the request and stores it as `pending`.
3. The **Plugin** receives `202 Accepted` with an intent ID and polling hint.
4. The **Plugin** periodically polls the **Relay Broker** for status.
5. The **Operator** polls the **Relay Broker** for pending intents filtered by identity fingerprint/tag.
6. The **Operator** unwraps the request locally using their private key.
7. The **Operator** fulfills or rejects the intent.
8. The **Plugin** eventually polls the final result and completes decryption locally.

This removes the need for direct synchronous communication between the plugin and the operator.

---

## Core Principles

### 1. One intent per unwrap
Each unwrap request creates exactly one intent.

### 2. Pull-based communication
Both the Plugin and the Operator poll the Relay Broker.

### 3. Explicit rejection supported
The Operator can explicitly reject an intent.

### 4. Plugin controls requested expiry
The Plugin specifies the desired expiry duration.
The Relay Broker enforces a maximum TTL and uses the smaller of:
- requested expiry
- broker maximum expiry

### 5. Fixed retry interval
The Relay Broker returns a fixed `retry_after` value.

### 6. Operator filters by fingerprint/tag
The Operator discovers only intents relevant to their identity by filtering on fingerprint/tag.

### 7. Plugin timeout config drives expiry request
The Plugin’s configured timeout is used as the requested expiry duration.

---

## Security Requirement

The **Relay Broker must never see the plaintext file key or any sensitive key material**.

### Implication

The Relay Broker is a **blind intermediary**:
- it stores encrypted stanzas
- it stores the plugin ephemeral public key
- it stores the encrypted result returned by the Operator
- it never sees the decrypted file key in plaintext

---

## Payload Clarification

### Plugin -> Relay Broker
The Plugin sends:
- action: `unwrap`
- tag/fingerprint
- stanzas
- plugin ephemeral public key
- requested expiry duration

### Relay Broker -> Operator
The Relay Broker returns:
- intent metadata
- tag/fingerprint
- stanzas
- plugin ephemeral public key
- expiry information

### Operator -> Relay Broker
The Operator sends:
- either `reject`
- or `fulfill` with `encrypted_file_key`

### Relay Broker -> Plugin
The Relay Broker returns:
- pending / fulfilled / rejected / expired
- if fulfilled, the encrypted file key blob

---

## End-to-End Encryption Model

To ensure the Relay Broker cannot read the file key:

1. The **Plugin** generates an ephemeral X25519 keypair.
2. The **Plugin** includes the ephemeral public key when creating the intent.
3. The **Operator** unwraps the stanza locally and obtains the plaintext file key.
4. The **Operator** encrypts the file key to the Plugin’s ephemeral public key.
5. The **Operator** sends only the encrypted file key to the Relay Broker.
6. The **Plugin** polls and decrypts the result locally using its ephemeral private key.

### Result
The Relay Broker only stores opaque ciphertext and cannot decrypt it.

---

## Sequence Diagram

```text
Plugin                        Relay Broker                        Operator CLI
  │                                │                                │
  │── POST /intents ──────────────▶│                                │
  │   {action: "unwrap",           │                                │
  │    tag: "QPg24g",              │  min(requested, broker_max)    │
  │    stanzas: [...],             │  → effective expiry            │
  │    ephemeral_pub: "...",       │                                │
  │    expires_in: 300}            │  store intent, start TTL       │
  │◀── 202 ───────────────────────│                                │
  │   {intent_id,                  │                                │
  │    status: "pending",          │                                │
  │    expires_at: "...",          │                                │
  │    retry_after: 2}             │                                │
  │                                │                                │
  │         ... sleep 2s ...       │                                │
  │── GET /intents/{id} ─────────▶│                                │
  │◀── {status:"pending",        ─│                                │
  │     retry_after: 2}            │                                │
  │                                │                                │
  │                                │◀── GET /intents?tag=QPg24g ────│
  │                                │     &status=pending            │
  │                                │──▶ [{intent_id, action,       ─│
  │                                │      stanzas, ephemeral_pub,   │
  │                                │      expires_at}]              │
  │                                │                                │
  │                                │    (operator unwraps locally,   │
  │                                │     seals file key to plugin    │
  │                                │     ephemeral key)              │
  │                                │                                │
  │                                │◀── POST /intents/{id}/fulfill ─│
  │                                │    {encrypted_file_key: "..."}  │
  │                                │──▶ 200 OK ─────────────────────│
  │                                │                                │
  │         ... sleep 2s ...       │                                │
  │── GET /intents/{id} ─────────▶│                                │
  │◀── {status:"fulfilled",      ─│                                │
  │     encrypted_file_key: "..."} │                                │
  │                                │                                │
  │  decrypt locally → file key    │                                │
```

---

## Rejection Flow

```text
Operator -> Relay Broker: POST /intents/{id}/reject
Relay Broker -> Operator: 200 OK

Plugin -> Relay Broker: GET /intents/{id}
Relay Broker -> Plugin: {status:"rejected"}
```

The Plugin then returns an error to `age`.

---

## Intent State Machine

```text
         ┌──────────┐
         │ pending  │
         └────┬─────┘
              │
    ┌─────────┼──────────┐
    ▼         ▼          ▼
fulfilled  rejected   expired
```

No transitions occur out of terminal states.

---

## Broker API Surface

### Plugin-facing

#### `POST /intents`
Create a new unwrap intent.

Request includes:
- action
- tag
- stanzas
- ephemeral public key
- expires_in

Response:
- intent_id
- status
- expires_at
- retry_after

#### `GET /intents/{id}`
Poll current state.

Possible responses:
- `pending`
- `fulfilled` with `encrypted_file_key`
- `rejected`
- `expired`

### Operator-facing

#### `GET /intents?tag={tag}&status=pending`
List pending intents for a specific operator identity.

#### `POST /intents/{id}/fulfill`
Submit encrypted result.

#### `POST /intents/{id}/reject`
Reject intent.

---

## Broker Implementation Decision

### Component
New binary:

- `cmd/relay-broker/main.go`

### Characteristics
- lightweight Go HTTP server
- in-memory storage
- TTL-based expiry
- periodic sweep or lazy expiration on read

### Suggested internal structure

```go
type Intent struct {
    ID               string
    Tag              string
    Action           string
    Stanzas          []relay.RelayStanza
    EphemeralPub     string
    Status           string
    EncryptedFileKey string
    CreatedAt        time.Time
    ExpiresAt        time.Time
}

type Broker struct {
    mu         sync.RWMutex
    intents     map[string]*Intent
    maxTTL      time.Duration
    retryAfter  int
}
```

### Runtime flags
Example:

```bash
relay-broker -addr :8443 -max-ttl 10m -retry-after 2
```

---

## Operator Implementation Decision

### Component
New binary:

- `cmd/relay-operator/main.go`

### Characteristics
- CLI-based polling tool
- polls the Relay Broker for pending intents by tag
- prompts for approve/reject unless auto-approve is enabled
- performs unwrap locally using operator identity
- encrypts result to plugin ephemeral public key
- fulfills or rejects the intent

### Example usage

Interactive:

```bash
relay-operator \
  --broker https://broker.example \
  --identity keys.txt \
  --tag QPg24g
```

Auto-approve mode:

```bash
relay-operator \
  --broker https://broker.example \
  --identity keys.txt \
  --tag QPg24g \
  --auto-approve
```

---

## Plugin Flow Configuration Decision

The Plugin should support **configurable flow mode** in `relay-config.yaml`.

### Example

```yaml
remotes:
  direct-server:
    url: https://relay.example:8443/unwrap
    flow: sync
    timeout: 5m
    hmac_key: secret

  approved-server:
    url: https://broker.example:8443
    flow: async
    timeout: 5m
    hmac_key: secret
    encrypted_response: true
```

### Meaning

- `flow: sync`
  - existing direct HTTP unwrap flow
- `flow: async`
  - new brokered intent + polling flow

### Default
`sync`

---

## Plugin Integration Decision

The plugin should branch behavior based on configured `flow`.

### Sync flow
Keep the existing direct HTTP POST behavior.

### Async flow
Use:
1. submit intent
2. poll until fulfilled / rejected / expired / local timeout
3. decrypt the returned encrypted file key locally

### Important rule
The plugin’s configured timeout is used as:
- the requested intent expiry
- the local maximum polling duration

---

## Proposed Code Changes

### New files / binaries

- `cmd/relay-broker/main.go`
- `cmd/relay-operator/main.go`

### Shared types
Potential new shared package:

- `relay/broker/types.go`

### Existing files to update

- `relay/client.go`
  - add async submit/poll support
- `relay/config.go`
  - add `Flow` field
- `relay/identity.go`
  - route unwrap by flow

---

## Proposed Repository Layout

```text
age-plugin-relay/
├── relay/
│   ├── client.go
│   ├── config.go
│   ├── identity.go
│   ├── broker/
│   │   └── types.go
│   └── ...
├── cmd/
│   ├── age-plugin-relay/
│   ├── relay-server/
│   ├── relay-broker/
│   │   └── main.go
│   └── relay-operator/
│       └── main.go
```

---

## Agreed Build Order

Implementation should proceed in this order:

1. `relay/broker/types.go`
2. `cmd/relay-broker/main.go`
3. `cmd/relay-operator/main.go`
4. `relay/client.go` async support
5. `relay/config.go` flow support
6. `relay/identity.go` flow routing
7. tests

---

## Final Summary

We agreed to introduce an **async brokered unwrap flow** that preserves the existing sync mode while enabling approval-based remote decryption.

### Final architecture
- Plugin submits unwrap intents
- Relay Broker stores and exposes them asynchronously
- Operator polls, approves/rejects, and fulfills them
- Broker remains blind to plaintext file keys
- Plugin polls and completes decryption locally

### Final decisions
- keep actor name **Plugin**
- use **Relay Broker**
- use **Operator**
- one intent per unwrap
- operator polls by tag/fingerprint
- plugin timeout drives requested expiry
- broker enforces max TTL
- retry interval is fixed
- explicit rejection is supported
- async vs sync is configurable in the plugin config
- broker implementation is lightweight Go + in-memory TTL
- operator is a new CLI binary
- implementation should follow the agreed build order
```

If you want, I can also format this into a shorter `ADR`-style document next.