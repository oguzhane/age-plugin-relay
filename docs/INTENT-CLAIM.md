# Intent Claim — Per-Intent Ed25519 Authorization

## Problem Statement

In the async flow, the broker is a zero-trust stateful queue that stores and forwards opaque encrypted payloads. However, anyone who can send HTTP requests to the broker can fabricate `fulfill` or `reject` actions for any `intent_id`. There is no proof the sender actually decrypted the encrypted payload — i.e., is the legitimate operator who holds the age identity.

**Threat:** A malicious actor (or compromised broker) can:
- Fabricate a `fulfill` with a garbage `encrypted_payload` to deny service (plugin's `age.Decrypt` fails).
- Fabricate a `reject` to silently deny service.
- Race the legitimate operator to fulfill first with a crafted response.

The outer hash prevents *content* tampering but does not prove *authorship* — anyone can compute `SHA-256("1.fulfill.{intent_id}")`.

## Design

**Intent Claim** adds per-intent Ed25519 proof-of-knowledge: only someone who decrypted the inner payload can act on the intent.

### Key Distribution

```
Plugin                          Broker                          Operator
──────                          ──────                          ────────

1. Generate Ed25519 keypair
   per intent

2. intent_claim_pub (32B)
   → outer envelope              3. Store intent_claim_pub
                                    with intent

4. intent_claim_secret (32B seed)
   → encrypted inner payload     ✗ (opaque)                     5. Decrypt inner →
                                                                    extract secret →
                                                                    reconstruct private key

                                                                 6. Sign fulfill/reject
                                                                    with private key

                                 7. Verify signature
                                    against stored pub →
                                    403 if invalid
```

### Why Ed25519?

| Property | Benefit |
|----------|---------|
| Asymmetric | Broker stores only the public key; cannot forge signatures |
| Deterministic | Same key + message always produces the same signature |
| Fast | ~15,000 sign/verify ops per second on commodity hardware |
| Small | 32B seed, 32B public key, 64B signature |
| Standard | Go stdlib `crypto/ed25519`, no external dependencies |

### Why Not HMAC?

HMAC requires the broker to hold the shared secret for verification, which contradicts the zero-trust broker model. With Ed25519, the broker holds only the public key and can verify without ever seeing the private key.

### Why Not Hash Commitment?

A hash commitment (e.g., `SHA-256(secret)` in outer, `secret` in inner) proves knowledge but doesn't bind to the action content. An attacker who learns the secret (e.g., from a leaked log) can reuse it for any action. Ed25519 signatures bind to the specific action and payload content.

## Protocol Flow

### 1. Plugin generates keypair (submit)

```go
pub, priv, _ := relay.GenerateIntentClaim()
```

- `intent_claim_pub` = base64-raw-std encoded 32-byte Ed25519 public key → outer envelope
- `intent_claim_secret` = base64-raw-std encoded 32-byte Ed25519 private key seed → encrypted inner payload

### 2. Broker stores public key

On `unwrap` submit, the broker stores `intent_claim_pub` alongside the intent. Rejects with `400` if missing.

### 3. Operator extracts secret and signs

After decrypting the inner payload, the operator:

```go
claimPriv, _ := relay.DecodeIntentClaimSecret(inner.IntentClaimSecret)
sig := relay.SignIntentClaim(claimPriv, version, action, intentID, encryptedPayload)
```

The signature is sent as `intent_claim_sig` in the fulfill/reject request.

### 4. Broker verifies signature

```go
err := relay.VerifyIntentClaim(storedPub, sig, version, action, intentID, encryptedPayload)
```

Returns `403 Forbidden` with `"invalid_claim_sig"` if verification fails.

## Field Reference

| Field | Location | Encoding | Size | Description |
|-------|----------|----------|------|-------------|
| `intent_claim_pub` | Outer envelope (unwrap request) | Base64 raw standard | 44 chars (32 bytes) | Ed25519 public key |
| `intent_claim_secret` | Inner request payload (encrypted) | Base64 raw standard | 44 chars (32 bytes) | Ed25519 private key seed |
| `intent_claim_sig` | Outer envelope (fulfill/reject request) | Base64 raw standard | 88 chars (64 bytes) | Ed25519 signature |

## Canonical Signing Input

The signature covers a deterministic canonical string that binds the signature to the specific action and response content:

```
"{version}.{action}.{intent_id}.{SHA-256(encrypted_payload)}"
```

| Component | Description |
|-----------|-------------|
| `version` | Protocol version (decimal string, e.g., `"1"`) |
| `action` | The action being signed (`"fulfill"` or `"reject"`) |
| `intent_id` | The intent being acted on |
| `SHA-256(encrypted_payload)` | Hex-encoded SHA-256 of the `encrypted_payload` field value |

### Why hash the encrypted payload?

The `encrypted_payload` is included (via its SHA-256 hash) to **bind the signature to the specific response content**. Without this:

- An attacker who intercepts a valid signature could replay it with a different `encrypted_payload` (e.g., substitute a garbage payload to cause decryption failure on the plugin side).
- The hash ensures the signature is only valid for the exact `encrypted_payload` the operator produced.

### Example

```
IntentClaimCanonical(1, "fulfill", "a3f12c4e8b9d6f0a1b2c3d4e5f6a7b8c", "<encrypted_payload>")
→ "1.fulfill.a3f12c4e8b9d6f0a1b2c3d4e5f6a7b8c.e3b0c44298fc1c149afb..."
```

## Outer Hash Integration

`intent_claim_pub` is included in the request outer hash as a bound field (per the [Complete Outer Field Binding](ARCHITECTURE.md#35-outer-hash-construction) principle):

```
SHA-256("{version}.{action}.{stream}.{intent_id}.{tag}.{expires_at}.{intent_claim_pub}")
```

This ensures the broker cannot substitute a different public key without detection by the operator.

## Security Properties

| Property | How |
|----------|-----|
| Broker never sees private key | `intent_claim_secret` is inside the age-encrypted payload |
| Payload binding prevents swap | Signature includes `SHA-256(encrypted_payload)` |
| Single-use + 409 prevents replay | Intent state machine: fulfill/reject are terminal (409 on repeat) |
| Broker cannot forge signatures | Only holds public key; Ed25519 is existentially unforgeable |
| Tamper detection on public key | `intent_claim_pub` is bound in the outer hash |

## Error Codes

| HTTP Status | Error | Condition |
|-------------|-------|-----------|
| 400 Bad Request | `missing intent_claim_pub` | `unwrap` without `intent_claim_pub` |
| 400 Bad Request | `missing intent_claim_sig` | `fulfill`/`reject` without `intent_claim_sig` |
| 403 Forbidden | `invalid_claim_sig` | Signature verification failed |

## Sync Flow Note

In the sync flow (`relay-server`), the plugin sends `intent_claim_pub` in the outer envelope and `intent_claim_secret` in the inner payload for format consistency. However, the relay-server does not need to verify `intent_claim_sig` because it handles both decrypt and respond in a single process — there is no third-party fulfill step. The `intent_claim_pub` is still included in the outer hash for consistency.
