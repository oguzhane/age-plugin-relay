// Package relay — claim.go provides Intent Claim: per-intent Ed25519
// authorization that prevents fabricated fulfill/reject actions.
//
// The plugin generates an Ed25519 keypair per intent. The public key
// (intent_claim_pub) goes in the outer envelope; the private key seed
// (intent_claim_secret) goes in the encrypted payload. Only someone who
// decrypted the payload can sign a fulfill/reject — the broker verifies the
// signature against the stored public key.
//
// Canonical signing input: "{version}.{action}.{intent_id}.{SHA256(encrypted_payload)}"
// This binds the signature to the specific action and response content.
package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
)

// GenerateIntentClaim generates a fresh Ed25519 keypair for intent claim
// authorization. The caller should encode pub with EncodeIntentClaimPub and
// store priv.Seed() (32 bytes) in the encrypted payload.
func GenerateIntentClaim() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating intent claim keypair: %w", err)
	}
	return pub, priv, nil
}

// EncodeIntentClaimPub encodes an Ed25519 public key as base64 raw standard.
func EncodeIntentClaimPub(pub ed25519.PublicKey) string {
	return base64.RawStdEncoding.EncodeToString(pub)
}

// EncodeIntentClaimSecret encodes an Ed25519 private key seed (32 bytes) as
// base64 raw standard for inclusion in the encrypted payload.
func EncodeIntentClaimSecret(priv ed25519.PrivateKey) string {
	return base64.RawStdEncoding.EncodeToString(priv.Seed())
}

// DecodeIntentClaimSecret decodes a base64-raw-std intent_claim_secret and
// reconstructs the Ed25519 private key from its seed.
func DecodeIntentClaimSecret(secretB64 string) (ed25519.PrivateKey, error) {
	seed, err := base64.RawStdEncoding.DecodeString(secretB64)
	if err != nil {
		return nil, fmt.Errorf("decoding intent claim secret: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("intent claim secret: expected %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// IntentClaimCanonical computes the canonical string that is signed/verified
// for intent claim authorization.
//
// Format: "{version}.{action}.{intent_id}.{SHA256(encrypted_payload)}"
// where SHA256(encrypted_payload) is hex-encoded.
func IntentClaimCanonical(version int, action, intentID, encryptedPayload string) string {
	h := sha256.Sum256([]byte(encryptedPayload))
	return strconv.Itoa(version) + "." + action + "." + intentID + "." + hex.EncodeToString(h[:])
}

// SignIntentClaim signs the canonical intent claim message with the given
// Ed25519 private key. Returns the signature as base64 raw standard.
func SignIntentClaim(priv ed25519.PrivateKey, version int, action, intentID, encryptedPayload string) string {
	canonical := IntentClaimCanonical(version, action, intentID, encryptedPayload)
	sig := ed25519.Sign(priv, []byte(canonical))
	return base64.RawStdEncoding.EncodeToString(sig)
}

// VerifyIntentClaim verifies an intent claim signature. The pubB64 and sigB64
// are base64-raw-std encoded. Returns nil on success, an error on failure.
func VerifyIntentClaim(pubB64, sigB64 string, version int, action, intentID, encryptedPayload string) error {
	pub, err := base64.RawStdEncoding.DecodeString(pubB64)
	if err != nil {
		return fmt.Errorf("decoding intent claim public key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("intent claim public key: expected %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}

	sig, err := base64.RawStdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("decoding intent claim signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("intent claim signature: expected %d bytes, got %d", ed25519.SignatureSize, len(sig))
	}

	canonical := IntentClaimCanonical(version, action, intentID, encryptedPayload)
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(canonical), sig) {
		return fmt.Errorf("invalid_claim_sig")
	}
	return nil
}
