// Package relay — envelope.go provides ephemeral age response encryption.
//
// The operator seals an InnerResponsePayload (containing the file key) using
// age encryption (X25519 + HKDF + ChaCha20-Poly1305) to the plugin's ephemeral
// age recipient. The plugin opens the sealed response with its ephemeral identity.
//
// Both directions (request and response) now use age encryption as the sole
// cryptographic primitive.
package relay

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"filippo.io/age"
)

// EphemeralKeypair holds a per-request age X25519 identity for response encryption.
type EphemeralKeypair struct {
	Identity  *age.X25519Identity
	Recipient *age.X25519Recipient
}

// GenerateEphemeral creates a new random age X25519 identity/recipient pair.
func GenerateEphemeral() (*EphemeralKeypair, error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral keypair: %w", err)
	}
	return &EphemeralKeypair{
		Identity:  id,
		Recipient: id.Recipient(),
	}, nil
}

// Clear nils the identity and recipient to prevent further use.
// Note: Go's garbage collector may not zero freed memory immediately.
func (ek *EphemeralKeypair) Clear() {
	ek.Identity = nil
	ek.Recipient = nil
}

// RecipientString returns the bech32-encoded age recipient string (age1...).
func (ek *EphemeralKeypair) RecipientString() string {
	return ek.Recipient.String()
}

// SealResponse encrypts an InnerResponsePayload to the given age recipient string.
// Called by the operator/server. Each call uses age's internal ephemeral key, so
// the ciphertext is unique even for identical payloads.
//
// Returns base64-encoded age ciphertext.
func SealResponse(inner InnerResponsePayload, recipientStr string) (string, error) {
	recipient, err := ParseRecipientString(recipientStr)
	if err != nil {
		return "", fmt.Errorf("parsing ephemeral recipient: %w", err)
	}

	plaintext, err := json.Marshal(inner)
	if err != nil {
		return "", fmt.Errorf("marshaling inner response: %w", err)
	}

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return "", fmt.Errorf("creating age encryptor: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return "", fmt.Errorf("writing to age encryptor: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("closing age encryptor: %w", err)
	}

	return base64.RawStdEncoding.EncodeToString(buf.Bytes()), nil
}

// OpenResponse decrypts a sealed InnerResponsePayload using the plugin's
// ephemeral age identity. Called by the plugin.
func OpenResponse(sealed string, identity *age.X25519Identity) (*InnerResponsePayload, error) {
	raw, err := base64.RawStdEncoding.DecodeString(sealed)
	if err != nil {
		return nil, fmt.Errorf("decoding sealed response: %w", err)
	}

	r, err := age.Decrypt(bytes.NewReader(raw), identity)
	if err != nil {
		return nil, fmt.Errorf("decrypting sealed response: %w", err)
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading decrypted response: %w", err)
	}

	var inner InnerResponsePayload
	if err := json.Unmarshal(plaintext, &inner); err != nil {
		return nil, fmt.Errorf("parsing inner response payload: %w", err)
	}
	return &inner, nil
}
