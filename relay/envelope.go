// Package relay — envelope.go provides ephemeral X25519 response encryption.
//
// The operator seals an InnerResponsePayload (containing the file key) using
// NaCl box (X25519 + XSalsa20-Poly1305) to the plugin's ephemeral public key.
// The plugin opens the sealed response with its ephemeral private key.
package relay

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// EphemeralKeypair holds a per-request X25519 keypair for response encryption.
type EphemeralKeypair struct {
	PublicKey  [32]byte
	PrivateKey [32]byte
}

// GenerateEphemeral creates a new random X25519 keypair.
func GenerateEphemeral() (*EphemeralKeypair, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral keypair: %w", err)
	}
	return &EphemeralKeypair{PublicKey: *pub, PrivateKey: *priv}, nil
}

// Clear zeros the private key material.
func (ek *EphemeralKeypair) Clear() {
	clear(ek.PrivateKey[:])
}

// SealResponse encrypts an InnerResponsePayload to the client's ephemeral public
// key. Called by the operator/server. Uses an ephemeral server keypair per
// response so the sealed box is unique even for identical payloads.
//
// Returns base64-encoded: serverPub(32) || nonce(24) || ciphertext.
func SealResponse(inner InnerResponsePayload, clientPub [32]byte) (string, error) {
	plaintext, err := json.Marshal(inner)
	if err != nil {
		return "", fmt.Errorf("marshaling inner response: %w", err)
	}

	// Generate a one-time server keypair for this response.
	serverPub, serverPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generating server ephemeral key: %w", err)
	}
	defer clear(serverPriv[:])

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}

	sealed := box.Seal(nil, plaintext, &nonce, &clientPub, serverPriv)

	// Wire format: serverPub(32) || nonce(24) || sealed
	out := make([]byte, 0, 32+24+len(sealed))
	out = append(out, serverPub[:]...)
	out = append(out, nonce[:]...)
	out = append(out, sealed...)

	return base64.RawStdEncoding.EncodeToString(out), nil
}

// OpenResponse decrypts a sealed InnerResponsePayload using the client's
// ephemeral private key. Called by the plugin.
// Parses: serverPub(32) || nonce(24) || ciphertext.
func OpenResponse(sealed string, clientPriv [32]byte) (*InnerResponsePayload, error) {
	defer clear(clientPriv[:])

	raw, err := base64.RawStdEncoding.DecodeString(sealed)
	if err != nil {
		return nil, fmt.Errorf("decoding sealed response: %w", err)
	}

	if len(raw) < 32+24+box.Overhead {
		return nil, fmt.Errorf("sealed response too short (%d bytes)", len(raw))
	}

	var serverPub [32]byte
	var nonce [24]byte
	copy(serverPub[:], raw[:32])
	copy(nonce[:], raw[32:56])
	ciphertext := raw[56:]

	plaintext, ok := box.Open(nil, ciphertext, &nonce, &serverPub, &clientPriv)
	if !ok {
		return nil, fmt.Errorf("decrypting sealed response failed (authentication error)")
	}

	var inner InnerResponsePayload
	if err := json.Unmarshal(plaintext, &inner); err != nil {
		return nil, fmt.Errorf("parsing inner response payload: %w", err)
	}
	return &inner, nil
}

// DerivePublicKey derives the X25519 public key from a private key.
// Used only in tests.
func DerivePublicKey(priv [32]byte) [32]byte {
	pub, _ := curve25519.X25519(priv[:], curve25519.Basepoint)
	var out [32]byte
	copy(out[:], pub)
	return out
}
