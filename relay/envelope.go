// Package relay — envelope.go provides ephemeral X25519 response encryption.
//
// When enabled, the client generates a per-request X25519 keypair, sends the
// public key in X-Relay-Ephemeral-Key, and the server encrypts the file key
// response using NaCl box (X25519 + XSalsa20-Poly1305).
//
// The ephemeral key MUST be included in the HMAC signature to prevent
// key substitution attacks. This means hmac_key is a prerequisite for
// encrypted_response.
package relay

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

const (
	// EnvelopeHeader is the HTTP header carrying the client's ephemeral public key.
	EnvelopeHeader = "X-Relay-Ephemeral-Key"
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

// SealFileKey encrypts a file key to the client's ephemeral public key.
// Called by the server. Uses an ephemeral server keypair per response so the
// sealed box is unique even for identical file keys.
//
// Returns base64-encoded: serverPub(32) || nonce(24) || ciphertext(16+box.Overhead).
func SealFileKey(fileKey []byte, clientPub [32]byte) (string, error) {
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

	sealed := box.Seal(nil, fileKey, &nonce, &clientPub, serverPriv)

	// Wire format: serverPub(32) || nonce(24) || sealed
	out := make([]byte, 0, 32+24+len(sealed))
	out = append(out, serverPub[:]...)
	out = append(out, nonce[:]...)
	out = append(out, sealed...)

	return base64.RawStdEncoding.EncodeToString(out), nil
}

// OpenFileKey decrypts a sealed file key using the client's ephemeral private key.
// Called by the client. Parses: serverPub(32) || nonce(24) || ciphertext.
func OpenFileKey(sealed string, clientPriv [32]byte) ([]byte, error) {
	defer clear(clientPriv[:])

	raw, err := base64.RawStdEncoding.DecodeString(sealed)
	if err != nil {
		return nil, fmt.Errorf("decoding sealed file key: %w", err)
	}

	if len(raw) < 32+24+box.Overhead {
		return nil, fmt.Errorf("sealed file key too short (%d bytes)", len(raw))
	}

	var serverPub [32]byte
	var nonce [24]byte
	copy(serverPub[:], raw[:32])
	copy(nonce[:], raw[32:56])
	ciphertext := raw[56:]

	fileKey, ok := box.Open(nil, ciphertext, &nonce, &serverPub, &clientPriv)
	if !ok {
		return nil, fmt.Errorf("decrypting sealed file key failed (authentication error)")
	}
	return fileKey, nil
}

// DerivePublicKey derives the X25519 public key from a private key.
// Used only in tests.
func DerivePublicKey(priv [32]byte) [32]byte {
	pub, _ := curve25519.X25519(priv[:], curve25519.Basepoint)
	var out [32]byte
	copy(out[:], pub)
	return out
}
