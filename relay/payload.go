// Package relay — payload.go provides encrypted payload construction and verification.
//
// The encrypted payload feature provides end-to-end confidentiality through a
// zero-trust broker. Both directions use age encryption as the sole primitive:
// request payloads are age-encrypted to the operator's recipient, and response
// payloads are age-encrypted to the plugin's ephemeral recipient. Both directions
// include a SHA-256 outer hash binding the encrypted blob to the cleartext routing
// fields, ensuring tamper detection.
package relay

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
)

// InnerRequestPayload is the age-encrypted payload sent from the plugin to the
// operator via the broker. It contains the age stanzas, the plugin's ephemeral
// public key for response encryption, and integrity fields.
type InnerRequestPayload struct {
	Nonce        string        `json:"nonce"`         // 16 random bytes, hex-encoded
	OuterHash    string        `json:"outer_hash"`    // SHA-256 of outer fields
	ExpiresAt    int64         `json:"expires_at"`    // Unix timestamp (seconds)
	Stanzas      []RelayStanza `json:"stanzas"`       // inner age stanzas
	EphemeralKey string        `json:"ephemeral_key"` // age recipient string (age1...)
}

// InnerResponsePayload is the age-encrypted payload sent from the operator
// back to the plugin. It contains the unwrapped file key and integrity fields.
type InnerResponsePayload struct {
	Nonce     string `json:"nonce"`      // 16 random bytes, hex-encoded
	OuterHash string `json:"outer_hash"` // SHA-256 of intent_id
	FileKey   string `json:"file_key"`   // base64 raw standard, 16-byte age file key
}

// OuterHashRequest computes the SHA-256 hash that binds the encrypted request
// payload to the outer routing fields. The canonical input is:
//
//	"{version}.{action}.{intent_id}.{tag}.{expires_at}"
//
// All fields are dot-separated, no JSON, no whitespace.
func OuterHashRequest(version int, action, intentID, tag string, expiresAt int64) string {
	canonical := strconv.Itoa(version) + "." + action + "." + intentID + "." + tag + "." + strconv.FormatInt(expiresAt, 10)
	h := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(h[:])
}

// OuterHashResponse computes the SHA-256 hash that binds the encrypted response
// payload to the intent. The canonical input is simply the intent_id.
func OuterHashResponse(intentID string) string {
	h := sha256.Sum256([]byte(intentID))
	return hex.EncodeToString(h[:])
}

// generateNonce produces 16 random bytes, hex-encoded (32 chars).
func generateNonce() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}

// EncryptPayload age-encrypts an InnerRequestPayload to the given recipient
// string. Returns the base64-encoded ciphertext.
func EncryptPayload(inner InnerRequestPayload, recipientStr string) (string, error) {
	recipient, err := age.ParseX25519Recipient(recipientStr)
	if err != nil {
		return "", fmt.Errorf("parsing recipient %q: %w", recipientStr, err)
	}

	plaintext, err := json.Marshal(inner)
	if err != nil {
		return "", fmt.Errorf("marshaling inner payload: %w", err)
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

// DecryptPayload decrypts a base64-encoded age ciphertext and parses it as an
// InnerRequestPayload.
func DecryptPayload(encryptedB64 string, identities []age.Identity) (*InnerRequestPayload, error) {
	raw, err := base64.RawStdEncoding.DecodeString(encryptedB64)
	if err != nil {
		return nil, fmt.Errorf("decoding encrypted payload: %w", err)
	}

	r, err := age.Decrypt(bytes.NewReader(raw), identities...)
	if err != nil {
		return nil, fmt.Errorf("decrypting payload: %w", err)
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading decrypted payload: %w", err)
	}

	var inner InnerRequestPayload
	if err := json.Unmarshal(plaintext, &inner); err != nil {
		return nil, fmt.Errorf("parsing inner request payload: %w", err)
	}
	return &inner, nil
}

// VerifyRequestPayload checks that the inner payload's outer_hash matches the
// recomputed hash from the outer routing fields, and that the intent has not
// expired.
func VerifyRequestPayload(inner *InnerRequestPayload, version int, action, intentID, tag string, expiresAt int64) error {
	expected := OuterHashRequest(version, action, intentID, tag, expiresAt)
	if inner.OuterHash != expected {
		return fmt.Errorf("outer_hash mismatch: broker may have tampered with routing fields")
	}
	if time.Now().Unix() > inner.ExpiresAt {
		return fmt.Errorf("intent expired at %d", inner.ExpiresAt)
	}
	return nil
}

// BuildRequestPayload constructs an InnerRequestPayload with a fresh nonce and
// the computed outer hash.
func BuildRequestPayload(version int, action, intentID, tag string, expiresAt int64, stanzas []RelayStanza, ephemeralRecipient string) (*InnerRequestPayload, error) {
	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}
	return &InnerRequestPayload{
		Nonce:        nonce,
		OuterHash:    OuterHashRequest(version, action, intentID, tag, expiresAt),
		ExpiresAt:    expiresAt,
		Stanzas:      stanzas,
		EphemeralKey: ephemeralRecipient,
	}, nil
}

// BuildResponsePayload constructs an InnerResponsePayload with a fresh nonce,
// the computed outer hash, and the base64-encoded file key.
func BuildResponsePayload(intentID string, fileKey []byte) (*InnerResponsePayload, error) {
	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}
	return &InnerResponsePayload{
		Nonce:     nonce,
		OuterHash: OuterHashResponse(intentID),
		FileKey:   base64.RawStdEncoding.EncodeToString(fileKey),
	}, nil
}

// VerifyResponsePayload checks that the inner response payload's outer_hash
// matches the recomputed hash from the intent_id.
func VerifyResponsePayload(inner *InnerResponsePayload, intentID string) error {
	expected := OuterHashResponse(intentID)
	if inner.OuterHash != expected {
		return fmt.Errorf("response outer_hash mismatch: possible tampering")
	}
	return nil
}

// ParseRecipientString parses a recipient string into an age.Recipient.
// Supports X25519 recipients (age1...). Returns an error for unsupported types.
func ParseRecipientString(recipientStr string) (age.Recipient, error) {
	if strings.HasPrefix(recipientStr, "age1") {
		return age.ParseX25519Recipient(recipientStr)
	}
	return nil, fmt.Errorf("unsupported recipient type: %q", recipientStr)
}
