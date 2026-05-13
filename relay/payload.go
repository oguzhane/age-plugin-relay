// Package relay — payload.go provides encrypted payload construction and verification.
//
// The encrypted payload feature provides end-to-end confidentiality through a
// zero-trust broker. Both directions use age encryption as the sole primitive:
// request payloads are age-encrypted to the operator's recipient, and response
// payloads are age-encrypted to the plugin's ephemeral recipient.
//
// FUNDAMENTAL PRINCIPLE — Complete Outer Field Binding:
//
// The outer hash inside every encrypted payload MUST cover every field in the
// cleartext JSON envelope except encrypted_payload itself. This is the sole
// mechanism that detects broker tampering of routing fields. Any field omitted
// from the hash is a field the broker can silently alter without detection.
//
// When adding a new field to RelayRequest, you MUST also add it to the
// corresponding OuterHash function below. See ARCHITECTURE.md §3.5.
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
	OuterHash    string        `json:"outer_hash"`    // SHA-256 of ALL outer envelope fields (see package doc)
	ExpiresAt    int64         `json:"expires_at"`    // Unix timestamp (seconds)
	Stanzas      []RelayStanza `json:"stanzas"`       // inner age stanzas
	EphemeralKey string        `json:"ephemeral_key"` // age recipient string (age1...)
}

// InnerResponsePayload is the age-encrypted payload sent from the operator
// back to the plugin. It contains the unwrapped file key and integrity fields.
type InnerResponsePayload struct {
	Nonce     string `json:"nonce"`      // 16 random bytes, hex-encoded
	OuterHash string `json:"outer_hash"` // SHA-256 of ALL outer envelope fields (see package doc)
	FileKey   string `json:"file_key"`   // base64 raw standard, 16-byte age file key
}

// OuterHashRequest computes the SHA-256 hash that binds the encrypted request
// payload to every outer envelope field (the Complete Outer Field Binding principle).
//
// Inputs: every RelayRequest field except encrypted_payload.
// Canonical form: "{version}.{action}.{stream}.{intent_id}.{tag}.{expires_at}"
// where stream is "0" or "1". Dot-separated, no JSON, no whitespace.
//
// IMPORTANT: If a new field is added to the request envelope, it MUST be added
// here. Omitting a field allows the broker to tamper with it undetected.
func OuterHashRequest(version int, action string, stream bool, intentID, tag string, expiresAt int64) string {
	streamStr := "0"
	if stream {
		streamStr = "1"
	}
	canonical := strconv.Itoa(version) + "." + action + "." + streamStr + "." + intentID + "." + tag + "." + strconv.FormatInt(expiresAt, 10)
	h := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(h[:])
}

// OuterHashResponse computes the SHA-256 hash that binds the encrypted response
// payload to every outer envelope field (the Complete Outer Field Binding principle).
//
// Inputs: every response envelope field except encrypted_payload.
// Canonical form: "{version}.{action}.{intent_id}"
//
// IMPORTANT: If a new field is added to the response envelope, it MUST be added
// here. Omitting a field allows the broker to tamper with it undetected.
func OuterHashResponse(version int, action, intentID string) string {
	canonical := strconv.Itoa(version) + "." + action + "." + intentID
	h := sha256.Sum256([]byte(canonical))
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
func VerifyRequestPayload(inner *InnerRequestPayload, version int, action string, stream bool, intentID, tag string, expiresAt int64) error {
	expected := OuterHashRequest(version, action, stream, intentID, tag, expiresAt)
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
func BuildRequestPayload(version int, action string, stream bool, intentID, tag string, expiresAt int64, stanzas []RelayStanza, ephemeralRecipient string) (*InnerRequestPayload, error) {
	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}
	return &InnerRequestPayload{
		Nonce:        nonce,
		OuterHash:    OuterHashRequest(version, action, stream, intentID, tag, expiresAt),
		ExpiresAt:    expiresAt,
		Stanzas:      stanzas,
		EphemeralKey: ephemeralRecipient,
	}, nil
}

// BuildResponsePayload constructs an InnerResponsePayload with a fresh nonce,
// the computed outer hash, and the base64-encoded file key.
func BuildResponsePayload(version int, action, intentID string, fileKey []byte) (*InnerResponsePayload, error) {
	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}
	return &InnerResponsePayload{
		Nonce:     nonce,
		OuterHash: OuterHashResponse(version, action, intentID),
		FileKey:   base64.RawStdEncoding.EncodeToString(fileKey),
	}, nil
}

// VerifyResponsePayload checks that the inner response payload's outer_hash
// matches the recomputed hash from the intent_id.
func VerifyResponsePayload(inner *InnerResponsePayload, version int, action, intentID string) error {
	expected := OuterHashResponse(version, action, intentID)
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
