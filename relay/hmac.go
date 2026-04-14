package relay

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

const (
	// HMACHeaderTimestamp is the HTTP header carrying the unix timestamp.
	HMACHeaderTimestamp = "X-Relay-Timestamp"

	// HMACHeaderNonce is the HTTP header carrying the per-request nonce.
	HMACHeaderNonce = "X-Relay-Nonce"

	// HMACHeaderSignature is the HTTP header carrying the HMAC-SHA256 signature.
	HMACHeaderSignature = "X-Relay-Signature"

	// HMACMaxDrift is the maximum allowed clock drift between client and server.
	HMACMaxDrift = 5 * time.Minute
)

// SignRequest computes HMAC-SHA256 over "timestamp.nonce.[ephemeralKey.]body"
// and returns the three header values (timestamp, nonce, signature hex).
// If ephemeralKey is non-empty it is included in the signed string to prevent
// key substitution attacks on encrypted responses.
func SignRequest(key []byte, body []byte, ephemeralKey ...string) (timestamp, nonce, signature string, err error) {
	var nonceBuf [16]byte
	if _, err := rand.Read(nonceBuf[:]); err != nil {
		return "", "", "", fmt.Errorf("generating nonce: %w", err)
	}

	timestamp = strconv.FormatInt(time.Now().Unix(), 10)
	nonce = hex.EncodeToString(nonceBuf[:])

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write([]byte(nonce))
	mac.Write([]byte("."))
	if len(ephemeralKey) > 0 && ephemeralKey[0] != "" {
		mac.Write([]byte(ephemeralKey[0]))
		mac.Write([]byte("."))
	}
	mac.Write(body)
	signature = hex.EncodeToString(mac.Sum(nil))

	return timestamp, nonce, signature, nil
}

// VerifySignature recomputes the HMAC and compares in constant time.
// If ephemeralKey is non-empty it is included in the signed string.
// Returns nil on success.
func VerifySignature(key []byte, timestamp, nonce string, body []byte, signature string, ephemeralKey ...string) error {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write([]byte(nonce))
	mac.Write([]byte("."))
	if len(ephemeralKey) > 0 && ephemeralKey[0] != "" {
		mac.Write([]byte(ephemeralKey[0]))
		mac.Write([]byte("."))
	}
	mac.Write(body)

	expected := mac.Sum(nil)
	got, err := hex.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding")
	}

	if !hmac.Equal(expected, got) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

// ValidateTimestamp checks that the timestamp is within the allowed drift window.
func ValidateTimestamp(timestamp string) error {
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp")
	}
	drift := time.Now().Unix() - ts
	if drift < 0 {
		drift = -drift
	}
	if drift > int64(HMACMaxDrift.Seconds()) {
		return fmt.Errorf("timestamp outside allowed window")
	}
	return nil
}
