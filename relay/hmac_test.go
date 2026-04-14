package relay

import (
	"fmt"
	"testing"
	"time"
)

func TestSignAndVerify(t *testing.T) {
	key := []byte("test-secret-key-123")
	body := []byte(`{"version":1,"action":"unwrap","stanzas":[]}`)

	ts, nonce, sig, err := SignRequest(key, body)
	if err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	if ts == "" || nonce == "" || sig == "" {
		t.Fatal("SignRequest returned empty values")
	}

	if err := VerifySignature(key, ts, nonce, body, sig); err != nil {
		t.Fatalf("VerifySignature failed for valid signature: %v", err)
	}
}

func TestVerifyWrongKey(t *testing.T) {
	key := []byte("correct-key")
	body := []byte(`{"action":"unwrap"}`)

	ts, nonce, sig, _ := SignRequest(key, body)

	wrongKey := []byte("wrong-key")
	if err := VerifySignature(wrongKey, ts, nonce, body, sig); err == nil {
		t.Fatal("expected error for wrong key")
	}
}

func TestVerifyTamperedBody(t *testing.T) {
	key := []byte("test-key")
	body := []byte(`{"action":"unwrap"}`)

	ts, nonce, sig, _ := SignRequest(key, body)

	tampered := []byte(`{"action":"evil"}`)
	if err := VerifySignature(key, ts, nonce, tampered, sig); err == nil {
		t.Fatal("expected error for tampered body")
	}
}

func TestVerifyBadSignatureEncoding(t *testing.T) {
	key := []byte("test-key")
	body := []byte(`hello`)
	ts, nonce, _, _ := SignRequest(key, body)

	if err := VerifySignature(key, ts, nonce, body, "not-hex!!!"); err == nil {
		t.Fatal("expected error for bad hex encoding")
	}
}

func TestValidateTimestamp(t *testing.T) {
	// Current time should be valid.
	ts, _, _, _ := SignRequest([]byte("k"), []byte("b"))
	if err := ValidateTimestamp(ts); err != nil {
		t.Fatalf("current timestamp should be valid: %v", err)
	}

	// Garbage should fail.
	if err := ValidateTimestamp("not-a-number"); err == nil {
		t.Fatal("expected error for non-numeric timestamp")
	}

	// Old timestamp (10 minutes ago) should fail.
	old := time.Now().Add(-10 * time.Minute).Unix()
	if err := ValidateTimestamp(formatInt64(old)); err == nil {
		t.Fatal("expected error for old timestamp")
	}

	// Future timestamp (10 minutes ahead) should fail.
	future := time.Now().Add(10 * time.Minute).Unix()
	if err := ValidateTimestamp(formatInt64(future)); err == nil {
		t.Fatal("expected error for future timestamp")
	}
}

func TestNoncesAreUnique(t *testing.T) {
	key := []byte("k")
	body := []byte("b")
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		_, nonce, _, _ := SignRequest(key, body)
		if seen[nonce] {
			t.Fatalf("duplicate nonce on iteration %d", i)
		}
		seen[nonce] = true
	}
}

func formatInt64(v int64) string {
	return fmt.Sprintf("%d", v)
}
