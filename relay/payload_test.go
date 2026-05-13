package relay_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	relay "github.com/oguzhane/age-plugin-relay/relay"

	"filippo.io/age"
)

// testIdentity generates a fresh X25519 identity and returns (identity, recipient string).
func testIdentity(t *testing.T) (*age.X25519Identity, string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}
	return id, id.Recipient().String()
}

func TestOuterHashRequestDeterminism(t *testing.T) {
	h1 := relay.OuterHashRequest(1, "unwrap", "abc123", "QPg24g", 1715350800)
	h2 := relay.OuterHashRequest(1, "unwrap", "abc123", "QPg24g", 1715350800)
	if h1 != h2 {
		t.Fatalf("expected deterministic hash, got %q != %q", h1, h2)
	}

	// Known-answer: SHA-256("1.unwrap.abc123.QPg24g.1715350800")
	canonical := "1.unwrap.abc123.QPg24g.1715350800"
	expected := sha256.Sum256([]byte(canonical))
	expectedHex := hex.EncodeToString(expected[:])
	if h1 != expectedHex {
		t.Fatalf("expected %q, got %q", expectedHex, h1)
	}
}

func TestOuterHashRequestDifferentFields(t *testing.T) {
	h1 := relay.OuterHashRequest(1, "unwrap", "abc123", "QPg24g", 1715350800)
	h2 := relay.OuterHashRequest(1, "unwrap", "abc123", "QPg24g", 1715350801) // different expires_at
	if h1 == h2 {
		t.Fatal("different expires_at should produce different hashes")
	}

	h3 := relay.OuterHashRequest(1, "unwrap", "different_id", "QPg24g", 1715350800)
	if h1 == h3 {
		t.Fatal("different intent_id should produce different hashes")
	}
}

func TestOuterHashResponseDeterminism(t *testing.T) {
	h1 := relay.OuterHashResponse("unwrap", "abc123")
	h2 := relay.OuterHashResponse("unwrap", "abc123")
	if h1 != h2 {
		t.Fatalf("expected deterministic hash, got %q != %q", h1, h2)
	}

	expected := sha256.Sum256([]byte("unwrap.abc123"))
	expectedHex := hex.EncodeToString(expected[:])
	if h1 != expectedHex {
		t.Fatalf("expected %q, got %q", expectedHex, h1)
	}
}

func TestEncryptDecryptPayloadRoundTrip(t *testing.T) {
	id, recipientStr := testIdentity(t)

	inner := relay.InnerRequestPayload{
		Nonce:        "deadbeef01020304deadbeef01020304",
		OuterHash:    relay.OuterHashRequest(1, "unwrap", "intent1", "tag1", 1715350800),
		ExpiresAt:    1715350800,
		Stanzas:      []relay.RelayStanza{{Type: "X25519", Args: []string{"arg1"}, Body: "Ym9keQ"}},
		EphemeralKey: "dGVzdGtleQ",
	}

	encrypted, err := relay.EncryptPayload(inner, recipientStr)
	if err != nil {
		t.Fatalf("EncryptPayload: %v", err)
	}

	decrypted, err := relay.DecryptPayload(encrypted, []age.Identity{id})
	if err != nil {
		t.Fatalf("DecryptPayload: %v", err)
	}

	if decrypted.Nonce != inner.Nonce {
		t.Errorf("nonce mismatch: %q != %q", decrypted.Nonce, inner.Nonce)
	}
	if decrypted.OuterHash != inner.OuterHash {
		t.Errorf("outer_hash mismatch: %q != %q", decrypted.OuterHash, inner.OuterHash)
	}
	if decrypted.ExpiresAt != inner.ExpiresAt {
		t.Errorf("expires_at mismatch: %d != %d", decrypted.ExpiresAt, inner.ExpiresAt)
	}
	if len(decrypted.Stanzas) != 1 || decrypted.Stanzas[0].Type != "X25519" {
		t.Errorf("stanzas mismatch")
	}
	if decrypted.EphemeralKey != inner.EphemeralKey {
		t.Errorf("ephemeral_key mismatch: %q != %q", decrypted.EphemeralKey, inner.EphemeralKey)
	}
}

func TestDecryptPayloadWrongIdentityFails(t *testing.T) {
	_, recipientStr := testIdentity(t)
	wrongID, _ := testIdentity(t)

	inner := relay.InnerRequestPayload{
		Nonce:     "deadbeef01020304deadbeef01020304",
		OuterHash: "somehash",
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		Stanzas:   []relay.RelayStanza{{Type: "X25519", Args: []string{"a"}, Body: "Yg"}},
	}

	encrypted, err := relay.EncryptPayload(inner, recipientStr)
	if err != nil {
		t.Fatalf("EncryptPayload: %v", err)
	}

	_, err = relay.DecryptPayload(encrypted, []age.Identity{wrongID})
	if err == nil {
		t.Fatal("expected error decrypting with wrong identity")
	}
}

func TestVerifyRequestPayloadValid(t *testing.T) {
	expiresAt := time.Now().Add(5 * time.Minute).Unix()
	inner := &relay.InnerRequestPayload{
		OuterHash: relay.OuterHashRequest(1, "unwrap", "intent1", "tag1", expiresAt),
		ExpiresAt: expiresAt,
	}

	if err := relay.VerifyRequestPayload(inner, 1, "unwrap", "intent1", "tag1", expiresAt); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestVerifyRequestPayloadTamperedHash(t *testing.T) {
	expiresAt := time.Now().Add(5 * time.Minute).Unix()
	inner := &relay.InnerRequestPayload{
		OuterHash: relay.OuterHashRequest(1, "unwrap", "intent1", "tag1", expiresAt),
		ExpiresAt: expiresAt,
	}

	// Tamper: use different intent_id
	err := relay.VerifyRequestPayload(inner, 1, "unwrap", "tampered_id", "tag1", expiresAt)
	if err == nil {
		t.Fatal("expected error for tampered outer fields")
	}
}

func TestVerifyRequestPayloadExpired(t *testing.T) {
	expiresAt := time.Now().Add(-1 * time.Minute).Unix() // in the past
	inner := &relay.InnerRequestPayload{
		OuterHash: relay.OuterHashRequest(1, "unwrap", "intent1", "tag1", expiresAt),
		ExpiresAt: expiresAt,
	}

	err := relay.VerifyRequestPayload(inner, 1, "unwrap", "intent1", "tag1", expiresAt)
	if err == nil {
		t.Fatal("expected error for expired intent")
	}
}

func TestVerifyResponsePayloadValid(t *testing.T) {
	inner := &relay.InnerResponsePayload{
		OuterHash: relay.OuterHashResponse("unwrap", "intent1"),
	}
	if err := relay.VerifyResponsePayload(inner, "unwrap", "intent1"); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestVerifyResponsePayloadTamperedHash(t *testing.T) {
	inner := &relay.InnerResponsePayload{
		OuterHash: relay.OuterHashResponse("unwrap", "intent1"),
	}
	err := relay.VerifyResponsePayload(inner, "unwrap", "different_intent")
	if err == nil {
		t.Fatal("expected error for tampered intent_id")
	}
}

func TestBuildRequestPayload(t *testing.T) {
	expiresAt := time.Now().Add(5 * time.Minute).Unix()
	stanzas := []relay.RelayStanza{{Type: "X25519", Args: []string{"a"}, Body: "Yg"}}

	inner, err := relay.BuildRequestPayload(1, "unwrap", "intent1", "tag1", expiresAt, stanzas, "ephkey")
	if err != nil {
		t.Fatalf("BuildRequestPayload: %v", err)
	}

	if inner.Nonce == "" || len(inner.Nonce) != 32 {
		t.Errorf("expected 32-char hex nonce, got %q", inner.Nonce)
	}
	if inner.OuterHash != relay.OuterHashRequest(1, "unwrap", "intent1", "tag1", expiresAt) {
		t.Error("outer_hash mismatch")
	}
	if inner.ExpiresAt != expiresAt {
		t.Error("expires_at mismatch")
	}
	if inner.EphemeralKey != "ephkey" {
		t.Error("ephemeral_key mismatch")
	}
}

func TestBuildResponsePayload(t *testing.T) {
	fileKey := []byte("0123456789abcdef") // 16 bytes

	inner, err := relay.BuildResponsePayload("unwrap", "intent1", fileKey)
	if err != nil {
		t.Fatalf("BuildResponsePayload: %v", err)
	}

	if inner.Nonce == "" || len(inner.Nonce) != 32 {
		t.Errorf("expected 32-char hex nonce, got %q", inner.Nonce)
	}
	if inner.OuterHash != relay.OuterHashResponse("unwrap", "intent1") {
		t.Error("outer_hash mismatch")
	}

	decoded, err := base64.RawStdEncoding.DecodeString(inner.FileKey)
	if err != nil {
		t.Fatalf("decoding file_key: %v", err)
	}
	if string(decoded) != string(fileKey) {
		t.Errorf("file_key mismatch: %q != %q", decoded, fileKey)
	}
}

func TestNonceUniqueness(t *testing.T) {
	id, recipientStr := testIdentity(t)

	inner := relay.InnerRequestPayload{
		Nonce:     "deadbeef01020304deadbeef01020304",
		OuterHash: "hash",
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		Stanzas:   []relay.RelayStanza{{Type: "X25519", Args: []string{"a"}, Body: "Yg"}},
	}

	enc1, err := relay.EncryptPayload(inner, recipientStr)
	if err != nil {
		t.Fatal(err)
	}
	enc2, err := relay.EncryptPayload(inner, recipientStr)
	if err != nil {
		t.Fatal(err)
	}

	if enc1 == enc2 {
		t.Fatal("two encryptions of the same payload should produce different ciphertext (age adds its own randomness)")
	}

	// Both must decrypt correctly.
	_, err = relay.DecryptPayload(enc1, []age.Identity{id})
	if err != nil {
		t.Fatalf("decrypt enc1: %v", err)
	}
	_, err = relay.DecryptPayload(enc2, []age.Identity{id})
	if err != nil {
		t.Fatalf("decrypt enc2: %v", err)
	}
}

func TestEncryptDecryptFullFlow(t *testing.T) {
	// Simulate the full request path: build → encrypt → decrypt → verify
	id, recipientStr := testIdentity(t)
	expiresAt := time.Now().Add(5 * time.Minute).Unix()
	intentID := "a3f12c4e8b9d6f0a1b2c3d4e5f6a7b8c"
	tag := "QPg24g"
	stanzas := []relay.RelayStanza{{Type: "X25519", Args: []string{"ephkey1"}, Body: "c3RhbnphYm9keQ"}}

	inner, err := relay.BuildRequestPayload(1, "unwrap", intentID, tag, expiresAt, stanzas, "ZXBoZW1lcmFsa2V5")
	if err != nil {
		t.Fatalf("BuildRequestPayload: %v", err)
	}

	encrypted, err := relay.EncryptPayload(*inner, recipientStr)
	if err != nil {
		t.Fatalf("EncryptPayload: %v", err)
	}

	decrypted, err := relay.DecryptPayload(encrypted, []age.Identity{id})
	if err != nil {
		t.Fatalf("DecryptPayload: %v", err)
	}

	if err := relay.VerifyRequestPayload(decrypted, 1, "unwrap", intentID, tag, expiresAt); err != nil {
		t.Fatalf("VerifyRequestPayload: %v", err)
	}
}

func TestResponsePayloadFullFlow(t *testing.T) {
	// Simulate the full response path: build → verify
	intentID := "a3f12c4e8b9d6f0a1b2c3d4e5f6a7b8c"
	fileKey := []byte("0123456789abcdef")

	inner, err := relay.BuildResponsePayload("unwrap", intentID, fileKey)
	if err != nil {
		t.Fatalf("BuildResponsePayload: %v", err)
	}

	if err := relay.VerifyResponsePayload(inner, "unwrap", intentID); err != nil {
		t.Fatalf("VerifyResponsePayload: %v", err)
	}

	decoded, err := base64.RawStdEncoding.DecodeString(inner.FileKey)
	if err != nil {
		t.Fatalf("decoding file_key: %v", err)
	}
	if string(decoded) != string(fileKey) {
		t.Errorf("file_key mismatch")
	}
}

// ── ParseRecipientString ────────────────────────────────────────────────────

func TestParseRecipientStringValid(t *testing.T) {
	_, recipientStr := testIdentity(t)
	r, err := relay.ParseRecipientString(recipientStr)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("expected non-nil recipient")
	}
}

func TestParseRecipientStringUnsupported(t *testing.T) {
	_, err := relay.ParseRecipientString("ssh-ed25519 AAAA...")
	if err == nil {
		t.Fatal("expected error for unsupported type")
	}
}

func TestParseRecipientStringInvalid(t *testing.T) {
	_, err := relay.ParseRecipientString("age1notavalidrecipient")
	if err == nil {
		t.Fatal("expected error for invalid age1 string")
	}
}

// ── Outer hash tamper detection (encrypt → decrypt → verify) ────────────────

func TestOuterHashTamperDetectionTag(t *testing.T) {
	id, recipientStr := testIdentity(t)

	tagBytes := relay.ComputeTag(recipientStr)
	tag := base64.RawStdEncoding.EncodeToString(tagBytes[:4])
	expiresAt := time.Now().Add(10 * time.Minute).Unix()

	inner, _ := relay.BuildRequestPayload(1, "unwrap", "abc123", tag, expiresAt,
		[]relay.RelayStanza{{Type: "X25519", Args: []string{"a"}, Body: "Ym9keQ"}}, "ZXBoZW1lcmFs")
	encrypted, _ := relay.EncryptPayload(*inner, recipientStr)

	decrypted, _ := relay.DecryptPayload(encrypted, []age.Identity{id})
	err := relay.VerifyRequestPayload(decrypted, 1, "unwrap", "abc123", "TAMPERED", expiresAt)
	if err == nil {
		t.Fatal("expected outer_hash mismatch for tampered tag")
	}
}

func TestOuterHashTamperDetectionIntentID(t *testing.T) {
	id, recipientStr := testIdentity(t)

	expiresAt := time.Now().Add(10 * time.Minute).Unix()
	inner, _ := relay.BuildRequestPayload(1, "unwrap", "abc123", "QPg24g", expiresAt,
		[]relay.RelayStanza{{Type: "X25519", Args: []string{"a"}, Body: "Ym9keQ"}}, "ZXBoZW1lcmFs")
	encrypted, _ := relay.EncryptPayload(*inner, recipientStr)

	decrypted, _ := relay.DecryptPayload(encrypted, []age.Identity{id})
	err := relay.VerifyRequestPayload(decrypted, 1, "unwrap", "TAMPERED", "QPg24g", expiresAt)
	if err == nil {
		t.Fatal("expected outer_hash mismatch for tampered intent_id")
	}
}

func TestExpiresAtEnforcement(t *testing.T) {
	id, recipientStr := testIdentity(t)

	expiresAt := time.Now().Add(-1 * time.Minute).Unix() // already expired
	inner, _ := relay.BuildRequestPayload(1, "unwrap", "abc123", "QPg24g", expiresAt,
		[]relay.RelayStanza{{Type: "X25519", Args: []string{"a"}, Body: "Ym9keQ"}}, "ZXBoZW1lcmFs")
	encrypted, _ := relay.EncryptPayload(*inner, recipientStr)

	decrypted, _ := relay.DecryptPayload(encrypted, []age.Identity{id})
	err := relay.VerifyRequestPayload(decrypted, 1, "unwrap", "abc123", "QPg24g", expiresAt)
	if err == nil {
		t.Fatal("expected expiry error")
	}
}
