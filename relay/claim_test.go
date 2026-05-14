package relay_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	relay "github.com/oguzhane/age-plugin-relay/relay"
)

func TestGenerateIntentClaim(t *testing.T) {
	pub, priv, err := relay.GenerateIntentClaim()
	if err != nil {
		t.Fatalf("GenerateIntentClaim: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("expected %d-byte public key, got %d", ed25519.PublicKeySize, len(pub))
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("expected %d-byte private key, got %d", ed25519.PrivateKeySize, len(priv))
	}
}

func TestEncodeDecodeIntentClaimSecret(t *testing.T) {
	_, priv, err := relay.GenerateIntentClaim()
	if err != nil {
		t.Fatal(err)
	}
	encoded := relay.EncodeIntentClaimSecret(priv)
	decoded, err := relay.DecodeIntentClaimSecret(encoded)
	if err != nil {
		t.Fatalf("DecodeIntentClaimSecret: %v", err)
	}
	if !priv.Equal(decoded) {
		t.Fatal("round-trip failed: decoded key != original")
	}
}

func TestSignAndVerifyIntentClaim(t *testing.T) {
	pub, priv, _ := relay.GenerateIntentClaim()
	pubB64 := relay.EncodeIntentClaimPub(pub)

	sig := relay.SignIntentClaim(priv, 1, "fulfill", "intent-abc", "encrypted-data")
	if err := relay.VerifyIntentClaim(pubB64, sig, 1, "fulfill", "intent-abc", "encrypted-data"); err != nil {
		t.Fatalf("expected valid signature, got: %v", err)
	}
}

func TestVerifyIntentClaimWrongKey(t *testing.T) {
	_, priv, _ := relay.GenerateIntentClaim()
	otherPub, _, _ := relay.GenerateIntentClaim()
	otherPubB64 := relay.EncodeIntentClaimPub(otherPub)

	sig := relay.SignIntentClaim(priv, 1, "fulfill", "intent-abc", "encrypted-data")
	err := relay.VerifyIntentClaim(otherPubB64, sig, 1, "fulfill", "intent-abc", "encrypted-data")
	if err == nil {
		t.Fatal("expected error verifying with wrong public key")
	}
	if err.Error() != "invalid_claim_sig" {
		t.Fatalf("expected invalid_claim_sig, got: %v", err)
	}
}

func TestVerifyIntentClaimTamperedAction(t *testing.T) {
	pub, priv, _ := relay.GenerateIntentClaim()
	pubB64 := relay.EncodeIntentClaimPub(pub)

	sig := relay.SignIntentClaim(priv, 1, "fulfill", "intent-abc", "encrypted-data")
	// Tamper: change action
	err := relay.VerifyIntentClaim(pubB64, sig, 1, "reject", "intent-abc", "encrypted-data")
	if err == nil {
		t.Fatal("expected error for tampered action")
	}
}

func TestVerifyIntentClaimTamperedIntentID(t *testing.T) {
	pub, priv, _ := relay.GenerateIntentClaim()
	pubB64 := relay.EncodeIntentClaimPub(pub)

	sig := relay.SignIntentClaim(priv, 1, "fulfill", "intent-abc", "encrypted-data")
	err := relay.VerifyIntentClaim(pubB64, sig, 1, "fulfill", "tampered-id", "encrypted-data")
	if err == nil {
		t.Fatal("expected error for tampered intent_id")
	}
}

func TestVerifyIntentClaimTamperedPayload(t *testing.T) {
	pub, priv, _ := relay.GenerateIntentClaim()
	pubB64 := relay.EncodeIntentClaimPub(pub)

	sig := relay.SignIntentClaim(priv, 1, "fulfill", "intent-abc", "encrypted-data")
	err := relay.VerifyIntentClaim(pubB64, sig, 1, "fulfill", "intent-abc", "tampered-data")
	if err == nil {
		t.Fatal("expected error for tampered encrypted_payload")
	}
}

func TestIntentClaimCanonical(t *testing.T) {
	c := relay.IntentClaimCanonical(1, "fulfill", "abc123", "payload-data")
	if c == "" {
		t.Fatal("expected non-empty canonical string")
	}
	// Should be deterministic
	c2 := relay.IntentClaimCanonical(1, "fulfill", "abc123", "payload-data")
	if c != c2 {
		t.Fatal("canonical string not deterministic")
	}
	// Different inputs should produce different canonicals
	c3 := relay.IntentClaimCanonical(1, "reject", "abc123", "payload-data")
	if c == c3 {
		t.Fatal("different action should produce different canonical")
	}
}

func TestVerifyIntentClaimInvalidPubKey(t *testing.T) {
	_, priv, _ := relay.GenerateIntentClaim()
	sig := relay.SignIntentClaim(priv, 1, "fulfill", "abc", "data")

	err := relay.VerifyIntentClaim("not-valid-base64!!!", sig, 1, "fulfill", "abc", "data")
	if err == nil {
		t.Fatal("expected error for invalid pub key")
	}
}

func TestVerifyIntentClaimInvalidSignature(t *testing.T) {
	pub, _, _ := relay.GenerateIntentClaim()
	pubB64 := relay.EncodeIntentClaimPub(pub)

	err := relay.VerifyIntentClaim(pubB64, "not-valid-base64!!!", 1, "fulfill", "abc", "data")
	if err == nil {
		t.Fatal("expected error for invalid signature encoding")
	}
}

func TestVerifyIntentClaimWrongSizeKey(t *testing.T) {
	// 16 bytes instead of 32
	shortKey := make([]byte, 16)
	rand.Read(shortKey)
	pubB64 := relay.EncodeIntentClaimPub(shortKey)

	err := relay.VerifyIntentClaim(pubB64, "AAAA", 1, "fulfill", "abc", "data")
	if err == nil {
		t.Fatal("expected error for wrong-size public key")
	}
}
