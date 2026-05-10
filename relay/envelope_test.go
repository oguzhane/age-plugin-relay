package relay

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestSealOpenResponse(t *testing.T) {
	client, err := GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer client.Clear()

	inner := InnerResponsePayload{
		Nonce:     "deadbeef01020304deadbeef01020304",
		OuterHash: "abcdef1234567890",
		FileKey:   base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef")),
	}

	sealed, err := SealResponse(inner, client.PublicKey)
	if err != nil {
		t.Fatalf("SealResponse: %v", err)
	}

	recovered, err := OpenResponse(sealed, client.PrivateKey)
	if err != nil {
		t.Fatalf("OpenResponse: %v", err)
	}

	if recovered.Nonce != inner.Nonce {
		t.Errorf("nonce mismatch: %q != %q", recovered.Nonce, inner.Nonce)
	}
	if recovered.OuterHash != inner.OuterHash {
		t.Errorf("outer_hash mismatch: %q != %q", recovered.OuterHash, inner.OuterHash)
	}
	if recovered.FileKey != inner.FileKey {
		t.Errorf("file_key mismatch: %q != %q", recovered.FileKey, inner.FileKey)
	}
}

func TestOpenResponseWrongKey(t *testing.T) {
	client, _ := GenerateEphemeral()
	other, _ := GenerateEphemeral()

	inner := InnerResponsePayload{
		Nonce:     "deadbeef01020304deadbeef01020304",
		OuterHash: "hash",
		FileKey:   "ZmlsZWtleQ",
	}

	sealed, _ := SealResponse(inner, client.PublicKey)

	_, err := OpenResponse(sealed, other.PrivateKey)
	if err == nil {
		t.Fatal("expected error when opening with wrong key")
	}
}

func TestOpenResponseTruncated(t *testing.T) {
	_, err := OpenResponse("dG9vc2hvcnQ", [32]byte{})
	if err == nil {
		t.Fatal("expected error for truncated sealed data")
	}
}

func TestSealResponseDifferentEachTime(t *testing.T) {
	client, _ := GenerateEphemeral()
	inner := InnerResponsePayload{
		Nonce:     "deadbeef01020304deadbeef01020304",
		OuterHash: "hash",
		FileKey:   "ZmlsZWtleQ",
	}

	sealed1, _ := SealResponse(inner, client.PublicKey)
	sealed2, _ := SealResponse(inner, client.PublicKey)

	if sealed1 == sealed2 {
		t.Fatal("two seals should differ (different server ephemerals + nonces)")
	}
}

func TestEphemeralClear(t *testing.T) {
	ek, _ := GenerateEphemeral()
	ek.Clear()
	var zero [32]byte
	if ek.PrivateKey != zero {
		t.Fatal("private key not zeroed after Clear()")
	}
}

func TestOpenResponseBadBase64(t *testing.T) {
	_, err := OpenResponse("not-valid-base64!!!@@@", [32]byte{})
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestOpenResponseTamperedCiphertext(t *testing.T) {
	client, _ := GenerateEphemeral()
	inner := InnerResponsePayload{
		Nonce:     "deadbeef01020304deadbeef01020304",
		OuterHash: "hash",
		FileKey:   "ZmlsZWtleQ",
	}

	sealed, _ := SealResponse(inner, client.PublicKey)

	// Decode, flip a byte in the ciphertext area, re-encode.
	raw, _ := base64.RawStdEncoding.DecodeString(sealed)
	raw[len(raw)-1] ^= 0xFF
	tampered := base64.RawStdEncoding.EncodeToString(raw)

	_, err := OpenResponse(tampered, client.PrivateKey)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

func TestDerivePublicKeyConsistency(t *testing.T) {
	ek, _ := GenerateEphemeral()
	derived := DerivePublicKey(ek.PrivateKey)
	if derived != ek.PublicKey {
		t.Fatalf("DerivePublicKey does not match GenerateEphemeral public key:\n  derived: %x\n  actual:  %x", derived, ek.PublicKey)
	}
}

func TestEphemeralKeypairsAreUnique(t *testing.T) {
	seen := make(map[[32]byte]bool)
	for i := 0; i < 50; i++ {
		ek, _ := GenerateEphemeral()
		if seen[ek.PublicKey] {
			t.Fatalf("duplicate public key on iteration %d", i)
		}
		seen[ek.PublicKey] = true
	}
}

func TestSealOpenResponseVariousSizes(t *testing.T) {
	// Test with various file key sizes for robustness.
	for _, size := range []int{0, 1, 15, 16, 32, 64} {
		client, _ := GenerateEphemeral()
		data := make([]byte, size)
		rand.Read(data)

		inner := InnerResponsePayload{
			Nonce:     "deadbeef01020304deadbeef01020304",
			OuterHash: "hash",
			FileKey:   base64.RawStdEncoding.EncodeToString(data),
		}

		sealed, err := SealResponse(inner, client.PublicKey)
		if err != nil {
			t.Fatalf("SealResponse (size=%d): %v", size, err)
		}

		recovered, err := OpenResponse(sealed, client.PrivateKey)
		if err != nil {
			t.Fatalf("OpenResponse (size=%d): %v", size, err)
		}

		if recovered.FileKey != inner.FileKey {
			t.Fatalf("round-trip mismatch (size=%d)", size)
		}
	}
}
