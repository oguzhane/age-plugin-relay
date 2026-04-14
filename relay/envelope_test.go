package relay

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestSealOpenFileKey(t *testing.T) {
	client, err := GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer client.Clear()

	fileKey := make([]byte, 16)
	rand.Read(fileKey)

	sealed, err := SealFileKey(fileKey, client.PublicKey)
	if err != nil {
		t.Fatalf("SealFileKey: %v", err)
	}

	recovered, err := OpenFileKey(sealed, client.PrivateKey)
	if err != nil {
		t.Fatalf("OpenFileKey: %v", err)
	}

	if !bytes.Equal(recovered, fileKey) {
		t.Fatalf("file key mismatch:\n  got:  %x\n  want: %x", recovered, fileKey)
	}
}

func TestOpenWrongKey(t *testing.T) {
	client, _ := GenerateEphemeral()
	other, _ := GenerateEphemeral()

	fileKey := make([]byte, 16)
	rand.Read(fileKey)

	sealed, _ := SealFileKey(fileKey, client.PublicKey)

	_, err := OpenFileKey(sealed, other.PrivateKey)
	if err == nil {
		t.Fatal("expected error when opening with wrong key")
	}
}

func TestOpenTruncated(t *testing.T) {
	_, err := OpenFileKey("dG9vc2hvcnQ", [32]byte{})
	if err == nil {
		t.Fatal("expected error for truncated sealed data")
	}
}

func TestSealDifferentEachTime(t *testing.T) {
	client, _ := GenerateEphemeral()
	fileKey := make([]byte, 16)
	rand.Read(fileKey)

	sealed1, _ := SealFileKey(fileKey, client.PublicKey)
	sealed2, _ := SealFileKey(fileKey, client.PublicKey)

	if sealed1 == sealed2 {
		t.Fatal("two seals of the same file key should differ (different server ephemerals + nonces)")
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

func TestSealOpenVariousSizes(t *testing.T) {
	// age file keys are always 16 bytes, but test boundary sizes for robustness.
	for _, size := range []int{0, 1, 15, 16, 32, 64, 256} {
		client, _ := GenerateEphemeral()
		data := make([]byte, size)
		rand.Read(data)

		sealed, err := SealFileKey(data, client.PublicKey)
		if err != nil {
			t.Fatalf("SealFileKey (size=%d): %v", size, err)
		}

		recovered, err := OpenFileKey(sealed, client.PrivateKey)
		if err != nil {
			t.Fatalf("OpenFileKey (size=%d): %v", size, err)
		}

		if !bytes.Equal(recovered, data) {
			t.Fatalf("round-trip mismatch (size=%d)", size)
		}
	}
}

func TestOpenBadBase64(t *testing.T) {
	_, err := OpenFileKey("not-valid-base64!!!@@@", [32]byte{})
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestOpenTamperedCiphertext(t *testing.T) {
	client, _ := GenerateEphemeral()
	fileKey := make([]byte, 16)
	rand.Read(fileKey)

	sealed, _ := SealFileKey(fileKey, client.PublicKey)

	// Decode, flip a byte in the ciphertext area, re-encode.
	raw, _ := base64.RawStdEncoding.DecodeString(sealed)
	raw[len(raw)-1] ^= 0xFF
	tampered := base64.RawStdEncoding.EncodeToString(raw)

	_, err := OpenFileKey(tampered, client.PrivateKey)
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
