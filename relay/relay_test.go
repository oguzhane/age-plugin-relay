package relay

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

func TestComputeTagDeterministic(t *testing.T) {
	tag1 := ComputeTag("age1abc")
	tag2 := ComputeTag("age1abc")
	if tag1 != tag2 {
		t.Fatalf("tags differ for same input: %x vs %x", tag1, tag2)
	}
}

func TestComputeTagDifferent(t *testing.T) {
	tag1 := ComputeTag("age1abc")
	tag2 := ComputeTag("age1def")
	if tag1 == tag2 {
		t.Fatalf("tags should differ for different inputs")
	}
}

func TestEncodeDecodeRecipient(t *testing.T) {
	inner := "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq"
	encoded := EncodeRelayRecipient(inner)

	if !strings.HasPrefix(encoded, "age1relay1") {
		t.Fatalf("expected age1relay1 prefix, got %s", encoded)
	}

	_, data, err := plugin.ParseRecipient(encoded)
	if err != nil {
		t.Fatalf("parsing encoded recipient: %v", err)
	}
	if string(data) != inner {
		t.Fatalf("round-trip mismatch: got %q, want %q", string(data), inner)
	}
}

func TestEncodeDecodeIdentity(t *testing.T) {
	tag := [4]byte{0x01, 0x02, 0x03, 0x04}
	url := "https://relay.example.com:8443/unwrap"

	encoded := EncodeRelayIdentity(tag, url)
	if !strings.HasPrefix(encoded, "AGE-PLUGIN-RELAY-1") {
		t.Fatalf("expected AGE-PLUGIN-RELAY-1 prefix, got %s", encoded)
	}

	_, data, err := plugin.ParseIdentity(encoded)
	if err != nil {
		t.Fatalf("parsing encoded identity: %v", err)
	}

	gotTag, gotTarget, err := DecodeIdentityData(data)
	if err != nil {
		t.Fatalf("decoding identity data: %v", err)
	}
	if gotTag != tag {
		t.Fatalf("tag mismatch: %x vs %x", gotTag, tag)
	}
	if gotTarget != url {
		t.Fatalf("target mismatch: %q vs %q", gotTarget, url)
	}
}

func TestWrapProducesRelayStanzas(t *testing.T) {
	inner := "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq"
	r, err := NewRelayRecipient([]byte(inner))
	if err != nil {
		t.Fatalf("NewRelayRecipient: %v", err)
	}

	fileKey := make([]byte, 16)
	if _, err := rand.Read(fileKey); err != nil {
		t.Fatalf("generating file key: %v", err)
	}

	stanzas, err := r.Wrap(fileKey)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	if len(stanzas) == 0 {
		t.Fatal("expected at least 1 stanza")
	}

	s := stanzas[0]
	if s.Type != "relay" {
		t.Fatalf("expected stanza type 'relay', got %q", s.Type)
	}
	if len(s.Args) < 2 {
		t.Fatalf("expected >= 2 args, got %d", len(s.Args))
	}

	tagBytes, err := base64.RawStdEncoding.DecodeString(s.Args[0])
	if err != nil {
		t.Fatalf("decoding tag: %v", err)
	}
	if len(tagBytes) != 4 {
		t.Fatalf("expected 4-byte tag, got %d", len(tagBytes))
	}
	if s.Args[1] != "X25519" {
		t.Fatalf("expected inner type X25519, got %q", s.Args[1])
	}
	if len(s.Body) == 0 {
		t.Fatal("expected non-empty body")
	}
}

func TestEndToEndWithMockRelay(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generating identity: %v", err)
	}
	recipientStr := identity.Recipient().String()

	server := newMockRelayServer(t, identity)
	defer server.Close()

	relayRecipient, err := NewRelayRecipient([]byte(recipientStr))
	if err != nil {
		t.Fatalf("NewRelayRecipient: %v", err)
	}

	fileKey := make([]byte, 16)
	if _, err := rand.Read(fileKey); err != nil {
		t.Fatalf("generating file key: %v", err)
	}

	stanzas, err := relayRecipient.Wrap(fileKey)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	tag := ComputeTag(recipientStr)
	relayIdentity := &RelayIdentity{
		Tag:    tag,
		Remote: RemoteConfig{URL: server.URL},
	}

	recovered, err := relayIdentity.Unwrap(stanzas)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}

	if !bytes.Equal(recovered, fileKey) {
		t.Fatalf("file key mismatch:\n  got:  %x\n  want: %x", recovered, fileKey)
	}
}

func TestUnwrapNoMatchingStanza(t *testing.T) {
	id := &RelayIdentity{
		Tag:    [4]byte{0xFF, 0xFF, 0xFF, 0xFF},
		Remote: RemoteConfig{URL: "http://localhost:1/unused"},
	}

	stanzas := []*age.Stanza{
		{Type: "X25519", Args: []string{"foo"}, Body: []byte("bar")},
	}

	_, err := id.Unwrap(stanzas)
	if err == nil {
		t.Fatal("expected error for non-matching stanzas")
	}
}

// newMockRelayServer starts an httptest server that unwraps stanzas using the
// given age identity.
func newMockRelayServer(t *testing.T, identity *age.X25519Identity) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req RelayRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			json.NewEncoder(w).Encode(RelayResponse{Error: err.Error()})
			return
		}

		var stanzas []*age.Stanza
		for _, s := range req.Stanzas {
			body, _ := base64.RawStdEncoding.DecodeString(s.Body)
			stanzas = append(stanzas, &age.Stanza{
				Type: s.Type,
				Args: s.Args,
				Body: body,
			})
		}

		fileKey, err := identity.Unwrap(stanzas)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(RelayResponse{Error: err.Error()})
			return
		}

		json.NewEncoder(w).Encode(RelayResponse{
			FileKey: base64.RawStdEncoding.EncodeToString(fileKey),
		})
	}))
}
