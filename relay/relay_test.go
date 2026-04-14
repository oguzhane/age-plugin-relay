package relay

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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
	var tag [TagSize]byte
	for i := range tag {
		tag[i] = byte(i + 1)
	}
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
	if len(tagBytes) != TagSize {
		t.Fatalf("expected %d-byte tag, got %d", TagSize, len(tagBytes))
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
	var tag [TagSize]byte
	for i := range tag {
		tag[i] = 0xFF
	}
	id := &RelayIdentity{
		Tag:    tag,
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

// newMockSSERelayServer starts an httptest server that responds with SSE events.
func newMockSSERelayServer(t *testing.T, identity *age.X25519Identity) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req RelayRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
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

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)

		// Send a heartbeat comment first.
		fmt.Fprintf(w, ": heartbeat\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		fileKey, err := identity.Unwrap(stanzas)
		if err != nil {
			data, _ := json.Marshal(RelayResponse{Error: err.Error()})
			fmt.Fprintf(w, "event: error\ndata: %s\n\n", data)
			return
		}

		data, _ := json.Marshal(RelayResponse{
			FileKey: base64.RawStdEncoding.EncodeToString(fileKey),
		})
		fmt.Fprintf(w, "event: result\ndata: %s\n\n", data)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
}

func TestEndToEndWithSSERelay(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recipientStr := identity.Recipient().String()

	server := newMockSSERelayServer(t, identity)
	defer server.Close()

	relayRecipient, err := NewRelayRecipient([]byte(recipientStr))
	if err != nil {
		t.Fatal(err)
	}

	fileKey := make([]byte, 16)
	rand.Read(fileKey)

	stanzas, err := relayRecipient.Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}

	tag := ComputeTag(recipientStr)
	relayIdentity := &RelayIdentity{
		Tag:    tag,
		Remote: RemoteConfig{URL: server.URL, Stream: true},
	}

	recovered, err := relayIdentity.Unwrap(stanzas)
	if err != nil {
		t.Fatalf("SSE Unwrap: %v", err)
	}

	if !bytes.Equal(recovered, fileKey) {
		t.Fatalf("file key mismatch:\n  got:  %x\n  want: %x", recovered, fileKey)
	}
	t.Log("SSE relay unwrap succeeded")
}

func TestSSERelayError(t *testing.T) {
	// Encrypt to identity A, relay has identity B (wrong key) via SSE.
	identityA, _ := age.GenerateX25519Identity()
	identityB, _ := age.GenerateX25519Identity()
	recipientA := identityA.Recipient().String()

	server := newMockSSERelayServer(t, identityB)
	defer server.Close()

	relayRecipient, _ := NewRelayRecipient([]byte(recipientA))
	fileKey := make([]byte, 16)
	rand.Read(fileKey)
	stanzas, _ := relayRecipient.Wrap(fileKey)

	tag := ComputeTag(recipientA)
	relayIdentity := &RelayIdentity{
		Tag:    tag,
		Remote: RemoteConfig{URL: server.URL, Stream: true},
	}

	_, err := relayIdentity.Unwrap(stanzas)
	if err == nil {
		t.Fatal("expected error from SSE relay with wrong identity")
	}
	t.Logf("Got expected SSE error: %v", err)
}

// newMockHMACRelayServer starts an httptest server that verifies HMAC signatures
// before unwrapping stanzas.
func newMockHMACRelayServer(t *testing.T, identity *age.X25519Identity, hmacKey string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		// Verify HMAC.
		sig := r.Header.Get(HMACHeaderSignature)
		ts := r.Header.Get(HMACHeaderTimestamp)
		nonce := r.Header.Get(HMACHeaderNonce)
		if sig == "" || ts == "" || nonce == "" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(RelayResponse{Error: "missing HMAC headers"})
			return
		}
		if err := ValidateTimestamp(ts); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(RelayResponse{Error: err.Error()})
			return
		}
		if err := VerifySignature([]byte(hmacKey), ts, nonce, body, sig); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(RelayResponse{Error: err.Error()})
			return
		}

		var req RelayRequest
		if err := json.Unmarshal(body, &req); err != nil {
			json.NewEncoder(w).Encode(RelayResponse{Error: err.Error()})
			return
		}

		var stanzas []*age.Stanza
		for _, s := range req.Stanzas {
			b, _ := base64.RawStdEncoding.DecodeString(s.Body)
			stanzas = append(stanzas, &age.Stanza{Type: s.Type, Args: s.Args, Body: b})
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

func TestEndToEndWithHMACRelay(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recipientStr := identity.Recipient().String()
	hmacSecret := "my-shared-hmac-secret"

	server := newMockHMACRelayServer(t, identity, hmacSecret)
	defer server.Close()

	relayRecipient, err := NewRelayRecipient([]byte(recipientStr))
	if err != nil {
		t.Fatal(err)
	}

	fileKey := make([]byte, 16)
	rand.Read(fileKey)

	stanzas, err := relayRecipient.Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}

	tag := ComputeTag(recipientStr)
	relayIdentity := &RelayIdentity{
		Tag: tag,
		Remote: RemoteConfig{
			URL:     server.URL,
			HMACKey: hmacSecret,
		},
	}

	recovered, err := relayIdentity.Unwrap(stanzas)
	if err != nil {
		t.Fatalf("HMAC Unwrap: %v", err)
	}

	if !bytes.Equal(recovered, fileKey) {
		t.Fatalf("file key mismatch:\n  got:  %x\n  want: %x", recovered, fileKey)
	}
	t.Log("HMAC relay unwrap succeeded")
}

func TestHMACRelayRejectsNoSignature(t *testing.T) {
	identity, _ := age.GenerateX25519Identity()
	recipientStr := identity.Recipient().String()

	server := newMockHMACRelayServer(t, identity, "secret")
	defer server.Close()

	relayRecipient, _ := NewRelayRecipient([]byte(recipientStr))
	fileKey := make([]byte, 16)
	rand.Read(fileKey)
	stanzas, _ := relayRecipient.Wrap(fileKey)

	tag := ComputeTag(recipientStr)
	// No HMACKey → no signature headers sent → server rejects.
	relayIdentity := &RelayIdentity{
		Tag:    tag,
		Remote: RemoteConfig{URL: server.URL},
	}

	_, err := relayIdentity.Unwrap(stanzas)
	if err == nil {
		t.Fatal("expected error when HMAC headers are missing")
	}
	t.Logf("Got expected error: %v", err)
}

func TestHMACRelayRejectsWrongKey(t *testing.T) {
	identity, _ := age.GenerateX25519Identity()
	recipientStr := identity.Recipient().String()

	server := newMockHMACRelayServer(t, identity, "correct-key")
	defer server.Close()

	relayRecipient, _ := NewRelayRecipient([]byte(recipientStr))
	fileKey := make([]byte, 16)
	rand.Read(fileKey)
	stanzas, _ := relayRecipient.Wrap(fileKey)

	tag := ComputeTag(recipientStr)
	relayIdentity := &RelayIdentity{
		Tag: tag,
		Remote: RemoteConfig{
			URL:     server.URL,
			HMACKey: "wrong-key",
		},
	}

	_, err := relayIdentity.Unwrap(stanzas)
	if err == nil {
		t.Fatal("expected error for wrong HMAC key")
	}
	t.Logf("Got expected error: %v", err)
}

// newMockEnvelopeRelayServer starts an httptest server that verifies HMAC
// (including ephemeral key) and returns an encrypted file key response.
func newMockEnvelopeRelayServer(t *testing.T, identity *age.X25519Identity, hmacSecret string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		sig := r.Header.Get(HMACHeaderSignature)
		ts := r.Header.Get(HMACHeaderTimestamp)
		nonce := r.Header.Get(HMACHeaderNonce)
		ephKey := r.Header.Get(EnvelopeHeader)
		if sig == "" || ts == "" || nonce == "" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(RelayResponse{Error: "missing HMAC headers"})
			return
		}
		if err := VerifySignature([]byte(hmacSecret), ts, nonce, body, sig, ephKey); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(RelayResponse{Error: err.Error()})
			return
		}

		var req RelayRequest
		json.Unmarshal(body, &req)

		var stanzas []*age.Stanza
		for _, s := range req.Stanzas {
			b, _ := base64.RawStdEncoding.DecodeString(s.Body)
			stanzas = append(stanzas, &age.Stanza{Type: s.Type, Args: s.Args, Body: b})
		}

		fileKey, err := identity.Unwrap(stanzas)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(RelayResponse{Error: err.Error()})
			return
		}

		// If ephemeral key is provided, seal the response.
		if ephKey != "" {
			ephBytes, _ := base64.RawStdEncoding.DecodeString(ephKey)
			var clientPub [32]byte
			copy(clientPub[:], ephBytes)
			sealed, err := SealFileKey(fileKey, clientPub)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(RelayResponse{Error: "seal failed"})
				return
			}
			json.NewEncoder(w).Encode(RelayResponse{EncryptedFileKey: sealed})
			return
		}

		json.NewEncoder(w).Encode(RelayResponse{
			FileKey: base64.RawStdEncoding.EncodeToString(fileKey),
		})
	}))
}

func TestEndToEndWithEnvelopeEncryption(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recipientStr := identity.Recipient().String()
	hmacSecret := "envelope-test-secret"

	server := newMockEnvelopeRelayServer(t, identity, hmacSecret)
	defer server.Close()

	relayRecipient, err := NewRelayRecipient([]byte(recipientStr))
	if err != nil {
		t.Fatal(err)
	}

	fileKey := make([]byte, 16)
	rand.Read(fileKey)

	stanzas, err := relayRecipient.Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}

	tag := ComputeTag(recipientStr)
	relayIdentity := &RelayIdentity{
		Tag: tag,
		Remote: RemoteConfig{
			URL:               server.URL,
			HMACKey:           hmacSecret,
			EncryptedResponse: true,
		},
	}

	recovered, err := relayIdentity.Unwrap(stanzas)
	if err != nil {
		t.Fatalf("Envelope Unwrap: %v", err)
	}

	if !bytes.Equal(recovered, fileKey) {
		t.Fatalf("file key mismatch:\n  got:  %x\n  want: %x", recovered, fileKey)
	}
	t.Log("Envelope encrypted relay unwrap succeeded")
}

func TestEnvelopeRejectsSwappedEphemeralKey(t *testing.T) {
	// If an attacker swaps the ephemeral key, HMAC verification should fail.
	identity, _ := age.GenerateX25519Identity()
	recipientStr := identity.Recipient().String()
	hmacSecret := "swap-test"

	server := newMockEnvelopeRelayServer(t, identity, hmacSecret)
	defer server.Close()

	relayRecipient, _ := NewRelayRecipient([]byte(recipientStr))
	fileKey := make([]byte, 16)
	rand.Read(fileKey)
	stanzas, _ := relayRecipient.Wrap(fileKey)

	// Manually craft a request with mismatched ephemeral key in HMAC vs header.
	// This simulates a MITM swapping the header after signing.
	reqBody := RelayRequest{
		Version: 1,
		Action:  "unwrap",
		Stanzas: []RelayStanza{{
			Type: stanzas[0].Type,
			Args: stanzas[0].Args,
			Body: base64.RawStdEncoding.EncodeToString(stanzas[0].Body),
		}},
	}
	body, _ := json.Marshal(reqBody)

	// Sign with one ephemeral key.
	realEph, _ := GenerateEphemeral()
	realEphB64 := base64.RawStdEncoding.EncodeToString(realEph.PublicKey[:])
	ts, nonce, sig, _ := SignRequest([]byte(hmacSecret), body, realEphB64)

	// But send a different ephemeral key in the header.
	fakeEph, _ := GenerateEphemeral()
	fakeEphB64 := base64.RawStdEncoding.EncodeToString(fakeEph.PublicKey[:])

	httpReq, _ := http.NewRequest("POST", server.URL, bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(HMACHeaderTimestamp, ts)
	httpReq.Header.Set(HMACHeaderNonce, nonce)
	httpReq.Header.Set(HMACHeaderSignature, sig)
	httpReq.Header.Set(EnvelopeHeader, fakeEphB64) // swapped!

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for swapped ephemeral key, got %d", resp.StatusCode)
	}
	t.Log("Swapped ephemeral key correctly rejected by HMAC")
}

// newMockSSEEnvelopeRelayServer starts an httptest server that verifies HMAC,
// seals the file key with SSE, and returns encrypted_file_key in the SSE event.
func newMockSSEEnvelopeRelayServer(t *testing.T, identity *age.X25519Identity, hmacSecret string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		sig := r.Header.Get(HMACHeaderSignature)
		ts := r.Header.Get(HMACHeaderTimestamp)
		nonce := r.Header.Get(HMACHeaderNonce)
		ephKey := r.Header.Get(EnvelopeHeader)
		if err := VerifySignature([]byte(hmacSecret), ts, nonce, body, sig, ephKey); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(RelayResponse{Error: err.Error()})
			return
		}

		var req RelayRequest
		json.Unmarshal(body, &req)

		var stanzas []*age.Stanza
		for _, s := range req.Stanzas {
			b, _ := base64.RawStdEncoding.DecodeString(s.Body)
			stanzas = append(stanzas, &age.Stanza{Type: s.Type, Args: s.Args, Body: b})
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)

		fmt.Fprintf(w, ": heartbeat\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		fileKey, err := identity.Unwrap(stanzas)
		if err != nil {
			data, _ := json.Marshal(RelayResponse{Error: err.Error()})
			fmt.Fprintf(w, "event: error\ndata: %s\n\n", data)
			return
		}

		resp := RelayResponse{}
		if ephKey != "" {
			ephBytes, _ := base64.RawStdEncoding.DecodeString(ephKey)
			var clientPub [32]byte
			copy(clientPub[:], ephBytes)
			sealed, _ := SealFileKey(fileKey, clientPub)
			resp.EncryptedFileKey = sealed
		} else {
			resp.FileKey = base64.RawStdEncoding.EncodeToString(fileKey)
		}

		data, _ := json.Marshal(resp)
		fmt.Fprintf(w, "event: result\ndata: %s\n\n", data)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
}

func TestEndToEndSSEWithEnvelopeEncryption(t *testing.T) {
	identity, _ := age.GenerateX25519Identity()
	recipientStr := identity.Recipient().String()
	hmacSecret := "sse-envelope-secret"

	server := newMockSSEEnvelopeRelayServer(t, identity, hmacSecret)
	defer server.Close()

	relayRecipient, _ := NewRelayRecipient([]byte(recipientStr))
	fileKey := make([]byte, 16)
	rand.Read(fileKey)
	stanzas, _ := relayRecipient.Wrap(fileKey)

	tag := ComputeTag(recipientStr)
	relayIdentity := &RelayIdentity{
		Tag: tag,
		Remote: RemoteConfig{
			URL:               server.URL,
			HMACKey:           hmacSecret,
			Stream:            true,
			EncryptedResponse: true,
		},
	}

	recovered, err := relayIdentity.Unwrap(stanzas)
	if err != nil {
		t.Fatalf("SSE Envelope Unwrap: %v", err)
	}

	if !bytes.Equal(recovered, fileKey) {
		t.Fatalf("file key mismatch:\n  got:  %x\n  want: %x", recovered, fileKey)
	}
	t.Log("SSE + envelope encrypted relay unwrap succeeded")
}

func TestEnvelopeFallbackToPlaintext(t *testing.T) {
	// Server does NOT seal (no ephemeral key sent), client has EncryptedResponse=false.
	// This confirms the plaintext path still works even when the server could seal.
	identity, _ := age.GenerateX25519Identity()
	recipientStr := identity.Recipient().String()
	hmacSecret := "fallback-test"

	server := newMockEnvelopeRelayServer(t, identity, hmacSecret)
	defer server.Close()

	relayRecipient, _ := NewRelayRecipient([]byte(recipientStr))
	fileKey := make([]byte, 16)
	rand.Read(fileKey)
	stanzas, _ := relayRecipient.Wrap(fileKey)

	tag := ComputeTag(recipientStr)
	relayIdentity := &RelayIdentity{
		Tag: tag,
		Remote: RemoteConfig{
			URL:               server.URL,
			HMACKey:           hmacSecret,
			EncryptedResponse: false, // no envelope
		},
	}

	recovered, err := relayIdentity.Unwrap(stanzas)
	if err != nil {
		t.Fatalf("Plaintext fallback Unwrap: %v", err)
	}

	if !bytes.Equal(recovered, fileKey) {
		t.Fatalf("file key mismatch:\n  got:  %x\n  want: %x", recovered, fileKey)
	}
	t.Log("Plaintext fallback (no envelope) succeeded")
}

func TestEnvelopeWithWrongRelayIdentity(t *testing.T) {
	// Encrypt to identity A, relay has identity B (wrong key), envelope enabled.
	identityA, _ := age.GenerateX25519Identity()
	identityB, _ := age.GenerateX25519Identity()
	recipientA := identityA.Recipient().String()
	hmacSecret := "wrong-id-envelope"

	server := newMockEnvelopeRelayServer(t, identityB, hmacSecret)
	defer server.Close()

	relayRecipient, _ := NewRelayRecipient([]byte(recipientA))
	fileKey := make([]byte, 16)
	rand.Read(fileKey)
	stanzas, _ := relayRecipient.Wrap(fileKey)

	tag := ComputeTag(recipientA)
	relayIdentity := &RelayIdentity{
		Tag: tag,
		Remote: RemoteConfig{
			URL:               server.URL,
			HMACKey:           hmacSecret,
			EncryptedResponse: true,
		},
	}

	_, err := relayIdentity.Unwrap(stanzas)
	if err == nil {
		t.Fatal("expected error when relay has wrong identity with envelope")
	}
	t.Logf("Got expected error: %v", err)
}

func TestExtractFileKeyPlaintext(t *testing.T) {
	fk := make([]byte, 16)
	rand.Read(fk)
	resp := RelayResponse{FileKey: base64.RawStdEncoding.EncodeToString(fk)}

	got, err := extractFileKey(resp, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, fk) {
		t.Fatal("mismatch")
	}
}

func TestExtractFileKeyEncrypted(t *testing.T) {
	ek, _ := GenerateEphemeral()
	fk := make([]byte, 16)
	rand.Read(fk)

	sealed, _ := SealFileKey(fk, ek.PublicKey)
	resp := RelayResponse{EncryptedFileKey: sealed}

	got, err := extractFileKey(resp, ek)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, fk) {
		t.Fatal("mismatch")
	}
}

func TestExtractFileKeyEmpty(t *testing.T) {
	_, err := extractFileKey(RelayResponse{}, nil)
	if err == nil {
		t.Fatal("expected error for empty response")
	}
}

func TestExtractFileKeyPrefersEncrypted(t *testing.T) {
	// When both file_key and encrypted_file_key are set, and ephemeral is
	// provided, encrypted_file_key should be used.
	ek, _ := GenerateEphemeral()
	fk := make([]byte, 16)
	rand.Read(fk)

	sealed, _ := SealFileKey(fk, ek.PublicKey)
	resp := RelayResponse{
		FileKey:          "AAAAAAAAAAAAAAAAAAAAAA", // decoy — should not be used
		EncryptedFileKey: sealed,
	}

	got, err := extractFileKey(resp, ek)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, fk) {
		t.Fatal("should have used encrypted_file_key, not file_key")
	}
}
