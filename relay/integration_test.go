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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestIntegrationConfigMode(t *testing.T) {
	remoteIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	remotePubKey := remoteIdentity.Recipient().String()

	server := newMockRelayServer(t, remoteIdentity)
	defer server.Close()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "relay-config.yaml")
	configContent := "remotes:\n  testremote:\n    url: " + server.URL +
		"\n    unwrap_recipient: " + remotePubKey +
		"\n    timeout: 10s\n"
	os.WriteFile(configPath, []byte(configContent), 0644)
	t.Setenv("AGE_PLUGIN_RELAY_CONFIG", configPath)

	relayRecipient, err := NewRelayRecipient([]byte(remotePubKey))
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("Config mode: secrets encrypted with named remote 'testremote'")

	var ciphertext bytes.Buffer
	w, err := age.Encrypt(&ciphertext, relayRecipient)
	if err != nil {
		t.Fatalf("age.Encrypt: %v", err)
	}
	w.Write(plaintext)
	w.Close()

	tag := ComputeTag(remotePubKey)

	remote, err := ResolveRemote("testremote")
	if err != nil {
		t.Fatalf("ResolveRemote: %v", err)
	}
	if remote.URL != server.URL {
		t.Fatalf("resolved URL mismatch: %q vs %q", remote.URL, server.URL)
	}
	t.Logf("Resolved remote 'testremote' → URL=%s, timeout=%s", remote.URL, remote.Timeout)

	relayIdentity := &RelayIdentity{Tag: tag, Remote: remote}

	r, err := age.Decrypt(bytes.NewReader(ciphertext.Bytes()), relayIdentity)
	if err != nil {
		t.Fatalf("age.Decrypt: %v", err)
	}
	decrypted, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading decrypted: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("plaintext mismatch:\n  got:  %q\n  want: %q", decrypted, plaintext)
	}
	t.Logf("Decrypted OK: %q", decrypted)
}

func TestIntegrationConfigMissingRemote(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "relay-config.yaml")
	os.WriteFile(configPath, []byte("remotes:\n  alpha:\n    url: http://localhost:1/unused\n    unwrap_recipient: age1unused\n"), 0644)
	t.Setenv("AGE_PLUGIN_RELAY_CONFIG", configPath)

	_, err := ResolveRemote("nonexistent")
	if err == nil {
		t.Fatal("expected error for missing remote")
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Fatalf("error should mention remote name, got: %v", err)
	}
	t.Logf("Got expected error: %v", err)
}

func TestIntegrationRelayServerDown(t *testing.T) {
	remoteIdentity, _ := age.GenerateX25519Identity()
	remotePubKey := remoteIdentity.Recipient().String()
	relayRecipient, _ := NewRelayRecipient([]byte(remotePubKey))

	plaintext := []byte("this will fail to decrypt")
	var ciphertext bytes.Buffer
	w, _ := age.Encrypt(&ciphertext, relayRecipient)
	w.Write(plaintext)
	w.Close()

	tag := ComputeTag(remotePubKey)
	relayIdentity := &RelayIdentity{
		Tag: tag,
		Remote: RemoteConfig{
			URL:             "http://127.0.0.1:1/unwrap",
			UnwrapRecipient: remotePubKey,
		},
	}

	_, err := age.Decrypt(bytes.NewReader(ciphertext.Bytes()), relayIdentity)
	if err == nil {
		t.Fatal("expected error when relay is down")
	}
	if !strings.Contains(err.Error(), "relay") {
		t.Fatalf("error should mention relay, got: %v", err)
	}
	t.Logf("Got expected error: %v", err)
}

func TestIntegrationWrongIdentity(t *testing.T) {
	identityA, _ := age.GenerateX25519Identity()
	recipientA := identityA.Recipient().String()
	relayRecipient, _ := NewRelayRecipient([]byte(recipientA))

	plaintext := []byte("encrypted to A, relay has B")
	var ciphertext bytes.Buffer
	w, _ := age.Encrypt(&ciphertext, relayRecipient)
	w.Write(plaintext)
	w.Close()

	identityB, _ := age.GenerateX25519Identity()
	server := newMockRelayServer(t, identityB)
	defer server.Close()

	tag := ComputeTag(recipientA)
	relayIdentity := &RelayIdentity{
		Tag: tag,
		Remote: RemoteConfig{
			URL:             server.URL,
			UnwrapRecipient: recipientA,
		},
	}

	_, err := age.Decrypt(bytes.NewReader(ciphertext.Bytes()), relayIdentity)
	if err == nil {
		t.Fatal("expected error when relay has wrong identity")
	}
	t.Logf("Got expected error: %v", err)
}

func TestIntegrationEncryptedPayloadE2E(t *testing.T) {
	remoteIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	remotePubKey := remoteIdentity.Recipient().String()

	server := newMockRelayServer(t, remoteIdentity)
	defer server.Close()

	relayRecipient, err := NewRelayRecipient([]byte(remotePubKey))
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("Integration test: encrypted payload end-to-end")

	var ciphertext bytes.Buffer
	w, err := age.Encrypt(&ciphertext, relayRecipient)
	if err != nil {
		t.Fatalf("age.Encrypt: %v", err)
	}
	w.Write(plaintext)
	w.Close()

	t.Logf("Encrypted %d bytes → %d bytes ciphertext", len(plaintext), ciphertext.Len())

	tag := ComputeTag(remotePubKey)
	relayIdentity := &RelayIdentity{
		Tag: tag,
		Remote: RemoteConfig{
			URL:             server.URL,
			UnwrapRecipient: remotePubKey,
		},
	}

	r, err := age.Decrypt(bytes.NewReader(ciphertext.Bytes()), relayIdentity)
	if err != nil {
		t.Fatalf("age.Decrypt: %v", err)
	}
	decrypted, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading decrypted: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("plaintext mismatch:\n  got:  %q\n  want: %q", decrypted, plaintext)
	}
	t.Logf("Integration encrypted payload OK: %q", decrypted)
}

func TestIntegrationMissingUnwrapRecipient(t *testing.T) {
	remoteIdentity, _ := age.GenerateX25519Identity()
	remotePubKey := remoteIdentity.Recipient().String()
	relayRecipient, _ := NewRelayRecipient([]byte(remotePubKey))

	plaintext := []byte("should fail without unwrap_recipient")
	var ciphertext bytes.Buffer
	w, _ := age.Encrypt(&ciphertext, relayRecipient)
	w.Write(plaintext)
	w.Close()

	tag := ComputeTag(remotePubKey)
	relayIdentity := &RelayIdentity{
		Tag: tag,
		Remote: RemoteConfig{
			URL:             "http://127.0.0.1:1/unused",
			UnwrapRecipient: "", // missing!
		},
	}

	_, err := age.Decrypt(bytes.NewReader(ciphertext.Bytes()), relayIdentity)
	if err == nil {
		t.Fatal("expected error for missing unwrap_recipient")
	}
	if !strings.Contains(err.Error(), "unwrap_recipient") {
		t.Fatalf("error should mention unwrap_recipient, got: %v", err)
	}
	t.Logf("Got expected error: %v", err)
}

// ── Encrypted payload sync E2E through age.Encrypt / age.Decrypt ────────────

func TestEncryptedPayloadSyncE2E(t *testing.T) {
	identity, _ := age.GenerateX25519Identity()
	recipientStr := identity.Recipient().String()

	server := newMockRelayServer(t, identity)
	defer server.Close()

	relayRecipient, _ := NewRelayRecipient([]byte(recipientStr))
	plaintext := []byte("sync E2E: encrypted payload only mode")

	var ciphertext bytes.Buffer
	w, _ := age.Encrypt(&ciphertext, relayRecipient)
	w.Write(plaintext)
	w.Close()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "relay-config.yaml")
	configContent := fmt.Sprintf("remotes:\n  test:\n    url: %s\n    unwrap_recipient: %s\n    timeout: 10s\n", server.URL, recipientStr)
	os.WriteFile(configPath, []byte(configContent), 0644)
	t.Setenv("AGE_PLUGIN_RELAY_CONFIG", configPath)

	tag := ComputeTag(recipientStr)
	relayIdentity := &RelayIdentity{
		Tag:    tag,
		Remote: RemoteConfig{URL: server.URL, UnwrapRecipient: recipientStr},
	}

	r, err := age.Decrypt(bytes.NewReader(ciphertext.Bytes()), relayIdentity)
	if err != nil {
		t.Fatalf("age.Decrypt: %v", err)
	}
	decrypted, _ := io.ReadAll(r)
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("mismatch: %q vs %q", decrypted, plaintext)
	}
}

func TestEncryptedPayloadSyncE2EWithSSE(t *testing.T) {
	identity, _ := age.GenerateX25519Identity()
	recipientStr := identity.Recipient().String()

	server := newMockRelayServer(t, identity)
	defer server.Close()

	relayRecipient, _ := NewRelayRecipient([]byte(recipientStr))
	plaintext := []byte("SSE sync E2E: encrypted payload with streaming")

	var ciphertext bytes.Buffer
	w, _ := age.Encrypt(&ciphertext, relayRecipient)
	w.Write(plaintext)
	w.Close()

	tag := ComputeTag(recipientStr)
	relayIdentity := &RelayIdentity{
		Tag:    tag,
		Remote: RemoteConfig{URL: server.URL, Stream: true, UnwrapRecipient: recipientStr},
	}

	r, err := age.Decrypt(bytes.NewReader(ciphertext.Bytes()), relayIdentity)
	if err != nil {
		t.Fatalf("age.Decrypt SSE: %v", err)
	}
	decrypted, _ := io.ReadAll(r)
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("mismatch: %q vs %q", decrypted, plaintext)
	}
}

// ── Broker blindness — opaque encrypted_payload verification ────────────────

func TestBrokerBlindnessVerification(t *testing.T) {
	identity, _ := age.GenerateX25519Identity()
	recipientStr := identity.Recipient().String()

	var capturedPayload string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req RelayRequest
		json.NewDecoder(r.Body).Decode(&req)
		capturedPayload = req.EncryptedPayload

		inner, err := DecryptPayload(req.EncryptedPayload, []age.Identity{identity})
		if err != nil {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(RelayResponse{Error: err.Error()})
			return
		}
		if err := VerifyRequestPayload(inner, req.Version, req.Action, req.Stream, req.IntentID, req.Tag, req.ExpiresAt, req.IntentClaimPub); err != nil {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(RelayResponse{Error: err.Error()})
			return
		}
		stanzas := make([]*age.Stanza, len(inner.Stanzas))
		for i, s := range inner.Stanzas {
			body, _ := base64.RawStdEncoding.DecodeString(s.Body)
			stanzas[i] = &age.Stanza{Type: s.Type, Args: s.Args, Body: body}
		}
		fileKey, _ := identity.Unwrap(stanzas)
		respInner, _ := BuildResponsePayload(1, "fulfill", req.IntentID, fileKey)
		sealed, _ := SealResponse(*respInner, inner.EphemeralKey)
		json.NewEncoder(w).Encode(RelayRequest{Version: 1, Action: "fulfill", IntentID: req.IntentID, EncryptedPayload: sealed})
	}))
	defer server.Close()

	relayRecipient, _ := NewRelayRecipient([]byte(recipientStr))
	fileKey := make([]byte, 16)
	rand.Read(fileKey)
	stanzas, _ := relayRecipient.Wrap(fileKey)

	tag := ComputeTag(recipientStr)
	relayIdentity := &RelayIdentity{
		Tag:    tag,
		Remote: RemoteConfig{URL: server.URL, UnwrapRecipient: recipientStr},
	}
	recovered, err := relayIdentity.Unwrap(stanzas)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(recovered, fileKey) {
		t.Fatal("file key mismatch")
	}

	// Broker cannot parse encrypted payload as JSON
	raw, _ := base64.RawStdEncoding.DecodeString(capturedPayload)
	var testJSON map[string]interface{}
	if json.Unmarshal(raw, &testJSON) == nil {
		t.Fatal("broker should not be able to parse encrypted payload as JSON")
	}
	// Broker with wrong identity cannot decrypt
	wrongIdentity, _ := age.GenerateX25519Identity()
	_, decryptErr := DecryptPayload(capturedPayload, []age.Identity{wrongIdentity})
	if decryptErr == nil {
		t.Fatal("broker (wrong identity) should not be able to decrypt the payload")
	}
}

// ── Response outer_hash tampering detection E2E ─────────────────────────────

func TestResponseOuterHashTamperingE2E(t *testing.T) {
	identity, _ := age.GenerateX25519Identity()
	recipientStr := identity.Recipient().String()

	// Server seals response with WRONG intent_id in outer_hash
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req RelayRequest
		json.NewDecoder(r.Body).Decode(&req)

		inner, _ := DecryptPayload(req.EncryptedPayload, []age.Identity{identity})
		stanzas := make([]*age.Stanza, len(inner.Stanzas))
		for i, s := range inner.Stanzas {
			body, _ := base64.RawStdEncoding.DecodeString(s.Body)
			stanzas[i] = &age.Stanza{Type: s.Type, Args: s.Args, Body: body}
		}
		fileKey, _ := identity.Unwrap(stanzas)

		// Build response with WRONG intent_id
		respInner, _ := BuildResponsePayload(1, "fulfill", "wrong-intent-id", fileKey)
		sealed, _ := SealResponse(*respInner, inner.EphemeralKey)
		json.NewEncoder(w).Encode(RelayRequest{Version: 1, Action: "fulfill", IntentID: req.IntentID, EncryptedPayload: sealed})
	}))
	defer server.Close()

	relayRecipient, _ := NewRelayRecipient([]byte(recipientStr))
	fileKey := make([]byte, 16)
	rand.Read(fileKey)
	stanzas, _ := relayRecipient.Wrap(fileKey)

	tag := ComputeTag(recipientStr)
	relayIdentity := &RelayIdentity{
		Tag:    tag,
		Remote: RemoteConfig{URL: server.URL, UnwrapRecipient: recipientStr},
	}

	_, err := relayIdentity.Unwrap(stanzas)
	if err == nil {
		t.Fatal("expected error for response outer_hash tampering")
	}
	if !strings.Contains(err.Error(), "outer_hash") {
		t.Fatalf("error should mention outer_hash, got: %v", err)
	}
}
