package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

// newMockRelayServer starts an httptest server that unwraps stanzas using the
// given age identity. Returns the server (caller must Close) and its URL.
func newMockRelayServer(t *testing.T, identity *age.X25519Identity) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req RelayRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
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

// TestIntegrationLegacyURL tests full encrypt→decrypt with URL embedded in the
// identity string (legacy / backwards-compatible mode).
func TestIntegrationLegacyURL(t *testing.T) {
	// 1. Generate a "remote" X25519 key pair.
	remoteIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	remotePubKey := remoteIdentity.Recipient().String()

	// 2. Start mock relay server with the remote identity.
	server := newMockRelayServer(t, remoteIdentity)
	defer server.Close()

	// 3. Create relay recipient (embeds remote public key).
	relayRecipient, err := NewRelayRecipient([]byte(remotePubKey))
	if err != nil {
		t.Fatal(err)
	}

	// 4. Encrypt a message using age.Encrypt with the relay recipient.
	plaintext := []byte("Legacy URL mode: the quick brown fox jumps over the lazy dog")

	var ciphertext bytes.Buffer
	w, err := age.Encrypt(&ciphertext, relayRecipient)
	if err != nil {
		t.Fatalf("age.Encrypt: %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("writing plaintext: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("closing writer: %v", err)
	}

	t.Logf("Encrypted %d bytes plaintext → %d bytes ciphertext", len(plaintext), ciphertext.Len())

	// 5. Create relay identity with URL (legacy mode).
	tag := ComputeTag(remotePubKey)
	relayIdentity := &RelayIdentity{
		tag:    tag,
		remote: RemoteConfig{URL: server.URL},
	}

	// 6. Decrypt.
	r, err := age.Decrypt(bytes.NewReader(ciphertext.Bytes()), relayIdentity)
	if err != nil {
		t.Fatalf("age.Decrypt: %v", err)
	}
	decrypted, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading decrypted: %v", err)
	}

	// 7. Verify.
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("plaintext mismatch:\n  got:  %q\n  want: %q", decrypted, plaintext)
	}
	t.Logf("Decrypted OK: %q", decrypted)
}

// TestIntegrationConfigMode tests full encrypt→decrypt with a remote name
// resolved from relay-config.yaml.
func TestIntegrationConfigMode(t *testing.T) {
	// 1. Generate a "remote" X25519 key pair.
	remoteIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	remotePubKey := remoteIdentity.Recipient().String()

	// 2. Start mock relay server.
	server := newMockRelayServer(t, remoteIdentity)
	defer server.Close()

	// 3. Write a config file to a temp dir and point env var at it.
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "relay-config.yaml")
	configContent := "remotes:\n  testremote:\n    url: " + server.URL + "\n    timeout: 10s\n"
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGE_PLUGIN_RELAY_CONFIG", configPath)

	t.Logf("Config file: %s", configPath)
	t.Logf("Config content:\n%s", configContent)

	// 4. Create relay recipient (same as legacy — recipient doesn't change).
	relayRecipient, err := NewRelayRecipient([]byte(remotePubKey))
	if err != nil {
		t.Fatal(err)
	}

	// 5. Encrypt.
	plaintext := []byte("Config mode: secrets encrypted with named remote 'testremote'")

	var ciphertext bytes.Buffer
	w, err := age.Encrypt(&ciphertext, relayRecipient)
	if err != nil {
		t.Fatalf("age.Encrypt: %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("writing plaintext: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("closing writer: %v", err)
	}

	t.Logf("Encrypted %d bytes plaintext → %d bytes ciphertext", len(plaintext), ciphertext.Len())

	// 6. Create relay identity with remote name (config mode).
	//    This constructs the identity directly; in production, NewRelayIdentity
	//    would decode the Bech32 payload and call resolveRemote("testremote").
	tag := ComputeTag(remotePubKey)

	// Verify the config-based resolution works.
	remote, err := resolveRemote("testremote")
	if err != nil {
		t.Fatalf("resolveRemote: %v", err)
	}
	if remote.URL != server.URL {
		t.Fatalf("resolved URL mismatch: %q vs %q", remote.URL, server.URL)
	}
	if remote.Timeout != "10s" {
		t.Fatalf("resolved timeout mismatch: %q vs %q", remote.Timeout, "10s")
	}
	t.Logf("Resolved remote 'testremote' → URL=%s, timeout=%s", remote.URL, remote.Timeout)

	relayIdentity := &RelayIdentity{
		tag:    tag,
		remote: remote,
	}

	// 7. Decrypt.
	r, err := age.Decrypt(bytes.NewReader(ciphertext.Bytes()), relayIdentity)
	if err != nil {
		t.Fatalf("age.Decrypt: %v", err)
	}
	decrypted, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading decrypted: %v", err)
	}

	// 8. Verify.
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("plaintext mismatch:\n  got:  %q\n  want: %q", decrypted, plaintext)
	}
	t.Logf("Decrypted OK: %q", decrypted)
}

// TestIntegrationConfigMissingRemote verifies that resolving a non-existent
// remote name produces a clear error.
func TestIntegrationConfigMissingRemote(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "relay-config.yaml")
	configContent := "remotes:\n  alpha:\n    url: http://localhost:1/unused\n"
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGE_PLUGIN_RELAY_CONFIG", configPath)

	_, err := resolveRemote("nonexistent")
	if err == nil {
		t.Fatal("expected error for missing remote")
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Fatalf("error should mention remote name, got: %v", err)
	}
	if !strings.Contains(err.Error(), "alpha") {
		t.Fatalf("error should list available remotes, got: %v", err)
	}
	t.Logf("Got expected error: %v", err)
}

// TestIntegrationNoConfigFile verifies that URL-based identities work even
// when no config file exists.
func TestIntegrationNoConfigFile(t *testing.T) {
	// Point to a non-existent config — should be fine for URL-based identity.
	t.Setenv("AGE_PLUGIN_RELAY_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))

	remote, err := resolveRemote("https://example.com/unwrap")
	if err != nil {
		t.Fatalf("URL-based resolve should work without config: %v", err)
	}
	if remote.URL != "https://example.com/unwrap" {
		t.Fatalf("URL mismatch: %q", remote.URL)
	}
}

// TestIntegrationRelayServerDown verifies that a clear error is returned when
// the relay endpoint is unreachable.
func TestIntegrationRelayServerDown(t *testing.T) {
	remoteIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	remotePubKey := remoteIdentity.Recipient().String()

	relayRecipient, err := NewRelayRecipient([]byte(remotePubKey))
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt a message.
	plaintext := []byte("this will fail to decrypt")
	var ciphertext bytes.Buffer
	w, err := age.Encrypt(&ciphertext, relayRecipient)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(plaintext)
	w.Close()

	// Point identity at a port that's not listening.
	tag := ComputeTag(remotePubKey)
	relayIdentity := &RelayIdentity{
		tag:    tag,
		remote: RemoteConfig{URL: "http://127.0.0.1:1/unwrap"},
	}

	// Decrypt should fail with a relay connection error.
	_, err = age.Decrypt(bytes.NewReader(ciphertext.Bytes()), relayIdentity)
	if err == nil {
		t.Fatal("expected error when relay is down")
	}
	if !strings.Contains(err.Error(), "relay") {
		t.Fatalf("error should mention relay, got: %v", err)
	}
	t.Logf("Got expected error: %v", err)
}

// TestIntegrationWrongIdentity verifies that decryption fails cleanly when the
// relay server has a different key than what was used for encryption.
func TestIntegrationWrongIdentity(t *testing.T) {
	// Encrypt to identity A.
	identityA, _ := age.GenerateX25519Identity()
	recipientA := identityA.Recipient().String()

	relayRecipient, _ := NewRelayRecipient([]byte(recipientA))

	plaintext := []byte("encrypted to A, relay has B")
	var ciphertext bytes.Buffer
	w, _ := age.Encrypt(&ciphertext, relayRecipient)
	w.Write(plaintext)
	w.Close()

	// Relay server holds identity B (wrong key).
	identityB, _ := age.GenerateX25519Identity()
	server := newMockRelayServer(t, identityB)
	defer server.Close()

	tag := ComputeTag(recipientA)
	relayIdentity := &RelayIdentity{
		tag:    tag,
		remote: RemoteConfig{URL: server.URL},
	}

	_, err := age.Decrypt(bytes.NewReader(ciphertext.Bytes()), relayIdentity)
	if err == nil {
		t.Fatal("expected error when relay has wrong identity")
	}
	t.Logf("Got expected error: %v", err)
}
