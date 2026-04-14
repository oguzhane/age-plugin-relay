package relay

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestIntegrationLegacyURL(t *testing.T) {
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

	t.Logf("Encrypted %d bytes → %d bytes ciphertext", len(plaintext), ciphertext.Len())

	tag := ComputeTag(remotePubKey)
	relayIdentity := &RelayIdentity{
		Tag:    tag,
		Remote: RemoteConfig{URL: server.URL},
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
	t.Logf("Decrypted OK: %q", decrypted)
}

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
	configContent := "remotes:\n  testremote:\n    url: " + server.URL + "\n    timeout: 10s\n"
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
	os.WriteFile(configPath, []byte("remotes:\n  alpha:\n    url: http://localhost:1/unused\n"), 0644)
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

func TestIntegrationNoConfigFile(t *testing.T) {
	t.Setenv("AGE_PLUGIN_RELAY_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))

	remote, err := ResolveRemote("https://example.com/unwrap")
	if err != nil {
		t.Fatalf("URL-based resolve should work without config: %v", err)
	}
	if remote.URL != "https://example.com/unwrap" {
		t.Fatalf("URL mismatch: %q", remote.URL)
	}
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
		Tag:    tag,
		Remote: RemoteConfig{URL: "http://127.0.0.1:1/unwrap"},
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
		Tag:    tag,
		Remote: RemoteConfig{URL: server.URL},
	}

	_, err := age.Decrypt(bytes.NewReader(ciphertext.Bytes()), relayIdentity)
	if err == nil {
		t.Fatal("expected error when relay has wrong identity")
	}
	t.Logf("Got expected error: %v", err)
}

func TestIntegrationEnvelopeEncryption(t *testing.T) {
	remoteIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	remotePubKey := remoteIdentity.Recipient().String()
	hmacSecret := "integration-envelope-secret"

	server := newMockEnvelopeRelayServer(t, remoteIdentity, hmacSecret)
	defer server.Close()

	relayRecipient, err := NewRelayRecipient([]byte(remotePubKey))
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("Integration test: encrypted response via ephemeral X25519")

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
			URL:               server.URL,
			HMACKey:           hmacSecret,
			EncryptedResponse: true,
		},
	}

	r, err := age.Decrypt(bytes.NewReader(ciphertext.Bytes()), relayIdentity)
	if err != nil {
		t.Fatalf("age.Decrypt with envelope: %v", err)
	}
	decrypted, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading decrypted: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("plaintext mismatch:\n  got:  %q\n  want: %q", decrypted, plaintext)
	}
	t.Logf("Integration envelope OK: %q", decrypted)
}

func TestIntegrationEnvelopeWithConfigMode(t *testing.T) {
	remoteIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	remotePubKey := remoteIdentity.Recipient().String()
	hmacSecret := "config-envelope-secret"

	server := newMockEnvelopeRelayServer(t, remoteIdentity, hmacSecret)
	defer server.Close()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "relay-config.yaml")
	configContent := "remotes:\n  secure:\n    url: " + server.URL +
		"\n    hmac_key: " + hmacSecret +
		"\n    encrypted_response: true\n    timeout: 10s\n"
	os.WriteFile(configPath, []byte(configContent), 0644)
	t.Setenv("AGE_PLUGIN_RELAY_CONFIG", configPath)

	relayRecipient, _ := NewRelayRecipient([]byte(remotePubKey))

	plaintext := []byte("Config mode with envelope encryption enabled")

	var ciphertext bytes.Buffer
	w, _ := age.Encrypt(&ciphertext, relayRecipient)
	w.Write(plaintext)
	w.Close()

	tag := ComputeTag(remotePubKey)
	remote, err := ResolveRemote("secure")
	if err != nil {
		t.Fatalf("ResolveRemote: %v", err)
	}
	if !remote.EncryptedResponse {
		t.Fatal("expected encrypted_response=true from config")
	}
	t.Logf("Resolved remote 'secure' → URL=%s, hmac_key=%s, encrypted_response=%v",
		remote.URL, remote.HMACKey, remote.EncryptedResponse)

	relayIdentity := &RelayIdentity{Tag: tag, Remote: remote}

	r, err := age.Decrypt(bytes.NewReader(ciphertext.Bytes()), relayIdentity)
	if err != nil {
		t.Fatalf("age.Decrypt with config envelope: %v", err)
	}
	decrypted, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("plaintext mismatch:\n  got:  %q\n  want: %q", decrypted, plaintext)
	}
	t.Logf("Config mode envelope OK: %q", decrypted)
}
