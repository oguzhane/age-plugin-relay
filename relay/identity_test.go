package relay

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"
)

// ── Unwrap ──────────────────────────────────────────────────────────────────

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
		Tag: tag,
		Remote: RemoteConfig{
			URL:             server.URL,
			UnwrapRecipient: recipientStr,
		},
	}

	recovered, err := relayIdentity.Unwrap(stanzas)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}

	if !bytes.Equal(recovered, fileKey) {
		t.Fatalf("file key mismatch:\n  got:  %x\n  want: %x", recovered, fileKey)
	}
}

func TestEndToEndWithSSERelay(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recipientStr := identity.Recipient().String()

	server := newMockRelayServer(t, identity)
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
			URL:             server.URL,
			Stream:          true,
			UnwrapRecipient: recipientStr,
		},
	}

	recovered, err := relayIdentity.Unwrap(stanzas)
	if err != nil {
		t.Fatalf("SSE Unwrap: %v", err)
	}

	if !bytes.Equal(recovered, fileKey) {
		t.Fatalf("file key mismatch:\n  got:  %x\n  want: %x", recovered, fileKey)
	}
}

func TestSSERelayError(t *testing.T) {
	identityA, _ := age.GenerateX25519Identity()
	identityB, _ := age.GenerateX25519Identity()
	recipientA := identityA.Recipient().String()

	// Server has identityB but we encrypt to identityA → unwrap fails.
	server := newMockRelayServer(t, identityB)
	defer server.Close()

	relayRecipient, _ := NewRelayRecipient([]byte(recipientA))
	fileKey := make([]byte, 16)
	rand.Read(fileKey)
	stanzas, _ := relayRecipient.Wrap(fileKey)

	tag := ComputeTag(recipientA)
	relayIdentity := &RelayIdentity{
		Tag: tag,
		Remote: RemoteConfig{
			URL:             server.URL,
			Stream:          true,
			UnwrapRecipient: recipientA,
		},
	}

	_, err := relayIdentity.Unwrap(stanzas)
	if err == nil {
		t.Fatal("expected error from SSE relay with wrong identity")
	}
	t.Logf("Got expected SSE error: %v", err)
}

func TestUnwrapNoMatchingStanza(t *testing.T) {
	var tag [TagSize]byte
	for i := range tag {
		tag[i] = 0xFF
	}
	id := &RelayIdentity{
		Tag:    tag,
		Remote: RemoteConfig{URL: "http://localhost:1/unused", UnwrapRecipient: "age1unused"},
	}

	stanzas := []*age.Stanza{
		{Type: "X25519", Args: []string{"foo"}, Body: []byte("bar")},
	}

	_, err := id.Unwrap(stanzas)
	if err == nil {
		t.Fatal("expected error for non-matching stanzas")
	}
}

func TestUnwrapMissingUnwrapRecipient(t *testing.T) {
	identity, _ := age.GenerateX25519Identity()
	recipientStr := identity.Recipient().String()

	relayRecipient, _ := NewRelayRecipient([]byte(recipientStr))
	fileKey := make([]byte, 16)
	rand.Read(fileKey)
	stanzas, _ := relayRecipient.Wrap(fileKey)

	tag := ComputeTag(recipientStr)
	relayIdentity := &RelayIdentity{
		Tag: tag,
		Remote: RemoteConfig{
			URL:             "http://localhost:1/unused",
			UnwrapRecipient: "", // missing!
		},
	}

	_, err := relayIdentity.Unwrap(stanzas)
	if err == nil {
		t.Fatal("expected error for missing unwrap_recipient")
	}
	if !strings.Contains(err.Error(), "unwrap_recipient") {
		t.Fatalf("expected error about unwrap_recipient, got: %v", err)
	}
}

// ── ResolveRemote ───────────────────────────────────────────────────────────

func TestResolveRemoteNamedNotFound(t *testing.T) {
	t.Setenv("AGE_PLUGIN_RELAY_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	_, err := ResolveRemote("myremote")
	if err == nil {
		t.Fatal("expected error for named remote without config")
	}
}

// ── Concurrency ─────────────────────────────────────────────────────────────

func TestConcurrentUnwrapRequests(t *testing.T) {
	identity, _ := age.GenerateX25519Identity()
	recipientStr := identity.Recipient().String()
	server := newMockRelayServer(t, identity)
	defer server.Close()

	const n = 10
	var wg sync.WaitGroup
	errors := make(chan error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
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
				errors <- err
				return
			}
			if !bytes.Equal(recovered, fileKey) {
				errors <- fmt.Errorf("file key mismatch")
			}
		}()
	}
	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}
