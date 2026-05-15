package relay

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestE2EAuthTokenSync tests the sync flow with bearer token authentication.
func TestE2EAuthTokenSync(t *testing.T) {
	bins := buildAllBinaries(t)
	tmpDir := t.TempDir()

	remoteKeyFile := filepath.Join(tmpDir, "remote.key")
	run(t, bins.AgeKeygen, "-o", remoteKeyFile)
	remotePubKey := extractPublicKey(t, remoteKeyFile)

	authToken := "sync-secret-token-42"

	port := freePort(t)
	relayURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	startServer(t, bins.RelayServer, remoteKeyFile, port, "-auth-token", authToken)

	// Correct token → should succeed.
	configFile := writeRelayConfig(t, tmpDir, "auth-sync", relayURL, remotePubKey, map[string]string{
		"timeout":    "10s",
		"auth_token": authToken,
	})
	relayRecipient, relayIdentityStr := generateRelayKeys(t, bins.Plugin, remotePubKey, "auth-sync", configFile)

	plaintext := "E2E sync with auth — " + time.Now().Format(time.RFC3339Nano)
	ciphertextFile := encryptMessage(t, bins.Age, bins.Plugin, relayRecipient, plaintext, tmpDir)
	decrypted := decryptMessage(t, bins.Age, bins.Plugin, relayIdentityStr, ciphertextFile, configFile)
	if decrypted != plaintext {
		t.Fatalf("plaintext mismatch:\n  want: %q\n  got:  %q", plaintext, decrypted)
	}

	// Wrong token → should fail.
	wrongDir := filepath.Join(tmpDir, "wrong")
	os.MkdirAll(wrongDir, 0755)
	wrongConfig := writeRelayConfig(t, wrongDir, "auth-sync", relayURL, remotePubKey, map[string]string{
		"timeout":    "5s",
		"auth_token": "wrong-token",
	})
	output := decryptMessageExpectFailure(t, bins.Age, bins.Plugin, relayIdentityStr, ciphertextFile, wrongConfig)
	t.Logf("Expected auth failure: %s", strings.TrimSpace(output))
}

// TestE2ESyncServerDown tests that decryption fails when relay-server is not running.
func TestE2ESyncServerDown(t *testing.T) {
	bins := buildAllBinaries(t)
	tmpDir := t.TempDir()

	remoteKeyFile := filepath.Join(tmpDir, "remote.key")
	run(t, bins.AgeKeygen, "-o", remoteKeyFile)
	remotePubKey := extractPublicKey(t, remoteKeyFile)

	// Point at a port with nothing listening.
	deadPort := freePort(t)
	deadURL := fmt.Sprintf("http://127.0.0.1:%d", deadPort)

	configFile := writeRelayConfig(t, tmpDir, "dead-server", deadURL, remotePubKey, map[string]string{
		"timeout": "3s",
	})
	relayRecipient, relayIdentityStr := generateRelayKeys(t, bins.Plugin, remotePubKey, "dead-server", configFile)

	plaintext := "server is down"
	ciphertextFile := encryptMessage(t, bins.Age, bins.Plugin, relayRecipient, plaintext, tmpDir)

	output := decryptMessageExpectFailure(t, bins.Age, bins.Plugin, relayIdentityStr, ciphertextFile, configFile)
	t.Logf("Expected connection failure: %s", strings.TrimSpace(output))
	if !strings.Contains(output, "connection refused") && !strings.Contains(output, "connect:") && !strings.Contains(output, "dial") {
		t.Logf("Warning: unexpected error message (may still be correct): %s", output)
	}
}

// TestE2ESyncWrongKey tests that relay-server rejects when it holds a different key.
func TestE2ESyncWrongKey(t *testing.T) {
	bins := buildAllBinaries(t)
	tmpDir := t.TempDir()

	// Key A: used for relay recipient.
	keyFileA := filepath.Join(tmpDir, "keyA.key")
	run(t, bins.AgeKeygen, "-o", keyFileA)
	pubKeyA := extractPublicKey(t, keyFileA)

	// Key B: held by relay-server (wrong key).
	keyFileB := filepath.Join(tmpDir, "keyB.key")
	run(t, bins.AgeKeygen, "-o", keyFileB)

	port := freePort(t)
	relayURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	startServer(t, bins.RelayServer, keyFileB, port)

	configFile := writeRelayConfig(t, tmpDir, "wrong-key-sync", relayURL, pubKeyA, map[string]string{
		"timeout": "10s",
	})
	relayRecipient, relayIdentityStr := generateRelayKeys(t, bins.Plugin, pubKeyA, "wrong-key-sync", configFile)

	plaintext := "wrong key test"
	ciphertextFile := encryptMessage(t, bins.Age, bins.Plugin, relayRecipient, plaintext, tmpDir)

	output := decryptMessageExpectFailure(t, bins.Age, bins.Plugin, relayIdentityStr, ciphertextFile, configFile)
	t.Logf("Expected wrong-key failure: %s", strings.TrimSpace(output))
}

// TestE2EAsyncBrokerDown tests that decryption fails when broker is unreachable.
func TestE2EAsyncBrokerDown(t *testing.T) {
	bins := buildAllBinaries(t)
	tmpDir := t.TempDir()

	remoteKeyFile := filepath.Join(tmpDir, "remote.key")
	run(t, bins.AgeKeygen, "-o", remoteKeyFile)
	remotePubKey := extractPublicKey(t, remoteKeyFile)

	deadPort := freePort(t)
	deadURL := fmt.Sprintf("http://127.0.0.1:%d", deadPort)

	configFile := writeRelayConfig(t, tmpDir, "dead-broker", deadURL, remotePubKey, map[string]string{
		"timeout": "3s",
	})
	relayRecipient, relayIdentityStr := generateRelayKeys(t, bins.Plugin, remotePubKey, "dead-broker", configFile)

	plaintext := "broker is down"
	ciphertextFile := encryptMessage(t, bins.Age, bins.Plugin, relayRecipient, plaintext, tmpDir)

	output := decryptMessageExpectFailure(t, bins.Age, bins.Plugin, relayIdentityStr, ciphertextFile, configFile)
	t.Logf("Expected broker connection failure: %s", strings.TrimSpace(output))
}
