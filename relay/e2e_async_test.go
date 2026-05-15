package relay

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestE2EAsyncHappyPath exercises the full async flow:
// plugin → relay-broker → relay-operator → fulfill → plugin decrypts.
func TestE2EAsyncHappyPath(t *testing.T) {
	bins := buildAllBinaries(t)
	tmpDir := t.TempDir()

	// 1. Generate remote X25519 key pair.
	remoteKeyFile := filepath.Join(tmpDir, "remote.key")
	run(t, bins.AgeKeygen, "-o", remoteKeyFile)
	remotePubKey := extractPublicKey(t, remoteKeyFile)
	t.Logf("Remote public key: %s", remotePubKey)

	// 2. Start relay-broker.
	brokerPort := freePort(t)
	brokerURL := fmt.Sprintf("http://127.0.0.1:%d", brokerPort)
	startBroker(t, bins.RelayBroker, brokerPort, "", "2m")
	t.Logf("Broker listening on :%d", brokerPort)

	// 3. Compute tag and start relay-operator.
	tag := computeTagB64(remotePubKey)
	t.Logf("Tag: %s", tag)
	startOperator(t, bins.RelayOperator, brokerURL, remoteKeyFile, tag, "", "500ms")
	t.Logf("Operator started, polling broker for tag=%s", tag)

	// 4. Write relay-config.yaml pointing at broker.
	configFile := writeRelayConfig(t, tmpDir, "async-test", brokerURL, remotePubKey, map[string]string{
		"timeout":       "30s",
		"poll_interval": "500ms",
	})

	// 5. Generate relay recipient + identity.
	relayRecipient, relayIdentityStr := generateRelayKeys(t, bins.Plugin, remotePubKey, "async-test", configFile)

	// 6. Encrypt.
	plaintext := "E2E async happy path — " + time.Now().Format(time.RFC3339Nano)
	ciphertextFile := encryptMessage(t, bins.Age, bins.Plugin, relayRecipient, plaintext, tmpDir)

	// 7. Decrypt via async flow (plugin → broker → operator → fulfill → plugin).
	decrypted := decryptMessage(t, bins.Age, bins.Plugin, relayIdentityStr, ciphertextFile, configFile)
	t.Logf("Decrypted: %q", decrypted)

	// 8. Verify.
	if decrypted != plaintext {
		t.Fatalf("plaintext mismatch:\n  want: %q\n  got:  %q", plaintext, decrypted)
	}
}

// TestE2EAsyncOperatorRejectsWrongKey tests that operator rejects when it holds
// a different key than what was used for encryption.
func TestE2EAsyncOperatorRejectsWrongKey(t *testing.T) {
	bins := buildAllBinaries(t)
	tmpDir := t.TempDir()

	// Key A: used for encryption relay recipient.
	keyFileA := filepath.Join(tmpDir, "keyA.key")
	run(t, bins.AgeKeygen, "-o", keyFileA)
	pubKeyA := extractPublicKey(t, keyFileA)

	// Key B: held by operator (wrong key).
	keyFileB := filepath.Join(tmpDir, "keyB.key")
	run(t, bins.AgeKeygen, "-o", keyFileB)

	// Start broker + operator with key B.
	brokerPort := freePort(t)
	brokerURL := fmt.Sprintf("http://127.0.0.1:%d", brokerPort)
	startBroker(t, bins.RelayBroker, brokerPort, "", "2m")

	tag := computeTagB64(pubKeyA)
	startOperator(t, bins.RelayOperator, brokerURL, keyFileB, tag, "", "500ms")

	// Config pointing at broker, unwrap_recipient = pubKeyA.
	configFile := writeRelayConfig(t, tmpDir, "wrong-key", brokerURL, pubKeyA, map[string]string{
		"timeout":       "15s",
		"poll_interval": "500ms",
	})

	relayRecipient, relayIdentityStr := generateRelayKeys(t, bins.Plugin, pubKeyA, "wrong-key", configFile)

	plaintext := "this should fail"
	ciphertextFile := encryptMessage(t, bins.Age, bins.Plugin, relayRecipient, plaintext, tmpDir)

	// Decrypt should fail — operator holds wrong key and will reject.
	output := decryptMessageExpectFailure(t, bins.Age, bins.Plugin, relayIdentityStr, ciphertextFile, configFile)
	t.Logf("Expected failure output: %s", output)
}

// TestE2EAsyncIntentExpiry tests that intents expire when no operator fulfills them.
func TestE2EAsyncIntentExpiry(t *testing.T) {
	bins := buildAllBinaries(t)
	tmpDir := t.TempDir()

	remoteKeyFile := filepath.Join(tmpDir, "remote.key")
	run(t, bins.AgeKeygen, "-o", remoteKeyFile)
	remotePubKey := extractPublicKey(t, remoteKeyFile)

	// Start broker with very short TTL, NO operator.
	brokerPort := freePort(t)
	brokerURL := fmt.Sprintf("http://127.0.0.1:%d", brokerPort)
	startBroker(t, bins.RelayBroker, brokerPort, "", "2s")

	configFile := writeRelayConfig(t, tmpDir, "expiry-test", brokerURL, remotePubKey, map[string]string{
		"timeout":       "10s",
		"poll_interval": "500ms",
	})

	relayRecipient, relayIdentityStr := generateRelayKeys(t, bins.Plugin, remotePubKey, "expiry-test", configFile)

	plaintext := "this will expire"
	ciphertextFile := encryptMessage(t, bins.Age, bins.Plugin, relayRecipient, plaintext, tmpDir)

	// Decrypt should fail — intent will expire (no operator).
	output := decryptMessageExpectFailure(t, bins.Age, bins.Plugin, relayIdentityStr, ciphertextFile, configFile)
	t.Logf("Expected expiry failure output: %s", output)
}

// TestE2EAsyncMultipleIdentities tests that operator with multiple keys can
// unwrap for different relay recipients.
func TestE2EAsyncMultipleIdentities(t *testing.T) {
	bins := buildAllBinaries(t)
	tmpDir := t.TempDir()

	// Generate two key pairs.
	keyFileA := filepath.Join(tmpDir, "keyA.key")
	run(t, bins.AgeKeygen, "-o", keyFileA)
	pubKeyA := extractPublicKey(t, keyFileA)

	keyFileB := filepath.Join(tmpDir, "keyB.key")
	run(t, bins.AgeKeygen, "-o", keyFileB)
	pubKeyB := extractPublicKey(t, keyFileB)

	// Combine both into one identity file.
	dataA, _ := os.ReadFile(keyFileA)
	dataB, _ := os.ReadFile(keyFileB)
	combinedFile := filepath.Join(tmpDir, "combined.key")
	os.WriteFile(combinedFile, append(dataA, dataB...), 0600)

	// Start broker.
	brokerPort := freePort(t)
	brokerURL := fmt.Sprintf("http://127.0.0.1:%d", brokerPort)
	startBroker(t, bins.RelayBroker, brokerPort, "", "2m")

	// Start operator for BOTH tags (we need two operators or one that matches both).
	// Since operator filters by tag, we need two operators.
	tagA := computeTagB64(pubKeyA)
	tagB := computeTagB64(pubKeyB)
	startOperator(t, bins.RelayOperator, brokerURL, combinedFile, tagA, "", "500ms")
	startOperator(t, bins.RelayOperator, brokerURL, combinedFile, tagB, "", "500ms")

	// Test with key A.
	configFileA := writeRelayConfig(t, tmpDir, "multi-a", brokerURL, pubKeyA, map[string]string{
		"timeout":       "30s",
		"poll_interval": "500ms",
	})
	recipientA, identityA := generateRelayKeys(t, bins.Plugin, pubKeyA, "multi-a", configFileA)
	plaintextA := "message for key A — " + time.Now().Format(time.RFC3339Nano)
	ciphertextA := encryptMessage(t, bins.Age, bins.Plugin, recipientA, plaintextA, tmpDir)
	// Rename to avoid overwrite
	ciphertextARenamed := ciphertextA + ".a"
	os.Rename(ciphertextA, ciphertextARenamed)
	decryptedA := decryptMessage(t, bins.Age, bins.Plugin, identityA, ciphertextARenamed, configFileA)
	if decryptedA != plaintextA {
		t.Fatalf("key A plaintext mismatch:\n  want: %q\n  got:  %q", plaintextA, decryptedA)
	}
	t.Logf("Key A: OK")

	// Test with key B.
	bDir := filepath.Join(tmpDir, "b")
	os.MkdirAll(bDir, 0755)
	configFileB := writeRelayConfig(t, bDir, "multi-b", brokerURL, pubKeyB, map[string]string{
		"timeout":       "30s",
		"poll_interval": "500ms",
	})
	recipientB, identityB := generateRelayKeys(t, bins.Plugin, pubKeyB, "multi-b", configFileB)
	plaintextB := "message for key B — " + time.Now().Format(time.RFC3339Nano)
	ciphertextB := encryptMessage(t, bins.Age, bins.Plugin, recipientB, plaintextB, bDir)
	decryptedB := decryptMessage(t, bins.Age, bins.Plugin, identityB, ciphertextB, configFileB)
	if decryptedB != plaintextB {
		t.Fatalf("key B plaintext mismatch:\n  want: %q\n  got:  %q", plaintextB, decryptedB)
	}
	t.Logf("Key B: OK")
}

// TestE2EAsyncWithAuthToken tests the async flow with bearer token authentication.
func TestE2EAsyncWithAuthToken(t *testing.T) {
	bins := buildAllBinaries(t)
	tmpDir := t.TempDir()

	remoteKeyFile := filepath.Join(tmpDir, "remote.key")
	run(t, bins.AgeKeygen, "-o", remoteKeyFile)
	remotePubKey := extractPublicKey(t, remoteKeyFile)

	authToken := "test-secret-token-12345"

	// Start broker with auth token.
	brokerPort := freePort(t)
	brokerURL := fmt.Sprintf("http://127.0.0.1:%d", brokerPort)
	startBroker(t, bins.RelayBroker, brokerPort, authToken, "2m")

	tag := computeTagB64(remotePubKey)
	startOperator(t, bins.RelayOperator, brokerURL, remoteKeyFile, tag, authToken, "500ms")

	configFile := writeRelayConfig(t, tmpDir, "auth-test", brokerURL, remotePubKey, map[string]string{
		"timeout":       "30s",
		"poll_interval": "500ms",
		"auth_token":    authToken,
	})

	relayRecipient, relayIdentityStr := generateRelayKeys(t, bins.Plugin, remotePubKey, "auth-test", configFile)

	plaintext := "E2E async with auth — " + time.Now().Format(time.RFC3339Nano)
	ciphertextFile := encryptMessage(t, bins.Age, bins.Plugin, relayRecipient, plaintext, tmpDir)

	decrypted := decryptMessage(t, bins.Age, bins.Plugin, relayIdentityStr, ciphertextFile, configFile)
	if decrypted != plaintext {
		t.Fatalf("plaintext mismatch:\n  want: %q\n  got:  %q", plaintext, decrypted)
	}
}

// TestE2EAsyncWrongAuthToken tests that the async flow fails with wrong auth token.
func TestE2EAsyncWrongAuthToken(t *testing.T) {
	bins := buildAllBinaries(t)
	tmpDir := t.TempDir()

	remoteKeyFile := filepath.Join(tmpDir, "remote.key")
	run(t, bins.AgeKeygen, "-o", remoteKeyFile)
	remotePubKey := extractPublicKey(t, remoteKeyFile)

	// Broker expects "correct-token"
	brokerPort := freePort(t)
	brokerURL := fmt.Sprintf("http://127.0.0.1:%d", brokerPort)
	startBroker(t, bins.RelayBroker, brokerPort, "correct-token", "2m")

	// Config uses wrong token
	configFile := writeRelayConfig(t, tmpDir, "wrong-auth", brokerURL, remotePubKey, map[string]string{
		"timeout":       "5s",
		"poll_interval": "500ms",
		"auth_token":    "wrong-token",
	})

	relayRecipient, relayIdentityStr := generateRelayKeys(t, bins.Plugin, remotePubKey, "wrong-auth", configFile)

	plaintext := "this should fail due to auth"
	ciphertextFile := encryptMessage(t, bins.Age, bins.Plugin, relayRecipient, plaintext, tmpDir)

	// Should fail — broker rejects unauthorized requests.
	output := decryptMessageExpectFailure(t, bins.Age, bins.Plugin, relayIdentityStr, ciphertextFile, configFile)
	t.Logf("Expected auth failure output: %s", strings.TrimSpace(output))
}
