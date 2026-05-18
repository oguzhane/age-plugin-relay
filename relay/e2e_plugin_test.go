package relay

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestE2EPluginAgnosticSync exercises the full sync flow with a non-X25519 plugin
// recipient (age1stub1...), proving the relay is plugin-agnostic.
func TestE2EPluginAgnosticSync(t *testing.T) {
	bins := buildAllBinaries(t)
	tmpDir := t.TempDir()

	// 1. Generate stub plugin keypair (age1stub1... / AGE-PLUGIN-STUB-1...).
	stubRecipient, stubIdentityStr := generateStubKeys(t, bins.StubPlugin)
	t.Logf("Stub recipient: %s", truncate(stubRecipient, 60))

	// 2. Write identity file for relay-server.
	stubKeyFile := filepath.Join(tmpDir, "stub.key")
	os.WriteFile(stubKeyFile, []byte(stubIdentityStr+"\n"), 0600)

	// 3. Start relay-server with stub identity (needs age-plugin-stub in PATH).
	port := freePort(t)
	relayURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	startServerWithEnv(t, bins.RelayServer, stubKeyFile, port, pluginEnvMulti(bins.Plugin, bins.StubPlugin))

	// 4. Write config with stub recipient as unwrap_recipient.
	configFile := writeRelayConfig(t, tmpDir, "stub-sync", relayURL, stubRecipient, map[string]string{
		"timeout": "30s",
	})

	// 5. Generate relay keys wrapping the stub recipient.
	relayRecipient, relayIdentityStr := generateRelayKeys(t, bins.Plugin, stubRecipient, "stub-sync", configFile)

	// 6. Encrypt and decrypt.
	plaintext := "E2E plugin-agnostic sync — " + time.Now().Format(time.RFC3339Nano)
	ciphertextFile := encryptMessageWithEnv(t, bins.Age, plaintext, tmpDir, pluginEnvMulti(bins.Plugin, bins.StubPlugin), relayRecipient)
	decrypted := decryptMessageWithEnv(t, bins.Age, relayIdentityStr, ciphertextFile, configFile, pluginEnvMulti(bins.Plugin, bins.StubPlugin))
	t.Logf("Decrypted: %q", decrypted)

	if decrypted != plaintext {
		t.Fatalf("plaintext mismatch:\n  want: %q\n  got:  %q", plaintext, decrypted)
	}
}

// TestE2EPluginAgnosticAsync exercises the full async flow with a non-X25519 plugin
// recipient (age1stub1...), proving the relay is plugin-agnostic end-to-end.
func TestE2EPluginAgnosticAsync(t *testing.T) {
	bins := buildAllBinaries(t)
	tmpDir := t.TempDir()

	// 1. Generate stub plugin keypair.
	stubRecipient, stubIdentityStr := generateStubKeys(t, bins.StubPlugin)

	// 2. Write identity file for operator.
	stubKeyFile := filepath.Join(tmpDir, "stub.key")
	os.WriteFile(stubKeyFile, []byte(stubIdentityStr+"\n"), 0600)

	// 3. Start broker.
	brokerPort := freePort(t)
	brokerURL := fmt.Sprintf("http://127.0.0.1:%d", brokerPort)
	startBroker(t, bins.RelayBroker, brokerPort, "", "2m")

	// 4. Start operator with stub identity (needs age-plugin-stub in PATH).
	tag := computeTagB64(stubRecipient)
	startOperatorWithEnv(t, bins.RelayOperator, brokerURL, stubKeyFile, tag, "", "500ms", pluginEnvMulti(bins.Plugin, bins.StubPlugin))

	// 5. Write config pointing at broker.
	configFile := writeRelayConfig(t, tmpDir, "stub-async", brokerURL, stubRecipient, map[string]string{
		"timeout":       "30s",
		"poll_interval": "500ms",
	})

	// 6. Generate relay keys wrapping the stub recipient.
	relayRecipient, relayIdentityStr := generateRelayKeys(t, bins.Plugin, stubRecipient, "stub-async", configFile)

	// 7. Encrypt.
	plaintext := "E2E plugin-agnostic async — " + time.Now().Format(time.RFC3339Nano)
	ciphertextFile := encryptMessageWithEnv(t, bins.Age, plaintext, tmpDir, pluginEnvMulti(bins.Plugin, bins.StubPlugin), relayRecipient)

	// 8. Decrypt via async flow.
	decrypted := decryptMessageWithEnv(t, bins.Age, relayIdentityStr, ciphertextFile, configFile, pluginEnvMulti(bins.Plugin, bins.StubPlugin))
	t.Logf("Decrypted: %q", decrypted)

	if decrypted != plaintext {
		t.Fatalf("plaintext mismatch:\n  want: %q\n  got:  %q", plaintext, decrypted)
	}
}

// generateStubKeys runs age-plugin-stub --generate and returns (recipient, identity).
func generateStubKeys(t *testing.T, stubBin string) (string, string) {
	t.Helper()
	out, err := exec.Command(stubBin, "--generate").CombinedOutput()
	if err != nil {
		t.Fatalf("stub --generate: %v\n%s", err, out)
	}
	output := string(out)
	// Recipient is on a comment line: "# recipient: age1stub1..."
	var recipient, identity string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "age1stub1") {
			// Extract the age1stub1... token from the line.
			for _, word := range strings.Fields(line) {
				if strings.HasPrefix(word, "age1stub1") {
					recipient = word
					break
				}
			}
		}
		if strings.HasPrefix(line, "AGE-PLUGIN-STUB-1") {
			identity = line
		}
	}
	if recipient == "" {
		t.Fatalf("no stub recipient in output:\n%s", output)
	}
	if identity == "" {
		t.Fatalf("no stub identity in output:\n%s", output)
	}
	return recipient, identity
}

// pluginEnvMulti returns an env slice with all given plugin binary dirs in PATH.
func pluginEnvMulti(pluginBins ...string) []string {
	env := os.Environ()
	var dirs []string
	for _, bin := range pluginBins {
		dirs = append(dirs, filepath.Dir(bin))
	}
	prefix := strings.Join(dirs, string(os.PathListSeparator))
	for i, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			env[i] = "PATH=" + prefix + string(os.PathListSeparator) + strings.TrimPrefix(e, "PATH=")
			return env
		}
	}
	return append(env, "PATH="+prefix)
}

// startServerWithEnv starts relay-server with a custom env (for PATH with plugin binaries).
func startServerWithEnv(t *testing.T, serverBin, identityFile string, port int, env []string, extraArgs ...string) *exec.Cmd {
	t.Helper()
	args := []string{"-identity", identityFile, "-addr", fmt.Sprintf(":%d", port)}
	args = append(args, extraArgs...)
	cmd := exec.Command(serverBin, args...)
	cmd.Env = env
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting relay-server: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	waitForServer(t, port)
	return cmd
}

// startOperatorWithEnv starts relay-operator with a custom env.
func startOperatorWithEnv(t *testing.T, operatorBin, brokerURL, identityFile, tag string, authToken, pullInterval string, env []string) *exec.Cmd {
	t.Helper()
	args := []string{"--broker", brokerURL, "--identity", identityFile, "--tag", tag, "--loop"}
	if authToken != "" {
		args = append(args, "--auth-token", authToken)
	}
	if pullInterval != "" {
		args = append(args, "--pull-interval", pullInterval)
	}
	cmd := exec.Command(operatorBin, args...)
	cmd.Env = env
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting relay-operator: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	return cmd
}

// encryptMessageWithEnv encrypts with a custom env (multiple plugins in PATH).
func encryptMessageWithEnv(t *testing.T, ageBin, plaintext, tmpDir string, env []string, relayRecipient string) string {
	t.Helper()
	ciphertextFile := filepath.Join(tmpDir, "secret.age")
	cmd := exec.Command(ageBin, "-r", relayRecipient, "-o", ciphertextFile)
	cmd.Stdin = strings.NewReader(plaintext)
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("encrypt: %v\n%s", err, out)
	}
	t.Logf("Encrypted %d bytes", fileSize(t, ciphertextFile))
	return ciphertextFile
}

// decryptMessageWithEnv decrypts with a custom env (multiple plugins in PATH).
func decryptMessageWithEnv(t *testing.T, ageBin, identityStr, ciphertextFile, configFile string, env []string) string {
	t.Helper()
	tmpDir := t.TempDir()
	identityFile := filepath.Join(tmpDir, "relay-identity.txt")
	os.WriteFile(identityFile, []byte(identityStr+"\n"), 0600)

	cmd := exec.Command(ageBin, "-d", "-i", identityFile, ciphertextFile)
	cmd.Env = append(env, "AGE_PLUGIN_RELAY_CONFIG="+configFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("decrypt: %v\n%s", err, out)
	}
	return strings.TrimRight(string(out), "\n")
}
