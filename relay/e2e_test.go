package relay

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestE2ESyncHappyPath exercises the full sync flow: encrypt → relay-server → decrypt.
func TestE2ESyncHappyPath(t *testing.T) {
	bins := buildAllBinaries(t)
	tmpDir := t.TempDir()

	remoteKeyFile := filepath.Join(tmpDir, "remote.key")
	run(t, bins.AgeKeygen, "-o", remoteKeyFile)
	remotePubKey := extractPublicKey(t, remoteKeyFile)

	port := freePort(t)
	relayURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	startServer(t, bins.RelayServer, remoteKeyFile, port)

	configFile := writeRelayConfig(t, tmpDir, "myremote", relayURL, remotePubKey, map[string]string{
		"timeout": "30s",
	})
	relayRecipient, relayIdentityStr := generateRelayKeys(t, bins.Plugin, remotePubKey, "myremote", configFile)

	plaintext := "E2E config: named remote 'myremote' — " + time.Now().Format(time.RFC3339Nano)
	ciphertextFile := encryptMessage(t, bins.Age, bins.Plugin, relayRecipient, plaintext, tmpDir)
	decrypted := decryptMessage(t, bins.Age, bins.Plugin, relayIdentityStr, ciphertextFile, configFile)
	t.Logf("Decrypted: %q", decrypted)

	if decrypted != plaintext {
		t.Fatalf("plaintext mismatch:\n  want: %q\n  got:  %q", plaintext, decrypted)
	}
}

// TestE2ESSEStream exercises the full user flow with SSE streaming enabled
// via relay-config.yaml stream: true.
func TestE2ESSEStream(t *testing.T) {
	bins := buildAllBinaries(t)
	tmpDir := t.TempDir()

	remoteKeyFile := filepath.Join(tmpDir, "remote.key")
	run(t, bins.AgeKeygen, "-o", remoteKeyFile)
	remotePubKey := extractPublicKey(t, remoteKeyFile)

	port := freePort(t)
	relayURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	startServer(t, bins.RelayServer, remoteKeyFile, port)

	configFile := writeRelayConfig(t, tmpDir, "sse-remote", relayURL, remotePubKey, map[string]string{
		"stream":  "true",
		"timeout": "30s",
	})
	relayRecipient, relayIdentityStr := generateRelayKeys(t, bins.Plugin, remotePubKey, "sse-remote", configFile)

	plaintext := "E2E SSE: streaming relay with heartbeats — " + time.Now().Format(time.RFC3339Nano)
	ciphertextFile := encryptMessage(t, bins.Age, bins.Plugin, relayRecipient, plaintext, tmpDir)
	decrypted := decryptMessage(t, bins.Age, bins.Plugin, relayIdentityStr, ciphertextFile, configFile)
	t.Logf("Decrypted via SSE: %q", decrypted)

	if decrypted != plaintext {
		t.Fatalf("plaintext mismatch:\n  want: %q\n  got:  %q", plaintext, decrypted)
	}
}

// ── Helpers ─────────────────────────────────────────────────────────────────

// e2eBinaries holds paths to all built binaries for E2E tests.
type e2eBinaries struct {
	Age           string
	AgeKeygen     string
	Plugin        string
	RelayServer   string
	RelayBroker   string
	RelayOperator string
}

func buildAllBinaries(t *testing.T) e2eBinaries {
	t.Helper()

	// Locate age binaries: one level up from relay/ → ../tools/bin/
	srcDir, _ := os.Getwd()
	ageBin := filepath.Join(srcDir, "..", "tools", "bin", "age")
	ageKeygenBin := filepath.Join(srcDir, "..", "tools", "bin", "age-keygen")
	if _, err := os.Stat(ageBin); err != nil {
		t.Skipf("age binary not found at %s — skipping E2E test", ageBin)
	}
	if _, err := os.Stat(ageKeygenBin); err != nil {
		t.Skipf("age-keygen binary not found at %s — skipping E2E test", ageKeygenBin)
	}

	binDir := t.TempDir()
	moduleRoot := filepath.Join(srcDir, "..")

	bins := e2eBinaries{
		Age:           ageBin,
		AgeKeygen:     ageKeygenBin,
		Plugin:        filepath.Join(binDir, "age-plugin-relay"),
		RelayServer:   filepath.Join(binDir, "relay-server"),
		RelayBroker:   filepath.Join(binDir, "relay-broker"),
		RelayOperator: filepath.Join(binDir, "relay-operator"),
	}

	gobuild(t, moduleRoot, "./cmd/age-plugin-relay/", bins.Plugin)
	gobuild(t, moduleRoot, "./cmd/relay-server/", bins.RelayServer)
	gobuild(t, moduleRoot, "./cmd/relay-broker/", bins.RelayBroker)
	gobuild(t, moduleRoot, "./cmd/relay-operator/", bins.RelayOperator)

	return bins
}

// startServer starts a relay-server and returns cleanup. Blocks until server is ready.
func startServer(t *testing.T, serverBin, identityFile string, port int, extraArgs ...string) *exec.Cmd {
	t.Helper()
	args := []string{"-identity", identityFile, "-addr", fmt.Sprintf(":%d", port)}
	args = append(args, extraArgs...)
	cmd := exec.Command(serverBin, args...)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting relay-server: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	waitForServer(t, port)
	return cmd
}

// startBroker starts a relay-broker and returns cleanup. Blocks until server is ready.
func startBroker(t *testing.T, brokerBin string, port int, authToken, maxTTL string) *exec.Cmd {
	t.Helper()
	args := []string{"-addr", fmt.Sprintf(":%d", port)}
	if authToken != "" {
		args = append(args, "-auth-token", authToken)
	}
	if maxTTL != "" {
		args = append(args, "-max-ttl", maxTTL)
	}
	cmd := exec.Command(brokerBin, args...)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting relay-broker: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	waitForServer(t, port)
	return cmd
}

// startOperator starts a relay-operator in the background.
func startOperator(t *testing.T, operatorBin, brokerURL, identityFile, tag string, authToken, pullInterval string) *exec.Cmd {
	t.Helper()
	args := []string{"--broker", brokerURL, "--identity", identityFile, "--tag", tag, "--loop"}
	if authToken != "" {
		args = append(args, "--auth-token", authToken)
	}
	if pullInterval != "" {
		args = append(args, "--pull-interval", pullInterval)
	}
	cmd := exec.Command(operatorBin, args...)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting relay-operator: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	return cmd
}

// writeRelayConfig writes a relay-config.yaml for testing and returns the file path.
func writeRelayConfig(t *testing.T, tmpDir, remoteName, url, unwrapRecipient string, extras map[string]string) string {
	t.Helper()
	configFile := filepath.Join(tmpDir, "relay-config.yaml")
	var buf strings.Builder
	fmt.Fprintf(&buf, "remotes:\n  %s:\n    url: %s\n    unwrap_recipient: %s\n", remoteName, url, unwrapRecipient)
	for k, v := range extras {
		fmt.Fprintf(&buf, "    %s: %s\n", k, v)
	}
	os.WriteFile(configFile, []byte(buf.String()), 0644)
	t.Logf("Config:\n%s", buf.String())
	return configFile
}

// generateRelayKeys runs the plugin --generate and returns (recipient, identity).
func generateRelayKeys(t *testing.T, pluginBin, remotePubKey, remoteName, configFile string) (string, string) {
	t.Helper()
	genCmd := exec.Command(pluginBin, "--generate", "--inner-recipient", remotePubKey, "--remote", remoteName)
	genCmd.Env = append(os.Environ(), "AGE_PLUGIN_RELAY_CONFIG="+configFile)
	genOutBytes, err := genCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("--generate --remote: %v\n%s", err, genOutBytes)
	}
	genOut := string(genOutBytes)
	relayRecipient := extractLine(t, genOut, "age1relay1")
	relayIdentityStr := extractLine(t, genOut, "AGE-PLUGIN-RELAY-1")
	t.Logf("Relay recipient: %s", truncate(relayRecipient, 50))
	t.Logf("Relay identity:  %s", truncate(relayIdentityStr, 50))
	return relayRecipient, relayIdentityStr
}

// encryptMessage encrypts plaintext with a relay recipient and returns the ciphertext file path.
func encryptMessage(t *testing.T, ageBin, pluginBin, relayRecipient, plaintext, tmpDir string) string {
	t.Helper()
	ciphertextFile := filepath.Join(tmpDir, "secret.age")
	encCmd := exec.Command(ageBin, "-r", relayRecipient, "-o", ciphertextFile)
	encCmd.Stdin = strings.NewReader(plaintext)
	encCmd.Env = pluginEnv(pluginBin)
	if out, err := encCmd.CombinedOutput(); err != nil {
		t.Fatalf("encrypt: %v\n%s", err, out)
	}
	t.Logf("Encrypted %d bytes", fileSize(t, ciphertextFile))
	return ciphertextFile
}

// decryptMessage decrypts a ciphertext file using a relay identity and returns the plaintext.
func decryptMessage(t *testing.T, ageBin, pluginBin, identityStr, ciphertextFile, configFile string) string {
	t.Helper()
	tmpDir := t.TempDir()
	identityFile := filepath.Join(tmpDir, "relay-identity.txt")
	os.WriteFile(identityFile, []byte(identityStr+"\n"), 0600)

	decCmd := exec.Command(ageBin, "-d", "-i", identityFile, ciphertextFile)
	decCmd.Env = append(pluginEnv(pluginBin), "AGE_PLUGIN_RELAY_CONFIG="+configFile)
	decOutBytes, err := decCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("decrypt: %v\n%s", err, decOutBytes)
	}
	return strings.TrimRight(string(decOutBytes), "\n")
}

// decryptMessageExpectFailure decrypts and expects an error. Returns the combined output.
func decryptMessageExpectFailure(t *testing.T, ageBin, pluginBin, identityStr, ciphertextFile, configFile string) string {
	t.Helper()
	tmpDir := t.TempDir()
	identityFile := filepath.Join(tmpDir, "relay-identity.txt")
	os.WriteFile(identityFile, []byte(identityStr+"\n"), 0600)

	decCmd := exec.Command(ageBin, "-d", "-i", identityFile, ciphertextFile)
	decCmd.Env = append(pluginEnv(pluginBin), "AGE_PLUGIN_RELAY_CONFIG="+configFile)
	out, err := decCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected decrypt to fail, but it succeeded: %s", out)
	}
	return string(out)
}

// computeTagB64 computes the base64 tag for a recipient (first 16 bytes of SHA256).
func computeTagB64(innerRecipient string) string {
	tag := ComputeTag(innerRecipient)
	return base64.RawStdEncoding.EncodeToString(tag[:])
}

func gobuild(t *testing.T, dir, pkg, output string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", output, pkg)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s (in %s): %v\n%s", pkg, dir, err, out)
	}
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

func pluginEnv(pluginBin string) []string {
	env := os.Environ()
	pluginDir := filepath.Dir(pluginBin)
	for i, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			env[i] = "PATH=" + pluginDir + string(os.PathListSeparator) + strings.TrimPrefix(e, "PATH=")
			return env
		}
	}
	return append(env, "PATH="+pluginDir)
}

func extractPublicKey(t *testing.T, keyFile string) string {
	t.Helper()
	data, _ := os.ReadFile(keyFile)
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "public key:") {
			return strings.Fields(line)[len(strings.Fields(line))-1]
		}
	}
	t.Fatalf("no public key in %s", keyFile)
	return ""
}

func extractLine(t *testing.T, output, prefix string) string {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	t.Fatalf("no line with prefix %q in:\n%s", prefix, output)
	return ""
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func waitForServer(t *testing.T, port int) {
	t.Helper()
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server on :%d did not start in time", port)
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	info, _ := os.Stat(path)
	return info.Size()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
