package relay

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestE2ELegacyURL exercises the full user flow with real binaries:
//
//	age-keygen → age-plugin-relay --generate → relay-server → age -r (encrypt) → age -d (decrypt)
func TestE2ELegacyURL(t *testing.T) {
	ageBin, ageKeygenBin, pluginBin, relayServerBin := buildAll(t)
	tmpDir := t.TempDir()

	remoteKeyFile := filepath.Join(tmpDir, "remote.key")
	run(t, ageKeygenBin, "-o", remoteKeyFile)
	remotePubKey := extractPublicKey(t, remoteKeyFile)
	t.Logf("Remote public key: %s", remotePubKey)

	port := freePort(t)
	relayURL := fmt.Sprintf("http://127.0.0.1:%d/unwrap", port)

	relayCmd := exec.Command(relayServerBin, "-identity", remoteKeyFile, "-addr", fmt.Sprintf(":%d", port))
	relayCmd.Stderr = os.Stderr
	if err := relayCmd.Start(); err != nil {
		t.Fatalf("starting relay-server: %v", err)
	}
	t.Cleanup(func() { relayCmd.Process.Kill(); relayCmd.Wait() })
	waitForServer(t, port)
	t.Logf("Relay server listening on :%d", port)

	genOut := runCapture(t, pluginBin, "--generate", "--inner-recipient", remotePubKey, "--relay-url", relayURL)
	relayRecipient := extractLine(t, genOut, "age1relay1")
	relayIdentityStr := extractLine(t, genOut, "AGE-PLUGIN-RELAY-1")
	t.Logf("Relay recipient: %s", truncate(relayRecipient, 50))
	t.Logf("Relay identity:  %s", truncate(relayIdentityStr, 50))

	identityFile := filepath.Join(tmpDir, "relay-identity.txt")
	os.WriteFile(identityFile, []byte(relayIdentityStr+"\n"), 0600)

	plaintext := "E2E legacy: the quick brown fox — " + time.Now().Format(time.RFC3339Nano)
	ciphertextFile := filepath.Join(tmpDir, "secret.age")

	encCmd := exec.Command(ageBin, "-r", relayRecipient, "-o", ciphertextFile)
	encCmd.Stdin = strings.NewReader(plaintext)
	encCmd.Env = pluginEnv(pluginBin)
	if out, err := encCmd.CombinedOutput(); err != nil {
		t.Fatalf("encrypt: %v\n%s", err, out)
	}
	t.Logf("Encrypted %d bytes", fileSize(t, ciphertextFile))

	header := readFileHead(t, ciphertextFile, 4)
	if !strings.Contains(header, "-> relay ") {
		t.Fatalf("expected relay stanza in header, got:\n%s", header)
	}

	decCmd := exec.Command(ageBin, "-d", "-i", identityFile, ciphertextFile)
	decCmd.Env = pluginEnv(pluginBin)
	decOutBytes, err := decCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("decrypt: %v\n%s", err, decOutBytes)
	}
	decrypted := strings.TrimRight(string(decOutBytes), "\n")
	t.Logf("Decrypted: %q", decrypted)

	if decrypted != plaintext {
		t.Fatalf("plaintext mismatch:\n  want: %q\n  got:  %q", plaintext, decrypted)
	}
}

// TestE2EConfigMode exercises the full user flow with relay-config.yaml.
func TestE2EConfigMode(t *testing.T) {
	ageBin, ageKeygenBin, pluginBin, relayServerBin := buildAll(t)
	tmpDir := t.TempDir()

	remoteKeyFile := filepath.Join(tmpDir, "remote.key")
	run(t, ageKeygenBin, "-o", remoteKeyFile)
	remotePubKey := extractPublicKey(t, remoteKeyFile)

	port := freePort(t)
	relayURL := fmt.Sprintf("http://127.0.0.1:%d/unwrap", port)

	relayCmd := exec.Command(relayServerBin, "-identity", remoteKeyFile, "-addr", fmt.Sprintf(":%d", port))
	relayCmd.Stderr = os.Stderr
	if err := relayCmd.Start(); err != nil {
		t.Fatalf("starting relay-server: %v", err)
	}
	t.Cleanup(func() { relayCmd.Process.Kill(); relayCmd.Wait() })
	waitForServer(t, port)

	configFile := filepath.Join(tmpDir, "relay-config.yaml")
	configContent := fmt.Sprintf("remotes:\n  myremote:\n    url: %s\n    timeout: 30s\n", relayURL)
	os.WriteFile(configFile, []byte(configContent), 0644)
	t.Logf("Config:\n%s", configContent)

	genCmd := exec.Command(pluginBin, "--generate", "--inner-recipient", remotePubKey, "--remote", "myremote")
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

	if strings.Contains(relayIdentityStr, "127.0.0.1") {
		t.Fatalf("config-mode identity should NOT contain URL, got: %s", relayIdentityStr)
	}

	identityFile := filepath.Join(tmpDir, "relay-identity.txt")
	os.WriteFile(identityFile, []byte(relayIdentityStr+"\n"), 0600)

	plaintext := "E2E config: named remote 'myremote' — " + time.Now().Format(time.RFC3339Nano)
	ciphertextFile := filepath.Join(tmpDir, "secret.age")

	encCmd := exec.Command(ageBin, "-r", relayRecipient, "-o", ciphertextFile)
	encCmd.Stdin = strings.NewReader(plaintext)
	encCmd.Env = pluginEnv(pluginBin)
	if out, err := encCmd.CombinedOutput(); err != nil {
		t.Fatalf("encrypt: %v\n%s", err, out)
	}
	t.Logf("Encrypted %d bytes", fileSize(t, ciphertextFile))

	decCmd := exec.Command(ageBin, "-d", "-i", identityFile, ciphertextFile)
	decCmd.Env = append(pluginEnv(pluginBin), "AGE_PLUGIN_RELAY_CONFIG="+configFile)
	decOutBytes, err := decCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("decrypt: %v\n%s", err, decOutBytes)
	}
	decrypted := strings.TrimRight(string(decOutBytes), "\n")
	t.Logf("Decrypted: %q", decrypted)

	if decrypted != plaintext {
		t.Fatalf("plaintext mismatch:\n  want: %q\n  got:  %q", plaintext, decrypted)
	}
}

// TestE2ESSEStream exercises the full user flow with SSE streaming enabled
// via relay-config.yaml stream: true.
func TestE2ESSEStream(t *testing.T) {
	ageBin, ageKeygenBin, pluginBin, relayServerBin := buildAll(t)
	tmpDir := t.TempDir()

	// ── Step 1: Generate remote key pair ────────────────────────────────
	remoteKeyFile := filepath.Join(tmpDir, "remote.key")
	run(t, ageKeygenBin, "-o", remoteKeyFile)
	remotePubKey := extractPublicKey(t, remoteKeyFile)
	t.Logf("Remote public key: %s", remotePubKey)

	// ── Step 2: Start relay-server ──────────────────────────────────────
	port := freePort(t)
	relayURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	relayCmd := exec.Command(relayServerBin, "-identity", remoteKeyFile, "-addr", fmt.Sprintf(":%d", port))
	relayCmd.Stderr = os.Stderr
	if err := relayCmd.Start(); err != nil {
		t.Fatalf("starting relay-server: %v", err)
	}
	t.Cleanup(func() { relayCmd.Process.Kill(); relayCmd.Wait() })
	waitForServer(t, port)
	t.Logf("Relay server listening on :%d", port)

	// ── Step 3: Write config with stream: true ──────────────────────────
	configFile := filepath.Join(tmpDir, "relay-config.yaml")
	configContent := fmt.Sprintf("remotes:\n  sse-remote:\n    url: %s\n    stream: true\n    timeout: 30s\n", relayURL)
	os.WriteFile(configFile, []byte(configContent), 0644)
	t.Logf("Config:\n%s", configContent)

	// ── Step 4: Generate with --remote ──────────────────────────────────
	genCmd := exec.Command(pluginBin, "--generate", "--inner-recipient", remotePubKey, "--remote", "sse-remote")
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

	identityFile := filepath.Join(tmpDir, "relay-identity.txt")
	os.WriteFile(identityFile, []byte(relayIdentityStr+"\n"), 0600)

	// ── Step 5: Encrypt ─────────────────────────────────────────────────
	plaintext := "E2E SSE: streaming relay with heartbeats — " + time.Now().Format(time.RFC3339Nano)
	ciphertextFile := filepath.Join(tmpDir, "secret.age")

	encCmd := exec.Command(ageBin, "-r", relayRecipient, "-o", ciphertextFile)
	encCmd.Stdin = strings.NewReader(plaintext)
	encCmd.Env = pluginEnv(pluginBin)
	if out, err := encCmd.CombinedOutput(); err != nil {
		t.Fatalf("encrypt: %v\n%s", err, out)
	}
	t.Logf("Encrypted %d bytes", fileSize(t, ciphertextFile))

	// ── Step 6: Decrypt (SSE path — config has stream: true) ────────────
	decCmd := exec.Command(ageBin, "-d", "-i", identityFile, ciphertextFile)
	decCmd.Env = append(pluginEnv(pluginBin), "AGE_PLUGIN_RELAY_CONFIG="+configFile)
	decOutBytes, err := decCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("decrypt (SSE): %v\n%s", err, decOutBytes)
	}
	decrypted := strings.TrimRight(string(decOutBytes), "\n")
	t.Logf("Decrypted via SSE: %q", decrypted)

	// ── Step 7: Verify ──────────────────────────────────────────────────
	if decrypted != plaintext {
		t.Fatalf("plaintext mismatch:\n  want: %q\n  got:  %q", plaintext, decrypted)
	}
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func buildAll(t *testing.T) (ageBin, ageKeygenBin, pluginBin, relayServerBin string) {
	t.Helper()

	// Locate age binaries: two levels up from relay/ → ../../bin/
	srcDir, _ := os.Getwd()
	ageBin = filepath.Join(srcDir, "..", "..", "bin", "age")
	ageKeygenBin = filepath.Join(srcDir, "..", "..", "bin", "age-keygen")
	if _, err := os.Stat(ageBin); err != nil {
		t.Skipf("age binary not found at %s — skipping E2E test", ageBin)
	}
	if _, err := os.Stat(ageKeygenBin); err != nil {
		t.Skipf("age-keygen binary not found at %s — skipping E2E test", ageKeygenBin)
	}

	binDir := t.TempDir()
	pluginBin = filepath.Join(binDir, "age-plugin-relay")
	relayServerBin = filepath.Join(binDir, "relay-server")

	// Build from the module root (one level up from relay/)
	moduleRoot := filepath.Join(srcDir, "..")
	gobuild(t, moduleRoot, "./cmd/age-plugin-relay/", pluginBin)
	gobuild(t, moduleRoot, "./cmd/relay-server/", relayServerBin)

	return
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

func runCapture(t *testing.T, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
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

func readFileHead(t *testing.T, path string, n int) string {
	t.Helper()
	data, _ := os.ReadFile(path)
	lines := strings.SplitN(string(data), "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
