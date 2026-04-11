package main

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
//
// Uses URL-in-identity (legacy mode).
func TestE2ELegacyURL(t *testing.T) {
	ageBin, ageKeygenBin, pluginBin, relayServerBin := buildAll(t)
	tmpDir := t.TempDir()

	// ── Step 1: Generate remote key pair ────────────────────────────────
	remoteKeyFile := filepath.Join(tmpDir, "remote.key")
	run(t, ageKeygenBin, "-o", remoteKeyFile)
	remotePubKey := extractPublicKey(t, remoteKeyFile)
	t.Logf("Remote public key: %s", remotePubKey)

	// ── Step 2: Start relay-server ──────────────────────────────────────
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

	// ── Step 3: Generate relay recipient + identity ─────────────────────
	genOut := runCapture(t, pluginBin, "--generate",
		"--inner-recipient", remotePubKey,
		"--relay-url", relayURL)

	relayRecipient := extractLine(t, genOut, "age1relay1")
	relayIdentityStr := extractLine(t, genOut, "AGE-PLUGIN-RELAY-1")
	t.Logf("Relay recipient: %s", truncate(relayRecipient, 50))
	t.Logf("Relay identity:  %s", truncate(relayIdentityStr, 50))

	identityFile := filepath.Join(tmpDir, "relay-identity.txt")
	os.WriteFile(identityFile, []byte(relayIdentityStr+"\n"), 0600)

	// ── Step 4: Encrypt ─────────────────────────────────────────────────
	plaintext := "E2E legacy: the quick brown fox — " + time.Now().Format(time.RFC3339Nano)
	plaintextFile := filepath.Join(tmpDir, "plaintext.txt")
	ciphertextFile := filepath.Join(tmpDir, "secret.age")
	os.WriteFile(plaintextFile, []byte(plaintext), 0644)

	runWithStdin(t, plaintext, ageBin, "-r", relayRecipient, "-o", ciphertextFile)
	t.Logf("Encrypted %d bytes", fileSize(t, ciphertextFile))

	// Verify stanza format in encrypted file.
	header := readFileHead(t, ciphertextFile, 4)
	if !strings.Contains(header, "-> relay ") {
		t.Fatalf("expected relay stanza in header, got:\n%s", header)
	}

	// ── Step 5: Decrypt ─────────────────────────────────────────────────
	decrypted := runCapture(t, ageBin, "-d", "-i", identityFile, ciphertextFile)
	decrypted = strings.TrimRight(decrypted, "\n")
	t.Logf("Decrypted: %q", decrypted)

	// ── Step 6: Verify ──────────────────────────────────────────────────
	if decrypted != plaintext {
		t.Fatalf("plaintext mismatch:\n  want: %q\n  got:  %q", plaintext, decrypted)
	}
}

// TestE2EConfigMode exercises the full user flow with relay-config.yaml:
//
//	age-keygen → relay-config.yaml → age-plugin-relay --generate --remote → relay-server → encrypt → decrypt
func TestE2EConfigMode(t *testing.T) {
	ageBin, ageKeygenBin, pluginBin, relayServerBin := buildAll(t)
	tmpDir := t.TempDir()

	// ── Step 1: Generate remote key pair ────────────────────────────────
	remoteKeyFile := filepath.Join(tmpDir, "remote.key")
	run(t, ageKeygenBin, "-o", remoteKeyFile)
	remotePubKey := extractPublicKey(t, remoteKeyFile)

	// ── Step 2: Start relay-server ──────────────────────────────────────
	port := freePort(t)
	relayURL := fmt.Sprintf("http://127.0.0.1:%d/unwrap", port)

	relayCmd := exec.Command(relayServerBin, "-identity", remoteKeyFile, "-addr", fmt.Sprintf(":%d", port))
	relayCmd.Stderr = os.Stderr
	if err := relayCmd.Start(); err != nil {
		t.Fatalf("starting relay-server: %v", err)
	}
	t.Cleanup(func() { relayCmd.Process.Kill(); relayCmd.Wait() })
	waitForServer(t, port)

	// ── Step 3: Write relay-config.yaml ─────────────────────────────────
	configFile := filepath.Join(tmpDir, "relay-config.yaml")
	configContent := fmt.Sprintf("remotes:\n  myremote:\n    url: %s\n    timeout: 30s\n", relayURL)
	os.WriteFile(configFile, []byte(configContent), 0644)
	t.Logf("Config:\n%s", configContent)

	// ── Step 4: Generate with --remote ──────────────────────────────────
	genCmd := exec.Command(pluginBin, "--generate",
		"--inner-recipient", remotePubKey,
		"--remote", "myremote")
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

	// Verify identity is shorter (contains "myremote" not full URL).
	if strings.Contains(relayIdentityStr, "127.0.0.1") {
		t.Fatalf("config-mode identity should NOT contain URL, got: %s", relayIdentityStr)
	}

	identityFile := filepath.Join(tmpDir, "relay-identity.txt")
	os.WriteFile(identityFile, []byte(relayIdentityStr+"\n"), 0600)

	// ── Step 5: Encrypt ─────────────────────────────────────────────────
	plaintext := "E2E config: named remote 'myremote' — " + time.Now().Format(time.RFC3339Nano)
	ciphertextFile := filepath.Join(tmpDir, "secret.age")

	// age -r needs plugin in PATH. Config env var is only needed for decrypt.
	encCmd := exec.Command(ageBin, "-r", relayRecipient, "-o", ciphertextFile)
	encCmd.Stdin = strings.NewReader(plaintext)
	encCmd.Env = pluginEnv(pluginBin)
	if out, err := encCmd.CombinedOutput(); err != nil {
		t.Fatalf("encrypt: %v\n%s", err, out)
	}
	t.Logf("Encrypted %d bytes", fileSize(t, ciphertextFile))

	// ── Step 6: Decrypt (needs config env var for remote resolution) ────
	decCmd := exec.Command(ageBin, "-d", "-i", identityFile, ciphertextFile)
	decCmd.Env = append(pluginEnv(pluginBin), "AGE_PLUGIN_RELAY_CONFIG="+configFile)
	decOutBytes, err := decCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("decrypt: %v\n%s", err, decOutBytes)
	}
	decrypted := strings.TrimRight(string(decOutBytes), "\n")
	t.Logf("Decrypted: %q", decrypted)

	// ── Step 7: Verify ──────────────────────────────────────────────────
	if decrypted != plaintext {
		t.Fatalf("plaintext mismatch:\n  want: %q\n  got:  %q", plaintext, decrypted)
	}
}

// ── Helpers ─────────────────────────────────────────────────────────────────

// buildAll compiles the plugin and relay-server binaries, returning paths.
// Also locates age and age-keygen from ../bin/.
func buildAll(t *testing.T) (ageBin, ageKeygenBin, pluginBin, relayServerBin string) {
	t.Helper()

	// Locate age binaries relative to the source dir.
	srcDir, _ := os.Getwd()
	ageBin = filepath.Join(srcDir, "..", "bin", "age")
	ageKeygenBin = filepath.Join(srcDir, "..", "bin", "age-keygen")
	if _, err := os.Stat(ageBin); err != nil {
		t.Skipf("age binary not found at %s — skipping E2E test", ageBin)
	}
	if _, err := os.Stat(ageKeygenBin); err != nil {
		t.Skipf("age-keygen binary not found at %s — skipping E2E test", ageKeygenBin)
	}

	// Build plugin and relay-server to a temp dir.
	binDir := t.TempDir()
	pluginBin = filepath.Join(binDir, "age-plugin-relay")
	relayServerBin = filepath.Join(binDir, "relay-server")

	gobuild(t, ".", pluginBin)
	gobuild(t, "./cmd/relay-server/", relayServerBin)

	return ageBin, ageKeygenBin, pluginBin, relayServerBin
}

func gobuild(t *testing.T, pkg, output string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", output, pkg)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", pkg, err, out)
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
	cmd.Env = pluginEnv(findPluginInArgs(args))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

func runWithStdin(t *testing.T, stdin, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Env = pluginEnv(findPluginInArgs(args))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

// pluginEnv returns an environment with the plugin binary's directory in PATH.
func pluginEnv(pluginBin string) []string {
	env := os.Environ()
	if pluginBin == "" {
		return env
	}
	pluginDir := filepath.Dir(pluginBin)
	for i, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			env[i] = "PATH=" + pluginDir + string(os.PathListSeparator) + strings.TrimPrefix(e, "PATH=")
			return env
		}
	}
	return append(env, "PATH="+pluginDir)
}

// findPluginInArgs looks through args for a path to the plugin binary.
// Used by runCapture/runWithStdin to set PATH correctly.
func findPluginInArgs(args []string) string {
	// The plugin binary path is the program being run (first arg to exec),
	// but we need it from the calling context. We'll rely on the test
	// calling pluginEnv directly for age commands.
	return ""
}

func extractPublicKey(t *testing.T, keyFile string) string {
	t.Helper()
	data, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "public key:") {
			parts := strings.Fields(line)
			return parts[len(parts)-1]
		}
	}
	t.Fatalf("no public key found in %s", keyFile)
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
	t.Fatalf("no line starting with %q in output:\n%s", prefix, output)
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
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
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
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

func readFileHead(t *testing.T, path string, nLines int) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitN(string(data), "\n", nLines+1)
	if len(lines) > nLines {
		lines = lines[:nLines]
	}
	return strings.Join(lines, "\n")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
