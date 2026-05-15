package relay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestE2ETLSSync tests the sync flow over HTTPS with a self-signed CA.
func TestE2ETLSSync(t *testing.T) {
	bins := buildAllBinaries(t)
	tmpDir := t.TempDir()

	remoteKeyFile := filepath.Join(tmpDir, "remote.key")
	run(t, bins.AgeKeygen, "-o", remoteKeyFile)
	remotePubKey := extractPublicKey(t, remoteKeyFile)

	// Generate CA + server cert.
	caKey, caCert, caCertPEM := generateCA(t, tmpDir)
	serverCertFile, serverKeyFile := generateServerCert(t, tmpDir, caKey, caCert)
	caCertFile := filepath.Join(tmpDir, "ca.crt")
	os.WriteFile(caCertFile, caCertPEM, 0644)

	port := freePort(t)
	relayURL := fmt.Sprintf("https://127.0.0.1:%d", port)
	startServer(t, bins.RelayServer, remoteKeyFile, port, "-tls-cert", serverCertFile, "-tls-key", serverKeyFile)

	configFile := writeRelayConfig(t, tmpDir, "tls-sync", relayURL, remotePubKey, map[string]string{
		"timeout": "10s",
		"tls_ca":  caCertFile,
	})
	relayRecipient, relayIdentityStr := generateRelayKeys(t, bins.Plugin, remotePubKey, "tls-sync", configFile)

	plaintext := "E2E TLS sync — " + time.Now().Format(time.RFC3339Nano)
	ciphertextFile := encryptMessage(t, bins.Age, bins.Plugin, relayRecipient, plaintext, tmpDir)
	decrypted := decryptMessage(t, bins.Age, bins.Plugin, relayIdentityStr, ciphertextFile, configFile)
	if decrypted != plaintext {
		t.Fatalf("plaintext mismatch:\n  want: %q\n  got:  %q", plaintext, decrypted)
	}
}

// TestE2EMTLSSync tests the sync flow with mutual TLS.
func TestE2EMTLSSync(t *testing.T) {
	bins := buildAllBinaries(t)
	tmpDir := t.TempDir()

	remoteKeyFile := filepath.Join(tmpDir, "remote.key")
	run(t, bins.AgeKeygen, "-o", remoteKeyFile)
	remotePubKey := extractPublicKey(t, remoteKeyFile)

	// Generate CA, server cert, client cert.
	caKey, caCert, caCertPEM := generateCA(t, tmpDir)
	serverCertFile, serverKeyFile := generateServerCert(t, tmpDir, caKey, caCert)
	clientCertFile, clientKeyFile := generateClientCert(t, tmpDir, caKey, caCert)
	caCertFile := filepath.Join(tmpDir, "ca.crt")
	os.WriteFile(caCertFile, caCertPEM, 0644)

	port := freePort(t)
	relayURL := fmt.Sprintf("https://127.0.0.1:%d", port)
	// Server requires client certs (mTLS via -tls-ca).
	startServer(t, bins.RelayServer, remoteKeyFile, port, "-tls-cert", serverCertFile, "-tls-key", serverKeyFile, "-tls-ca", caCertFile)

	// With client cert → should succeed.
	configFile := writeRelayConfig(t, tmpDir, "mtls-sync", relayURL, remotePubKey, map[string]string{
		"timeout":  "10s",
		"tls_ca":   caCertFile,
		"tls_cert": clientCertFile,
		"tls_key":  clientKeyFile,
	})
	relayRecipient, relayIdentityStr := generateRelayKeys(t, bins.Plugin, remotePubKey, "mtls-sync", configFile)

	plaintext := "E2E mTLS sync — " + time.Now().Format(time.RFC3339Nano)
	ciphertextFile := encryptMessage(t, bins.Age, bins.Plugin, relayRecipient, plaintext, tmpDir)
	decrypted := decryptMessage(t, bins.Age, bins.Plugin, relayIdentityStr, ciphertextFile, configFile)
	if decrypted != plaintext {
		t.Fatalf("plaintext mismatch:\n  want: %q\n  got:  %q", plaintext, decrypted)
	}

	// Without client cert → should fail.
	noCertDir := filepath.Join(tmpDir, "nocert")
	os.MkdirAll(noCertDir, 0755)
	noCertConfig := writeRelayConfig(t, noCertDir, "mtls-sync", relayURL, remotePubKey, map[string]string{
		"timeout": "5s",
		"tls_ca":  caCertFile,
	})
	output := decryptMessageExpectFailure(t, bins.Age, bins.Plugin, relayIdentityStr, ciphertextFile, noCertConfig)
	t.Logf("Expected mTLS failure: %s", strings.TrimSpace(output))
}

// ── TLS Certificate Helpers ─────────────────────────────────────────────────

func generateCA(t *testing.T, tmpDir string) (*ecdsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatal(err)
	}

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	return caKey, caCert, caCertPEM
}

func generateServerCert(t *testing.T, tmpDir string, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) (certFile, keyFile string) {
	t.Helper()
	return generateCert(t, tmpDir, "server", caKey, caCert, x509.ExtKeyUsageServerAuth)
}

func generateClientCert(t *testing.T, tmpDir string, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) (certFile, keyFile string) {
	t.Helper()
	return generateCert(t, tmpDir, "client", caKey, caCert, x509.ExtKeyUsageClientAuth)
}

func generateCert(t *testing.T, tmpDir, name string, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, usage x509.ExtKeyUsage) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test " + name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certFile = filepath.Join(tmpDir, name+".crt")
	keyFile = filepath.Join(tmpDir, name+".key")
	os.WriteFile(certFile, certPEM, 0644)
	os.WriteFile(keyFile, keyPEM, 0600)
	return
}
