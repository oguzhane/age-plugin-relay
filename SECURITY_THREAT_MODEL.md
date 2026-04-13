# Security Threat Model Analysis: `age-plugin-relay`

**Date:** 2026-04-13  
**Repository:** [oguzhane/age-plugin-relay](https://github.com/oguzhane/age-plugin-relay)  
**Scope:** Full codebase — all Go source files, shell scripts, configuration, and dependencies

---

## Overview

`age-plugin-relay` is a Go-based [age encryption](https://age-encryption.org) plugin that decouples key material from encryption/decryption operations. During **encryption**, the plugin wraps file keys using an inner recipient's public key and tags the resulting stanzas as `relay`. During **decryption**, it forwards the encrypted stanzas over HTTP(S) to a remote relay endpoint that performs the actual unwrapping with the private key.

The codebase is compact: ~600 lines across 6 source files, plus a reference relay server (~160 lines), a test suite, and a test shell script.

---

## Architecture & Data Flow

### Sensitive Data Lifecycle

**Encryption path (offline):**

```
age1relay1<bech32(inner_recipient_str)>
  → NewRelayRecipient() parses inner recipient string from Bech32 payload
  → inner.Wrap(fileKey) delegates to age (X25519/HPKE/plugin)
  → stanza is re-tagged as "relay", inner type+args promoted to relay args
  → file key material never leaves the host; all crypto is local
```

**Decryption path (online):**

```
AGE-PLUGIN-RELAY-1<bech32(4-byte tag || target)>
  → NewRelayIdentity() decodes tag + target (URL or remote name)
  → identity.Unwrap() matches stanzas by tag, reconstructs inner stanza
  → PostToRelay() sends inner stanzas over HTTP/HTTPS
  → relay endpoint performs unwrap, returns 16-byte file key
  → file key received in JSON/SSE response, decoded from base64
  → file key returned to age for stream decryption
```

**Key observation:** The file key (16 bytes) travels over the network during decryption. It is the only cryptographic material exposed over the wire. No private key material is present in the plugin binary or identity string.

---

## Risk Summary

| # | Finding | Severity | Location |
|---|---|---|---|
| 3.1 | Reference relay-server transmits file key in plaintext HTTP | **Critical** | `cmd/relay-server/main.go:124` |
| 3.2 | Silent TLS failure — mTLS/CA silently disabled on error | **High** | `relay/client.go:239–256` |
| 7.1 | No authentication on relay server (unauthenticated decryption oracle) | **High** | `cmd/relay-server/main.go:55–127` |
| 7.2 | Replay attack — no request nonce, deterministic stanzas reusable | **Medium** | `relay/client.go:45–85` |
| 2.1 | 4-byte tag collision — DoS and misdirected decryption | **Medium** | `relay/encoding.go:14–17` |
| 3.5 | SSE response has no byte/event limit — resource exhaustion | **Medium** | `relay/client.go:129–186` |
| 4.1 | Config loaded from CWD — path injection via untrusted directory | **Medium** | `relay/config.go:53–56` |
| 6.1 | File key not zeroed after use in client | **Medium** | `relay/client.go:110–114` |
| 6.2 | Private key logged to stdout in test.sh | **Medium** | `test.sh:105` |
| 3.3 | No minimum TLS version configured | **Medium** | `relay/client.go:229` |
| 3.4 | No auth token in relay protocol | **Medium** | Protocol design |
| 3.6 | HTTP URLs accepted without warning | **Low** | `relay/identity.go:42` |
| 4.2 | Relay error messages echoed verbatim (injection) | **Low** | `relay/client.go:97–107` |
| 4.3 | Full HTTP error body in error messages | **Low** | `relay/client.go:99` |
| 9.1 | Relay URL embedded in legacy identity (disclosure) | **Low** | `relay/identity.go:42–44` |
| 7.3 | Protocol version not validated by server | **Low** | `cmd/relay-server/main.go:79` |
| 10.1 | No CI/CD, no automated security scanning | **Medium** | Repository-wide |
| 10.2 | Hardcoded port in test.sh | **Low** | `test.sh:35` |

---

## 1. Cryptographic Implementation

### 1.1 [MEDIUM] 4-Byte Tag Collision Risk

**File:** `relay/encoding.go:14–17`

```go
func ComputeTag(innerRecipient string) [4]byte {
    h := sha256.Sum256([]byte(innerRecipient))
    return [4]byte(h[:4])
}
```

Only 4 bytes (32 bits) of SHA-256 output are used as a routing tag. The birthday bound for 50% collision probability is ~2^16 (~65,000) distinct recipients. While collisions do not enable decryption of another recipient's data (the relay server's `identity.Unwrap()` would fail), they can:

- Cause the wrong relay identity to attempt (and fail) to unwrap stanzas, resulting in silent decryption failure (`age.ErrIncorrectIdentity` is swallowed after failing all identities)
- Serve as a targeted DoS: an adversary who can control an inner recipient string can create a collision forcing relay requests to an unintended endpoint

**Recommendation:** Increase the tag to at least 16 bytes (128 bits) to make collisions infeasible.

### 1.2 [POSITIVE] No Cryptographic Primitives Implemented Directly

All actual cryptographic operations (X25519 key exchange, HPKE, ChaCha20-Poly1305, Argon2id for passphrase, HMAC, nonce generation) are fully delegated to `filippo.io/age v1.3.1`. The plugin itself does no raw cryptography beyond SHA-256 tag computation. This is architecturally sound.

### 1.3 [POSITIVE] No Hardcoded Keys or Weak Randomness

Tests use `crypto/rand` for file key generation (`relay_test.go:85`, `relay_test.go:274`). No hardcoded keys, static nonces, or seeded pseudorandom generators were found.

---

## 2. Network / Transport Security

### 2.1 [CRITICAL] Reference Relay Server Defaults to Plaintext HTTP

**File:** `cmd/relay-server/main.go:124`

```go
if err := http.ListenAndServe(addr, nil); err != nil {
```

The reference `relay-server` only supports HTTP. The 16-byte file key is returned in the JSON response body in cleartext. Any network observer on the path between the plugin client and the relay server can recover the file key and decrypt the ciphertext. This is the highest-impact finding.

The README acknowledges this as a "minimal test server," but a reference implementation that transmits key material in plaintext normalizes insecure usage. There is no TLS support at all in the server binary.

**Recommendation:** The relay-server should support TLS (and preferably mTLS) at minimum, or include prominent warnings in the output about HTTP being insecure.

### 2.2 [HIGH] Silent TLS Failure — Security Silently Downgraded

**File:** `relay/client.go:239–243`, `relay/client.go:250–256`

```go
cert, err := tls.LoadX509KeyPair(certFile, keyFile)
if err == nil {
    tlsConfig.Certificates = []tls.Certificate{cert}
}
// ...
caCert, err := os.ReadFile(caFile)
if err == nil {
    pool := x509.NewCertPool()
    pool.AppendCertsFromPEM(caCert)
    tlsConfig.RootCAs = pool
}
```

If TLS cert/key files are specified (in config or env) but cannot be loaded (permissions error, missing file, wrong format), the error is silently swallowed and the connection proceeds:

- Without client certificate → mTLS silently disabled, relay server accepts anonymous clients
- Without custom CA → system root CAs used instead of the intended CA, allowing relay endpoint substitution with any publicly trusted certificate

An operator who configured mTLS and then accidentally breaks the cert/key path will have no indication that mTLS is no longer active.

**Recommendation:** Log warnings and optionally fail-closed when configured TLS files cannot be loaded.

### 2.3 [MEDIUM] No TLS Minimum Version Configured

**File:** `relay/client.go:229`

```go
tlsConfig := &tls.Config{}
```

No minimum TLS version is set. Go's default (TLS 1.0+) is more permissive than modern security baselines require. While Go's TLS stack is generally well-maintained, explicitly requiring TLS 1.2 or 1.3 would be safer.

**Recommendation:** Set `tlsConfig.MinVersion = tls.VersionTLS12` (or `tls.VersionTLS13`).

### 2.4 [MEDIUM] No Authentication on Relay Server

**File:** `cmd/relay-server/main.go:55–127`

The reference relay server accepts decryption requests from any client without any authentication. It acts as an unauthenticated decryption oracle for any network-reachable party. Mitigations mentioned in the README (mTLS, network controls) are not enforced by default. The plugin client also does not send any authentication token with requests. Protocol version (`"version": 1`) is sent but not validated by the server (`relay-server` doesn't check `req.Version`).

### 2.5 [MEDIUM] SSE Response Has No Resource Bounds

**File:** `relay/client.go:129–186`

```go
scanner := bufio.NewScanner(r)
for scanner.Scan() {
    ...
}
```

The JSON response path is bounded to 64KB (`io.LimitReader(resp.Body, 1<<16)` at line 89). The SSE response reader has no equivalent bound. A malicious or compromised relay server could stream infinite heartbeat comments, keeping the goroutine alive until the HTTP timeout (default 5 minutes) expires. With many concurrent decryption requests, this becomes a resource exhaustion vector.

**Recommendation:** Add a total-bytes-read counter or event count limit to `readSSEResponse`.

### 2.6 [LOW] `http://` URLs Accepted Without Warning

**File:** `relay/identity.go:42`

```go
if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
    return RemoteConfig{URL: target}, nil
}
```

HTTP URLs are silently accepted in legacy mode with no warning. Users may not realize their file keys are transmitted in plaintext.

**Recommendation:** Emit a warning when `http://` is used (similar to the `warnIfPluginMissing` warning in the generate command).

---

## 3. Input Validation & Parsing

### 3.1 [MEDIUM] Config File Path Read from CWD by Default

**File:** `relay/config.go:53–56`

```go
path := os.Getenv("AGE_PLUGIN_RELAY_CONFIG")
if path == "" {
    path = DefaultConfigFile  // = "relay-config.yaml"
}
```

The config is loaded from the current working directory. If an attacker can place a `relay-config.yaml` in a directory from which the plugin is invoked (e.g., `/tmp`, a shared workspace), they could redirect relay requests to an attacker-controlled endpoint. Combined with a plaintext HTTP relay server, this would expose file keys.

**Recommendation:** Default to a fixed user-specific path (e.g., `$XDG_CONFIG_HOME/age-plugin-relay/config.yaml` or `~/.config/age-plugin-relay/config.yaml`) rather than `$PWD`.

### 3.2 [LOW] Relay Error Messages Echoed Verbatim

**File:** `relay/client.go:97–99`, `relay/client.go:107`

```go
return nil, fmt.Errorf("relay error (HTTP %d): %s", resp.StatusCode, relayResp.Error)
// ...
return nil, fmt.Errorf("relay error: %s", relayResp.Error)
```

The relay server's error string is inserted verbatim into the error message returned to the age client. A compromised or MITM relay server could inject arbitrary strings into error messages displayed to users (social engineering, confusion attacks).

### 3.3 [LOW] Full HTTP Error Body in Error Messages

**File:** `relay/client.go:99`

```go
return nil, fmt.Errorf("relay returned HTTP %d: %s", resp.StatusCode, respBody)
```

When the relay returns a non-OK status with non-JSON body, up to 64KB of raw HTTP response body is included in the error string. This could expose internal server information to the user (who passes it to debugging channels), or be used by a malicious server for injection.

### 3.4 [LOW] Stanza Args Not Validated Before Forwarding

**File:** `relay/identity.go:70–75`

```go
inner := &age.Stanza{
    Type: s.Args[1],
    Args: s.Args[2:],
    Body: s.Body,
}
```

The stanza `Type` and `Args` are taken directly from the age header without validation before being forwarded to the relay server. An attacker who can craft a malicious age ciphertext header could set `Type` to an arbitrary string. However, the relay server passes these to `identity.Unwrap()`, which validates them using the age library's type system, limiting exploitability.

---

## 4. Dependency Security

### Dependency Inventory

| Dependency | Version | Role |
|---|---|---|
| `filippo.io/age` | v1.3.1 | Core age types, recipient parsing, crypto |
| `filippo.io/hpke` | v0.4.0 | HPKE for hybrid PQ age (indirect) |
| `golang.org/x/crypto` | v0.45.0 | Low-level crypto (indirect via age) |
| `golang.org/x/sys` | v0.38.0 | OS interfaces (indirect) |
| `golang.org/x/term` | v0.37.0 | Terminal passphrase input (indirect) |
| `gopkg.in/yaml.v3` | v3.0.1 | Config file parsing |
| `c2sp.org/CCTV/age` | v0.0.0-20251208 | age test vectors (indirect) |

All direct dependencies appear to be current, well-maintained versions. No known CVEs were identified against these specific versions.

### 4.1 [NOTE] `go.mod` Declares `go 1.25.4`

**File:** `go.mod:3`

Go 1.25 does not exist at the time of this analysis. This is likely a future version, or an error. Future Go versions could include breaking changes to TLS defaults or security-relevant standard library behavior.

### 4.2 [MEDIUM] No Supply Chain Security Controls

No `.github/workflows/` directory was found. There is no:
- Automated `go vet`, `staticcheck`, or `govulncheck` execution
- Automated dependency vulnerability scanning
- SAST tooling (CodeQL, Semgrep)
- Signed releases or provenance attestation (SLSA)
- Renovate/Dependabot for dependency updates

---

## 5. Secret Management

### 5.1 [MEDIUM] File Key Not Zeroed After Use

**File:** `relay/client.go:110–114`, `cmd/relay-server/main.go:104`

```go
fileKey, err := base64.RawStdEncoding.DecodeString(relayResp.FileKey)
// ...
return fileKey, nil
```

The 16-byte file key is returned as a plain `[]byte` from `PostToRelay`. There is no explicit zeroing before the slice is GC'd. In Go, memory zeroing is non-trivial due to GC, but `filippo.io/age` itself typically uses secure erasure patterns for key material.

**Recommendation:** Use `clear(fileKey)` after the file key has been consumed.

### 5.2 [MEDIUM] Private Key Logged to Stdout in test.sh

**File:** `test.sh:105`

```bash
echo "  Private key: $(grep "^AGE-SECRET-KEY-" "$REMOTE_IDENTITY")"
```

The age X25519 private key (`AGE-SECRET-KEY-1...`) is explicitly printed to stdout during step 1. In CI/CD environments, this would be captured in build logs and retained indefinitely.

**Recommendation:** Remove or redact private key output from the test script.

### 5.3 [LOW] Identity File Loaded Into Memory for Server Lifetime

**File:** `cmd/relay-server/main.go:130–137`

Age private keys remain in memory for the entire relay server lifetime. There is no credential rotation, memory locking (`mlock`), or secure erasure on shutdown. In a high-security environment, a process memory dump exposes private keys.

### 5.4 [POSITIVE] No Sensitive Data in Logs

The relay server logs only counts and types, not key material:

```go
fmt.Fprintf(os.Stderr, "[relay-server] Unwrap succeeded, returning file key\n")
// the actual fileKey is NOT logged
```

---

## 6. Authentication & Authorization

### 6.1 [HIGH] No Mutual Authentication by Default

The HTTP relay protocol has no bearer tokens, API keys, request signing, or mandatory mTLS. The relay server is a completely unauthenticated decryption oracle accessible to anyone who can reach its network address.

The README positions mTLS as a recommended mitigation, but:
- It is not configured by default
- The reference server does not support TLS at all
- Silent TLS failures (§2.2) mean a broken mTLS config degrades to no authentication without warning

### 6.2 [MEDIUM] Replay Attack — No Request Nonce or Timestamp

The relay protocol (`RelayRequest`) contains `version`, `action`, and `stanzas`, but no request nonce, timestamp, or HMAC. A network observer who captures a relay request can replay it indefinitely to obtain the file key again.

Since age stanzas are deterministic (the encrypted file key for a given recipient is fixed in the ciphertext), the relay request will always be the same for a given encrypted file. An attacker who captures one successful relay request can replay it to obtain the file key without any valid cryptographic identity.

**Recommendation:** Add a per-request nonce or timestamp, validated by the relay server within a time window, to prevent replay attacks.

### 6.3 [LOW] Protocol Version Not Enforced

**File:** `cmd/relay-server/main.go:79`

```go
if req.Action != "unwrap" {
    writeJSON(w, http.StatusBadRequest, relay.RelayResponse{Error: "unsupported action: " + req.Action})
    return
}
```

The server checks `Action` but ignores `Version`. Future protocol changes that are version-dependent cannot be enforced, potentially causing silent incompatibilities.

---

## 7. Error Handling

### 7.1 [LOW] Error Messages from Relay Forwarded to Users

As noted in §3.2, relay server error messages (which may contain internal state from the remote system) propagate through `fmt.Errorf` chains and surface to the user as age decryption errors. An attacker controlling a relay endpoint could craft error messages to confuse users.

### 7.2 [POSITIVE] JSON Body Size Limits

The JSON response path correctly limits responses to 64KB:

```go
io.LimitReader(resp.Body, 1<<16)
```

This prevents memory exhaustion from oversized relay responses in the JSON path (but see §2.5 for the SSE gap).

---

## 8. Configuration Security

### 8.1 [LOW] Legacy Mode Embeds Relay URL in Identity String

**File:** `relay/identity.go:42–44`

In legacy mode, the relay URL is embedded inside the Bech32-encoded identity string. The README suggests the identity "contains no key material" and is safe to commit. However:

- The relay endpoint URL is exposed to anyone with the identity file
- If `http://` is used, it confirms to observers that the relay uses plaintext HTTP
- The URL cannot be changed without regenerating the identity (and re-encrypting all files)

### 8.2 [LOW] TLS Key File Path from Environment Variables

**File:** `relay/client.go:233–238`

TLS private key file paths are read from environment variables (`AGE_PLUGIN_RELAY_TLS_KEY`). In environments where environment variables are logged (some cloud platforms, `/proc/self/environ` accessible to other users), these paths are exposed. The key files themselves are not in environment variables (good), just their paths.

---

## 9. Build & Supply Chain

### 9.1 [MEDIUM] No CI/CD or Automated Security Workflows

No `.github/workflows/` directory was found in the repository. There is no:
- Automated `go vet`, `staticcheck`, or `govulncheck` execution
- Automated dependency vulnerability scanning
- SAST tooling (CodeQL, Semgrep)
- Signed releases or provenance attestation (SLSA)
- Renovate/Dependabot for dependency updates

### 9.2 [LOW] Hardcoded Port in test.sh

**File:** `test.sh:35`

```bash
RELAY_PORT=19876
```

A fixed port in the test script can conflict with other services on the host. The Go integration tests (`e2e_test.go:314–323`) correctly use ephemeral ports via `net.Listen("tcp", "127.0.0.1:0")` — the shell test should do the same.

### 9.3 [LOW] No Race Condition Tests

The codebase has no `go test -race` configuration. The relay server handles HTTP requests concurrently, and `loadIdentities` is called once at startup — there's no obvious concurrent mutation, but explicit race detection in CI would give stronger guarantees.

---

## Appendix: README Threat Model Comparison

The README includes a basic threat model table:

| Scenario | Impact |
|---|---|
| Plugin binary compromised | Attacker could redirect relay URL, but still needs the remote identity to unwrap |
| Relay URL intercepted (no TLS) | Attacker sees encrypted stanzas (useless without identity) and file key (one Shamir share if using key groups) |
| mTLS cert stolen | Attacker can talk to relay, but relay still requires the actual identity to unwrap |
| Relay endpoint compromised | Attacker gets file keys — mitigated by using SOPS key groups (need both shares) |
| Both relay + server compromised | Need physical access to all identity holders (geographic separation with YubiKeys) |

This analysis **extends** the README's threat model with the following gaps not addressed there:

1. The reference relay server has **no TLS support**, making "Relay URL intercepted (no TLS)" the default scenario rather than an edge case.
2. **Silent TLS failures** mean the mTLS mitigation can silently disappear without operator awareness.
3. **Replay attacks** are not addressed: a captured relay request grants permanent decryption capability, not just one-time access.
4. **4-byte tag collisions** can cause DoS and routing confusion.
5. **CWD-based config loading** creates a path injection vector not mentioned.
