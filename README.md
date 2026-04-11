# age-plugin-relay

An [age](https://age-encryption.org) plugin that decouples the **location** of age identities from the encryption/decryption process. It acts as a router — any age identity (X25519, YubiKey, hybrid PQ, or other plugins) can be used remotely through an HTTP relay endpoint.

## How It Works

```
ENCRYPTION (offline — no relay needed)        DECRYPTION (online — relay required)

  age1relay1<inner_recipient>                   AGE-PLUGIN-RELAY-1<tag + target>
    |                                             |
    v                                             v
  Extract inner recipient string                Receive relay stanzas from age header
    |                                             |
    v                                             v
  age.ParseRecipients() -> Wrap()               Match stanzas by tag, reconstruct inner stanzas
    |                                             |
    v                                             v
  Re-tag stanza: X25519 -> relay                Resolve target (URL or remote name from config)
    |                                             |
    v                                             v
  Done. No network. Identity-agnostic.          HTTP POST inner stanzas -> file key returned
```

**Encryption** uses only the inner recipient's public key — no relay, no network, no hardware. The plugin delegates to `age.ParseRecipients()`, so it works with any recipient type the `age` library (or plugins in `PATH`) can parse.

**Decryption** forwards the encrypted stanzas to a relay endpoint over HTTP(S). What serves that endpoint is not the plugin's concern — it could be a simple agent, a gateway with an approval UI, a serverless function, etc.

## Install

```bash
go build -o age-plugin-relay ./cmd/age-plugin-relay/
go build -o relay-server ./cmd/relay-server/        # optional: test relay server
```

Place the binary in your `PATH` so `age` can discover it:

```bash
cp age-plugin-relay /usr/local/bin/
# or
export PATH="/path/to/age-plugin-relay:$PATH"
```

## Usage

### Generate a relay recipient and identity

**Legacy mode** (URL embedded in identity):

```bash
age-plugin-relay --generate \
  --inner-recipient "age1abc..." \
  --relay-url "https://relay.example:8443/unwrap"
```

**Config mode** (remote name, resolved from `relay-config.yaml`):

```bash
age-plugin-relay --generate \
  --inner-recipient "age1abc..." \
  --remote myserver
```

Config mode produces shorter identity strings and supports per-remote TLS and timeout. See [Config File](#config-file) below.

Output:

```
# Relay recipient (for encryption — add to .sops.yaml or age -r):
#   Inner: age1abc...
#   Relay: https://relay.example:8443/unwrap
age1relay1q...

# Relay identity (for decryption — add to identity file):
#   Relay: https://relay.example:8443/unwrap
AGE-PLUGIN-RELAY-1...
```

The inner recipient can be any age recipient type:

| Inner type | Example | Plugin needed in PATH? |
|---|---|---|
| X25519 | `age1abc...` | No (native) |
| Hybrid PQ | `age1pq1...` | No (native, age v1.3+) |
| YubiKey P-256 | `age1yubikey1q...` | Yes: `age-plugin-yubikey` |
| Any plugin | `age1NAME1...` | Yes: `age-plugin-NAME` |

If the inner recipient requires a plugin that is not in `PATH`, `--generate` prints a warning but proceeds.

### Encrypt

```bash
echo "secret" | age -r "age1relay1q..." -o secret.age
```

This wraps the file key using the inner recipient's public key and tags the stanza as `relay`. No network or relay endpoint is contacted.

### Decrypt

```bash
age -d -i identities.txt secret.age
```

Where `identities.txt` contains:

```
AGE-PLUGIN-RELAY-1...
```

The plugin sends the encrypted stanzas to the relay URL and returns the unwrapped file key.

### Use with SOPS key groups

SOPS [key groups](https://github.com/getsops/sops#key-groups) use Shamir's Secret Sharing to require multiple keys for decryption. Combine a local key with a relayed remote key:

```yaml
# .sops.yaml
creation_rules:
  - path_regex: \.enc\.yaml$
    key_groups:
      - age:
          - age1yubikey1q...    # Group 1: local YubiKey on server
      - age:
          - age1relay1q...      # Group 2: relayed to remote identity
    shamir_threshold: 2         # BOTH groups required
```

Identity file on the server:

```
# Group 1: local YubiKey
AGE-PLUGIN-YUBIKEY-1...

# Group 2: relay to remote
AGE-PLUGIN-RELAY-1...
```

SOPS splits the data encryption key into 2 Shamir shares. Group 1 is decrypted locally. Group 2 is forwarded through the relay plugin to the remote endpoint.

## Data Model

### Recipient: `age1relay1<bech32(inner_recipient_string)>`

The Bech32 data payload is the UTF-8 bytes of the inner age recipient string. The plugin extracts it, calls `age.ParseRecipients()`, and delegates `Wrap()` to the parsed recipient.

### Identity: `AGE-PLUGIN-RELAY-1<bech32(tag || target)>`

The target is either a full URL (legacy) or a remote name (config mode).

| Field | Size | Description |
|---|---|---|
| `tag` | 4 bytes | `SHA-256(inner_recipient_string)[:4]` — matches stanzas to this identity |
| `target` | variable | URL (`https://...`) or remote name (`myserver`) |

Not secret. Contains no key material — only routing information. Safe to commit to version control.

At decrypt time, the plugin detects the target type:
- Starts with `http://` or `https://` → use as relay URL directly (legacy)
- Anything else → look up in `relay-config.yaml` (config mode)

### Stanza format

```
-> relay <tag_b64> <inner_type> [inner_args...]
<body>
```

Example with an X25519 inner recipient:

```
-> relay QPg24g X25519 CKTwCgeHBEBFmdC7GJSffbto8y+8G8iPHhTeMnhxIg4
X0e7a90Lzp8lnpGBH7JdWnpW+WcH61T4obAXzVHa6N8
```

| Argument | Description |
|---|---|
| `QPg24g` | Base64-encoded 4-byte tag (for routing) |
| `X25519` | Original inner stanza type |
| `CKTw...` | Original inner stanza arguments (passed through) |

On decryption the plugin strips `relay` and the tag, reconstructs the original inner stanza, and forwards it to the relay endpoint.

## Relay Endpoint HTTP Contract

The plugin POSTs to the relay URL during decryption. What serves that URL is entirely decoupled from the plugin. The URL is opaque to the plugin — the intent is conveyed by the `action` field in the payload.

### Request

```http
POST / HTTP/1.1
Content-Type: application/json

{
  "version": 1,
  "action": "unwrap",
  "stanzas": [
    {
      "type": "X25519",
      "args": ["CKTwCgeHBEBFmdC7GJSffbto8y+8G8iPHhTeMnhxIg4"],
      "body": "X0e7a90Lzp8lnpGBH7JdWnpW+WcH61T4obAXzVHa6N8"
    }
  ]
}
```

- `version`: Protocol version (currently `1`).
- `action`: The operation to perform. Currently only `"unwrap"` is defined.
- `stanzas`: Array of inner stanzas with the relay wrapping stripped. The `body` field is base64 raw standard encoded.

### Response

**Success (200):**

```json
{
  "file_key": "dGVzdGtleS4uLi4uLi4u"
}
```

`file_key` is the 16-byte age file key, base64 raw standard encoded.

**Errors:**

| HTTP Status | Body | Meaning |
|---|---|---|
| 404 | `{"error": "no_matching_identity"}` | No identity can unwrap these stanzas |
| 408 | `{"error": "timeout"}` | Identity interaction timed out (e.g., YubiKey not touched) |
| 503 | `{"error": "unavailable"}` | Relay can't reach the identity |

## Config File

For managing multiple remotes with per-remote TLS and timeout, create a `relay-config.yaml`:

```yaml
# relay-config.yaml
remotes:
  myserver:
    url: https://relay.example:8443/unwrap         # required
    tls_cert: /path/to/client.crt                  # optional (mTLS)
    tls_key: /path/to/client.key                   # optional (mTLS)
    tls_ca: /path/to/ca.crt                        # optional (custom CA)
    timeout: 5m                                    # optional (default: 5m)

  backup:
    url: https://backup.example:9999/unwrap
```

The plugin looks for the config file at:
1. `AGE_PLUGIN_RELAY_CONFIG` env var (if set)
2. `$PWD/relay-config.yaml`

Config is optional — URL-based identities work without any config file.

### Resolution priority at decrypt time

Per-remote config takes priority over environment variables:

| Setting | Priority |
|---|---|
| TLS cert/key/CA | Remote config > env var (`AGE_PLUGIN_RELAY_TLS_*`) |
| Timeout | Remote config > env var (`AGE_PLUGIN_RELAY_TIMEOUT`) > default 5m |

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `AGE_PLUGIN_RELAY_CONFIG` | `$PWD/relay-config.yaml` | Path to config file |
| `AGE_PLUGIN_RELAY_TIMEOUT` | `5m` | HTTP timeout (fallback if not set per-remote). Supports Go duration format. |
| `AGE_PLUGIN_RELAY_TLS_CERT` | — | Client TLS certificate (fallback if not set per-remote) |
| `AGE_PLUGIN_RELAY_TLS_KEY` | — | Client TLS private key (fallback if not set per-remote) |
| `AGE_PLUGIN_RELAY_TLS_CA` | — | CA certificate for server verification (fallback if not set per-remote) |

## Architecture

```
age-plugin-relay/
├── relay/                              # Importable library (package relay)
│   ├── encoding.go                     # ComputeTag, EncodeRelayRecipient, EncodeRelayIdentity
│   ├── errors.go                       # Sentinel errors
│   ├── recipient.go                    # RelayRecipient, NewRelayRecipient, Wrap
│   ├── identity.go                     # RelayIdentity, NewRelayIdentity, Unwrap, ResolveRemote
│   ├── client.go                       # RelayRequest/Response/Stanza, PostToRelay, HTTP client
│   ├── config.go                       # Config, RemoteConfig, LoadConfig, LookupRemote
│   ├── relay_test.go                   # 7 unit tests
│   ├── integration_test.go             # 6 integration tests (mock relay, config, errors)
│   └── e2e_test.go                     # 2 E2E tests (real binaries, full user flow)
├── cmd/
│   ├── age-plugin-relay/
│   │   └── main.go                     # Plugin binary: flags, --generate, HandleRecipient/Identity
│   └── relay-server/
│       └── main.go                     # Minimal relay HTTP server (imports relay package)
├── test.sh                             # Step-by-step CLI integration test
└── README.md
```

### Dependencies

- [`filippo.io/age`](https://pkg.go.dev/filippo.io/age) v1.3.1 — age types (`Recipient`, `Identity`, `Stanza`), recipient parsing
- [`filippo.io/age/plugin`](https://pkg.go.dev/filippo.io/age/plugin) — Plugin framework, Bech32 encoding helpers
- [`gopkg.in/yaml.v3`](https://pkg.go.dev/gopkg.in/yaml.v3) — Config file parsing

## Testing

### Unit tests

```bash
go test -v ./relay/
```

| Test | What it validates |
|---|---|
| `TestComputeTagDeterministic` | Same input always produces same 4-byte tag |
| `TestComputeTagDifferent` | Different inputs produce different tags |
| `TestEncodeDecodeRecipient` | `age1relay1...` round-trips through Bech32 encode/decode |
| `TestEncodeDecodeIdentity` | `AGE-PLUGIN-RELAY-1...` round-trips with tag and target preserved |
| `TestWrapProducesRelayStanzas` | `Wrap()` produces stanzas with type `relay`, correct tag, inner type `X25519` |
| `TestEndToEndWithMockRelay` | Full flow: generate key pair, wrap via relay, mock HTTP server unwraps, file key matches |
| `TestUnwrapNoMatchingStanza` | Non-matching stanzas return `age.ErrIncorrectIdentity` |

### Integration tests

| Test | What it validates |
|---|---|
| `TestIntegrationLegacyURL` | Full `age.Encrypt` → `age.Decrypt` with URL in identity |
| `TestIntegrationConfigMode` | Full encrypt/decrypt with remote name resolved from config |
| `TestIntegrationConfigMissingRemote` | Clear error for non-existent remote (lists available) |
| `TestIntegrationNoConfigFile` | URL-based identities work without any config file |
| `TestIntegrationRelayServerDown` | Clean error when relay endpoint unreachable |
| `TestIntegrationWrongIdentity` | Clean error when relay has wrong key |

### E2E tests

| Test | What it validates |
|---|---|
| `TestE2ELegacyURL` | Full user flow with real `age` + `age-keygen` + plugin + relay-server binaries (URL mode) |
| `TestE2EConfigMode` | Same with config file: shorter identity, `--remote` flag, env var for config path |

### Integration test (CLI)

The integration test uses the `age` CLI binary, the plugin binary, and a minimal `relay-server` to test the full encrypt → relay → decrypt flow.

```bash
# Run all steps at once:
./test.sh

# Or step by step (artifacts in tmp/ for inspection):
./test.sh 1    # Generate remote X25519 key pair        → tmp/remote-identity.txt
./test.sh 2    # Generate relay recipient + identity     → tmp/relay-recipient.txt, tmp/relay-identity.txt
./test.sh 3    # Start relay-server on :19876            → tmp/relay-server.pid, tmp/relay-server.log
./test.sh 4    # Encrypt via relay recipient             → tmp/plaintext.txt, tmp/secret.age
./test.sh 5    # Decrypt via relay identity (HTTP POST)  → tmp/decrypted.txt
./test.sh 6    # Verify plaintext matches

# Clean up:
./test.sh clean
```

The `relay-server` (`cmd/relay-server/main.go`) is a minimal HTTP server that:
1. Loads an age identity file (X25519 private key)
2. Serves `POST /unwrap` — deserializes stanzas, calls `identity.Unwrap()`, returns the file key
3. Implements the same JSON contract the plugin expects

In production, the relay endpoint could be anything — an approval gateway, a WebSocket relay agent, a serverless function, etc.

## Security Properties

- **Encryption is offline** — uses only the inner recipient's public key. No network, no relay, no hardware.
- **No secrets in the plugin** — the recipient contains only a public key string; the identity contains only a tag and URL.
- **File key (16 bytes) travels over HTTPS** — use TLS/mTLS for transport security.
- **With SOPS key groups + Shamir** — intercepting one group's unwrapped share is information-theoretically useless without the other share(s).
- **Relay endpoint is the trust boundary** — it holds the actual private key or identity. The plugin itself holds no key material.

## Threat Model

| Scenario | Impact |
|---|---|
| Plugin binary compromised | Attacker could redirect relay URL, but still needs the remote identity to unwrap |
| Relay URL intercepted (no TLS) | Attacker sees encrypted stanzas (useless without identity) and file key (one Shamir share if using key groups) |
| mTLS cert stolen | Attacker can talk to relay, but relay still requires the actual identity to unwrap |
| Relay endpoint compromised | Attacker gets file keys — mitigated by using SOPS key groups (need both shares) |
| Both relay + server compromised | Need physical access to all identity holders (geographic separation with YubiKeys) |
