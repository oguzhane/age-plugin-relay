# age-plugin-relay

An [age](https://age-encryption.org) plugin that decouples the **location** of age identities from the encryption/decryption process. It acts as a router — any age identity (X25519, YubiKey, hybrid PQ, or other plugins) can be used remotely through an HTTP relay endpoint.

All payloads are encrypted end-to-end. The broker/relay sees only opaque ciphertext and routing metadata.

## Install

```bash
go build -o age-plugin-relay ./cmd/age-plugin-relay/
go build -o relay-server ./cmd/relay-server/        # optional: sync relay server
go build -o relay-broker ./cmd/relay-broker/        # optional: async broker
go build -o relay-operator ./cmd/relay-operator/    # optional: async operator
```

Place the binary in your `PATH` so `age` can discover it:

```bash
cp age-plugin-relay /usr/local/bin/
# or
export PATH="/path/to/age-plugin-relay:$PATH"
```

## Usage

### Generate a relay recipient and identity

```bash
age-plugin-relay --generate \
  --inner-recipient "age1abc..." \
  --remote myserver
```

Config mode produces short identity strings and supports per-remote TLS, timeout, and `unwrap_recipient`. See [Config File](#config-file) below.

Output:

```
# Relay recipient (for encryption — add to .sops.yaml or age -r):
#   Inner: age1abc...
age1relay1q...

# Relay identity (for decryption — add to identity file):
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

The plugin builds an encrypted payload containing the stanzas and an ephemeral key, sends it to the relay endpoint, and decrypts the sealed response to recover the file key.

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

## Config File

Create a `relay-config.yaml`:

```yaml
# relay-config.yaml
remotes:
  myserver:
    url: https://relay.example:8443/unwrap         # required
    unwrap_recipient: age1abc...                    # required: age recipient of the unwrapper
    tls_cert: /path/to/client.crt                  # optional (mTLS)
    tls_key: /path/to/client.key                   # optional (mTLS)
    tls_ca: /path/to/ca.crt                        # optional (custom CA)
    timeout: 5m                                    # optional (default: 5m)
    stream: true                                   # optional (SSE for long-running requests)
    auth_token: my-bearer-token                    # optional (Bearer token for simple auth)

  backup:
    url: https://backup.example:9999/unwrap
    unwrap_recipient: age1def...
```

The plugin looks for the config file at:
1. `AGE_PLUGIN_RELAY_CONFIG` env var (if set)
2. `$PWD/relay-config.yaml`

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `AGE_PLUGIN_RELAY_CONFIG` | `$PWD/relay-config.yaml` | Path to config file |
| `AGE_PLUGIN_RELAY_TIMEOUT` | `5m` | HTTP timeout (fallback if not set per-remote). Supports Go duration format. |
| `AGE_PLUGIN_RELAY_TLS_CERT` | — | Client TLS certificate (fallback if not set per-remote) |
| `AGE_PLUGIN_RELAY_TLS_KEY` | — | Client TLS private key (fallback if not set per-remote) |
| `AGE_PLUGIN_RELAY_TLS_CA` | — | CA certificate for server verification (fallback if not set per-remote) |
| `AGE_PLUGIN_RELAY_AUTH_TOKEN` | — | Bearer token for relay server auth (fallback if not set per-remote) |

## Authentication

### Bearer Token

A shared token sent as `Authorization: Bearer <token>`. Quick to set up.

```yaml
# relay-config.yaml
remotes:
  myserver:
    url: https://relay.example:8443/unwrap
    unwrap_recipient: age1abc...
    auth_token: my-secret-token
```

Server: `relay-server -identity keys.txt -auth-token my-secret-token`

## Architecture & Design

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the complete technical reference, including:

- Wire protocol and encrypted payload format
- Data model (recipient, identity, stanza formats)
- Sync and async (broker) flows
- Security model and threat analysis
- Relay server, broker, and operator configuration
- Code architecture and test matrix
