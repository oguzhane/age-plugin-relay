# age-plugin-relay

**Decrypt age data from anywhere.**

An [age](https://age-encryption.org) plugin that relays decryption requests to a remote server over HTTP. The private key never leaves the remote machine. All payloads are encrypted end-to-end — the relay infrastructure sees only opaque ciphertext and routing metadata.

Works with any age identity: X25519, YubiKey, hybrid post-quantum, or other plugins.

## Why

Encrypting with age is offline — you only need the recipient's public key. But decryption requires the private key, and that key might live on another machine, inside a hardware token locked in a safe, or behind a policy gate.

age-plugin-relay bridges this gap. It wraps age's standard plugin protocol around an HTTP relay, so decryption works transparently even when the identity is somewhere else. The key never moves. The relay never sees plaintext.

## How It Works

age-plugin-relay supports two modes:

### Sync — direct relay

```
age -d ──► age-plugin-relay ──► relay-server ──► unwrap with local identity
                                     │
                                     ◄──────────── return file key (encrypted)
```

The plugin sends an encrypted unwrap request directly to a `relay-server`, which holds the identity file locally. The server decrypts the payload, unwraps the stanzas, and returns the file key — all encrypted end-to-end.

**Use sync when** the identity is always reachable and you want the simplest setup.

### Async — broker + operator

```
age -d ──► age-plugin-relay ──► broker (stores intent)
                                   │
                            operator (polls) ──► unwrap with local identity
                                   │
           age-plugin-relay ◄── broker (returns result)
```

The plugin posts an intent to a `relay-broker`. A `relay-operator` polls the broker, decrypts and unwraps the stanzas, and fulfills the intent. The plugin polls until the result is ready.

**Use async when** the identity holder is intermittently connected, behind a firewall, or you want a human-in-the-loop approval step.

## Quick Start

### Prerequisites

- [Go](https://go.dev) 1.21+
- [age](https://age-encryption.org) CLI

### Build

```bash
./relayctl.sh build
```

Or build individually:

```bash
go build -o bin/age-plugin-relay ./cmd/age-plugin-relay/
go build -o bin/relay-server ./cmd/relay-server/
go build -o bin/relay-broker ./cmd/relay-broker/
go build -o bin/relay-operator ./cmd/relay-operator/
```

Place the plugin binary in your `PATH` so age can discover it:

```bash
cp bin/age-plugin-relay /usr/local/bin/
```

### Generate keys

```bash
# Generate a standard age key pair (the "inner" identity)
age-keygen -o identity.txt
# => created: age1abc...

# Generate a relay recipient + identity pointing to a remote
age-plugin-relay -generate \
  -inner-recipient "age1abc..." \
  -remote myserver
```

Output:

```
# Relay recipient (for encryption):
#   Inner: age1abc...
age1relay1q...

# Relay identity (for decryption):
AGE-PLUGIN-RELAY-1...
```

### Start the relay server

```bash
bin/relay-server -identity identity.txt -addr :9876
```

### Encrypt and decrypt

```bash
# Encrypt (offline — no server needed)
echo "secret data" | age -r "age1relay1q..." -o secret.age

# Decrypt (contacts the relay server)
age -d -i relay-identity.txt secret.age
```

## Supported Inner Recipients

The inner recipient can be any age recipient type:

| Type | Example | Plugin needed? |
|------|---------|----------------|
| X25519 | `age1abc...` | No (native) |
| Hybrid PQ | `age1pq1...` | No (native, age v1.3+) |
| YubiKey P-256 | `age1yubikey1q...` | Yes: `age-plugin-yubikey` |
| Any plugin | `age1NAME1...` | Yes: `age-plugin-NAME` |

## Configuration

Create a `relay-config.yaml` to define named remotes:

```yaml
remotes:
  myserver:
    url: https://relay.example:8443/unwrap      # required
    unwrap_recipient: age1abc...                 # required: recipient of the unwrapper
    tls_cert: /path/to/client.crt               # optional: mTLS client cert
    tls_key: /path/to/client.key                # optional: mTLS client key
    tls_ca: /path/to/ca.crt                     # optional: custom CA
    timeout: 5m                                  # optional (default: 5m)
    auth_token: my-bearer-token                  # optional: Bearer token
```

**Config discovery order:**

1. `AGE_PLUGIN_RELAY_CONFIG` environment variable
2. `$PWD/relay-config.yaml`

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AGE_PLUGIN_RELAY_CONFIG` | `$PWD/relay-config.yaml` | Config file path |
| `AGE_PLUGIN_RELAY_TIMEOUT` | `5m` | HTTP timeout (Go duration format) |
| `AGE_PLUGIN_RELAY_TLS_CERT` | — | Client TLS certificate (fallback) |
| `AGE_PLUGIN_RELAY_TLS_KEY` | — | Client TLS private key (fallback) |
| `AGE_PLUGIN_RELAY_TLS_CA` | — | CA certificate for verification (fallback) |
| `AGE_PLUGIN_RELAY_AUTH_TOKEN` | — | Bearer token (fallback) |

Per-remote config values take priority over environment variables.

## Authentication

### Bearer Token

Set `auth_token` in the config file or the `AGE_PLUGIN_RELAY_AUTH_TOKEN` env var. The token is sent as `Authorization: Bearer <token>`.

Server side: `relay-server -identity keys.txt -auth-token my-secret-token`

### Mutual TLS

Set `tls_cert`, `tls_key`, and `tls_ca` per-remote in the config file, or use the corresponding `AGE_PLUGIN_RELAY_TLS_*` env vars.

Server side: `relay-server -identity keys.txt -tls-cert server.crt -tls-key server.key -tls-ca ca.crt`

## relayctl CLI

`relayctl.sh` is a convenience wrapper for managing keys, services, and encrypt/decrypt workflows.

| Command | Description |
|---------|-------------|
| `relayctl.sh build` | Build all binaries |
| `relayctl.sh keygen` | Generate an age key pair |
| `relayctl.sh generate --recipient <r> --remote <name>` | Generate relay recipient + identity |
| `relayctl.sh server start\|stop\|status\|logs` | Manage the relay server |
| `relayctl.sh broker start\|stop\|status\|logs` | Manage the broker |
| `relayctl.sh operator start\|run\|stop\|status\|logs` | Manage the operator |
| `relayctl.sh encrypt -r <recipient> [-i infile] [-o outfile]` | Encrypt a file |
| `relayctl.sh decrypt -i <identity> [-f ciphertext] [-o outfile]` | Decrypt a file |
| `relayctl.sh status` | Show all running services |
| `relayctl.sh stop` | Stop all services |
| `relayctl.sh clean` | Remove workspace and stop services |

See [docs/RELAYCTL.md](docs/RELAYCTL.md) for the full reference.

### Sync Flow Walkthrough

```bash
# 1. Build all binaries
./relayctl.sh build

# 2. Generate an age key pair (the server-side identity)
./relayctl.sh keygen
# => Public key:  age1abc...
# => Identity:    workspace/identity.txt

# 3. Create relay-config.yaml pointing to the relay server
cat > relay-config.yaml <<EOF
remotes:
  my-server:
    url: http://127.0.0.1:19876
    unwrap_recipient: age1abc...
EOF

# 4. Generate relay recipient + identity
./relayctl.sh generate --recipient age1abc... --remote my-server
# => Relay recipient: age1relay1...
# => Relay identity:  AGE-PLUGIN-RELAY-1...

# 5. Start the relay server
./relayctl.sh server start --identity workspace/identity.txt

# 6. Encrypt a message (no server needed)
echo "hello relay" | ./relayctl.sh encrypt -r age1relay1... -o workspace/secret.age

# 7. Decrypt (contacts the relay server)
./relayctl.sh decrypt -i workspace/relay-identity.txt -f workspace/secret.age --config relay-config.yaml
# => hello relay

# 8. Clean up
./relayctl.sh stop && ./relayctl.sh clean
```

### Async Flow Walkthrough

```bash
# 1. Build all binaries
./relayctl.sh build

# 2. Generate an age key pair (the operator-side identity)
./relayctl.sh keygen
# => Public key:  age1abc...
# => Identity:    workspace/identity.txt

# 3. Create relay-config.yaml pointing to the broker
cat > relay-config.yaml <<EOF
remotes:
  async-test:
    url: http://127.0.0.1:8443
    unwrap_recipient: age1abc...
    mode: async
EOF

# 4. Generate relay recipient + identity
./relayctl.sh generate --recipient age1abc... --remote async-test
# => Relay recipient: age1relay1...
# => Relay identity:  AGE-PLUGIN-RELAY-1...

# 5. Start the broker
./relayctl.sh broker start

# 6. Encrypt a message
echo "hello async relay" | ./relayctl.sh encrypt -r age1relay1... -o workspace/secret.age

# 7. Decrypt (posts intent to broker, then waits for operator)
./relayctl.sh decrypt -i workspace/relay-identity.txt -f workspace/secret.age --config relay-config.yaml &

# 8. Get the routing tag and run the operator one-shot
./relayctl.sh tag --recipient age1abc...
# => Tag: ZZnBS3j6P3TOWCrPMO/YGA

./relayctl.sh operator run \
  --broker http://127.0.0.1:8443 \
  --identity workspace/identity.txt \
  --tag ZZnBS3j6P3TOWCrPMO/YGA
# => ✓ Operator completed

# The decrypt command returns:
# => hello async relay

# 9. Clean up
./relayctl.sh stop && ./relayctl.sh clean
```

## Architecture & Security

- **End-to-end encryption**: All payloads are encrypted with `age.Encrypt`/`age.Decrypt`. The broker never sees plaintext.
- **Outer hash binding**: SHA-256 binds the encrypted payload to all cleartext routing fields, detecting any tampering.
- **Intent claims**: Per-intent Ed25519 signatures prevent fabricated fulfill/reject actions in async mode.
- **Forward secrecy**: Fresh ephemeral keys are generated per decryption request.
- **Transport-independent**: Security does not depend on TLS — payloads are safe over plaintext HTTP.

For the complete technical reference — wire formats, threat model, sequence diagrams — see:

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/INTENT-CLAIM.md](docs/INTENT-CLAIM.md)
- [docs/SYNC-WIRE-FORMAT.md](docs/SYNC-WIRE-FORMAT.md)
- [docs/ASYNC-WIRE-FORMAT.md](docs/ASYNC-WIRE-FORMAT.md)

## Development

```bash
# Build all binaries
go build -o bin/age-plugin-relay ./cmd/age-plugin-relay/
go build -o bin/relay-server ./cmd/relay-server/
go build -o bin/relay-broker ./cmd/relay-broker/
go build -o bin/relay-operator ./cmd/relay-operator/

# Run all tests
go test ./...

# Run specific test suites
go test ./relay -v                              # core package
go test ./relay/broker -v                       # broker queue
go test ./relay -run 'TestE2E' -v               # end-to-end tests
```

### Project Structure

```
cmd/
├── age-plugin-relay/   # age plugin binary (--generate, wrap/unwrap)
├── relay-server/       # sync relay server
├── relay-broker/       # async message broker
└── relay-operator/     # async operator (polls + unwraps)
relay/                  # core library (client, config, crypto, encoding)
├── broker/             # in-memory intent queue
docs/                   # architecture, wire formats, CLI reference
```
