# relayctl — CLI Reference

Operational CLI tool for `age-plugin-relay`. Manages keys, services, and encrypt/decrypt workflows for both sync and async relay flows.

```
relayctl <command> [options]
```

---

## Key Management

### `keygen`

Generate a new X25519 key pair and save it to the workspace.

```bash
relayctl keygen
```

Output:
- `workspace/identity.txt` (or `identity-N.txt` if the file already exists)

Prints the public key and suggests the next step.

---

### `generate`

Generate a relay recipient (for encryption) and relay identity (for decryption) from an inner recipient.

```bash
relayctl generate --recipient <age1...> --remote <name> [--config <relay-config.yaml>]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--recipient`, `-r` | Yes | Inner age recipient (e.g., `age1...`) |
| `--remote` | Yes | Remote name from `relay-config.yaml` |
| `--config` | No | Path to `relay-config.yaml` |

Output:
- `workspace/relay-recipient.txt`
- `workspace/relay-identity.txt`

---

### `tag`

Compute the routing tag for a recipient. The tag is used by the operator to filter which intents to pull from the broker.

```bash
relayctl tag --recipient <age1...>
```

The tag is `base64(SHA256(recipient)[:16])` — the same value the plugin embeds in relay stanzas.

---

## Services

All services run as background daemons. PID files and logs are stored in the workspace directory.

### `server`

Manage the relay-server (sync flow — holds an age identity and unwraps stanzas directly).

```bash
relayctl server start --identity <file> [options]
relayctl server stop
relayctl server status
relayctl server logs [N]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--identity`, `-i` | — | Age identity file (required) |
| `--port`, `-p` | `19876` | Listen port |
| `--auth-token` | — | Bearer token for authentication |
| `--tls-cert` | — | TLS certificate file |
| `--tls-key` | — | TLS private key file |
| `--tls-ca` | — | CA certificate (enables mTLS) |

---

### `broker`

Manage the relay-broker (async flow — zero-trust queue, holds no key material).

```bash
relayctl broker start [options]
relayctl broker stop
relayctl broker status
relayctl broker logs [N]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--port`, `-p` | `8443` | Listen port |
| `--auth-token` | — | Bearer token for authentication |
| `--max-ttl` | `10m` | Maximum intent time-to-live |

---

### `operator`

Manage the relay-operator (async flow — polls the broker, holds the age identity, fulfills/rejects intents).

```bash
relayctl operator start --broker <url> --identity <file> --tag <tag> [options]
relayctl operator run --broker <url> --identity <file> --tag <tag> [options]
relayctl operator stop
relayctl operator status
relayctl operator logs [N]
```

- `start` — runs the operator as a background daemon with `--loop` (continuous polling)
- `run` — runs the operator in one-shot mode (foreground, pulls once, exits)

| Flag | Default | Description |
|------|---------|-------------|
| `--broker` | — | Broker URL (required) |
| `--identity`, `-i` | — | Age identity file (required) |
| `--tag` | — | Routing tag to filter intents (required) |
| `--auth-token` | — | Bearer token for broker access |
| `--pull-interval` | `5s` | How often to poll the broker (daemon mode only) |
| `--loop` | off | Run as continuous daemon (used internally by `start`) |

Use `relayctl tag --recipient <age1...>` to compute the tag for a recipient.

---

## Encrypt / Decrypt

### `encrypt`

Encrypt data using a relay recipient. Reads from stdin or a file, writes to stdout or a file.

```bash
echo "secret" | relayctl encrypt -r <age1relay1...> -o secret.age
relayctl encrypt -r <age1relay1...> -i plaintext.txt -o secret.age
```

| Flag | Description |
|------|-------------|
| `-r`, `--recipient` | Relay recipient string (required) |
| `-i`, `--input` | Input file (default: stdin) |
| `-o`, `--output` | Output file (default: stdout) |

---

### `decrypt`

Decrypt data using a relay identity. Requires a running relay-server (sync) or broker+operator (async).

```bash
relayctl decrypt -i workspace/relay-identity.txt -f secret.age
relayctl decrypt -i relay-id.txt -f secret.age --config relay-config.yaml -o plaintext.txt
```

| Flag | Description |
|------|-------------|
| `-i`, `--identity` | Relay identity file (required) |
| `-f`, `--file` | Ciphertext file (default: stdin) |
| `-o`, `--output` | Output file (default: stdout) |
| `--config` | Path to `relay-config.yaml` |

Config auto-discovery order:
1. `--config` flag
2. `AGE_PLUGIN_RELAY_CONFIG` environment variable
3. `workspace/relay-config.yaml` (if it exists)

---

## Utilities

### `status`

Show all running services at a glance.

```bash
relayctl status
```

### `stop`

Stop all running services (operator, broker, server).

```bash
relayctl stop
```

### `clean`

Stop all services and remove the workspace directory.

```bash
relayctl clean
```

### `build`

Build all Go binaries (plugin, server, broker, operator). Binaries that are missing are auto-built on first use; this command forces a rebuild.

```bash
relayctl build
```

---

## Environment

| Variable | Description |
|----------|-------------|
| `RELAYCTL_WORKSPACE` | Workspace directory (default: `./workspace`) |
| `AGE_PLUGIN_RELAY_CONFIG` | Path to `relay-config.yaml` (overrides auto-discovery) |

---

## Workspace Layout

```
workspace/
├── identity.txt              # X25519 key pair (from keygen)
├── relay-recipient.txt       # Relay recipient (from generate)
├── relay-identity.txt        # Relay identity (from generate)
├── relay-config.yaml         # User-created config file
├── relay-server.pid          # Server PID
├── relay-server.log          # Server log
├── relay-broker.pid          # Broker PID
├── relay-broker.log          # Broker log
├── relay-operator.pid        # Operator PID
└── relay-operator.log        # Operator log
```

---

## Examples

### Sync Flow

Encrypt and decrypt through a relay-server that holds the identity directly.

```bash
# 1. Generate keys
relayctl keygen
PUBKEY=$(grep "public key:" workspace/identity.txt | awk '{print $NF}')

# 2. Create config
cat > workspace/relay-config.yaml <<EOF
remotes:
  local:
    url: http://127.0.0.1:19876
    unwrap_recipient: ${PUBKEY}
    timeout: 10s
EOF

# 3. Generate relay recipient + identity
relayctl generate -r "$PUBKEY" --remote local --config workspace/relay-config.yaml

# 4. Start relay-server
relayctl server start --identity workspace/identity.txt

# 5. Encrypt + decrypt
echo "hello world" | relayctl encrypt -r "$(cat workspace/relay-recipient.txt)" -o secret.age
relayctl decrypt -i workspace/relay-identity.txt -f secret.age

# 6. Cleanup
relayctl server stop
```

### Async Flow

Encrypt and decrypt through a broker + operator. The operator can run on a different machine.

```bash
# 1. Generate keys
relayctl keygen
PUBKEY=$(grep "public key:" workspace/identity.txt | awk '{print $NF}')
TAG=$(relayctl tag -r "$PUBKEY" 2>&1 | grep "Tag:" | awk '{print $NF}')

# 2. Create config pointing at the broker
cat > workspace/relay-config.yaml <<EOF
remotes:
  mybroker:
    url: http://127.0.0.1:8443
    unwrap_recipient: ${PUBKEY}
    timeout: 15s
    poll_interval: 500ms
EOF

# 3. Generate relay recipient + identity
relayctl generate -r "$PUBKEY" --remote mybroker --config workspace/relay-config.yaml

# 4. Start broker + operator
relayctl broker start --port 8443
relayctl operator start \
  --broker http://127.0.0.1:8443 \
  --identity workspace/identity.txt \
  --tag "$TAG" \
  --pull-interval 500ms

# One-shot: pull once and exit
relayctl operator run \
  --broker http://127.0.0.1:8443 \
  --identity workspace/identity.txt \
  --tag "$TAG"

# 5. Encrypt + decrypt (plugin → broker → operator → broker → plugin)
echo "async secret" | relayctl encrypt -r "$(cat workspace/relay-recipient.txt)" -o secret.age
relayctl decrypt -i workspace/relay-identity.txt -f secret.age

# 6. Cleanup
relayctl stop
```

### With Authentication

```bash
relayctl server start --identity keys.txt --auth-token my-secret-token
# Config must include: auth_token: my-secret-token
```

### With TLS

```bash
relayctl server start --identity keys.txt \
  --tls-cert server.crt --tls-key server.key

# With mTLS (client certificates required):
relayctl server start --identity keys.txt \
  --tls-cert server.crt --tls-key server.key --tls-ca ca.crt
# Config must include: tls_cert, tls_key, tls_ca
```
