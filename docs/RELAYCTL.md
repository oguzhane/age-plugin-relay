# relayctl.sh — CLI Reference

Operational CLI tool for `age-plugin-relay`. Manages keys, services, and encrypt/decrypt workflows for both sync and async relay flows.

```
./relayctl.sh <command> [options]
```

---

## Key Management

### `keygen`

Generate a new X25519 key pair and save it to the workspace.

```bash
./relayctl.sh keygen
```

Output:
- `workspace/identity.txt` (or `identity-N.txt` if the file already exists)

Prints the public key and suggests the next step.

---

### `generate`

Generate a relay recipient (for encryption) and relay identity (for decryption) from an inner recipient.

```bash
./relayctl.sh generate --recipient <age1...> --remote <name> [--config <relay-config.yaml>]
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
./relayctl.sh tag --recipient <age1...>
```

The tag is `base64(SHA256(recipient)[:16])` — the same value the plugin embeds in relay stanzas.

---

## Services

All services run as background daemons. PID files and logs are stored in the workspace directory.

### `server`

Manage the relay-server (sync flow — holds an age identity and unwraps stanzas directly).

```bash
./relayctl.sh server start --identity <file> [options]
./relayctl.sh server stop
./relayctl.sh server status
./relayctl.sh server logs [N]
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
./relayctl.sh broker start [options]
./relayctl.sh broker stop
./relayctl.sh broker status
./relayctl.sh broker logs [N]
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
./relayctl.sh operator start --broker <url> --identity <file> --tag <tag> [options]
./relayctl.sh operator run --broker <url> --identity <file> --tag <tag> [options]
./relayctl.sh operator stop
./relayctl.sh operator status
./relayctl.sh operator logs [N]
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

Use `./relayctl.sh tag --recipient <age1...>` to compute the tag for a recipient.

---

## Encrypt / Decrypt

### `encrypt`

Encrypt data using a relay recipient. Reads from stdin or a file, writes to stdout or a file.

```bash
echo "secret" | ./relayctl.sh encrypt -r <age1relay1...> -o secret.age
./relayctl.sh encrypt -r <age1relay1...> -i plaintext.txt -o secret.age
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
./relayctl.sh decrypt -i workspace/relay-identity.txt -f secret.age
./relayctl.sh decrypt -i relay-id.txt -f secret.age --config relay-config.yaml -o plaintext.txt
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
./relayctl.sh status
```

### `stop`

Stop all running services (operator, broker, server).

```bash
./relayctl.sh stop
```

### `clean`

Stop all services and remove the workspace directory.

```bash
./relayctl.sh clean
```

### `build`

Build all Go binaries (plugin, server, broker, operator). Binaries that are missing are auto-built on first use; this command forces a rebuild.

```bash
./relayctl.sh build
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

### Sync Flow Walkthrough

Encrypt and decrypt through a relay-server that holds the identity directly.

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

Encrypt and decrypt through a broker + operator. The operator can run on a different machine.

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

### With Authentication

```bash
./relayctl.sh server start --identity keys.txt --auth-token my-secret-token
# Config must include: auth_token: my-secret-token
```

### With TLS

```bash
./relayctl.sh server start --identity keys.txt \
  --tls-cert server.crt --tls-key server.key

# With mTLS (client certificates required):
./relayctl.sh server start --identity keys.txt \
  --tls-cert server.crt --tls-key server.key --tls-ca ca.crt
# Config must include: tls_cert, tls_key, tls_ca
```
