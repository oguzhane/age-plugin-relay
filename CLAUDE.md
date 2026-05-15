# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

age-plugin-relay is a Go plugin for [age encryption](https://age-encryption.org) that decouples identities from encryption/decryption by relaying unwrap operations to a remote server. It supports two modes: **sync** (direct HTTP relay) and **async** (broker + operator with intent queue).

## Build Commands

```bash
go build -o bin/age-plugin-relay ./cmd/age-plugin-relay/
go build -o bin/relay-server ./cmd/relay-server/
go build -o bin/relay-broker ./cmd/relay-broker/
go build -o bin/relay-operator ./cmd/relay-operator/
# Or use relayctl:
./relayctl.sh build
```

## Test Commands

```bash
go test ./...                                        # all tests
go test ./relay -v                                   # relay package tests
go test ./relay/broker -v                            # broker tests
go test ./relay -run TestGenerateIntentIDFormat -v   # single test
go test ./relay -run 'TestE2E' -v                    # E2E tests (sync, async, TLS, errors)
```

## Architecture

### Binaries (all in `cmd/`)
- **age-plugin-relay** — The age plugin binary. Handles `--generate` for key creation and the age plugin protocol for wrap/unwrap.
- **relay-server** — Sync relay that unwraps stanzas using a local identity.
- **relay-broker** — Async message broker storing intents in an in-memory queue with TTL.
- **relay-operator** — Async operator that polls the broker, unwraps, and fulfills intents.

### Core Package (`relay/`)
All binaries share this package:
- **client.go** — HTTP client, intent ID generation, relay request/response handling
- **recipient.go** — Parses `age1relay1<bech32(inner_recipient)>` recipients
- **identity.go** — Parses `AGE-PLUGIN-RELAY-1<bech32(tag||target)>` identities, resolves remote config
- **payload.go** — Encrypted payload (inner/outer layers) with outer hash binding for tamper detection
- **claim.go** — Ed25519 intent claim signing/verification for async authorization
- **envelope.go** — Codec for converting between age stanzas and relay wire format
- **config.go** — Loads `relay-config.yaml` (per-remote: url, unwrap_recipient, TLS, auth)
- **broker/queue.go** — In-memory intent queue with TTL sweep

### Encryption Design
- End-to-end age encryption between plugin and operator (broker is blind)
- Outer hash binding detects tampering of routing fields
- Ed25519 intent claims prevent fabricated async actions

### Two Modes
- **Sync**: Plugin → HTTP POST → Relay Server (unwraps locally) → response
- **Async**: Plugin → POST intent → Broker (stores) → Operator (polls, unwraps, fulfills) → Plugin GETs response

## Configuration

- **relay-config.yaml** — YAML with per-remote settings (url, unwrap_recipient, TLS, auth tokens)
- `AGE_PLUGIN_RELAY_CONFIG` — Config file path (default: `$PWD/relay-config.yaml`)
- `AGE_PLUGIN_RELAY_TIMEOUT` — HTTP timeout (default: 5m)
- `AGE_PLUGIN_RELAY_TLS_CERT/TLS_KEY/TLS_CA` — mTLS client credentials
- `AGE_PLUGIN_RELAY_AUTH_TOKEN` — Bearer token for relay auth

## Dependencies

- `filippo.io/age v1.3.1` — Core age library
- `gopkg.in/yaml.v3` — YAML config parsing
