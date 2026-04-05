# LP2LN — Layered Peer-to-Peer Network

Decentralized P2P networking stack in Rust: encrypted transport, peer discovery, optional HTTP gateway on the classic stack, and a **v2** node runtime focused on TCP/UDP transports and a structured node model.

---

## Contents

- [Overview](#overview)
- [Workspace layout](#workspace-layout)
- [Crates](#crates)
- [Requirements](#requirements)
- [Build](#build)
- [Run](#run)
  - [`lp2lnd` (v2 node)](#lp2lnd-v2-node)
  - [`lp2ln-gateway` (HTTP + legacy core)](#lp2ln-gateway-http--legacy-core)
  - [`lp2ln-db-export`](#lp2ln-db-export)
- [Configuration](#configuration)
- [Development](#development)
- [License](#license)

---

## Overview

| Area | Notes |
|------|--------|
| **Networking** | Async I/O (Tokio), TCP/UDP transports in v2; STUN client usage in core crates |
| **Crypto** | ECDH/ECDSA (k256), ChaCha20-Poly1305, SHA-256 |
| **Storage** | Embedded [redb](https://github.com/cberner/redb) databases where enabled |
| **Contracts** | WASM build target for on-chain-style modules (see `contracts/readme.md`) |

This repository is a **Cargo workspace**. There is no single root `src/main.rs`; binaries live under `crates/`.

---

## Workspace layout

```
P2P-Server/
├── Cargo.toml              # workspace manifest
├── config.toml             # used by lp2ln-gateway (signal server, storage, proxy)
├── LICENSE
├── crates/
│   ├── lp2ln-core/         # original library (peer, signal, HTTP pieces, wasmtime, …)
│   ├── lp2ln-core-v2/      # v2 library (node runtime, transports, DB tables, …)
│   ├── lp2ln-gateway/      # binary: P2P + HTTP proxy/API on lp2ln-core
│   ├── lp2lnd/             # binary: v2 node daemon (lp2ln-core-v2)
│   └── lp2ln-db-export/    # binary: export redb / node DB to JSON
├── contracts/              # WASM contract build notes
├── tools/                  # e.g. topology-viewer (Python)
└── vscode-extension/       # editor extension (see vscode-extension/README.md)
```

---

## Crates

| Crate | Role |
|-------|------|
| **lp2ln-core-v2** | Library: `NodeBuilder`, `NodeOptions`, TCP/UDP transports, logging, peer scoring, `P2PDatabase` / storage tables. **MSRV:** Rust **1.81** (see `Cargo.toml`). |
| **lp2lnd** | Default entry point for the v2 stack. Loads `options.json` (or path from CLI), starts the node, waits for Ctrl+C. Optional binary: `lp2lnd-scale` (`scale_daemon.rs`). Optional feature: `tokio-console` (needs `RUSTFLAGS="--cfg tokio_unstable"`). |
| **lp2ln-core** | Original integrated library used by the gateway (peer, connection manager, tunnels, WASM runtime, etc.). |
| **lp2ln-gateway** | Standalone daemon: reads `config.toml` from the **current working directory**, opens `./gateway_storage`, runs HTTP proxy/API over the P2P layer. |
| **lp2ln-db-export** | CLI to dump node `redb` data to JSON (`-h` for usage). Default build includes file-picker support via the `pick` feature. |

---

## Requirements

- **Rust** toolchain matching workspace **1.81+** (as declared in crate manifests).
- **Gateway only:** a valid `config.toml` in the process working directory (repository root already contains an example).
- **WASM contracts:** `rustup target add wasm32-unknown-unknown` (see `contracts/readme.md`).

---

## Build

From the repository root:

```bash
cargo build --workspace
```

Release binaries:

```bash
cargo build --workspace --release
```

Run tests:

```bash
cargo test --workspace
```

---

## Run

### `lp2lnd` (v2 node)

```bash
cargo run -p lp2lnd --release
```

- If `./options.json` exists in the current directory, it is loaded automatically.
- Otherwise you can pass a file explicitly:

```bash
cargo run -p lp2lnd --release -- --options path/to/options.json
# short form:
cargo run -p lp2lnd --release -- -o path/to/options.json
```

Example option files ship under `crates/lp2lnd/` (e.g. `options-client.json`, `options-bootstrap-*.json`) and `crates/lp2ln-core-v2/options.json`. The on-disk format is JSON; fields include `listens`, `default_nodes`, `bootstrap_nodes`, `database_dir`, `logger_options`, `peer_connection_policy`, and others (see `NodeOptions` / `NodeOptionsFile` in `crates/lp2ln-core-v2/src/node/options.rs`).

Logs: when file logging is enabled, output typically goes under `./logs/` (see `logger_options` in your JSON).

Secondary binary (same package):

```bash
cargo run -p lp2lnd --bin lp2lnd-scale --release
```

### `lp2ln-gateway` (HTTP + legacy core)

Run from a directory that contains `config.toml` (e.g. clone root):

```bash
cargo run -p lp2ln-gateway --release
```

`config.toml` keys include `signal_server_ip`, `signal_server_port`, `storage_size`, `proxy_ip`, and `proxy_port`.

### `lp2ln-db-export`

```bash
cargo run -p lp2ln-db-export --release -- --help
```

Point it at a redb `db` file or a node data directory that contains `db`.

---

## Configuration

| Component | File | Format |
|-----------|------|--------|
| **lp2lnd** / v2 node | `options.json` (or path via `-o`/`--options`) | JSON |
| **lp2ln-gateway** | `config.toml` | TOML |

---

## Development

- **v2 node logic:** `crates/lp2ln-core-v2/src/` (notably `node/`, `transport/`, `db/`).
- **Gateway + legacy peer path:** `crates/lp2ln-core/src/` and `crates/lp2ln-gateway/src/`.
- **Docker:** a `Dockerfile` exists at the repository root but targets an older single-binary layout (`P2P-Server`, `start.sh`). Expect to adapt it if you want container builds for the current workspace outputs (`target/release/lp2lnd`, `lp2ln-gateway`, etc.).

---

## License

See the [`LICENSE`](LICENSE) file in this repository.
