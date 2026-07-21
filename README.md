# LP2LN — Layered Peer-to-Peer Network

[![MSRV](https://img.shields.io/badge/Rust-1.85%2B-93450a?logo=rust)](https://www.rust-lang.org/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/krusalovorg/lp2ln)

Decentralized P2P networking stack in Rust. The **current direction** is **`lp2ln-core-v2`**: a flat network where **peers are equal** (no special coordinator role) and **no signal servers are required**—bootstrap and discovery follow the new node model. Legacy components were moved out to dedicated repositories (see [Related repositories](#related-repositories)).

**Wiki:** [https://deepwiki.com/krusalovorg/lp2ln](https://deepwiki.com/krusalovorg/lp2ln)

---

## Contents

- [Documentation (Wiki)](#documentation-wiki)
- [Related repositories](#related-repositories)
- [Overview](#overview)
- [Workspace layout](#workspace-layout)
- [Crates](#crates)
- [Requirements](#requirements)
- [Build](#build)
- [Using `lp2ln-core-v2` as a library](#using-lp2ln-core-v2-as-a-library)
- [Run](#run)
  - [`lp2lnd` (v2 node)](#lp2lnd-v2-node)
  - [`lp2ln-updater` (supervisor)](#lp2ln-updater-supervisor)
  - [`lp2ln-magic-folder`](#lp2ln-magic-folder)
  - [`lp2ln-release-tool`](#lp2ln-release-tool)
  - [`debug-ui` (web debug interface)](#debug-ui-web-debug-interface)
  - [`lp2ln-db-export`](#lp2ln-db-export)
- [Configuration](#configuration)
- [Development](#development)
- [Validation and tests](#validation-and-tests)
- [Why AGPL + Commercial Licensing?](#why-agpl--commercial-licensing)
- [License](#license)

---

## Documentation (Wiki)

Architecture and deeper explanations for this project are on DeepWiki:

[https://deepwiki.com/krusalovorg/lp2ln](https://deepwiki.com/krusalovorg/lp2ln)

Additional local docs:

- `lp2lnd` usage: [`crates/lp2lnd/README.md`](crates/lp2lnd/README.md)
- `lp2lnd` configuration guide: [`crates/lp2lnd/CONFIGURATION.md`](crates/lp2lnd/CONFIGURATION.md)

---

## Related repositories

- Browser wallet extension (moved from this repo): [https://github.com/krusalovorg/lp2ln-browser-extension](https://github.com/krusalovorg/lp2ln-browser-extension)
- Legacy code and historical stack: [https://github.com/krusalovorg/lp2ln-legacy](https://github.com/krusalovorg/lp2ln-legacy)
- VS Code extension (moved from this repo): [https://github.com/krusalovorg/lp2ln-vscode](https://github.com/krusalovorg/lp2ln-vscode)

---

## Overview

| Area | Notes |
|------|--------|
| **Stacks** | **v2 (`lp2ln-core-v2`):** egalitarian peers, no signal server in the runtime design—**main focus**. Legacy stack has been moved to a dedicated repository: [lp2ln-legacy](https://github.com/krusalovorg/lp2ln-legacy). |
| **Networking** | Async I/O (Tokio), TCP/UDP transports in v2, peer discovery/maintenance, health/debug auxiliary endpoints |
| **Crypto** | ECDH/ECDSA (k256), ChaCha20-Poly1305, SHA-256 |
| **Storage** | Embedded [redb](https://github.com/cberner/redb) databases where enabled |
| **Contracts** | WASM contract modules were moved to a dedicated repository; this workspace is focused on core/node crates |
| **App Plane** | Sidecar IPC layer: `lp2lnd` exposes a Unix socket (or dev TCP) App Plane server; sidecars use `lp2ln-app-sdk` to open typed channels without speaking the raw P2P protocol |
| **Content layer** | `lp2ln-content` — content-addressed, encrypted block storage (no networking). Used by `lp2ln-magic-folder` and future DHT/replication crates |
| **Updater** | `lp2ln-updater` supervises `lp2lnd` as a child process and rolls back atomically when a new binary fails health checks |
| **Debug tooling** | `debug-ui/` provides a React + Vite interface for packet/debug workflows; `lp2lnd` can expose a debug WebSocket stream |

This repository is a **Cargo workspace**. There is no single root `src/main.rs`; binaries live under `crates/`.

---

## Workspace layout

```
P2P-Server/
├── Cargo.toml              # workspace manifest
├── rust-toolchain.toml     # pins stable (needed for lp2ln-core-v2 edition 2024)
├── LICENSE
├── crates/
│   ├── lp2ln-core-v2/          # core library: equal peers, node runtime, transports, …
│   ├── lp2lnd/                 # binary: v2 node daemon
│   ├── lp2ln-db-export/        # binary: export redb / node DB to JSON
│   ├── lp2ln-app-protocol/     # library: App Plane wire protocol (sidecar ↔ daemon IPC)
│   ├── lp2ln-app-sdk/          # library: App Plane client SDK for sidecars
│   ├── lp2ln-content/          # library: content IDs, encryption, manifests, block store
│   ├── lp2ln-release/          # library + tool: release manifests, signing, packaging
│   ├── lp2ln-updater/          # binary: parent-process supervisor with atomic rollback
│   └── lp2ln-magic-folder/     # binary: encrypted sync folder (chunk → encrypt → DHT)
├── debug-ui/               # React + Vite debug interface
└── tools/                  # e.g. topology-viewer (Python)
```


---

## Crates

| Crate | Kind | Role |
|-------|------|------|
| **lp2ln-core-v2** | lib | Core P2P library. Flat topology — **all peers equal, no signal server**. `NodeBuilder`, `NodeOptions`, TCP/UDP transports, topology maintenance, event core, metrics/health, peer scoring, `P2PDatabase`. **MSRV:** Rust 1.85 (edition 2024). |
| **lp2lnd** | bin | Default node daemon. Transactional config load (`ConfigAutonomy`), last-known-good rollback, developer-defaults fallback, health endpoint, debug WebSocket. Extra binaries: `lp2lnd-scale` (multi-node scale runner). Feature: `tokio-console`. |
| **lp2ln-db-export** | bin | CLI to dump node `redb` data to JSON (`-h` for usage). |
| **lp2ln-app-protocol** | lib | App Plane wire protocol shared between daemon and sidecars: framing, commands, events, capabilities. Serialised with `postcard`. |
| **lp2ln-app-sdk** | lib | Async client SDK for App Plane sidecars. Wraps the protocol framing so sidecar authors work with typed commands/events instead of raw bytes. |
| **lp2ln-content** | lib | Pure content primitives: content-addressed IDs (`ContentId`), LZ4 per-chunk compression (before encryption), ChaCha20-Poly1305 chunk encryption, `FileManifest` / `DirectoryManifest`, `BlockStore` (redb-backed). No networking — composable building block. |
| **lp2ln-release** | lib + bin | Release manifest types, ECDSA (k256) signing, and the `lp2ln-release-tool` packaging binary for cutting signed releases. |
| **lp2ln-updater** | bin | Stable parent-process supervisor (`lp2ln-updater`). Watches a child binary, gates restarts on health checks, and performs atomic rollback if the new version fails to start healthy. |
| **lp2ln-magic-folder** | bin | Encrypted sync folder daemon (`lp2ln-magic-folder`). Poll-watches a directory, chunks and encrypts changed files via `lp2ln-content`, builds `FileManifest`/`DirectoryManifest`, persists state to redb. DHT announce and block replication land in a future milestone. |

---

## Requirements

- **Rust** toolchain **1.85+** for the workspace (`lp2ln-core-v2` uses **edition 2024**). The repo includes **`rust-toolchain.toml`** pinning **stable** so `rustup` selects a new enough toolchain in this directory.
- **Node.js + pnpm** for `debug-ui` (frontend debug interface).
- **Legacy stack and contracts:** moved to dedicated repositories (see [Related repositories](#related-repositories)).

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

## Using `lp2ln-core-v2` as a library

Add the crate to your `Cargo.toml` (path, git, or crates.io when published):

```toml
[dependencies]
lp2ln-core-v2 = { path = "../P2P-Server/crates/lp2ln-core-v2" }
tokio = { version = "1", features = ["macros", "rt-multi-thread", "signal"] }
anyhow = "1"
```

Minimal flow: **`NodeOptions`** → **`NodeBuilder`** (transports, optional `P2PDatabase`) → **`build`** → **`start`**. Shutdown with **`stop`**.

```rust
use lp2ln_core_v2::node::{NodeBuilder, NodeOptions};
use lp2ln_core_v2::peer_score::PeerConnectionPolicy;
use lp2ln_core_v2::transport::{tcp::TcpTransport, udp::UdpTransport};
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let options = NodeOptions::empty()
        .with_listen("tcp", "0.0.0.0:8080".parse()?)
        .with_listen("udp", "0.0.0.0:8080".parse()?)
        .with_default_nodes(vec![] /* bootstrap / initial peers */)
        .with_peer_connection_policy(PeerConnectionPolicy {
            min_active_peers: 2,
            target_active_peers: 4,
            max_active_peers: 8,
        })
        .allow_unsigned_packets(true)
        .keypair_generate();

    let mut node = NodeBuilder::new()
        .add_transport(Arc::new(TcpTransport::new()))
        .add_transport(Arc::new(UdpTransport::new()))
        // .db(Arc::new(lp2ln_core_v2::db::P2PDatabase::new("./data")?))
        .build(options)?;

    node.start().await?;
    tokio::signal::ctrl_c().await?;
    node.stop().await?;
    Ok(())
}
```

- **File-based config:** `let options = NodeOptions::from_file("options.json")?;` (same schema as `lp2lnd`).
- **Runnable example** in the repo: `cargo run -p lp2ln-core-v2 --example minimal_node` — source: [`crates/lp2ln-core-v2/examples/minimal_node.rs`](crates/lp2ln-core-v2/examples/minimal_node.rs).

---

## Run

### `lp2lnd` (v2 node)

Runs on **`lp2ln-core-v2`**: **egalitarian peers**, **no signal server**—configure bootstrap / discovery via `options.json` (see `bootstrap_nodes`, `default_nodes`, etc.).

Detailed docs:

- runtime usage: [`crates/lp2lnd/README.md`](crates/lp2lnd/README.md)
- config reference: [`crates/lp2lnd/CONFIGURATION.md`](crates/lp2lnd/CONFIGURATION.md)

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

Example option files ship under `crates/lp2lnd/` (e.g. `options-client.json`, `options-bootstrap-*.json`) and `crates/lp2ln-core-v2/options.json`. The on-disk format is JSON; fields include `listens`, `advertise_addrs`, `default_nodes`, `bootstrap_nodes`, `database_dir`, `logger_options`, `peer_connection_policy`, `node_role`, `topology_tuning`, `transport_obfuscation`, `flow_trace`, `debug_server`, and others (see `NodeOptions` / `NodeOptionsFile` in `crates/lp2ln-core-v2/src/node/options.rs`).

Logs: when file logging is enabled, output typically goes under `./logs/` (see `logger_options` in your JSON).

`lp2lnd` runtime behavior summary:

- config startup goes through transactional autonomy (`primary -> last-known-good -> developer defaults`);
- runtime starts a local health endpoint (`127.0.0.1:9088` by default, overridable via `LP2LND_HEALTH_ADDR`);
- if `debug_server.enabled` is true, debug WebSocket stream is started on configured address;
- if `database_dir` is missing, default is `./db`.

Secondary binary (same package):

```bash
cargo run -p lp2lnd --bin lp2lnd-scale --release
```

Scale mode docs:

- crate README: [`crates/lp2lnd/README.md`](crates/lp2lnd/README.md)
- supports `--virtual-peers`, `--from`, `--debug-base`, and related env vars for local large-node runs.

### `lp2ln-updater` (supervisor)

Wraps `lp2lnd` as a supervised child process. On update, the new binary must pass a health gate before the old one is retired; on failure it rolls back to the previous binary automatically.

```bash
cargo run -p lp2ln-updater --release -- --child target/release/lp2lnd
```

### `lp2ln-magic-folder`

Watches a local directory, chunks and encrypts changed files, and builds a content-addressed `DirectoryManifest` in a local redb store.

```bash
cargo run -p lp2ln-magic-folder --release -- --folder /path/to/watch
```

State survives restarts (job journal in redb). DHT announce and remote sync land in a future milestone.

### `lp2ln-release-tool`

Signs and packages a release manifest:

```bash
cargo run -p lp2ln-release --bin lp2ln-release-tool --release -- --help
```

### `debug-ui` (web debug interface)

Runs the local React/Vite UI used for debugging and packet-building workflows.

```bash
cd debug-ui
pnpm install
pnpm run dev
```

Optional:

```bash
pnpm run build
pnpm run preview
```

### `lp2ln-db-export`

```bash
cargo run -p lp2ln-db-export --release -- --help
```

Point it at a redb `db` file or a node data directory that contains `db`.

---

## Configuration

| Component | File | Format |
|-----------|------|--------|
| **lp2lnd** / v2 node | `options.json` (or path via `-o`/`--options`) | JSON — no signal server |

---

## Development

- **New work / v2:** `crates/lp2ln-core-v2/src/` (`node/`, `transport/`, `db/`, …)—equal peers, no signal server.
- **Debug UI:** `debug-ui/src/` (React + TypeScript + Vite).
- **Docker:** two production Dockerfiles are available at repo root:
  - `Dockerfile` — full multi-stage build from source.
  - `Dockerfile.binary` — runtime-only image from a prebuilt `lp2lnd` binary.

### Docker

Build from source (multi-stage):

```bash
docker build -f Dockerfile -t lp2lnd:source .
```

Build from prebuilt binary:

```bash
cargo build --release -p lp2lnd
mkdir -p dist
cp target/release/lp2lnd dist/lp2lnd
docker build -f Dockerfile.binary --build-arg BIN_PATH=dist/lp2lnd -t lp2lnd:binary .
```

Run example:

```bash
docker run --rm \
  -p 8080:8080/tcp -p 8080:8080/udp -p 9088:9088 \
  -v "$(pwd)/crates/lp2lnd/options-client.json:/app/options.json:ro" \
  -v "$(pwd)/data/db:/app/db" \
  -v "$(pwd)/data/logs:/app/logs" \
  lp2lnd:binary
```

---

## Validation and tests

Recommended baseline checks from repository root:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features
cargo test --workspace
cargo build --workspace
```

Topology simulation regression and size sweep (in `lp2ln-core-v2`):

```bash
cargo test -p lp2ln-core-v2 --test topology_sim_regression
cargo test -p lp2ln-core-v2 --test topology_sim_size_sweep
```

Manual smoke scenario (2+ nodes):

1. Start one bootstrap-like node with `options-bootstrap-*.json`.
2. Start one regular node with `options-client.json` pointing at bootstrap.
3. Verify peer discovery, stable connectivity, and health endpoint (`/livez`, `/readyz`).
4. If debug server is enabled, verify debug WebSocket connect and command roundtrip.

---

## Why AGPL + Commercial Licensing?

LP2LN is built to support an open, decentralized internet.

We want developers, researchers, and open-source communities to use, study, and improve the technology openly.

At the same time, if a company wants to build a proprietary commercial product on top of LP2LN without contributing changes back, a commercial license is required.

This model helps keep the core technology open while ensuring the project can be sustainably developed long-term.

---

## License

LP2LN is dual-licensed:

- Open-source use: GNU Affero General Public License v3.0 (AGPLv3)
- Commercial/proprietary use: available under a separate commercial license

If you use, modify, or provide LP2LN as part of a network service,
you must comply with AGPLv3, including providing access to the source code
of your modified version to users interacting with it.

To use LP2LN in closed-source or proprietary environments,
you must obtain a commercial license.

Contact: krusalovorg@gmail.com
