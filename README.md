# LP2LN — Layered Peer-to-Peer Network

Decentralized P2P networking stack in Rust. The **current direction** is **`lp2ln-core-v2`**: a flat network where **peers are equal** (no special coordinator role) and **no signal servers are required**—bootstrap and discovery follow the new node model. The older **`lp2ln-core`** + **`lp2ln-gateway`** stack lives under **`archive/`** (not part of the default workspace build); it assumed a **signal server** and the classic peer architecture. **`lp2ln-gateway` is frozen for now**—active development is on finishing **v2** first; the gateway will be revisited afterward.

**Wiki:** [https://deepwiki.com/krusalovorg/lp2ln](https://deepwiki.com/krusalovorg/lp2ln)

---

## Contents

- [Documentation (Wiki)](#documentation-wiki)
- [Overview](#overview)
- [Workspace layout](#workspace-layout)
- [Crates](#crates)
- [Requirements](#requirements)
- [Build](#build)
- [Using `lp2ln-core-v2` as a library](#using-lp2ln-core-v2-as-a-library)
- [Run](#run)
  - [`lp2lnd` (v2 node)](#lp2lnd-v2-node)
  - [`lp2ln-gateway` (HTTP + legacy core)](#lp2ln-gateway-http--legacy-core)
  - [`lp2ln-db-export`](#lp2ln-db-export)
- [Configuration](#configuration)
- [Development](#development)
- [License](#license)

---

## Documentation (Wiki)

Architecture and deeper explanations for this project are on DeepWiki:

[https://deepwiki.com/krusalovorg/lp2ln](https://deepwiki.com/krusalovorg/lp2ln)

---

## Overview

| Area | Notes |
|------|--------|
| **Stacks** | **v2 (`lp2ln-core-v2`):** egalitarian peers, no signal server—**main focus**. **Legacy (`archive/lp2ln-core` + `archive/lp2ln-gateway`):** signal server + classic model; **frozen** until v2 is further along—not built by `cargo build --workspace`. |
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
├── rust-toolchain.toml     # pins stable (needed for lp2ln-core-v2 edition 2024)
├── config.toml             # legacy gateway only: signal server, storage, proxy
├── LICENSE
├── crates/
│   ├── lp2ln-core-v2/      # current core: equal peers, no signal server, node runtime, …
│   ├── lp2lnd/             # binary: v2 node daemon (lp2ln-core-v2)
│   └── lp2ln-db-export/    # binary: export redb / node DB to JSON
├── archive/                # legacy stack (excluded from workspace; optional standalone build)
│   ├── lp2ln-core/
│   └── lp2ln-gateway/
├── contracts/              # WASM contract build notes
├── tools/                  # e.g. topology-viewer (Python)
└── vscode-extension/       # editor extension (see vscode-extension/README.md)
```

---

## Crates

| Crate | Role |
|-------|------|
| **lp2ln-core-v2** | **Current** library: flat topology—**all peers are equal**; **no signal server**. `NodeBuilder`, `NodeOptions`, TCP/UDP transports, logging, peer scoring, `P2PDatabase` / storage tables. **MSRV:** Rust **1.85** (edition **2024**; see `crates/lp2ln-core-v2/Cargo.toml`). |
| **lp2lnd** | Default entry point for the v2 stack. Loads `options.json` (or path from CLI), starts the node, waits for Ctrl+C. Optional binary: `lp2lnd-scale` (`scale_daemon.rs`). Optional feature: `tokio-console` (needs `RUSTFLAGS="--cfg tokio_unstable"`). |
| **lp2ln-core** (archive) | **Legacy** core under `archive/lp2ln-core/`: signal-server-oriented peer stack, connection manager, tunnels, WASM runtime, etc. Not built with the main workspace. |
| **lp2ln-gateway** (archive) | Legacy daemon under `archive/lp2ln-gateway/` on **`lp2ln-core`** (`config.toml`, `./gateway_storage`, HTTP proxy/API). **Frozen**—build only if needed via `--manifest-path` (see [Run](#run)). |
| **lp2ln-db-export** | CLI to dump node `redb` data to JSON (`-h` for usage). Default build includes file-picker support via the `pick` feature. |

---

## Requirements

- **Rust** toolchain **1.85+** for the workspace (`lp2ln-core-v2` uses **edition 2024**). The repo includes **`rust-toolchain.toml`** pinning **stable** so `rustup` selects a new enough toolchain in this directory.
- **Gateway only (legacy stack in `archive/`, frozen):** if you still run it, build with `--manifest-path archive/lp2ln-gateway/Cargo.toml` and use `config.toml` in the working directory (signal server settings; repository root has an example). **v2 nodes** use `options.json` and no signal server.
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

### `lp2ln-gateway` (HTTP + **legacy** core)

**Status: frozen.** Maintenance and feature work on the gateway are on hold while **v2** (`lp2ln-core-v2` / `lp2lnd`) is the priority. The code may still build and run as-is.

Uses **`lp2ln-core`** (signal-server model), not v2. Not a workspace member; run from a directory that contains `config.toml` (e.g. clone root):

```bash
cargo run --manifest-path archive/lp2ln-gateway/Cargo.toml --release
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
| **lp2lnd** / v2 node | `options.json` (or path via `-o`/`--options`) | JSON — no signal server |
| **lp2ln-gateway** (legacy, frozen) | `config.toml` | TOML — includes `signal_server_*` |

---

## Development

- **New work / v2:** `crates/lp2ln-core-v2/src/` (`node/`, `transport/`, `db/`, …)—equal peers, no signal server.
- **Legacy gateway stack (frozen):** `archive/lp2ln-core/src/` and `archive/lp2ln-gateway/src/`—no active development until v2 matures.
- **Docker:** a `Dockerfile` exists at the repository root but targets an older single-binary layout (`P2P-Server`, `start.sh`). Expect to adapt it if you want container builds for the current workspace outputs (`target/release/lp2lnd`, etc.).

---

## License

See the [`LICENSE`](LICENSE) file in this repository.
