# `lp2lnd`

Daemon binaries for running LP2LN v2 nodes from this workspace.

- `lp2lnd` — single node runtime based on `lp2ln-core-v2`
- `lp2lnd-scale` — multi-node local scale runner (many virtual peers from one template)

## Requirements

- Rust 1.85+ (edition 2024)
- A valid `NodeOptions` JSON file (`options.json`) if you do not want fallback developer defaults

## Binaries

`Cargo.toml` defines two binaries:

- `lp2lnd` (`src/main.rs`)
- `lp2lnd-scale` (`src/scale_daemon.rs`)

Build both:

```bash
cargo build -p lp2lnd --release
```

## `lp2lnd` (single node)

Полная документация по конфигурации с объяснением полей и профилей:

- [`CONFIGURATION.md`](./CONFIGURATION.md)

### Run

From repository root:

```bash
cargo run -p lp2lnd --release
```

With explicit config path:

```bash
cargo run -p lp2lnd --release -- -o crates/lp2lnd/options-client.json
# equivalent:
cargo run -p lp2lnd --release -- --options crates/lp2lnd/options-client.json
```

### Config loading behavior

- If `-o/--options` is provided, that file is used.
- If not provided, `./options.json` in current working directory is used when present.
- If file load fails or no config is found, daemon falls back to built-in developer defaults.
- If `database_dir` is missing in options, default is `./db`.

On startup the daemon writes normalized options back to the provided config path (when one is used).

### Useful options files in this crate

- `options-client.json`
- `options-bootstrap-1.json`
- `options-bootstrap-2.json`
- `options-bootstrap-3.json`

### Tokio Console (optional)

Enable feature:

```bash
RUSTFLAGS="--cfg tokio_unstable" cargo run -p lp2lnd --release --features tokio-console
```

## Debug WebSocket server

`lp2lnd` can expose a local debug WebSocket stream (configured via `debug_server` in `NodeOptions`):

```json
{
  "debug_server": {
    "enabled": true,
    "bind_addr": "127.0.0.1:9090",
    "push_interval_ms": 1000
  }
}
```

When enabled, server publishes periodic snapshots and accepts command messages (for example connect/disconnect peers, send payloads, inspect DB tables, adjust peer policy).

## `lp2lnd-scale` (virtual peers)

`lp2lnd-scale` launches many virtual peers from one template config, generating per-peer configs and DB folders.

### Run

```bash
cargo run -p lp2lnd --bin lp2lnd-scale --release -- -o crates/lp2lnd/options-bootstrap-1.json --virtual-peers 10
```

### CLI flags

- `-o, --options <path>` — template options file
- `--virtual-peers <N>` / `--scale-peers <N>` — number of peers to spawn
- `--from <IDX>` — global peer index offset (useful for multi-process sharding)
- `--debug-base <PORT>` / `--scale-debug-base <PORT>` — base port for per-peer debug WS
- `--debug` / `--no-debug` — force enable/disable per-peer debug WS

### Environment variables

- `LP2LND_VIRTUAL_PEERS`
- `LP2LND_VIRTUAL_PEER_FROM`
- `LP2LND_SCALE_BIND_IP`
- `LP2LND_SCALE_TCP_BASE` (default `22000`)
- `LP2LND_SCALE_UDP_BASE` (default `24000`)

### Generated artifacts

`lp2lnd-scale` creates:

- `temp_configs/peer_<idx>/options.json`
- `temp_configs/peer_<idx>/logs/`
- `temp_db/peer_<idx>/`

The template should include either `bootstrap_nodes` or `default_nodes`; otherwise scale startup fails.

## Operational notes

- Stop daemon with `Ctrl+C`.
- `lp2lnd` and `lp2lnd-scale` both initialize transports from options (`tcp` / `udp`).
- Database is optional for `lp2lnd` (daemon can continue without DB if open fails), but required for each generated scale peer.
