# `lp2lnd` Configuration Guide

This guide explains `NodeOptions` for `lp2lnd`: what each setting does, why it matters, and how to choose values for real scenarios.

> Architecture context: [Core Node Architecture (DeepWiki)](https://deepwiki.com/krusalovorg/lp2ln/2-core-node-architecture)

## How config loading works

`lp2lnd` resolves configuration in this order:

1. Path from `-o/--options`
2. `./options.json` in the current working directory
3. Built-in developer fallback (if the file is missing or invalid)

Additional behavior:

- If `database_dir` is not set, default is `./db`.
- When started with `-o/--options`, the daemon writes normalized options back to that file path.

## Minimal full example

```json
{
  "listens": {
    "tcp": "0.0.0.0:18090",
    "udp": "0.0.0.0:18190"
  },
  "default_nodes": [],
  "bootstrap_nodes": [],
  "allow_unsigned_packets": true,
  "logger_options": {
    "log_dir": "./logs/node",
    "file_enabled": true,
    "show_debug": true,
    "show_info": true,
    "show_warning": true,
    "show_error": true
  },
  "peer_connection_policy": {
    "min_active_peers": 2,
    "target_active_peers": 6,
    "max_active_peers": 14
  },
  "database_dir": "./db/node",
  "node_role": "regular"
}
```

## Field-by-field reference

### 1) Network I/O

#### `listens: { "<protocol>": "ip:port" }`

Local bind addresses (`tcp`, `udp`).

- Why: peers cannot connect to this node without correct binds.
- Recommended:
  - local development: `127.0.0.1:*`
  - LAN/server: `0.0.0.0:*` plus firewall/NAT rules

#### `advertise_addrs` (optional)

Explicit addresses announced to peers.

- Why: useful when public reachability differs from local bind (NAT, containers, reverse proxies).
- Recommended: set only when default behavior is not enough.

#### `default_nodes: ["ip:port", ...]`

Static known peers list.

- Why: simple seed list without extra metadata.
- Best for: small environments and local testing.

#### `bootstrap_nodes` / `seed_nodes`: `[{ addr, protocols, peer_id_hint? }, ...]`

Local **seed address book** (known endpoints to dial on cold start). Alias: `seed_nodes`.

- Why: join the mesh without a special node cast — seeds are ordinary peers with known IPs.
- `protocols` should match what those nodes actually listen on.
- `peer_id_hint` improves early identity association.
- After join, the node prefers non-seed mesh peers (`min`/`target`/`max` apply equally to everyone).

#### `bootstrap_peer_hints: { "ip:port": "peer_id" }` (optional)

Peer ID hints map for seed addresses.

- Why: helps map seed address -> expected peer identity faster.

### 2) Identity and signatures

#### `private_key_hex` (optional)

Node private key. If omitted, a keypair is generated.

- Why: stable peer identity across restarts/deployments.
- Set for: production and any stable-identity environments.
- Omit for: disposable local runs.

#### `allow_unsigned_packets: bool`

Allow packets without signatures.

- Why: easier interoperability and local development.
- Recommended:
  - dev/test: `true`
  - production/untrusted networks: prefer `false` if your full stack supports strict signing

#### `signature_format: "v3_hash"`

Outgoing packet signature wire format. Ingress accepts **only** V3 (`v3:` prefix).

| Value | Payload | Wire prefix |
|---|---|---|
| `v3_hash` (default, only) | postcard: SHA-256(`data`) + routing fields + `protocol_id` | `v3:` |

Legacy V1 (JSON) and V2 (`v2:`) were removed before any public deployment — there is no mixed-version compatibility path.

#### `experimental` (P0-04)

Opt-in flags for unfinished DHT / content / repair / App Plane skeletons. **All default to `false`.**

```json
{
  "experimental": {
    "dht": false,
    "content": false,
    "repair": false,
    "app_plane": false
  }
}
```

| Flag | Meaning |
|---|---|
| `dht` | Reserved for DHT background lifecycle (not started by `lp2lnd` yet) |
| `content` | Enables debug `block_put` / `block_get` on debug WS / IPC TCP |
| `repair` | Reserved for RepairWorker (not started by `lp2lnd` yet) |
| `app_plane` | Reserved for binary App Plane TCP server (module exists; not started by default) |

These are **not** a production distributed storage stack. Library APIs under `dht` / `storage` / `app_plane` remain available for tests and sidecars; the default daemon does not promise their lifecycle until the P4 content-runtime gate.

### 3) Connectivity policy

#### `peer_connection_policy`

```json
{
  "min_active_peers": 2,
  "target_active_peers": 6,
  "max_active_peers": 14
}
```

- `min_active_peers`: floor where node aggressively redials.
- `target_active_peers`: steady-state target.
- `max_active_peers`: hard cap.

Why it matters:

- too low -> weaker resilience/routing
- too high -> unnecessary CPU/memory/socket pressure

Recommended starting points:

- small dev mesh: `2/4/8` or `2/6/14`
- medium production: `4/8/16` or `6/12/24`
- keep `max` around `~2x target` as a practical baseline

### 4) Topology and discovery tuning

#### `node_role: "regular" | "bootstrap_join"` (deprecated distinction)

- Prefer `"regular"` always.
- `"bootstrap_join"` is **deprecated** and treated as `"regular"`: seed endpoints come from `bootstrap_nodes` / `seed_nodes`, not from a network role.
- Wire field `capabilities.bootstrap_entry` is kept for compatibility but is no longer set or used for policy.

#### `peer_discovery_random_fraction` (`0.0..0.9`)

Randomness ratio in discovery.

- Why: avoids deterministic local minima in peer graph formation.
- Recommended: `0.25..0.40` for most networks.

#### `catalog_max_peers` (optional, clamped to `128..1_000_000`)

Peer catalog size limit.

- Why: controls memory growth and catalog traversal cost.
- Recommended:
  - small networks: `1024..4096`
  - larger networks: `8192+` as needed

#### `topology_tuning`

Fine-grained adaptive controls:

- `regular_auto_target_min/max`
- `regular_bootstrap_min_keep`
- `regular_bootstrap_rejoin_interval_ms`
- `regular_exploration_interval_ms`
- `dial_retry_cooldown_ms`, `prune_redial_cooldown_ms`
- `bootstrap_stable_peer_threshold`
- `avoid_reseed_when_stable_bootstrap`
- `adaptive_topology_enabled`
- `adaptive_profile` (`conservative|balanced|aggressive`)
- `adaptive_target_min_floor`, `adaptive_target_max_ceil`
- `adaptive_bootstrap_hard_max`, `adaptive_bootstrap_top_k`
- `adaptive_exploration_interval_min/max_ms`
- `adaptive_rejoin_cooldown_min/max_ms`
- `adaptive_redirect_memory_ms`

Practical approach:

- start with `balanced`
- change 1-2 knobs per iteration
- evaluate with runtime metrics and peer stability

### 5) Peer scoring

#### `peer_score_weights`

Weights in peer ranking formula:

- positive terms: `w_uptime`, `w_success`, `w_bandwidth`, `w_relay`, `w_nat`, `w_trust`, `w_geo`
- penalty terms: `w_load`, `w_latency` (via `latency_norm_ms`)

Why it matters:

- directly impacts peer preference for connectivity and routing.

Recommendations:

- keep defaults first
- increase `w_latency` and/or lower `latency_norm_ms` for stronger low-latency preference
- increase `w_trust` only if trust signals are reliable in your environment

### 6) Transport obfuscation

#### `transport_obfuscation`

Per-protocol (`tcp`, `udp`) `ObfuscationConfig`:

- `mode`: `plain` or `mimic_http`
- `fake_hosts`, `fake_paths`
- `padding_min/max`
- `min_chunk_size/max_chunk_size`
- `min_chunk_delay_ms/max_chunk_delay_ms`

#### `transport_obfuscation_enabled`

Feature flags to enable/disable obfuscation by protocol.

Why it matters:

- can improve traffic camouflage
- increases overhead and complicates troubleshooting

Recommendation:

- start with `plain`
- roll out `mimic_http` gradually and validate both ends of each protocol pair

### 7) Storage and logging

#### `database_dir`

Path to node redb storage.

- Why: persistence across restarts.
- Recommended: dedicated directory per node (`./db/node-a`, `./db/node-b`).

#### `log_peer_score_snapshot: bool`

Enables peer-score snapshot logging (where used by runtime path).

- Why: helps analyze topology churn and ranking behavior.
- Recommended: enable selectively during diagnostics.

#### `logger_options`

- `log_dir`
- `file_enabled`
- `show_debug`, `show_info`, `show_warning`, `show_error`

Recommended:

- production: `show_debug=false`, `show_info=true`, file logging enabled
- load testing: temporarily enable `show_debug=true`

### 8) Runtime diagnostics

#### `flow_trace`

- `enabled`
- `json_packets`
- `payload_preview_bytes`

Why:

- useful for deep packet/routing investigation.

Recommended:

- keep disabled by default
- enable temporarily for incident analysis

#### `debug_server`

- `enabled`
- `bind_addr` (usually `127.0.0.1:<port>`)
- `push_interval_ms` (practically not below ~250ms)

Why:

- powers debug streams and command interface for debug tooling.

Recommended:

- bind to loopback by default
- do not expose publicly without extra security controls

## Preset profiles

### A. Local development (1-5 nodes)

- `allow_unsigned_packets=true`
- `peer_connection_policy=2/4/8` or `2/6/14`
- `adaptive_topology_enabled=true`, `adaptive_profile=balanced`
- `debug_server.enabled=true`, `bind_addr=127.0.0.1:*`
- `logger.show_debug=true`

### B. Stable server node

- fixed `private_key_hex`
- `allow_unsigned_packets=false` (if compatible with all peers)
- `peer_connection_policy=6/12/24` (or close)
- `catalog_max_peers>=4096`
- `logger.show_debug=false` with file logging enabled
- `debug_server` limited to loopback/private segment

### C. Public seed / entry node (ordinary peer with known IP)

- `node_role=regular` (preferred; `bootstrap_join` is deprecated and equivalent)
- list this node's address in newcomers' `bootstrap_nodes` / `seed_nodes`
- same `peer_connection_policy` as everyone else — inbound cap + redirect when full
- `topology_tuning.avoid_reseed_when_stable_bootstrap=true` on clients is fine

## Common mistakes

- `listens` points to unreachable IP/port -> bind failures.
- no `bootstrap_nodes` and no `default_nodes` when external seeding is needed -> node isolation.
- shared `database_dir` between multiple nodes -> state conflicts/corruption.
- overly high `target/max` on weak hardware -> churn and degraded stability.
- enabling `mimic_http` only on one side -> protocol mismatch.

## Safe tuning workflow

1. Record baseline metrics (latency, active peers, reconnect rate).
2. Change only a small set of parameters per iteration.
3. Run 30-60+ minutes under representative load.
4. Keep rollback config files next to active config.
