//! Minimal LP2LN v2 node: TCP + UDP transports, in-memory-style options (no DB).
//!
//! Run from the repository root:
//! ```text
//! cargo run -p lp2ln-core-v2 --example minimal_node
//! ```
//!
//! To join an existing network, set bootstrap addresses (see `with_default_nodes` / JSON `bootstrap_nodes`).

use lp2ln_core_v2::node::{NodeBuilder, NodeOptions};
use lp2ln_core_v2::peer_score::PeerConnectionPolicy;
use lp2ln_core_v2::transport::{tcp::TcpTransport, udp::UdpTransport};
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1) Options: either `NodeOptions::from_file("options.json")?` or build in code.
    let options = NodeOptions::empty()
        .with_listen("tcp", "0.0.0.0:8080".parse()?)
        .with_listen("udp", "0.0.0.0:8080".parse()?)
        // Peers to dial at startup (SocketAddr list). Same idea as `default_nodes` in JSON.
        .with_default_nodes(vec![])
        .with_peer_connection_policy(PeerConnectionPolicy {
            min_active_peers: 2,
            target_active_peers: 4,
            max_active_peers: 8,
        })
        .allow_unsigned_packets(true)
        .keypair_generate();

    // 2) Builder: register transports (at least those you enabled in `listens`).
    let mut node = NodeBuilder::new()
        .add_transport(Arc::new(TcpTransport::new()))
        .add_transport(Arc::new(UdpTransport::new()))
        // Optional: `.db(Arc::new(P2PDatabase::new("./node_data")?))`
        .build(options)?;

    // 3) Lifecycle
    node.start().await?;

    eprintln!("Node running on TCP/UDP 0.0.0.0:8080 — press Ctrl+C to stop");

    tokio::signal::ctrl_c().await?;
    node.stop().await?;

    Ok(())
}
