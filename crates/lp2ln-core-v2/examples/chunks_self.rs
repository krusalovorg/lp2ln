use lp2ln_core_v2::{
    Packet,
    db::P2PDatabase,
    node::{NodeBuilder, NodeOptions},
    transport::{tcp::TcpTransport, udp::UdpTransport},
};
use std::net::SocketAddr;
use std::sync::Arc;

const OPTIONS_PATH: &str = "./options.json";
const CHUNK_STREAM_ID: u64 = 1;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let db = Arc::new(P2PDatabase::new("./db")?);

    let builder = NodeBuilder::new()
        .add_transport(Arc::new(TcpTransport::new()))
        .add_transport(Arc::new(UdpTransport::new()));

    let options = match NodeOptions::from_file(OPTIONS_PATH) {
        Ok(opts) => opts,
        Err(_) => NodeOptions::new(),
    };
    let options = options
        .keypair(db.clone().get_or_create_node_keypair().unwrap())
        .allow_unsigned_packets(true);
    options.save(OPTIONS_PATH).map_err(anyhow::Error::msg)?;

    let mut node = builder.build(options)?;

    lp2ln_core_v2::info!("Starting P2P node (chunks self example)...");
    node.start().await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let self_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let session_id = match node.connect("tcp", self_addr).await {
        Ok(id) => {
            lp2ln_core_v2::info!("Connected to self, session_id: {}", id);
            id
        }
        Err(e) => {
            lp2ln_core_v2::error!("Connect error: {}", e);
            tokio::signal::ctrl_c().await?;
            node.stop().await?;
            return Ok(());
        }
    };

    let data = b"hello world";
    let chunk_size = 4_usize; // чанки: "hell", "o wo", "rld"
    let peer_id = node.peer_id().to_string();

    let chunks = Packet::chunk_packets(
        data,
        chunk_size,
        CHUNK_STREAM_ID,
        &peer_id,
        &peer_id,
        vec![],
        Some(8),
    );

    lp2ln_core_v2::info!(
        "Sending {} chunks ({} bytes total, chunk_size={})",
        chunks.len(),
        data.len(),
        chunk_size
    );

    let router = node.router().expect("node started");
    for (i, p) in chunks.iter().enumerate() {
        router
            .send_to_session(session_id.clone(), p.clone())
            .await?;
        lp2ln_core_v2::info!("Sent chunk {}/{}", i + 1, chunks.len());
    }

    lp2ln_core_v2::info!(
        "All chunks sent. Processor will receive one assembled packet (hello world)."
    );
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    tokio::signal::ctrl_c().await?;

    lp2ln_core_v2::info!("Shutting down...");
    node.stop().await?;
    lp2ln_core_v2::info!("Node stopped");

    Ok(())
}
