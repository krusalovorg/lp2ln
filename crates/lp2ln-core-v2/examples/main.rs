use lp2ln_core_v2::{
    db::P2PDatabase,
    node::{NodeBuilder, NodeOptions},
    packet_processor::PING,
    transport::{tcp::TcpTransport, udp::UdpTransport},
};
use std::net::SocketAddr;
use std::sync::Arc;

const OPTIONS_PATH: &str = "./options.json";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let db = Arc::new(P2PDatabase::new("./db")?);

    let builder = NodeBuilder::new()
        // .db(db)
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

    lp2ln_core_v2::info!("Starting P2P node...");
    node.start().await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    let self_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    match node.connect("tcp", self_addr).await {
        Ok(session_id) => {
            lp2ln_core_v2::info!("Connected to self (session_id): {}", session_id);
            match node
                .send_to_session(session_id.clone(), PING.to_vec())
                .await
            {
                Ok(()) => lp2ln_core_v2::info!("Sent to session: {}", session_id),
                Err(e) => lp2ln_core_v2::error!("Send error: {}", e),
            }
        }
        Err(e) => lp2ln_core_v2::error!("Connect error: {}", e),
    }

    tokio::signal::ctrl_c().await?;

    lp2ln_core_v2::info!("Shutting down...");
    node.stop().await?;
    lp2ln_core_v2::info!("Node stopped");

    Ok(())
}
