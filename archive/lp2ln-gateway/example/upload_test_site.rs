use std::net::SocketAddr;
use lp2ln_core::peer::{Peer, PeerAPI, PeerOptions};
use lp2ln_core::db::P2PDatabase;

#[tokio::main]
async fn main() {
    let options = PeerOptions::new(SocketAddr::from(([0, 0, 0, 0], 8080)), 1024 * 1024 * 1024);
    let db = P2PDatabase::new("./db").unwrap();
    let peer = Peer::new(options, &db.clone()).await;
    peer.run();
    let peer_api = PeerAPI::new(peer.connection.clone(), &db.clone(), &peer.connection_manager.clone());
    peer_api.upload_directory("./site".to_string(), false, true, true).await.unwrap();
}