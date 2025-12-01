// LP2LN Peer CLI Daemon
// Interactive command-line interface for the LP2LN P2P network

use p2p_server::config::Config;
use p2p_server::db::P2PDatabase;
use p2p_server::logger;
use p2p_server::peer::Peer;
use p2p_server::peer::peer_api::PeerAPI;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;

mod commands;
mod handlers;
mod ui;

use commands::{parse_command, Command};
use handlers::execute_command;
use ui::{print_banner, print_prompt, print_connection_info};

#[tokio::main]
async fn main() {
    // Initialize logging
    logger::set_log_file(Some("./peer_cli.log"));
    logger::info("Starting LP2LN Peer CLI Daemon...");

    // Load configuration
    let config = Config::from_file("config.toml");

    // Create database path
    let db_path = "./storage_peer";
    let path = PathBuf::from(db_path);
    if !path.exists() {
        std::fs::create_dir_all(&path).expect("Failed to create database directory");
    }

    // Initialize database
    let db = P2PDatabase::new(path.to_str().unwrap())
        .expect("Failed to create database");

    // Get or create peer ID
    let peer_id = db.get_or_create_peer_id().unwrap();
    logger::info(&format!("[Peer] Your UUID: {}", peer_id));

    // Create peer
    logger::info("[Peer] Initializing peer...");
    let peer = Peer::new(&config, &db).await;

    // Get connection manager and connection for API
    let connection_manager = peer.get_connection_manager();
    let connection = peer.get_connection();

    // Create PeerAPI
    let peer_api = PeerAPI::new(connection.clone(), &db, &connection_manager);

    logger::info(&format!("[Peer] Connected to signal server: {}:{}",
        config.signal_server_ip, config.signal_server_port));

    // Print banner
    print_banner();
    print_connection_info(&peer_id, &config.signal_server_ip, config.signal_server_port);

    // Create channel for command communication
    let (tx, mut rx) = mpsc::channel::<Command>(32);

    // Clone what we need for the input handler task
    let tx_clone = tx.clone();

    // Spawn input handler in a separate task
    tokio::spawn(async move {
        let stdin = io::stdin();
        loop {
            print_prompt();
            io::stdout().flush().unwrap();

            let mut input = String::new();
            match stdin.read_line(&mut input) {
                Ok(0) => {
                    // EOF reached
                    let _ = tx_clone.send(Command::Exit).await;
                    break;
                }
                Ok(_) => {
                    let cmd = parse_command(&input);
                    if tx_clone.send(cmd).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Error reading input: {}", e);
                    break;
                }
            }
        }
    });

    // Spawn peer packet handler in background
    let peer_clone = Arc::new(peer);
    let peer_for_handler = peer_clone.clone();
    tokio::spawn(async move {
        peer_for_handler.connection_manager.handle_incoming_packets().await;
    });

    // Main command loop
    while let Some(cmd) = rx.recv().await {
        if execute_command(cmd, &peer_api, &db, &config).await {
            break;
        }
    }

    logger::info("[Peer] CLI Daemon stopped");
}
