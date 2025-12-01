// Daemon for the basic peer client with console interface
// This daemon provides a user-friendly CLI with all available functions from the lp2ln library

use p2p_server::config::Config;
use p2p_server::db::P2PDatabase;
use p2p_server::logger;
use p2p_server::peer::Peer;
use p2p_server::peer::peer_api::PeerAPI;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use colored::Colorize;

/// CLI command structure
#[derive(Debug, Clone)]
enum Command {
    // Information commands
    Help,
    Status,
    Info,

    // File operations
    Upload { path: String, encrypt: bool, public: bool },
    UploadDir { path: String, encrypt: bool, public: bool },
    Download { identifier: String },
    Delete { file_hash: String },
    Move { file_hash: String, new_path: String },
    Update { file_hash: String, new_path: String, encrypt: bool, public: bool },
    SetPublic { file_hash: String, public: bool },
    ListFiles,

    // Network operations
    Peers,
    SearchPeer { peer_id: String },
    Connect { peer_id: String },
    Message { peer_id: String, text: String },

    // Storage operations
    Reserve { size_mb: u64 },
    ValidateToken { token: String },
    ListTokens,

    // Contract operations
    UploadContract { path: String },
    CallContract { hash: String, function: String, payload: String },

    // Sync operations
    Sync,

    // Exit
    Exit,

    // Unknown command
    Unknown(String),
}

fn print_banner() {
    println!("{}", r#"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   █░░ █▀█ ▀█ █░░ █▄░█   Light Protocol for Layered          ║
║   █▄▄ █▀▀ █▄ █▄▄ █░▀█   Peer Network - CLI Daemon            ║
║                                                              ║
║   Type 'help' to see available commands                      ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"#.cyan());
}

fn print_help() {
    println!("{}", "\n=== LP2LN Peer Daemon - Available Commands ===\n".green().bold());

    println!("{}", "📋 INFORMATION".yellow().bold());
    println!("  {}  - Show this help message", "help".cyan());
    println!("  {}  - Display peer status and connection info", "status".cyan());
    println!("  {}  - Show detailed peer information", "info".cyan());

    println!("\n{}", "📁 FILE OPERATIONS".yellow().bold());
    println!("  {} <path> [--public] [--no-encrypt]", "upload".cyan());
    println!("         - Upload a file to the network");
    println!("  {} <path> [--public] [--no-encrypt]", "upload-dir".cyan());
    println!("         - Upload entire directory to the network");
    println!("  {} <file_hash|filename>", "download".cyan());
    println!("         - Download a file from the network");
    println!("  {} <file_hash>", "delete".cyan());
    println!("         - Delete a file from the network");
    println!("  {} <file_hash> <new_path>", "move".cyan());
    println!("         - Move/rename a file");
    println!("  {} <file_hash> <new_path> [--public] [--no-encrypt]", "update".cyan());
    println!("         - Update file content");
    println!("  {} <file_hash>", "set-public".cyan());
    println!("         - Make file public");
    println!("  {} <file_hash>", "set-private".cyan());
    println!("         - Make file private");
    println!("  {}  - List all your files", "files".cyan());

    println!("\n{}", "🌐 NETWORK OPERATIONS".yellow().bold());
    println!("  {}  - Request list of connected peers", "peers".cyan());
    println!("  {} <peer_id>", "search".cyan());
    println!("         - Search for a specific peer");
    println!("  {} <peer_id>", "connect".cyan());
    println!("         - Establish direct connection to peer");
    println!("  {} <peer_id> <message>", "msg".cyan());
    println!("         - Send message to a peer");

    println!("\n{}", "💾 STORAGE OPERATIONS".yellow().bold());
    println!("  {} <size_mb>", "reserve".cyan());
    println!("         - Reserve storage space (in MB)");
    println!("  {} <token>", "validate".cyan());
    println!("         - Validate a storage token");
    println!("  {}  - List all storage tokens", "tokens".cyan());

    println!("\n{}", "📜 CONTRACT OPERATIONS".yellow().bold());
    println!("  {} <path.wasm>", "deploy".cyan());
    println!("         - Deploy a WASM smart contract");
    println!("  {} <contract_hash> <function> [payload]", "call".cyan());
    println!("         - Execute a contract function");

    println!("\n{}", "🔄 SYNCHRONIZATION".yellow().bold());
    println!("  {}  - Synchronize metadata with signal node", "sync".cyan());

    println!("\n{}", "🚪 EXIT".yellow().bold());
    println!("  {} / {}  - Exit the daemon", "exit".cyan(), "quit".cyan());

    println!();
}

fn parse_command(input: &str) -> Command {
    let parts: Vec<&str> = input.trim().split_whitespace().collect();

    if parts.is_empty() {
        return Command::Unknown(String::new());
    }

    let cmd = parts[0].to_lowercase();

    match cmd.as_str() {
        "help" | "h" | "?" => Command::Help,
        "status" => Command::Status,
        "info" => Command::Info,

        "upload" => {
            if parts.len() < 2 {
                println!("{}", "Error: upload requires a file path".red());
                return Command::Unknown(input.to_string());
            }
            let path = parts[1].to_string();
            let public = parts.contains(&"--public");
            let encrypt = !parts.contains(&"--no-encrypt");
            Command::Upload { path, encrypt, public }
        }

        "upload-dir" | "uploaddir" => {
            if parts.len() < 2 {
                println!("{}", "Error: upload-dir requires a directory path".red());
                return Command::Unknown(input.to_string());
            }
            let path = parts[1].to_string();
            let public = parts.contains(&"--public");
            let encrypt = !parts.contains(&"--no-encrypt");
            Command::UploadDir { path, encrypt, public }
        }

        "download" | "get" => {
            if parts.len() < 2 {
                println!("{}", "Error: download requires a file hash or filename".red());
                return Command::Unknown(input.to_string());
            }
            Command::Download { identifier: parts[1].to_string() }
        }

        "delete" | "rm" => {
            if parts.len() < 2 {
                println!("{}", "Error: delete requires a file hash".red());
                return Command::Unknown(input.to_string());
            }
            Command::Delete { file_hash: parts[1].to_string() }
        }

        "move" | "mv" => {
            if parts.len() < 3 {
                println!("{}", "Error: move requires file_hash and new_path".red());
                return Command::Unknown(input.to_string());
            }
            Command::Move {
                file_hash: parts[1].to_string(),
                new_path: parts[2].to_string()
            }
        }

        "update" => {
            if parts.len() < 3 {
                println!("{}", "Error: update requires file_hash and new_path".red());
                return Command::Unknown(input.to_string());
            }
            let public = parts.contains(&"--public");
            let encrypt = !parts.contains(&"--no-encrypt");
            Command::Update {
                file_hash: parts[1].to_string(),
                new_path: parts[2].to_string(),
                encrypt,
                public,
            }
        }

        "set-public" => {
            if parts.len() < 2 {
                println!("{}", "Error: set-public requires a file hash".red());
                return Command::Unknown(input.to_string());
            }
            Command::SetPublic { file_hash: parts[1].to_string(), public: true }
        }

        "set-private" => {
            if parts.len() < 2 {
                println!("{}", "Error: set-private requires a file hash".red());
                return Command::Unknown(input.to_string());
            }
            Command::SetPublic { file_hash: parts[1].to_string(), public: false }
        }

        "files" | "ls" | "list" => Command::ListFiles,

        "peers" => Command::Peers,

        "search" => {
            if parts.len() < 2 {
                println!("{}", "Error: search requires a peer_id".red());
                return Command::Unknown(input.to_string());
            }
            Command::SearchPeer { peer_id: parts[1].to_string() }
        }

        "connect" => {
            if parts.len() < 2 {
                println!("{}", "Error: connect requires a peer_id".red());
                return Command::Unknown(input.to_string());
            }
            Command::Connect { peer_id: parts[1].to_string() }
        }

        "msg" | "message" | "send" => {
            if parts.len() < 3 {
                println!("{}", "Error: msg requires peer_id and message".red());
                return Command::Unknown(input.to_string());
            }
            let peer_id = parts[1].to_string();
            let text = parts[2..].join(" ");
            Command::Message { peer_id, text }
        }

        "reserve" => {
            if parts.len() < 2 {
                println!("{}", "Error: reserve requires size in MB".red());
                return Command::Unknown(input.to_string());
            }
            match parts[1].parse::<u64>() {
                Ok(size_mb) => Command::Reserve { size_mb },
                Err(_) => {
                    println!("{}", "Error: invalid size, must be a number".red());
                    Command::Unknown(input.to_string())
                }
            }
        }

        "validate" => {
            if parts.len() < 2 {
                println!("{}", "Error: validate requires a token".red());
                return Command::Unknown(input.to_string());
            }
            Command::ValidateToken { token: parts[1].to_string() }
        }

        "tokens" => Command::ListTokens,

        "deploy" => {
            if parts.len() < 2 {
                println!("{}", "Error: deploy requires a wasm file path".red());
                return Command::Unknown(input.to_string());
            }
            Command::UploadContract { path: parts[1].to_string() }
        }

        "call" => {
            if parts.len() < 3 {
                println!("{}", "Error: call requires contract_hash and function name".red());
                return Command::Unknown(input.to_string());
            }
            let payload = if parts.len() > 3 {
                parts[3..].join(" ")
            } else {
                String::new()
            };
            Command::CallContract {
                hash: parts[1].to_string(),
                function: parts[2].to_string(),
                payload,
            }
        }

        "sync" => Command::Sync,

        "exit" | "quit" | "q" => Command::Exit,

        _ => Command::Unknown(cmd),
    }
}

async fn execute_command(
    cmd: Command,
    peer_api: &PeerAPI,
    db: &P2PDatabase,
    config: &Config,
) -> bool {
    match cmd {
        Command::Help => {
            print_help();
        }

        Command::Status => {
            println!("\n{}", "=== Peer Status ===".green().bold());
            let peer_id = db.get_or_create_peer_id().unwrap_or_else(|_| "Unknown".to_string());
            println!("  Peer ID: {}", peer_id.cyan());
            println!("  Signal Server: {}:{}", config.signal_server_ip.yellow(), config.signal_server_port.to_string().yellow());

            if let Ok(fragments) = db.get_my_fragments() {
                println!("  My Files: {}", fragments.len().to_string().green());
            }

            if let Ok(tokens) = db.get_all_tokens() {
                println!("  Storage Tokens: {}", tokens.len().to_string().green());
            }
            println!();
        }

        Command::Info => {
            println!("\n{}", "=== Detailed Peer Information ===".green().bold());
            let peer_id = db.get_or_create_peer_id().unwrap_or_else(|_| "Unknown".to_string());
            println!("  Peer Public Key: {}", peer_id.cyan());
            println!("  Database Path: {}", db.path.yellow());
            println!("  Signal Server: {}:{}", config.signal_server_ip, config.signal_server_port);
            println!("  Configured Storage Size: {} bytes", config.storage_size);

            if let Ok(total_space) = db.get_total_space() {
                println!("  Total Storage Space: {} bytes ({:.2} MB)",
                    total_space, total_space as f64 / 1024.0 / 1024.0);
            }

            if let Ok(storage_size) = db.get_storage_size().await {
                println!("  Used Storage: {} bytes ({:.2} MB)",
                    storage_size, storage_size as f64 / 1024.0 / 1024.0);
            }
            println!();
        }

        Command::Upload { path, encrypt, public } => {
            println!("Uploading file: {} (encrypt: {}, public: {})", path.cyan(), encrypt, public);
            match peer_api.upload_file(path.clone(), encrypt, public, false, "", false).await {
                Ok(_) => println!("{}", "File uploaded successfully!".green()),
                Err(e) => println!("{}: {}", "Upload failed".red(), e),
            }
        }

        Command::UploadDir { path, encrypt, public } => {
            println!("Uploading directory: {} (encrypt: {}, public: {})", path.cyan(), encrypt, public);
            match peer_api.upload_directory(path, encrypt, public, false).await {
                Ok(_) => println!("{}", "Directory uploaded successfully!".green()),
                Err(e) => println!("{}: {}", "Upload failed".red(), e),
            }
        }

        Command::Download { identifier } => {
            println!("Downloading file: {}", identifier.cyan());
            match peer_api.get_file(identifier).await {
                Ok(_) => println!("{}", "Download request sent!".green()),
                Err(e) => println!("{}: {}", "Download failed".red(), e),
            }
        }

        Command::Delete { file_hash } => {
            println!("Deleting file: {}", file_hash.cyan());
            match peer_api.delete_file(file_hash).await {
                Ok(_) => println!("{}", "File deleted successfully!".green()),
                Err(e) => println!("{}: {}", "Delete failed".red(), e),
            }
        }

        Command::Move { file_hash, new_path } => {
            println!("Moving file {} to {}", file_hash.cyan(), new_path.cyan());
            match peer_api.move_file(file_hash, new_path).await {
                Ok(_) => println!("{}", "File moved successfully!".green()),
                Err(e) => println!("{}: {}", "Move failed".red(), e),
            }
        }

        Command::Update { file_hash, new_path, encrypt, public } => {
            println!("Updating file: {}", file_hash.cyan());
            match peer_api.update_file(file_hash, new_path, encrypt, public, false).await {
                Ok(_) => println!("{}", "File updated successfully!".green()),
                Err(e) => println!("{}: {}", "Update failed".red(), e),
            }
        }

        Command::SetPublic { file_hash, public } => {
            let visibility = if public { "public" } else { "private" };
            println!("Setting file {} to {}", file_hash.cyan(), visibility);
            match peer_api.change_file_public_access(file_hash, public).await {
                Ok(_) => println!("{}", format!("File is now {}!", visibility).green()),
                Err(e) => println!("{}: {}", "Failed to change access".red(), e),
            }
        }

        Command::ListFiles => {
            println!("\n{}", "=== Your Files ===".green().bold());
            match db.get_my_fragments() {
                Ok(files) => {
                    if files.is_empty() {
                        println!("  No files found");
                    } else {
                        println!("  {:<64} {:<30} {:<10} {:<10}",
                            "Hash".yellow(), "Filename".yellow(), "Size".yellow(), "Public".yellow());
                        println!("  {}", "-".repeat(120));
                        for file in files {
                            let size_str = format_size(file.size);
                            let public_str = if file.public { "Yes".green() } else { "No".red() };
                            println!("  {:<64} {:<30} {:<10} {}",
                                &file.file_hash[..64.min(file.file_hash.len())],
                                truncate_string(&file.filename, 28),
                                size_str,
                                public_str);
                        }
                    }
                }
                Err(e) => println!("{}: {}", "Failed to list files".red(), e),
            }
            println!();
        }

        Command::Peers => {
            println!("Requesting peer list...");
            match peer_api.request_peer_list().await {
                Ok(_) => println!("{}", "Peer list request sent!".green()),
                Err(e) => println!("{}: {}", "Failed to request peers".red(), e),
            }
        }

        Command::SearchPeer { peer_id } => {
            println!("Searching for peer: {}", peer_id.cyan());
            match peer_api.search_peer(peer_id).await {
                Ok(_) => println!("{}", "Search request sent!".green()),
                Err(e) => println!("{}: {}", "Search failed".red(), e),
            }
        }

        Command::Connect { peer_id } => {
            println!("Connecting to peer: {}", peer_id.cyan());
            match peer_api.connect_to_peer(peer_id).await {
                Ok(_) => println!("{}", "Connection request sent!".green()),
                Err(e) => println!("{}: {}", "Connection failed".red(), e),
            }
        }

        Command::Message { peer_id, text } => {
            println!("Sending message to {}", peer_id.cyan());
            match peer_api.send_message(peer_id, text).await {
                Ok(_) => println!("{}", "Message sent!".green()),
                Err(e) => println!("{}: {}", "Failed to send message".red(), e),
            }
        }

        Command::Reserve { size_mb } => {
            let size_bytes = size_mb * 1024 * 1024;
            println!("Reserving {} MB ({} bytes) of storage...", size_mb, size_bytes);
            match peer_api.reserve_storage(size_bytes).await {
                Ok(_) => println!("{}", "Storage reservation request sent!".green()),
                Err(e) => println!("{}: {}", "Reservation failed".red(), e),
            }
        }

        Command::ValidateToken { token } => {
            println!("Validating token...");
            match peer_api.valid_token(token).await {
                Ok(_) => println!("{}", "Token validation request sent!".green()),
                Err(e) => println!("{}: {}", "Validation failed".red(), e),
            }
        }

        Command::ListTokens => {
            println!("\n{}", "=== Storage Tokens ===".green().bold());
            match db.get_all_tokens() {
                Ok(tokens) => {
                    if tokens.is_empty() {
                        println!("  No tokens found. Use 'reserve <size_mb>' to get storage tokens.");
                    } else {
                        println!("  {:<40} {:<15} {:<15}",
                            "Peer ID".yellow(), "Free Space".yellow(), "Used Space".yellow());
                        println!("  {}", "-".repeat(75));
                        for (peer_id, token_info) in tokens {
                            println!("  {:<40} {:<15} {:<15}",
                                truncate_string(&peer_id, 38),
                                format_size(token_info.free_space),
                                format_size(token_info.used_space));
                        }
                    }
                }
                Err(e) => println!("{}: {}", "Failed to list tokens".red(), e),
            }
            println!();
        }

        Command::UploadContract { path } => {
            println!("Deploying contract: {}", path.cyan());
            match peer_api.upload_contract(path).await {
                Ok(_) => println!("{}", "Contract deployed successfully!".green()),
                Err(e) => println!("{}: {}", "Deployment failed".red(), e),
            }
        }

        Command::CallContract { hash, function, payload } => {
            println!("Calling contract {} function {}", hash.cyan(), function.cyan());
            let payload_bytes = payload.into_bytes();
            match peer_api.call_contract(hash, function, payload_bytes).await {
                Ok(_) => println!("{}", "Contract call request sent!".green()),
                Err(e) => println!("{}: {}", "Contract call failed".red(), e),
            }
        }

        Command::Sync => {
            println!("Synchronizing metadata with signal node...");
            match peer_api.sync_fragment_metadata().await {
                Ok(_) => println!("{}", "Sync request sent!".green()),
                Err(e) => println!("{}: {}", "Sync failed".red(), e),
            }
        }

        Command::Exit => {
            println!("{}", "Goodbye!".cyan());
            return true; // Signal to exit
        }

        Command::Unknown(cmd) => {
            if !cmd.is_empty() {
                println!("{}: {}. Type 'help' for available commands.", "Unknown command".red(), cmd);
            }
        }
    }

    false // Continue running
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / 1024.0 / 1024.0)
    } else {
        format!("{:.2} GB", bytes as f64 / 1024.0 / 1024.0 / 1024.0)
    }
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

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

    println!("Your Peer ID: {}", peer_id.cyan());
    println!("Connected to: {}:{}", config.signal_server_ip.yellow(), config.signal_server_port.to_string().yellow());
    println!();

    // Create channel for command communication
    let (tx, mut rx) = mpsc::channel::<Command>(32);

    // Clone what we need for the input handler task
    let tx_clone = tx.clone();

    // Spawn input handler in a separate task
    tokio::spawn(async move {
        let stdin = io::stdin();
        loop {
            print!("{}", "lp2ln> ".green().bold());
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
