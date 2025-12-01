// Command handlers for the LP2LN Peer CLI
use colored::Colorize;
use p2p_server::config::Config;
use p2p_server::db::P2PDatabase;
use p2p_server::peer::peer_api::PeerAPI;

use crate::commands::Command;
use crate::ui::{format_size, truncate_string, print_help};

/// Execute a command and return true if the CLI should exit
pub async fn execute_command(
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
            handle_status(db, config);
        }

        Command::Info => {
            handle_info(db, config).await;
        }

        Command::Upload { path, encrypt, public } => {
            handle_upload(peer_api, path, encrypt, public).await;
        }

        Command::UploadDir { path, encrypt, public } => {
            handle_upload_dir(peer_api, path, encrypt, public).await;
        }

        Command::Download { identifier } => {
            handle_download(peer_api, identifier).await;
        }

        Command::Delete { file_hash } => {
            handle_delete(peer_api, file_hash).await;
        }

        Command::Move { file_hash, new_path } => {
            handle_move(peer_api, file_hash, new_path).await;
        }

        Command::Update { file_hash, new_path, encrypt, public } => {
            handle_update(peer_api, file_hash, new_path, encrypt, public).await;
        }

        Command::SetPublic { file_hash, public } => {
            handle_set_public(peer_api, file_hash, public).await;
        }

        Command::ListFiles => {
            handle_list_files(db);
        }

        Command::Peers => {
            handle_peers(peer_api).await;
        }

        Command::SearchPeer { peer_id } => {
            handle_search_peer(peer_api, peer_id).await;
        }

        Command::Connect { peer_id } => {
            handle_connect(peer_api, peer_id).await;
        }

        Command::Message { peer_id, text } => {
            handle_message(peer_api, peer_id, text).await;
        }

        Command::Reserve { size_mb } => {
            handle_reserve(peer_api, size_mb).await;
        }

        Command::ValidateToken { token } => {
            handle_validate_token(peer_api, token).await;
        }

        Command::ListTokens => {
            handle_list_tokens(db);
        }

        Command::UploadContract { path } => {
            handle_upload_contract(peer_api, path).await;
        }

        Command::CallContract { hash, function, payload } => {
            handle_call_contract(peer_api, hash, function, payload).await;
        }

        Command::Sync => {
            handle_sync(peer_api).await;
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

// Information handlers
fn handle_status(db: &P2PDatabase, config: &Config) {
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

async fn handle_info(db: &P2PDatabase, config: &Config) {
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

// File operation handlers
async fn handle_upload(peer_api: &PeerAPI, path: String, encrypt: bool, public: bool) {
    println!("Uploading file: {} (encrypt: {}, public: {})", path.cyan(), encrypt, public);
    match peer_api.upload_file(path.clone(), encrypt, public, false, "", false).await {
        Ok(_) => println!("{}", "File uploaded successfully!".green()),
        Err(e) => println!("{}: {}", "Upload failed".red(), e),
    }
}

async fn handle_upload_dir(peer_api: &PeerAPI, path: String, encrypt: bool, public: bool) {
    println!("Uploading directory: {} (encrypt: {}, public: {})", path.cyan(), encrypt, public);
    match peer_api.upload_directory(path, encrypt, public, false).await {
        Ok(_) => println!("{}", "Directory uploaded successfully!".green()),
        Err(e) => println!("{}: {}", "Upload failed".red(), e),
    }
}

async fn handle_download(peer_api: &PeerAPI, identifier: String) {
    println!("Downloading file: {}", identifier.cyan());
    match peer_api.get_file(identifier).await {
        Ok(_) => println!("{}", "Download request sent!".green()),
        Err(e) => println!("{}: {}", "Download failed".red(), e),
    }
}

async fn handle_delete(peer_api: &PeerAPI, file_hash: String) {
    println!("Deleting file: {}", file_hash.cyan());
    match peer_api.delete_file(file_hash).await {
        Ok(_) => println!("{}", "File deleted successfully!".green()),
        Err(e) => println!("{}: {}", "Delete failed".red(), e),
    }
}

async fn handle_move(peer_api: &PeerAPI, file_hash: String, new_path: String) {
    println!("Moving file {} to {}", file_hash.cyan(), new_path.cyan());
    match peer_api.move_file(file_hash, new_path).await {
        Ok(_) => println!("{}", "File moved successfully!".green()),
        Err(e) => println!("{}: {}", "Move failed".red(), e),
    }
}

async fn handle_update(peer_api: &PeerAPI, file_hash: String, new_path: String, encrypt: bool, public: bool) {
    println!("Updating file: {}", file_hash.cyan());
    match peer_api.update_file(file_hash, new_path, encrypt, public, false).await {
        Ok(_) => println!("{}", "File updated successfully!".green()),
        Err(e) => println!("{}: {}", "Update failed".red(), e),
    }
}

async fn handle_set_public(peer_api: &PeerAPI, file_hash: String, public: bool) {
    let visibility = if public { "public" } else { "private" };
    println!("Setting file {} to {}", file_hash.cyan(), visibility);
    match peer_api.change_file_public_access(file_hash, public).await {
        Ok(_) => println!("{}", format!("File is now {}!", visibility).green()),
        Err(e) => println!("{}: {}", "Failed to change access".red(), e),
    }
}

fn handle_list_files(db: &P2PDatabase) {
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

// Network operation handlers
async fn handle_peers(peer_api: &PeerAPI) {
    println!("Requesting peer list...");
    match peer_api.request_peer_list().await {
        Ok(_) => println!("{}", "Peer list request sent!".green()),
        Err(e) => println!("{}: {}", "Failed to request peers".red(), e),
    }
}

async fn handle_search_peer(peer_api: &PeerAPI, peer_id: String) {
    println!("Searching for peer: {}", peer_id.cyan());
    match peer_api.search_peer(peer_id).await {
        Ok(_) => println!("{}", "Search request sent!".green()),
        Err(e) => println!("{}: {}", "Search failed".red(), e),
    }
}

async fn handle_connect(peer_api: &PeerAPI, peer_id: String) {
    println!("Connecting to peer: {}", peer_id.cyan());
    match peer_api.connect_to_peer(peer_id).await {
        Ok(_) => println!("{}", "Connection request sent!".green()),
        Err(e) => println!("{}: {}", "Connection failed".red(), e),
    }
}

async fn handle_message(peer_api: &PeerAPI, peer_id: String, text: String) {
    println!("Sending message to {}", peer_id.cyan());
    match peer_api.send_message(peer_id, text).await {
        Ok(_) => println!("{}", "Message sent!".green()),
        Err(e) => println!("{}: {}", "Failed to send message".red(), e),
    }
}

// Storage operation handlers
async fn handle_reserve(peer_api: &PeerAPI, size_mb: u64) {
    let size_bytes = size_mb * 1024 * 1024;
    println!("Reserving {} MB ({} bytes) of storage...", size_mb, size_bytes);
    match peer_api.reserve_storage(size_bytes).await {
        Ok(_) => println!("{}", "Storage reservation request sent!".green()),
        Err(e) => println!("{}: {}", "Reservation failed".red(), e),
    }
}

async fn handle_validate_token(peer_api: &PeerAPI, token: String) {
    println!("Validating token...");
    match peer_api.valid_token(token).await {
        Ok(_) => println!("{}", "Token validation request sent!".green()),
        Err(e) => println!("{}: {}", "Validation failed".red(), e),
    }
}

fn handle_list_tokens(db: &P2PDatabase) {
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

// Contract operation handlers
async fn handle_upload_contract(peer_api: &PeerAPI, path: String) {
    println!("Deploying contract: {}", path.cyan());
    match peer_api.upload_contract(path).await {
        Ok(_) => println!("{}", "Contract deployed successfully!".green()),
        Err(e) => println!("{}: {}", "Deployment failed".red(), e),
    }
}

async fn handle_call_contract(peer_api: &PeerAPI, hash: String, function: String, payload: String) {
    println!("Calling contract {} function {}", hash.cyan(), function.cyan());
    let payload_bytes = payload.into_bytes();
    match peer_api.call_contract(hash, function, payload_bytes).await {
        Ok(_) => println!("{}", "Contract call request sent!".green()),
        Err(e) => println!("{}: {}", "Contract call failed".red(), e),
    }
}

// Sync operation handlers
async fn handle_sync(peer_api: &PeerAPI) {
    println!("Synchronizing metadata with signal node...");
    match peer_api.sync_fragment_metadata().await {
        Ok(_) => println!("{}", "Sync request sent!".green()),
        Err(e) => println!("{}: {}", "Sync failed".red(), e),
    }
}
