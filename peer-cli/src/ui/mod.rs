// UI utilities for the LP2LN Peer CLI
use colored::Colorize;

/// Print the CLI banner
pub fn print_banner() {
    println!("{}", r#"
+==============================================================+
|                                                              |
|   LP2LN   Light Protocol for Layered                         |
|           Peer Network - CLI Daemon                          |
|                                                              |
|   Type 'help' to see available commands                      |
|                                                              |
+==============================================================+
"#.cyan());
}

/// Print help information for all available commands
pub fn print_help() {
    println!("{}", "\n=== LP2LN Peer Daemon - Available Commands ===\n".green().bold());

    println!("{}", "INFORMATION".yellow().bold());
    println!("  {}  - Show this help message", "help".cyan());
    println!("  {}  - Display peer status and connection info", "status".cyan());
    println!("  {}  - Show detailed peer information", "info".cyan());

    println!("\n{}", "FILE OPERATIONS".yellow().bold());
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

    println!("\n{}", "NETWORK OPERATIONS".yellow().bold());
    println!("  {}  - Request list of connected peers", "peers".cyan());
    println!("  {} <peer_id>", "search".cyan());
    println!("         - Search for a specific peer");
    println!("  {} <peer_id>", "connect".cyan());
    println!("         - Establish direct connection to peer");
    println!("  {} <peer_id> <message>", "msg".cyan());
    println!("         - Send message to a peer");

    println!("\n{}", "STORAGE OPERATIONS".yellow().bold());
    println!("  {} <size_mb>", "reserve".cyan());
    println!("         - Reserve storage space (in MB)");
    println!("  {} <token>", "validate".cyan());
    println!("         - Validate a storage token");
    println!("  {}  - List all storage tokens", "tokens".cyan());

    println!("\n{}", "CONTRACT OPERATIONS".yellow().bold());
    println!("  {} <path.wasm>", "deploy".cyan());
    println!("         - Deploy a WASM smart contract");
    println!("  {} <contract_hash> <function> [payload]", "call".cyan());
    println!("         - Execute a contract function");

    println!("\n{}", "SYNCHRONIZATION".yellow().bold());
    println!("  {}  - Synchronize metadata with signal node", "sync".cyan());

    println!("\n{}", "EXIT".yellow().bold());
    println!("  {} / {}  - Exit the daemon", "exit".cyan(), "quit".cyan());

    println!();
}

/// Format byte size into human-readable string (B, KB, MB, GB)
pub fn format_size(bytes: u64) -> String {
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

/// Truncate a string to a maximum length, adding "..." if truncated
pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

/// Print the CLI prompt
pub fn print_prompt() {
    print!("{}", "lp2ln> ".green().bold());
}

/// Print connection info at startup
pub fn print_connection_info(peer_id: &str, signal_ip: &str, signal_port: i64) {
    println!("Your Peer ID: {}", peer_id.cyan());
    println!("Connected to: {}:{}", signal_ip.yellow(), signal_port.to_string().yellow());
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_size_bytes() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1023), "1023 B");
    }

    #[test]
    fn test_format_size_kilobytes() {
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(2048), "2.0 KB");
        assert_eq!(format_size(1536), "1.5 KB");
    }

    #[test]
    fn test_format_size_megabytes() {
        assert_eq!(format_size(1024 * 1024), "1.0 MB");
        assert_eq!(format_size(5 * 1024 * 1024), "5.0 MB");
    }

    #[test]
    fn test_format_size_gigabytes() {
        assert_eq!(format_size(1024 * 1024 * 1024), "1.00 GB");
        assert_eq!(format_size(2 * 1024 * 1024 * 1024), "2.00 GB");
    }

    #[test]
    fn test_truncate_string_short() {
        assert_eq!(truncate_string("hello", 10), "hello");
        assert_eq!(truncate_string("hello", 5), "hello");
    }

    #[test]
    fn test_truncate_string_long() {
        assert_eq!(truncate_string("hello world", 8), "hello...");
        assert_eq!(truncate_string("hello world and more", 10), "hello w...");
    }

    #[test]
    fn test_truncate_string_exact() {
        assert_eq!(truncate_string("abc", 3), "abc");
    }
}
