// Command definitions and parsing for the LP2LN Peer CLI
use colored::Colorize;

/// CLI command structure representing all available operations
#[derive(Debug, Clone)]
pub enum Command {
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

/// Parse user input string into a Command
pub fn parse_command(input: &str) -> Command {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_help() {
        assert!(matches!(parse_command("help"), Command::Help));
        assert!(matches!(parse_command("h"), Command::Help));
        assert!(matches!(parse_command("?"), Command::Help));
    }

    #[test]
    fn test_parse_status() {
        assert!(matches!(parse_command("status"), Command::Status));
    }

    #[test]
    fn test_parse_info() {
        assert!(matches!(parse_command("info"), Command::Info));
    }

    #[test]
    fn test_parse_upload() {
        if let Command::Upload { path, encrypt, public } = parse_command("upload /path/to/file") {
            assert_eq!(path, "/path/to/file");
            assert!(encrypt);
            assert!(!public);
        } else {
            panic!("Expected Upload command");
        }
    }

    #[test]
    fn test_parse_upload_with_flags() {
        if let Command::Upload { path, encrypt, public } = parse_command("upload /path/to/file --public --no-encrypt") {
            assert_eq!(path, "/path/to/file");
            assert!(!encrypt);
            assert!(public);
        } else {
            panic!("Expected Upload command");
        }
    }

    #[test]
    fn test_parse_download() {
        if let Command::Download { identifier } = parse_command("download abc123") {
            assert_eq!(identifier, "abc123");
        } else {
            panic!("Expected Download command");
        }

        if let Command::Download { identifier } = parse_command("get abc123") {
            assert_eq!(identifier, "abc123");
        } else {
            panic!("Expected Download command with 'get' alias");
        }
    }

    #[test]
    fn test_parse_delete() {
        if let Command::Delete { file_hash } = parse_command("delete abc123") {
            assert_eq!(file_hash, "abc123");
        } else {
            panic!("Expected Delete command");
        }

        if let Command::Delete { file_hash } = parse_command("rm abc123") {
            assert_eq!(file_hash, "abc123");
        } else {
            panic!("Expected Delete command with 'rm' alias");
        }
    }

    #[test]
    fn test_parse_move() {
        if let Command::Move { file_hash, new_path } = parse_command("move abc123 /new/path") {
            assert_eq!(file_hash, "abc123");
            assert_eq!(new_path, "/new/path");
        } else {
            panic!("Expected Move command");
        }
    }

    #[test]
    fn test_parse_files() {
        assert!(matches!(parse_command("files"), Command::ListFiles));
        assert!(matches!(parse_command("ls"), Command::ListFiles));
        assert!(matches!(parse_command("list"), Command::ListFiles));
    }

    #[test]
    fn test_parse_peers() {
        assert!(matches!(parse_command("peers"), Command::Peers));
    }

    #[test]
    fn test_parse_message() {
        if let Command::Message { peer_id, text } = parse_command("msg peer123 Hello World!") {
            assert_eq!(peer_id, "peer123");
            assert_eq!(text, "Hello World!");
        } else {
            panic!("Expected Message command");
        }
    }

    #[test]
    fn test_parse_reserve() {
        if let Command::Reserve { size_mb } = parse_command("reserve 100") {
            assert_eq!(size_mb, 100);
        } else {
            panic!("Expected Reserve command");
        }
    }

    #[test]
    fn test_parse_tokens() {
        assert!(matches!(parse_command("tokens"), Command::ListTokens));
    }

    #[test]
    fn test_parse_deploy() {
        if let Command::UploadContract { path } = parse_command("deploy /path/to/contract.wasm") {
            assert_eq!(path, "/path/to/contract.wasm");
        } else {
            panic!("Expected UploadContract command");
        }
    }

    #[test]
    fn test_parse_call() {
        if let Command::CallContract { hash, function, payload } = parse_command("call abc123 execute arg1 arg2") {
            assert_eq!(hash, "abc123");
            assert_eq!(function, "execute");
            assert_eq!(payload, "arg1 arg2");
        } else {
            panic!("Expected CallContract command");
        }
    }

    #[test]
    fn test_parse_sync() {
        assert!(matches!(parse_command("sync"), Command::Sync));
    }

    #[test]
    fn test_parse_exit() {
        assert!(matches!(parse_command("exit"), Command::Exit));
        assert!(matches!(parse_command("quit"), Command::Exit));
        assert!(matches!(parse_command("q"), Command::Exit));
    }

    #[test]
    fn test_parse_unknown() {
        assert!(matches!(parse_command("unknown_cmd"), Command::Unknown(_)));
    }

    #[test]
    fn test_parse_empty() {
        assert!(matches!(parse_command(""), Command::Unknown(_)));
        assert!(matches!(parse_command("   "), Command::Unknown(_)));
    }
}
