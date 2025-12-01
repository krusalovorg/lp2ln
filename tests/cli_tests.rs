#[cfg(test)]
mod tests {
    // Tests for CLI command parsing and utility functions
    // Note: These tests cover the command parsing logic used in the peer-cli daemon

    /// Test helper function for size formatting
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

    /// Test helper function for string truncation
    fn truncate_string(s: &str, max_len: usize) -> String {
        if s.len() <= max_len {
            s.to_string()
        } else {
            format!("{}...", &s[..max_len - 3])
        }
    }

    #[test]
    fn test_format_size_bytes() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(100), "100 B");
        assert_eq!(format_size(1023), "1023 B");
    }

    #[test]
    fn test_format_size_kilobytes() {
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1536), "1.5 KB");
        assert_eq!(format_size(10240), "10.0 KB");
    }

    #[test]
    fn test_format_size_megabytes() {
        assert_eq!(format_size(1024 * 1024), "1.0 MB");
        assert_eq!(format_size(1024 * 1024 * 10), "10.0 MB");
        assert_eq!(format_size(1024 * 1024 * 512), "512.0 MB");
    }

    #[test]
    fn test_format_size_gigabytes() {
        assert_eq!(format_size(1024 * 1024 * 1024), "1.00 GB");
        assert_eq!(format_size(1024 * 1024 * 1024 * 2), "2.00 GB");
    }

    #[test]
    fn test_truncate_string_short() {
        let short = "hello";
        assert_eq!(truncate_string(short, 10), "hello");
    }

    #[test]
    fn test_truncate_string_exact() {
        let exact = "hello";
        assert_eq!(truncate_string(exact, 5), "hello");
    }

    #[test]
    fn test_truncate_string_long() {
        let long = "this is a very long string that needs truncation";
        let truncated = truncate_string(long, 20);
        assert_eq!(truncated.len(), 20);
        assert!(truncated.ends_with("..."));
    }

    /// Command enum for testing
    #[derive(Debug, Clone, PartialEq)]
    enum TestCommand {
        Help,
        Status,
        Info,
        Upload { path: String, encrypt: bool, public: bool },
        UploadDir { path: String, encrypt: bool, public: bool },
        Download { identifier: String },
        Delete { file_hash: String },
        Move { file_hash: String, new_path: String },
        ListFiles,
        Peers,
        SearchPeer { peer_id: String },
        Connect { peer_id: String },
        Message { peer_id: String, text: String },
        Reserve { size_mb: u64 },
        ValidateToken { token: String },
        ListTokens,
        UploadContract { path: String },
        Sync,
        Exit,
        Unknown(String),
    }

    fn parse_test_command(input: &str) -> TestCommand {
        let parts: Vec<&str> = input.trim().split_whitespace().collect();

        if parts.is_empty() {
            return TestCommand::Unknown(String::new());
        }

        let cmd = parts[0].to_lowercase();

        match cmd.as_str() {
            "help" | "h" | "?" => TestCommand::Help,
            "status" => TestCommand::Status,
            "info" => TestCommand::Info,

            "upload" => {
                if parts.len() < 2 {
                    return TestCommand::Unknown(input.to_string());
                }
                let path = parts[1].to_string();
                let public = parts.contains(&"--public");
                let encrypt = !parts.contains(&"--no-encrypt");
                TestCommand::Upload { path, encrypt, public }
            }

            "upload-dir" | "uploaddir" => {
                if parts.len() < 2 {
                    return TestCommand::Unknown(input.to_string());
                }
                let path = parts[1].to_string();
                let public = parts.contains(&"--public");
                let encrypt = !parts.contains(&"--no-encrypt");
                TestCommand::UploadDir { path, encrypt, public }
            }

            "download" | "get" => {
                if parts.len() < 2 {
                    return TestCommand::Unknown(input.to_string());
                }
                TestCommand::Download { identifier: parts[1].to_string() }
            }

            "delete" | "rm" => {
                if parts.len() < 2 {
                    return TestCommand::Unknown(input.to_string());
                }
                TestCommand::Delete { file_hash: parts[1].to_string() }
            }

            "move" | "mv" => {
                if parts.len() < 3 {
                    return TestCommand::Unknown(input.to_string());
                }
                TestCommand::Move {
                    file_hash: parts[1].to_string(),
                    new_path: parts[2].to_string()
                }
            }

            "files" | "ls" | "list" => TestCommand::ListFiles,

            "peers" => TestCommand::Peers,

            "search" => {
                if parts.len() < 2 {
                    return TestCommand::Unknown(input.to_string());
                }
                TestCommand::SearchPeer { peer_id: parts[1].to_string() }
            }

            "connect" => {
                if parts.len() < 2 {
                    return TestCommand::Unknown(input.to_string());
                }
                TestCommand::Connect { peer_id: parts[1].to_string() }
            }

            "msg" | "message" | "send" => {
                if parts.len() < 3 {
                    return TestCommand::Unknown(input.to_string());
                }
                let peer_id = parts[1].to_string();
                let text = parts[2..].join(" ");
                TestCommand::Message { peer_id, text }
            }

            "reserve" => {
                if parts.len() < 2 {
                    return TestCommand::Unknown(input.to_string());
                }
                match parts[1].parse::<u64>() {
                    Ok(size_mb) => TestCommand::Reserve { size_mb },
                    Err(_) => TestCommand::Unknown(input.to_string()),
                }
            }

            "validate" => {
                if parts.len() < 2 {
                    return TestCommand::Unknown(input.to_string());
                }
                TestCommand::ValidateToken { token: parts[1].to_string() }
            }

            "tokens" => TestCommand::ListTokens,

            "deploy" => {
                if parts.len() < 2 {
                    return TestCommand::Unknown(input.to_string());
                }
                TestCommand::UploadContract { path: parts[1].to_string() }
            }

            "sync" => TestCommand::Sync,

            "exit" | "quit" | "q" => TestCommand::Exit,

            _ => TestCommand::Unknown(cmd),
        }
    }

    #[test]
    fn test_parse_help_commands() {
        assert_eq!(parse_test_command("help"), TestCommand::Help);
        assert_eq!(parse_test_command("h"), TestCommand::Help);
        assert_eq!(parse_test_command("?"), TestCommand::Help);
        assert_eq!(parse_test_command("HELP"), TestCommand::Help);
    }

    #[test]
    fn test_parse_status_info() {
        assert_eq!(parse_test_command("status"), TestCommand::Status);
        assert_eq!(parse_test_command("info"), TestCommand::Info);
    }

    #[test]
    fn test_parse_upload_command() {
        assert_eq!(
            parse_test_command("upload /path/to/file.txt"),
            TestCommand::Upload {
                path: "/path/to/file.txt".to_string(),
                encrypt: true,
                public: false,
            }
        );

        assert_eq!(
            parse_test_command("upload /path/to/file.txt --public"),
            TestCommand::Upload {
                path: "/path/to/file.txt".to_string(),
                encrypt: true,
                public: true,
            }
        );

        assert_eq!(
            parse_test_command("upload /path/to/file.txt --no-encrypt"),
            TestCommand::Upload {
                path: "/path/to/file.txt".to_string(),
                encrypt: false,
                public: false,
            }
        );

        assert_eq!(
            parse_test_command("upload /path/to/file.txt --public --no-encrypt"),
            TestCommand::Upload {
                path: "/path/to/file.txt".to_string(),
                encrypt: false,
                public: true,
            }
        );
    }

    #[test]
    fn test_parse_upload_dir_command() {
        assert_eq!(
            parse_test_command("upload-dir /path/to/dir"),
            TestCommand::UploadDir {
                path: "/path/to/dir".to_string(),
                encrypt: true,
                public: false,
            }
        );

        assert_eq!(
            parse_test_command("uploaddir /path/to/dir --public"),
            TestCommand::UploadDir {
                path: "/path/to/dir".to_string(),
                encrypt: true,
                public: true,
            }
        );
    }

    #[test]
    fn test_parse_download_command() {
        assert_eq!(
            parse_test_command("download abc123"),
            TestCommand::Download { identifier: "abc123".to_string() }
        );

        assert_eq!(
            parse_test_command("get abc123"),
            TestCommand::Download { identifier: "abc123".to_string() }
        );
    }

    #[test]
    fn test_parse_delete_command() {
        assert_eq!(
            parse_test_command("delete abc123"),
            TestCommand::Delete { file_hash: "abc123".to_string() }
        );

        assert_eq!(
            parse_test_command("rm abc123"),
            TestCommand::Delete { file_hash: "abc123".to_string() }
        );
    }

    #[test]
    fn test_parse_move_command() {
        assert_eq!(
            parse_test_command("move abc123 /new/path"),
            TestCommand::Move {
                file_hash: "abc123".to_string(),
                new_path: "/new/path".to_string(),
            }
        );

        assert_eq!(
            parse_test_command("mv abc123 /new/path"),
            TestCommand::Move {
                file_hash: "abc123".to_string(),
                new_path: "/new/path".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_list_files() {
        assert_eq!(parse_test_command("files"), TestCommand::ListFiles);
        assert_eq!(parse_test_command("ls"), TestCommand::ListFiles);
        assert_eq!(parse_test_command("list"), TestCommand::ListFiles);
    }

    #[test]
    fn test_parse_network_commands() {
        assert_eq!(parse_test_command("peers"), TestCommand::Peers);

        assert_eq!(
            parse_test_command("search peer123"),
            TestCommand::SearchPeer { peer_id: "peer123".to_string() }
        );

        assert_eq!(
            parse_test_command("connect peer123"),
            TestCommand::Connect { peer_id: "peer123".to_string() }
        );
    }

    #[test]
    fn test_parse_message_command() {
        assert_eq!(
            parse_test_command("msg peer123 Hello world"),
            TestCommand::Message {
                peer_id: "peer123".to_string(),
                text: "Hello world".to_string(),
            }
        );

        assert_eq!(
            parse_test_command("message peer123 Test message"),
            TestCommand::Message {
                peer_id: "peer123".to_string(),
                text: "Test message".to_string(),
            }
        );

        assert_eq!(
            parse_test_command("send peer123 Multi word message here"),
            TestCommand::Message {
                peer_id: "peer123".to_string(),
                text: "Multi word message here".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_reserve_command() {
        assert_eq!(
            parse_test_command("reserve 100"),
            TestCommand::Reserve { size_mb: 100 }
        );

        assert_eq!(
            parse_test_command("reserve 1024"),
            TestCommand::Reserve { size_mb: 1024 }
        );

        // Invalid size should return Unknown
        match parse_test_command("reserve invalid") {
            TestCommand::Unknown(_) => {}
            _ => panic!("Expected Unknown command for invalid reserve size"),
        }
    }

    #[test]
    fn test_parse_validate_token() {
        assert_eq!(
            parse_test_command("validate token123abc"),
            TestCommand::ValidateToken { token: "token123abc".to_string() }
        );
    }

    #[test]
    fn test_parse_tokens_command() {
        assert_eq!(parse_test_command("tokens"), TestCommand::ListTokens);
    }

    #[test]
    fn test_parse_deploy_command() {
        assert_eq!(
            parse_test_command("deploy /path/to/contract.wasm"),
            TestCommand::UploadContract { path: "/path/to/contract.wasm".to_string() }
        );
    }

    #[test]
    fn test_parse_sync_command() {
        assert_eq!(parse_test_command("sync"), TestCommand::Sync);
    }

    #[test]
    fn test_parse_exit_commands() {
        assert_eq!(parse_test_command("exit"), TestCommand::Exit);
        assert_eq!(parse_test_command("quit"), TestCommand::Exit);
        assert_eq!(parse_test_command("q"), TestCommand::Exit);
    }

    #[test]
    fn test_parse_unknown_command() {
        match parse_test_command("unknowncommand") {
            TestCommand::Unknown(cmd) => assert_eq!(cmd, "unknowncommand"),
            _ => panic!("Expected Unknown command"),
        }
    }

    #[test]
    fn test_parse_empty_input() {
        match parse_test_command("") {
            TestCommand::Unknown(s) => assert!(s.is_empty()),
            _ => panic!("Expected Unknown command for empty input"),
        }

        match parse_test_command("   ") {
            TestCommand::Unknown(s) => assert!(s.is_empty()),
            _ => panic!("Expected Unknown command for whitespace input"),
        }
    }

    #[test]
    fn test_parse_missing_arguments() {
        // Upload without path
        match parse_test_command("upload") {
            TestCommand::Unknown(_) => {}
            _ => panic!("Expected Unknown for upload without path"),
        }

        // Download without identifier
        match parse_test_command("download") {
            TestCommand::Unknown(_) => {}
            _ => panic!("Expected Unknown for download without identifier"),
        }

        // Move without both arguments
        match parse_test_command("move abc123") {
            TestCommand::Unknown(_) => {}
            _ => panic!("Expected Unknown for move without new_path"),
        }

        // Message without text
        match parse_test_command("msg peer123") {
            TestCommand::Unknown(_) => {}
            _ => panic!("Expected Unknown for message without text"),
        }

        // Reserve without size
        match parse_test_command("reserve") {
            TestCommand::Unknown(_) => {}
            _ => panic!("Expected Unknown for reserve without size"),
        }
    }

    #[test]
    fn test_case_insensitivity() {
        assert_eq!(parse_test_command("UPLOAD /path"), TestCommand::Upload {
            path: "/path".to_string(),
            encrypt: true,
            public: false,
        });
        assert_eq!(parse_test_command("Upload /path"), TestCommand::Upload {
            path: "/path".to_string(),
            encrypt: true,
            public: false,
        });
        assert_eq!(parse_test_command("STATUS"), TestCommand::Status);
        assert_eq!(parse_test_command("Status"), TestCommand::Status);
    }
}
