use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignalServerInfo {
    pub public_key: String,
    pub public_ip: String,
    pub port: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignalServersList {
    pub servers: Vec<SignalServerInfo>,
}

impl SignalServersList {
    pub fn new() -> Self {
        SignalServersList {
            servers: Vec::new(),
        }
    }

    pub fn load_or_create() -> Result<Self, String> {
        let path = Path::new("signal_servers.json");
        if path.exists() {
            let content = fs::read_to_string(path)
                .map_err(|e| format!("Failed to read signal_servers.json: {}", e))?;
            serde_json::from_str(&content)
                .map_err(|e| format!("Failed to parse signal_servers.json: {}", e))
        } else {
            let list = SignalServersList::new();
            list.save()?;
            Ok(list)
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize signal servers list: {}", e))?;
        fs::write("signal_servers.json", content)
            .map_err(|e| format!("Failed to write signal_servers.json: {}", e))
    }

    pub fn add_server(&mut self, server: SignalServerInfo) -> Result<(), String> {
        if !self.servers.iter().any(|s| s.public_key == server.public_key) {
            self.servers.push(server);
            self.save()?;
        }
        Ok(())
    }
} 