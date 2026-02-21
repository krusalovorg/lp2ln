pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
    "stun3.l.google.com:19302",
    "stun4.l.google.com:19302",
    "stun.stunprotocol.org:3478",
    "stun.voipstunt.com:3478",
];

#[derive(Clone, Debug)]
pub struct StunConfig {
    servers: Vec<String>,
}

impl Default for StunConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl StunConfig {
    pub fn new() -> Self {
        Self {
            servers: DEFAULT_STUN_SERVERS
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }

    pub fn with_servers(custom_servers: Vec<String>) -> Self {
        let mut servers = DEFAULT_STUN_SERVERS
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<String>>();

        for server in custom_servers {
            if !servers.contains(&server) {
                servers.push(server);
            }
        }

        Self {
            servers,
        }
    }

    pub fn with_custom_servers_only(custom_servers: Vec<String>) -> Self {
        Self {
            servers: custom_servers,
        }
    }

    pub fn add_servers(&mut self, additional_servers: Vec<String>) {
        for server in additional_servers {
            if !self.servers.contains(&server) {
                self.servers.push(server);
            }
        }
    }

    pub fn get_servers(&self) -> &Vec<String> {
        &self.servers
    }
}