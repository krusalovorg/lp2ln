use stun_client::{Attribute, Client};
use super::config::StunConfig;

pub struct StunClient {
    config: StunConfig,
}

impl StunClient {
    pub fn new() -> Self {
        Self {
            config: StunConfig::new(),
        }
    }

    pub fn with_config(config: StunConfig) -> Self {
        Self { config }
    }

    pub fn get_servers(&self) -> Vec<String> {
        self.config.get_servers().clone()
    }

    pub async fn get_public_address(&self, port: u16) -> (String, u16) {
        let client = Client::new(format!("0.0.0.0:{}", port), None).await;
        if let Err(e) = client {
            panic!("Failed to create STUN client: {:?}", e);
        }
        let mut client = client.unwrap();

        let stun_servers = self.get_servers();
        let mut last_error = None;
        let mut last_res = None;

        for server in stun_servers {
            let res = client.binding_request(&server, None).await;
            match res {
                Ok(response) => {
                    crate::info!("[STUN] Successfully connected to server: {}", server);
                    last_res = Some(response);
                    break;
                }
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            }
        }

        if last_res.is_none() {
            if let Some(e) = last_error {
                panic!(
                    "Failed to connect to any STUN server. Last error: {:?}",
                    e
                );
            } else {
                panic!("Failed to connect to any STUN server and no error was recorded");
            }
        }

        let res = last_res.unwrap();

        let xor_mapped_addr = Attribute::get_xor_mapped_address(&res);
        if let Some(addr) = xor_mapped_addr {
            (addr.ip().to_string(), addr.port())
        } else {
            let mapped_addr = Attribute::get_mapped_address(&res);
            if let Some(addr) = mapped_addr {
                (addr.ip().to_string(), addr.port())
            } else {
                panic!(
                    "Failed to get XOR mapped address or Mapped address from STUN response: {:?}",
                    res
                );
            }
        }
    }

    pub async fn get_public_ip(&self, port: u16) -> String {
        let (ip, _) = self.get_public_address(port).await;
        ip
    }

    pub async fn get_public_port(&self, port: u16) -> u16 {
        let (_, port) = self.get_public_address(port).await;
        port
    }
}

impl Default for StunClient {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn get_public_address(port: u16) -> (String, u16) {
    let client = StunClient::new();
    client.get_public_address(port).await
}

pub async fn get_public_address_with_servers(
    port: u16,
    custom_servers: Vec<String>,
) -> (String, u16) {
    let config = StunConfig::with_servers(custom_servers);
    let client = StunClient::with_config(config);
    client.get_public_address(port).await
}
