use std::io::ErrorKind;

use super::config::StunConfig;
use stun_client::{Attribute, Client, STUNClientError};

pub struct StunClient {
    config: StunConfig,
}

fn stun_bind_addr_in_use(e: &STUNClientError) -> bool {
    matches!(e, STUNClientError::IOError(io) if io.kind() == ErrorKind::AddrInUse)
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

    pub async fn get_public_address(&self, port: u16) -> anyhow::Result<(String, u16)> {
        let bind_res = Client::new(format!("0.0.0.0:{}", port), None).await;
        let mut client = match bind_res {
            Ok(c) => c,
            Err(e) if stun_bind_addr_in_use(&e) => {
                crate::warn!(
                    "[STUN] cannot bind 0.0.0.0:{} ({}); using ephemeral local port (XOR mapped port may differ from UDP listener)",
                    port,
                    e
                );
                Client::new("0.0.0.0:0", None).await.map_err(|e2| {
                    anyhow::anyhow!("Failed to create STUN client (fallback): {:?}", e2)
                })?
            }
            Err(e) => return Err(anyhow::anyhow!("Failed to create STUN client: {:?}", e)),
        };

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

        let res = match last_res {
            Some(v) => v,
            None => {
                if let Some(e) = last_error {
                    return Err(anyhow::anyhow!(
                        "Failed to connect to any STUN server. Last error: {:?}",
                        e
                    ));
                }
                return Err(anyhow::anyhow!(
                    "Failed to connect to any STUN server and no error was recorded"
                ));
            }
        };

        let xor_mapped_addr = Attribute::get_xor_mapped_address(&res);
        if let Some(addr) = xor_mapped_addr {
            Ok((addr.ip().to_string(), addr.port()))
        } else {
            let mapped_addr = Attribute::get_mapped_address(&res);
            if let Some(addr) = mapped_addr {
                Ok((addr.ip().to_string(), addr.port()))
            } else {
                Err(anyhow::anyhow!(
                    "Failed to get XOR mapped address or Mapped address from STUN response: {:?}",
                    res
                ))
            }
        }
    }

    pub async fn get_public_ip(&self, port: u16) -> anyhow::Result<String> {
        let (ip, _) = self.get_public_address(port).await?;
        Ok(ip)
    }

    pub async fn get_public_port(&self, port: u16) -> anyhow::Result<u16> {
        let (_, port) = self.get_public_address(port).await?;
        Ok(port)
    }
}

impl Default for StunClient {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn get_public_address(port: u16) -> anyhow::Result<(String, u16)> {
    let client = StunClient::new();
    client.get_public_address(port).await
}

pub async fn get_public_address_with_servers(
    port: u16,
    custom_servers: Vec<String>,
) -> anyhow::Result<(String, u16)> {
    let config = StunConfig::with_servers(custom_servers);
    let client = StunClient::with_config(config);
    client.get_public_address(port).await
}
