use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::crypto::NodeKeypair;
use crate::logger::LoggerOptions;

#[derive(Clone)]
pub struct NodeOptions {
    pub listens: DashMap<String, SocketAddr>,
    pub default_nodes: Vec<SocketAddr>,
    pub keypair: Option<NodeKeypair>,
    pub allow_unsigned_packets: bool,
    pub logger_options: Option<LoggerOptions>,
}

impl NodeOptions {
    pub fn new() -> Self {
        let mut options = Self {
            listens: DashMap::new(),
            default_nodes: vec![],
            keypair: Some(NodeKeypair::generate()),
            allow_unsigned_packets: true,
            logger_options: Some(LoggerOptions {
                log_dir: Some(PathBuf::from("./logs")),
                file_enabled: true,
                show_debug: true,
                show_info: true,
                show_warning: true,
                show_error: true,
            }),
        };
        options.default_listens();
        options
    }

    pub fn empty() -> Self {
        Self {
            listens: DashMap::new(),
            default_nodes: vec![],
            keypair: None,
            allow_unsigned_packets: true,
            logger_options: Some(LoggerOptions::default()),
        }
    }

    pub fn keypair(mut self, keypair: NodeKeypair) -> Self {
        self.keypair = Some(keypair);
        self
    }

    pub fn keypair_from_hex(mut self, hex: &str) -> Result<Self, String> {
        self.keypair = Some(NodeKeypair::from_hex(hex)?);
        Ok(self)
    }

    pub fn keypair_generate(mut self) -> Self {
        self.keypair = Some(NodeKeypair::generate());
        self
    }

    pub fn allow_unsigned_packets(mut self, allow: bool) -> Self {
        self.allow_unsigned_packets = allow;
        self
    }

    pub fn default_listens(&mut self) -> &mut Self {
        self.set_listen(
            "tcp".to_string(),
            "0.0.0.0:8080".parse::<SocketAddr>().unwrap(),
        );
        self.set_listen(
            "udp".to_string(),
            "0.0.0.0:8081".parse::<SocketAddr>().unwrap(),
        );
        self
    }

    pub fn set_listen(&mut self, protocol: String, addr: SocketAddr) -> &mut Self {
        self.listens.insert(protocol, addr);
        self
    }

    pub fn with_listen(self, protocol: impl Into<String>, addr: SocketAddr) -> Self {
        self.listens.insert(protocol.into(), addr);
        self
    }

    pub fn with_default_nodes(mut self, nodes: Vec<SocketAddr>) -> Self {
        self.default_nodes = nodes;
        self
    }

    pub fn with_logger_options(mut self, opts: LoggerOptions) -> Self {
        self.logger_options = Some(opts);
        self
    }

    pub fn add_node(&mut self, node: SocketAddr) -> &mut Self {
        self.default_nodes.push(node);
        self
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        let data = fs::read_to_string(path).map_err(|e| e.to_string())?;
        Self::from_json(&data)
    }

    pub fn from_json(s: &str) -> Result<Self, String> {
        let file: NodeOptionsFile = serde_json::from_str(s).map_err(|e| e.to_string())?;
        file.try_into()
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), String> {
        let file: NodeOptionsFile = self.into();
        let data = serde_json::to_string_pretty(&file).map_err(|e| e.to_string())?;
        fs::write(path.as_ref(), data).map_err(|e| e.to_string())?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LoggerOptionsFile {
    #[serde(default, alias = "file_path")]
    log_dir: Option<String>,
    #[serde(default = "default_true")]
    file_enabled: bool,
    #[serde(default = "default_true")]
    show_debug: bool,
    #[serde(default = "default_true")]
    show_info: bool,
    #[serde(default = "default_true")]
    show_warning: bool,
    #[serde(default = "default_true")]
    show_error: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NodeOptionsFile {
    #[serde(default)]
    listens: HashMap<String, String>,
    #[serde(default)]
    default_nodes: Vec<String>,
    private_key_hex: Option<String>,
    #[serde(default = "default_allow_unsigned")]
    allow_unsigned_packets: bool,
    #[serde(default)]
    logger_options: Option<LoggerOptionsFile>,
}

fn default_allow_unsigned() -> bool {
    true
}

impl From<LoggerOptionsFile> for LoggerOptions {
    fn from(f: LoggerOptionsFile) -> Self {
        let log_dir = f.log_dir.map(|s| {
            let p = PathBuf::from(&s);
            if p.extension().is_some() {
                p.parent().unwrap_or(&p).to_path_buf()
            } else {
                p
            }
        });
        Self {
            log_dir,
            file_enabled: f.file_enabled,
            show_debug: f.show_debug,
            show_info: f.show_info,
            show_warning: f.show_warning,
            show_error: f.show_error,
        }
    }
}

impl From<&LoggerOptions> for LoggerOptionsFile {
    fn from(o: &LoggerOptions) -> Self {
        Self {
            log_dir: o.log_dir.as_ref().map(|p| p.to_string_lossy().into_owned()),
            file_enabled: o.file_enabled,
            show_debug: o.show_debug,
            show_info: o.show_info,
            show_warning: o.show_warning,
            show_error: o.show_error,
        }
    }
}

impl TryFrom<NodeOptionsFile> for NodeOptions {
    type Error = String;

    fn try_from(file: NodeOptionsFile) -> Result<Self, String> {
        let mut options = Self {
            listens: DashMap::new(),
            default_nodes: vec![],
            keypair: None,
            allow_unsigned_packets: file.allow_unsigned_packets,
            logger_options: file.logger_options.map(LoggerOptions::from),
        };
        for (protocol, addr_str) in file.listens {
            let addr: SocketAddr = addr_str
                .parse()
                .map_err(|e: std::net::AddrParseError| e.to_string())?;
            options.listens.insert(protocol, addr);
        }
        for addr_str in file.default_nodes {
            let addr: SocketAddr = addr_str
                .parse()
                .map_err(|e: std::net::AddrParseError| e.to_string())?;
            options.default_nodes.push(addr);
        }
        if let Some(hex) = file.private_key_hex {
            options.keypair = Some(NodeKeypair::from_hex(&hex)?);
        }
        Ok(options)
    }
}

impl From<&NodeOptions> for NodeOptionsFile {
    fn from(opts: &NodeOptions) -> Self {
        let listens: HashMap<String, String> = opts
            .listens
            .iter()
            .map(|r| (r.key().clone(), r.value().to_string()))
            .collect();
        let default_nodes: Vec<String> = opts
            .default_nodes
            .iter()
            .map(SocketAddr::to_string)
            .collect();
        let private_key_hex = opts.keypair.as_ref().map(|k| k.to_hex());
        let logger_options = Some(
            opts.logger_options
                .as_ref()
                .map(LoggerOptionsFile::from)
                .unwrap_or_else(|| LoggerOptionsFile::from(&LoggerOptions::default())),
        );
        Self {
            listens,
            default_nodes,
            private_key_hex,
            allow_unsigned_packets: opts.allow_unsigned_packets,
            logger_options,
        }
    }
}
