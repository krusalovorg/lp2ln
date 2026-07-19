use crate::db::P2PDatabase;
use crate::node::options::NodeOptions;
use crate::node::runtime::NodeRuntime;
use crate::packet_processor::PacketProcessor;
use crate::transport::Transport;
use crate::transport::quic::QuicTransport;
use crate::transport::tcp::TcpTransport;
use crate::transport::udp::UdpTransport;
use anyhow::Result;
use std::sync::Arc;

pub struct NodeBuilder {
    db: Option<Arc<P2PDatabase>>,
    transports: Vec<Arc<dyn Transport>>,
    packet_processor: Option<Arc<dyn PacketProcessor>>,
}

impl Default for NodeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeBuilder {
    pub fn new() -> Self {
        Self {
            db: None,
            transports: vec![],
            packet_processor: None,
        }
    }

    pub fn db(mut self, db: Arc<P2PDatabase>) -> Self {
        self.db = Some(db);
        self
    }

    pub fn add_transport(mut self, transport: Arc<dyn Transport>) -> Self {
        self.transports.push(transport);
        self
    }

    pub fn add_default_transports_from_options(mut self, options: &NodeOptions) -> Self {
        let tcp_transport = if let Some(cfg) = options.transport_obfuscation_for("tcp") {
            Arc::new(TcpTransport::new_listener_with_obfuscation(None, cfg)) as Arc<dyn Transport>
        } else {
            Arc::new(TcpTransport::new()) as Arc<dyn Transport>
        };
        self.transports.push(tcp_transport);

        let udp_transport = if let Some(cfg) = options.transport_obfuscation_for("udp") {
            Arc::new(UdpTransport::new_listener_with_obfuscation(
                "0.0.0.0:8081".parse().expect("valid socket addr"),
                cfg,
            )) as Arc<dyn Transport>
        } else {
            Arc::new(UdpTransport::new()) as Arc<dyn Transport>
        };
        self.transports.push(udp_transport);

        if options.listens.contains_key("quic") {
            let listen_addr = options.listens.get("quic").map(|r| *r);
            let quic_transport = Arc::new(QuicTransport::new_listener(
                listen_addr,
                options.quic.clone(),
            )) as Arc<dyn Transport>;
            self.transports.push(quic_transport);
        }

        self
    }

    pub fn packet_processor(mut self, processor: Arc<dyn PacketProcessor>) -> Self {
        self.packet_processor = Some(processor);
        self
    }

    pub fn build(self, options: NodeOptions) -> Result<NodeRuntime> {
        let mut runtime = NodeRuntime::new(self.db, options, self.packet_processor);

        for transport in self.transports {
            runtime = runtime.add_transport(transport);
        }
        crate::info!("[NodeBuilder] Node runtime built");
        Ok(runtime)
    }
}
