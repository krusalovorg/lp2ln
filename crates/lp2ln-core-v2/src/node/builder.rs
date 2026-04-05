use std::sync::Arc;
use crate::db::P2PDatabase;
use crate::node::options::NodeOptions;
use crate::node::runtime::NodeRuntime;
use crate::transport::Transport;
use crate::packet_processor::PacketProcessor;
use anyhow::Result;

pub struct NodeBuilder {
    db: Option<Arc<P2PDatabase>>,
    transports: Vec<Arc<dyn Transport>>,
    packet_processor: Option<Arc<dyn PacketProcessor>>,
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