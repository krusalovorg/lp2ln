use std::sync::Arc;
use crate::crypto::NodeKeypair;
use crate::db::P2PDatabase;
use crate::node::options::NodeOptions;
use crate::transport::Transport;
use crate::transport::TransportContext;
use crate::sessions::Session;
use crate::sessions::manager::SessionManager;
use crate::packet_processor::{PacketProcessor, DefaultPacketProcessor};
use crate::router::Router;
use crate::packet::Packet;
use crate::sessions::LinkKind;
use crate::sessions::SessionMetrics;
use crate::types::PeerId;
use crate::types::SessionId;
use crate::logger;
use tokio::sync::mpsc;
use anyhow::Result;
use std::net::SocketAddr;

pub struct NodeRuntime {
    _db: Option<Arc<P2PDatabase>>,
    _options: NodeOptions,
    keypair: NodeKeypair,
    transports: Vec<Arc<dyn Transport>>,
    packet_processor: Arc<dyn PacketProcessor>,
    session_manager: Arc<SessionManager>,
    router: Option<Arc<Router>>,
    incoming_sessions_tx: Option<mpsc::Sender<Arc<dyn Session>>>,
}

impl NodeRuntime {
    pub fn new(
        db: Option<Arc<P2PDatabase>>,
        options: NodeOptions,
        packet_processor: Option<Arc<dyn PacketProcessor>>,
    ) -> Self {
        if let Some(ref opts) = options.logger_options {
            logger::init(opts);
        }
        let keypair = options
            .keypair
            .or_else(|| {
                db.as_ref().and_then(|db| {
                    db.get_or_create_node_keypair().ok()
                })
            })
            .unwrap_or_else(NodeKeypair::generate);
        let packet_processor = packet_processor.unwrap_or_else(|| {
            Arc::new(DefaultPacketProcessor::new(
                keypair.peer_id().to_string(),
                options.allow_unsigned_packets,
            )) as Arc<dyn PacketProcessor>
        });
        Self {
            _db: db,
            _options: NodeOptions {
                listens: options.listens,
                default_nodes: options.default_nodes,
                keypair: None,
                allow_unsigned_packets: options.allow_unsigned_packets,
                logger_options: options.logger_options,
            },
            keypair,
            transports: vec![],
            packet_processor,
            session_manager: Arc::new(SessionManager::new()),
            router: None,
            incoming_sessions_tx: None,
        }
    }

    pub fn add_transport(mut self, transport: Arc<dyn Transport>) -> Self {
        self.transports.push(transport);
        self
    }

    pub async fn dial(&self, transport_name: &str, addr: SocketAddr) -> Result<Arc<dyn Session>> {
        let transport = self
            .transports
            .iter()
            .find(|t| t.name() == transport_name)
            .ok_or_else(|| anyhow::anyhow!("Transport '{}' is not registered in runtime", transport_name))?;

        transport.dial(addr).await
    }

    pub async fn connect(&self, transport_name: &str, addr: SocketAddr) -> Result<SessionId> {
        let router = self
            .router
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Node is not started, call start() first"))?;

        let session = self.dial(transport_name, addr).await?;

        let session_id = SessionId::from(session.id().to_string());
        router.register_session_only(session_id.clone(), session.clone());
        session.spawn_reader(router.incoming_sender());

        let handshake = Packet {
            signature: None,
            data: vec![],
            nodes: vec![],
            sender: self.keypair.peer_id().to_string(),
            receiver: String::new(),
            max_hops: 8,
            chunk_stream_id: None,
            chunk_index: None,
            total_chunks: None,
        };
        router.send_to_session(session_id.clone(), handshake).await?;

        Ok(session_id)
    }

    pub async fn send(&self, peer_id: PeerId, data: Vec<u8>) -> Result<()> {
        let router = self
            .router
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Node is not started, call start() first"))?;

        let sender = self.keypair.peer_id();

        let packet = Packet {
            signature: None,
            data,
            nodes: vec![],
            sender: sender.to_string(),
            receiver: peer_id.as_str().to_string(),
            max_hops: 8,
            chunk_stream_id: None,
            chunk_index: None,
            total_chunks: None,
        };

        router.send_to_peer(peer_id, packet, None).await
    }

    pub async fn send_to_session(&self, session_id: SessionId, data: Vec<u8>) -> Result<()> {
        let router = self
            .router
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Node is not started, call start() first"))?;

        let sender = self.keypair.peer_id();
        let packet = Packet {
            signature: None,
            data,
            nodes: vec![],
            sender: sender.to_string(),
            receiver: sender.to_string(),
            max_hops: 8,
            chunk_stream_id: None,
            chunk_index: None,
            total_chunks: None,
        };
        router.send_to_session(session_id, packet).await
    }

    pub fn router(&self) -> Option<Arc<Router>> {
        self.router.clone()
    }

    pub fn peer_id(&self) -> &str {
        self.keypair.peer_id()
    }

    pub fn get_metrics_for_protocol(&self, kind: LinkKind) -> Vec<SessionMetrics> {
        self.session_manager.get_metrics_for_protocol(kind)
    }

    pub fn get_metrics_by_protocol(&self) -> Vec<(LinkKind, Vec<SessionMetrics>)> {
        self.session_manager.get_metrics_by_protocol()
    }

    pub async fn start(&mut self) -> Result<()> {
        let (incoming_sessions_tx, mut incoming_sessions_rx) = mpsc::channel(1024);
        let signing_key = Some(Arc::new(self.keypair.signing_key().clone()));
        let router = {
            let (router, incoming_packets_rx) = Router::new(
                self.session_manager.clone(),
                self.packet_processor.clone(),
                signing_key,
                self.keypair.peer_id(),
            );
            let router = Arc::new(router);
            tokio::spawn(router.clone().run(incoming_packets_rx));
            router
        };
        self.router = Some(router.clone());

        self.incoming_sessions_tx = Some(incoming_sessions_tx.clone());
        let ctx = TransportContext {
            incoming_sessions_tx: incoming_sessions_tx.clone(),
            incoming_packets_tx: router.incoming_sender(),
            listen_addr: None,
        };

        if self.transports.is_empty() {
            crate::error!("[NodeRuntime] No transports registered");
            return Err(anyhow::anyhow!("No transports registered"));
        }

        for transport in &self.transports {
            if !transport.is_listener() {
                continue;
            }
            let listen_addr = self._options.listens.get(transport.name()).map(|r| *r);
            let ctx_clone = TransportContext {
                incoming_sessions_tx: ctx.incoming_sessions_tx.clone(),
                incoming_packets_tx: ctx.incoming_packets_tx.clone(),
                listen_addr,
            };
            let transport_clone = transport.clone();
            let transport_name = transport.name();
            
            tokio::spawn(async move {
                if let Err(e) = transport_clone.start(ctx_clone).await {
                    crate::error!("[NodeRuntime] Failed to start transport {}: {}", transport_name, e);
                } else {
                    crate::info!("[NodeRuntime] Transport {} started on {}", transport_name, listen_addr.unwrap());
                }
            });
        }

        let session_manager = self.session_manager.clone();
        let incoming_packets_tx_for_sessions = router.incoming_sender();
        let router_for_incoming = router.clone();
        let our_peer_id_for_incoming = self.keypair.peer_id().to_string();
        tokio::spawn(async move {
            while let Some(session) = incoming_sessions_rx.recv().await {
                crate::session!("[NodeRuntime] New session: {} (kind: {:?})", session.id(), session.kind());

                let session_id = SessionId::from(session.id().to_string());
                if let Some(peer_id) = session.peer_id() {
                    session_manager.register(
                        PeerId::from(peer_id.to_string()),
                        session_id.clone(),
                        session.clone(),
                    );
                } else {
                    session_manager.register_session(session_id.clone(), session.clone());
                }

                session.clone().spawn_reader(incoming_packets_tx_for_sessions.clone());

                if session.peer_id().is_some() {
                    let peer_id_str = session.peer_id().unwrap().to_string();
                    let ack = Packet {
                        signature: None,
                        data: vec![],
                        nodes: vec![],
                        sender: our_peer_id_for_incoming.clone(),
                        receiver: peer_id_str,
                        max_hops: 1,
                        chunk_stream_id: None,
                        chunk_index: None,
                        total_chunks: None,
                    };
                    if let Err(e) = router_for_incoming.send_to_session(session_id, ack).await {
                        crate::error!("[NodeRuntime] Failed to send handshake ack to incoming session: {}", e);
                    }
                }
            }
        });

        let default_nodes = self._options.default_nodes.clone();
        let transports = self.transports.clone();
        let router_outgoing = router.clone();
        let incoming_packets_tx_outgoing = router.incoming_sender();
        let our_peer_id = self.keypair.peer_id().to_string();
        tokio::spawn(async move {
            for addr in default_nodes {
                for transport in &transports {
                    if !transport.is_listener() {
                        continue;
                    }
                    match transport.dial(addr).await {
                        Ok(session) => {
                            crate::info!("[NodeRuntime] Connected to default node {} via {}", addr, transport.name());
                            let session_id = SessionId::from(session.id().to_string());
                            router_outgoing.register_session_only(session_id.clone(), session.clone());
                            session.spawn_reader(incoming_packets_tx_outgoing.clone());
                            let handshake = Packet {
                                signature: None,
                                data: vec![],
                                nodes: vec![],
                                sender: our_peer_id.clone(),
                                receiver: String::new(),
                                max_hops: 8,
                                chunk_stream_id: None,
                                chunk_index: None,
                                total_chunks: None,
                            };
                            if let Err(e) = router_outgoing.send_to_session(session_id, handshake).await {
                                crate::error!("[NodeRuntime] Failed to send handshake to {}: {}", addr, e);
                            }
                            break;
                        }
                        Err(e) => {
                            crate::error!("[NodeRuntime] Failed to dial {} via {}: {}", addr, transport.name(), e);
                        }
                    }
                }
            }
        });

        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        for transport in &self.transports {
            transport.stop().await?;
            crate::info!("[NodeRuntime] Stopped transport: {}", transport.name());
        }
        Ok(())
    }
}