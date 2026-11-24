use crate::sessions::Session;
use crate::sessions::session::LinkKind;
use crate::transport::obfuscation::{ObfuscationConfig, Obfuscator};
use crate::transport::tcp::session::TcpSession;
use crate::transport::transport::TransportContext;
use crate::transport::{
    ACCEPT_TASK_JOIN_TIMEOUT, Transport, bind_with_port_fallback, join_accept_task,
};
use anyhow::Result;
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// Upper bound for reading the client's hello on an accepted connection.
const INCOMING_HANDSHAKE_LIMIT: usize = 64;
const INCOMING_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

async fn handle_incoming(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    obfuscator: Arc<Obfuscator>,
    incoming_sessions_tx: tokio::sync::mpsc::Sender<Arc<dyn Session>>,
    _pre_auth: Option<crate::router::admission::IngressPermit>,
) {
    let handshake = tokio::time::timeout(
        INCOMING_HANDSHAKE_TIMEOUT,
        TcpSession::perform_handshake_on_stream(&mut stream, obfuscator.as_ref()),
    )
    .await;
    let peer_id = match handshake {
        Ok(Ok(peer_id)) => {
            crate::info!("[TcpTransport] Handshake successful, peer_id: {}", peer_id);
            peer_id
        }
        Ok(Err(e)) => {
            crate::error!("[TcpTransport] Handshake from {} failed: {}", peer_addr, e);
            return;
        }
        Err(_) => {
            crate::warn!("[TcpTransport] Handshake from {} timed out", peer_addr);
            return;
        }
    };

    let Ok(Ok(slot)) =
        tokio::time::timeout(INCOMING_HANDSHAKE_TIMEOUT, incoming_sessions_tx.reserve()).await
    else {
        return;
    };
    match TcpSession::new_from_stream(stream, Some(peer_id), LinkKind::DirectTcp, obfuscator) {
        Ok(session) => {
            slot.send(session.clone() as Arc<dyn Session>);
            crate::session!(
                "[TcpTransport] Session registered: {} (peer_id: {:?})",
                session.id(),
                session.peer_id()
            );
        }
        Err(e) => {
            crate::error!("[TcpTransport] Failed to create session from stream: {}", e);
        }
    }
}

pub struct TcpTransport {
    receive_budget: std::sync::Mutex<Option<crate::transport::TransportReceiveBudget>>,
    listen_addr: SocketAddr,
    shutdown_tx: Arc<Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
    accept_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    is_listener: bool,
    obfuscator: Arc<Obfuscator>,
}

impl Default for TcpTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpTransport {
    pub fn new() -> Self {
        Self {
            receive_budget: std::sync::Mutex::new(None),
            listen_addr: "0.0.0.0:0".parse().expect("valid socket addr"),
            shutdown_tx: Arc::new(Mutex::new(None)),
            accept_task: Arc::new(Mutex::new(None)),
            is_listener: true,
            obfuscator: Arc::new(Obfuscator::plain()),
        }
    }

    pub fn new_listener(listen_addr: Option<SocketAddr>) -> Self {
        Self {
            receive_budget: std::sync::Mutex::new(None),
            listen_addr: listen_addr.unwrap_or("0.0.0.0:8080".parse().expect("valid socket addr")),
            shutdown_tx: Arc::new(Mutex::new(None)),
            accept_task: Arc::new(Mutex::new(None)),
            is_listener: true,
            obfuscator: Arc::new(Obfuscator::plain()),
        }
    }

    pub fn new_dial() -> Self {
        Self {
            receive_budget: std::sync::Mutex::new(None),
            listen_addr: "0.0.0.0:0".parse().expect("valid socket addr"),
            shutdown_tx: Arc::new(Mutex::new(None)),
            accept_task: Arc::new(Mutex::new(None)),
            is_listener: false,
            obfuscator: Arc::new(Obfuscator::plain()),
        }
    }

    pub fn new_listener_with_obfuscation(
        listen_addr: Option<SocketAddr>,
        config: ObfuscationConfig,
    ) -> Self {
        Self {
            receive_budget: std::sync::Mutex::new(None),
            listen_addr: listen_addr.unwrap_or("0.0.0.0:8080".parse().expect("valid socket addr")),
            shutdown_tx: Arc::new(Mutex::new(None)),
            accept_task: Arc::new(Mutex::new(None)),
            is_listener: true,
            obfuscator: Arc::new(Obfuscator::from_config(config)),
        }
    }

    pub fn new_dial_with_obfuscation(config: ObfuscationConfig) -> Self {
        Self {
            receive_budget: std::sync::Mutex::new(None),
            listen_addr: "0.0.0.0:0".parse().expect("valid socket addr"),
            shutdown_tx: Arc::new(Mutex::new(None)),
            accept_task: Arc::new(Mutex::new(None)),
            is_listener: false,
            obfuscator: Arc::new(Obfuscator::from_config(config)),
        }
    }
}

#[async_trait]
impl Transport for TcpTransport {
    fn bind_receive_budget(&self, budget: crate::transport::TransportReceiveBudget) -> Result<()> {
        let mut current = self.receive_budget.lock().unwrap();
        if let Some(active) = current.as_ref().and_then(|b| b.get()) {
            anyhow::ensure!(
                budget.get().is_some_and(|new| Arc::ptr_eq(&active, &new)),
                "transport already bound to another node"
            );
        }
        *current = Some(budget);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "tcp"
    }

    fn is_listener(&self) -> bool {
        self.is_listener
    }

    async fn start(&self, ctx: TransportContext) -> Result<Option<SocketAddr>> {
        if !self.is_listener {
            return Ok(None);
        }
        {
            let shutdown_tx_guard = self.shutdown_tx.lock().await;
            if shutdown_tx_guard.is_some() {
                return Err(anyhow::anyhow!("TcpTransport is already started"));
            }
        }

        let bind_addr = ctx.listen_addr.unwrap_or(self.listen_addr);
        let (listener, actual_addr) = bind_with_port_fallback(bind_addr, |addr| async move {
            let listener = TcpListener::bind(addr).await?;
            let actual = listener.local_addr()?;
            Ok((listener, actual))
        })
        .await
        .map_err(|e| anyhow::anyhow!("Failed to bind TCP: {}", e))?;
        if actual_addr != bind_addr {
            crate::info!(
                "[TcpTransport] Port {} busy, bound to {}",
                bind_addr.port(),
                actual_addr.port()
            );
        }

        let listener = Arc::new(listener);
        let listener_clone = listener.clone();
        let incoming_sessions_tx = ctx.incoming_sessions_tx.clone();
        let obfuscator = self.obfuscator.clone();

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        {
            let mut shutdown_tx_guard = self.shutdown_tx.lock().await;
            *shutdown_tx_guard = Some(shutdown_tx);
        }

        let shared = self
            .receive_budget
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|b| b.get());
        let accept_handle = tokio::spawn(async move {
            let mut handshakes = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        crate::info!("[TcpTransport] Listener shutting down");
                        break;
                    }
                    _ = handshakes.join_next(), if !handshakes.is_empty() => {}
                    result = listener_clone.accept(), if handshakes.len() < INCOMING_HANDSHAKE_LIMIT => {
                        match result {
                            Ok((stream, peer_addr)) => {
                                crate::info!("[TcpTransport] New incoming connection from {}", peer_addr);
                                // Handshake per connection in its own task: a client that
                                // connects but never sends a full hello (port scanners on a
                                // public address, half-open mobile links) must not stall the
                                // accept loop for everyone else.
                                let pre_auth = match &shared {
                                    Some(b) => match b.pre_auth(208 * 1024) {
                                        Some(permit) => Some(permit),
                                        None => continue,
                                    },
                                    None => None,
                                };
                                handshakes.spawn(handle_incoming(
                                    stream,
                                    peer_addr,
                                    obfuscator.clone(),
                                    incoming_sessions_tx.clone(),
                                    pre_auth,
                                ));
                            }
                            Err(e) => {
                                crate::error!("[TcpTransport] Error accepting connection: {}", e);
                            }
                        }
                    }
                }
            }
            handshakes.shutdown().await;
        });

        {
            let mut accept_task_guard = self.accept_task.lock().await;
            *accept_task_guard = Some(accept_handle);
        }

        Ok(Some(actual_addr))
    }

    async fn stop(&self) -> Result<()> {
        let shutdown_tx = {
            let mut shutdown_tx_guard = self.shutdown_tx.lock().await;
            shutdown_tx_guard.take()
        };

        if let Some(shutdown_tx) = shutdown_tx {
            let _ = shutdown_tx.send(());
        } else {
            crate::info!("[TcpTransport] Already stopped or not started");
        }

        let accept_handle = {
            let mut accept_task_guard = self.accept_task.lock().await;
            accept_task_guard.take()
        };
        join_accept_task("TcpTransport", accept_handle, ACCEPT_TASK_JOIN_TIMEOUT).await;
        crate::info!("[TcpTransport] Stopped");

        Ok(())
    }

    async fn dial(&self, addr: SocketAddr) -> Result<Arc<dyn Session>> {
        crate::info!("[TcpTransport] Dialing {}", addr);

        if self.obfuscator.is_enabled() {
            crate::info!(
                "[TcpTransport] Obfuscation enabled: {:?}",
                self.obfuscator.config().mode
            );
        }

        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| anyhow::Error::new(e).context(format!("tcp connect {}", addr)))?;

        crate::info!("[TcpTransport] Connected to {}", addr);

        let session = TcpSession::new_from_stream(
            stream,
            None,
            LinkKind::DirectTcp,
            self.obfuscator.clone(),
        )?;

        Ok(session as Arc<dyn Session>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::node_keypair::NodeKeypair;
    use crate::crypto::signature::sign_packet;
    use crate::packet::Packet;
    use crate::transport::tcp::codec::encode_packet;
    use std::time::Duration;

    #[tokio::test]
    async fn silent_connection_does_not_block_other_handshakes() {
        let (sessions_tx, mut sessions_rx) = tokio::sync::mpsc::channel(4);
        let (packets_tx, _packets_rx) = tokio::sync::mpsc::channel(4);
        let transport = TcpTransport::new_listener(Some("127.0.0.1:0".parse().unwrap()));
        let addr = transport
            .start(TransportContext {
                incoming_sessions_tx: sessions_tx,
                incoming_packets_tx: packets_tx,
                listen_addr: None,
                event_tx: None,
                keypair: None,
                catalog: None,
            })
            .await
            .expect("start")
            .expect("listen addr");

        // Connects and never sends a hello, like a port scanner.
        let _silent = TcpStream::connect(addr).await.expect("silent connect");
        tokio::time::sleep(Duration::from_millis(50)).await;

        let keypair = NodeKeypair::generate();
        let mut hello = Packet {
            signature: None,
            data: crate::protocol::handshake::encode_hello(vec![], None),
            nodes: vec![],
            sender: keypair.peer_id().to_string(),
            receiver: String::new(),
            max_hops: 8,
            request_id: None,
            chunk_stream_id: None,
            chunk_index: None,
            total_chunks: None,
            protocol_id: None,
        };
        sign_packet(&mut hello, keypair.signing_key()).expect("sign");
        let mut client = TcpStream::connect(addr).await.expect("client connect");
        Obfuscator::plain()
            .write_frame(&mut client, &encode_packet(hello).expect("encode"))
            .await
            .expect("write hello");

        let session = tokio::time::timeout(Duration::from_secs(2), sessions_rx.recv())
            .await
            .expect("handshake not blocked by silent connection")
            .expect("session");
        assert_eq!(session.peer_id(), Some(keypair.peer_id()));

        transport.stop().await.expect("stop");
    }
}
