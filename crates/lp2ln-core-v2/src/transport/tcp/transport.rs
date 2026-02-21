use std::net::SocketAddr;
use std::sync::Arc;
use anyhow::Result;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use async_trait::async_trait;
use crate::transport::{Transport, bind_with_port_fallback};
use crate::transport::transport::TransportContext;
use crate::sessions::Session;
use crate::sessions::session::LinkKind;
use crate::transport::tcp::session::TcpSession;

pub struct TcpTransport {
    listen_addr: SocketAddr,
    shutdown_tx: Arc<Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
    is_listener: bool,
}

impl TcpTransport {
    pub fn new() -> Self {
        Self {
            listen_addr: "0.0.0.0:0".parse().expect("valid socket addr"),
            shutdown_tx: Arc::new(Mutex::new(None)),
            is_listener: true,
        }
    }

    pub fn new_listener(listen_addr: Option<SocketAddr>) -> Self {
        Self {
            listen_addr: listen_addr.unwrap_or("0.0.0.0:8080".parse().expect("valid socket addr")),
            shutdown_tx: Arc::new(Mutex::new(None)),
            is_listener: true,
        }
    }

    pub fn new_dial() -> Self {
        Self {
            listen_addr: "0.0.0.0:0".parse().expect("valid socket addr"),
            shutdown_tx: Arc::new(Mutex::new(None)),
            is_listener: false,
        }
    }
}

#[async_trait]
impl Transport for TcpTransport {
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
            crate::info!("[TcpTransport] Port {} busy, bound to {}", bind_addr.port(), actual_addr.port());
        }

        let listener = Arc::new(listener);
        let listener_clone = listener.clone();
        let incoming_sessions_tx = ctx.incoming_sessions_tx.clone();
        
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        
        {
            let mut shutdown_tx_guard = self.shutdown_tx.lock().await;
            *shutdown_tx_guard = Some(shutdown_tx);
        }
        
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        crate::info!("[TcpTransport] Listener shutting down");
                        break;
                    }
                    result = listener_clone.accept() => {
                        match result {
                            Ok((mut stream, peer_addr)) => {
                                crate::info!("[TcpTransport] New incoming connection from {}", peer_addr);
                                
                                let peer_id = match TcpSession::perform_handshake_on_stream(&mut stream).await {
                                    Ok(peer_id) => {
                                        crate::info!("[TcpTransport] Handshake successful, peer_id: {}", peer_id);
                                        Some(peer_id)
                                    }
                                    Err(e) => {
                                        crate::error!("[TcpTransport] Handshake failed: {}", e);
                                        continue;
                                    }
                                };
                                
                                match TcpSession::new_from_stream(stream, peer_id, LinkKind::DirectTcp) {
                                    Ok(session) => {
                                        if incoming_sessions_tx.try_send(session.clone() as Arc<dyn Session>).is_err() {
                                            crate::error!("[TcpTransport] Failed to send incoming session: channel full or closed");
                                        } else {
                                            crate::session!("[TcpTransport] Session registered: {} (peer_id: {:?})", session.id(), session.peer_id());
                                        }
                                    }
                                    Err(e) => {
                                        crate::error!("[TcpTransport] Failed to create session from stream: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                crate::error!("[TcpTransport] Error accepting connection: {}", e);
                            }
                        }
                    }
                }
            }
        });
        
        Ok(Some(actual_addr))
    }

    async fn stop(&self) -> Result<()> {
        let shutdown_tx = {
            let mut shutdown_tx_guard = self.shutdown_tx.lock().await;
            shutdown_tx_guard.take()
        };
        
        if let Some(shutdown_tx) = shutdown_tx {
            let _ = shutdown_tx.send(());
            crate::info!("[TcpTransport] Stopped");
        } else {
            crate::info!("[TcpTransport] Already stopped or not started");
        }
        
        Ok(())
    }

    async fn dial(&self, addr: SocketAddr) -> Result<Arc<dyn Session>> {
        crate::info!("[TcpTransport] Dialing {}", addr);
        
        let stream = TcpStream::connect(addr).await
            .map_err(|e| anyhow::anyhow!("Failed to connect to {}: {}", addr, e))?;
        
        crate::info!("[TcpTransport] Connected to {}", addr);
        
        let session = TcpSession::new_from_stream(stream, None, LinkKind::DirectTcp)?;
        
        Ok(session as Arc<dyn Session>)
    }
}
