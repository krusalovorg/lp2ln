use crate::packet::Packet;
use crate::sessions::{IncomingPacket, LinkKind, Session};
use crate::transport::obfuscation::Obfuscator;
use crate::transport::udp::codec::{decode_packet, encode_packet};
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Upper bound for a single datagram send before the writer task gives up and
/// tears down the session. Guards against indefinite blocking when the socket
/// send buffer stays full.
const WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub struct UdpSession {
    id: String,
    peer_id: Option<String>,
    kind: LinkKind,

    tx: tokio::sync::mpsc::Sender<(Vec<u8>, SocketAddr)>,

    socket: Arc<UdpSocket>,

    peer_addr: SocketAddr,
    obfuscator: Arc<Obfuscator>,
    datagrams: Option<tokio::sync::Mutex<mpsc::Receiver<Packet>>>,
    reader_started: AtomicBool,
    // Cancelled by close(); reader and writer loops select on it so both
    // tasks terminate even while blocked on socket recv / channel recv.
    shutdown: tokio_util::sync::CancellationToken,
    // Tracks the reader and writer tasks so close_session() can join them
    // during shutdown instead of leaving them detached.
    task_tracker: tokio_util::task::TaskTracker,
}

#[async_trait::async_trait]
impl Session for UdpSession {
    fn id(&self) -> &str {
        &self.id
    }

    fn peer_id(&self) -> Option<&str> {
        self.peer_id.as_deref()
    }

    fn kind(&self) -> LinkKind {
        self.kind
    }

    fn remote_addr(&self) -> Option<std::net::SocketAddr> {
        Some(self.peer_addr)
    }

    async fn send(&self, packet: Packet) -> Result<u64> {
        let bytes = encode_packet(packet)?;
        self.send_wire(bytes).await
    }

    async fn send_wire(&self, encoded: Vec<u8>) -> Result<u64> {
        let len = encoded.len() as u64;
        tokio::select! {
            _ = self.shutdown.cancelled() => anyhow::bail!("UDP session closed"),
            result = self.tx.send((encoded, self.peer_addr)) => {
                result.map_err(|e| anyhow::anyhow!("Failed to send packet to writer task: {}", e))?;
            }
        }
        Ok(len)
    }

    async fn close(&self) -> Result<()> {
        self.shutdown.cancel();
        Ok(())
    }

    async fn join_tasks(&self) {
        self.task_tracker.close();
        self.task_tracker.wait().await;
    }

    fn spawn_reader(
        self: Arc<Self>,
        incoming_packets_tx: tokio::sync::mpsc::Sender<IncomingPacket>,
    ) {
        if self.reader_started.swap(true, Ordering::Relaxed) {
            return;
        }
        let session_id = self.id().to_string();
        let peer_id = self.peer_id().map(|s| s.to_string());
        let shutdown = self.shutdown.clone();
        let task_tracker = self.task_tracker.clone();

        task_tracker.spawn(async move {
            loop {
                let read_result = tokio::select! {
                    _ = shutdown.cancelled() => break,
                    result = self.read_packet() => result,
                };
                match read_result {
                    Ok(pkt) => {
                        let forwarded = tokio::select! {
                            _ = shutdown.cancelled() => break,
                            result = incoming_packets_tx.send(IncomingPacket {
                                session_id: session_id.clone(),
                                from_node: peer_id.clone(),
                                packet: pkt,
                            }) => result,
                        };
                        match forwarded {
                            Ok(()) => {}
                            Err(_) => {
                                crate::warn!(
                                    "[UdpSession] Incoming packets channel closed, stopping reader"
                                );
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        crate::error!("[UdpSession] Error reading packet: {}", e);
                        let _ = self.close().await;
                        break;
                    }
                }
            }
        });
    }
}

impl UdpSession {
    pub fn new_from_socket(
        socket: Arc<UdpSocket>,
        peer_addr: SocketAddr,
        peer_id: Option<String>,
        kind: LinkKind,
        obfuscator: Arc<Obfuscator>,
    ) -> Result<Arc<Self>> {
        Ok(Self::create(
            socket,
            peer_addr,
            peer_id,
            kind,
            obfuscator,
            None,
            CancellationToken::new(),
        ))
    }

    pub(super) fn from_listener(
        socket: Arc<UdpSocket>,
        peer_addr: SocketAddr,
        kind: LinkKind,
        obfuscator: Arc<Obfuscator>,
        datagrams: mpsc::Receiver<Packet>,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        Self::create(
            socket,
            peer_addr,
            None,
            kind,
            obfuscator,
            Some(datagrams),
            shutdown,
        )
    }

    pub(super) fn is_closed(&self) -> bool {
        self.shutdown.is_cancelled()
    }

    fn create(
        socket: Arc<UdpSocket>,
        peer_addr: SocketAddr,
        peer_id: Option<String>,
        kind: LinkKind,
        obfuscator: Arc<Obfuscator>,
        datagrams: Option<mpsc::Receiver<Packet>>,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        let id = Uuid::new_v4().to_string();

        let (tx, mut rx) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);
        let task_tracker = tokio_util::task::TaskTracker::new();

        let session = Arc::new(Self {
            id,
            peer_id,
            kind,
            tx,
            socket: socket.clone(),
            peer_addr,
            obfuscator: obfuscator.clone(),
            datagrams: datagrams.map(tokio::sync::Mutex::new),
            reader_started: AtomicBool::new(false),
            shutdown: shutdown.clone(),
            task_tracker: task_tracker.clone(),
        });

        let socket_clone = socket.clone();
        let obfuscator_clone = obfuscator.clone();
        task_tracker.spawn(async move {
            loop {
                let (data, addr) = tokio::select! {
                    _ = shutdown.cancelled() => break,
                    maybe = rx.recv() => match maybe {
                        Some(item) => item,
                        None => break,
                    },
                };
                let encoded = match obfuscator_clone.encode_datagram(&data) {
                    Ok(v) => v,
                    Err(e) => {
                        crate::error!("[UdpSession] Error obfuscating datagram: {}", e);
                        break;
                    }
                };
                // Bound the send: send_to().await runs outside the select! and can
                // stall (e.g. a full socket buffer), which would wedge this task
                // even after shutdown is requested. On timeout we cancel the
                // session so the reader half also unwinds.
                match tokio::time::timeout(WRITE_TIMEOUT, socket_clone.send_to(&encoded, addr))
                    .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        crate::error!("[UdpSession] Error sending datagram: {}", e);
                        shutdown.cancel();
                        break;
                    }
                    Err(_) => {
                        crate::warn!("[UdpSession] Send timed out, closing session");
                        shutdown.cancel();
                        break;
                    }
                }
            }
        });

        session
    }

    async fn read_packet(&self) -> Result<Packet> {
        if let Some(datagrams) = &self.datagrams {
            return datagrams
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("UDP listener closed"));
        }
        let mut buf = vec![0u8; 65507];
        loop {
            let (size, from_addr) = self.socket.recv_from(&mut buf).await?;
            if from_addr == self.peer_addr {
                if let Ok(packet) = self
                    .obfuscator
                    .decode_datagram(&buf[..size])
                    .and_then(decode_packet)
                {
                    return Ok(packet);
                }
            }
        }
    }
}
