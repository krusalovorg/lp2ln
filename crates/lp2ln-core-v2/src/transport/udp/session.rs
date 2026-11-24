use crate::packet::Packet;
use crate::router::admission::{IngressPermit, ReaderIngress};
use crate::sessions::{IncomingPacket, LinkKind, Session};
use crate::transport::obfuscation::Obfuscator;
use crate::transport::udp::codec::{decode_packet, encode_packet};
use crate::transport::writer_queue::{DATAGRAM_QUEUE_BYTES, WriterQueue};
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::sync::{OwnedSemaphorePermit, mpsc};
use uuid::Uuid;

/// Upper bound for a single datagram send before the writer task gives up and
/// tears down the session. Guards against indefinite blocking when the socket
/// send buffer stays full.
const WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub(super) const MAX_UDP_DATAGRAM: usize = 65_507;
pub(super) type InboundDatagram = (Vec<u8>, OwnedSemaphorePermit, Option<IngressPermit>);

pub struct UdpSession {
    id: String,
    peer_id: Option<String>,
    kind: LinkKind,

    tx: WriterQueue,

    socket: Arc<UdpSocket>,
    inbox: Mutex<Option<mpsc::Receiver<InboundDatagram>>>,
    reader_started: AtomicBool,

    peer_addr: SocketAddr,
    obfuscator: Arc<Obfuscator>,
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
        self.tx.send(encoded).await
    }

    async fn close(&self) -> Result<()> {
        self.shutdown.cancel();
        self.inbox.lock().unwrap().take();
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
        self.start_reader(ReaderIngress::Legacy(incoming_packets_tx));
    }

    fn spawn_budgeted_reader(self: Arc<Self>, ingress: crate::router::SessionIngress) {
        self.start_reader(ReaderIngress::Budgeted(ingress));
    }
}

impl UdpSession {
    fn start_reader(self: Arc<Self>, ingress: ReaderIngress) {
        if self.reader_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let mut inbox = self.inbox.lock().unwrap().take();
        if self.shutdown.is_cancelled() {
            return;
        }
        let session_id = self.id().to_string();
        let peer_id = self.peer_id().map(|s| s.to_string());
        let shutdown = self.shutdown.clone();
        let task_tracker = self.task_tracker.clone();

        task_tracker.spawn(async move {
            let mut socket_buffer = Vec::new();
            let _socket_charge = if inbox.is_none() {
                let Ok(permit) = ingress.reserve(MAX_UDP_DATAGRAM + 256).await else { shutdown.cancel(); return; };
                socket_buffer.resize(MAX_UDP_DATAGRAM, 0);
                permit
            } else {
                None
            };
            loop {
                let read_result = tokio::select! {
                    _ = shutdown.cancelled() => break,
                    result = self.read_datagram(&mut inbox, &mut socket_buffer, &ingress) => result,
                };
                let (packet, permit) = match read_result {
                    Ok(Some(data)) => data,
                    Ok(None) => break,
                    Err(error) => {
                        crate::debug!("[UdpSession] Receive failed: {}", error);
                        break;
                    }
                };
                let incoming = IncomingPacket {
                    session_id: session_id.clone(),
                    from_node: peer_id.clone(),
                    packet,
                };
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    sent = ingress.submit(incoming, permit) => {
                        match sent {
                            Ok(()) | Err(crate::router::IngressAdmissionError::Overloaded | crate::router::IngressAdmissionError::Oversize) => {}
                            Err(crate::router::IngressAdmissionError::Closed) => break,
                        }
                    }
                }
            }
            shutdown.cancel();
        });
    }

    pub fn new_from_socket(
        socket: Arc<UdpSocket>,
        peer_addr: SocketAddr,
        peer_id: Option<String>,
        kind: LinkKind,
        obfuscator: Arc<Obfuscator>,
    ) -> Result<Arc<Self>> {
        Self::new(socket, peer_addr, peer_id, kind, obfuscator, None)
    }

    pub(super) fn from_listener(
        socket: Arc<UdpSocket>,
        peer_addr: SocketAddr,
        obfuscator: Arc<Obfuscator>,
        inbox: mpsc::Receiver<InboundDatagram>,
    ) -> Result<Arc<Self>> {
        Self::new(
            socket,
            peer_addr,
            None,
            LinkKind::DirectUdp,
            obfuscator,
            Some(inbox),
        )
    }

    pub(super) fn is_closed(&self) -> bool {
        self.shutdown.is_cancelled()
    }

    fn new(
        socket: Arc<UdpSocket>,
        peer_addr: SocketAddr,
        peer_id: Option<String>,
        kind: LinkKind,
        obfuscator: Arc<Obfuscator>,
        inbox: Option<mpsc::Receiver<InboundDatagram>>,
    ) -> Result<Arc<Self>> {
        let id = Uuid::new_v4().to_string();

        let (tx, mut rx) = WriterQueue::channel(DATAGRAM_QUEUE_BYTES, MAX_UDP_DATAGRAM);
        let shutdown = tokio_util::sync::CancellationToken::new();
        let task_tracker = tokio_util::task::TaskTracker::new();

        let session = Arc::new(Self {
            id,
            peer_id,
            kind,
            tx,
            socket: socket.clone(),
            inbox: Mutex::new(inbox),
            reader_started: AtomicBool::new(false),
            peer_addr,
            obfuscator: obfuscator.clone(),
            shutdown: shutdown.clone(),
            task_tracker: task_tracker.clone(),
        });

        let socket_clone = socket.clone();
        let obfuscator_clone = obfuscator.clone();
        task_tracker.spawn(async move {
            loop {
                let data = tokio::select! {
                    _ = shutdown.cancelled() => break,
                    maybe = rx.recv() => match maybe {
                        Some(item) => item,
                        None => break,
                    },
                };
                let encoded = match obfuscator_clone.encode_datagram(&data.data) {
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
                match tokio::time::timeout(WRITE_TIMEOUT, socket_clone.send_to(&encoded, peer_addr))
                    .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        crate::error!("[UdpSession] Error sending datagram: {}", e);
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

        Ok(session)
    }

    async fn read_datagram(
        &self,
        inbox: &mut Option<mpsc::Receiver<InboundDatagram>>,
        buffer: &mut [u8],
        ingress: &ReaderIngress,
    ) -> Result<Option<(Packet, Option<IngressPermit>)>> {
        loop {
            let item;
            let data = match inbox {
                Some(receiver) => {
                    let Some(received) = receiver.recv().await else {
                        return Ok(None);
                    };
                    item = received;
                    item.0.as_slice()
                }
                None => {
                    let (size, from) = self.socket.recv_from(buffer).await?;
                    if from != self.peer_addr {
                        continue;
                    }
                    &buffer[..size]
                }
            };
            let permit = match ingress
                .reserve(crate::transport::tcp::codec::decode_reservation(data.len()))
                .await
            {
                Ok(permit) => permit,
                Err(err)
                    if err
                        .downcast_ref::<crate::router::IngressAdmissionError>()
                        .is_some_and(|err| {
                            *err != crate::router::IngressAdmissionError::Closed
                        }) =>
                {
                    continue;
                }
                Err(err) => return Err(err),
            };
            let packet = if self.obfuscator.is_enabled() {
                self.obfuscator
                    .decode_datagram(data)
                    .and_then(decode_packet)
            } else {
                crate::transport::tcp::codec::decode_packet_slice(data)
            };
            if let Ok(packet) = packet {
                return Ok(Some((packet, permit)));
            }
        }
    }
}
