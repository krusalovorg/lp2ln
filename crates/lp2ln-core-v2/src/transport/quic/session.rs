use crate::router::admission::{IngressPermit, ReaderIngress};
use std::io::ErrorKind;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::crypto::signature::verify_packet;
use crate::event_core::prelude::{
    CoreEvent, ServiceDescriptor, ServiceKind, TransportEvent, TransportProtocol,
};
use crate::packet::Packet;
#[cfg(feature = "packet-trace")]
use crate::packet_trace::{self, LinkEvent, Stage};
use crate::protocol::handshake::decode_hello;
use crate::sessions::session::{IncomingPacket, LinkKind, Session};
use crate::transport::quic::adaptive::AdaptiveLossConfig;
use crate::transport::tcp::codec::{decode_packet, encode_packet, read_frame, write_frame};
use crate::transport::writer_queue::{STREAM_QUEUE_BYTES, WriterQueue};
use anyhow::Result;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

fn is_benign_quic_disconnect(err: &anyhow::Error) -> bool {
    let msg = err.to_string();
    if msg.contains("Connection closed by peer")
        || msg.contains("Connection closed while reading")
        || msg.contains("closed by peer")
        || msg.contains("ApplicationClosed")
    {
        return true;
    }
    for cause in err.chain() {
        if let Some(io_err) = cause.downcast_ref::<std::io::Error>() {
            if matches!(
                io_err.kind(),
                ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::BrokenPipe
                    | ErrorKind::UnexpectedEof
                    | ErrorKind::NotConnected
            ) {
                return true;
            }
        }
    }
    false
}

pub struct QuicSession {
    id: String,
    peer_id: Option<String>,
    kind: LinkKind,
    tx: WriterQueue,
    read: tokio::sync::Mutex<RecvStream>,
    connection: Connection,
    // Endpoint must outlive the connection (quinn requirement).
    _endpoint: Arc<Endpoint>,
    native_credit: std::sync::Mutex<Option<IngressPermit>>,
    shutdown: CancellationToken,
    task_tracker: tokio_util::task::TaskTracker,
    reader_started: std::sync::atomic::AtomicBool,
    pub in_compensate: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl Session for QuicSession {
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
        Some(self.connection.remote_address())
    }

    async fn send(&self, packet: Packet) -> Result<u64> {
        let bytes = encode_packet(packet)?;
        self.send_wire(bytes).await
    }

    async fn send_wire(&self, encoded: Vec<u8>) -> Result<u64> {
        self.tx.send(encoded).await
    }

    fn is_degraded(&self) -> bool {
        self.in_compensate.load(Ordering::Relaxed)
    }

    async fn close(&self) -> Result<()> {
        self.shutdown.cancel();
        self.connection.close(0u32.into(), b"session closed");
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

impl QuicSession {
    pub(super) fn hold_receive_credit(&self, permit: Option<IngressPermit>) {
        *self.native_credit.lock().unwrap() = permit;
    }

    fn start_reader(self: Arc<Self>, ingress: ReaderIngress) {
        if self
            .reader_started
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
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
                    result = self.read_packet(&ingress) => result,
                };
                match read_result {
                    Ok((pkt, permit)) => {
                        let incoming = IncomingPacket {
                            session_id: session_id.clone(),
                            from_node: peer_id.clone(),
                            packet: pkt,
                        };
                        tokio::select! {
                            biased;
                            _ = shutdown.cancelled() => break,
                            sent = ingress.submit(incoming, permit) => {
                                if let Err(error) = sent {
                                    crate::warn!("reliable ingress handoff failed for {}: {}", session_id, error);
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        #[cfg(feature = "packet-trace")]
                        packet_trace::link_event(LinkEvent::ReadEnded);
                        if is_benign_quic_disconnect(&e) {
                            crate::net_disconnect!(
                                "[QuicSession] Peer disconnected (session={})",
                                &session_id[..8.min(session_id.len())]
                            );
                        } else {
                            crate::error!("[QuicSession] Read error for {}: {}", session_id, e);
                        }
                        break;
                    }
                }
            }
            let _ = self.close().await;
        });
    }

    pub fn new_from_streams(
        endpoint: Arc<Endpoint>,
        connection: Connection,
        send: SendStream,
        recv: RecvStream,
        peer_id: Option<String>,
        kind: LinkKind,
        event_tx: Option<mpsc::Sender<CoreEvent>>,
        adaptive: Option<AdaptiveLossConfig>,
    ) -> Result<Arc<Self>> {
        let id = Uuid::new_v4().to_string();
        let (tx, mut rx) = WriterQueue::channel(
            STREAM_QUEUE_BYTES,
            crate::transport::tcp::codec::MAX_FRAME_BYTES,
        );
        let shutdown = CancellationToken::new();
        let task_tracker = tokio_util::task::TaskTracker::new();
        let in_compensate = Arc::new(AtomicBool::new(false));

        // Clone connection before it's moved into the struct (for monitor task).
        let monitor_connection = connection.clone();

        let session = Arc::new(Self {
            id,
            peer_id,
            kind,
            tx,
            read: tokio::sync::Mutex::new(recv),
            connection,
            _endpoint: endpoint,
            native_credit: std::sync::Mutex::new(None),
            shutdown: shutdown.clone(),
            task_tracker: task_tracker.clone(),
            reader_started: std::sync::atomic::AtomicBool::new(false),
            in_compensate: in_compensate.clone(),
        });

        let mut writer = send;
        let writer_shutdown = shutdown.clone();
        let writer_connection = session.connection.clone();
        task_tracker.spawn(async move {
            loop {
                let data = tokio::select! {
                    _ = writer_shutdown.cancelled() => break,
                    maybe = rx.recv() => match maybe {
                        Some(data) => data,
                        None => break,
                    },
                };
                let write_result = tokio::select! {
                    biased;
                    _ = writer_shutdown.cancelled() => break,
                    result = tokio::time::timeout(WRITE_TIMEOUT, write_frame(&mut writer, &data.data)) => result,
                };
                match write_result {
                    Ok(Ok(())) => {
                        #[cfg(feature = "packet-trace")]
                        packet_trace::record_wire(&data.data, Stage::StreamWritten);
                    }
                    Ok(Err(e)) => {
                        #[cfg(feature = "packet-trace")]
                        packet_trace::link_event(LinkEvent::WriteFailed);
                        if !is_benign_quic_disconnect(&e) {
                            crate::error!("[QuicSession] Write error: {}", e);
                        }
                        writer_shutdown.cancel();
                        break;
                    }
                    Err(_) => {
                        #[cfg(feature = "packet-trace")]
                        packet_trace::link_event(LinkEvent::WriteFailed);
                        crate::warn!("[QuicSession] Write timed out, closing session");
                        writer_shutdown.cancel();
                        break;
                    }
                }
            }
            if writer_shutdown.is_cancelled() {
                writer_connection.close(0u32.into(), b"session closed");
            } else {
                let _ = writer.finish();
            }
        });

        // Spawn loss monitor if adaptive loss is enabled and we have an event channel.
        if let (Some(config), Some(tx)) = (adaptive, event_tx) {
            if config.enabled {
                let sid = session.id[..8.min(session.id.len())].to_string();
                let mon_shutdown = shutdown.clone();
                task_tracker.spawn(async move {
                    run_loss_monitor(
                        monitor_connection,
                        config,
                        tx,
                        in_compensate,
                        sid,
                        mon_shutdown,
                    )
                    .await;
                });
            }
        }

        Ok(session)
    }

    async fn read_packet(
        &self,
        ingress: &ReaderIngress,
    ) -> Result<(Packet, Option<IngressPermit>)> {
        let mut reader = self.read.lock().await;
        use crate::transport::tcp::codec::{
            MAX_FRAME_BYTES, decode_reservation, read_frame_body, read_frame_len,
        };
        let len = read_frame_len(&mut *reader, MAX_FRAME_BYTES).await?;
        let permit = ingress.reserve(decode_reservation(len)).await?;
        let frame_data = read_frame_body(&mut *reader, len).await?;
        #[cfg(feature = "packet-trace")]
        packet_trace::link_event(LinkEvent::ReadFrame);
        let packet = decode_packet(frame_data);
        #[cfg(feature = "packet-trace")]
        match &packet {
            Ok(packet) => packet_trace::record(packet, Stage::Decoded),
            Err(_) => packet_trace::link_event(LinkEvent::DecodeFailed),
        }
        Ok((packet?, permit))
    }

    #[allow(dead_code)]
    pub async fn perform_handshake_on_stream(recv: &mut RecvStream) -> Result<String> {
        let frame_data = read_frame(recv).await?;
        let packet = decode_packet(frame_data)?;
        verify_packet(&packet).map_err(anyhow::Error::msg)?;
        if decode_hello(&packet.data).is_none() {
            return Err(anyhow::anyhow!(
                "Invalid handshake payload from {}",
                packet.sender
            ));
        }
        if packet.sender.is_empty() {
            return Err(anyhow::anyhow!("Handshake sender is empty"));
        }
        Ok(packet.sender)
    }
}

async fn run_loss_monitor(
    connection: Connection,
    config: AdaptiveLossConfig,
    event_tx: mpsc::Sender<CoreEvent>,
    in_compensate: Arc<AtomicBool>,
    session_id_short: String,
    shutdown: CancellationToken,
) {
    let window = std::time::Duration::from_secs(config.window_secs);
    let mut prev_sent = 0u64;
    let mut prev_lost = 0u64;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(window) => {}
        }

        let stats = connection.stats();
        let sent = stats.path.sent_packets;
        let lost = stats.path.lost_packets;
        let delta_sent = sent.saturating_sub(prev_sent);
        let delta_lost = lost.saturating_sub(prev_lost);
        prev_sent = sent;
        prev_lost = lost;

        if delta_sent == 0 {
            continue;
        }

        let loss_rate = delta_lost as f64 / delta_sent as f64;
        let was_compensating = in_compensate.load(Ordering::Relaxed);

        if loss_rate > config.loss_threshold && !was_compensating {
            in_compensate.store(true, Ordering::Relaxed);
            crate::warn!(
                "[QuicSession] Loss {:.1}% > threshold {:.1}% – compensate mode (session={})",
                loss_rate * 100.0,
                config.loss_threshold * 100.0,
                session_id_short
            );
            let _ = event_tx.try_send(CoreEvent::Transport(TransportEvent::Degraded {
                service: ServiceDescriptor::new(
                    format!("quic-session:{}", session_id_short),
                    ServiceKind::Transport,
                ),
                protocol: TransportProtocol::Quic,
                reason: format!(
                    "packet loss {:.1}% exceeds threshold {:.1}%",
                    loss_rate * 100.0,
                    config.loss_threshold * 100.0,
                ),
                loss_rate,
            }));
        } else if loss_rate <= config.loss_threshold && was_compensating {
            in_compensate.store(false, Ordering::Relaxed);
            crate::info!(
                "[QuicSession] Loss recovered to {:.1}% – normal mode (session={})",
                loss_rate * 100.0,
                session_id_short
            );
            let _ = event_tx.try_send(CoreEvent::Transport(TransportEvent::Recovered {
                service: ServiceDescriptor::new(
                    format!("quic-session:{}", session_id_short),
                    ServiceKind::Transport,
                ),
                protocol: TransportProtocol::Quic,
                loss_rate,
            }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::tcp::codec::{decode_packet as decode, encode_packet as encode};

    #[test]
    fn quic_framing_roundtrip() {
        let packet = Packet {
            signature: None,
            data: b"hello-quic".to_vec(),
            nodes: vec![],
            sender: "peer-a".to_string(),
            receiver: "peer-b".to_string(),
            max_hops: 4,
            request_id: None,
            chunk_stream_id: None,
            chunk_index: None,
            total_chunks: None,
            protocol_id: None,
        };
        let bytes = encode(packet.clone()).expect("encode");
        let decoded = decode(bytes).expect("decode");
        assert_eq!(decoded.sender, packet.sender);
        assert_eq!(decoded.data, packet.data);
    }
}
