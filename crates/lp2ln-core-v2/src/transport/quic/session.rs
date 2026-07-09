use std::io::ErrorKind;
use std::sync::Arc;

use crate::crypto::signature::verify_packet;
use crate::packet::Packet;
use crate::protocol::handshake::decode_hello;
use crate::sessions::session::{IncomingPacket, LinkKind, Session};
use crate::transport::tcp::codec::{decode_packet, encode_packet, read_frame, write_frame};
use anyhow::Result;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
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
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    read: tokio::sync::Mutex<RecvStream>,
    connection: Connection,
    // Endpoint must outlive the connection (quinn requirement).
    _endpoint: Arc<Endpoint>,
    shutdown: tokio_util::sync::CancellationToken,
    task_tracker: tokio_util::task::TaskTracker,
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

    async fn send(&self, packet: Packet) -> Result<u64> {
        let bytes = encode_packet(packet)?;
        let len = bytes.len() as u64;
        self.tx
            .send(bytes)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send packet to QUIC writer task: {}", e))?;
        Ok(len)
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
                        if incoming_packets_tx
                            .send(IncomingPacket {
                                session_id: session_id.clone(),
                                from_node: peer_id.clone(),
                                packet: pkt,
                            })
                            .await
                            .is_err()
                        {
                            crate::warn!(
                                "[QuicSession] Incoming packets channel closed, stopping reader"
                            );
                            break;
                        }
                    }
                    Err(e) => {
                        if is_benign_quic_disconnect(&e) {
                            crate::net_disconnect!(
                                "[QuicSession] Peer disconnected (session={})",
                                &session_id[..8.min(session_id.len())]
                            );
                        } else {
                            crate::error!("[QuicSession] Read error for {}: {}", session_id, e);
                        }
                        let _ = self.close().await;
                        break;
                    }
                }
            }
        });
    }
}

impl QuicSession {
    pub fn new_from_streams(
        endpoint: Arc<Endpoint>,
        connection: Connection,
        send: SendStream,
        recv: RecvStream,
        peer_id: Option<String>,
        kind: LinkKind,
    ) -> Result<Arc<Self>> {
        let id = Uuid::new_v4().to_string();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
        let shutdown = tokio_util::sync::CancellationToken::new();
        let task_tracker = tokio_util::task::TaskTracker::new();

        let session = Arc::new(Self {
            id,
            peer_id,
            kind,
            tx,
            read: tokio::sync::Mutex::new(recv),
            connection: connection.clone(),
            _endpoint: endpoint,
            shutdown: shutdown.clone(),
            task_tracker: task_tracker.clone(),
        });

        let mut writer = send;
        let writer_shutdown = shutdown.clone();
        task_tracker.spawn(async move {
            loop {
                let data = tokio::select! {
                    _ = writer_shutdown.cancelled() => break,
                    maybe = rx.recv() => match maybe {
                        Some(data) => data,
                        None => break,
                    },
                };
                let write_result = tokio::time::timeout(WRITE_TIMEOUT, write_frame(&mut writer, &data))
                    .await;
                match write_result {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        if !is_benign_quic_disconnect(&e) {
                            crate::error!("[QuicSession] Write error: {}", e);
                        }
                        break;
                    }
                    Err(_) => {
                        crate::warn!("[QuicSession] Write timed out, closing session");
                        writer_shutdown.cancel();
                        break;
                    }
                }
            }
            let _ = writer.finish();
        });

        Ok(session)
    }

    async fn read_packet(&self) -> Result<Packet> {
        let mut reader = self.read.lock().await;
        let frame_data = read_frame(&mut *reader).await?;
        decode_packet(frame_data)
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
        };
        let bytes = encode(packet.clone()).expect("encode");
        let decoded = decode(bytes).expect("decode");
        assert_eq!(decoded.sender, packet.sender);
        assert_eq!(decoded.data, packet.data);
    }
}
