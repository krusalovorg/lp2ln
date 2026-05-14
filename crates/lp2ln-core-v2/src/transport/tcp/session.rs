use std::io::ErrorKind;
use std::sync::Arc;

use crate::crypto::signature::verify_packet;
use crate::packet::Packet;
use crate::protocol::handshake::decode_hello;
use crate::sessions::session::IncomingPacket;
use crate::sessions::session::LinkKind;
use crate::sessions::session::Session;
use crate::transport::obfuscation::Obfuscator;
use crate::transport::tcp::codec::{decode_packet, encode_packet};
use anyhow::Result;
use tokio::net::TcpStream;
use uuid::Uuid;

fn tcp_peer_display(peer_id: &Option<String>, session_id: &str) -> String {
    match peer_id {
        Some(id) if !id.is_empty() => id.clone(),
        _ => {
            let short: String = session_id.chars().take(8).collect();
            format!("outbound-tcp session {short}")
        }
    }
}

fn is_benign_tcp_disconnect(err: &anyhow::Error) -> bool {
    let msg = err.to_string();
    if msg.contains("Connection closed by peer")
        || msg.contains("Connection closed while reading")
        || msg.contains("Connection closed while writing")
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

fn log_tcp_session_disconnect(
    kind: LinkKind,
    peer_id: &Option<String>,
    session_id: &str,
    when: &str,
) {
    let peer = tcp_peer_display(peer_id, session_id);
    crate::net_disconnect!("[TcpSession] Node {peer} disconnected (link={kind}, {when})");
}

pub struct TcpSession {
    id: String,
    peer_id: Option<String>,
    kind: LinkKind,

    tx: tokio::sync::mpsc::Sender<Vec<u8>>,

    read: tokio::sync::Mutex<tokio::net::tcp::OwnedReadHalf>,
    obfuscator: Arc<Obfuscator>,
}

#[async_trait::async_trait]
impl Session for TcpSession {
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
            .map_err(|e| anyhow::anyhow!("Failed to send packet to writer task: {}", e))?;
        Ok(len)
    }

    async fn close(&self) -> Result<()> {
        drop(self.tx.clone());
        Ok(())
    }

    fn spawn_reader(
        self: Arc<Self>,
        incoming_packets_tx: tokio::sync::mpsc::Sender<IncomingPacket>,
    ) {
        let session_id = self.id().to_string();
        let peer_id = self.peer_id().map(|s| s.to_string());
        let link_kind = self.kind();

        tokio::spawn(async move {
            loop {
                match self.read_packet().await {
                    Ok(pkt) => {
                        match incoming_packets_tx
                            .send(IncomingPacket {
                                session_id: session_id.clone(),
                                from_node: peer_id.clone(),
                                packet: pkt,
                            })
                            .await
                        {
                            Ok(()) => {}
                            Err(_) => {
                                crate::warn!(
                                    "[TcpSession] Incoming packets channel closed, stopping reader"
                                );
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        if is_benign_tcp_disconnect(&e) {
                            log_tcp_session_disconnect(link_kind, &peer_id, &session_id, "on read");
                        } else {
                            crate::error!(
                                "[TcpSession] Read error for {}: {}",
                                tcp_peer_display(&peer_id, &session_id),
                                e
                            );
                        }
                        let _ = self.close().await;
                        break;
                    }
                }
            }
        });
    }
}

impl TcpSession {
    pub fn new_from_stream(
        stream: TcpStream,
        peer_id: Option<String>,
        kind: LinkKind,
        obfuscator: Arc<Obfuscator>,
    ) -> Result<Arc<Self>> {
        let id = Uuid::new_v4().to_string();
        let (read_half, write_half) = stream.into_split();

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);

        let session = Arc::new(Self {
            id,
            peer_id,
            kind,
            tx,
            read: tokio::sync::Mutex::new(read_half),
            obfuscator: obfuscator.clone(),
        });

        let write_half_arc = Arc::new(tokio::sync::Mutex::new(write_half));
        let write_half_clone = write_half_arc.clone();
        let obfuscator_clone = obfuscator.clone();
        let writer_peer_id = session.peer_id.clone();
        let writer_session_id = session.id.clone();
        let writer_kind = session.kind;

        tokio::spawn(async move {
            while let Some(data) = rx.recv().await {
                let mut writer = write_half_clone.lock().await;

                if let Err(e) = obfuscator_clone.write_frame(&mut *writer, &data).await {
                    if is_benign_tcp_disconnect(&e) {
                        log_tcp_session_disconnect(
                            writer_kind,
                            &writer_peer_id,
                            &writer_session_id,
                            "on write",
                        );
                    } else {
                        crate::error!(
                            "[TcpSession] Write error for {}: {}",
                            tcp_peer_display(&writer_peer_id, &writer_session_id),
                            e
                        );
                    }
                    break;
                }
            }
        });

        Ok(session)
    }

    async fn read_packet(&self) -> Result<Packet> {
        let mut reader = self.read.lock().await;
        let frame_data = self.obfuscator.read_frame(&mut *reader).await?;
        let packet = decode_packet(frame_data)?;
        Ok(packet)
    }

    pub async fn perform_handshake_on_stream(
        stream: &mut TcpStream,
        obfuscator: &Obfuscator,
    ) -> Result<String> {
        let frame_data = obfuscator.read_frame(stream).await?;
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

    pub async fn send_handshake_on_stream(
        stream: &mut TcpStream,
        our_peer_id: String,
    ) -> Result<()> {
        let handshake_packet = Packet {
            signature: None,
            data: vec![],
            nodes: vec![],
            sender: our_peer_id,
            receiver: String::new(),
            max_hops: 8,
            request_id: None,
            chunk_stream_id: None,
            chunk_index: None,
            total_chunks: None,
        };
        let bytes = encode_packet(handshake_packet)?;
        Obfuscator::plain().write_frame(stream, &bytes).await
    }
}
