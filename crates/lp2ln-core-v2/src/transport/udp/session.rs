use std::net::SocketAddr;
use std::sync::Arc;
use anyhow::Result;
use tokio::net::UdpSocket;
use uuid::Uuid;
use crate::packet::Packet;
use crate::sessions::{IncomingPacket, LinkKind, Session};
use crate::transport::udp::codec::{decode_packet, encode_packet};

pub struct UdpSession {
    id: String,
    peer_id: Option<String>,
    kind: LinkKind,
    
    tx: tokio::sync::mpsc::Sender<(Vec<u8>, SocketAddr)>,
    
    socket: Arc<UdpSocket>,
    
    peer_addr: SocketAddr,
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

    async fn send(&self, packet: Packet) -> Result<u64> {
        let bytes = encode_packet(packet)?;
        let len = bytes.len() as u64;
        self.tx.send((bytes, self.peer_addr)).await
            .map_err(|e| anyhow::anyhow!("Failed to send packet to writer task: {}", e))?;
        Ok(len)
    }

    async fn close(&self) -> Result<()> {
        drop(self.tx.clone());
        Ok(())
    }
    
    fn spawn_reader(self: Arc<Self>, incoming_packets_tx: tokio::sync::mpsc::Sender<IncomingPacket>) {
        let session_id = self.id().to_string();
        let peer_id = self.peer_id().map(|s| s.to_string());
        
        tokio::spawn(async move {
            loop {
                match self.read_packet().await {
                    Ok(pkt) => {
                        if incoming_packets_tx.try_send(IncomingPacket {
                            session_id: session_id.clone(),
                            from_node: peer_id.clone(),
                            packet: pkt,
                        }).is_err() {
                            crate::warn!("[UdpSession] Failed to send packet: channel full or closed");
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
    ) -> Result<Arc<Self>> {
        let id = Uuid::new_v4().to_string();
        
        let (tx, mut rx) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);
        
        let session = Arc::new(Self {
            id,
            peer_id,
            kind,
            tx,
            socket: socket.clone(),
            peer_addr,
        });
        
        let socket_clone = socket.clone();
        tokio::spawn(async move {
            while let Some((data, addr)) = rx.recv().await {
                if let Err(e) = socket_clone.send_to(&data, addr).await {
                    crate::error!("[UdpSession] Error sending datagram: {}", e);
                    break;
                }
            }
        });
        
        Ok(session)
    }
    
    async fn read_packet(&self) -> Result<Packet> {
        let mut buf = vec![0u8; 65507];
        
        match self.socket.recv_from(&mut buf).await {
            Ok((size, _from_addr)) => {
                buf.truncate(size);
                let packet = decode_packet(buf)?;
                Ok(packet)
            }
            Err(e) => {
                Err(anyhow::anyhow!("Failed to receive UDP datagram: {}", e))
            }
        }
    }
}

