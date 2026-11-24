use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use anyhow::{Context, Result};
use stun_client::{Attribute, Class, Message, Method};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::packet::Packet;
use crate::sessions::{LinkKind, Session};
use crate::transport::obfuscation::Obfuscator;

use super::codec::decode_packet;
use super::session::UdpSession;

const MAX_ENDPOINTS: usize = 1024;
const ENDPOINT_QUEUE: usize = 32;
const PUNCH: &[u8] = b"KPL";
const PUNCH_REPLY: &[u8] = b"KPA";
const STUN_COOKIE: [u8; 4] = 0x2112_a442_u32.to_be_bytes();
type StunKey = (SocketAddr, [u8; 12]);

struct Endpoint {
    session: Weak<UdpSession>,
    packets: mpsc::Sender<Packet>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stun_reports_the_listeners_actual_source_port() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local = socket.local_addr().unwrap();
        let shared = Arc::new(SharedSocket::new(socket, Arc::new(Obfuscator::plain())));
        let (tx, _rx) = mpsc::channel(2);
        let reader = tokio::spawn(shared.clone().run(tx));
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let mut buf = [0u8; 28];
            let (size, source) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(size, 20);
            assert_eq!(source, local);
            let mut response = vec![1, 1, 0, 12];
            response.extend_from_slice(&buf[4..20]);
            response.extend_from_slice(&[0, 1, 0, 8, 0, 1]);
            response.extend_from_slice(&source.port().to_be_bytes());
            response.extend_from_slice(&[127, 0, 0, 1]);
            server.send_to(&response, source).await.unwrap();
        });
        assert_eq!(shared.stun_binding(server_addr).await.unwrap(), local);
        responder.await.unwrap();
        shared.shutdown.cancel();
        reader.await.unwrap();
    }
}

impl Endpoint {
    fn live_session(&self) -> Option<Arc<UdpSession>> {
        self.session
            .upgrade()
            .filter(|session| !session.is_closed())
    }
}

/// The listener is the sole reader of this socket. Control replies and
/// per-endpoint packet queues share the same source port.
pub(super) struct SharedSocket {
    pub(super) socket: Arc<UdpSocket>,
    pub(super) shutdown: CancellationToken,
    obfuscator: Arc<Obfuscator>,
    endpoints: Mutex<HashMap<SocketAddr, Endpoint>>,
    punches: Mutex<HashMap<SocketAddr, mpsc::Sender<()>>>,
    stun: Mutex<HashMap<StunKey, oneshot::Sender<SocketAddr>>>,
}

impl SharedSocket {
    pub(super) fn new(socket: UdpSocket, obfuscator: Arc<Obfuscator>) -> Self {
        Self {
            socket: Arc::new(socket),
            shutdown: CancellationToken::new(),
            obfuscator,
            endpoints: Mutex::new(HashMap::new()),
            punches: Mutex::new(HashMap::new()),
            stun: Mutex::new(HashMap::new()),
        }
    }

    fn endpoint(
        &self,
        peer: SocketAddr,
        kind: LinkKind,
    ) -> Result<(Arc<UdpSession>, mpsc::Sender<Packet>, bool)> {
        let mut endpoints = self.endpoints.lock().unwrap();
        anyhow::ensure!(!self.shutdown.is_cancelled(), "UDP listener has stopped");
        if let Some(entry) = endpoints.get(&peer) {
            if let Some(session) = entry.live_session() {
                return Ok((session, entry.packets.clone(), false));
            }
        }
        if endpoints.len() >= MAX_ENDPOINTS {
            endpoints.retain(|_, endpoint| endpoint.live_session().is_some());
        }
        anyhow::ensure!(
            endpoints.len() < MAX_ENDPOINTS,
            "UDP endpoint capacity reached"
        );
        let (packets, receiver) = mpsc::channel(ENDPOINT_QUEUE);
        let session = UdpSession::from_listener(
            self.socket.clone(),
            peer,
            kind,
            self.obfuscator.clone(),
            receiver,
            self.shutdown.child_token(),
        );
        endpoints.insert(
            peer,
            Endpoint {
                session: Arc::downgrade(&session),
                packets: packets.clone(),
            },
        );
        Ok((session, packets, true))
    }

    pub(super) fn dial(&self, peer: SocketAddr, kind: LinkKind) -> Result<Arc<UdpSession>> {
        self.endpoint(peer, kind).map(|(session, _, _)| session)
    }

    pub(super) async fn run(self: Arc<Self>, incoming: mpsc::Sender<Arc<dyn Session>>) {
        let mut buffer = vec![0; 65535];
        loop {
            let result = tokio::select! {
                _ = self.shutdown.cancelled() => break,
                _ = incoming.closed() => break,
                result = self.socket.recv_from(&mut buffer) => result,
            };
            let (size, peer) = match result {
                Ok(received) => received,
                Err(error) => {
                    crate::debug!("[UdpTransport] Receive error: {}", error);
                    continue;
                }
            };
            let data = &buffer[..size];
            if data == PUNCH || data == PUNCH_REPLY {
                self.handle_punch(peer, data == PUNCH);
                continue;
            }
            if data.get(4..8) == Some(STUN_COOKIE.as_slice())
                && data.first().is_some_and(|b| b & 0xc0 == 0)
            {
                self.handle_stun(peer, data);
                continue;
            }
            let Ok(packet) = self
                .obfuscator
                .decode_datagram(data)
                .and_then(decode_packet)
            else {
                continue;
            };
            let Ok((session, queue, is_new)) = self.endpoint(peer, LinkKind::DirectUdp) else {
                continue;
            };
            // The handoff includes the first datagram. A slow endpoint cannot
            // block the socket or the queues belonging to other endpoints.
            let _ = queue.try_send(packet);
            if is_new
                && incoming
                    .try_send(session.clone() as Arc<dyn Session>)
                    .is_err()
            {
                let _ = session.close().await;
            }
        }
        self.shutdown.cancel();
        self.punches.lock().unwrap().clear();
        self.stun.lock().unwrap().clear();
    }

    fn handle_punch(&self, peer: SocketAddr, is_request: bool) {
        let pending = self.punches.lock().unwrap().get(&peer).cloned();
        let known = self
            .endpoints
            .lock()
            .unwrap()
            .get(&peer)
            .and_then(Endpoint::live_session)
            .is_some();
        if is_request && (pending.is_some() || known) {
            let _ = self.socket.try_send_to(PUNCH_REPLY, peer);
        }
        if let Some(pending) = pending {
            let _ = pending.try_send(());
        }
    }

    pub(super) async fn punch(
        &self,
        peer: SocketAddr,
        deadline: Duration,
    ) -> Result<Arc<UdpSession>> {
        let (tx, mut rx) = mpsc::channel(1);
        {
            let mut pending = self.punches.lock().unwrap();
            pending.retain(|_, reply| !reply.is_closed());
            anyhow::ensure!(!pending.contains_key(&peer), "UDP punch already active");
            pending.insert(peer, tx);
        }
        let result = tokio::time::timeout(deadline, async {
            let mut retry = tokio::time::interval(Duration::from_millis(300));
            retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = self.shutdown.cancelled() => anyhow::bail!("UDP listener has stopped"),
                    _ = retry.tick() => { self.socket.send_to(PUNCH, peer).await?; }
                    response = rx.recv() => return response.context("UDP punch was cancelled"),
                }
            }
        })
        .await;
        let session = result.context("No reply to UDP punch").and_then(|reply| {
            reply?;
            self.dial(peer, LinkKind::TunnelUdp)
        });
        self.punches.lock().unwrap().remove(&peer);
        session
    }

    fn handle_stun(&self, peer: SocketAddr, data: &[u8]) {
        let Some(id) = data
            .get(8..20)
            .and_then(|value| <[u8; 12]>::try_from(value).ok())
        else {
            return;
        };
        let mut pending = self.stun.lock().unwrap();
        if !pending.contains_key(&(peer, id)) {
            return;
        }
        let Ok(message) = Message::from_raw(data) else {
            return;
        };
        if !matches!(message.get_method(), Method::Binding)
            || !matches!(message.get_class(), Class::SuccessResponse)
        {
            return;
        }
        let address = Attribute::get_xor_mapped_address(&message)
            .or_else(|| Attribute::get_mapped_address(&message));
        if let (Some(address), Some(tx)) = (address, pending.remove(&(peer, id))) {
            let _ = tx.send(address);
        }
    }

    pub(super) async fn stun_binding(&self, server: SocketAddr) -> Result<SocketAddr> {
        let request = Message::new(Method::Binding, Class::Request, None);
        let id = <[u8; 12]>::try_from(request.get_transaction_id())
            .map_err(|_| anyhow::anyhow!("Invalid STUN transaction ID"))?;
        let key = (server, id);
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.stun.lock().unwrap();
            pending.retain(|_, reply| !reply.is_closed());
            pending.insert(key, tx);
        }
        let result = tokio::time::timeout(Duration::from_millis(500), async {
            self.socket.send_to(&request.to_raw(), server).await?;
            rx.await.context("UDP listener stopped during STUN binding")
        })
        .await;
        self.stun.lock().unwrap().remove(&key);
        result.context("STUN binding timed out")?
    }
}
