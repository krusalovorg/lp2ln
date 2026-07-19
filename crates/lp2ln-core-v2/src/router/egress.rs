use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use k256::ecdsa::SigningKey;

use crate::crypto::peer_cache::PeerCryptoCache;
use crate::crypto::secure_channel::is_secure_envelope;
use crate::crypto::signature::{SignatureFormat, sign_packet_with_format};
use crate::packet::Packet;

/// Outgoing packet signing and secure-envelope encoding (extracted from Router).
pub struct PacketEgressSecurity {
    signing_key: Option<Arc<SigningKey>>,
    our_peer_id: String,
    next_request_id: AtomicU64,
    next_secure_seq: AtomicU64,
    peer_cache: Arc<PeerCryptoCache>,
    signature_format: SignatureFormat,
}

impl PacketEgressSecurity {
    pub fn new(
        signing_key: Option<Arc<SigningKey>>,
        our_peer_id: impl Into<String>,
        start_request_id: u64,
        peer_cache: Arc<PeerCryptoCache>,
        signature_format: SignatureFormat,
    ) -> Self {
        Self {
            signing_key,
            our_peer_id: our_peer_id.into(),
            next_request_id: AtomicU64::new(start_request_id),
            next_secure_seq: AtomicU64::new(1),
            peer_cache,
            signature_format,
        }
    }

    #[allow(dead_code)]
    pub fn peer_cache(&self) -> &Arc<PeerCryptoCache> {
        &self.peer_cache
    }

    pub fn prepare_outgoing(&self, mut packet: Packet) -> Result<Packet> {
        if packet.request_id.is_none() {
            let id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
            packet.request_id = Some(id);
        }
        if !packet.data.is_empty()
            && !packet.receiver.is_empty()
            && packet.receiver != self.our_peer_id
            && !is_secure_envelope(&packet.data)
        {
            let signing_key = self
                .signing_key
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Secure transport requires signing key"))?;
            let seq = self.next_secure_seq.fetch_add(1, Ordering::Relaxed);
            packet.data = self.peer_cache.encode_secure(
                signing_key.as_ref(),
                &packet.receiver,
                &packet.data,
                seq,
            )?;
        }
        if let Some(ref key) = self.signing_key {
            sign_packet_with_format(&mut packet, key, self.signature_format)
                .map_err(anyhow::Error::msg)?;
        }
        Ok(packet)
    }
}
