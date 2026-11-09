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
    secure_seq_limit: u64,
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
        let (start_secure_seq, secure_seq_limit) = initial_secure_sequence_range()
            .expect("cannot reserve secure packet sequences");
        Self {
            signing_key,
            our_peer_id: our_peer_id.into(),
            next_request_id: AtomicU64::new(start_request_id),
            next_secure_seq: AtomicU64::new(start_secure_seq),
            secure_seq_limit,
            peer_cache,
            signature_format,
        }
    }

    #[allow(dead_code)]
    pub fn peer_cache(&self) -> &Arc<PeerCryptoCache> {
        &self.peer_cache
    }

    pub fn prepare_outgoing(&self, mut packet: Packet) -> Result<Packet> {
        // Forward the author's encrypted body and signature unchanged.
        if packet.sender != self.our_peer_id { return Ok(packet); }
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
            let seq = self.next_secure_seq.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
                |seq| (seq < self.secure_seq_limit).then(|| seq + 1))
                .map_err(|_| anyhow::anyhow!("secure sequence reservation exhausted"))?;
            packet.data = self.peer_cache.encode_secure(
                signing_key.as_ref(),
                &packet.receiver,
                &packet.data,
                seq,
            )?;
        }
        if let Some(ref key) = self.signing_key {
            let format = if self.peer_cache.supports_routed_signatures(&packet.receiver) {
                SignatureFormat::V4Hash
            } else { self.signature_format };
            sign_packet_with_format(&mut packet, key, format)
                .map_err(anyhow::Error::msg)?;
        }
        Ok(packet)
    }

    pub(crate) fn use_sequence_state(&mut self, path: &std::path::Path) -> Result<()> {
        let (start, limit) = reserve_secure_sequence_range(path)?;
        self.next_secure_seq.store(start, Ordering::Relaxed);
        self.secure_seq_limit = limit;
        Ok(())
    }
}


// Persist an exclusive high-water mark before sending any packet. A crash may
// skip a range, but cannot reuse it. Replay protection stays enabled per peer.
const SECURE_SEQUENCE_RESERVATION: u64 = 1 << 40;

fn sequence_clock() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos()
        .try_into()?)
}

fn initial_secure_sequence_range() -> Result<(u64, u64)> {
    match std::env::var_os("LP2LN_SECURE_SEQ_STATE") {
        Some(path) => reserve_secure_sequence_range(std::path::Path::new(&path)),
        None => Ok((sequence_clock()?, u64::MAX)),
    }
}

fn reserve_secure_sequence_range(path: &std::path::Path) -> Result<(u64, u64)> {
    use std::io::Write;
    let now = sequence_clock()?;
    let start = match std::fs::read_to_string(path) {
        Ok(value) => value.trim().parse::<u64>()?.max(now),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => now,
        Err(error) => return Err(error.into()),
    };
    let limit = start.checked_add(SECURE_SEQUENCE_RESERVATION)
        .ok_or_else(|| anyhow::anyhow!("secure sequence space exhausted"))?;
    let _parent = path.parent()
        .ok_or_else(|| anyhow::anyhow!("sequence state requires a parent directory"))?;
    let temp = path.with_extension(format!("{}.{}.tmp", std::process::id(), now));
    let result = (|| -> Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true).create_new(true).open(&temp)?;
        writeln!(file, "{}", limit)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        #[cfg(unix)]
        std::fs::File::open(_parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result?;
    Ok((start, limit))
}

#[cfg(test)]
mod reconnect_regression_tests {
    use super::*;
    use crate::crypto::secure_channel::ReplayWindow;

    #[test]
    fn relay_preserves_sender_signature_and_cannot_decrypt_recipient_payload() {
        use crate::crypto::{NodeKeypair, signature::verify_packet};
        let author = NodeKeypair::generate();
        let recipient = NodeKeypair::generate();
        let relay = NodeKeypair::generate();
        let author_cache = PeerCryptoCache::new();
        let relay_cache = PeerCryptoCache::new();
        let sender = PacketEgressSecurity::new(Some(Arc::new(author.signing_key().clone())),
            author.peer_id(), 1, author_cache, SignatureFormat::V4Hash);
        let intermediary = PacketEgressSecurity::new(Some(Arc::new(relay.signing_key().clone())),
            relay.peer_id(), 1, relay_cache.clone(), SignatureFormat::V3Hash);
        let original = Packet { signature: None, data: b"private file capability".to_vec(),
            nodes: vec![], sender: author.peer_id().to_owned(), receiver: recipient.peer_id().to_owned(),
            max_hops: 8, request_id: None, chunk_stream_id: None, chunk_index: None,
            total_chunks: None, protocol_id: Some(0x4c46) };
        let mut encrypted = sender.prepare_outgoing(original).unwrap();
        let signature = encrypted.signature.clone();
        let ciphertext = encrypted.data.clone();
        encrypted.nodes.push(relay.peer_id().to_owned());
        encrypted.max_hops -= 1;
        let forwarded = intermediary.prepare_outgoing(encrypted).unwrap();
        assert_eq!(forwarded.data, ciphertext);
        assert_eq!(forwarded.signature, signature);
        verify_packet(&forwarded).unwrap();
        assert!(relay_cache.decode_secure(relay.signing_key(), author.peer_id(), &forwarded.data).is_err());
        let (_, plaintext) = PeerCryptoCache::new()
            .decode_secure(recipient.signing_key(), author.peer_id(), &forwarded.data).unwrap();
        assert_eq!(plaintext, b"private file capability");
    }

    #[test]
    fn reserved_sequences_survive_restart_and_keep_replay_protection() {
        let directory = std::env::temp_dir().join(format!(
            "lp2ln-sequence-test-{}-{}", std::process::id(), sequence_clock().unwrap()));
        std::fs::create_dir(&directory).unwrap();
        let state = directory.join("sequence");
        let (first, first_limit) = reserve_secure_sequence_range(&state).unwrap();
        let mut receiver = ReplayWindow::default();
        assert!(receiver.check_and_record(first));
        assert!(receiver.check_and_record(first + 1));
        let (after_restart, _) = reserve_secure_sequence_range(&state).unwrap();
        assert!(after_restart >= first_limit);
        assert!(receiver.check_and_record(after_restart));
        assert!(!receiver.check_and_record(after_restart));
        assert!(!receiver.check_and_record(first));
        // Corruption must fail closed instead of resetting the counter.
        std::fs::write(&state, b"corrupted").unwrap();
        assert!(reserve_secure_sequence_range(&state).is_err());
        std::fs::remove_file(&state).unwrap();
        std::fs::remove_dir(&directory).unwrap();
    }
}
