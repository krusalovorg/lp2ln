use anyhow::{Context, Result, ensure};
use k256::ecdsa::{
    Signature, VerifyingKey,
    signature::{Signer, Verifier},
};
use rand::TryRngCore;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

use crate::crypto::{NodeKeypair, secure_channel::ReplayWindow};

use super::FlowId;

pub(crate) const ALPN: &[u8] = b"lp2ln-flow/1";
pub(crate) const CAPABILITIES: u16 = 0b11; // deadline-bearing DATAGRAM and ordered control
const VERSION: u8 = 1;
const EXPORTER: &[u8] = b"EXPORTER-LP2LN-FLOW-LINK-V1";
const NOISE_SUITE: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const MAX_HANDSHAKE: usize = 2048;
const CERT_LIFETIME_SECS: u64 = 300;
const MAX_RECORDS_PER_EPOCH: u64 = 1 << 32;
const MAX_RECORD_SIZE: usize = 8192;
const RECORD_HEADER: usize = 39;
const LOOKUP_HEADER: usize = 12;
const TAG_BYTES: usize = 16;
pub(crate) const OVERHEAD: usize = RECORD_HEADER + LOOKUP_HEADER + TAG_BYTES;
pub(crate) const KIND_DATA: u8 = 1;
pub(crate) const KIND_SYNC: u8 = 2;
pub(crate) const KIND_ACK: u8 = 3;
pub(crate) const KIND_REKEY: u8 = 4;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Role {
    Initiator,
    Responder,
}

impl Role {
    fn wire(self) -> u8 {
        match self {
            Self::Initiator => 0,
            Self::Responder => 1,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Offer {
    version: u8,
    capabilities: u16,
    id: FlowId,
    protocol: u16,
    peer: String,
    expected_peer: String,
    nonce: [u8; 32],
}

impl Offer {
    pub(crate) fn new(
        local: &NodeKeypair,
        expected: &str,
        id: FlowId,
        protocol: u16,
    ) -> Result<Self> {
        peer_key(expected)?;
        let mut nonce = [0; 32];
        OsRng
            .try_fill_bytes(&mut nonce)
            .context("link challenge RNG")?;
        Ok(Self {
            version: VERSION,
            capabilities: CAPABILITIES,
            id,
            protocol,
            peer: local.peer_id().into(),
            expected_peer: expected.into(),
            nonce,
        })
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == VERSION && self.capabilities == CAPABILITIES,
            "unsupported Flow capability offer"
        );
        ensure!(
            self.peer != self.expected_peer,
            "identical endpoint identities"
        );
        peer_key(&self.peer)?;
        peer_key(&self.expected_peer)?;
        Ok(())
    }
}

fn peer_key(peer: &str) -> Result<VerifyingKey> {
    ensure!(
        peer.len() == 66 && !peer.bytes().any(|b| b.is_ascii_uppercase()),
        "invalid canonical Peer ID"
    );
    Ok(VerifyingKey::from_sec1_bytes(&hex::decode(peer)?)?)
}

fn bind(a: &Offer, b: &Offer) -> Result<()> {
    a.validate()?;
    b.validate()?;
    ensure!(
        a.peer == b.expected_peer
            && b.peer == a.expected_peer
            && a.id == b.id
            && a.protocol == b.protocol
            && a.nonce != b.nonce,
        "Flow offer mismatch"
    );
    Ok(())
}

fn sign(key: &NodeKeypair, transcript: &[u8]) -> [u8; 64] {
    let sign: Signature = key.signing_key().sign(transcript);
    sign.to_bytes().into()
}

fn verify(peer: &str, transcript: &[u8], signature: &[u8]) -> Result<()> {
    let signature = Signature::from_slice(signature)?;
    ensure!(
        signature.normalize_s().is_none(),
        "non-canonical ECDSA signature"
    );
    peer_key(peer)?
        .verify(transcript, &signature)
        .context("peer proof invalid")
}

fn transcript(a: &Offer, b: &Offer, exporter: &[u8; 32], role: Role) -> Result<Vec<u8>> {
    bind(a, b)?;
    Ok(postcard::to_allocvec(&(
        b"LP2LN/link-proof/v1",
        ALPN,
        role.wire(),
        a,
        b,
        exporter,
    ))?)
}

fn link_proof(
    key: &NodeKeypair,
    a: &Offer,
    b: &Offer,
    exporter: &[u8; 32],
    role: Role,
) -> Result<[u8; 64]> {
    let author = if role == Role::Initiator {
        &a.peer
    } else {
        &b.peer
    };
    ensure!(author == key.peer_id(), "wrong link signer");
    Ok(sign(key, &transcript(a, b, exporter, role)?))
}

fn verify_link(
    expected: &str,
    a: &Offer,
    b: &Offer,
    exporter: &[u8; 32],
    role: Role,
    proof: &[u8],
) -> Result<()> {
    let author = if role == Role::Initiator {
        &a.peer
    } else {
        &b.peer
    };
    ensure!(author == expected, "link Peer ID mismatch");
    verify(expected, &transcript(a, b, exporter, role)?, proof)
}

pub(crate) struct ControlStream {
    pub(crate) send: quinn::SendStream,
    pub(crate) recv: quinn::RecvStream,
}

impl ControlStream {
    pub(crate) async fn write(&mut self, data: &[u8]) -> Result<()> {
        ensure!(
            !data.is_empty() && data.len() <= MAX_HANDSHAKE,
            "control frame too large"
        );
        self.send
            .write_all(&(data.len() as u16).to_be_bytes())
            .await?;
        self.send.write_all(data).await?;
        Ok(())
    }

    pub(crate) async fn read(&mut self) -> Result<Vec<u8>> {
        let mut prefix = [0; 2];
        // A verified Flow can wait idle for control. Once a frame starts,
        // its remaining bytes have a hard completion deadline.
        self.recv.read_exact(&mut prefix[..1]).await?;
        let data = tokio::time::timeout(Duration::from_secs(2), async {
            self.recv.read_exact(&mut prefix[1..]).await?;
            let len = u16::from_be_bytes(prefix) as usize;
            ensure!(len != 0 && len <= MAX_HANDSHAKE, "control frame too large");
            let mut data = vec![0; len];
            self.recv.read_exact(&mut data).await?;
            Ok::<_, anyhow::Error>(data)
        })
        .await??;
        Ok(data)
    }

    async fn offer(&mut self) -> Result<Offer> {
        let bytes = self.read().await?;
        let (offer, extra) = postcard::take_from_bytes::<Offer>(&bytes)?;
        ensure!(extra.is_empty(), "trailing bytes in Flow offer");
        offer.validate()?;
        Ok(offer)
    }
}

#[derive(Clone)]
pub(crate) struct EndpointBinding {
    pub(crate) id: FlowId,
    pub(crate) protocol: u16,
    initiator: String,
    responder: String,
    pub(crate) role: Role,
}

impl EndpointBinding {
    pub(crate) fn remote(&self) -> &str {
        match self.role {
            Role::Initiator => &self.responder,
            Role::Responder => &self.initiator,
        }
    }

    fn prologue(&self, epoch: u32) -> Result<Vec<u8>> {
        // Hop exporter and addresses are deliberately absent.
        Ok(postcard::to_allocvec(&(
            b"LP2LN/flow-noise/v1",
            VERSION,
            CAPABILITIES,
            self.id,
            self.protocol,
            self.initiator.as_str(),
            self.responder.as_str(),
            epoch,
        ))?)
    }
}

pub(crate) async fn authenticate_link(
    connection: &quinn::Connection,
    control: &mut ControlStream,
    identity: &NodeKeypair,
    outbound: Option<(&str, FlowId, u16)>,
    allows: impl Fn(&str, u16) -> bool,
) -> Result<EndpointBinding> {
    let mut exporter = [0; 32];
    connection
        .export_keying_material(&mut exporter, EXPORTER, ALPN)
        .map_err(|_| anyhow::anyhow!("TLS exporter unavailable"))?;
    let (a, b, role) = if let Some((peer, id, protocol)) = outbound {
        let a = Offer::new(identity, peer, id, protocol)?;
        control.write(&postcard::to_allocvec(&a)?).await?;
        let b = control.offer().await?;
        ensure!(b.peer == peer, "unexpected link peer");
        let remote_proof = control.read().await?;
        verify_link(peer, &a, &b, &exporter, Role::Responder, &remote_proof)?;
        control
            .write(&link_proof(identity, &a, &b, &exporter, Role::Initiator)?)
            .await?;
        (a, b, Role::Initiator)
    } else {
        let a = control.offer().await?;
        ensure!(
            a.expected_peer == identity.peer_id() && allows(&a.peer, a.protocol),
            "Flow endpoint not allowed"
        );
        let b = Offer::new(identity, &a.peer, a.id, a.protocol)?;
        control.write(&postcard::to_allocvec(&b)?).await?;
        control
            .write(&link_proof(identity, &a, &b, &exporter, Role::Responder)?)
            .await?;
        let proof = control.read().await?;
        verify_link(&a.peer, &a, &b, &exporter, Role::Initiator, &proof)?;
        (a, b, Role::Responder)
    };
    Ok(EndpointBinding {
        id: a.id,
        protocol: a.protocol,
        initiator: a.peer,
        responder: b.peer,
        role,
    })
}

fn unix_secs() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn noise_identity_message(
    prologue: &[u8],
    role: Role,
    noise_public: &[u8],
    expiry: u64,
) -> Result<Vec<u8>> {
    Ok(postcard::to_allocvec(&(
        b"LP2LN/noise-identity/v1",
        prologue,
        role.wire(),
        noise_public,
        expiry,
    ))?)
}

fn noise_certificate(
    key: &NodeKeypair,
    prologue: &[u8],
    role: Role,
    noise_public: &[u8],
) -> Result<[u8; 72]> {
    let expiry = unix_secs()?.saturating_add(CERT_LIFETIME_SECS);
    let mut certificate = [0; 72];
    certificate[..8].copy_from_slice(&expiry.to_be_bytes());
    certificate[8..].copy_from_slice(&sign(
        key,
        &noise_identity_message(prologue, role, noise_public, expiry)?,
    ));
    Ok(certificate)
}

fn verify_noise_identity(
    expected: &str,
    prologue: &[u8],
    role: Role,
    static_key: Option<&[u8]>,
    cert: &[u8],
) -> Result<()> {
    let static_key = static_key.context("Noise did not authenticate static key")?;
    ensure!(
        static_key.len() == 32 && cert.len() == 72,
        "invalid Noise peer identity proof"
    );
    let expiry = u64::from_be_bytes(cert[..8].try_into()?);
    let now = unix_secs()?;
    ensure!(
        now <= expiry && expiry <= now.saturating_add(CERT_LIFETIME_SECS * 2),
        "Noise identity expiry outside policy"
    );
    verify(
        expected,
        &noise_identity_message(prologue, role, static_key, expiry)?,
        &cert[8..],
    )
}

pub(crate) async fn noise_xx(
    control: &mut ControlStream,
    binding: &EndpointBinding,
    identity: &NodeKeypair,
    epoch: u32,
) -> Result<RecordKeys> {
    let prologue = binding.prologue(epoch)?;
    let builder = snow::Builder::new(NOISE_SUITE.parse()?);
    let pair = builder.generate_keypair()?;
    let private = Zeroizing::new(pair.private);
    let certificate = noise_certificate(identity, &prologue, binding.role, &pair.public)?;
    let builder = builder.local_private_key(&private)?.prologue(&prologue)?;
    let mut state = match binding.role {
        Role::Initiator => builder.build_initiator()?,
        Role::Responder => builder.build_responder()?,
    };
    drop(private);
    let mut buf = Zeroizing::new([0; MAX_HANDSHAKE]);
    match binding.role {
        Role::Initiator => {
            let n = state.write_message(&[], buf.as_mut())?;
            control.write(&buf[..n]).await?;
            let n = state.read_message(&control.read().await?, buf.as_mut())?;
            verify_noise_identity(
                binding.remote(),
                &prologue,
                Role::Responder,
                state.get_remote_static(),
                &buf[..n],
            )?;
            let n = state.write_message(&certificate, buf.as_mut())?;
            control.write(&buf[..n]).await?;
        }
        Role::Responder => {
            let n = state.read_message(&control.read().await?, buf.as_mut())?;
            ensure!(n == 0, "unexpected clear Noise payload");
            let n = state.write_message(&certificate, buf.as_mut())?;
            control.write(&buf[..n]).await?;
            let n = state.read_message(&control.read().await?, buf.as_mut())?;
            verify_noise_identity(
                binding.remote(),
                &prologue,
                Role::Initiator,
                state.get_remote_static(),
                &buf[..n],
            )?;
        }
    }
    Ok(RecordKeys {
        state: state.into_stateless_transport_mode()?,
        epoch,
        id: binding.id,
        role: binding.role,
        next: [0; 2],
        replay: std::array::from_fn(|_| ReplayWindow::default()),
    })
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RecordError {
    Invalid,
    Replay,
    Epoch,
}

pub(crate) struct RecordKeys {
    state: snow::StatelessTransportState,
    epoch: u32,
    id: FlowId,
    role: Role,
    next: [u64; 2],
    replay: [ReplayWindow; 2],
}

impl RecordKeys {
    pub(crate) fn seal(&mut self, kind: u8, expires: u64, data: &[u8]) -> Result<Vec<u8>> {
        // Each directional key has two disjoint nonce domains. A delayed
        // reliable control record can't be displaced by fast DATAGRAMs.
        let lane = usize::from(kind != KIND_DATA);
        ensure!(
            self.next[lane] < MAX_RECORDS_PER_EPOCH && data.len() <= MAX_RECORD_SIZE - OVERHEAD,
            "Flow epoch exhausted or record too big"
        );
        let nonce = (self.next[lane] << 1) | lane as u64;
        self.next[lane] += 1;
        let mut plain = Zeroizing::new(Vec::with_capacity(RECORD_HEADER + data.len()));
        plain.push(VERSION);
        plain.extend_from_slice(&self.id.0);
        plain.extend_from_slice(&self.epoch.to_be_bytes());
        plain.extend_from_slice(&nonce.to_be_bytes());
        plain.push(kind);
        plain.push(self.role.wire());
        plain.extend_from_slice(&expires.to_be_bytes());
        plain.extend_from_slice(data);
        let mut encrypted = vec![0; LOOKUP_HEADER + plain.len() + TAG_BYTES];
        encrypted[..4].copy_from_slice(&self.epoch.to_be_bytes());
        encrypted[4..12].copy_from_slice(&nonce.to_be_bytes());
        self.state
            .write_message(nonce, &plain, &mut encrypted[LOOKUP_HEADER..])?;
        Ok(encrypted)
    }

    pub(crate) fn open(&mut self, kind: u8, wire: &[u8]) -> Result<(u64, Vec<u8>), RecordError> {
        if !(OVERHEAD..=MAX_RECORD_SIZE).contains(&wire.len()) {
            return Err(RecordError::Invalid);
        }
        if wire[..4] != self.epoch.to_be_bytes() {
            return Err(RecordError::Epoch);
        }
        let nonce = u64::from_be_bytes(wire[4..12].try_into().unwrap());
        let lane = usize::from(kind != KIND_DATA);
        let seq = nonce >> 1;
        if nonce & 1 != lane as u64 || seq >= MAX_RECORDS_PER_EPOCH {
            return Err(RecordError::Invalid);
        }
        let mut plain = Zeroizing::new(vec![0; wire.len() - LOOKUP_HEADER]);
        let len = self
            .state
            .read_message(nonce, &wire[LOOKUP_HEADER..], plain.as_mut())
            .map_err(|_| RecordError::Invalid)?;
        if len < RECORD_HEADER
            || plain[0] != VERSION
            || plain[1..17] != self.id.0
            || plain[17..29] != wire[..12]
            || plain[29] != kind
            || plain[30] != (self.role.wire() ^ 1)
        {
            return Err(RecordError::Invalid);
        }
        if !self.replay[lane].check_and_record(seq) {
            return Err(RecordError::Replay);
        }
        let expiry = u64::from_be_bytes(plain[31..39].try_into().unwrap());
        Ok((expiry, plain[RECORD_HEADER..len].to_vec()))
    }

    pub(crate) fn epoch(&self) -> u32 {
        self.epoch
    }
}

pub(crate) struct Epochs {
    pub(crate) current: RecordKeys,
    previous: Option<(Instant, RecordKeys)>,
}

impl Epochs {
    pub(crate) fn new(current: RecordKeys) -> Self {
        Self {
            current,
            previous: None,
        }
    }

    pub(crate) fn install(&mut self, next: RecordKeys, now: Instant) -> Result<()> {
        ensure!(
            self.current.epoch.checked_add(1) == Some(next.epoch)
                && self.current.id == next.id
                && self.current.role == next.role,
            "invalid Flow epoch transition"
        );
        self.previous = Some((
            now + Duration::from_secs(2),
            std::mem::replace(&mut self.current, next),
        ));
        Ok(())
    }

    pub(crate) fn retire(&mut self, now: Instant) {
        if self
            .previous
            .as_ref()
            .is_some_and(|(expiry, _)| now >= *expiry)
        {
            self.previous = None;
        }
    }

    pub(crate) fn open_data(
        &mut self,
        wire: &[u8],
        now: Instant,
    ) -> Result<(u64, Vec<u8>), RecordError> {
        self.retire(now);
        match self.current.open(KIND_DATA, wire) {
            Err(RecordError::Epoch) => self
                .previous
                .as_mut()
                .ok_or(RecordError::Epoch)?
                .1
                .open(KIND_DATA, wire),
            result => result,
        }
    }
}

#[cfg(test)]
#[path = "vectors.rs"]
mod vectors;
