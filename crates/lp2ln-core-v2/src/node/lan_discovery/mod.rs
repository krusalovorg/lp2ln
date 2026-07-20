// LAN multicast discovery service.
//
// Периодически рассылает подписанный LanHello на два адреса:
//   IPv4: 239.255.42.1:42500  (RFC 2365 administratively scoped)
//   IPv6: [ff02::1:4250]:42500 (link-local, best-effort)
//
// При получении: проверяет подпись, кэш nonce-реплеев, rate-лимит по peer,
// затем записывает endpoint'ы в PeerDirectory — никакого dialing здесь нет.
//
// ADR: мультикаст-группы и порт 42500 закреплены здесь, а не в публичном
// идентификаторе протокола, чтобы менять их без изменения wire-protocol.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use k256::ecdsa::SigningKey;
use k256::ecdsa::signature::{Signer, Verifier};
use k256::ecdsa::{Signature, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::node::options::LanDiscoveryOptions;
use crate::topology::now_ms;
use crate::topology::peer_directory::PeerDirectory;
use crate::types::PeerId;

pub const LAN_PROTO_VERSION: u16 = 1;
pub const MULTICAST_V4: Ipv4Addr = Ipv4Addr::new(239, 255, 42, 1);
pub const MULTICAST_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0x0001, 0x4250);
pub const LAN_PORT: u16 = 42500;

const MAX_HELLO_BYTES: usize = 1400;

// ---- wire types ------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanHello {
    pub protocol_version: u16,
    /// Hex-encoded compressed secp256k1 public key (33 bytes = 66 hex chars).
    pub peer_id: String,
    /// Hex-encoded [u8; 16] random per process start — меняется при ребуте.
    pub boot_id: String,
    /// Монотонно растёт в рамках одного boot_id.
    pub seq: u64,
    /// Endpoint'ы: "tcp:IP:port" / "udp:IP:port" / "quic:IP:port".
    /// 0.0.0.0 и :: означают «используй source IP пакета».
    pub endpoints: Vec<String>,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    /// Hex-encoded [u8; 16] random per message — защита от replay.
    pub nonce: String,
    #[serde(default)]
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum LanMessage {
    Hello(LanHello),
}

// ---- sign / verify ---------------------------------------------------------

#[derive(Serialize)]
struct LanHelloUnsigned<'a> {
    protocol_version: u16,
    peer_id: &'a str,
    boot_id: &'a str,
    seq: u64,
    endpoints: &'a [String],
    issued_at_ms: u64,
    expires_at_ms: u64,
    nonce: &'a str,
}

pub fn sign_hello(hello: &mut LanHello, key: &SigningKey) -> Result<(), String> {
    hello.signature.clear();
    let u = to_unsigned(hello);
    let data = serde_json::to_vec(&u).map_err(|e| e.to_string())?;
    let sig: Signature = key.sign(&data);
    hello.signature = hex::encode(sig.to_bytes());
    Ok(())
}

fn verify_hello(hello: &LanHello) -> Result<(), String> {
    let pubkey_bytes = hex::decode(&hello.peer_id).map_err(|e| e.to_string())?;
    let vk = VerifyingKey::from_sec1_bytes(&pubkey_bytes).map_err(|e| e.to_string())?;
    let sig_bytes = hex::decode(&hello.signature).map_err(|e| e.to_string())?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|e| e.to_string())?;
    let data = serde_json::to_vec(&to_unsigned(hello)).map_err(|e| e.to_string())?;
    vk.verify(&data, &sig).map_err(|e| e.to_string())
}

fn to_unsigned(h: &LanHello) -> LanHelloUnsigned<'_> {
    LanHelloUnsigned {
        protocol_version: h.protocol_version,
        peer_id: &h.peer_id,
        boot_id: &h.boot_id,
        seq: h.seq,
        endpoints: &h.endpoints,
        issued_at_ms: h.issued_at_ms,
        expires_at_ms: h.expires_at_ms,
        nonce: &h.nonce,
    }
}

// ---- sockets ---------------------------------------------------------------

fn bind_multicast_v4(port: u16) -> anyhow::Result<UdpSocket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    #[cfg(unix)]
    s.set_reuse_port(true)?;
    s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
    s.set_multicast_loop_v4(false)?;
    s.join_multicast_v4(&MULTICAST_V4, &Ipv4Addr::UNSPECIFIED)?;
    s.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(s.into())?)
}

fn bind_multicast_v6(port: u16) -> anyhow::Result<UdpSocket> {
    let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_only_v6(true)?;
    s.set_reuse_address(true)?;
    #[cfg(unix)]
    s.set_reuse_port(true)?;
    s.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
    s.set_multicast_loop_v6(false)?;
    // ponytail: interface 0 = default interface; для multi-homed нужен перебор интерфейсов
    s.join_multicast_v6(&MULTICAST_V6, 0)?;
    s.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(s.into())?)
}

// ---- helpers ---------------------------------------------------------------

fn random_hex16() -> String {
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b);
    hex::encode(b)
}

/// Парсит "proto:addr:port", заменяет unspecified IP на `source_ip`.
/// Возвращает None для loopback, port 0 или плохого формата.
fn resolve_endpoint(ep: &str, source_ip: IpAddr) -> Option<(String, SocketAddr)> {
    let lower = ep.to_ascii_lowercase();
    let (proto, rest) = if let Some(r) = lower.strip_prefix("tcp:") {
        ("tcp", r)
    } else if let Some(r) = lower.strip_prefix("udp:") {
        ("udp", r)
    } else if let Some(r) = lower.strip_prefix("quic:") {
        ("quic", r)
    } else {
        return None;
    };
    let addr: SocketAddr = rest.parse().ok()?;
    let final_ip = if addr.ip().is_unspecified() {
        source_ip
    } else {
        addr.ip()
    };
    if final_ip.is_loopback() || final_ip.is_unspecified() || addr.port() == 0 {
        return None;
    }
    Some((proto.to_string(), SocketAddr::new(final_ip, addr.port())))
}

/// Future-обёртка для optional socket: если None — вечно pending.
async fn recv_optional<'a>(
    sock: &'a Option<UdpSocket>,
    buf: &'a mut Vec<u8>,
) -> Option<std::io::Result<(usize, SocketAddr)>> {
    match sock {
        Some(s) => Some(s.recv_from(buf).await),
        None => {
            std::future::pending::<()>().await;
            unreachable!()
        }
    }
}

// ---- internal state --------------------------------------------------------

struct BootState {
    boot_id: String,
    last_seq: u64,
}

struct RateSlot {
    window_start_ms: u64,
    count: u32,
}

// ---- main loop -------------------------------------------------------------

pub async fn run_lan_discovery(
    cancel: CancellationToken,
    our_peer_id: String,
    signing_key: SigningKey,
    listen_endpoints: Vec<String>,
    peer_dir: Arc<PeerDirectory>,
    opts: LanDiscoveryOptions,
) {
    let socket_v4 = match bind_multicast_v4(opts.port) {
        Ok(s) => s,
        Err(e) => {
            crate::warn!(
                "[LanDiscovery] IPv4 multicast bind failed (port {}): {e}",
                opts.port
            );
            return;
        }
    };

    let socket_v6 = match bind_multicast_v6(opts.port) {
        Ok(s) => {
            crate::info!("[LanDiscovery] IPv6 multicast joined ff02::1:4250");
            Some(s)
        }
        Err(e) => {
            crate::info!("[LanDiscovery] IPv6 multicast unavailable: {e}");
            None
        }
    };

    let target_v4 = SocketAddr::from((MULTICAST_V4, opts.port));
    let target_v6 = SocketAddr::V6(SocketAddrV6::new(MULTICAST_V6, opts.port, 0, 0));

    let boot_id = random_hex16();
    let mut seq: u64 = 0;
    let mut buf_v4 = vec![0u8; 8192];
    let mut buf_v6 = vec![0u8; 8192];
    let mut nonce_cache: HashMap<String, u64> = HashMap::new();
    let mut peer_rate: HashMap<String, RateSlot> = HashMap::new();
    let mut peer_boot: HashMap<String, BootState> = HashMap::new();

    let mut tick = tokio::time::interval(Duration::from_millis(opts.announce_interval_ms));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,

            _ = tick.tick() => {
                if let Err(e) = send_hello(
                    &socket_v4, Some(&socket_v6), &target_v4, &target_v6,
                    &our_peer_id, &boot_id, &mut seq,
                    &listen_endpoints, &signing_key, &opts,
                ).await {
                    crate::warn!("[LanDiscovery] send error: {e}");
                }
            }

            result = socket_v4.recv_from(&mut buf_v4) => {
                match result {
                    Ok((n, src)) => handle_recv(
                        &buf_v4[..n], src, &our_peer_id, &peer_dir, &opts,
                        &mut nonce_cache, &mut peer_rate, &mut peer_boot,
                    ),
                    Err(e) => crate::warn!("[LanDiscovery] v4 recv error: {e}"),
                }
            }

            Some(result) = recv_optional(&socket_v6, &mut buf_v6) => {
                match result {
                    Ok((n, src)) => handle_recv(
                        &buf_v6[..n], src, &our_peer_id, &peer_dir, &opts,
                        &mut nonce_cache, &mut peer_rate, &mut peer_boot,
                    ),
                    Err(e) => crate::warn!("[LanDiscovery] v6 recv error: {e}"),
                }
            }
        }
    }
}

async fn send_hello(
    v4: &UdpSocket,
    v6: Option<&Option<UdpSocket>>,
    target_v4: &SocketAddr,
    target_v6: &SocketAddr,
    peer_id: &str,
    boot_id: &str,
    seq: &mut u64,
    endpoints: &[String],
    key: &SigningKey,
    opts: &LanDiscoveryOptions,
) -> anyhow::Result<()> {
    *seq = seq.wrapping_add(1);
    let now = now_ms();
    let mut hello = LanHello {
        protocol_version: LAN_PROTO_VERSION,
        peer_id: peer_id.to_string(),
        boot_id: boot_id.to_string(),
        seq: *seq,
        endpoints: endpoints.to_vec(),
        issued_at_ms: now,
        expires_at_ms: now + opts.hello_ttl_ms,
        nonce: random_hex16(),
        signature: String::new(),
    };
    sign_hello(&mut hello, key).map_err(|e| anyhow::anyhow!(e))?;
    let bytes = serde_json::to_vec(&LanMessage::Hello(hello))?;
    if bytes.len() > MAX_HELLO_BYTES {
        crate::warn!(
            "[LanDiscovery] hello слишком большой ({} б), не отправлен",
            bytes.len()
        );
        return Ok(());
    }
    v4.send_to(&bytes, target_v4).await?;
    if let Some(Some(s)) = v6 {
        if let Err(e) = s.send_to(&bytes, target_v6).await {
            crate::debug!("[LanDiscovery] v6 send skipped: {e}");
        }
    }
    Ok(())
}

fn handle_recv(
    data: &[u8],
    src: SocketAddr,
    our_peer_id: &str,
    peer_dir: &Arc<PeerDirectory>,
    opts: &LanDiscoveryOptions,
    nonce_cache: &mut HashMap<String, u64>,
    peer_rate: &mut HashMap<String, RateSlot>,
    peer_boot: &mut HashMap<String, BootState>,
) {
    let msg: LanMessage = match serde_json::from_slice(data) {
        Ok(m) => m,
        Err(_) => return,
    };
    match msg {
        LanMessage::Hello(h) => handle_hello(
            h,
            src,
            our_peer_id,
            peer_dir,
            opts,
            nonce_cache,
            peer_rate,
            peer_boot,
        ),
    }
}

fn handle_hello(
    hello: LanHello,
    src: SocketAddr,
    our_peer_id: &str,
    peer_dir: &Arc<PeerDirectory>,
    opts: &LanDiscoveryOptions,
    nonce_cache: &mut HashMap<String, u64>,
    peer_rate: &mut HashMap<String, RateSlot>,
    peer_boot: &mut HashMap<String, BootState>,
) {
    // Фильтр собственных анонсов и версия протокола.
    if hello.peer_id == our_peer_id || hello.protocol_version != LAN_PROTO_VERSION {
        return;
    }
    let now = now_ms();
    // Окно метки времени ±30 с.
    if hello.issued_at_ms > now + 30_000 || now.saturating_sub(hello.issued_at_ms) > 30_000 {
        return;
    }
    if hello.expires_at_ms <= now {
        return;
    }
    // Replay: чистим устаревшие nonce, проверяем текущий.
    nonce_cache.retain(|_, exp| *exp > now);
    if nonce_cache.contains_key(&hello.nonce) {
        return;
    }
    // Rate limit: не более N hello/сек на peer.
    let slot = peer_rate.entry(hello.peer_id.clone()).or_insert(RateSlot {
        window_start_ms: now,
        count: 0,
    });
    if now >= slot.window_start_ms + 1_000 {
        slot.window_start_ms = now;
        slot.count = 0;
    }
    slot.count += 1;
    if slot.count > opts.max_hellos_per_peer_per_sec {
        return;
    }
    // Подпись.
    if verify_hello(&hello).is_err() {
        return;
    }
    // boot_id / seq дедупликация.
    let should_update = match peer_boot.get(&hello.peer_id) {
        None => true,
        Some(state) => hello.boot_id != state.boot_id || hello.seq > state.last_seq,
    };
    if !should_update {
        return;
    }
    // Резолвим endpoint'ы, подставляя source IP для unspecified.
    let endpoints: Vec<(String, SocketAddr)> = hello
        .endpoints
        .iter()
        .filter_map(|ep| resolve_endpoint(ep, src.ip()))
        .collect();
    if endpoints.is_empty() {
        return;
    }
    // Записываем nonce только после всех проверок.
    nonce_cache.insert(hello.nonce.clone(), hello.expires_at_ms);

    let pid = PeerId::from(hello.peer_id.as_str());
    peer_dir.replace_lan_addresses(&pid, &endpoints, hello.expires_at_ms, now);
    peer_boot.insert(
        hello.peer_id.clone(),
        BootState {
            boot_id: hello.boot_id,
            last_seq: hello.seq,
        },
    );
    crate::debug!(
        "[LanDiscovery] peer {}… → {} endpoint(s) via {}",
        &hello.peer_id[..8.min(hello.peer_id.len())],
        endpoints.len(),
        src,
    );
}

// ---- tests -----------------------------------------------------------------

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::topology::peer_directory::PeerDirectory;
    use std::sync::Arc;

    pub fn make_key() -> SigningKey {
        let mut b = [0u8; 32];
        rand::rng().fill_bytes(&mut b);
        SigningKey::from_bytes((&b).into()).unwrap()
    }

    pub fn peer_id_of(key: &SigningKey) -> String {
        hex::encode(key.verifying_key().to_encoded_point(true).as_bytes())
    }

    fn make_hello(key: &SigningKey, seq: u64, now: u64) -> LanHello {
        let mut h = LanHello {
            protocol_version: LAN_PROTO_VERSION,
            peer_id: peer_id_of(key),
            boot_id: random_hex16(),
            seq,
            endpoints: vec!["tcp:0.0.0.0:8080".to_string()],
            issued_at_ms: now,
            expires_at_ms: now + 60_000,
            nonce: random_hex16(),
            signature: String::new(),
        };
        sign_hello(&mut h, key).unwrap();
        h
    }

    fn default_opts() -> LanDiscoveryOptions {
        LanDiscoveryOptions {
            enabled: true,
            port: LAN_PORT,
            announce_interval_ms: 15_000,
            hello_ttl_ms: 60_000,
            max_hellos_per_peer_per_sec: 5,
        }
    }

    fn call_handle(
        hello: LanHello,
        our_id: &str,
        dir: &Arc<PeerDirectory>,
        opts: &LanDiscoveryOptions,
        nonces: &mut HashMap<String, u64>,
        rates: &mut HashMap<String, RateSlot>,
        boots: &mut HashMap<String, BootState>,
    ) {
        let src: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        handle_hello(hello, src, our_id, dir, opts, nonces, rates, boots);
    }

    // ---- sign / verify ----

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = make_key();
        let mut h = make_hello(&key, 1, 1_000_000);
        h.signature.clear();
        sign_hello(&mut h, &key).unwrap();
        assert!(verify_hello(&h).is_ok());
    }

    #[test]
    fn tampered_hello_fails_verify() {
        let key = make_key();
        let mut h = make_hello(&key, 1, 1_000_000);
        h.seq = 999;
        assert!(verify_hello(&h).is_err());
    }

    // ---- resolve_endpoint ----

    #[test]
    fn resolve_substitutes_unspecified_ipv4() {
        let src: IpAddr = "192.168.1.10".parse().unwrap();
        let (proto, addr) = resolve_endpoint("tcp:0.0.0.0:8080", src).unwrap();
        assert_eq!(proto, "tcp");
        assert_eq!(addr.ip(), src);
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn resolve_substitutes_unspecified_ipv6() {
        let src: IpAddr = "fe80::1".parse().unwrap();
        let (_, addr) = resolve_endpoint("udp:[::]:9000", src).unwrap();
        assert_eq!(addr.ip(), src);
        assert_eq!(addr.port(), 9000);
    }

    #[test]
    fn resolve_rejects_loopback() {
        let src: IpAddr = "192.168.1.10".parse().unwrap();
        assert!(resolve_endpoint("tcp:127.0.0.1:8080", src).is_none());
    }

    #[test]
    fn resolve_rejects_port_zero() {
        let src: IpAddr = "192.168.1.10".parse().unwrap();
        assert!(resolve_endpoint("tcp:192.168.1.5:0", src).is_none());
    }

    // ---- handle_hello logic ----

    #[test]
    fn handle_hello_happy_path_writes_to_peer_dir() {
        let key = make_key();
        let our_id = "ourpeer".to_string();
        let dir = Arc::new(PeerDirectory::new());
        let opts = default_opts();
        let now = now_ms();
        let h = make_hello(&key, 1, now);
        let pid = peer_id_of(&key);

        let mut nonces = HashMap::new();
        let mut rates = HashMap::new();
        let mut boots = HashMap::new();
        call_handle(h, &our_id, &dir, &opts, &mut nonces, &mut rates, &mut boots);

        let book = dir.dial_book(now);
        assert!(
            book.contains_key(&PeerId::from(pid.as_str())),
            "peer должен появиться в dial_book"
        );
    }

    #[test]
    fn handle_hello_rejects_self_announcement() {
        let key = make_key();
        let our_id = peer_id_of(&key);
        let dir = Arc::new(PeerDirectory::new());
        let opts = default_opts();
        let now = now_ms();
        let h = make_hello(&key, 1, now);

        let mut nonces = HashMap::new();
        let mut rates = HashMap::new();
        let mut boots = HashMap::new();
        call_handle(h, &our_id, &dir, &opts, &mut nonces, &mut rates, &mut boots);

        assert!(dir.dial_book(now).is_empty());
    }

    #[test]
    fn handle_hello_rejects_replay() {
        let key = make_key();
        let our_id = "ourpeer".to_string();
        let dir = Arc::new(PeerDirectory::new());
        let opts = default_opts();
        let now = now_ms();
        let h = make_hello(&key, 1, now);
        let nonce = h.nonce.clone();

        let mut nonces = HashMap::new();
        let mut rates = HashMap::new();
        let mut boots = HashMap::new();

        // Первый вызов — принят, nonce попадает в кэш.
        call_handle(
            h.clone(),
            &our_id,
            &dir,
            &opts,
            &mut nonces,
            &mut rates,
            &mut boots,
        );
        assert!(nonces.contains_key(&nonce), "nonce должен быть в кэше");
        assert_eq!(boots.len(), 1, "первый hello принят");

        // Второй вызов с тем же nonce — отклоняется на replay-проверке.
        // Строим новый hello с тем же нonce, но другим seq, чтобы seq-проверка
        // не маскировала replay-отклонение.
        let mut h_replay = LanHello {
            seq: 99,
            nonce: nonce.clone(),
            ..h
        };
        sign_hello(&mut h_replay, &key).unwrap();
        call_handle(
            h_replay,
            &our_id,
            &dir,
            &opts,
            &mut nonces,
            &mut rates,
            &mut boots,
        );

        // boot state должен содержать seq=1 (от первого вызова), а не seq=99.
        let pid = peer_id_of(&key);
        assert_eq!(
            boots[&pid].last_seq, 1,
            "replay не должен обновлять boot state"
        );
    }

    #[test]
    fn handle_hello_rejects_when_rate_exceeded() {
        let key = make_key();
        let our_id = "ourpeer".to_string();
        let dir = Arc::new(PeerDirectory::new());
        let opts = LanDiscoveryOptions {
            max_hellos_per_peer_per_sec: 2,
            ..default_opts()
        };
        let now = now_ms();

        let mut nonces = HashMap::new();
        let mut rates = HashMap::new();
        let mut boots = HashMap::new();

        // Отправляем 3 разных hello — третий должен быть отброшен.
        for seq in 1u64..=3 {
            let h = make_hello(&key, seq, now);
            call_handle(h, &our_id, &dir, &opts, &mut nonces, &mut rates, &mut boots);
        }

        let slot = rates.get(&peer_id_of(&key)).unwrap();
        // count фиксируется на 3 (включая отброшенный), boot_id есть только один
        assert_eq!(boots.len(), 1); // третий hello не обновил boot state
    }

    #[test]
    fn handle_hello_rejects_stale_timestamp() {
        let key = make_key();
        let our_id = "ourpeer".to_string();
        let dir = Arc::new(PeerDirectory::new());
        let opts = default_opts();
        let now = now_ms();

        // issued_at_ms сильно в прошлом
        let mut h = LanHello {
            protocol_version: LAN_PROTO_VERSION,
            peer_id: peer_id_of(&key),
            boot_id: random_hex16(),
            seq: 1,
            endpoints: vec!["tcp:192.168.1.5:8080".to_string()],
            issued_at_ms: now.saturating_sub(60_000), // -60 секунд → за пределами окна
            expires_at_ms: now + 60_000,
            nonce: random_hex16(),
            signature: String::new(),
        };
        sign_hello(&mut h, &key).unwrap();

        let mut nonces = HashMap::new();
        let mut rates = HashMap::new();
        let mut boots = HashMap::new();
        call_handle(h, &our_id, &dir, &opts, &mut nonces, &mut rates, &mut boots);

        assert!(dir.dial_book(now).is_empty());
    }

    #[test]
    fn handle_hello_old_seq_dropped() {
        let key = make_key();
        let our_id = "ourpeer".to_string();
        let dir = Arc::new(PeerDirectory::new());
        let opts = default_opts();
        let now = now_ms();
        let pid = peer_id_of(&key);
        let boot_id = random_hex16();

        let mut nonces = HashMap::new();
        let mut rates = HashMap::new();
        let mut boots = HashMap::new();

        // seq=5 принят
        let mut h5 = LanHello {
            protocol_version: LAN_PROTO_VERSION,
            peer_id: pid.clone(),
            boot_id: boot_id.clone(),
            seq: 5,
            endpoints: vec!["tcp:0.0.0.0:8080".to_string()],
            issued_at_ms: now,
            expires_at_ms: now + 60_000,
            nonce: random_hex16(),
            signature: String::new(),
        };
        sign_hello(&mut h5, &key).unwrap();
        call_handle(
            h5,
            &our_id,
            &dir,
            &opts,
            &mut nonces,
            &mut rates,
            &mut boots,
        );
        assert_eq!(boots[&pid].last_seq, 5);

        // seq=3 — старый, должен быть отброшен
        let mut h3 = LanHello {
            protocol_version: LAN_PROTO_VERSION,
            peer_id: pid.clone(),
            boot_id: boot_id.clone(),
            seq: 3,
            endpoints: vec!["tcp:0.0.0.0:9999".to_string()],
            issued_at_ms: now,
            expires_at_ms: now + 60_000,
            nonce: random_hex16(),
            signature: String::new(),
        };
        sign_hello(&mut h3, &key).unwrap();
        call_handle(
            h3,
            &our_id,
            &dir,
            &opts,
            &mut nonces,
            &mut rates,
            &mut boots,
        );

        // last_seq не изменился
        assert_eq!(boots[&pid].last_seq, 5);
    }

    #[test]
    fn handle_hello_new_boot_id_replaces_addresses() {
        let key = make_key();
        let our_id = "ourpeer".to_string();
        let dir = Arc::new(PeerDirectory::new());
        let opts = default_opts();
        let now = now_ms();
        let pid = PeerId::from(peer_id_of(&key).as_str());

        let mut nonces = HashMap::new();
        let mut rates = HashMap::new();
        let mut boots = HashMap::new();

        // Первый boot
        let h1 = make_hello(&key, 1, now);
        call_handle(
            h1,
            &our_id,
            &dir,
            &opts,
            &mut nonces,
            &mut rates,
            &mut boots,
        );
        let addrs_before = dir.dial_book(now).get(&pid).cloned().unwrap_or_default();
        assert_eq!(addrs_before.len(), 1);
        assert_eq!(addrs_before[0].1.port(), 8080);

        // Второй boot с новым boot_id и другим портом
        let mut h2 = LanHello {
            protocol_version: LAN_PROTO_VERSION,
            peer_id: peer_id_of(&key),
            boot_id: random_hex16(), // новый boot_id
            seq: 1,
            endpoints: vec!["tcp:0.0.0.0:9090".to_string()],
            issued_at_ms: now,
            expires_at_ms: now + 60_000,
            nonce: random_hex16(),
            signature: String::new(),
        };
        sign_hello(&mut h2, &key).unwrap();
        call_handle(
            h2,
            &our_id,
            &dir,
            &opts,
            &mut nonces,
            &mut rates,
            &mut boots,
        );

        let addrs_after = dir.dial_book(now).get(&pid).cloned().unwrap_or_default();
        assert_eq!(addrs_after.len(), 1);
        assert_eq!(
            addrs_after[0].1.port(),
            9090,
            "старый адрес должен быть заменён"
        );
    }
}
