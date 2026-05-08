use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use rand::seq::SliceRandom;

use crate::node::options::{NodeRole, TopologyTuning};
use crate::peer_score::{PeerScoreStore, PeerScoreWeights, total_score};
use crate::topology::{NodeDescriptor, PeerCatalog};
use crate::types::PeerId;

pub const REGULAR_BOOTSTRAP_DIAL_QUOTA: usize = 2;
pub const INCOMING_ROTATION_INTERVAL_MS: u64 = 1_500;
pub const BOOTSTRAP_INCOMING_HEADROOM: usize = 3;
pub const REGULAR_INCOMING_RESERVE_SLOTS: usize = 0;
pub const BOOTSTRAP_INCOMING_RESERVE_SLOTS: usize = 1;
pub const BOOTSTRAP_RESEED_INTERVAL_MS: u64 = 12_000;
pub const REGULAR_SELF_HEAL_FLOOR: usize = 3;
pub const DIAL_HUB_SOFT_CAP_EXTRA: usize = 2;

const OVERLOAD_REDIRECT_LIMIT: usize = 24;
const DIAL_HUB_PRESSURE_PENALTY: f32 = 0.14;
const DIAL_SATURATION_PENALTY: f32 = 2.0;
const DIAL_NO_DESCRIPTOR_PENALTY: f32 = 0.25;
const DIAL_BOOTSTRAP_RECOVERY_BONUS: f32 = 1.25;
const DIAL_MESH_NON_BOOTSTRAP_BONUS: f32 = 0.42;
const DIAL_VS_MEDIAN_LOAD_FACTOR: f32 = 0.11;
const RANK_TIE_SCORE_EPS: f32 = 0.14;

/// Максимальный штраф за высокий RTT в композитном скоре.
pub const DIAL_LATENCY_PENALTY_CAP: f32 = 2.0;
/// RTT (мс), после которого штраф близок к максимуму.
pub const DIAL_LATENCY_HIGH_MS: f32 = 400.0;
/// Бонус за разнообразие /24 в utility-слотах.
pub const DIAL_GEO_DIVERSITY_BONUS: f32 = 0.25;
/// Минимум XOR-ближайших среди utility-слотов.
pub const STRUCTURED_XOR_MIN: usize = 3;
/// Максимум XOR-ближайших (чтобы не захватить весь dial-target).
pub const STRUCTURED_XOR_MAX: usize = 8;
/// Exploratory-слоты: рандомная ротация для эпидемического покрытия.
pub const EXPLORATORY_SLOTS: usize = 2;
pub const EXPLORATORY_SLOTS_MAX: usize = 4;

/// Целевое число активных соседей для `Regular` — log-масштаб без
/// переуплотнения графа в малых/средних кластерах.
/// При `known_peers = N`: `target ≈ ceil(log2(N+1)) + 2`. Даёт
/// N=50 → ~8, N=1k → ~12, N=10k → ~16 — достаточно для O(log N)
/// диаметра, но без «почти-полносвязного» поведения.
///
/// `capacity_factor` ∈ [0.7; 1.25]: сильные узлы (низкий cpu/mem, высокий
/// `base_session_limit`) получают бонус, слабые — штраф. Естественные
/// «локальные хабы» без гегемонии.
pub fn regular_auto_dial_target(
    known_peers: usize,
    tuning: &TopologyTuning,
    capacity_factor: f32,
) -> usize {
    let log_term = ((known_peers.saturating_add(1)) as f32).log2().ceil() as usize;
    let base_target = log_term.saturating_add(2);
    let factor = capacity_factor.clamp(0.7, 1.25);
    let scaled = ((base_target as f32) * factor).round() as usize;
    let min_t = tuning.regular_auto_target_min;
    let max_t = tuning.regular_auto_target_max.max(min_t);
    if tuning.adaptive_topology_enabled {
        let floor = tuning
            .adaptive_target_min_floor
            .min(tuning.adaptive_target_max_ceil);
        let ceil = tuning.adaptive_target_max_ceil.max(floor);
        scaled.clamp(min_t.max(floor), max_t.min(ceil).max(min_t.max(floor)))
    } else {
        scaled.clamp(min_t, max_t)
    }
}

/// Capacity-фактор для target-scaling: 1.0 при номинальной нагрузке,
/// > 1.0 при большом запасе, < 1.0 при перегреве.
pub fn capacity_target_factor(cpu_load: f32, mem_pressure: f32, base_session_limit: u16) -> f32 {
    let load = cpu_load.max(mem_pressure).clamp(0.0, 1.0);
    let load_factor = 1.5 - load;
    let cap_factor = ((base_session_limit as f32) / 64.0).clamp(0.5, 1.5);
    ((load_factor + cap_factor) / 2.0).clamp(0.5, 1.5)
}

/// XOR-расстояние между двумя hex-представлениями PeerId.
/// Парсит первые 32 байта из hex и XOR'ит побайтно. Если парсинг
/// не удался — возвращает максимальное расстояние (все 0xFF).
pub fn xor_distance(a: &str, b: &str) -> [u8; 32] {
    fn hex_nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    fn pid_to_bytes(s: &str) -> Option<[u8; 32]> {
        let mut out = [0u8; 32];
        let bytes = s.as_bytes();
        let pairs = (bytes.len() / 2).min(32);
        for i in 0..pairs {
            let hi = hex_nibble(bytes[i * 2])?;
            let lo = hex_nibble(bytes[i * 2 + 1])?;
            out[i] = (hi << 4) | lo;
        }
        Some(out)
    }
    let Some(av) = pid_to_bytes(a) else {
        return [0xFFu8; 32];
    };
    let Some(bv) = pid_to_bytes(b) else {
        return [0xFFu8; 32];
    };
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = av[i] ^ bv[i];
    }
    out
}

/// Сколько core-слотов зарезервировать под XOR-ближайших.
/// Формула: `ceil(log2(N+1)).clamp(STRUCTURED_XOR_MIN, STRUCTURED_XOR_MAX)`.
/// Гарантирует O(log N) диаметр независимо от размера сети.
pub fn structured_slot_count(known_peers: usize) -> usize {
    let log_term = ((known_peers.saturating_add(1)) as f32).log2().ceil() as usize;
    log_term.clamp(STRUCTURED_XOR_MIN, STRUCTURED_XOR_MAX)
}

/// «Достаточно» связность, чтобы отдавать предпочтение только «принимающим» пирам и не перегружать хабы.
#[inline]
pub fn connectivity_selective(n: usize, dial_target: usize, min_active_peers: usize) -> bool {
    n >= dial_target && n >= min_active_peers
}

/// Сколько адресов перебирать за один тик на одного кандидата: при дефиците — агрессивнее.
pub fn dial_endpoint_attempt_budget(
    n: usize,
    dial_target: usize,
    min_active_peers: usize,
    addr_count: usize,
) -> usize {
    if addr_count == 0 {
        return 0;
    }
    if n < min_active_peers.max(1) || n + 1 < dial_target {
        return addr_count.min(4);
    }
    if n < dial_target {
        return addr_count.min(3);
    }
    addr_count.min(2)
}

#[allow(clippy::too_many_arguments)]
fn rank_dial_candidates_slice(
    candidates: &mut [PeerId],
    peer_store: &PeerScoreStore,
    weights: &PeerScoreWeights,
    desc_by_peer: &HashMap<PeerId, NodeDescriptor>,
    local_peer_id: &str,
    node_role: NodeRole,
    dial_target: usize,
    connected_bootstrap: usize,
    bootstrap_quota: usize,
    median_ac: f32,
    bootstrap_entry_peers: usize,
    connected_prefix24: &HashSet<[u8; 3]>,
) {
    if candidates.len() <= 1 {
        return;
    }
    candidates.sort_by(|a, b| {
        let sa = dial_candidate_score(
            a,
            peer_store,
            weights,
            desc_by_peer,
            local_peer_id,
            node_role,
            dial_target,
            connected_bootstrap,
            bootstrap_quota,
            median_ac,
            bootstrap_entry_peers,
            connected_prefix24,
        );
        let sb = dial_candidate_score(
            b,
            peer_store,
            weights,
            desc_by_peer,
            local_peer_id,
            node_role,
            dial_target,
            connected_bootstrap,
            bootstrap_quota,
            median_ac,
            bootstrap_entry_peers,
            connected_prefix24,
        );
        sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
    });
    let scores: Vec<f32> = candidates
        .iter()
        .map(|p| {
            dial_candidate_score(
                p,
                peer_store,
                weights,
                desc_by_peer,
                local_peer_id,
                node_role,
                dial_target,
                connected_bootstrap,
                bootstrap_quota,
                median_ac,
                bootstrap_entry_peers,
                connected_prefix24,
            )
        })
        .collect();
    let mut rng = rand::rng();
    let mut i = 0usize;
    while i < candidates.len() {
        let mut j = i + 1;
        while j < candidates.len() && (scores[i] - scores[j]).abs() <= RANK_TIE_SCORE_EPS {
            j += 1;
        }
        if j - i > 1 {
            candidates[i..j].shuffle(&mut rng);
        }
        i = j;
    }
}

/// Извлекает /24-префикс (3 октета) первого IPv4 из observed_addrs
/// — грубый geo-bucket для diversity-penalty.
pub fn descriptor_prefix24(desc: &NodeDescriptor) -> Option<[u8; 3]> {
    for line in &desc.observed_addrs {
        if let Some((_, addr)) = crate::topology::parse_observed_addr_line(line) {
            if let IpAddr::V4(v4) = addr.ip() {
                let o = v4.octets();
                return Some([o[0], o[1], o[2]]);
            }
        }
    }
    None
}

/// Сортировка кандидатов на исходящий дозвон. Применяет:
/// - `mesh_first`: не-bootstrap ранжируются раньше bootstrap (в steady state).
/// - Composite score: `total_score` + latency penalty + geo-diversity penalty.
/// - XOR-promotion: первые `k_xor` non_boot-слотов отводятся XOR-ближайшим
///   к `local_peer_id` для гарантии O(log N) диаметра.
#[allow(clippy::too_many_arguments)]
pub fn rank_dial_candidates(
    candidates: &mut Vec<PeerId>,
    peer_store: &PeerScoreStore,
    weights: &PeerScoreWeights,
    desc_by_peer: &HashMap<PeerId, NodeDescriptor>,
    local_peer_id: &str,
    node_role: NodeRole,
    dial_target: usize,
    connected_bootstrap: usize,
    bootstrap_quota: usize,
    mesh_first: bool,
    current_sessions: usize,
    min_active_peers: usize,
    connected_prefix24: &HashSet<[u8; 3]>,
    known_peers: usize,
    exploratory_slots: usize,
) {
    let median_ac = median_active_connections(desc_by_peer);
    let bootstrap_entry_peers = desc_by_peer
        .values()
        .filter(|d| d.capabilities.bootstrap_entry)
        .count();
    let mesh_first = mesh_first
        && matches!(node_role, NodeRole::Regular)
        && connected_bootstrap >= 1
        && current_sessions >= min_active_peers.max(1);
    if !mesh_first {
        rank_dial_candidates_slice(
            candidates.as_mut_slice(),
            peer_store,
            weights,
            desc_by_peer,
            local_peer_id,
            node_role,
            dial_target,
            connected_bootstrap,
            bootstrap_quota,
            median_ac,
            bootstrap_entry_peers,
            connected_prefix24,
        );
        promote_xor_closest(
            candidates.as_mut_slice(),
            desc_by_peer,
            local_peer_id,
            known_peers,
        );
        inject_exploratory_slots(
            candidates,
            local_peer_id,
            known_peers,
            dial_target,
            exploratory_slots,
        );
        return;
    }
    let mut non_boot: Vec<PeerId> = Vec::new();
    let mut boot: Vec<PeerId> = Vec::new();
    for p in candidates.drain(..) {
        if desc_by_peer
            .get(&p)
            .is_some_and(|d| d.capabilities.bootstrap_entry)
        {
            boot.push(p);
        } else {
            non_boot.push(p);
        }
    }
    rank_dial_candidates_slice(
        &mut non_boot,
        peer_store,
        weights,
        desc_by_peer,
        local_peer_id,
        node_role,
        dial_target,
        connected_bootstrap,
        bootstrap_quota,
        median_ac,
        bootstrap_entry_peers,
        connected_prefix24,
    );
    // XOR-promotion на первых k_xor non_boot позициях: гарантия routing O(log N).
    promote_xor_closest(
        non_boot.as_mut_slice(),
        desc_by_peer,
        local_peer_id,
        known_peers,
    );
    inject_exploratory_slots(
        &mut non_boot,
        local_peer_id,
        known_peers,
        dial_target,
        exploratory_slots,
    );
    rank_dial_candidates_slice(
        &mut boot,
        peer_store,
        weights,
        desc_by_peer,
        local_peer_id,
        node_role,
        dial_target,
        connected_bootstrap,
        bootstrap_quota,
        median_ac,
        bootstrap_entry_peers,
        connected_prefix24,
    );
    candidates.extend(non_boot);
    candidates.extend(boot);
}

/// Slot mix в ранжировании: первые места сохраняют structured+utility,
/// затем вставляем ограниченное число exploratory-кандидатов из хвоста.
/// Exploratory выбираются как XOR-далёкие от локального peer_id, чтобы
/// не локализоваться в одном кластере.
fn inject_exploratory_slots(
    candidates: &mut Vec<PeerId>,
    local_peer_id: &str,
    known_peers: usize,
    dial_target: usize,
    exploratory_slots: usize,
) {
    if candidates.len() <= 2 || dial_target == 0 {
        return;
    }
    let k_xor = structured_slot_count(known_peers)
        .min(dial_target)
        .min(candidates.len());
    let remain = candidates.len().saturating_sub(k_xor);
    if remain == 0 {
        return;
    }
    let k_explore = exploratory_slots
        .min(remain)
        .min(dial_target.saturating_sub(k_xor).max(1));
    if k_explore == 0 {
        return;
    }
    let k_metric = dial_target.saturating_sub(k_xor.saturating_add(k_explore));
    let metric_end = (k_xor.saturating_add(k_metric)).min(candidates.len());
    if metric_end >= candidates.len() {
        return;
    }

    let mut tail: Vec<(usize, [u8; 32])> = (metric_end..candidates.len())
        .map(|i| (i, xor_distance(local_peer_id, candidates[i].as_str())))
        .collect();
    // Чем дальше XOR, тем более exploratory-кандидат.
    tail.sort_by(|a, b| b.1.cmp(&a.1));
    let selected: Vec<usize> = tail.into_iter().take(k_explore).map(|(i, _)| i).collect();
    if selected.is_empty() {
        return;
    }

    let mut is_selected = vec![false; candidates.len()];
    for i in &selected {
        is_selected[*i] = true;
    }
    let mut reordered: Vec<PeerId> = Vec::with_capacity(candidates.len());
    reordered.extend(candidates.iter().take(metric_end).cloned());
    for i in selected {
        reordered.push(candidates[i].clone());
    }
    for (i, pid) in candidates.iter().enumerate().skip(metric_end) {
        if !is_selected[i] {
            reordered.push(pid.clone());
        }
    }
    *candidates = reordered;
}

/// Поднимает первых `k_xor = structured_slot_count(known_peers)` XOR-ближайших
/// к `local_peer_id` в начало списка non-bootstrap кандидатов. Структурный
/// core для маршрутизации O(log N). Только не-bootstrap: bootstrap'ы не должны
/// быть частью mesh-routing.
fn promote_xor_closest(
    candidates: &mut [PeerId],
    desc_by_peer: &HashMap<PeerId, NodeDescriptor>,
    local_peer_id: &str,
    known_peers: usize,
) {
    if candidates.len() <= 1 {
        return;
    }
    let k_xor = structured_slot_count(known_peers).min(candidates.len());
    // Выбираем k_xor индексов с минимальным XOR-distance.
    let mut xor_ranked: Vec<(usize, [u8; 32])> = candidates
        .iter()
        .enumerate()
        .filter(|(_, pid)| {
            !desc_by_peer
                .get(*pid)
                .is_some_and(|d| d.capabilities.bootstrap_entry)
        })
        .map(|(i, pid)| (i, xor_distance(local_peer_id, pid.as_str())))
        .collect();
    if xor_ranked.len() <= 1 {
        return;
    }
    xor_ranked.sort_by(|a, b| a.1.cmp(&b.1));
    let take_k = k_xor.min(xor_ranked.len());
    let selected: Vec<usize> = xor_ranked
        .into_iter()
        .take(take_k)
        .map(|(i, _)| i)
        .collect();
    // Перекладываем selected в начало, остальных — назад, сохраняя их порядок.
    let mut is_selected = vec![false; candidates.len()];
    for &i in &selected {
        is_selected[i] = true;
    }
    let mut reordered: Vec<PeerId> = Vec::with_capacity(candidates.len());
    for &i in &selected {
        reordered.push(candidates[i].clone());
    }
    for (i, pid) in candidates.iter().enumerate() {
        if !is_selected[i] {
            reordered.push(pid.clone());
        }
    }
    for (i, pid) in reordered.into_iter().enumerate() {
        candidates[i] = pid;
    }
}

pub fn should_skip_for_bootstrap_quota(
    desc: &NodeDescriptor,
    node_role: NodeRole,
    connected_bootstrap: usize,
    bootstrap_quota: usize,
    current_peers: usize,
    min_active_peers: usize,
) -> bool {
    matches!(node_role, NodeRole::Regular)
        && desc.capabilities.bootstrap_entry
        && ((connected_bootstrap >= bootstrap_quota && current_peers >= min_active_peers)
                // Even before reaching full target connectivity, keep only one bootstrap edge
                // once we already have at least a couple of peers.
                || (connected_bootstrap >= 1 && current_peers >= 2))
}

pub fn bootstrap_dial_quota(node_role: NodeRole) -> usize {
    if matches!(node_role, NodeRole::Regular) {
        REGULAR_BOOTSTRAP_DIAL_QUOTA
    } else {
        usize::MAX
    }
}

pub fn dial_reserve_slots(node_role: NodeRole) -> usize {
    if matches!(node_role, NodeRole::BootstrapJoin) {
        BOOTSTRAP_INCOMING_RESERVE_SLOTS
    } else {
        REGULAR_INCOMING_RESERVE_SLOTS
    }
}

pub fn should_reseed_bootstrap(
    active_peers: usize,
    min_active_peers: usize,
    connected_bootstrap: usize,
    now_ms: u64,
    last_reseed_ms: u64,
) -> bool {
    let low_connectivity =
        active_peers == 0 || (active_peers < min_active_peers && connected_bootstrap == 0);
    low_connectivity && now_ms.saturating_sub(last_reseed_ms) >= BOOTSTRAP_RESEED_INTERVAL_MS
}

/// Блокирует только «лишние» reseed по низкой связности, когда каталог ещё маленький и bootstrap уже есть.
/// Не используется для `missing_bootstrap_bridge` — мост к bootstrap должен оставаться доступным.
pub fn stable_bootstrap_reseed_guard(
    tuning: &TopologyTuning,
    node_role: NodeRole,
    n: usize,
    min_active_peers: usize,
    known_peers: usize,
    bootstrap_targets_len: usize,
    connected_bootstrap: usize,
) -> bool {
    if !tuning.avoid_reseed_when_stable_bootstrap {
        return false;
    }
    if n < min_active_peers.max(1) {
        return false;
    }
    let only_seed_known_mode = matches!(node_role, NodeRole::Regular)
        && n > 0
        && bootstrap_targets_len > 0
        && known_peers <= bootstrap_targets_len.saturating_add(1);
    let thin_catalog_stable_bootstrap = matches!(node_role, NodeRole::Regular)
        && connected_bootstrap > 0
        && known_peers < tuning.bootstrap_stable_peer_threshold;
    only_seed_known_mode || thin_catalog_stable_bootstrap
}

pub fn peers_to_drop_when_overloaded(
    connected: Vec<PeerId>,
    drop_n: usize,
    catalog: &PeerCatalog,
    peer_store: &PeerScoreStore,
    weights: &PeerScoreWeights,
    node_role: NodeRole,
) -> Vec<PeerId> {
    if drop_n == 0 || connected.is_empty() {
        return vec![];
    }
    let score = |p: &PeerId| total_score(&peer_store.get(p), weights);
    let boot_load = |p: &PeerId| {
        catalog
            .descriptor_of(p)
            .map(|d| d.dynamic_status.active_connections)
            .unwrap_or(0)
    };
    let mut boot: Vec<_> = connected
        .iter()
        .filter(|p| catalog.peer_is_bootstrap_entry(p))
        .cloned()
        .collect();
    let mut regular: Vec<_> = connected
        .iter()
        .filter(|p| !catalog.peer_is_bootstrap_entry(p))
        .cloned()
        .collect();
    match node_role {
        NodeRole::Regular => boot.sort_by(|a, b| {
            boot_load(b).cmp(&boot_load(a)).then_with(|| {
                score(a)
                    .partial_cmp(&score(b))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        }),
        NodeRole::BootstrapJoin => boot.sort_by(|a, b| {
            score(a)
                .partial_cmp(&score(b))
                .unwrap_or(std::cmp::Ordering::Equal)
        }),
    }
    regular.sort_by(|a, b| {
        score(a)
            .partial_cmp(&score(b))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let ordered: Vec<PeerId> = match node_role {
        NodeRole::Regular => boot.into_iter().chain(regular.into_iter()).collect(),
        NodeRole::BootstrapJoin => regular.into_iter().chain(boot.into_iter()).collect(),
    };
    ordered.into_iter().take(drop_n).collect()
}

pub(crate) const OVERLOAD_REDIRECT_DESCRIPTOR_LIMIT: usize = OVERLOAD_REDIRECT_LIMIT;

fn median_active_connections(desc_by_peer: &HashMap<PeerId, NodeDescriptor>) -> f32 {
    let mut v: Vec<u16> = desc_by_peer
        .values()
        .map(|d| d.dynamic_status.active_connections)
        .collect();
    if v.is_empty() {
        return 6.0;
    }
    v.sort_unstable();
    let mid = v.len() / 2;
    if v.len() % 2 == 0 {
        (v[mid.saturating_sub(1)] as f32 + v[mid] as f32) / 2.0
    } else {
        v[mid] as f32
    }
}

#[allow(clippy::too_many_arguments)]
fn dial_candidate_score(
    pid: &PeerId,
    peer_store: &PeerScoreStore,
    weights: &PeerScoreWeights,
    desc_by_peer: &HashMap<PeerId, NodeDescriptor>,
    local_peer_id: &str,
    node_role: NodeRole,
    dial_target: usize,
    connected_bootstrap: usize,
    bootstrap_quota: usize,
    median_active_conn: f32,
    bootstrap_entry_peers: usize,
    connected_prefix24: &HashSet<[u8; 3]>,
) -> f32 {
    let peer_score = peer_store.get(pid);
    let mut score = total_score(&peer_score, weights);

    // Жёсткий latency penalty: отсекает геоудалённые пиры (RU<->US etc.).
    // Линеен до DIAL_LATENCY_HIGH_MS, потом clamp на CAP.
    let latency_penalty = ((peer_score.latency_ms as f32) / DIAL_LATENCY_HIGH_MS)
        .clamp(0.0, DIAL_LATENCY_PENALTY_CAP);
    score -= latency_penalty;

    let Some(desc) = desc_by_peer.get(pid) else {
        return score - DIAL_NO_DESCRIPTOR_PENALTY;
    };

    let cap = desc.capabilities.base_session_limit.max(1) as f32;
    let utilization = (desc.dynamic_status.active_connections as f32 / cap).max(0.0);
    score -= utilization * DIAL_SATURATION_PENALTY;

    let over_target = (desc.dynamic_status.active_connections as f32 - dial_target as f32).max(0.0);
    score -= over_target * DIAL_HUB_PRESSURE_PENALTY;

    let ac = desc.dynamic_status.active_connections as f32;
    let vs_median = (ac - median_active_conn).max(0.0);
    score -= vs_median * DIAL_VS_MEDIAN_LOAD_FACTOR;

    // Geo-diversity: штраф если /24 уже присутствует среди активных подключений.
    // Бонус за уникальный /24 → разнообразие подсетей в mesh.
    if let Some(prefix) = descriptor_prefix24(desc) {
        if connected_prefix24.contains(&prefix) {
            score -= DIAL_GEO_DIVERSITY_BONUS;
        } else if !connected_prefix24.is_empty() {
            score += DIAL_GEO_DIVERSITY_BONUS * 0.5;
        }
    }

    if !desc.dynamic_status.accepts_new_sessions && !desc.capabilities.bootstrap_entry {
        score -= 10.0;
    }
    if desc.capabilities.bootstrap_entry && matches!(node_role, NodeRole::Regular) {
        score -= 0.35;
        if connected_bootstrap == 0 {
            score += DIAL_BOOTSTRAP_RECOVERY_BONUS;
        }
        if connected_bootstrap >= bootstrap_quota {
            score -= 2.5;
        }
        if bootstrap_entry_peers >= 2 && connected_bootstrap >= 1 {
            score -= vs_median * 0.06;
        }
    }
    if matches!(node_role, NodeRole::Regular)
        && !desc.capabilities.bootstrap_entry
        && dial_target >= 2
    {
        score += DIAL_MESH_NON_BOOTSTRAP_BONUS;
    }

    score += diversity_jitter(local_peer_id, pid.as_str(), 0.18);

    score
}

fn diversity_jitter(local_peer_id: &str, candidate_peer_id: &str, amplitude: f32) -> f32 {
    let mut h: u32 = 0x811C9DC5;
    for b in local_peer_id
        .as_bytes()
        .iter()
        .chain(candidate_peer_id.as_bytes().iter())
    {
        h ^= u32::from(*b);
        h = h.wrapping_mul(16777619);
    }
    let norm = (h as f32) / (u32::MAX as f32);
    (norm * 2.0 - 1.0) * amplitude
}
