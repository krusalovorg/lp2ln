"""Обход нод: RequestAdjacency (живые TCP-сессии) + RequestPeers (дескрипторы, BFS)."""

from __future__ import annotations

import logging
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from . import client, wire

logger = logging.getLogger(__name__)


_TCP_ADDR = re.compile(r"^tcp:\s*(.+)$", re.I)


def _parse_tcp_addrs(observed: Iterable[str]) -> List[Tuple[str, int]]:
    out: List[Tuple[str, int]] = []
    for line in observed:
        s = (line or "").strip()
        m = _TCP_ADDR.match(s)
        if m:
            rest = m.group(1).strip()
        elif s.lower().startswith("udp:"):
            continue
        else:
            rest = s
        if ":" not in rest:
            continue
        try:
            host, port_s = rest.rsplit(":", 1)
            out.append((host.strip(), int(port_s.strip())))
        except ValueError:
            continue
    return out


@dataclass
class TopologyGraph:
    """nodes[peer_id] — последний дескриптор.
    edges (a,b) — у ноды a активная сессия к peer b (ответ RequestAdjacency).
    catalog_edges — опционально «a упомянула b в PeersResponse» (каталог, не TCP)."""

    nodes: Dict[str, dict] = field(default_factory=dict)
    edges: Set[Tuple[str, str]] = field(default_factory=set)
    catalog_edges: Set[Tuple[str, str]] = field(default_factory=set)
    seeds: List[str] = field(default_factory=list)
    unreachable: Dict[str, str] = field(default_factory=dict)
    # (host, port), на котором реально ответил seed после опционального сканирования портов
    seed_tcp: Optional[Tuple[str, int]] = None

    def merge_descriptor(self, desc: dict[str, Any]) -> str:
        pid = str(desc.get("peer_id", ""))
        if not pid:
            return ""
        self.nodes[pid] = desc
        return pid

    def add_catalog_edge(self, source_peer: str, desc: dict[str, Any]) -> str:
        pid = self.merge_descriptor(desc)
        if pid:
            self.catalog_edges.add((source_peer, pid))
        return pid


def _ensure_node_stub(g: TopologyGraph, peer_id: str) -> None:
    if peer_id and peer_id not in g.nodes:
        g.nodes[peer_id] = {
            "peer_id": peer_id,
            "observed_addrs": [],
            "capabilities": {},
            "dynamic_status": {},
        }


def snapshot_topology_graph(g: TopologyGraph) -> TopologyGraph:
    """Копия графа для передачи в другой поток (UI): не разделяет изменяемые dict узлов с обходом."""
    return TopologyGraph(
        nodes={pid: dict(desc) for pid, desc in g.nodes.items()},
        edges=set(g.edges),
        catalog_edges=set(g.catalog_edges),
        seeds=list(g.seeds),
        unreachable=dict(g.unreachable),
        seed_tcp=g.seed_tcp,
    )


def ego_session_topology(g: TopologyGraph, focus: str) -> TopologyGraph:
    """Узел focus, все соседи по рёбрам сессий и только рёбра, инцидентные focus (вход/выход)."""
    if not focus or focus not in g.nodes:
        return g
    inc_nodes: Set[str] = {focus}
    inc_edges: Set[Tuple[str, str]] = set()
    for a, b in g.edges:
        if a == focus or b == focus:
            inc_nodes.add(a)
            inc_nodes.add(b)
            inc_edges.add((a, b))
    nodes = {pid: dict(g.nodes[pid]) for pid in inc_nodes if pid in g.nodes}
    seeds = [s for s in g.seeds if s in inc_nodes]
    return TopologyGraph(
        nodes=nodes,
        edges=inc_edges,
        catalog_edges=set(),
        seeds=seeds,
        unreachable={},
        seed_tcp=g.seed_tcp,
    )


def find_lp2ln_tcp_port(
    host: str,
    port_lo: int,
    port_hi: int,
    *,
    timeout: float = 2.0,
    our_peer_id: str = client.VIEWER_PEER_ID,
    connect_retries: int = 1,
    retry_backoff_s: float = 0.15,
) -> Optional[int]:
    """Перебор портов port_lo..port_hi (включительно): первый успешный handshake LP2LN."""
    lo = max(1, min(int(port_lo), 65535))
    hi = max(1, min(int(port_hi), 65535))
    if hi < lo:
        lo, hi = hi, lo
    retries = max(1, int(connect_retries))
    for port in range(lo, hi + 1):
        last_err: Optional[BaseException] = None
        for attempt in range(1, retries + 1):
            try:
                sock, _rid, _ = client.connect_and_handshake(
                    host, port, timeout=timeout, our_peer_id=our_peer_id
                )
                try:
                    sock.close()
                except OSError:
                    pass
                logger.info("Seed: найден ответ LP2LN на %s:%s (диапазон %s–%s)", host, port, lo, hi)
                return port
            except (OSError, ConnectionError, TimeoutError, RuntimeError, ValueError) as e:
                last_err = e
                if attempt < retries:
                    time.sleep(max(0.0, retry_backoff_s) * attempt)
        logger.debug(
            "%s:%s — нет handshake (%s)",
            host,
            port,
            type(last_err).__name__ if last_err else "?",
        )
    logger.warning("Seed: в диапазоне %s:%s–%s ответа LP2LN не найдено", host, lo, hi)
    return None


def fetch_topology_from_node(
    host: str,
    port: int,
    *,
    limit: int = 64,
    peer_rounds: int = 1,
    timeout: float = 10.0,
    our_peer_id: str = client.VIEWER_PEER_ID,
    use_descriptors: bool = False,
    connect_retries: int = 1,
    retry_backoff_s: float = 0.2,
) -> Tuple[str, List[str], List[dict[str, Any]]]:
    """Handshake → RequestAdjacency → AdjacencyResponse → RequestPeers (несколько раундов) → PeersResponse.

    На стороне lp2ln-core-v2 за один ответ не больше 64 дескрипторов; при большем каталоге выборка
    частичная (версия/время + случайная доля). Повторные запросы на том же сокете дают другие подмножества.
    """
    req_name = "RequestDescriptors" if use_descriptors else "RequestPeers"
    rounds = max(1, int(peer_rounds))
    logger.info(
        "%s:%s → RequestAdjacency, затем %s (limit=%s, rounds=%s)",
        host,
        port,
        req_name,
        limit,
        rounds,
    )
    last_err: Optional[BaseException] = None
    sock = None
    remote_id = ""
    redirect_descs: Optional[List[dict[str, Any]]] = None
    retries = max(1, int(connect_retries))
    for attempt in range(1, retries + 1):
        try:
            sock, remote_id, redirect_descs = client.connect_and_handshake(
                host, port, timeout=timeout, our_peer_id=our_peer_id
            )
            break
        except (OSError, ConnectionError, TimeoutError, RuntimeError, ValueError) as e:
            last_err = e
            if attempt < retries:
                logger.debug(
                    "%s:%s connect/handshake attempt %s/%s failed: %s (%s)",
                    host,
                    port,
                    attempt,
                    retries,
                    type(e).__name__,
                    e,
                )
                time.sleep(max(0.0, retry_backoff_s) * attempt)
    if sock is None:
        assert last_err is not None
        raise last_err
    try:
        if redirect_descs is not None:
            logger.info(
                "%s:%s ← redirect: %s дескрипторов без RequestAdjacency/RequestPeers (лимит/закрытие сессии)",
                host,
                port,
                len(redirect_descs),
            )
            return remote_id, [], redirect_descs

        client.send_control_local(
            sock,
            our_peer_id=our_peer_id,
            remote_peer_id=remote_id,
            control_json_bytes=wire.control_request_adjacency(),
        )

        neighbors: List[str] = []
        got_adj = False
        for i in range(64):
            try:
                pkt = client.recv_packet(sock, timeout=timeout)
            except socket.timeout:
                logger.warning(
                    "%s:%s — таймаут после RequestAdjacency (%ss), пакетов=%s",
                    host,
                    port,
                    timeout,
                    i,
                )
                break
            adj = wire.try_parse_adjacency_response(pkt.data)
            if adj is not None:
                neighbors = adj
                got_adj = True
                logger.info("%s:%s ← AdjacencyResponse: %s соседей по сессиям", host, port, len(neighbors))
                break
            logger.debug(
                "%s:%s пакет #%s (ожидали AdjacencyResponse): %s",
                host,
                port,
                i,
                wire.peek_control_type(pkt.data),
            )

        if not got_adj:
            logger.warning(
                "%s:%s — нет AdjacencyResponse (старая нода без RequestAdjacency?). "
                "Рёбра сессий будут пустыми для этого хоста.",
                host,
                port,
            )

        merged: Dict[str, dict[str, Any]] = {}
        for r in range(rounds):
            body = (
                wire.control_request_descriptors(limit)
                if use_descriptors
                else wire.control_request_peers(limit)
            )
            client.send_control_local(
                sock, our_peer_id=our_peer_id, remote_peer_id=remote_id, control_json_bytes=body
            )

            got = False
            for i in range(64):
                try:
                    pkt = client.recv_packet(sock, timeout=timeout)
                except socket.timeout:
                    logger.warning(
                        "%s:%s — таймаут ожидания PeersResponse (%ss), раунд %s/%s, пакетов=%s",
                        host,
                        port,
                        timeout,
                        r + 1,
                        rounds,
                        i,
                    )
                    break
                descs = wire.try_parse_control_peers_response(pkt.data)
                if descs is not None:
                    n_new = 0
                    for d in descs:
                        pid = str(d.get("peer_id", ""))
                        if pid and pid not in merged:
                            n_new += 1
                        if pid:
                            merged[pid] = d
                    logger.info(
                        "%s:%s ← PeersResponse раунд %s/%s: %s дескр., новых peer_id=%s, всего уник.=%s",
                        host,
                        port,
                        r + 1,
                        rounds,
                        len(descs),
                        n_new,
                        len(merged),
                    )
                    got = True
                    break
                logger.debug(
                    "%s:%s пакет #%s (ожидали PeersResponse): %s",
                    host,
                    port,
                    i,
                    wire.peek_control_type(pkt.data),
                )

            if not got:
                logger.warning(
                    "%s:%s — нет PeersResponse в раунде %s/%s (протокол, таймаут).",
                    host,
                    port,
                    r + 1,
                    rounds,
                )
                break

        if merged:
            return remote_id, neighbors, list(merged.values())
        logger.warning(
            "%s:%s — не получили PeersResponse (allow_unsigned_packets, версия протокола, TCP lp2ln-core-v2).",
            host,
            port,
        )
        return remote_id, neighbors, []
    finally:
        try:
            sock.close()
        except OSError:
            pass


def crawl_network(
    seed_host: str,
    seed_port: int,
    *,
    max_depth: int = 1,
    limit: int = 64,
    peer_rounds: int = 1,
    timeout: float = 10.0,
    our_peer_id: str = client.VIEWER_PEER_ID,
    use_descriptors: bool = False,
    include_catalog_edges: bool = False,
    max_addrs_per_peer: int = 3,
    connect_retries: int = 1,
    retry_backoff_s: float = 0.2,
    seed_port_end: Optional[int] = None,
    scan_probe_timeout: float = 2.0,
    on_progress: Optional[Callable[[TopologyGraph], None]] = None,
) -> TopologyGraph:
    seed_port_hi = seed_port
    if seed_port_end is not None:
        seed_port_hi = int(seed_port_end)
        logger.info(
            "Обход: seed %s, порты %s–%s (поиск LP2LN), затем max_depth=%s, limit=%s, peer_rounds=%s, timeout=%ss",
            seed_host,
            seed_port,
            seed_port_hi,
            max_depth,
            limit,
            max(1, int(peer_rounds)),
            timeout,
        )
        found = find_lp2ln_tcp_port(
            seed_host,
            seed_port,
            seed_port_hi,
            timeout=max(0.5, float(scan_probe_timeout)),
            our_peer_id=our_peer_id,
            connect_retries=min(2, max(1, connect_retries)),
            retry_backoff_s=retry_backoff_s,
        )
        if found is None:
            g = TopologyGraph()
            g.unreachable[f"{seed_host}:{seed_port}-{seed_port_hi}"] = (
                "no LP2LN handshake in port range"
            )
            logger.error(
                "Граф пустой: на %s в портах %s–%s нет ответа handshake LP2LN. "
                "Проверь --host и диапазон (--port / --port-end).",
                seed_host,
                seed_port,
                seed_port_hi,
            )
            if on_progress is not None:
                on_progress(snapshot_topology_graph(g))
            return g
        seed_port = found
    else:
        logger.info(
            "Обход: seed %s:%s, max_depth=%s, limit=%s, peer_rounds=%s, timeout=%ss",
            seed_host,
            seed_port,
            max_depth,
            limit,
            max(1, int(peer_rounds)),
            timeout,
        )

    g = TopologyGraph()
    g.seed_tcp = (seed_host, seed_port)

    def emit() -> None:
        if on_progress is not None:
            on_progress(snapshot_topology_graph(g))

    queue: List[Tuple[str, int, int]] = [(seed_host, seed_port, 0)]
    visited_addr: Set[Tuple[str, int]] = set()
    queued_addr: Set[Tuple[str, int]] = {(seed_host, seed_port)}
    crawled_peer: Set[str] = set()
    scheduled_peer: Set[str] = set()

    while queue:
        host, port, depth = queue.pop(0)
        key = (host, port)
        if key in visited_addr:
            logger.debug("пропуск уже посещённого адреса %s:%s", host, port)
            continue
        visited_addr.add(key)

        try:
            peer_id, neighbors, descs = fetch_topology_from_node(
                host,
                port,
                limit=limit,
                peer_rounds=peer_rounds,
                timeout=timeout,
                our_peer_id=our_peer_id,
                use_descriptors=use_descriptors,
                connect_retries=connect_retries,
                retry_backoff_s=retry_backoff_s,
            )
        except (OSError, ConnectionError, TimeoutError, RuntimeError, ValueError) as e:
            logger.warning(
                "%s:%s — ошибка: %s (%s)",
                host,
                port,
                type(e).__name__,
                e,
            )
            g.unreachable[f"{host}:{port}"] = f"{type(e).__name__}: {e}"
            emit()
            continue

        if not peer_id or peer_id in crawled_peer:
            if peer_id and peer_id in crawled_peer:
                logger.info("%s:%s — peer уже обойден, данные сливаем в граф", host, port)
            if not peer_id:
                logger.warning("%s:%s — пустой peer_id после handshake", host, port)
            if peer_id:
                for nb in neighbors:
                    if nb and nb != peer_id:
                        _ensure_node_stub(g, nb)
                        g.edges.add((peer_id, nb))
                for d in descs:
                    if include_catalog_edges:
                        g.add_catalog_edge(peer_id, d)
                    else:
                        g.merge_descriptor(d)
            emit()
            continue
        crawled_peer.add(peer_id)
        if peer_id not in g.nodes:
            g.nodes[peer_id] = {
                "peer_id": peer_id,
                "observed_addrs": [f"tcp:{host}:{port}"],
                "capabilities": {},
                "dynamic_status": {},
            }
        if depth == 0:
            g.seeds.append(peer_id)

        for nb in neighbors:
            if nb and nb != peer_id:
                _ensure_node_stub(g, nb)
                g.edges.add((peer_id, nb))

        for d in descs:
            if include_catalog_edges:
                g.add_catalog_edge(peer_id, d)
            else:
                g.merge_descriptor(d)
            if depth >= max_depth:
                continue
            pid = str(d.get("peer_id", ""))
            if not pid or pid in crawled_peer or pid in scheduled_peer:
                continue
            addrs = _parse_tcp_addrs(d.get("observed_addrs") or [])
            if not addrs:
                continue
            scheduled_peer.add(pid)
            max_addrs = max(1, int(max_addrs_per_peer))
            for nh, np in addrs[:max_addrs]:
                akey = (nh, np)
                if akey in visited_addr or akey in queued_addr:
                    continue
                queued_addr.add(akey)
                queue.append((nh, np, depth + 1))
                logger.debug("в очередь depth=%s: %s:%s (peer %s…)", depth + 1, nh, np, pid[:12])

        emit()

    logger.info(
        "Готово: узлов=%s, рёбер сессий=%s, рёбер каталога=%s, seeds=%s",
        len(g.nodes),
        len(g.edges),
        len(g.catalog_edges),
        g.seeds,
    )
    if g.unreachable:
        logger.info("Недоступных адресов: %s", len(g.unreachable))
    if not g.nodes:
        logger.error(
            "Граф пустой: не удалось подключиться к seed или handshake/запрос не прошли. "
            "Проверь --host/--port (и при сканировании --port-end), порт = listens.tcp ноды."
        )
    return g
