"""Обход нод: RequestAdjacency (живые TCP-сессии) + RequestPeers (дескрипторы, BFS)."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import socket
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from queue import Empty, Queue
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from . import client, wire

logger = logging.getLogger(__name__)

_tls_asyncio_loop = threading.local()


def _asyncio_run_on_thread_loop(coro):
    loop = getattr(_tls_asyncio_loop, "loop", None)
    if loop is None or loop.is_closed():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        _tls_asyncio_loop.loop = loop
    return loop.run_until_complete(coro)


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
    edges (a,b) — активная сессия между peer'ами (debug-ws / RequestAdjacency).
    edge_protocols[(a,b)] — набор протоколов на ненаправленном ребре (tcp/udp/quic/…).
    catalog_edges — опционально «a упомянула b в PeersResponse» (каталог, не сессия)."""

    nodes: Dict[str, dict] = field(default_factory=dict)
    edges: Set[Tuple[str, str]] = field(default_factory=set)
    edge_protocols: Dict[Tuple[str, str], Set[str]] = field(default_factory=dict)
    catalog_edges: Set[Tuple[str, str]] = field(default_factory=set)
    seeds: List[str] = field(default_factory=list)
    unreachable: Dict[str, str] = field(default_factory=dict)
    # (host, port), на котором реально ответил seed после опционального сканирования портов
    seed_tcp: Optional[Tuple[str, int]] = None
    # Последний набор ws://… для debug-ws (после скана или из fixed_urls) — для повторных опросов без скана
    debug_ws_urls: Optional[List[str]] = None
    # Короткий статус для HUD во время длинного скана/загрузки (1000 пиров)
    progress_note: str = ""
    # Счётчики активных сессий по протоколу (сумма по всем snapshot; каждая сторона считает свою).
    session_hits: Dict[str, int] = field(default_factory=dict)
    # Уникальные (self, peer, proto) — без двойного учёта одной стороны дважды в одном snapshot.
    _session_seen: Set[Tuple[str, str, str]] = field(default_factory=set, repr=False)

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

    def add_session_edge(self, a: str, b: str, protocol: Optional[str] = None) -> None:
        """Ребро сессии + опциональный протокол (tcp/udp/quic/…)."""
        if not a or not b or a == b:
            return
        self.edges.add((a, b))
        key = (a, b) if a <= b else (b, a)
        if protocol is not None and str(protocol).strip():
            self.edge_protocols.setdefault(key, set()).add(normalize_link_protocol(protocol))
        else:
            self.edge_protocols.setdefault(key, set())


def normalize_link_protocol(raw: Optional[str]) -> str:
    """Сводит LinkKind/строку debug snapshot к семейству: tcp|udp|quic|tunnel_tcp|tunnel_udp|relay|unknown."""
    s = (raw or "").strip().lower().replace("-", "_")
    if s in ("tcp", "directtcp", "direct_tcp"):
        return "tcp"
    if s in ("udp", "directudp", "direct_udp"):
        return "udp"
    if s in ("quic", "directquic", "direct_quic"):
        return "quic"
    if s in ("tunnel_tcp", "tunneltcp"):
        return "tunnel_tcp"
    if s in ("tunnel_udp", "tunneludp"):
        return "tunnel_udp"
    if s == "relay":
        return "relay"
    if "quic" in s:
        return "quic"
    if "udp" in s and "tunnel" in s:
        return "tunnel_udp"
    if "tcp" in s and "tunnel" in s:
        return "tunnel_tcp"
    if "udp" in s:
        return "udp"
    if "tcp" in s:
        return "tcp"
    if "relay" in s:
        return "relay"
    return s or "unknown"


def protocol_counts_from_graph(g: "TopologyGraph") -> Dict[str, int]:
    """Сколько ненаправленных рёбер несут каждый протокол (ребро с tcp+udp считается в обоих)."""
    counts: Dict[str, int] = {}
    seen_keys: Set[Tuple[str, str]] = set()
    for a, b in g.edges:
        if not a or not b or a == b:
            continue
        key = (a, b) if a <= b else (b, a)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        protos = g.edge_protocols.get(key) or set()
        # Убрать пустые; если протоколов нет — unknown
        clean = {p for p in protos if p}
        if not clean:
            counts["unknown"] = counts.get("unknown", 0) + 1
            continue
        for p in clean:
            counts[p] = counts.get(p, 0) + 1
    return counts


def protocol_stats_report(g: "TopologyGraph") -> Dict[str, Any]:
    """Сводка по протоколам для HUD / topo.json."""
    edges = protocol_counts_from_graph(g)
    sessions = {
        k: int(v)
        for k, v in sorted((getattr(g, "session_hits", None) or {}).items())
        if not str(k).endswith("_reported")
    }
    sessions_reported = {
        k.replace("_reported", ""): int(v)
        for k, v in (getattr(g, "session_hits", None) or {}).items()
        if str(k).endswith("_reported")
    }
    total_e = sum(edges.values())
    total_s = sum(sessions.values())
    share_e = (
        {k: round(v / total_e, 4) for k, v in edges.items()} if total_e else {}
    )
    share_s = (
        {k: round(v / total_s, 4) for k, v in sessions.items()} if total_s else {}
    )
    dominant_e = max(edges.items(), key=lambda kv: kv[1])[0] if edges else None
    return {
        "edges_by_protocol": edges,
        "sessions_by_protocol": sessions,
        "sessions_by_protocol_reported": sessions_reported,
        "edge_share": share_e,
        "session_share": share_s,
        "dominant_edge_protocol": dominant_e,
        "edges_total_proto_marks": total_e,
        "sessions_unique_undirected": total_s,
    }


def _undirected_key(a: str, b: str) -> Tuple[str, str]:
    return (a, b) if a <= b else (b, a)


def filter_topology(
    g: "TopologyGraph",
    *,
    age: str = "all",
    protocol: str = "all",
    scope: str = "all",
    new_node_ids: Optional[Set[str]] = None,
    new_edge_set: Optional[Set[Tuple[str, str]]] = None,
) -> "TopologyGraph":
    """Фильтр графа для UI.

    age: all|new|old — по сравнению с предыдущим кадром (new_*/old).
    protocol: all|tcp|udp|quic|tunnel_tcp|tunnel_udp|relay|unknown
    scope: all|core|iso — вся сеть / только с сессиями / только изоляты.
    """
    age_s = (age or "all").strip().lower()
    proto_s = (protocol or "all").strip().lower()
    scope_s = (scope or "all").strip().lower()
    nn = set(new_node_ids or ())
    ne = {_undirected_key(a, b) for a, b in (new_edge_set or set()) if a and b and a != b}

    # Полное покрытие рёбрами (для scope=iso/core относительно исходного графа).
    full_touch: Set[str] = set()
    for a, b in g.edges:
        if a and b and a != b:
            full_touch.add(a)
            full_touch.add(b)

    keep_edges: Set[Tuple[str, str]] = set()
    keep_proto: Dict[Tuple[str, str], Set[str]] = {}
    for a, b in g.edges:
        if not a or not b or a == b:
            continue
        key = _undirected_key(a, b)
        if age_s == "new" and key not in ne:
            continue
        if age_s == "old" and key in ne:
            continue
        protos = {p for p in (g.edge_protocols.get(key) or set()) if p}
        if not protos:
            protos = {"unknown"}
        if proto_s != "all" and proto_s not in protos:
            continue
        keep_edges.add((a, b))
        keep_proto[key] = {proto_s} if proto_s != "all" else set(g.edge_protocols.get(key) or set())

    if scope_s == "iso":
        keep_nodes = {pid for pid in g.nodes if pid not in full_touch}
        if age_s == "new":
            keep_nodes &= nn
        elif age_s == "old":
            keep_nodes -= nn
        keep_edges = set()
        keep_proto = {}
    else:
        ends: Set[str] = set()
        for a, b in keep_edges:
            ends.add(a)
            ends.add(b)
        if scope_s == "core":
            keep_nodes = set(ends)
        else:
            keep_nodes = set(g.nodes.keys())
            if age_s == "new":
                keep_nodes = set(nn) | ends
            elif age_s == "old":
                keep_nodes = {pid for pid in g.nodes if pid not in nn} | ends
            else:
                # all age: при protocol-фильтре показываем концы рёбер + остальные узлы
                # (чтобы изоляты оставались видны, если scope=all)
                pass
            if proto_s != "all" and age_s == "all":
                # протокол-фильтр: только участники этих рёбер (+ пустой граф если нет)
                keep_nodes = set(ends) if ends else set()

    final_edges: Set[Tuple[str, str]] = set()
    final_proto: Dict[Tuple[str, str], Set[str]] = {}
    for a, b in keep_edges:
        if a in keep_nodes and b in keep_nodes:
            final_edges.add((a, b))
            key = _undirected_key(a, b)
            if key in keep_proto:
                final_proto[key] = set(keep_proto[key])

    nodes = {pid: dict(g.nodes[pid]) for pid in keep_nodes if pid in g.nodes}
    seeds = [s for s in g.seeds if s in keep_nodes]
    return TopologyGraph(
        nodes=nodes,
        edges=final_edges,
        edge_protocols=final_proto,
        catalog_edges=set(),
        seeds=seeds,
        unreachable={},
        seed_tcp=g.seed_tcp,
        debug_ws_urls=list(g.debug_ws_urls) if g.debug_ws_urls else None,
        progress_note=str(getattr(g, "progress_note", "") or ""),
        session_hits=dict(getattr(g, "session_hits", None) or {}),
        _session_seen=set(getattr(g, "_session_seen", None) or set()),
    )


def filter_label(*, age: str, protocol: str, scope: str) -> str:
    parts = []
    if (age or "all") != "all":
        parts.append(f"age={age}")
    if (protocol or "all") != "all":
        parts.append(f"proto={protocol}")
    if (scope or "all") != "all":
        parts.append(f"scope={scope}")
    return " · ".join(parts) if parts else "all"


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
        edge_protocols={k: set(v) for k, v in g.edge_protocols.items()},
        catalog_edges=set(g.catalog_edges),
        seeds=list(g.seeds),
        unreachable=dict(g.unreachable),
        seed_tcp=g.seed_tcp,
        debug_ws_urls=list(g.debug_ws_urls) if g.debug_ws_urls else None,
        progress_note=str(getattr(g, "progress_note", "") or ""),
        session_hits=dict(getattr(g, "session_hits", None) or {}),
        _session_seen=set(getattr(g, "_session_seen", None) or set()),
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
    inc_proto: Dict[Tuple[str, str], Set[str]] = {}
    for a, b in inc_edges:
        key = (a, b) if a <= b else (b, a)
        if key in g.edge_protocols:
            inc_proto[key] = set(g.edge_protocols[key])
    return TopologyGraph(
        nodes=nodes,
        edges=inc_edges,
        edge_protocols=inc_proto,
        catalog_edges=set(),
        seeds=seeds,
        unreachable={},
        seed_tcp=g.seed_tcp,
        debug_ws_urls=list(g.debug_ws_urls) if g.debug_ws_urls else None,
        progress_note=str(getattr(g, "progress_note", "") or ""),
        session_hits=dict(getattr(g, "session_hits", None) or {}),
        _session_seen=set(getattr(g, "_session_seen", None) or set()),
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
    scan_workers: int = 1,
) -> Optional[int]:
    """Перебор портов port_lo..port_hi (включительно): успешный handshake LP2LN.

    При scan_workers>1 порты проверяются параллельно; возвращается минимальный открытый порт в диапазоне.
    """
    lo = max(1, min(int(port_lo), 65535))
    hi = max(1, min(int(port_hi), 65535))
    if hi < lo:
        lo, hi = hi, lo
    retries = max(1, int(connect_retries))
    n_ports = hi - lo + 1
    # На Windows параллельный скан портов легко упирается в WSAENOBUFS (10055).
    scan_cap = 8 if sys.platform == "win32" else 32
    workers = max(1, min(int(scan_workers), n_ports, scan_cap))

    def try_one(port: int) -> Optional[int]:
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
        return None

    if workers == 1:
        for port in range(lo, hi + 1):
            r = try_one(port)
            if r is not None:
                logger.info("Seed: найден ответ LP2LN на %s:%s (диапазон %s–%s)", host, port, lo, hi)
                return port
        logger.warning("Seed: в диапазоне %s:%s–%s ответа LP2LN не найдено", host, lo, hi)
        return None

    best_lock = threading.Lock()
    best: List[Optional[int]] = [None]

    def worker() -> None:
        while True:
            try:
                port = work_q.get_nowait()
            except Empty:
                return
            found = try_one(port)
            if found is None:
                continue
            with best_lock:
                if best[0] is None or found < best[0]:
                    best[0] = found

    work_q: Queue[int] = Queue()
    for p in range(lo, hi + 1):
        work_q.put(p)

    threads = [threading.Thread(target=worker, name=f"lp2ln-port-scan-{i}", daemon=True) for i in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    result = best[0]
    if result is not None:
        logger.info("Seed: найден ответ LP2LN на %s:%s (диапазон %s–%s, workers=%s)", host, result, lo, hi, workers)
    else:
        logger.warning("Seed: в диапазоне %s:%s–%s ответа LP2LN не найдено", host, lo, hi)
    return result


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


def _debug_ws_connect_kwargs(timeout_s: float) -> Dict[str, Any]:
    """websockets>=16 по умолчанию proxy=True → LAN ws:// часто ломается через системный HTTP-прокси."""
    ws_timeout = max(0.2, float(timeout_s))
    return {
        "open_timeout": ws_timeout,
        "close_timeout": ws_timeout,
        "proxy": None,
    }


async def _debug_ws_handshake_error(url: str, timeout_s: float) -> Optional[str]:
    """None — успешный WebSocket-handshake; иначе краткая строка ошибки."""
    try:
        import websockets
    except ImportError as e:
        raise RuntimeError(
            "Для режима debug-ws нужен пакет 'websockets' (pip install -r requirements.txt)"
        ) from e
    try:
        kw = _debug_ws_connect_kwargs(timeout_s)
        ws_timeout = float(kw["open_timeout"])
        async with websockets.connect(url, **kw) as ws:
            try:
                await asyncio.wait_for(ws.recv(), timeout=ws_timeout)
            except Exception:
                pass
        return None
    except Exception as e:
        logger.debug("debug-ws probe %s: %s: %s", url, type(e).__name__, e)
        return f"{type(e).__name__}: {e}"


async def _probe_debug_ws_url(url: str, timeout_s: float) -> bool:
    return await _debug_ws_handshake_error(url, timeout_s) is None


async def _scan_debug_ws_urls(
    host: str,
    port_lo: int,
    port_hi: int,
    *,
    timeout_s: float,
    workers: int,
    on_url_found: Optional[Callable[[str], Any]] = None,
    on_scan_progress: Optional[Callable[[int, int, int], Any]] = None,
) -> List[str]:
    lo = max(1, min(int(port_lo), 65535))
    hi = max(1, min(int(port_hi), 65535))
    if hi < lo:
        lo, hi = hi, lo
    ports = list(range(lo, hi + 1))
    if not ports:
        return []
    total = len(ports)
    sem = asyncio.Semaphore(max(1, min(int(workers), len(ports), 64)))
    found: List[str] = []
    scan_lock = asyncio.Lock()
    state = {"done": 0, "hits": 0, "zero_hint": False}
    step = max(50, min(500, total // 20 or 1))
    w_eff = max(1, min(int(workers), total, 64))
    logger.info(
        "debug-ws: старт скана %s портов %s..%s (parallel=%s, probe_timeout=%.2fs, proxy=off)",
        total,
        lo,
        hi,
        w_eff,
        max(0.25, float(timeout_s)),
    )

    async def _maybe_call(cb: Optional[Callable[..., Any]], *args: Any) -> None:
        if cb is None:
            return
        res = cb(*args)
        if asyncio.iscoroutine(res):
            await res

    async def run_one(p: int) -> None:
        url = f"ws://{host}:{p}"
        async with sem:
            ok = await _probe_debug_ws_url(url, timeout_s)
        async with scan_lock:
            state["done"] += 1
            d = state["done"]
            if ok:
                found.append(url)
                state["hits"] += 1
                logger.info("debug-ws: найден endpoint %s (всего найдено: %s)", url, state["hits"])
            elif d == total or (d % step == 0):
                logger.info(
                    "debug-ws: прогресс скана %s/%s портов, открытых WebSocket: %s",
                    d,
                    total,
                    state["hits"],
                )
                if (
                    state["hits"] == 0
                    and not state["zero_hint"]
                    and d >= min(step, 50)
                ):
                    state["zero_hint"] = True
                    logger.warning(
                        "debug-ws: пока ни одного WS. У lp2lnd-scale debug обычно с порта 9100 "
                        "(peer_N → 9100+N); диапазон 9090–9099 часто пуст. Сверьте --host с bind_ip "
                        "в логах scale (127.0.0.1 vs LAN), файрвол; узко: --port 9100 --port-end 9149."
                    )
            hits = state["hits"]
        if ok:
            await _maybe_call(on_url_found, url)
        if d == total or (d % step == 0) or (
            ok and (hits in (1, 5, 10, 25, 50) or hits % 50 == 0)
        ):
            await _maybe_call(on_scan_progress, d, total, hits)

    await asyncio.gather(*(run_one(p) for p in ports))
    found.sort(key=lambda u: int(u.rsplit(":", 1)[1]))
    logger.info(
        "debug-ws: скан завершён: проверено %s, найдено ws-endpoint(s): %s",
        total,
        len(found),
    )
    if found:
        ports_preview = ", ".join(u.rsplit(":", 1)[1] for u in found[:12])
        suffix = " …" if len(found) > 12 else ""
        logger.info("debug-ws: порты (первые): %s%s", ports_preview, suffix)
    else:
        sample_p = 9100 if lo <= 9100 <= hi else lo
        u = f"ws://{host}:{sample_p}"
        err = await _debug_ws_handshake_error(u, timeout_s)
        if err:
            logger.warning("debug-ws: скан %s..%s — 0 endpoint; пример %s: %s", lo, hi, u, err)
        else:
            logger.warning(
                "debug-ws: скан %s..%s — 0 endpoint, но %s подключается (несовпадение probe/сервера — редкий случай).",
                lo,
                hi,
                u,
            )
        if lo < 9100 <= hi:
            logger.warning(
                "debug-ws: в диапазон включены порты <9100; у scale по умолчанию база 9100 — задайте --port 9100."
            )
    await _maybe_call(on_scan_progress, total, total, len(found))
    return found


async def _fetch_debug_snapshot(url: str, *, timeout_s: float, request_refresh: bool) -> Dict[str, Any]:
    try:
        import websockets
    except ImportError as e:
        raise RuntimeError(
            "Для режима debug-ws нужен пакет 'websockets' (pip install -r requirements.txt)"
        ) from e

    ws_timeout = max(0.3, float(timeout_s))
    kw = _debug_ws_connect_kwargs(ws_timeout)
    logger.info(
        "debug-ws snapshot: подключение к %s (refresh_cmd=%s)",
        url,
        request_refresh,
    )
    async with websockets.connect(url, **kw) as ws:
        if request_refresh:
            await ws.send(json.dumps({"cmd": "refresh_snapshot"}))
            logger.debug("debug-ws snapshot: отправлен refresh_snapshot → %s", url)
        # Первое сообщение — hello; затем snapshot (или ответ refresh). Дайте запас > open_timeout.
        recv_deadline_s = max(15.0, ws_timeout * 4.0)
        deadline = time.monotonic() + recv_deadline_s
        n_msg = 0
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError(f"{url}: snapshot timeout")
            msg = await asyncio.wait_for(ws.recv(), timeout=left)
            n_msg += 1
            if not isinstance(msg, str):
                logger.debug("debug-ws snapshot: %s сообщение #%s не текст, пропуск", url, n_msg)
                continue
            try:
                payload = json.loads(msg)
            except json.JSONDecodeError:
                logger.debug("debug-ws snapshot: %s сообщение #%s не JSON", url, n_msg)
                continue
            if not isinstance(payload, dict):
                continue
            ev = payload.get("event")
            if ev == "snapshot":
                node = payload.get("node") or {}
                topo = payload.get("topology") or {}
                pid = str(topo.get("self_peer_id") or node.get("peer_id") or "")[:20]
                n_nei = len(topo.get("neighbors") or []) if isinstance(topo.get("neighbors"), list) else 0
                logger.info(
                    "debug-ws snapshot: %s получен snapshot (peer_id=%s…, neighbors=%s)",
                    url,
                    pid,
                    n_nei,
                )
                return payload
            logger.debug("debug-ws snapshot: %s сообщение #%s event=%r", url, n_msg, ev)


def _merge_debug_snapshot_to_graph(
    g: TopologyGraph,
    snapshot: Dict[str, Any],
    endpoint: str,
    *,
    include_catalog_edges: bool,
) -> None:
    node = snapshot.get("node") or {}
    topo = snapshot.get("topology") or {}
    self_peer = str(topo.get("self_peer_id") or node.get("peer_id") or "").strip()
    role = str(node.get("role") or "")
    self_bootstrap = "bootstrap" in role.lower()
    if self_peer:
        g.nodes[self_peer] = {
            "peer_id": self_peer,
            "observed_addrs": [f"debug_ws:{endpoint}"],
            "capabilities": {"bootstrap_entry": self_bootstrap},
            "dynamic_status": {
                "active_connections": int(node.get("active_peers") or 0),
                "accepts_new_sessions": True,
            },
        }
        if self_bootstrap and self_peer not in g.seeds:
            g.seeds.append(self_peer)

    neighbors = topo.get("neighbors") or []
    if isinstance(neighbors, list):
        for n in neighbors:
            if not isinstance(n, dict):
                continue
            pid = str(n.get("peer_id") or "").strip()
            if not pid:
                continue
            desc = {
                "peer_id": pid,
                "observed_addrs": list(n.get("observed_addrs") or []),
                "capabilities": {"bootstrap_entry": bool(n.get("bootstrap_entry", False))},
                "dynamic_status": {
                    "active_connections": int(n.get("active_connections") or 0),
                    "accepts_new_sessions": bool(n.get("accepts_new_sessions", True)),
                },
            }
            g.merge_descriptor(desc)
            if bool(n.get("bootstrap_entry", False)) and pid not in g.seeds:
                g.seeds.append(pid)
            if include_catalog_edges and self_peer and pid != self_peer:
                g.catalog_edges.add((self_peer, pid))

    edges = topo.get("edges") or []
    if isinstance(edges, list):
        for e in edges:
            if not isinstance(e, dict):
                continue
            if e.get("connected", True) is False:
                continue
            a = str(e.get("source") or "").strip()
            b = str(e.get("target") or "").strip()
            if not a or not b or a == b:
                continue
            _ensure_node_stub(g, a)
            _ensure_node_stub(g, b)
            # Протокол уточним из sessions ниже; пока unknown если ещё нет записи.
            g.add_session_edge(a, b, protocol=None)

    # sessions[] — источник протокола (tcp/udp/quic/…) для рёбер + статистика.
    sessions = snapshot.get("sessions") or []
    if isinstance(sessions, list) and self_peer:
        for s in sessions:
            if not isinstance(s, dict):
                continue
            if s.get("is_active", True) is False:
                continue
            peer = str(s.get("peer_id") or "").strip()
            if not peer or peer == self_peer:
                continue
            _ensure_node_stub(g, peer)
            proto_raw = str(s.get("protocol") or "")
            g.add_session_edge(self_peer, peer, protocol=proto_raw)
            fam = normalize_link_protocol(proto_raw)
            # уникально на стороне self→peer (повторный snapshot того же пира не раздувает)
            a, b = (self_peer, peer) if self_peer <= peer else (peer, self_peer)
            key = (a, b, fam)
            if key not in g._session_seen:
                g._session_seen.add(key)
                g.session_hits[fam] = int(g.session_hits.get(fam, 0)) + 1

    # sessions_by_protocol — если детального sessions нет.
    by_proto = snapshot.get("sessions_by_protocol") or []
    if isinstance(by_proto, list) and self_peer:
        detailed = any(isinstance(s, dict) and s.get("peer_id") for s in (sessions or []))
        if not detailed:
            for row in by_proto:
                if not isinstance(row, dict):
                    continue
                fam = normalize_link_protocol(str(row.get("kind") or row.get("protocol") or ""))
                n_s = int(row.get("sessions") or 0)
                if n_s > 0 and fam:
                    # грубая оценка без peer_id — помечаем отдельным ключом
                    k = f"{fam}_reported"
                    g.session_hits[k] = int(g.session_hits.get(k, 0)) + n_s


def _endpoint_from_ws_url(url: str) -> str:
    u = (url or "").strip()
    if "://" in u:
        u = u.split("://", 1)[1]
    return u


async def _debug_ws_stream_one_url(
    url: str,
    g: TopologyGraph,
    lock: asyncio.Lock,
    *,
    include_catalog_edges: bool,
    request_refresh: bool,
    timeout_s: float,
    emit_interval_s: float,
    stop: threading.Event,
    progress_callback: Callable[[TopologyGraph], None],
    emit_state: Dict[str, float],
) -> None:
    try:
        import websockets
    except ImportError:
        logger.error("debug-ws stream: нужен пакет websockets")
        return

    backoff = 1.0
    ep = _endpoint_from_ws_url(url)
    while not stop.is_set():
        try:
            kw = _debug_ws_connect_kwargs(timeout_s)
            async with websockets.connect(url, **kw) as ws:
                backoff = 1.0
                if request_refresh:
                    await ws.send(json.dumps({"cmd": "refresh_snapshot"}))
                while not stop.is_set():
                    try:
                        raw = await asyncio.wait_for(ws.recv(), timeout=0.5)
                    except asyncio.TimeoutError:
                        continue
                    if not isinstance(raw, str):
                        continue
                    try:
                        payload = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(payload, dict) or payload.get("event") != "snapshot":
                        continue
                    snap_for_ui: Optional[TopologyGraph] = None
                    async with lock:
                        _merge_debug_snapshot_to_graph(
                            g, payload, ep, include_catalog_edges=include_catalog_edges
                        )
                        now = time.monotonic()
                        last = float(emit_state.get("t", 0.0))
                        if now - last >= emit_interval_s:
                            emit_state["t"] = now
                            snap_for_ui = snapshot_topology_graph(g)
                    if snap_for_ui is not None:
                        progress_callback(snap_for_ui)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            if stop.is_set():
                break
            logger.warning("debug-ws stream %s: %s — повтор через %.1fs", url, e, backoff)
            try:
                await asyncio.sleep(backoff)
            except asyncio.CancelledError:
                break
            backoff = min(backoff * 2.0, 30.0)


async def _debug_ws_live_streams_async(
    urls: List[str],
    *,
    seed_tcp: Tuple[str, int],
    include_catalog_edges: bool,
    request_refresh: bool,
    timeout_s: float,
    emit_interval_s: float,
    stop: threading.Event,
    progress_callback: Callable[[TopologyGraph], None],
) -> None:
    urls = [u.strip() for u in urls if u and str(u).strip()]
    if not urls:
        return
    g = TopologyGraph()
    g.seed_tcp = seed_tcp
    g.debug_ws_urls = list(urls)
    lock = asyncio.Lock()
    emit_state: Dict[str, float] = {"t": 0.0}
    tasks = [
        asyncio.create_task(
            _debug_ws_stream_one_url(
                url,
                g,
                lock,
                include_catalog_edges=include_catalog_edges,
                request_refresh=request_refresh,
                timeout_s=timeout_s,
                emit_interval_s=emit_interval_s,
                stop=stop,
                progress_callback=progress_callback,
                emit_state=emit_state,
            )
        )
        for url in urls
    ]
    try:
        await asyncio.gather(*tasks)
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def run_debug_ws_live_streams_blocking(
    urls: List[str],
    *,
    seed_tcp: Tuple[str, int],
    include_catalog_edges: bool,
    request_refresh: bool,
    timeout_s: float,
    emit_interval_s: float,
    stop: threading.Event,
    progress_callback: Callable[[TopologyGraph], None],
) -> None:
    """Держит WebSocket на каждый endpoint: сервер пушит snapshot — мержим и зовём progress_callback."""
    _asyncio_run_on_thread_loop(
        _debug_ws_live_streams_async(
            urls,
            seed_tcp=seed_tcp,
            include_catalog_edges=include_catalog_edges,
            request_refresh=request_refresh,
            timeout_s=timeout_s,
            emit_interval_s=emit_interval_s,
            stop=stop,
            progress_callback=progress_callback,
        )
    )


def crawl_network_debug_ws(
    seed_host: str,
    seed_port: int,
    *,
    include_catalog_edges: bool = False,
    seed_port_end: Optional[int] = None,
    fixed_debug_ws_urls: Optional[List[str]] = None,
    timeout: float = 2.0,
    scan_workers: int = 16,
    crawl_workers: int = 8,
    request_refresh: bool = True,
    on_progress: Optional[Callable[[TopologyGraph], None]] = None,
    progress_min_interval_s: float = 0.4,
) -> TopologyGraph:
    logger.info(
        "Обход debug-ws: host=%s, port=%s%s, timeout=%ss, scan_workers=%s, crawl_workers=%s",
        seed_host,
        seed_port,
        f"..{seed_port_end}" if seed_port_end is not None else "",
        timeout,
        scan_workers,
        crawl_workers,
    )
    g = TopologyGraph()
    g.seed_tcp = (seed_host, seed_port)
    emit_interval = max(0.15, float(progress_min_interval_s))

    async def run_pipeline() -> Tuple[List[str], int, int]:
        """Скан + загрузка snapshot конвейером: UI получает узлы ещё до конца скана."""
        fixed = [u.strip() for u in (fixed_debug_ws_urls or []) if u and str(u).strip()]
        w_snap = max(1, min(int(crawl_workers), 32))
        if sys.platform == "win32":
            w_snap = min(w_snap, 12)
        fetch_sem = asyncio.Semaphore(w_snap)
        lock = asyncio.Lock()
        fetch_tasks: Set[asyncio.Task] = set()
        state = {"ok": 0, "fail": 0, "emit_t": 0.0, "urls": 0}

        def emit_progress(*, force: bool = False, note: str = "") -> None:
            if on_progress is None:
                return
            now = time.monotonic()
            if not force and (now - float(state["emit_t"])) < emit_interval:
                return
            state["emit_t"] = now
            if note:
                g.progress_note = note
            on_progress(snapshot_topology_graph(g))

        async def fetch_and_merge(url: str) -> None:
            endpoint = url.removeprefix("ws://")
            try:
                async with fetch_sem:
                    snap = await _fetch_debug_snapshot(
                        url,
                        timeout_s=max(0.25, float(timeout)),
                        request_refresh=request_refresh,
                    )
                async with lock:
                    _merge_debug_snapshot_to_graph(
                        g, snap, endpoint, include_catalog_edges=include_catalog_edges
                    )
                    state["ok"] += 1
                    note = (
                        f"snapshot {state['ok']}+{state['fail']}/{state['urls']} "
                        f"· узлов {len(g.nodes)} · рёбер {len(g.edges)}"
                    )
                    emit_progress(note=note)
            except Exception as e:
                logger.debug("debug-ws snapshot: ошибка %s → %s: %s", url, type(e).__name__, e)
                async with lock:
                    g.unreachable[url] = f"{type(e).__name__}: {e}"
                    state["fail"] += 1
                    emit_progress(
                        note=f"snapshot {state['ok']}+{state['fail']}/{state['urls']} · err++"
                    )

        def schedule_fetch(url: str) -> None:
            state["urls"] += 1
            t = asyncio.create_task(fetch_and_merge(url))
            fetch_tasks.add(t)

            def _done(task: asyncio.Task) -> None:
                fetch_tasks.discard(task)

            t.add_done_callback(_done)

        if fixed:
            urls = fixed
            logger.info(
                "debug-ws: скан порта пропущен, используем %s заданных endpoint(s)",
                len(urls),
            )
            g.progress_note = f"загрузка {len(urls)} snapshot…"
            emit_progress(force=True, note=g.progress_note)
            for u in urls:
                schedule_fetch(u)
        elif seed_port_end is None:
            urls = [f"ws://{seed_host}:{seed_port}"]
            schedule_fetch(urls[0])
        else:
            urls = await _scan_debug_ws_urls(
                seed_host,
                seed_port,
                int(seed_port_end),
                timeout_s=max(0.25, float(timeout)),
                workers=max(1, int(scan_workers)),
                on_url_found=schedule_fetch,
                on_scan_progress=lambda done, total, hits: emit_progress(
                    note=f"скан портов {done}/{total}, ws={hits}, узлов уже {len(g.nodes)}"
                ),
            )

        if fetch_tasks:
            logger.info(
                "debug-ws: ожидание %s snapshot-задач (parallel≤%s)",
                len(fetch_tasks),
                w_snap,
            )
            await asyncio.gather(*list(fetch_tasks), return_exceptions=True)

        g.debug_ws_urls = list(urls)
        g.progress_note = (
            f"готово: ws={len(urls)} ok={state['ok']} fail={state['fail']} "
            f"узлов={len(g.nodes)} рёбер={len(g.edges)}"
        )
        emit_progress(force=True, note=g.progress_note)
        return urls, int(state["ok"]), int(state["fail"])

    urls, n_ok, n_fail = _asyncio_run_on_thread_loop(run_pipeline())
    if not urls:
        logger.warning(
            "debug-ws: в диапазоне %s:%s..%s ни один порт не ответил WebSocket. "
            "Проверьте: запущен lp2lnd-scale с debug, --host совпадает с bind_ip в логах scale, "
            "файрвол; при websockets 16+ отключён системный HTTP-прокси (proxy=None). "
            "Широкий скан с 9090 долго даёт «0» — для N пиров: --port 9100 --port-end <9100+N−1> (50 пиров → 9149).",
            seed_host,
            seed_port,
            seed_port_end,
        )
        g.unreachable[f"ws://{seed_host}:{seed_port}..{seed_port_end}"] = "no debug websocket in range"
        g.progress_note = "нет WebSocket в диапазоне"
        if on_progress is not None:
            on_progress(snapshot_topology_graph(g))
        return g

    pstats = protocol_stats_report(g)
    share = pstats.get("session_share") or pstats.get("edge_share") or {}
    share_s = " ".join(f"{k}={v:.0%}" for k, v in sorted(share.items(), key=lambda kv: -kv[1]))
    logger.info(
        "debug-ws готово: endpoints=%s ok=%s fail=%s узлов=%s рёбер=%s протокол[%s] sessions=%s",
        len(urls),
        n_ok,
        n_fail,
        len(g.nodes),
        len(g.edges),
        share_s or "n/a",
        pstats.get("sessions_by_protocol") or {},
    )
    return g


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
    scan_workers: int = 16,
    crawl_workers: int = 8,
    progress_min_interval_s: float = 0.12,
    on_progress: Optional[Callable[[TopologyGraph], None]] = None,
    source: str = "tcp",
    debug_ws_timeout: float = 2.0,
    debug_request_refresh: bool = True,
    debug_ws_urls: Optional[List[str]] = None,
) -> TopologyGraph:
    source_norm = (source or "tcp").strip().lower()
    if source_norm in {"debug-ws", "debug_ws", "ws", "debug"}:
        return crawl_network_debug_ws(
            seed_host,
            seed_port,
            include_catalog_edges=include_catalog_edges,
            seed_port_end=seed_port_end,
            fixed_debug_ws_urls=debug_ws_urls,
            timeout=debug_ws_timeout,
            scan_workers=scan_workers,
            crawl_workers=crawl_workers,
            request_refresh=debug_request_refresh,
            on_progress=on_progress,
            progress_min_interval_s=progress_min_interval_s,
        )

    # Сильный параллелизм + десятки узлов на одной машине → исчерпание ephemeral-портов / WSAENOBUFS.
    crawl_workers_eff = max(1, min(int(crawl_workers), 16))
    scan_workers_eff = max(1, min(int(scan_workers), 32))
    if sys.platform == "win32":
        crawl_workers_eff = min(crawl_workers_eff, 3)
        scan_workers_eff = min(scan_workers_eff, 8)

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
            scan_workers=scan_workers_eff,
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

    last_progress_t = 0.0
    progress_iv = max(0.0, float(progress_min_interval_s))

    def emit(*, force: bool = False) -> None:
        nonlocal last_progress_t
        if on_progress is None:
            return
        now = time.monotonic()
        if not force and progress_iv > 0 and (now - last_progress_t) < progress_iv:
            return
        last_progress_t = now
        on_progress(snapshot_topology_graph(g))

    q: deque[Tuple[str, int, int]] = deque([(seed_host, seed_port, 0)])
    visited_addr: Set[Tuple[str, int]] = set()
    queued_addr: Set[Tuple[str, int]] = {(seed_host, seed_port)}
    crawled_peer: Set[str] = set()
    scheduled_peer: Set[str] = set()

    fetch_kw = dict(
        limit=limit,
        peer_rounds=peer_rounds,
        timeout=timeout,
        our_peer_id=our_peer_id,
        use_descriptors=use_descriptors,
        connect_retries=connect_retries,
        retry_backoff_s=retry_backoff_s,
    )
    workers_n = max(1, min(crawl_workers_eff, 16))

    def merge_fetch(
        host: str,
        port: int,
        depth: int,
        peer_id: str,
        neighbors: List[str],
        descs: List[Dict[str, Any]],
    ) -> None:
        if not peer_id or peer_id in crawled_peer:
            if peer_id and peer_id in crawled_peer:
                logger.info("%s:%s — peer уже обойден, данные сливаем в граф", host, port)
            if not peer_id:
                logger.warning("%s:%s — пустой peer_id после handshake", host, port)
            if peer_id:
                for nb in neighbors:
                    if nb and nb != peer_id:
                        _ensure_node_stub(g, nb)
                        g.add_session_edge(peer_id, nb, protocol="tcp")
                for d in descs:
                    if include_catalog_edges:
                        g.add_catalog_edge(peer_id, d)
                    else:
                        g.merge_descriptor(d)
            emit()
            return
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
                g.add_session_edge(peer_id, nb, protocol="tcp")

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
                q.append((nh, np, depth + 1))
                logger.debug("в очередь depth=%s: %s:%s (peer %s…)", depth + 1, nh, np, pid[:12])

        emit()

    def run_one(host: str, port: int, depth: int) -> None:
        try:
            peer_id, neighbors, descs = fetch_topology_from_node(host, port, **fetch_kw)
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
            return
        merge_fetch(host, port, depth, peer_id, neighbors, descs)

    if workers_n == 1:
        while q:
            host, port, depth = q.popleft()
            key = (host, port)
            if key in visited_addr:
                logger.debug("пропуск уже посещённого адреса %s:%s", host, port)
                continue
            visited_addr.add(key)
            run_one(host, port, depth)
    else:
        with ThreadPoolExecutor(max_workers=workers_n, thread_name_prefix="lp2ln-crawl") as ex:
            while q:
                batch: List[Tuple[str, int, int]] = []
                while q and len(batch) < workers_n:
                    host, port, depth = q.popleft()
                    key = (host, port)
                    if key in visited_addr:
                        logger.debug("пропуск уже посещённого адреса %s:%s", host, port)
                        continue
                    visited_addr.add(key)
                    batch.append((host, port, depth))
                if not batch:
                    if not q:
                        break
                    continue
                if len(batch) == 1:
                    h, p, d = batch[0]
                    run_one(h, p, d)
                    continue
                futures = {ex.submit(fetch_topology_from_node, h, p, **fetch_kw): (h, p, d) for h, p, d in batch}
                for fut in as_completed(futures):
                    h, p, d = futures[fut]
                    try:
                        peer_id, neighbors, descs = fut.result()
                    except (OSError, ConnectionError, TimeoutError, RuntimeError, ValueError) as e:
                        logger.warning(
                            "%s:%s — ошибка: %s (%s)",
                            h,
                            p,
                            type(e).__name__,
                            e,
                        )
                        g.unreachable[f"{h}:{p}"] = f"{type(e).__name__}: {e}"
                        emit()
                        continue
                    merge_fetch(h, p, d, peer_id, neighbors, descs)
                # Дать стеку TCP освободить очереди/TIME_WAIT между батчами.
                if len(batch) > 1:
                    time.sleep(0.04 * len(batch))

    emit(force=True)

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
