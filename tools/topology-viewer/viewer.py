#!/usr/bin/env python3
"""
Сбор топологии и отрисовка графа.

По умолчанию источник — debug-ws (WebSocket debug_server); скан портов как у lp2lnd-scale
(база debug 9100 + индекс пира). Классический обход LP2LN по TCP: --source tcp.

Пример (из каталога tools/topology-viewer, venv активирован):
  python viewer.py --host 192.168.0.16 --json topo.json
    live-окно + перезапись topo.json после каждого кадра обхода
  python viewer.py --host 192.168.0.16 --json topo.json --once
    один снимок в topo.json и выход (без окна)
  (debug-ws: по умолчанию ws 9100..9199; 50 пиров: --port 9100 --port-end 9149)

  python viewer.py --source tcp --host 192.168.0.16 --port 18080 --depth 2 --peer-rounds 6 --out topo.png
  python viewer.py --source tcp --host 192.168.0.16 --port 18080 --port-end --out topo.png
  (TCP: сканирование seed 18080..18200 — --port-end или --port-end 18200)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import queue
import signal
import sys
import threading
import time
from collections import Counter
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

DEFAULT_DEBUG_WS_PORT_LO: int = 9_100
DEFAULT_DEBUG_WS_PORT_HI: int = 9_199


def normalize_undirected_edges(edges: Set[Tuple[str, str]]) -> Set[Tuple[str, str]]:
    out: Set[Tuple[str, str]] = set()
    for a, b in edges:
        if not a or not b or a == b:
            continue
        out.add((a, b) if a <= b else (b, a))
    return out


def main() -> int:
    p = argparse.ArgumentParser(
        description="LP2LN topology viewer: источник TCP (протокол) или debug-ws (debug server snapshots).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Live-окно: нет --out, кроме «только JSON»: --json путь --once (один снимок, без окна). "
            "Иначе без --out — live; с --json без --once файл обновляется в фоне после каждого кадра.\n"
            "Пробел — пауза/продолжить, r — сразу обновить (debug-ws: стоп потока ws + полный скан порта), [ / ] — интервал, q или Esc — выход.\n"
            "По умолчанию debug-ws live держит постоянные WebSocket (push snapshot); отключить: --poll-debug-ws.\n"
            "ЛКМ по узлу — показать только его рёбра сессий (соседей); повторный клик по тому же узлу или c — весь граф.\n"
            "Цвета: фиолетовый — узел в фокусе; красный — bootstrap; оранжевый — seed; зелёный — новый с прошлого кадра; "
            "синий — остальные; оранжевые рёбра — новые TCP-сессии."
        ),
    )
    p.add_argument("--host", default="127.0.0.1", help="Адрес ноды (bootstrap / тот же bind_ip, что у scale)")
    p.add_argument(
        "--port",
        type=int,
        default=None,
        metavar="PORT",
        help="При --source tcp: порт или нижняя граница seed (по умолчанию 8080). "
        f"При --source debug-ws: нижняя граница скана ws (по умолчанию {DEFAULT_DEBUG_WS_PORT_LO}).",
    )
    p.add_argument(
        "--source",
        choices=["tcp", "debug-ws"],
        default="debug-ws",
        help="Источник топологии: debug-ws (ws://debug_server, по умолчанию) или tcp (RequestAdjacency/RequestPeers). "
        "Старый режим только TCP: задайте --source tcp.",
    )
    p.add_argument(
        "--port-end",
        type=int,
        default=None,
        nargs="?",
        const=18200,
        metavar="PORT",
        help="Верхняя граница сканирования seed (--port..PORT, первый успешный handshake). "
        "Флаг без числа: до 18200. Без флага — только --port. "
        "Для --source debug-ws: верхняя граница ws-портов (--port..PORT). "
        f"Если не указан, для debug-ws по умолчанию {DEFAULT_DEBUG_WS_PORT_HI}. "
        "В PowerShell пишите число в той же строке или используйте --port-end=10000.",
    )
    p.add_argument(
        "--scan-timeout",
        type=float,
        default=1.0,
        help="Таймаут handshake на один порт при сканировании seed, сек",
    )
    p.add_argument(
        "--scan-workers",
        type=int,
        default=8 if sys.platform == "win32" else 16,
        help="Параллельные проверки портов при --port-end; на Windows держите низким (WSAENOBUFS 10055).",
    )
    p.add_argument(
        "--debug-timeout",
        type=float,
        default=2.0,
        help="Таймаут одного ws-подключения/получения snapshot в режиме --source debug-ws, сек",
    )
    p.add_argument(
        "--debug-no-refresh-cmd",
        action="store_true",
        help="Не отправлять {cmd: refresh_snapshot}; ждать только периодический push от debug_server.",
    )
    p.add_argument(
        "--poll-debug-ws",
        action="store_true",
        help="Live + debug-ws: периодически заново подключаться (как раньше). "
        "По умолчанию — постоянные WebSocket на все endpoint: сервер пушит snapshot, граф обновляется в реальном времени.",
    )
    p.add_argument(
        "--crawl-workers",
        type=int,
        default=3 if sys.platform == "win32" else 6,
        help="Параллельные TCP-опросы узлов при обходе; на Windows 2–3, иначе часто WinError 10055.",
    )
    p.add_argument(
        "--progress-min-interval",
        type=float,
        default=0.12,
        help="Мин. интервал снимка on_progress/live, сек (реже — быстрее обход за счёт копирования графа)",
    )
    p.add_argument("--depth", type=int, default=1, help="Глубина обхода (1 = только соседи seed)")
    p.add_argument("--limit", type=int, default=64, help="Лимит дескрипторов в одном RequestPeers (сервер ≤64)")
    p.add_argument(
        "--peer-rounds",
        type=int,
        default=4,
        help="Сколько раз запросить PeersResponse на одном соединении (объединяем уникальные peer_id; "
        "нужно, т.к. сервер отдаёт ≤64 и сэмплирует каталог)",
    )
    p.add_argument("--timeout", type=float, default=10.0, help="Таймаут сокета, сек")
    p.add_argument("--connect-retries", type=int, default=2, help="Повторы connect/handshake для одного адреса")
    p.add_argument("--retry-backoff", type=float, default=0.2, help="Базовая пауза между повторами, сек")
    p.add_argument(
        "--max-addrs-per-peer",
        type=int,
        default=3,
        help="Сколько observed_addrs пробовать на peer (по умолчанию 3)",
    )
    p.add_argument("--out", default="", help="Сохранить PNG (если пусто — интерактивное окно)")
    p.add_argument(
        "--json-out",
        "--json",
        default="",
        dest="json_out",
        help="Снимок в JSON. С --once и без --out: один файл и выход. Без --once: live-окно, JSON после каждого кадра (фон).",
    )
    p.add_argument(
        "--refresh-seconds",
        type=float,
        default=5.0,
        help="Период опроса сети в live-режиме, сек (регулируется клавишами [ ] во время работы)",
    )
    p.add_argument(
        "--layout-iterations",
        type=int,
        default=50,
        help="Итераций spring_layout за кадр (больше — стабильнее, медленнее)",
    )
    p.add_argument(
        "--once",
        action="store_true",
        help="Сделать один снимок и завершить работу (без live-обновлений)",
    )
    p.add_argument(
        "--use-descriptors",
        action="store_true",
        help="Отправлять RequestDescriptors (ответ тот же PeersResponse)",
    )
    p.add_argument(
        "--catalog-edges",
        action="store_true",
        help="Дополнительно edges_catalog из PeersResponse (см. JSON)",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Подробные логи (DEBUG: кадры, типы пакетов)")
    p.add_argument("-q", "--quiet", action="store_true", help="Только ERROR")
    args = p.parse_args()

    if args.port is None:
        if args.source == "debug-ws":
            args.port = DEFAULT_DEBUG_WS_PORT_LO
        else:
            args.port = 8080

    if args.source == "debug-ws" and args.port_end is None:
        args.port_end = DEFAULT_DEBUG_WS_PORT_HI
        if args.port_end < args.port:
            args.port_end = args.port

    try:
        from lp2ln_topology.crawl import (
            crawl_network,
            ego_session_topology,
            run_debug_ws_live_streams_blocking,
        )
        from lp2ln_topology.logutil import setup_logging
        from lp2ln_topology.plot import draw_topology_on_axes, render_topology
        import matplotlib.pyplot as plt
    except ImportError:
        print("Запускайте из каталога tools/topology-viewer с активированным venv.", file=sys.stderr)
        raise

    if args.quiet:
        level = logging.ERROR
    elif args.verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    setup_logging(level=level)

    def _exit_immediately_on_sigint(_signum: int, _frame: Any) -> None:
        # В live-режиме crawl крутится в не-daemon потоке executor; обычный KeyboardInterrupt
        # может ждать завершения сетевых timeout'ов. Прерываем процесс сразу.
        logging.info("Остановка viewer по Ctrl+C")
        try:
            plt.close("all")
        finally:
            os._exit(130)

    signal.signal(signal.SIGINT, _exit_immediately_on_sigint)

    def _crawl_common_kwargs():
        return dict(
            source=args.source,
            max_depth=max(1, args.depth),
            limit=max(1, min(args.limit, 256)),
            peer_rounds=max(1, args.peer_rounds),
            timeout=args.timeout,
            use_descriptors=args.use_descriptors,
            include_catalog_edges=args.catalog_edges,
            connect_retries=max(1, args.connect_retries),
            retry_backoff_s=max(0.0, args.retry_backoff),
            max_addrs_per_peer=max(1, args.max_addrs_per_peer),
            seed_port_end=args.port_end,
            scan_probe_timeout=max(0.25, float(args.scan_timeout)),
            scan_workers=max(1, args.scan_workers),
            crawl_workers=max(1, args.crawl_workers),
            progress_min_interval_s=max(0.0, float(args.progress_min_interval)),
            debug_ws_timeout=max(0.25, float(args.debug_timeout)),
            debug_request_refresh=not args.debug_no_refresh_cmd,
        )

    def take_snapshot():
        return crawl_network(args.host, args.port, **_crawl_common_kwargs())

    def compute_stats(topo) -> dict:
        nodes = set(topo.nodes.keys())
        und_edges = normalize_undirected_edges(topo.edges)
        deg = Counter()
        for a, b in und_edges:
            deg[a] += 1
            deg[b] += 1
        n = len(nodes)
        m = len(und_edges)
        if n == 0:
            return {
                "nodes": 0,
                "edges_sessions": 0,
                "avg_out": 0.0,
                "avg_in": 0.0,
                "max_out": 0,
                "max_in": 0,
                "unreachable": 0,
                "degree_hist": {},
                "diameter": 0,
                "avg_path_length": 0.0,
                "largest_cc_size": 0,
            }
        deg_vals = [deg.get(pid, 0) for pid in nodes]

        # Undirected степень для гистограммы/диаметра: объединяем out+in пары.
        und_adj: Dict[str, Set[str]] = {pid: set() for pid in nodes}
        for a, b in und_edges:
            if a in und_adj and b in und_adj:
                und_adj[a].add(b)
                und_adj[b].add(a)
        und_degree = {pid: len(adj) for pid, adj in und_adj.items()}
        deg_hist: Counter = Counter(und_degree.values())

        # BFS в крупнейшей компоненте связности → diameter + avg path length.
        visited: Set[str] = set()
        components: list[Set[str]] = []
        for pid in nodes:
            if pid in visited:
                continue
            comp: Set[str] = set()
            stack = [pid]
            while stack:
                u = stack.pop()
                if u in comp:
                    continue
                comp.add(u)
                visited.add(u)
                for v in und_adj.get(u, ()):
                    if v not in comp:
                        stack.append(v)
            components.append(comp)
        largest_cc: Set[str] = max(components, key=len) if components else set()

        diameter = 0
        sum_path_len = 0.0
        pair_count = 0
        if len(largest_cc) >= 2:
            # Eccentricity BFS по каждому узлу крупнейшей CC. O(V * (V+E)).
            # Для ~1k узлов ок; при 10k+ будем сэмплировать.
            sample_nodes = list(largest_cc)
            if len(sample_nodes) > 256:
                import random
                random.seed(42)
                sample_nodes = random.sample(sample_nodes, 256)
            for src in sample_nodes:
                dist: Dict[str, int] = {src: 0}
                frontier = [src]
                while frontier:
                    next_frontier: list[str] = []
                    for u in frontier:
                        d_next = dist[u] + 1
                        for v in und_adj.get(u, ()):
                            if v not in dist:
                                dist[v] = d_next
                                next_frontier.append(v)
                    frontier = next_frontier
                local_max = max(dist.values()) if dist else 0
                if local_max > diameter:
                    diameter = local_max
                for d in dist.values():
                    if d > 0:
                        sum_path_len += d
                        pair_count += 1
        avg_path_length = round(sum_path_len / pair_count, 3) if pair_count else 0.0

        bootstrap_nodes = {
            pid
            for pid, desc in topo.nodes.items()
            if isinstance(desc, dict)
            and bool((desc.get("capabilities") or {}).get("bootstrap_entry", False))
        }
        bootstrap_incident: Dict[str, int] = {pid: 0 for pid in bootstrap_nodes}
        for a, b in und_edges:
            if a in bootstrap_incident:
                bootstrap_incident[a] += 1
            if b in bootstrap_incident:
                bootstrap_incident[b] += 1
        bootstrap_values = sorted(bootstrap_incident.values())
        if bootstrap_values:
            boot_max = max(bootstrap_values)
            boot_median = bootstrap_values[len(bootstrap_values) // 2]
            bootstrap_skew = round((boot_max / boot_median), 3) if boot_median > 0 else float(boot_max)
            max_bootstrap_in_share = round((boot_max / m), 5) if m > 0 else 0.0
            bootstrap_in_share = round((sum(bootstrap_values) / m), 5) if m > 0 else 0.0
        else:
            bootstrap_skew = 0.0
            max_bootstrap_in_share = 0.0
            bootstrap_in_share = 0.0

        return {
            "nodes": n,
            "edges_sessions": m,
            "avg_out": round(sum(deg_vals) / n, 3),
            "avg_in": round(sum(deg_vals) / n, 3),
            "max_out": max(deg_vals),
            "max_in": max(deg_vals),
            "unreachable": len(getattr(topo, "unreachable", {})),
            "degree_hist": {str(k): int(v) for k, v in sorted(deg_hist.items())},
            "diameter": int(diameter),
            "avg_path_length": avg_path_length,
            "largest_cc_size": int(len(largest_cc)),
            "bootstrap_count": len(bootstrap_nodes),
            "bootstrap_in_edges": {k: int(v) for k, v in sorted(bootstrap_incident.items())},
            "bootstrap_skew": bootstrap_skew,
            "max_bootstrap_in_share": max_bootstrap_in_share,
            "bootstrap_in_share": bootstrap_in_share,
        }

    json_out_lock = threading.Lock()

    def build_json_snapshot(topo: Any) -> dict:
        und_edges = normalize_undirected_edges(topo.edges)
        snap = {
            "seeds": list(topo.seeds),
            "nodes": dict(topo.nodes),
            "edges": [{"from": a, "to": b} for a, b in sorted(und_edges)],
            "edges_note": "from-to: ненаправленное ребро сессии между двумя peer_id",
            "stats": compute_stats(topo),
            "unreachable": dict(sorted(getattr(topo, "unreachable", {}).items())),
        }
        if topo.catalog_edges:
            snap["edges_catalog"] = [{"from": a, "to": b} for a, b in sorted(topo.catalog_edges)]
        return snap

    def save_json_snapshot(topo: Any, *, background: bool = False) -> None:
        """background=True (live): запись в отдельном потоке, не блокирует matplotlib."""
        if not args.json_out:
            return
        snap = build_json_snapshot(topo)
        path = args.json_out

        def _write() -> None:
            with json_out_lock:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(snap, f, indent=2, ensure_ascii=False)

        if background:
            threading.Thread(target=_write, name="json-out", daemon=True).start()
        else:
            _write()

    out = (args.out or "").strip() or None
    json_out_path = (args.json_out or "").strip()
    # --json без --out и с --once: один снимок в файл и выход (без окна). Без --once — live + JSON в фоне.
    json_headless = bool(json_out_path) and out is None and args.once
    if out or args.once or json_headless:
        topo = take_snapshot()
        save_json_snapshot(topo, background=False)
        seed_h, seed_p = (topo.seed_tcp if topo.seed_tcp else (args.host, args.port))
        mode_label = "debug-ws" if args.source == "debug-ws" else "TCP"
        title = f"LP2LN сессии ({mode_label}) @ {seed_h}:{seed_p} (depth={args.depth})"
        if out:
            render_topology(topo, out_path=out, title=title)
        elif json_headless:
            logging.info("Снимок записан в %s (окно matplotlib не открывалось).", json_out_path)
        else:
            render_topology(topo, out_path=None, title=title)
        return 0

    refresh_seconds = max(0.5, float(args.refresh_seconds))
    layout_iterations = max(10, int(args.layout_iterations))

    plt.ion()
    fig, ax = plt.subplots(figsize=(13, 9))
    fig.subplots_adjust(bottom=0.08)
    status_text = fig.text(
        0.02,
        0.02,
        "",
        fontsize=9,
        family="monospace",
        va="bottom",
        ha="left",
        transform=fig.transFigure,
        color="#2c3e50",
    )
    fig.text(
        0.98,
        0.02,
        "■ фокус  ■ bootstrap  ■ seed  ■ новый  ■ узел\n"
        "— новое ребро TCP   ·   ЛКМ — связи узла   ·   c — весь граф\n"
        "Подписи узлов: номер из пути …/peer_N/… при однозначности, иначе уникальный номер.",
        fontsize=8,
        family="sans-serif",
        va="bottom",
        ha="right",
        transform=fig.transFigure,
        color="#34495e",
    )
    ui: Dict[str, Any] = {
        "paused": False,
        "refresh": refresh_seconds,
        "force_refresh": False,
        "focus_peer_id": None,
        "debug_stream": False,
        "stream_started": 0.0,
    }
    NODE_PICK_RADIUS = 18.0
    live_topo: Optional[Any] = None
    prev_pos_full: Dict[str, Tuple[float, float]] = {}

    prev_nodes: Set[str] = set()
    prev_edges: Set[Tuple[str, str]] = set()
    frame_idx = 0
    last_crawl_s = 0.0
    next_crawl_at = time.monotonic()
    crawl_t0 = 0.0
    pending: Optional[Future] = None
    last_error: Optional[str] = None

    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="crawl")
    progress_q: queue.SimpleQueue = queue.SimpleQueue()
    cached_debug_ws_urls: Optional[List[str]] = None
    use_debug_stream = args.source == "debug-ws" and not args.poll_debug_ws
    stream_stop_event = threading.Event()
    stream_worker_thread: Optional[threading.Thread] = None
    debug_stream_mode_active = False

    def crawl_job():
        nonlocal cached_debug_ws_urls

        def on_progress(snap: Any) -> None:
            progress_q.put(snap)

        kw = _crawl_common_kwargs()
        if args.source == "debug-ws" and cached_debug_ws_urls:
            kw["debug_ws_urls"] = list(cached_debug_ws_urls)
        topo = crawl_network(
            args.host,
            args.port,
            **kw,
            on_progress=on_progress,
        )
        if args.source == "debug-ws" and topo.debug_ws_urls and cached_debug_ws_urls is None:
            cached_debug_ws_urls = list(topo.debug_ws_urls)
            logging.info(
                "debug-ws: закэшировано %s endpoint(s); следующие опросы — только snapshot, без скана порта (r — снова скан)",
                len(cached_debug_ws_urls),
            )
        return topo

    def drain_progress_queue() -> None:
        """Сбрасывает накопленные промежуточные снимки (актуален только финальный result)."""
        try:
            while True:
                progress_q.get_nowait()
        except queue.Empty:
            pass

    def paint_graph(topo: Any, crawl_s: float, *, scan_phase: bool = False, bump_frame: bool = True) -> None:
        nonlocal prev_nodes, prev_edges, prev_pos_full, frame_idx, last_crawl_s, last_error, live_topo
        live_topo = topo
        last_error = None
        last_crawl_s = crawl_s

        if bump_frame:
            save_json_snapshot(topo, background=True)
            nodes_now = set(topo.nodes.keys())
            edges_now = normalize_undirected_edges(topo.edges)
            new_nodes = nodes_now - prev_nodes
            lost_nodes = prev_nodes - nodes_now
            new_edges = edges_now - prev_edges
            lost_edges = prev_edges - edges_now
            prev_nodes = nodes_now
            prev_edges = edges_now
            frame_idx += 1
            dn = len(new_nodes) - len(lost_nodes)
            de = len(new_edges) - len(lost_edges)
            delta_n = f"{dn:+d}" if dn else "0"
            delta_e = f"{de:+d}" if de else "0"
        else:
            new_nodes = set()
            new_edges = set()
            delta_n = "0"
            delta_e = "0"

        fp = ui.get("focus_peer_id")
        if fp and fp not in topo.nodes:
            ui["focus_peer_id"] = None
            fp = None

        g_draw = ego_session_topology(topo, fp) if fp else topo
        st = compute_stats(g_draw)
        st_full = compute_stats(topo)
        seed_h, seed_p = (topo.seed_tcp if topo.seed_tcp else (args.host, args.port))
        mode_label = "debug-ws" if args.source == "debug-ws" else "tcp"
        now_s = datetime.now().strftime("%H:%M:%S")

        if fp:
            title = (
                f"LP2LN live ({mode_label}) @ {seed_h}:{seed_p}  |  {now_s}  |  фокус: {st['nodes']} узл., "
                f"{st['edges_sessions']} рёбер (только сессии к/от узла)  |  весь граф: {st_full['nodes']} узл."
            )
        else:
            title = (
                f"LP2LN live ({mode_label}) @ {seed_h}:{seed_p}  |  {now_s}  |  "
                f"узлов {st['nodes']} (Δ{delta_n})  рёбер {st['edges_sessions']} (Δ{delta_e})"
            )

        seeds_draw = set(topo.seeds) & set(g_draw.nodes.keys())

        if fp:
            draw_topology_on_axes(
                ax,
                g_draw,
                title=title,
                prev_pos=None,
                frozen_positions=prev_pos_full if prev_pos_full else None,
                new_node_ids=new_nodes,
                new_edge_set=new_edges,
                seed_peer_ids=seeds_draw,
                layout_iterations=layout_iterations,
                node_picker_radius=NODE_PICK_RADIUS,
                focus_peer_id=fp,
            )
        else:
            prev_pos_full = draw_topology_on_axes(
                ax,
                g_draw,
                title=title,
                prev_pos=prev_pos_full or None,
                frozen_positions=None,
                new_node_ids=new_nodes,
                new_edge_set=new_edges,
                seed_peer_ids=set(topo.seeds),
                layout_iterations=layout_iterations,
                node_picker_radius=NODE_PICK_RADIUS,
                focus_peer_id=None,
            )

        unreachable_n = st_full.get("unreachable", 0)
        diameter = st_full.get("diameter", 0)
        avg_pl = st_full.get("avg_path_length", 0.0)
        largest_cc = st_full.get("largest_cc_size", 0)
        boot_skew = st_full.get("bootstrap_skew", 0.0)
        boot_max_share = st_full.get("max_bootstrap_in_share", 0.0)
        focus_hint = "  |  ЛКМ узел — фокус  c — весь граф" if not fp else "  |  c — весь граф"
        if scan_phase:
            status_text.set_text(
                f"сканирование… {crawl_s:.1f}с (промежуточный кадр)  |  "
                f"узлов {st_full['nodes']}  рёбер {st_full['edges_sessions']}  |  недоступно: {unreachable_n}  |  "
                f"[{frame_idx}]  пробел пауза  r  [ ] интервал  q выход{focus_hint}"
            )
        else:
            if ui.get("debug_stream"):
                interval_hint = "постоянные ws (push)"
            else:
                interval_hint = f"след. кадр через {ui['refresh']:.1f}с"
            status_text.set_text(
                f"опрос {crawl_s:.1f}с  |  недоступно: {unreachable_n}  |  "
                f"диаметр {diameter}  ср. путь {avg_pl}  макс.CC {largest_cc}  |  "
                f"boot_skew {boot_skew}  boot_max_share {boot_max_share}  |  "
                f"max_out {st_full.get('max_out', 0)}  max_in {st_full.get('max_in', 0)}  |  "
                f"{interval_hint}  |  "
                f"[{frame_idx}]  пробел пауза  r сразу  [ ] интервал  q выход{focus_hint}"
            )
        fig.tight_layout()
        fig.subplots_adjust(bottom=0.08)
        fig.canvas.draw_idle()

    def apply_topology(topo: Any, crawl_s: float, *, scan_phase: bool = False) -> None:
        paint_graph(topo, crawl_s, scan_phase=scan_phase, bump_frame=True)

    def on_pick(event: Any) -> None:
        artist = getattr(ax, "_lp2ln_nodes_artist", None)
        if artist is None or event.artist is not artist:
            return
        me = getattr(event, "mouseevent", None)
        if me is not None and getattr(me, "button", 1) != 1:
            return
        ind = getattr(event, "ind", None)
        if ind is None or len(ind) == 0:
            return
        order = getattr(ax, "_lp2ln_node_pick_order", None) or []
        idx = int(ind[0])
        if idx < 0 or idx >= len(order):
            return
        peer_id = order[idx]
        if ui.get("focus_peer_id") == peer_id:
            ui["focus_peer_id"] = None
            logging.info("Фокус снят (клик по тому же узлу)")
        else:
            ui["focus_peer_id"] = peer_id
            logging.info("Фокус: связи узла %s…", peer_id[:16])
        if live_topo is not None:
            paint_graph(live_topo, last_crawl_s, scan_phase=False, bump_frame=False)

    def on_key(event: Any) -> None:
        if not event.key:
            return
        k = event.key.lower()
        if k in ("q", "escape"):
            plt.close(fig)
        elif k == " ":
            ui["paused"] = not ui["paused"]
            logging.info("Пауза опроса: %s", ui["paused"])
        elif k == "[":
            ui["refresh"] = max(0.5, ui["refresh"] - 1.0)
            logging.info("Интервал опроса: %.1f с", ui["refresh"])
        elif k == "]":
            ui["refresh"] = min(600.0, ui["refresh"] + 1.0)
            logging.info("Интервал опроса: %.1f с", ui["refresh"])
        elif k == "r":
            ui["force_refresh"] = True
            logging.info("Запрошено обновление (r); для debug-ws при старте обхода сбросится кэш ws-портов")
        elif k == "c":
            if ui.get("focus_peer_id"):
                ui["focus_peer_id"] = None
                logging.info("Фокус снят (весь граф)")
                if live_topo is not None:
                    paint_graph(live_topo, last_crawl_s, scan_phase=False, bump_frame=False)

    fig.canvas.mpl_connect("key_press_event", on_key)
    fig.canvas.mpl_connect("pick_event", on_pick)

    try:
        while plt.fignum_exists(fig.number):
            now = time.monotonic()
            if (
                use_debug_stream
                and debug_stream_mode_active
                and stream_worker_thread is not None
                and not stream_worker_thread.is_alive()
            ):
                debug_stream_mode_active = False
                ui["debug_stream"] = False
                next_crawl_at = min(next_crawl_at, now + 1.0)
                logging.warning(
                    "debug-ws: поток постоянных WebSocket завершился (ошибка/сеть); "
                    "повторный обход через %.0fs или нажмите r",
                    max(0.0, next_crawl_at - now),
                )

            if pending is not None and pending.done():
                try:
                    topo = pending.result()
                    drain_progress_queue()
                    crawl_s = time.perf_counter() - crawl_t0
                    apply_topology(topo, crawl_s)
                    if (
                        use_debug_stream
                        and topo.debug_ws_urls
                        and (
                            stream_worker_thread is None
                            or not stream_worker_thread.is_alive()
                        )
                    ):
                        stream_stop_event.clear()
                        urls_snap = list(topo.debug_ws_urls)
                        seed_snap = topo.seed_tcp or (
                            args.host,
                            int(args.port) if args.port is not None else 0,
                        )

                        def stream_runner() -> None:
                            try:
                                run_debug_ws_live_streams_blocking(
                                    urls_snap,
                                    seed_tcp=seed_snap,
                                    include_catalog_edges=args.catalog_edges,
                                    request_refresh=not args.debug_no_refresh_cmd,
                                    timeout_s=max(0.5, float(args.debug_timeout)),
                                    emit_interval_s=max(
                                        0.05,
                                        min(float(args.progress_min_interval), 0.5),
                                    ),
                                    stop=stream_stop_event,
                                    progress_callback=lambda snap: progress_q.put(snap),
                                )
                            except Exception:
                                logging.exception("debug-ws live stream")

                        stream_worker_thread = threading.Thread(
                            target=stream_runner,
                            name="debug-ws-stream",
                            daemon=True,
                        )
                        stream_worker_thread.start()
                        ui["debug_stream"] = True
                        ui["stream_started"] = time.perf_counter()
                        debug_stream_mode_active = True
                        logging.info(
                            "debug-ws: постоянные WebSocket (%s endpoint), push snapshot → UI",
                            len(urls_snap),
                        )
                except Exception as e:
                    last_error = f"{type(e).__name__}: {e}"
                    logging.exception("Ошибка обхода в фоне")
                    status_text.set_text(
                        f"ОШИБКА: {last_error}  |  повтор через {ui['refresh']:.1f}с  |  r — сразу  q — выход"
                    )
                    fig.canvas.draw_idle()
                pending = None
                if ui["force_refresh"]:
                    next_crawl_at = now
                elif debug_stream_mode_active:
                    next_crawl_at = float("inf")
                else:
                    next_crawl_at = now + ui["refresh"]

            periodic_ok = (not use_debug_stream) or (not debug_stream_mode_active)
            want_crawl = (
                pending is None
                and (ui["force_refresh"] or not ui["paused"])
                and (ui["force_refresh"] or (periodic_ok and now >= next_crawl_at))
            )
            if want_crawl:
                rescan_ports = ui["force_refresh"]
                ui["force_refresh"] = False
                if rescan_ports and args.source == "debug-ws":
                    if (
                        use_debug_stream
                        and stream_worker_thread is not None
                        and stream_worker_thread.is_alive()
                    ):
                        stream_stop_event.set()
                        stream_worker_thread.join(timeout=4.0)
                    stream_worker_thread = None
                    ui["debug_stream"] = False
                    debug_stream_mode_active = False
                    cached_debug_ws_urls = None
                    logging.info("debug-ws: сброс кэша ws-endpoint / остановка потока (полный скан)")
                drain_progress_queue()
                crawl_t0 = time.perf_counter()
                pending = executor.submit(crawl_job)

            if pending is not None and not pending.done():
                latest_partial = None
                try:
                    while True:
                        latest_partial = progress_q.get_nowait()
                except queue.Empty:
                    pass
                if latest_partial is not None:
                    apply_topology(
                        latest_partial,
                        time.perf_counter() - crawl_t0,
                        scan_phase=True,
                    )
                else:
                    elapsed = time.perf_counter() - crawl_t0
                    extra = f"  |  {last_error}" if last_error else ""
                    status_text.set_text(
                        f"сканирование сети… {elapsed:.1f}с (ожидание первого узла…)  |  "
                        f"кадр {frame_idx}  интервал {ui['refresh']:.1f}с{extra}"
                    )
                    fig.canvas.draw_idle()
            elif ui.get("debug_stream") and pending is None:
                latest_stream = None
                try:
                    while True:
                        latest_stream = progress_q.get_nowait()
                except queue.Empty:
                    pass
                if latest_stream is not None:
                    st0 = float(ui.get("stream_started") or crawl_t0)
                    apply_topology(
                        latest_stream,
                        time.perf_counter() - st0,
                        scan_phase=False,
                    )
            elif pending is None and ui["paused"] and not ui["force_refresh"]:
                status_text.set_text(
                    f"ПАУЗА  |  интервал {ui['refresh']:.1f}с  |  кадр {frame_idx}  "
                    f"|  последний опрос {last_crawl_s:.1f}с  |  пробел — продолжить"
                )
                fig.canvas.draw_idle()

            fig.canvas.flush_events()
            plt.pause(0.05)
    except KeyboardInterrupt:
        logging.info("Остановка viewer по Ctrl+C")
    finally:
        stream_stop_event.set()
        if stream_worker_thread is not None and stream_worker_thread.is_alive():
            stream_worker_thread.join(timeout=4.0)
        try:
            executor.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            executor.shutdown(wait=False)
        plt.close(fig)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
