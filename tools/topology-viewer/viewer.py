#!/usr/bin/env python3
"""
Сбор топологии по TCP с bootstrap-ноды и отрисовка графа.

Пример (из каталога tools/topology-viewer, venv активирован):
  python viewer.py --host 127.0.0.1 --port 18080 --depth 2 --peer-rounds 6 --out topo.png
  python viewer.py --host 127.0.0.1 --port 18080 --refresh-seconds 3   # live-окно
  python viewer.py --host 192.168.0.16 --port 18080 --port-end --out topo.png
  (сканирование seed с 18080 до 18200: --port-end или --port-end 18200)
"""

from __future__ import annotations

import argparse
import json
import logging
import queue
import sys
import threading
import time
from collections import Counter
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime
from typing import Any, Dict, Optional, Set, Tuple


def main() -> int:
    p = argparse.ArgumentParser(
        description="LP2LN topology viewer: TCP + JSON кадры как в lp2ln-core-v2.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Live-окно (без --out и без --once): обход в фоне; граф обновляется по мере обхода узлов, "
            "не только после полного завершения crawl.\n"
            "Пробел — пауза/продолжить, r — сразу обновить, [ / ] — интервал −1с / +1с, q или Esc — выход.\n"
            "ЛКМ по узлу — показать только его рёбра сессий (соседей); повторный клик по тому же узлу или c — весь граф.\n"
            "Цвета: фиолетовый — узел в фокусе; красный — bootstrap; оранжевый — seed; зелёный — новый с прошлого кадра; "
            "синий — остальные; оранжевые рёбра — новые TCP-сессии."
        ),
    )
    p.add_argument("--host", default="127.0.0.1", help="Адрес ноды (bootstrap)")
    p.add_argument("--port", type=int, default=8080, help="Нижняя граница TCP для seed (начало сканирования)")
    p.add_argument(
        "--port-end",
        type=int,
        default=None,
        nargs="?",
        const=18200,
        metavar="PORT",
        help="Верхняя граница сканирования seed (--port..PORT, первый успешный handshake). "
        "Флаг без числа: до 18200. Без флага — только --port.",
    )
    p.add_argument(
        "--scan-timeout",
        type=float,
        default=1.0,
        help="Таймаут handshake на один порт при сканировании seed, сек",
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
        default="",
        help="Снимок в JSON; в live-режиме запись в фоне (после каждого кадра crawl), с блокировкой",
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

    try:
        from lp2ln_topology.crawl import crawl_network, ego_session_topology
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

    def _crawl_common_kwargs():
        return dict(
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
        )

    def take_snapshot():
        return crawl_network(args.host, args.port, **_crawl_common_kwargs())

    def compute_stats(topo) -> dict:
        nodes = set(topo.nodes.keys())
        out = Counter(a for a, _ in topo.edges)
        inn = Counter(b for _, b in topo.edges)
        n = len(nodes)
        m = len(topo.edges)
        if n == 0:
            return {
                "nodes": 0,
                "edges_sessions": 0,
                "avg_out": 0.0,
                "avg_in": 0.0,
                "max_out": 0,
                "max_in": 0,
                "unreachable": 0,
            }
        out_vals = [out.get(pid, 0) for pid in nodes]
        in_vals = [inn.get(pid, 0) for pid in nodes]
        return {
            "nodes": n,
            "edges_sessions": m,
            "avg_out": round(sum(out_vals) / n, 3),
            "avg_in": round(sum(in_vals) / n, 3),
            "max_out": max(out_vals),
            "max_in": max(in_vals),
            "unreachable": len(getattr(topo, "unreachable", {})),
        }

    json_out_lock = threading.Lock()

    def build_json_snapshot(topo: Any) -> dict:
        snap = {
            "seeds": list(topo.seeds),
            "nodes": dict(topo.nodes),
            "edges": [{"from": a, "to": b} for a, b in sorted(topo.edges)],
            "edges_note": "from→to: у from активная сессия к to (AdjacencyResponse)",
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
    if out or args.once:
        topo = take_snapshot()
        save_json_snapshot(topo, background=False)
        seed_h, seed_p = (topo.seed_tcp if topo.seed_tcp else (args.host, args.port))
        render_topology(
            topo,
            out_path=out,
            title=f"LP2LN TCP-сессии @ {seed_h}:{seed_p} (depth={args.depth})",
        )
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
        "— новое ребро TCP   ·   ЛКМ — связи узла   ·   c — весь граф",
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

    def crawl_job():
        def on_progress(snap: Any) -> None:
            progress_q.put(snap)

        return crawl_network(
            args.host,
            args.port,
            **_crawl_common_kwargs(),
            on_progress=on_progress,
        )

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
            edges_now = set(topo.edges)
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
        now_s = datetime.now().strftime("%H:%M:%S")

        if fp:
            title = (
                f"LP2LN live @ {seed_h}:{seed_p}  |  {now_s}  |  фокус: {st['nodes']} узл., "
                f"{st['edges_sessions']} рёбер (только сессии к/от узла)  |  весь граф: {st_full['nodes']} узл."
            )
        else:
            title = (
                f"LP2LN live @ {seed_h}:{seed_p}  |  {now_s}  |  "
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
        focus_hint = "  |  ЛКМ узел — фокус  c — весь граф" if not fp else "  |  c — весь граф"
        if scan_phase:
            status_text.set_text(
                f"сканирование… {crawl_s:.1f}с (промежуточный кадр)  |  "
                f"узлов {st_full['nodes']}  рёбер {st_full['edges_sessions']}  |  недоступно: {unreachable_n}  |  "
                f"[{frame_idx}]  пробел пауза  r  [ ] интервал  q выход{focus_hint}"
            )
        else:
            status_text.set_text(
                f"опрос {crawl_s:.1f}с  |  недоступно адресов: {unreachable_n}  |  "
                f"след. кадр через {ui['refresh']:.1f}с  |  "
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

            if pending is not None and pending.done():
                try:
                    topo = pending.result()
                    drain_progress_queue()
                    crawl_s = time.perf_counter() - crawl_t0
                    apply_topology(topo, crawl_s)
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
                else:
                    next_crawl_at = now + ui["refresh"]

            want_crawl = (
                pending is None
                and (ui["force_refresh"] or not ui["paused"])
                and (ui["force_refresh"] or now >= next_crawl_at)
            )
            if want_crawl:
                ui["force_refresh"] = False
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
        try:
            executor.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            executor.shutdown(wait=False)
        plt.close(fig)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
