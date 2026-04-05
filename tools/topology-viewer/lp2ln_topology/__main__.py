"""Запуск: cd tools/topology-viewer && python -m lp2ln_topology --host 127.0.0.1 --port 18080"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter


def main() -> int:
    p = argparse.ArgumentParser(
        description="Снимок топологии LP2LN: рёбра = активные TCP-сессии (RequestAdjacency), "
        "обход по адресам из PeersResponse.",
    )
    p.add_argument("--host", default="127.0.0.1", help="Адрес ноды (bootstrap или любая)")
    p.add_argument("--port", type=int, default=8080, help="TCP порт")
    p.add_argument("--depth", type=int, default=1, help="Глубина обхода (1 = только соседи seed)")
    p.add_argument("--limit", type=int, default=64, help="Лимит дескрипторов в запросе")
    p.add_argument("--timeout", type=float, default=10.0, help="Таймаут сокета, сек")
    p.add_argument("--connect-retries", type=int, default=2, help="Повторы connect/handshake для одного адреса")
    p.add_argument("--retry-backoff", type=float, default=0.2, help="Базовая пауза между повторами, сек")
    p.add_argument(
        "--max-addrs-per-peer",
        type=int,
        default=3,
        help="Сколько observed_addrs пробовать на peer (по умолчанию 3)",
    )
    p.add_argument(
        "--use-descriptors",
        action="store_true",
        help="Отправлять RequestDescriptors вместо RequestPeers (ответ тот же)",
    )
    p.add_argument(
        "--catalog-edges",
        action="store_true",
        help="Дополнительно сохранять рёбра каталога (кто кого вернул в PeersResponse) в JSON как edges_catalog",
    )
    p.add_argument("-o", "--output", default="", help="PNG файл (если пусто — окно matplotlib)")
    p.add_argument("--json-out", default="", help="JSON снимок узлов и рёбер")
    p.add_argument(
        "--refresh-seconds",
        type=float,
        default=15.0,
        help="Период live-обновления окна в секундах (по умолчанию 15)",
    )
    p.add_argument(
        "--once",
        action="store_true",
        help="Сделать один снимок и завершить работу (без live-обновлений)",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="DEBUG логи")
    p.add_argument("-q", "--quiet", action="store_true", help="Только ERROR")
    args = p.parse_args()

    try:
        from .crawl import crawl_network
        from .logutil import setup_logging
        from .plot import draw_topology_on_axes, render_topology
        import matplotlib.pyplot as plt
    except ImportError as e:
        print("Импорт не удался:", e, file=sys.stderr)
        print("Установите зависимости: pip install -r requirements.txt", file=sys.stderr)
        return 1

    if args.quiet:
        level = logging.ERROR
    elif args.verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    setup_logging(level=level)

    def take_snapshot():
        return crawl_network(
            args.host,
            args.port,
            max_depth=max(1, args.depth),
            limit=max(1, min(args.limit, 256)),
            timeout=args.timeout,
            use_descriptors=args.use_descriptors,
            include_catalog_edges=args.catalog_edges,
            connect_retries=max(1, args.connect_retries),
            retry_backoff_s=max(0.0, args.retry_backoff),
            max_addrs_per_peer=max(1, args.max_addrs_per_peer),
        )

    def compute_stats(g) -> dict:
        nodes = set(g.nodes.keys())
        out = Counter(a for a, _ in g.edges)
        inn = Counter(b for _, b in g.edges)
        n = len(nodes)
        m = len(g.edges)
        if n == 0:
            return {"nodes": 0, "edges": 0}
        out_vals = [out.get(pid, 0) for pid in nodes]
        in_vals = [inn.get(pid, 0) for pid in nodes]
        return {
            "nodes": n,
            "edges_sessions": m,
            "avg_out": round(sum(out_vals) / n, 3),
            "avg_in": round(sum(in_vals) / n, 3),
            "max_out": max(out_vals),
            "max_in": max(in_vals),
            "unreachable": len(getattr(g, "unreachable", {})),
        }

    def save_json_snapshot(g) -> None:
        if not args.json_out:
            return
        snap = {
            "seeds": g.seeds,
            "nodes": g.nodes,
            "edges": [{"from": a, "to": b} for a, b in sorted(g.edges)],
            "edges_note": "from→to: у from активная сессия к to (AdjacencyResponse)",
            "stats": compute_stats(g),
            "unreachable": dict(sorted(getattr(g, "unreachable", {}).items())),
        }
        if g.catalog_edges:
            snap["edges_catalog"] = [{"from": a, "to": b} for a, b in sorted(g.catalog_edges)]
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(snap, f, indent=2, ensure_ascii=False)

    out = (args.output or "").strip() or None
    if out or args.once:
        g = take_snapshot()
        save_json_snapshot(g)
        render_topology(
            g,
            out_path=out,
            title=f"LP2LN TCP-сессии @ {args.host}:{args.port} (depth={args.depth}, nodes={len(g.nodes)})",
        )
        return 0 if g.nodes else 2

    refresh_seconds = max(1.0, float(args.refresh_seconds))
    plt.ion()
    fig, ax = plt.subplots(figsize=(12, 9))
    try:
        while plt.fignum_exists(fig.number):
            g = take_snapshot()
            save_json_snapshot(g)
            draw_topology_on_axes(
                ax,
                g,
                title=f"LP2LN TCP-сессии @ {args.host}:{args.port} (depth={args.depth}, nodes={len(g.nodes)})",
            )
            fig.tight_layout()
            fig.canvas.draw_idle()
            plt.pause(0.1)

            elapsed = 0.0
            while elapsed < refresh_seconds and plt.fignum_exists(fig.number):
                step = min(0.25, refresh_seconds - elapsed)
                plt.pause(step)
                elapsed += step
    except KeyboardInterrupt:
        logging.info("Остановка viewer по Ctrl+C")
    finally:
        plt.close(fig)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
