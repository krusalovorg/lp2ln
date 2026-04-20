"""Рисунок графа: networkx + matplotlib."""

from __future__ import annotations

import logging
import math
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

import matplotlib.pyplot as plt
import networkx as nx

from .crawl import TopologyGraph

logger = logging.getLogger(__name__)

PosMap = Dict[str, Tuple[float, float]]

_PEER_DIR_INDEX = re.compile(r"peer[_-](\d+)", re.I)


def build_peer_display_labels(g: TopologyGraph) -> Dict[str, str]:
    """Короткие уникальные подписи: `peer_N` из пути в observed_addrs (если однозначно), иначе свободные целые 1,2,3… без коллизий."""
    pids_sorted: List[str] = sorted(g.nodes.keys())
    inferred: Dict[str, int] = {}
    for pid in pids_sorted:
        desc = g.nodes.get(pid)
        if not isinstance(desc, dict):
            continue
        for line in desc.get("observed_addrs") or []:
            m = _PEER_DIR_INDEX.search(str(line))
            if m:
                inferred[pid] = int(m.group(1))
                break
    by_num: Dict[int, List[str]] = defaultdict(list)
    for pid, n in inferred.items():
        by_num[n].append(pid)
    for n in by_num:
        by_num[n].sort()

    out: Dict[str, str] = {}
    used: Set[str] = set()
    for n, group in sorted(by_num.items(), key=lambda x: x[0]):
        if len(group) == 1:
            s = str(n)
            out[group[0]] = s
            used.add(s)
        else:
            for i, pid in enumerate(group):
                s = f"{n}.{i}"
                out[pid] = s
                used.add(s)

    next_k = 1
    for pid in pids_sorted:
        if pid in out:
            continue
        while str(next_k) in used:
            next_k += 1
        s = str(next_k)
        out[pid] = s
        used.add(s)
        next_k += 1
    return out


def _normalize_undirected_edges(edges: Set[Tuple[str, str]]) -> Set[Tuple[str, str]]:
    out: Set[Tuple[str, str]] = set()
    for a, b in edges:
        if not a or not b or a == b:
            continue
        out.add((a, b) if a <= b else (b, a))
    return out


def topology_to_nx(g: TopologyGraph) -> nx.Graph:
    labels = build_peer_display_labels(g)
    dg = nx.Graph()
    for pid, desc in g.nodes.items():
        cap = (desc.get("capabilities") or {}) if isinstance(desc, dict) else {}
        dyn = (desc.get("dynamic_status") or {}) if isinstance(desc, dict) else {}
        boot = bool(cap.get("bootstrap_entry", False))
        base_limit = float(cap.get("base_session_limit") or 0) or 1.0
        active = float(dyn.get("active_connections") or 0)
        load = max(float(dyn.get("cpu_load") or 0), float(dyn.get("memory_pressure") or 0))
        utilization = min(1.0, active / base_limit) if base_limit else 0.0
        dg.add_node(
            pid,
            label=labels.get(pid, "?"),
            bootstrap=boot,
            active_connections=int(active),
            base_session_limit=int(base_limit),
            utilization=utilization,
            load=min(1.0, load),
            addrs=desc.get("observed_addrs") or [],
        )
    for a, b in _normalize_undirected_edges(g.edges):
        if a in dg and b in dg:
            dg.add_edge(a, b)
    return dg


def _load_color(load_0_to_1: float) -> str:
    """Градиент от зелёного к красному: 0→зелёный, 0.5→жёлтый, 1→красный."""
    t = max(0.0, min(1.0, float(load_0_to_1)))
    if t < 0.5:
        # зелёный → жёлтый
        r = int(0x27 + (0xF1 - 0x27) * (t / 0.5))
        g = int(0xae + (0xc4 - 0xae) * (t / 0.5))
        b = int(0x60 + (0x0f - 0x60) * (t / 0.5))
    else:
        # жёлтый → красный
        u = (t - 0.5) / 0.5
        r = int(0xF1 + (0xc0 - 0xF1) * u)
        g = int(0xc4 + (0x39 - 0xc4) * u)
        b = int(0x0f + (0x2b - 0x0f) * u)
    return f"#{r:02x}{g:02x}{b:02x}"


def draw_topology_on_axes(
    ax: Any,
    g: TopologyGraph,
    *,
    title: str = "LP2LN topology (TCP session adjacency)",
    seed: int = 42,
    prev_pos: Optional[PosMap] = None,
    frozen_positions: Optional[PosMap] = None,
    new_node_ids: Optional[Set[str]] = None,
    new_edge_set: Optional[Set[Tuple[str, str]]] = None,
    seed_peer_ids: Optional[Set[str]] = None,
    layout_iterations: int = 50,
    node_picker_radius: float = 0.0,
    focus_peer_id: Optional[str] = None,
) -> PosMap:
    """Рисует топологию в переданные axes (для live-обновления).

    Возвращает pos для следующего кадра (стабильнее, чем полный пересчёт с нуля).
    """
    dg = topology_to_nx(g)
    ax.clear()
    if dg.number_of_nodes() == 0:
        logger.warning(
            "Рисунок: 0 узлов — см. логи обхода выше (часто неверный порт, нода не запущена или нет PeersResponse)."
        )
        ax.text(0.5, 0.5, "Нет узлов (проверь адрес и что нода запущена).", ha="center", va="center")
        ax.axis("off")
        ax.set_title(title)
        ax._lp2ln_nodes_artist = None  # type: ignore[attr-defined]
        ax._lp2ln_node_pick_order = []  # type: ignore[attr-defined]
        return {}

    logger.info("Рисунок: %s узлов, %s рёбер", dg.number_of_nodes(), dg.number_of_edges())
    nn = new_node_ids or set()
    ne = _normalize_undirected_edges(new_edge_set or set())
    seeds = seed_peer_ids or set()

    nodes_list = list(dg.nodes)
    n_nodes = dg.number_of_nodes()
    n_edges = dg.number_of_edges()
    # Плотные графы (много рёбер на узел) — увеличиваем k и число итераций, иначе spring_layout схлопывает «ком».
    density = n_edges / float(max(1, n_nodes))
    k_base = 2.0 / max(1, n_nodes) ** 0.5
    k = k_base * (1.0 + 0.24 * min(18.0, max(0.0, density - 0.6)))
    iterations_eff = max(15, int(layout_iterations), int(38 + min(160, density * 11.0)))
    pos: PosMap
    if frozen_positions and all(n in frozen_positions for n in dg.nodes):
        pos = {n: frozen_positions[n] for n in dg.nodes}
    elif frozen_positions:
        init_f = {n: frozen_positions[n] for n in dg.nodes if n in frozen_positions}
        pos = nx.spring_layout(
            dg,
            seed=seed,
            k=k,
            pos=init_f if init_f else None,
            iterations=iterations_eff,
        )
    else:
        init_pos: PosMap = {}
        if prev_pos:
            init_pos = {n: p for n, p in prev_pos.items() if n in dg}
        if len(init_pos) < n_nodes:
            r_ring = 2.3 + 0.45 * math.sqrt(float(n_nodes))
            for i, n in enumerate(nodes_list):
                if n in init_pos:
                    continue
                ang = 2 * math.pi * float(i) / max(1, len(nodes_list))
                init_pos[n] = (math.cos(ang) * r_ring, math.sin(ang) * r_ring)
        pos = nx.spring_layout(
            dg,
            seed=seed,
            k=k,
            pos=init_pos if init_pos else None,
            iterations=iterations_eff,
        )

    colors: list[str] = []
    for n in dg.nodes:
        nd = dg.nodes[n]
        if focus_peer_id and n == focus_peer_id:
            colors.append("#8e44ad")
        elif nd.get("bootstrap"):
            colors.append("#c0392b")
        elif n in seeds:
            colors.append("#f39c12")
        elif n in nn:
            colors.append("#27ae60")
        else:
            # Цвет по заполнению ёмкости/нагрузке CPU (берём максимум).
            util = float(nd.get("utilization") or 0.0)
            load = float(nd.get("load") or 0.0)
            colors.append(_load_color(max(util, load)))

    labels: Dict[str, str] = {n: dg.nodes[n]["label"] for n in dg.nodes}

    w_scale = max(0.38, 0.95 - min(0.58, n_edges / 720.0))
    edge_colors: list[str] = []
    edge_widths: list[float] = []
    for u, v in dg.edges:
        edge_key = (u, v) if u <= v else (v, u)
        if edge_key in ne:
            edge_colors.append("#e67e22")
            edge_widths.append(max(1.8, 2.35 * w_scale))
        else:
            edge_colors.append("#7f8c8d")
            edge_widths.append(w_scale)

    edge_alpha = 0.72 if n_edges <= 3 * max(1, n_nodes) else 0.26
    nx.draw_networkx_edges(
        dg,
        pos,
        ax=ax,
        edgelist=list(dg.edges),
        edge_color=edge_colors,
        width=edge_widths,
        alpha=edge_alpha,
    )
    node_size = int(max(320.0, 820.0 - 11.5 * float(n_nodes)))
    nodes_artist = nx.draw_networkx_nodes(
        dg, pos, ax=ax, node_color=colors, node_size=node_size, alpha=0.92
    )
    nx.draw_networkx_labels(dg, pos, labels, ax=ax, font_size=9, font_weight="bold")
    ax.set_title(title)
    ax.axis("off")
    if node_picker_radius and nodes_artist is not None:
        nodes_artist.set_picker(float(node_picker_radius))
        ax._lp2ln_nodes_artist = nodes_artist  # type: ignore[attr-defined]
        ax._lp2ln_node_pick_order = nodes_list  # type: ignore[attr-defined]
    else:
        ax._lp2ln_nodes_artist = None  # type: ignore[attr-defined]
        ax._lp2ln_node_pick_order = []  # type: ignore[attr-defined]
    return pos


def render_topology(
    g: TopologyGraph,
    *,
    out_path: Optional[str] = None,
    title: str = "LP2LN topology (TCP session adjacency)",
    figsize: Tuple[float, float] = (12, 9),
    seed: int = 42,
) -> None:
    fig, ax = plt.subplots(figsize=figsize)
    _ = draw_topology_on_axes(ax, g, title=title, seed=seed)
    fig.tight_layout()
    if out_path:
        fig.savefig(out_path, bbox_inches="tight", dpi=140)
    else:
        plt.show()
    plt.close(fig)


def edges_to_dot_strings(g: TopologyGraph) -> Tuple[Set[str], Set[str]]:
    """Для отладки или внешнего Graphviz."""
    nodes = set(g.nodes.keys())
    es = {f'"{a}" -- "{b}"' for a, b in _normalize_undirected_edges(g.edges)}
    return nodes, es
