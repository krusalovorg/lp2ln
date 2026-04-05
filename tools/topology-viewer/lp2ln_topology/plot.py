"""Рисунок графа: networkx + matplotlib."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Set, Tuple

import matplotlib.pyplot as plt
import networkx as nx

from .crawl import TopologyGraph

logger = logging.getLogger(__name__)

PosMap = Dict[str, Tuple[float, float]]


def _short(s: str, n: int = 10) -> str:
    if len(s) <= n:
        return s
    return s[: n - 2] + "…"


def topology_to_nx(g: TopologyGraph) -> nx.DiGraph:
    dg = nx.DiGraph()
    for pid, desc in g.nodes.items():
        cap = (desc.get("capabilities") or {}) if isinstance(desc, dict) else {}
        boot = bool(cap.get("bootstrap_entry", False))
        dg.add_node(
            pid,
            label=_short(pid, 12),
            bootstrap=boot,
            addrs=desc.get("observed_addrs") or [],
        )
    for a, b in g.edges:
        if a in dg and b in dg:
            dg.add_edge(a, b)
    return dg


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
    ne = new_edge_set or set()
    seeds = seed_peer_ids or set()

    nodes_list = list(dg.nodes)
    k = 2.0 / max(1, dg.number_of_nodes()) ** 0.5
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
            iterations=max(15, int(layout_iterations)),
        )
    else:
        init_pos: Optional[PosMap] = None
        if prev_pos:
            init_pos = {n: p for n, p in prev_pos.items() if n in dg}
        pos = nx.spring_layout(
            dg,
            seed=seed,
            k=k,
            pos=init_pos,
            iterations=max(15, int(layout_iterations)),
        )

    colors: list[str] = []
    for n in dg.nodes:
        if focus_peer_id and n == focus_peer_id:
            colors.append("#8e44ad")
        elif dg.nodes[n].get("bootstrap"):
            colors.append("#c0392b")
        elif n in seeds:
            colors.append("#f39c12")
        elif n in nn:
            colors.append("#27ae60")
        else:
            colors.append("#2980b9")

    labels: Dict[str, str] = {n: dg.nodes[n]["label"] for n in dg.nodes}

    edge_colors: list[str] = []
    edge_widths: list[float] = []
    for u, v in dg.edges:
        if (u, v) in ne:
            edge_colors.append("#e67e22")
            edge_widths.append(2.2)
        else:
            edge_colors.append("#7f8c8d")
            edge_widths.append(1.0)

    nx.draw_networkx_edges(
        dg,
        pos,
        ax=ax,
        edgelist=list(dg.edges),
        edge_color=edge_colors,
        arrows=True,
        arrowsize=12,
        width=edge_widths,
        alpha=0.75,
        connectionstyle="arc3,rad=0.08",
    )
    nodes_artist = nx.draw_networkx_nodes(dg, pos, ax=ax, node_color=colors, node_size=800, alpha=0.9)
    nx.draw_networkx_labels(dg, pos, labels, ax=ax, font_size=8)
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
    es = {f'"{a}" -> "{b}"' for a, b in g.edges}
    return nodes, es
