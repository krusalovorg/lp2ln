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


# Цвета рёбер по протоколу (приоритет выбора одного цвета: quic > udp > tcp > tunnel > relay).
PROTO_EDGE_COLOR: Dict[str, str] = {
    "quic": "#e84393",  # розовый — не путать с фиолетовым «фокус»
    "udp": "#1a5276",  # тёмно-синий — сильнее отличается от бирюзового tcp
    "tcp": "#16a085",
    "tunnel_udp": "#5dade2",
    "tunnel_tcp": "#48c9b0",
    "relay": "#d35400",
    "unknown": "#7f8c8d",
}
PROTO_EDGE_PRIORITY: Tuple[str, ...] = (
    "quic",
    "udp",
    "tcp",
    "tunnel_udp",
    "tunnel_tcp",
    "relay",
    "unknown",
)


def primary_edge_protocol(protos: Set[str]) -> str:
    clean = {p for p in protos if p}
    if not clean:
        return "unknown"
    for p in PROTO_EDGE_PRIORITY:
        if p in clean:
            return p
    return sorted(clean)[0]


def edge_protocol_color(protos: Set[str], *, is_new: bool = False) -> str:
    if is_new:
        return "#e67e22"
    return PROTO_EDGE_COLOR.get(primary_edge_protocol(protos), "#7f8c8d")


def make_topology_legend_handles() -> Tuple[List[Any], List[Any]]:
    """Цветные handles: (узлы, рёбра)."""
    from matplotlib.lines import Line2D
    from matplotlib.patches import Patch

    node_items = [
        ("фокус", "#8e44ad"),
        ("bootstrap", "#c0392b"),
        ("seed", "#f39c12"),
        ("новый", "#27ae60"),
        ("нагрузка↑", "#e74c3c"),
        ("изолят", "#bdc3c7"),
    ]
    edge_items = [
        ("quic (розов.)", PROTO_EDGE_COLOR["quic"]),
        ("udp (синий)", PROTO_EDGE_COLOR["udp"]),
        ("tcp (бирюз.)", PROTO_EDGE_COLOR["tcp"]),
        ("новое ребро", "#e67e22"),
    ]
    nodes = [Patch(facecolor=c, edgecolor="#2c3e50", linewidth=0.6, label=lab) for lab, c in node_items]
    edges = [
        Line2D([0], [0], color=c, lw=3.4, solid_capstyle="round", label=lab) for lab, c in edge_items
    ]
    return nodes, edges


def attach_topology_legend(ax: Any, *, loc: str = "lower right") -> Any:
    """Две легенды: узлы и протоколы рёбер — с реальными цветами."""
    node_h, edge_h = make_topology_legend_handles()
    leg_nodes = ax.legend(
        handles=node_h,
        loc="lower right",
        bbox_to_anchor=(1.0, 0.28),
        fontsize=7,
        framealpha=0.92,
        fancybox=False,
        edgecolor="#95a5a6",
        title="узлы",
        title_fontsize=8,
        borderpad=0.4,
        labelspacing=0.35,
        handlelength=1.2,
    )
    ax.add_artist(leg_nodes)
    leg_edges = ax.legend(
        handles=edge_h,
        loc="lower right",
        fontsize=7,
        framealpha=0.92,
        fancybox=False,
        edgecolor="#95a5a6",
        title="рёбра (протокол)",
        title_fontsize=8,
        borderpad=0.4,
        labelspacing=0.35,
        handlelength=2.0,
    )
    return leg_edges


# LOD: подписи дорогие; рёбра на большом N — тонкие/прозрачные, но видимые.
LOD_LABEL_NODES: int = 40
LOD_EDGE_FAINT_NODES: int = 50
LOD_TINY_NODE_NODES: int = 60


def _seed_missing_on_ring(
    nodes_list: List[str],
    init_pos: PosMap,
    n_nodes: int,
) -> PosMap:
    """Новые узлы — на кольцо вокруг уже известных (или вокруг нуля)."""
    out = dict(init_pos)
    missing = [n for n in nodes_list if n not in out]
    if not missing:
        return out
    if out:
        cx = sum(p[0] for p in out.values()) / float(len(out))
        cy = sum(p[1] for p in out.values()) / float(len(out))
        span = max(
            0.8,
            max(math.hypot(p[0] - cx, p[1] - cy) for p in out.values()),
        )
        r_ring = span * 1.15
    else:
        cx = cy = 0.0
        r_ring = 2.3 + 0.45 * math.sqrt(float(n_nodes))
    for i, n in enumerate(missing):
        ang = 2 * math.pi * float(i) / max(1, len(missing))
        out[n] = (cx + math.cos(ang) * r_ring, cy + math.sin(ang) * r_ring)
    return out


def _place_isolates_on_ring(pos: PosMap, isolates: List[str], core: List[str]) -> PosMap:
    """Изоляты — на внешнее кольцо вокруг ядра (не мешают spring)."""
    out = dict(pos)
    if not isolates:
        return out
    if core:
        pts = [out[n] for n in core if n in out]
        if pts:
            cx = sum(p[0] for p in pts) / float(len(pts))
            cy = sum(p[1] for p in pts) / float(len(pts))
            span = max(1.0, max(math.hypot(p[0] - cx, p[1] - cy) for p in pts))
        else:
            cx = cy = 0.0
            span = 2.0
    else:
        cx = cy = 0.0
        span = 2.0
    r = span * 1.55
    for i, n in enumerate(sorted(isolates)):
        ang = 2 * math.pi * float(i) / max(1, len(isolates))
        out[n] = (cx + math.cos(ang) * r, cy + math.sin(ang) * r)
    return out


def compute_stable_layout(
    dg: nx.Graph,
    *,
    seed: int = 42,
    prev_pos: Optional[PosMap] = None,
    frozen_positions: Optional[PosMap] = None,
    layout_iterations: int = 50,
    force_relayout: bool = False,
) -> PosMap:
    """Layout с разделением ядра (есть рёбра) и изолятов (degree 0).

    Изоляты намеренно на внешнем кольце — это сигнал «ещё не в mesh», а не баг.
    Ядро — spring; live-кадры без изменения состава ядра — 0 итераций.
    """
    nodes_list = list(dg.nodes)
    n_nodes = dg.number_of_nodes()
    if n_nodes == 0:
        return {}

    isolates = [n for n in nodes_list if dg.degree(n) == 0]
    core = [n for n in nodes_list if dg.degree(n) > 0]
    isolate_set = set(isolates)

    if frozen_positions and all(n in frozen_positions for n in dg.nodes) and not force_relayout:
        return {n: frozen_positions[n] for n in dg.nodes}

    base: PosMap = {}
    if frozen_positions:
        base = {n: frozen_positions[n] for n in dg.nodes if n in frozen_positions}
    elif prev_pos:
        base = {n: p for n, p in prev_pos.items() if n in dg}

    # Только изоляты — кольцо, spring не нужен.
    if not core:
        return _place_isolates_on_ring({}, isolates, [])

    sub = dg.subgraph(core).copy()
    n_core = sub.number_of_nodes()
    n_core_edges = sub.number_of_edges()
    density = n_core_edges / float(max(1, n_core))
    k_base = 2.2 / max(1, n_core) ** 0.5
    k = k_base * (1.0 + 0.2 * min(12.0, max(0.0, density - 0.5)))
    full_iters = max(20, min(int(layout_iterations), int(36 + min(60, density * 6.0))))

    core_base = {n: base[n] for n in core if n in base}
    known = len(core_base)
    missing = n_core - known
    coverage = known / float(n_core) if n_core else 1.0

    if not force_relayout and coverage >= 1.0 and missing == 0:
        pos = {n: core_base[n] for n in core}
        return _place_isolates_on_ring(pos, isolates, core)

    init_core = _seed_missing_on_ring(core, core_base, n_core)

    # Новые узлы в ядре — spring БЕЗ fixed, иначе новички навечно на кольце.
    if force_relayout or coverage < 0.5 or missing > max(2, int(0.08 * n_core)):
        iters = full_iters
    elif missing > 0:
        iters = min(full_iters, 22)
    else:
        iters = min(12, full_iters // 2)

    # networkx при N≥~500 тянет scipy sparse; без scipy — падает весь viewer.
    try:
        core_pos = nx.spring_layout(sub, seed=seed, k=k, pos=init_core, iterations=iters)
    except ModuleNotFoundError as e:
        if "scipy" not in str(e).lower() and "scipy" not in repr(e).lower():
            raise
        logger.warning(
            "scipy не установлен — spring_layout недоступен для N=%s; "
            "fallback circular. pip install scipy",
            n_core,
        )
        core_pos = nx.circular_layout(sub, scale=2.3 + 0.35 * math.sqrt(float(n_core)))
        # слегка развести поверх prev, если есть
        for n, p in init_core.items():
            if n in core_pos and n in core_base:
                core_pos[n] = p
    except Exception:
        logger.exception("spring_layout failed; fallback circular (N=%s)", n_core)
        core_pos = nx.circular_layout(sub, scale=2.3 + 0.35 * math.sqrt(float(n_core)))

    return _place_isolates_on_ring(core_pos, isolates, core)


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
    show_labels: Optional[bool] = None,
    show_edges: Optional[bool] = None,
    force_relayout: bool = False,
) -> PosMap:
    """Рисует топологию в переданные axes (для live-обновления).

    Возвращает pos для следующего кадра.

    LOD (если show_* не заданы явно):
      N≥40 — без подписей (в фокусе — с подписями);
      рёбра всегда рисуются (на большом N тоньше/прозрачнее);
      изоляты (degree 0) — серые на внешнем кольце.
    """
    dg = topology_to_nx(g)
    ax.clear()
    if dg.number_of_nodes() == 0:
        note = str(getattr(g, "progress_note", "") or "").strip()
        if note:
            logger.info("Рисунок: пока 0 узлов (%s)", note)
            ax.text(0.5, 0.55, note, ha="center", va="center", fontsize=11, color="#2c3e50")
            ax.text(
                0.5,
                0.42,
                "ждём snapshot с найденных WS…",
                ha="center",
                va="center",
                fontsize=9,
                color="#7f8c8d",
            )
        else:
            logger.warning(
                "Рисунок: 0 узлов — см. логи обхода выше (часто неверный порт, нода не запущена или нет PeersResponse)."
            )
            ax.text(0.5, 0.5, "Нет узлов (проверь адрес и что нода запущена).", ha="center", va="center")
        ax.axis("off")
        ax.set_title(title)
        ax._lp2ln_nodes_artist = None  # type: ignore[attr-defined]
        ax._lp2ln_node_pick_order = []  # type: ignore[attr-defined]
        return {}

    nn = new_node_ids or set()
    ne = _normalize_undirected_edges(new_edge_set or set())
    seeds = seed_peer_ids or set()

    nodes_list = list(dg.nodes)
    n_nodes = dg.number_of_nodes()
    n_edges = dg.number_of_edges()
    isolate_set = {n for n in dg.nodes if dg.degree(n) == 0}
    n_iso = len(isolate_set)

    do_labels = (
        bool(show_labels)
        if show_labels is not None
        else (n_nodes < LOD_LABEL_NODES or bool(focus_peer_id))
    )
    # Рёбра по умолчанию ВСЕГДА (иначе на 100 узлах — бесполезное кольцо точек).
    do_edges = True if show_edges is None else bool(show_edges)

    pos = compute_stable_layout(
        dg,
        seed=seed,
        prev_pos=prev_pos,
        frozen_positions=frozen_positions,
        layout_iterations=layout_iterations,
        force_relayout=force_relayout,
    )

    logger.info(
        "Рисунок: %s узлов (%s изолятов), %s рёбер (labels=%s edges=%s relayout=%s)",
        n_nodes,
        n_iso,
        n_edges,
        do_labels,
        do_edges,
        force_relayout,
    )

    colors: list[str] = []
    for n in dg.nodes:
        nd = dg.nodes[n]
        if focus_peer_id and n == focus_peer_id:
            colors.append("#8e44ad")
        elif n in isolate_set:
            colors.append("#bdc3c7")  # серый = нет сессий
        elif nd.get("bootstrap"):
            colors.append("#c0392b")
        elif n in seeds:
            colors.append("#f39c12")
        elif n in nn:
            colors.append("#27ae60")
        else:
            util = float(nd.get("utilization") or 0.0)
            load = float(nd.get("load") or 0.0)
            colors.append(_load_color(max(util, load)))

    if do_edges and n_edges > 0:
        edge_protos = getattr(g, "edge_protocols", None) or {}
        w_scale = max(0.35, 0.95 - min(0.55, n_edges / 900.0))
        if n_nodes >= LOD_TINY_NODE_NODES:
            w_scale = max(0.28, w_scale * 0.85)
        edge_colors: list[str] = []
        edge_widths: list[float] = []
        for u, v in dg.edges:
            edge_key = (u, v) if u <= v else (v, u)
            is_new = edge_key in ne
            protos = edge_protos.get(edge_key) or set()
            edge_colors.append(edge_protocol_color(protos, is_new=is_new))
            # Мультипротокол / новое ребро — чуть толще.
            multi = len({p for p in protos if p}) > 1
            edge_widths.append(max(1.4, (2.2 if is_new or multi else 1.0) * w_scale))
        if n_nodes >= LOD_EDGE_FAINT_NODES:
            edge_alpha = 0.42
        elif n_edges <= 3 * max(1, n_nodes):
            edge_alpha = 0.72
        else:
            edge_alpha = 0.32
        nx.draw_networkx_edges(
            dg,
            pos,
            ax=ax,
            edgelist=list(dg.edges),
            edge_color=edge_colors,
            width=edge_widths,
            alpha=edge_alpha,
        )

    if n_nodes >= LOD_TINY_NODE_NODES:
        node_size = int(max(55.0, 260.0 - 1.5 * float(n_nodes)))
    elif n_nodes >= LOD_LABEL_NODES:
        node_size = int(max(110.0, 520.0 - 6.0 * float(n_nodes)))
    else:
        node_size = int(max(320.0, 820.0 - 11.5 * float(n_nodes)))
    # Изоляты чуть меньше ядра.
    sizes = [max(28, int(node_size * 0.55)) if n in isolate_set else node_size for n in dg.nodes]
    nodes_artist = nx.draw_networkx_nodes(
        dg, pos, ax=ax, node_color=colors, node_size=sizes, alpha=0.92
    )
    if do_labels:
        labels: Dict[str, str] = {n: dg.nodes[n]["label"] for n in dg.nodes}
        font_size = 8 if n_nodes < LOD_LABEL_NODES else 7
        nx.draw_networkx_labels(dg, pos, labels, ax=ax, font_size=font_size, font_weight="bold")
    ax.set_title(title)
    ax.axis("off")
    attach_topology_legend(ax, loc="lower right")
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
