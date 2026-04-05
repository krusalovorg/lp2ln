#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple


def percentile(values: List[int], p: float) -> int:
    if not values:
        return 0
    s = sorted(values)
    idx = int((len(s) - 1) * p)
    return s[idx]


def fmt_ratio(x: float) -> str:
    return f"{x:.4f}"


def connected_components(nodes: Set[str], adj: Dict[str, Set[str]]) -> List[int]:
    seen: Set[str] = set()
    sizes: List[int] = []
    for v in nodes:
        if v in seen:
            continue
        q: deque[str] = deque([v])
        seen.add(v)
        size = 0
        while q:
            cur = q.popleft()
            size += 1
            for nxt in adj.get(cur, ()):
                if nxt not in seen:
                    seen.add(nxt)
                    q.append(nxt)
        sizes.append(size)
    sizes.sort(reverse=True)
    return sizes


def main() -> int:
    p = argparse.ArgumentParser(description="Fast analytics for LP2LN topology JSON")
    p.add_argument("--file", default="topo.json", help="Path to topology JSON")
    p.add_argument("--top", type=int, default=12, help="Top hubs to print")
    p.add_argument("--target-min", type=int, default=3, help="Auto-target clamp min")
    p.add_argument("--target-max", type=int, default=6, help="Auto-target clamp max")
    p.add_argument("--headroom", type=int, default=1, help="Allowed peers above target")
    args = p.parse_args()

    path = Path(args.file)
    data = json.loads(path.read_text(encoding="utf-8"))
    nodes_map = data.get("nodes", {})
    edges = data.get("edges", [])
    nodes: Set[str] = set(nodes_map.keys())

    out = Counter()
    inn = Counter()
    directed_edges: Set[Tuple[str, str]] = set()
    undirected_edges: Set[Tuple[str, str]] = set()
    adj_und: Dict[str, Set[str]] = defaultdict(set)

    for e in edges:
        a = e.get("from")
        b = e.get("to")
        if not a or not b:
            continue
        directed_edges.add((a, b))
        out[a] += 1
        inn[b] += 1
        u, v = sorted((a, b))
        undirected_edges.add((u, v))
        adj_und[u].add(v)
        adj_und[v].add(u)
        nodes.add(a)
        nodes.add(b)

    n = len(nodes)
    m_dir = len(directed_edges)
    m_und = len(undirected_edges)

    out_vals = [out.get(x, 0) for x in nodes]
    in_vals = [inn.get(x, 0) for x in nodes]
    und_vals = [len(adj_und.get(x, set())) for x in nodes]

    density_und = (m_und / (n * (n - 1) / 2.0)) if n > 1 else 0.0
    density_dir = (m_dir / (n * (n - 1))) if n > 1 else 0.0
    reciprocity = (
        sum(1 for (a, b) in directed_edges if (b, a) in directed_edges) / m_dir
        if m_dir
        else 0.0
    )

    comps = connected_components(nodes, adj_und)
    giant = comps[0] if comps else 0
    isolated = sum(1 for d in und_vals if d == 0)

    auto_target = max(args.target_min, min(args.target_max, round(math.sqrt(max(1, n)))))
    max_allowed = auto_target + max(0, args.headroom)
    overloaded = sum(1 for d in und_vals if d > max_allowed)
    underlinked = sum(1 for d in und_vals if d < max(1, auto_target - 2))

    print(f"FILE: {path}")
    print(f"NODES: {n}")
    print(f"EDGES directed={m_dir} undirected_unique={m_und}")
    print(f"DENSITY directed={fmt_ratio(density_dir)} undirected={fmt_ratio(density_und)}")
    print(f"COMPONENTS count={len(comps)} giant={giant} isolated={isolated}")
    print(f"RECIPROCITY directed={fmt_ratio(reciprocity)}")
    print(
        "DEGREE out p50/p90/p99/max="
        f"{percentile(out_vals,0.5)}/{percentile(out_vals,0.9)}/{percentile(out_vals,0.99)}/{max(out_vals) if out_vals else 0}"
    )
    print(
        "DEGREE in  p50/p90/p99/max="
        f"{percentile(in_vals,0.5)}/{percentile(in_vals,0.9)}/{percentile(in_vals,0.99)}/{max(in_vals) if in_vals else 0}"
    )
    print(
        "DEGREE und p50/p90/p99/max="
        f"{percentile(und_vals,0.5)}/{percentile(und_vals,0.9)}/{percentile(und_vals,0.99)}/{max(und_vals) if und_vals else 0}"
    )
    print(
        f"AUTO_TARGET target={auto_target} max_allowed={max_allowed} "
        f"overloaded_nodes={overloaded} underlinked_nodes={underlinked}"
    )

    top = max(1, args.top)
    print(f"TOP_OUT ({top}):")
    for pid, v in out.most_common(top):
        print(f"  {v:>3}  {pid}")
    print(f"TOP_IN ({top}):")
    for pid, v in inn.most_common(top):
        print(f"  {v:>3}  {pid}")

    print("ASSESSMENT:")
    if len(comps) > 1 and giant < int(0.95 * n):
        print("  - Graph is fragmented (giant component too small).")
    else:
        print("  - Connectivity is acceptable (giant component dominates).")
    if overloaded > max(3, n // 20):
        print("  - Too many hubs above target; add stronger anti-hub penalties.")
    else:
        print("  - Hub pressure is moderate.")
    if underlinked > n // 2:
        print("  - Many nodes are underlinked; improve discovery and admission fairness.")
    else:
        print("  - Most nodes have reasonable neighborhood size.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

