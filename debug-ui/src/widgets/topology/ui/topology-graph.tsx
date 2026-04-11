import { useMemo, useState } from 'react'
import ReactFlow, { Background, Controls, type Edge, type Node } from 'reactflow'
import 'reactflow/dist/style.css'
import type { Snapshot } from '@/shared/types/debug'

export function TopologyGraph({ snapshot }: { snapshot: Snapshot }) {
  const [selectedPeer, setSelectedPeer] = useState<string | null>(null)
  const topology = snapshot.topology
  const selfId = topology?.self_peer_id ?? snapshot.node?.peer_id ?? 'self'
  const neighbors = topology?.neighbors ?? []

  const nodes = useMemo<Node[]>(() => {
    const center: Node = {
      id: selfId,
      position: { x: 420, y: 220 },
      data: { label: `вы\n${selfId.slice(0, 18)}…` },
      style: { border: '1px solid #22c55e', borderRadius: 12, padding: 8, background: '#052e16', color: '#bbf7d0' },
    }
    const ring = neighbors.map((n, i) => {
      const angle = (2 * Math.PI * i) / Math.max(1, neighbors.length)
      const radius = 220
      const x = 420 + Math.cos(angle) * radius
      const y = 220 + Math.sin(angle) * radius
      return {
        id: n.peer_id,
        position: { x, y },
        data: { label: `${n.peer_id.slice(0, 14)}…\n${n.is_connected ? 'онлайн' : 'известен'}` },
        style: {
          border: `1px solid ${n.is_connected ? '#3b82f6' : '#71717a'}`,
          borderRadius: 12,
          padding: 8,
          background: n.is_connected ? '#172554' : '#18181b',
          color: '#e4e4e7',
          minWidth: 180,
        },
      } as Node
    })
    return [center, ...ring]
  }, [neighbors, selfId])

  const edges = useMemo<Edge[]>(
    () =>
      (topology?.edges ?? []).map((e, i) => ({
        id: `e-${i}-${e.source}-${e.target}`,
        source: e.source,
        target: e.target,
        animated: e.connected,
        style: { stroke: e.connected ? '#3b82f6' : '#52525b', strokeWidth: e.connected ? 2.5 : 1.2 },
      })),
    [topology?.edges],
  )

  const selected = neighbors.find((n) => n.peer_id === selectedPeer) ?? null
  const graphKey = `${selfId}-${neighbors.length}-${edges.length}`

  return (
    <section className="space-y-4">
      <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">Топология</h2>
      <p className="text-sm text-zinc-500 dark:text-zinc-400">
        Вы в центре (зелёный), соседи по кругу. Синий контур — есть активное соединение. Клик по узлу — детали ниже.
      </p>
      <div className="h-[min(460px,55vh)] min-h-[320px] overflow-hidden rounded-lg border border-zinc-200 dark:border-zinc-800">
        <ReactFlow
          key={graphKey}
          nodes={nodes}
          edges={edges}
          fitView
          onNodeClick={(_, node) => {
            if (node.id !== selfId) setSelectedPeer(node.id)
          }}
        >
          <Background />
          <Controls />
        </ReactFlow>
      </div>
      {selected && (
        <div className="grid gap-x-6 gap-y-2 border-t border-zinc-100 pt-4 text-xs sm:grid-cols-[minmax(0,140px)_1fr] dark:border-zinc-800">
          <span className="text-zinc-500">Пир</span>
          <span className="break-all font-mono">{selected.peer_id}</span>
          <span className="text-zinc-500">Соединён</span>
          <span className="tabular-nums">{selected.is_connected ? 'да' : 'нет'}</span>
          <span className="text-zinc-500">Активных связей</span>
          <span className="tabular-nums">{selected.active_connections ?? 0}</span>
          <span className="text-zinc-500">Принимает сессии</span>
          <span className="tabular-nums">{selected.accepts_new_sessions ? 'да' : 'нет'}</span>
          <span className="text-zinc-500">Точка bootstrap</span>
          <span className="tabular-nums">{selected.bootstrap_entry ? 'да' : 'нет'}</span>
          <span className="text-zinc-500">Замеченные адреса</span>
          <span className="break-all font-mono">{(selected.observed_addrs ?? []).join(', ') || '—'}</span>
        </div>
      )}
    </section>
  )
}
