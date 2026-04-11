import { useCallback, useMemo, useRef, useState } from 'react'
import type {
  CommandResult,
  DbTables,
  FileLookupPayload,
  HelloPayload,
  PeerRowsPayload,
  Snapshot,
} from '@/shared/types/debug'

type TargetData = {
  connected: boolean
  snapshot: Snapshot
  events: string[]
  dbTables: DbTables
  lastCommandResult: CommandResult | null
  hello: HelloPayload | null
  peerRankings: Array<Record<string, unknown>>
  peerRollup: Array<Record<string, unknown>>
  fileLookup: FileLookupPayload | null
}

type Target = {
  id: string
  url: string
  label: string
  nodeAddr: string
}

const emptyTargetData = (): TargetData => ({
  connected: false,
  snapshot: {},
  events: [],
  dbTables: {},
  lastCommandResult: null,
  hello: null,
  peerRankings: [],
  peerRollup: [],
  fileLookup: null,
})

export function useDebugSocket(initialUrl = 'ws://127.0.0.1:9090') {
  const [targets, setTargets] = useState<Target[]>([
    { id: 'primary', url: initialUrl, label: 'Node 1', nodeAddr: '127.0.0.1:8080' },
  ])
  const [activeTargetId, setActiveTargetId] = useState('primary')
  const [dataByTarget, setDataByTarget] = useState<Record<string, TargetData>>({
    primary: emptyTargetData(),
  })
  const socketsRef = useRef<Record<string, WebSocket>>({})

  const setTargetData = (targetId: string, patch: Partial<TargetData>) => {
    setDataByTarget((prev) => ({
      ...prev,
      [targetId]: {
        ...(prev[targetId] ?? emptyTargetData()),
        ...patch,
      },
    }))
  }

  const pushEvent = (targetId: string, line: string) => {
    setDataByTarget((prev) => ({
      ...prev,
      [targetId]: {
        ...(prev[targetId] ?? emptyTargetData()),
        events: [line, ...((prev[targetId]?.events ?? []).slice(0, 49))],
      },
    }))
  }

  const activeTarget = targets.find((t) => t.id === activeTargetId) ?? targets[0]
  const activeData = dataByTarget[activeTarget?.id ?? ''] ?? emptyTargetData()
  const connectedTargetsCount = useMemo(
    () => targets.filter((t) => dataByTarget[t.id]?.connected).length,
    [dataByTarget, targets],
  )
  const anyConnected = connectedTargetsCount > 0

  const connectTarget = (targetId: string) => {
    const target = targets.find((t) => t.id === targetId)
    if (!target) return
    socketsRef.current[targetId]?.close()
    const ws = new WebSocket(target.url)
    socketsRef.current[targetId] = ws
    ws.onopen = () => setTargetData(targetId, { connected: true })
    ws.onclose = () => setTargetData(targetId, { connected: false })
    ws.onmessage = (evt) => {
      try {
        const payload = JSON.parse(evt.data as string) as Record<string, unknown>
        const eventType = String(payload.event ?? 'unknown')
        if (eventType === 'snapshot') setTargetData(targetId, { snapshot: payload as Snapshot })
        if (eventType === 'db_tables') setTargetData(targetId, { dbTables: (payload.tables ?? {}) as DbTables })
        if (eventType === 'command_result') setTargetData(targetId, { lastCommandResult: payload as CommandResult })
        if (eventType === 'hello') setTargetData(targetId, { hello: payload as HelloPayload })
        if (eventType === 'peer_rankings') {
          setTargetData(targetId, {
            peerRankings: ((payload as PeerRowsPayload).rows ?? []) as Array<Record<string, unknown>>,
          })
        }
        if (eventType === 'peer_rollup') {
          setTargetData(targetId, {
            peerRollup: ((payload as PeerRowsPayload).rows ?? []) as Array<Record<string, unknown>>,
          })
        }
        if (eventType === 'file_lookup') setTargetData(targetId, { fileLookup: payload as FileLookupPayload })
        pushEvent(targetId, JSON.stringify(payload, null, 2))
      } catch {
        pushEvent(targetId, String(evt.data))
      }
    }
  }

  const disconnectTarget = (targetId: string) => {
    socketsRef.current[targetId]?.close()
    delete socketsRef.current[targetId]
  }

  const requestDbTables = () => {
    if (!activeTarget) return
    const ws = socketsRef.current[activeTarget.id]
    if (!ws || ws.readyState !== WebSocket.OPEN) return
    ws.send(JSON.stringify({ cmd: 'get_db_tables' }))
  }

  const sendCommand = (payload: Record<string, unknown>) => {
    if (!activeTarget) return false
    const ws = socketsRef.current[activeTarget.id]
    if (!ws || ws.readyState !== WebSocket.OPEN) return false
    ws.send(JSON.stringify(payload))
    return true
  }

  const clearLastCommandResult = useCallback(() => {
    setDataByTarget((prev) => {
      const cur = prev[activeTargetId]
      if (!cur) return prev
      return { ...prev, [activeTargetId]: { ...cur, lastCommandResult: null } }
    })
  }, [activeTargetId])

  const addTarget = (url: string) => {
    const id = `target-${Date.now()}-${Math.round(Math.random() * 9999)}`
    setTargets((prev) => [...prev, { id, url, label: `Node ${prev.length + 1}`, nodeAddr: '127.0.0.1:8080' }])
    setDataByTarget((prev) => ({ ...prev, [id]: emptyTargetData() }))
    setActiveTargetId(id)
    return id
  }

  const removeTarget = (targetId: string) => {
    disconnectTarget(targetId)
    setTargets((prev) => prev.filter((t) => t.id !== targetId))
    setDataByTarget((prev) => {
      const next = { ...prev }
      delete next[targetId]
      return next
    })
    setActiveTargetId((prev) => (prev === targetId ? 'primary' : prev))
  }

  const updateTarget = (targetId: string, patch: Partial<Target>) => {
    setTargets((prev) => prev.map((t) => (t.id === targetId ? { ...t, ...patch } : t)))
  }

  const connect = () => activeTarget && connectTarget(activeTarget.id)
  const disconnect = () => activeTarget && disconnectTarget(activeTarget.id)
  const connectAll = () => targets.forEach((t) => connectTarget(t.id))
  const disconnectAll = () => targets.forEach((t) => disconnectTarget(t.id))

  const scanDebugRange = async (host: string, start: number, end: number) => {
    const found: string[] = []
    for (let port = start; port <= end; port += 1) {
      const url = `ws://${host}:${port}`
      const ok = await new Promise<boolean>((resolve) => {
        let settled = false
        const ws = new WebSocket(url)
        const timer = window.setTimeout(() => {
          if (!settled) {
            settled = true
            try { ws.close() } catch {}
            resolve(false)
          }
        }, 1000)
        ws.onopen = () => {
          if (!settled) {
            settled = true
            window.clearTimeout(timer)
            try { ws.close() } catch {}
            resolve(true)
          }
        }
        ws.onerror = () => {
          if (!settled) {
            settled = true
            window.clearTimeout(timer)
            resolve(false)
          }
        }
      })
      if (ok) found.push(url)
    }
    found.forEach((url) => {
      if (!targets.some((t) => t.url === url)) addTarget(url)
    })
    return found
  }

  const totalSessions = useMemo(
    () => (activeData.snapshot.sessions_by_protocol ?? []).reduce((acc, r) => acc + (r.sessions ?? 0), 0),
    [activeData.snapshot.sessions_by_protocol],
  )

  return {
    targets,
    activeTargetId,
    setActiveTargetId,
    activeTarget,
    connectedTargetsCount,
    anyConnected,
    isTargetConnected: (targetId: string) => Boolean(dataByTarget[targetId]?.connected),
    addTarget,
    removeTarget,
    updateTarget,
    connectAll,
    disconnectAll,
    connectTarget,
    disconnectTarget,
    scanDebugRange,
    url: activeTarget?.url ?? '',
    setUrl: (v: string) => activeTarget && updateTarget(activeTarget.id, { url: v }),
    connected: activeData.connected,
    snapshot: activeData.snapshot,
    events: activeData.events,
    dbTables: activeData.dbTables,
    hello: activeData.hello,
    peerRankings: activeData.peerRankings,
    peerRollup: activeData.peerRollup,
    fileLookup: activeData.fileLookup,
    lastCommandResult: activeData.lastCommandResult,
    clearLastCommandResult,
    connect,
    disconnect,
    requestDbTables,
    sendCommand,
    totalSessions,
  }
}
