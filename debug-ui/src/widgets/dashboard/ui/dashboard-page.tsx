import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import {
  Database,
  LayoutDashboard,
  Moon,
  Network,
  Package,
  PlugZap,
  SlidersHorizontal,
  Sun,
  Terminal,
  Workflow,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { useDebugSocket } from '@/features/debug-connection/model/use-debug-socket'
import { useTheme } from '@/features/theme/model/use-theme'
import { cn } from '@/lib/utils'
import { formatBytes } from '@/shared/lib/format'
import { Metric } from './db-table'
import { DatabaseSection } from './database-section'
import { SessionsSection } from './sessions-section'
import { OperationsSection } from './operations-section'
import { NodeConfigSection } from './node-config-section'
import { PacketBuilderSection } from '@/widgets/packet-builder'
import { TopologyGraph } from '@/widgets/topology/ui/topology-graph'
import { useDebugToastStore } from '@/widgets/dashboard/model/debug-toast-store'
import { useDashboardStore, type DashboardPageKey } from '@/widgets/dashboard/model/use-dashboard-store'
import { DebugToastHost } from '@/widgets/dashboard/ui/debug-toast-host'

const SCORE_WEIGHT_LABELS: Record<string, string> = {
  w_uptime: 'Аптайм',
  w_success: 'Успех',
  w_bandwidth: 'Канал',
  w_relay: 'Релей',
  w_nat: 'NAT',
  w_trust: 'Доверие',
  w_geo: 'Гео',
  w_load: 'Нагрузка',
  w_latency: 'Задержка',
  latency_norm_ms: 'Норма задержки (мс)',
}

const PAGE_META: Record<
  DashboardPageKey,
  { label: string; icon: ReactNode }
> = {
  connections: { label: 'Подключения', icon: <PlugZap className="h-4 w-4 shrink-0 opacity-80" /> },
  overview: { label: 'Обзор', icon: <LayoutDashboard className="h-4 w-4 shrink-0 opacity-80" /> },
  network: { label: 'Сеть', icon: <Network className="h-4 w-4 shrink-0 opacity-80" /> },
  sessions: { label: 'Сессии', icon: <Workflow className="h-4 w-4 shrink-0 opacity-80" /> },
  packets: { label: 'Пакеты (отладка)', icon: <Package className="h-4 w-4 shrink-0 opacity-80" /> },
  database: { label: 'Локальная БД', icon: <Database className="h-4 w-4 shrink-0 opacity-80" /> },
  operations: { label: 'Управление сетью', icon: <Terminal className="h-4 w-4 shrink-0 opacity-80" /> },
  node_config: { label: 'Политика и рейтинги', icon: <SlidersHorizontal className="h-4 w-4 shrink-0 opacity-80" /> },
}

const NAV_ORDER: DashboardPageKey[] = [
  'connections',
  'overview',
  'network',
  'sessions',
  'packets',
  'database',
  'operations',
  'node_config',
]

export function DashboardPage() {
  const { theme, toggleTheme } = useTheme()
  const {
    targets,
    activeTargetId,
    setActiveTargetId,
    connectedTargetsCount,
    anyConnected,
    isTargetConnected,
    addTarget,
    removeTarget,
    updateTarget,
    connectAll,
    disconnectAll,
    connectTarget,
    disconnectTarget,
    scanDebugRange,
    url,
    setUrl,
    connected,
    snapshot,
    hello,
    dbTables,
    peerRankings,
    peerRollup,
    fileLookup,
    lastCommandResult,
    clearLastCommandResult,
    connect,
    disconnect,
    requestDbTables,
    sendCommand: sendWsCommand,
    totalSessions,
  } = useDebugSocket()

  const pushToast = useDebugToastStore((s) => s.push)

  const sendCommand = useCallback(
    (payload: Record<string, unknown>) => {
      const ok = sendWsCommand(payload)
      if (!ok) pushToast('Нет связи с нодой', 'error')
      return ok
    },
    [pushToast, sendWsCommand],
  )

  const lastResultTsRef = useRef<number | undefined>(undefined)
  useEffect(() => {
    const r = lastCommandResult
    const ts = r?.ts_ms
    if (ts === undefined || ts === lastResultTsRef.current) return
    lastResultTsRef.current = ts
    const cmd = String(r?.cmd ?? '')
    if (cmd === 'refresh_snapshot') return
    if (r?.ok === false) {
      pushToast(`${cmd}: ${String(r.error ?? 'ошибка')}`, 'error')
    }
  }, [lastCommandResult, pushToast])

  const {
    view,
    setView,
    activeTable,
    setActiveTable,
    showAllTables,
    setShowAllTables,
    connectTransport,
    setConnectTransport,
    connectAddr,
    setConnectAddr,
    disconnectPeerId,
    setDisconnectPeerId,
    rawCommand,
    setRawCommand,
    knownPeerId,
    setKnownPeerId,
    knownPeerTransport,
    setKnownPeerTransport,
    knownPeerAddr,
    setKnownPeerAddr,
    batchConnectTransport,
    setBatchConnectTransport,
    batchConnectAddrs,
    setBatchConnectAddrs,
    batchDisconnectPeers,
    setBatchDisconnectPeers,
    fileHashQuery,
    setFileHashQuery,
    sessionQuery,
    setSessionQuery,
    sessionProtocolFilter,
    setSessionProtocolFilter,
  } = useDashboardStore()

  const storageRows = useMemo(() => dbTables.storage_files ?? [], [dbTables.storage_files])
  const descriptorRows = useMemo(() => dbTables.peer_descriptors ?? [], [dbTables.peer_descriptors])
  const scoreRows = useMemo(() => dbTables.peer_scores ?? [], [dbTables.peer_scores])

  useEffect(() => {
    if (showAllTables) return
    if (activeTable === 'storage_files' && storageRows.length === 0) {
      if (descriptorRows.length > 0) {
        setActiveTable('peer_descriptors')
        return
      }
      if (scoreRows.length > 0) {
        setActiveTable('peer_scores')
      }
    }
  }, [activeTable, descriptorRows.length, scoreRows.length, setActiveTable, showAllTables, storageRows.length])

  const activeRows = useMemo(() => {
    if (activeTable === 'storage_files') return storageRows
    if (activeTable === 'peer_descriptors') return descriptorRows
    return scoreRows
  }, [activeTable, descriptorRows, scoreRows, storageRows])

  const sessionRows = snapshot.sessions ?? []
  const sessionRowsFiltered = sessionRows.filter((s) => {
    const byProtocol = sessionProtocolFilter === 'all' || s.protocol === sessionProtocolFilter
    const q = sessionQuery.trim().toLowerCase()
    const byQuery =
      q.length === 0 ||
      s.session_id.toLowerCase().includes(q) ||
      (s.peer_id ?? '').toLowerCase().includes(q)
    return byProtocol && byQuery
  })
  const protocolOptions = Array.from(new Set(sessionRows.map((s) => s.protocol))).sort()
  const availableCommands = hello?.commands ?? []
  const ownPeerId = snapshot.node?.peer_id ?? hello?.peer_id ?? ''
  const [newTargetUrl, setNewTargetUrl] = useState('ws://127.0.0.1:9090')
  const [scanHost, setScanHost] = useState('127.0.0.1')
  const [scanStart, setScanStart] = useState('9090')
  const [scanEnd, setScanEnd] = useState('9100')

  useEffect(() => {
    const raw = window.location.hash.replace('#', '')
    if (
      (
        [
          'connections',
          'overview',
          'network',
          'sessions',
          'packets',
          'database',
          'operations',
          'node_config',
        ] as const
      ).includes(raw as DashboardPageKey)
    ) {
      setView(raw as DashboardPageKey)
    }
  }, [setView])

  useEffect(() => {
    window.location.hash = view
  }, [view])

  useEffect(() => {
    if (!connected) return
    sendWsCommand({ cmd: 'get_peer_rankings' })
    sendWsCommand({ cmd: 'get_peer_rollup' })
  }, [connected, sendWsCommand])

  useEffect(() => {
    if (!connected) return
    sendWsCommand({ cmd: 'refresh_snapshot' })
    if (view === 'database') {
      requestDbTables()
    }
  }, [connected, view, requestDbTables, sendWsCommand])

  const pageTitle = PAGE_META[view].label

  return (
    <div className="flex h-screen overflow-hidden bg-white text-zinc-900 dark:bg-zinc-950 dark:text-zinc-100">
      <aside className="flex w-[260px] shrink-0 flex-col border-r border-slate-800 bg-slate-900 text-slate-100">
        <div className="border-b border-slate-800 px-4 py-4">
          <div className="text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-500">Debug UI</div>
          <div className="mt-1 text-lg font-semibold tracking-tight text-white">LP2LN</div>
        </div>

        <nav className="flex-1 space-y-0.5 overflow-y-auto px-2 py-3">
          {NAV_ORDER.map((key) => {
            const disabled = !anyConnected && key !== 'connections'
            const meta = PAGE_META[key]
            const active = view === key
            return (
              <button
                key={key}
                type="button"
                disabled={disabled}
                onClick={() => setView(key)}
                className={cn(
                  'flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left text-sm font-medium transition-colors',
                  active
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-300 hover:bg-slate-800/80 hover:text-white',
                  disabled && 'pointer-events-none opacity-40',
                )}
              >
                {meta.icon}
                <span>{meta.label}</span>
              </button>
            )
          })}
        </nav>

        <div className="border-t border-slate-800 px-3 py-3">
          <div className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-slate-500">Цели отладки</div>
          <div className="max-h-[200px] space-y-1 overflow-y-auto">
            {targets.map((t) => {
              const on = isTargetConnected(t.id)
              const active = t.id === activeTargetId
              return (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => setActiveTargetId(t.id)}
                  className={cn(
                    'flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-xs transition-colors',
                    active ? 'bg-slate-800 text-white' : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200',
                  )}
                >
                  <span
                    className={cn('h-1.5 w-1.5 shrink-0 rounded-full', on ? 'bg-emerald-400' : 'bg-slate-600')}
                    aria-hidden
                  />
                  <span className="min-w-0 flex-1 truncate font-medium">{t.label}</span>
                </button>
              )
            })}
          </div>
        </div>
      </aside>

      <div className="flex min-h-0 min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center justify-between gap-4 border-b border-zinc-200 bg-white px-6 dark:border-zinc-800 dark:bg-zinc-950">
          <h1 className="text-base font-semibold tracking-tight">{pageTitle}</h1>
          <div className="flex flex-wrap items-center justify-end gap-2">
            <span
              className={cn(
                'h-2 w-2 shrink-0 rounded-full',
                connected ? 'bg-emerald-500' : 'bg-amber-500',
              )}
              title={connected ? 'WebSocket к активной ноде подключён' : 'Нет подключения к debug WebSocket'}
              role="img"
              aria-label={connected ? 'WebSocket подключён' : 'WebSocket не подключён'}
            />
            <span
              className="text-xs tabular-nums text-zinc-500 dark:text-zinc-400"
              title="Сколько целей отладки сейчас в сети по WebSocket"
            >
              WS: {connectedTargetsCount}/{targets.length}
            </span>
            {ownPeerId ? (
              <code
                className="hidden max-w-[200px] truncate rounded bg-zinc-100 px-2 py-0.5 text-[11px] text-zinc-700 dark:bg-zinc-900 dark:text-zinc-300 sm:inline"
                title="Peer ID активной ноды"
              >
                {ownPeerId}
              </code>
            ) : null}
            <Button
              size="sm"
              variant="secondary"
              className="h-8"
              disabled={!connected}
              title="Запросить свежий снимок состояния ноды"
              onClick={() => sendWsCommand({ cmd: 'refresh_snapshot' })}
            >
              Обновить снимок
            </Button>
            <Button
              variant="secondary"
              size="sm"
              className="h-8 px-2"
              onClick={toggleTheme}
              title={theme === 'dark' ? 'Переключить на светлую тему' : 'Переключить на тёмную тему'}
            >
              {theme === 'dark' ? <Moon className="h-4 w-4" /> : <Sun className="h-4 w-4" />}
            </Button>
          </div>
        </header>

        <main className="min-h-0 min-w-0 flex-1 overflow-y-auto">
          <div className="mx-auto max-w-6xl px-6 py-8 pb-6">
            {view === 'connections' && (
              <section className="mb-10 space-y-4 border-b border-zinc-100 pb-10 dark:border-zinc-800">
                <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">Одна нода</h2>
                <p className="text-sm text-zinc-500 dark:text-zinc-400">
                  Адрес debug WebSocket (указан в конфиге ноды). После подключения станут доступны остальные разделы.
                </p>
                <div className="flex flex-col gap-2 sm:flex-row sm:items-end">
                  <div className="min-w-0 flex-1">
                    <label htmlFor="dash-primary-ws" className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-zinc-500">
                      Debug WebSocket
                    </label>
                    <Input
                      id="dash-primary-ws"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      placeholder="ws://127.0.0.1:9090"
                      autoComplete="off"
                    />
                  </div>
                  <div className="flex shrink-0 gap-2">
                    <Button size="sm" onClick={connect}>
                      Подключить
                    </Button>
                    <Button size="sm" variant="secondary" onClick={disconnect} title="Разорвать WebSocket">
                      Отключить
                    </Button>
                  </div>
                </div>
              </section>
            )}

            {view === 'connections' && (
              <section className="mb-10 space-y-4 border-b border-zinc-100 pb-10 dark:border-zinc-800">
                <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">Несколько нод</h2>
                <p className="text-sm text-zinc-500 dark:text-zinc-400">
                  Список слева внизу переключает активную цель. Поле «публичный адрес» — подсказка для приложения, не URL WebSocket.
                </p>
                <div className="flex flex-wrap items-end gap-2">
                  <div>
                    <label htmlFor="dash-new-target-ws" className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-zinc-500">
                      Новый WebSocket
                    </label>
                    <Input
                      id="dash-new-target-ws"
                      className="max-w-xs"
                      value={newTargetUrl}
                      onChange={(e) => setNewTargetUrl(e.target.value)}
                      placeholder="ws://хост:порт"
                    />
                  </div>
                  <Button size="sm" onClick={() => addTarget(newTargetUrl)} title="Добавить цель в список слева">
                    Добавить ноду
                  </Button>
                  <Button size="sm" variant="secondary" onClick={connectAll} title="Подключить WebSocket ко всем целям">
                    Подключить все
                  </Button>
                  <Button size="sm" variant="secondary" onClick={disconnectAll} title="Отключить WebSocket у всех целей">
                    Отключить все
                  </Button>
                </div>
                <div className="flex flex-wrap items-end gap-2">
                  <div>
                    <label htmlFor="dash-scan-host" className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-zinc-500">
                      Хост
                    </label>
                    <Input id="dash-scan-host" className="max-w-[140px]" value={scanHost} onChange={(e) => setScanHost(e.target.value)} />
                  </div>
                  <div>
                    <label htmlFor="dash-scan-start" className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-zinc-500">
                      Порт с
                    </label>
                    <Input id="dash-scan-start" className="w-24" value={scanStart} onChange={(e) => setScanStart(e.target.value)} inputMode="numeric" />
                  </div>
                  <div>
                    <label htmlFor="dash-scan-end" className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-zinc-500">
                      по
                    </label>
                    <Input id="dash-scan-end" className="w-24" value={scanEnd} onChange={(e) => setScanEnd(e.target.value)} inputMode="numeric" />
                  </div>
                  <Button
                    size="sm"
                    variant="secondary"
                    title="Проверить диапазон портов на наличие debug WebSocket"
                    onClick={async () => {
                      const s = Number(scanStart)
                      const e = Number(scanEnd)
                      if (Number.isFinite(s) && Number.isFinite(e) && s > 0 && e >= s) {
                        await scanDebugRange(scanHost, s, e)
                      }
                    }}
                  >
                    Сканировать порты
                  </Button>
                </div>
                <div className="space-y-3">
                  {targets.map((t) => (
                    <div
                      key={t.id}
                      className={cn(
                        'grid gap-2 border-l-2 py-2 pl-3 transition-colors sm:grid-cols-[auto_1fr_1fr_auto] sm:items-center',
                        t.id === activeTargetId ? 'border-blue-600' : 'border-transparent',
                      )}
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <Button size="sm" variant={t.id === activeTargetId ? 'default' : 'secondary'} onClick={() => setActiveTargetId(t.id)}>
                          {t.label}
                        </Button>
                        <Badge variant={isTargetConnected(t.id) ? 'success' : 'warn'} className="max-w-full whitespace-normal text-[10px] leading-tight">
                          {isTargetConnected(t.id) ? 'Подключено' : 'Нет связи'}
                        </Badge>
                      </div>
                      <Input
                        value={t.url}
                        onChange={(e) => updateTarget(t.id, { url: e.target.value })}
                        placeholder="ws://…"
                        title="URL debug WebSocket"
                        aria-label={`WebSocket для ${t.label}`}
                      />
                      <Input
                        value={t.nodeAddr}
                        onChange={(e) => updateTarget(t.id, { nodeAddr: e.target.value })}
                        placeholder="Публичный адрес ноды (не WebSocket)"
                        title="Для подсказок UI и отчётов, не для подключения отладчика"
                        aria-label={`Публичный адрес для ${t.label}`}
                      />
                      <div className="flex flex-wrap gap-1">
                        <Button size="sm" onClick={() => connectTarget(t.id)} title="Подключиться по WebSocket">
                          Подключить
                        </Button>
                        <Button
                          size="sm"
                          variant="secondary"
                          onClick={() => disconnectTarget(t.id)}
                          title="Отключить WebSocket"
                          aria-label="Отключить WebSocket"
                        >
                          ×
                        </Button>
                        {t.id !== 'primary' && (
                          <Button size="sm" variant="secondary" onClick={() => removeTarget(t.id)}>
                            Удалить
                          </Button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </section>
            )}

            {!anyConnected && view !== 'connections' && (
              <div className="py-16 text-center text-sm text-zinc-500">
                <p className="mb-4">Сначала подключите debug WebSocket хотя бы к одной ноде.</p>
                <Button size="sm" onClick={() => setView('connections')}>
                  К подключениям
                </Button>
              </div>
            )}

            {anyConnected && view === 'overview' && (
              <>
                <p className="mb-8 text-sm text-zinc-500 dark:text-zinc-400">
                  Данные из последнего снимка активной ноды. Актуализировать — кнопка «Обновить снимок» в шапке.
                </p>
                <section className="mb-10 grid grid-cols-2 gap-4 border-b border-zinc-100 pb-10 sm:grid-cols-4 dark:border-zinc-800">
                  <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/50 p-4 dark:border-zinc-800 dark:bg-zinc-900/40">
                    <div className="text-[11px] font-medium uppercase tracking-wide text-zinc-400">ID этой ноды</div>
                    <div className="mt-1 truncate font-mono text-sm">{snapshot.node?.peer_id ?? '—'}</div>
                  </div>
                  <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/50 p-4 dark:border-zinc-800 dark:bg-zinc-900/40">
                    <div className="text-[11px] font-medium uppercase tracking-wide text-zinc-400">Пиры (акт. / изв.)</div>
                    <div className="mt-1 text-2xl font-semibold tabular-nums">
                      {snapshot.node?.active_peers ?? 0}
                      <span className="text-base font-normal text-zinc-400"> / {snapshot.node?.known_peers ?? 0}</span>
                    </div>
                  </div>
                  <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/50 p-4 dark:border-zinc-800 dark:bg-zinc-900/40">
                    <div className="text-[11px] font-medium uppercase tracking-wide text-zinc-400">Сессии</div>
                    <div className="mt-1 text-2xl font-semibold tabular-nums">{totalSessions}</div>
                  </div>
                  <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/50 p-4 dark:border-zinc-800 dark:bg-zinc-900/40">
                    <div className="text-[11px] font-medium uppercase tracking-wide text-zinc-400">Размер БД на диске</div>
                    <div className="mt-1 text-2xl font-semibold tabular-nums">{formatBytes(snapshot.db?.db_file_bytes ?? 0)}</div>
                  </div>
                </section>

                <section className="mb-10 border-b border-zinc-100 pb-10 dark:border-zinc-800">
                  <h2 className="mb-3 text-xs font-semibold uppercase tracking-wider text-zinc-400">Трафик по протоколам</h2>
                  <div className="hidden gap-4 border-b border-zinc-200 pb-2 text-[10px] font-medium uppercase tracking-wider text-zinc-400 sm:grid sm:grid-cols-4 dark:border-zinc-700">
                    <div>Протокол</div>
                    <div>Сессии</div>
                    <div>Пакеты (отпр. / получ.)</div>
                    <div>Объём (отпр. / получ.)</div>
                  </div>
                  <div className="divide-y divide-zinc-100 dark:divide-zinc-800">
                    {(snapshot.sessions_by_protocol ?? []).map((row) => (
                      <div
                        key={row.kind}
                        className="grid grid-cols-2 gap-4 py-3 text-sm sm:grid-cols-4"
                      >
                        <div className="font-medium">{row.kind}</div>
                        <div className="tabular-nums text-zinc-600 dark:text-zinc-400">{row.sessions}</div>
                        <div className="tabular-nums text-zinc-600 dark:text-zinc-400">
                          {row.packets_sent} / {row.packets_received}
                        </div>
                        <div className="tabular-nums text-zinc-600 dark:text-zinc-400">
                          {formatBytes(row.bytes_sent)} / {formatBytes(row.bytes_received)}
                        </div>
                      </div>
                    ))}
                  </div>
                </section>

                <section className="pb-4">
                  <h2 className="mb-1 text-xs font-semibold uppercase tracking-wider text-zinc-400">База данных</h2>
                  <p className="mb-4 text-xs text-zinc-500">Путь к файлу и занятое место</p>
                  <div className="grid grid-cols-2 gap-x-8 gap-y-4 sm:grid-cols-3">
                    <Metric title="Путь к файлу БД" value={snapshot.db?.path ?? '—'} />
                    <Metric title="Размер файла БД" value={formatBytes(snapshot.db?.db_file_bytes ?? 0)} />
                    <Metric title="Blobs на диске" value={formatBytes(snapshot.db?.blobs_bytes ?? 0)} />
                    <Metric title="Файлов" value={String(snapshot.db?.stored_files_count ?? 0)} />
                    <Metric title="Дескрипторы" value={String(snapshot.db?.cached_descriptors_count ?? 0)} />
                    <Metric title="Оценки пиров" value={String(snapshot.db?.cached_peer_scores_count ?? 0)} />
                  </div>
                </section>
              </>
            )}

            {anyConnected && view === 'database' && (
              <DatabaseSection
                ownPeerId={ownPeerId}
                activeTable={activeTable}
                setActiveTable={setActiveTable}
                showAllTables={showAllTables}
                setShowAllTables={setShowAllTables}
                requestDbTables={requestDbTables}
                storageRows={storageRows}
                descriptorRows={descriptorRows}
                scoreRows={scoreRows}
                activeRows={activeRows}
              />
            )}

            {anyConnected && view === 'network' && <TopologyGraph snapshot={snapshot} />}

            {anyConnected && view === 'sessions' && (
              <SessionsSection
                snapshot={snapshot}
                ownPeerId={ownPeerId}
                sessionRows={sessionRows}
                sessionRowsFiltered={sessionRowsFiltered}
                sessionProtocolFilter={sessionProtocolFilter}
                setSessionProtocolFilter={setSessionProtocolFilter}
                sessionQuery={sessionQuery}
                setSessionQuery={setSessionQuery}
                protocolOptions={protocolOptions}
                connectTransport={connectTransport}
                setConnectTransport={setConnectTransport}
                connectAddr={connectAddr}
                setConnectAddr={setConnectAddr}
                sendCommand={sendCommand}
              />
            )}

            {anyConnected && view === 'packets' && (
              <PacketBuilderSection
                snapshot={snapshot}
                sendCommand={sendCommand}
                lastCommandResult={lastCommandResult}
                clearLastCommandResult={clearLastCommandResult}
              />
            )}

            {anyConnected && view === 'operations' && (
              <OperationsSection
                disconnectPeerId={disconnectPeerId}
                setDisconnectPeerId={setDisconnectPeerId}
                rawCommand={rawCommand}
                setRawCommand={setRawCommand}
                knownPeerId={knownPeerId}
                setKnownPeerId={setKnownPeerId}
                knownPeerTransport={knownPeerTransport}
                setKnownPeerTransport={setKnownPeerTransport}
                knownPeerAddr={knownPeerAddr}
                setKnownPeerAddr={setKnownPeerAddr}
                batchConnectTransport={batchConnectTransport}
                setBatchConnectTransport={setBatchConnectTransport}
                batchConnectAddrs={batchConnectAddrs}
                setBatchConnectAddrs={setBatchConnectAddrs}
                batchDisconnectPeers={batchDisconnectPeers}
                setBatchDisconnectPeers={setBatchDisconnectPeers}
                availableCommands={availableCommands}
                sendCommand={sendCommand}
              />
            )}

            {anyConnected && view === 'node_config' && (
              <NodeConfigSection
                ownPeerId={ownPeerId}
                snapshot={snapshot}
                scoreWeightLabels={SCORE_WEIGHT_LABELS}
                peerRankings={peerRankings}
                peerRollup={peerRollup}
                fileLookup={fileLookup}
                fileHashQuery={fileHashQuery}
                setFileHashQuery={setFileHashQuery}
                sendCommand={sendCommand}
              />
            )}
          </div>
        </main>
        <DebugToastHost />
      </div>
    </div>
  )
}
