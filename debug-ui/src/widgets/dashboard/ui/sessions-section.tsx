import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { formatBytes } from '@/shared/lib/format'
import type { Snapshot } from '@/shared/types/debug'

export function SessionsSection(props: {
  snapshot: Snapshot
  ownPeerId?: string
  sessionRowsFiltered: NonNullable<Snapshot['sessions']>
  sessionRows: NonNullable<Snapshot['sessions']>
  sessionProtocolFilter: string
  setSessionProtocolFilter: (v: string) => void
  sessionQuery: string
  setSessionQuery: (v: string) => void
  protocolOptions: string[]
  connectTransport: string
  setConnectTransport: (v: string) => void
  connectAddr: string
  setConnectAddr: (v: string) => void
  sendCommand: (payload: Record<string, unknown>) => boolean
}) {
  const {
    ownPeerId,
    sessionRowsFiltered,
    sessionRows,
    sessionProtocolFilter,
    setSessionProtocolFilter,
    sessionQuery,
    setSessionQuery,
    protocolOptions,
    connectTransport,
    setConnectTransport,
    connectAddr,
    setConnectAddr,
    sendCommand,
  } = props

  return (
    <section className="space-y-6">
      <p className="text-sm text-zinc-500 dark:text-zinc-400">
        Сессии ноды: фильтр, закрытие и исходящее подключение к пиру (через транспорт ноды, не через этот UI).
      </p>

      <div>
        <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">Исходящее подключение к пиру</h2>
        <div className="mt-3 grid grid-cols-1 gap-2 md:grid-cols-4 md:items-end">
          <div>
            <label htmlFor="sess-connect-transport" className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-zinc-500">
              Транспорт
            </label>
            <Input
              id="sess-connect-transport"
              value={connectTransport}
              onChange={(e) => setConnectTransport(e.target.value)}
              placeholder="Напр. tcp"
            />
          </div>
          <div className="md:col-span-2">
            <label htmlFor="sess-connect-addr" className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-zinc-500">
              Адрес пира
            </label>
            <Input
              id="sess-connect-addr"
              value={connectAddr}
              onChange={(e) => setConnectAddr(e.target.value)}
              placeholder="host:port"
            />
          </div>
          <Button size="sm" className="md:mb-0.5" onClick={() => sendCommand({ cmd: 'connect_peer', transport: connectTransport, addr: connectAddr })}>
            Подключиться
          </Button>
        </div>
      </div>

      <div>
        <div className="flex flex-wrap items-baseline gap-2">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">Текущие сессии</h2>
          <span className="text-sm tabular-nums text-zinc-500">
            показано {sessionRowsFiltered.length} из {sessionRows.length}
          </span>
        </div>
        <datalist id="protocol-options">
          <option value="all" />
          {protocolOptions.map((p) => (
            <option key={p} value={p} />
          ))}
        </datalist>
        <div className="mt-3 grid grid-cols-1 gap-2 md:grid-cols-4 md:items-end">
          <div className="md:col-span-3">
            <label htmlFor="sess-query" className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-zinc-500">
              Поиск
            </label>
            <Input
              id="sess-query"
              value={sessionQuery}
              onChange={(e) => setSessionQuery(e.target.value)}
              placeholder="session_id или peer_id"
            />
          </div>
          <div>
            <label htmlFor="sess-protocol" className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-zinc-500">
              Протокол
            </label>
            <Input
              id="sess-protocol"
              value={sessionProtocolFilter}
              onChange={(e) => setSessionProtocolFilter(e.target.value)}
              list="protocol-options"
              placeholder="all или имя"
              title="Введите all или конкретный протокол из списка сессий"
            />
          </div>
        </div>
      </div>

      <div className="overflow-x-auto rounded-xl border border-zinc-200 dark:border-zinc-800">
        <table className="min-w-full text-left text-xs">
          <thead>
            <tr className="border-b border-zinc-200 bg-zinc-50/80 text-zinc-600 dark:border-zinc-800 dark:bg-zinc-900/50 dark:text-zinc-400">
              <th className="px-3 py-2.5 pr-4 font-medium">Сессия</th>
              <th className="px-0 py-2.5 pr-4 font-medium">Пир</th>
              <th className="px-0 py-2.5 pr-4 font-medium">Протокол</th>
              <th className="px-0 py-2.5 pr-4 font-medium">Активна</th>
              <th className="px-0 py-2.5 pr-4 font-medium">Пакеты (отпр./получ.)</th>
              <th className="px-0 py-2.5 pr-4 font-medium">Данные</th>
              <th className="py-2.5 pr-3 font-medium" />
            </tr>
          </thead>
          <tbody>
            {sessionRowsFiltered.map((s) => (
              <tr
                key={s.session_id}
                className={`border-b border-zinc-100 dark:border-zinc-800/80 ${s.peer_id === ownPeerId ? 'bg-blue-50/80 dark:bg-blue-950/20' : ''}`}
              >
                <td className="max-w-[140px] truncate px-3 py-2.5 pr-4 font-mono">{s.session_id}</td>
                <td
                  className={`max-w-[160px] truncate py-2.5 pr-4 font-mono ${s.peer_id === ownPeerId ? 'font-semibold text-blue-700 dark:text-blue-300' : ''}`}
                >
                  {s.peer_id ?? '—'}
                </td>
                <td className="py-2.5 pr-4">{s.protocol}</td>
                <td className="py-2.5 pr-4 tabular-nums">{s.is_active ? 'да' : 'нет'}</td>
                <td className="py-2.5 pr-4 tabular-nums">
                  {s.packets_sent}/{s.packets_received}
                </td>
                <td className="py-2.5 pr-4 tabular-nums">
                  {formatBytes(s.bytes_sent)} / {formatBytes(s.bytes_received)}
                </td>
                <td className="py-2.5 pr-3">
                  <Button size="sm" variant="secondary" onClick={() => sendCommand({ cmd: 'close_session', session_id: s.session_id })}>
                    Закрыть
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}
