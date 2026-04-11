import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { cn } from '@/lib/utils'

const fieldBase =
  'w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 shadow-sm placeholder:text-zinc-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-zinc-400 dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-100 dark:focus-visible:ring-zinc-600'

function SectionTitle({ id, children }: { id?: string; children: React.ReactNode }) {
  return (
    <h2 id={id} className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
      {children}
    </h2>
  )
}

function SectionHint({ children }: { children: React.ReactNode }) {
  return <p className="mt-1 text-xs leading-relaxed text-zinc-500 dark:text-zinc-400">{children}</p>
}

export function OperationsSection(props: {
  disconnectPeerId: string
  setDisconnectPeerId: (v: string) => void
  rawCommand: string
  setRawCommand: (v: string) => void
  knownPeerId: string
  setKnownPeerId: (v: string) => void
  knownPeerTransport: string
  setKnownPeerTransport: (v: string) => void
  knownPeerAddr: string
  setKnownPeerAddr: (v: string) => void
  batchConnectTransport: string
  setBatchConnectTransport: (v: string) => void
  batchConnectAddrs: string
  setBatchConnectAddrs: (v: string) => void
  batchDisconnectPeers: string
  setBatchDisconnectPeers: (v: string) => void
  availableCommands: string[]
  sendCommand: (payload: Record<string, unknown>) => boolean
}) {
  const {
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
    availableCommands,
    sendCommand,
  } = props

  return (
    <div className="mx-auto max-w-2xl space-y-10 pb-12">
      <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/80 p-4 dark:border-zinc-800 dark:bg-zinc-900/40">
        <p className="text-sm leading-relaxed text-zinc-700 dark:text-zinc-300">
          Сообщения пирам и тестовые пакеты — в разделе{' '}
          <span className="font-medium text-zinc-900 dark:text-zinc-100">Пакеты (отладка)</span>. Здесь —{' '}
          <span className="font-medium text-zinc-900 dark:text-zinc-100">сеть ноды</span>: отключения, известные адреса,
          пакетное подключение и произвольные команды в JSON.
        </p>
      </div>

      <div className="rounded-2xl border border-zinc-200/90 bg-white p-5 shadow-sm dark:border-zinc-800 dark:bg-zinc-950 sm:p-6">
        <div className="space-y-10">
          <section aria-labelledby="ops-addr-heading">
            <SectionTitle id="ops-addr-heading">Запомнить адрес пира</SectionTitle>
            <SectionHint>
              Сообщаете ноде: «у пира с таким ID можно искать по этому транспорту и адресу» (например{' '}
              <code className="rounded bg-zinc-100 px-1 text-[11px] dark:bg-zinc-800">tcp</code> и{' '}
              <code className="rounded bg-zinc-100 px-1 text-[11px] dark:bg-zinc-800">127.0.0.1:4001</code>). Полезно
              перед попыткой соединения, если пир ещё не в списке из топологии.
            </SectionHint>
            <div className="mt-4 grid gap-3 sm:grid-cols-3">
              <div>
                <span className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-zinc-500">Peer ID</span>
                <Input className={cn(fieldBase, 'font-mono text-xs')} value={knownPeerId} onChange={(e) => setKnownPeerId(e.target.value)} placeholder="Идентификатор пира" />
              </div>
              <div>
                <span className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-zinc-500">Транспорт</span>
                <Input className={fieldBase} value={knownPeerTransport} onChange={(e) => setKnownPeerTransport(e.target.value)} placeholder="Напр. tcp, udp" />
              </div>
              <div>
                <span className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-zinc-500">Адрес</span>
                <Input className={fieldBase} value={knownPeerAddr} onChange={(e) => setKnownPeerAddr(e.target.value)} placeholder="host:port" />
              </div>
            </div>
            <Button
              className="mt-3"
              size="sm"
              variant="secondary"
              onClick={() =>
                sendCommand({
                  cmd: 'register_known_peer_addr',
                  peer_id: knownPeerId,
                  transport: knownPeerTransport,
                  addr: knownPeerAddr,
                })
              }
            >
              Сохранить адрес
            </Button>
          </section>

          <section className="border-t border-zinc-100 pt-10 dark:border-zinc-800" aria-labelledby="ops-one-heading">
            <SectionTitle id="ops-one-heading">Отключить одного пира</SectionTitle>
            <SectionHint>Разрывает уже установленное соединение с этим ID. Сама нода при этом продолжает работать.</SectionHint>
            <div className="mt-4 flex flex-wrap items-end gap-2">
              <div className="min-w-0 max-w-md flex-1">
                <span className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-zinc-500">Peer ID</span>
                <Input
                  className={cn(fieldBase, 'font-mono text-xs')}
                  value={disconnectPeerId}
                  onChange={(e) => setDisconnectPeerId(e.target.value)}
                  placeholder="Кого отключить"
                />
              </div>
              <Button size="sm" variant="secondary" onClick={() => sendCommand({ cmd: 'disconnect_peer', peer_id: disconnectPeerId })}>
                Отключить
              </Button>
            </div>
          </section>

          <section className="border-t border-zinc-100 pt-10 dark:border-zinc-800" aria-labelledby="ops-batch-heading">
            <SectionTitle id="ops-batch-heading">Массово: подключить или отключить</SectionTitle>
            <SectionHint>
              Список адресов — попытка исходящих подключений одной кнопкой. Список ID — отключение нескольких пиров подряд.
            </SectionHint>
            <div className="mt-4 space-y-4">
              <div>
                <span className="mb-1 block text-xs font-medium text-zinc-600 dark:text-zinc-400">Подключить по адресам</span>
                <Input className={cn(fieldBase, 'mb-2 max-w-xs')} value={batchConnectTransport} onChange={(e) => setBatchConnectTransport(e.target.value)} placeholder="tcp" />
                <textarea
                  value={batchConnectAddrs}
                  onChange={(e) => setBatchConnectAddrs(e.target.value)}
                  className={cn(fieldBase, 'min-h-[88px] resize-y font-mono text-xs')}
                  placeholder="каждый адрес с новой строки"
                />
                <Button
                  className="mt-2"
                  size="sm"
                  variant="secondary"
                  onClick={() =>
                    sendCommand({
                      cmd: 'connect_batch',
                      transport: batchConnectTransport,
                      addrs: batchConnectAddrs
                        .split(/\r?\n/)
                        .map((v) => v.trim())
                        .filter(Boolean),
                    })
                  }
                >
                  Подключить списком
                </Button>
              </div>
              <div>
                <span className="mb-1 block text-xs font-medium text-zinc-600 dark:text-zinc-400">Отключить по ID пиров</span>
                <textarea
                  value={batchDisconnectPeers}
                  onChange={(e) => setBatchDisconnectPeers(e.target.value)}
                  className={cn(fieldBase, 'min-h-[88px] resize-y font-mono text-xs')}
                  placeholder="по одному ID на строку"
                />
                <Button
                  className="mt-2"
                  size="sm"
                  onClick={() =>
                    sendCommand({
                      cmd: 'disconnect_peer_batch',
                      peer_ids: batchDisconnectPeers
                        .split(/\r?\n/)
                        .map((v) => v.trim())
                        .filter(Boolean),
                    })
                  }
                >
                  Отключить списком
                </Button>
              </div>
            </div>
          </section>

          <section className="border-t border-zinc-100 pt-10 dark:border-zinc-800" aria-labelledby="ops-stop-heading">
            <SectionTitle id="ops-stop-heading">Остановить ноду</SectionTitle>
            <SectionHint>Завершает работу процесса ноды. Обычно нужно только при отладке или перезапуске.</SectionHint>
            <Button variant="secondary" size="sm" className="mt-4 text-red-700 dark:text-red-400" onClick={() => sendCommand({ cmd: 'stop_node' })}>
              Остановить ноду
            </Button>
          </section>

          <section className="border-t border-zinc-100 pt-10 dark:border-zinc-800" aria-labelledby="ops-json-heading">
            <SectionTitle id="ops-json-heading">Команда вручную (JSON)</SectionTitle>
            <SectionHint>
              Для разработчиков: любой объект с полем <code className="rounded bg-zinc-100 px-1 text-[11px] dark:bg-zinc-800">cmd</code>, как ожидает
              debug-сервер. Если JSON невалидный, уйдёт запрос обновления снимка (как запасной вариант).
            </SectionHint>
            <textarea
              value={rawCommand}
              onChange={(e) => setRawCommand(e.target.value)}
              spellCheck={false}
              className={cn(fieldBase, 'mt-4 min-h-[180px] resize-y font-mono text-xs')}
            />
            <div className="mt-3 flex flex-wrap gap-2">
              <Button
                size="sm"
                onClick={() => {
                  try {
                    const parsed = JSON.parse(rawCommand) as Record<string, unknown>
                    sendCommand(parsed)
                  } catch {
                    sendCommand({ cmd: 'refresh_snapshot' })
                  }
                }}
              >
                Отправить JSON
              </Button>
              <Button size="sm" variant="secondary" onClick={() => setRawCommand('{\n  "cmd": "refresh_snapshot"\n}')}>
                Пример: обновить снимок
              </Button>
            </div>
            <details className="mt-4 text-xs text-zinc-500">
              <summary className="cursor-pointer hover:text-zinc-700 dark:hover:text-zinc-300">Имена команд с сервера</summary>
              <p className="mt-2 font-mono leading-relaxed break-all">{availableCommands.length ? availableCommands.join(', ') : '—'}</p>
            </details>
          </section>
        </div>
      </div>
    </div>
  )
}
