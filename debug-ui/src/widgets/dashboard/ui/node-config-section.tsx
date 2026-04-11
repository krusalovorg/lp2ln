import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { DbTable, Metric } from './db-table'
import type { FileLookupPayload, Snapshot } from '@/shared/types/debug'

export function NodeConfigSection(props: {
  ownPeerId?: string
  snapshot: Snapshot
  scoreWeightLabels: Record<string, string>
  peerRankings: Array<Record<string, unknown>>
  peerRollup: Array<Record<string, unknown>>
  fileLookup: FileLookupPayload | null
  fileHashQuery: string
  setFileHashQuery: (v: string) => void
  sendCommand: (payload: Record<string, unknown>) => boolean
}) {
  const { ownPeerId, snapshot, scoreWeightLabels, peerRankings, peerRollup, fileLookup, fileHashQuery, setFileHashQuery, sendCommand } =
    props

  return (
    <div className="space-y-10">
      <p className="text-sm text-zinc-500 dark:text-zinc-400">
        Лимиты пиров, веса скоринга, таблицы рейтинга и поиск файла в локальном хранилище по хешу.
      </p>

      <section className="space-y-4 border-b border-zinc-100 pb-10 dark:border-zinc-800">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">Цели по числу пиров</h2>
        <p className="text-xs text-zinc-500">Минимум, желаемое и потолок одновременных активных соединений</p>
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-3">
          <Metric title="Мин. активных пиров" value={String(snapshot.node?.policy?.min_active_peers ?? 0)} />
          <Metric title="Цель: активных пиров" value={String(snapshot.node?.policy?.target_active_peers ?? 0)} />
          <Metric title="Макс. активных пиров" value={String(snapshot.node?.policy?.max_active_peers ?? 0)} />
        </div>
      </section>

      <section className="space-y-4 border-b border-zinc-100 pb-10 dark:border-zinc-800">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">Веса при оценке пиров</h2>
        <div className="divide-y divide-zinc-100 dark:divide-zinc-800">
          {Object.entries(snapshot.node?.score_weights ?? {}).map(([k, v]) => (
            <div key={k} className="flex items-center justify-between py-2 text-sm">
              <span className="text-zinc-600 dark:text-zinc-400">{scoreWeightLabels[k] ?? k}</span>
              <span className="tabular-nums font-medium">{String(v)}</span>
            </div>
          ))}
        </div>
        {Object.keys(snapshot.node?.score_weights ?? {}).length === 0 && <p className="text-sm text-zinc-500">Нет данных в снимке</p>}
      </section>

      <section className="space-y-3 border-b border-zinc-100 pb-10 dark:border-zinc-800">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">Рейтинги и сводка с ноды</h2>
        <p className="text-xs text-zinc-500">Отдельный запрос — данные могут отличаться от полей в снимке</p>
        <div className="flex flex-wrap gap-2">
          <Button size="sm" variant="secondary" onClick={() => sendCommand({ cmd: 'get_peer_rankings' })}>
            Запросить рейтинг
          </Button>
          <Button size="sm" variant="secondary" onClick={() => sendCommand({ cmd: 'get_peer_rollup' })}>
            Запросить сводку
          </Button>
        </div>
      </section>

      <section className="space-y-3">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">Таблица рейтинга</h2>
        <DbTable rows={peerRankings} ownPeerId={ownPeerId} />
      </section>

      <section className="space-y-3">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">Сводка по пирам</h2>
        <DbTable rows={peerRollup} ownPeerId={ownPeerId} />
      </section>

      <section className="space-y-4">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">Файл по хешу</h2>
        <div className="flex flex-col gap-2 sm:flex-row sm:items-end">
          <div className="min-w-0 flex-1">
            <label htmlFor="node-file-hash" className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-zinc-500">
              Хеш содержимого
            </label>
            <Input id="node-file-hash" value={fileHashQuery} onChange={(e) => setFileHashQuery(e.target.value)} placeholder="Вставьте хеш файла" />
          </div>
          <div className="flex gap-2">
            <Button size="sm" variant="secondary" onClick={() => sendCommand({ cmd: 'get_file_by_hash', file_hash: fileHashQuery })}>
              Найти
            </Button>
            <Button
              size="sm"
              className="bg-red-600 text-white hover:bg-red-700 dark:bg-red-700 dark:hover:bg-red-600"
              onClick={() => sendCommand({ cmd: 'remove_file', file_hash: fileHashQuery })}
            >
              Удалить из хранилища
            </Button>
          </div>
        </div>
        {fileLookup && (
          <div className="space-y-2 border-t border-zinc-100 pt-4 text-sm dark:border-zinc-800">
            <div className="text-xs text-zinc-600 dark:text-zinc-400">
              {fileLookup.ok ? (fileLookup.found ? 'Найдено' : 'Не найдено') : String(fileLookup.error ?? 'ошибка')}
            </div>
            {fileLookup.file && (
              <pre className="overflow-x-auto rounded-md bg-zinc-50 p-3 font-mono text-xs dark:bg-zinc-900">
                {JSON.stringify(fileLookup.file, null, 2)}
              </pre>
            )}
          </div>
        )}
      </section>
    </div>
  )
}
