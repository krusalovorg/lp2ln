import { Button } from '@/components/ui/button'
import { DbTable } from './db-table'

type TableName = 'storage_files' | 'peer_descriptors' | 'peer_scores'

const TABLE_LABELS: Record<TableName, string> = {
  storage_files: 'Файлы в хранилище',
  peer_descriptors: 'Дескрипторы пиров',
  peer_scores: 'Оценки пиров',
}

export function DatabaseSection(props: {
  ownPeerId?: string
  activeTable: TableName
  setActiveTable: (v: TableName) => void
  showAllTables: boolean
  setShowAllTables: (v: boolean) => void
  requestDbTables: () => void
  storageRows: Array<Record<string, unknown>>
  descriptorRows: Array<Record<string, unknown>>
  scoreRows: Array<Record<string, unknown>>
  activeRows: Array<Record<string, unknown>>
}) {
  const {
    ownPeerId,
    activeTable,
    setActiveTable,
    showAllTables,
    setShowAllTables,
    requestDbTables,
    storageRows,
    descriptorRows,
    scoreRows,
    activeRows,
  } = props

  return (
    <section className="space-y-5">
      <p className="text-sm text-zinc-500 dark:text-zinc-400">
        Строки из SQLite ноды. «Загрузить» запрашивает срез; ответ приходит отдельным событием по WebSocket.
      </p>

      <div className="flex flex-wrap gap-2">
        <Button size="sm" variant="secondary" onClick={requestDbTables} title="Запросить таблицы с активной ноды">
          Загрузить с ноды
        </Button>
        <Button size="sm" variant={showAllTables ? 'default' : 'secondary'} onClick={() => setShowAllTables(!showAllTables)}>
          {showAllTables ? 'Показать одну таблицу' : 'Показать все таблицы'}
        </Button>
        <Button
          size="sm"
          variant={activeTable === 'storage_files' ? 'default' : 'secondary'}
          onClick={() => setActiveTable('storage_files')}
        >
          {TABLE_LABELS.storage_files} ({storageRows.length})
        </Button>
        <Button
          size="sm"
          variant={activeTable === 'peer_descriptors' ? 'default' : 'secondary'}
          onClick={() => setActiveTable('peer_descriptors')}
        >
          {TABLE_LABELS.peer_descriptors} ({descriptorRows.length})
        </Button>
        <Button
          size="sm"
          variant={activeTable === 'peer_scores' ? 'default' : 'secondary'}
          onClick={() => setActiveTable('peer_scores')}
        >
          {TABLE_LABELS.peer_scores} ({scoreRows.length})
        </Button>
      </div>

      {!showAllTables ? (
        <DbTable rows={activeRows} ownPeerId={ownPeerId} />
      ) : (
        <div className="space-y-10">
          <div>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-zinc-400">
              {TABLE_LABELS.storage_files} ({storageRows.length})
            </h3>
            <DbTable rows={storageRows} ownPeerId={ownPeerId} />
          </div>
          <div>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-zinc-400">
              {TABLE_LABELS.peer_descriptors} ({descriptorRows.length})
            </h3>
            <DbTable rows={descriptorRows} ownPeerId={ownPeerId} />
          </div>
          <div>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-zinc-400">
              {TABLE_LABELS.peer_scores} ({scoreRows.length})
            </h3>
            <DbTable rows={scoreRows} ownPeerId={ownPeerId} />
          </div>
        </div>
      )}
    </section>
  )
}
