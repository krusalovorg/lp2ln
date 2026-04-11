import { useMemo } from 'react'

function renderValue(value: unknown): string {
  if (typeof value === 'boolean') return value ? '1' : '0'
  if (value === null || value === undefined) return '—'
  if (typeof value === 'string') return value
  return JSON.stringify(value, null, 0)
}

function rowContainsPeerId(row: Record<string, unknown>, peerId: string): boolean {
  if (!peerId) return false
  return Object.values(row).some((v) => {
    if (typeof v === 'string') return v === peerId
    if (Array.isArray(v)) return v.some((i) => typeof i === 'string' && i === peerId)
    return false
  })
}

function cellContainsPeerId(value: unknown, peerId: string): boolean {
  if (!peerId) return false
  if (typeof value === 'string') return value === peerId
  if (Array.isArray(value)) return value.some((i) => typeof i === 'string' && i === peerId)
  return false
}

export function DbTable({
  rows,
  ownPeerId,
}: {
  rows: Array<Record<string, unknown>>
  ownPeerId?: string
}) {
  const sortedRows = useMemo(() => {
    const copy = [...rows]
    const by = (r: Record<string, unknown>): string => {
      const v =
        (r.peer_id as string | undefined) ??
        (r.session_id as string | undefined) ??
        (r.file_hash as string | undefined) ??
        (r.id as string | undefined) ??
        ''
      return typeof v === 'string' ? v : ''
    }
    copy.sort((a, b) => by(a).localeCompare(by(b)))
    return copy
  }, [rows])

  const columns = useMemo(() => {
    const keys = new Set<string>()
    sortedRows.slice(0, 100).forEach((r) => Object.keys(r).forEach((k) => keys.add(k)))
    return Array.from(keys)
  }, [sortedRows])

  if (!rows.length) {
    return <div className="py-8 text-center text-sm text-zinc-400">Нет строк</div>
  }

  return (
    <div className="overflow-x-auto border-y border-zinc-200 dark:border-zinc-800">
      <table className="min-w-full text-left text-xs">
        <thead>
          <tr className="border-b border-zinc-200 dark:border-zinc-800">
            {columns.map((col) => (
              <th key={col} className="px-0 py-2 pr-4 font-medium text-zinc-500">
                {col}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sortedRows.map((row, idx) => {
            const isOwnRow = rowContainsPeerId(row, ownPeerId ?? '')
            const rowKey =
              (row.peer_id as string | undefined) ??
              (row.session_id as string | undefined) ??
              (row.file_hash as string | undefined) ??
              (row.id as string | undefined) ??
              String(idx)
            return (
              <tr
                key={rowKey}
                className={`border-b border-zinc-100 dark:border-zinc-800/80 ${isOwnRow ? 'bg-blue-50/80 dark:bg-blue-950/20' : ''}`}
              >
                {columns.map((col) => {
                  const isOwnCell = cellContainsPeerId(row[col], ownPeerId ?? '')
                  return (
                    <td
                      key={col}
                      className={`max-w-[320px] py-2 pr-4 align-top ${isOwnCell ? 'font-semibold text-blue-700 dark:text-blue-300' : ''}`}
                    >
                      <pre className="whitespace-pre-wrap break-all font-mono">{renderValue(row[col])}</pre>
                    </td>
                  )
                })}
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

export function Metric({ title, value }: { title: string; value: string }) {
  return (
    <div>
      <p className="text-[11px] font-medium uppercase tracking-wide text-zinc-400">{title}</p>
      <p className="mt-1 break-all font-mono text-sm">{value}</p>
    </div>
  )
}
