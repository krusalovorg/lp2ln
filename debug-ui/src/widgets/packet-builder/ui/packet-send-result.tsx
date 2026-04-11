import { Loader2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { decodeReplyPreview, prettyFormatIfJson } from '@/shared/lib/debug-reply-preview'
import type { CommandResult } from '@/shared/types/debug'

export function PacketSendResult(props: {
  lastCommandResult: CommandResult | null
  waitingForPeerReply?: boolean
}) {
  const { lastCommandResult, waitingForPeerReply } = props

  const show =
    lastCommandResult &&
    (lastCommandResult.cmd === 'send_packet' ||
      lastCommandResult.cmd === 'send_to_peer' ||
      lastCommandResult.cmd === 'send_to_session')

  if (waitingForPeerReply) {
    return (
      <div className="mt-8 rounded-2xl border border-emerald-200/80 bg-emerald-50/50 p-4 dark:border-emerald-900/50 dark:bg-emerald-950/20">
        <div className="flex items-center gap-3 text-sm text-emerald-900 dark:text-emerald-100">
          <Loader2 className="h-5 w-5 shrink-0 animate-spin text-emerald-600 dark:text-emerald-400" aria-hidden />
          <span className="font-medium">Ожидание ответа пира…</span>
        </div>
        <p className="mt-2 text-xs text-emerald-800/80 dark:text-emerald-200/80">
          Предыдущий результат сброшен; по завершении здесь появится новый ответ или ошибка.
        </p>
      </div>
    )
  }

  if (!show || !lastCommandResult) return null

  const peerBody = decodeReplyPreview(lastCommandResult)

  return (
    <div className="mt-8 rounded-2xl border border-emerald-200/80 bg-emerald-50/50 p-4 dark:border-emerald-900/50 dark:bg-emerald-950/20">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-semibold text-emerald-900 dark:text-emerald-100">Результат отправки</span>
        <Badge variant={lastCommandResult.ok ? 'success' : 'warn'} className="text-[10px]">
          {lastCommandResult.ok ? 'ok' : 'fail'}
        </Badge>
        {lastCommandResult.request_id != null ? (
          <span className="text-xs text-emerald-800/90 dark:text-emerald-200/90">
            № запроса <span className="font-mono">{String(lastCommandResult.request_id)}</span>
          </span>
        ) : null}
      </div>
      {lastCommandResult.ok === false ? (
        <p className="mt-2 text-sm text-red-600 dark:text-red-400">{String(lastCommandResult.error ?? 'ошибка')}</p>
      ) : null}
      {peerBody ? (
        <pre className="mt-3 max-h-48 overflow-auto whitespace-pre-wrap rounded-lg border border-emerald-200/50 bg-white/90 p-3 font-mono text-[12px] leading-relaxed text-zinc-800 shadow-inner dark:border-emerald-900/40 dark:bg-zinc-900/90 dark:text-zinc-100">
          {prettyFormatIfJson(peerBody)}
        </pre>
      ) : null}
      <details className="mt-3 text-[11px] text-zinc-500">
        <summary className="cursor-pointer hover:text-zinc-700 dark:hover:text-zinc-300">Полный ответ (JSON)</summary>
        <pre className="mt-2 max-h-40 overflow-auto rounded-lg border border-zinc-200/80 bg-white/80 p-2 font-mono dark:border-zinc-700 dark:bg-zinc-950/80">
          {JSON.stringify(lastCommandResult, null, 2)}
        </pre>
      </details>
    </div>
  )
}
