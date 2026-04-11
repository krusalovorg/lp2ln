import { X } from 'lucide-react'
import { cn } from '@/lib/utils'

import { useDebugToastStore } from '../model/debug-toast-store'

export function DebugToastHost() {
  const toasts = useDebugToastStore((s) => s.toasts)
  const dismiss = useDebugToastStore((s) => s.dismiss)

  if (toasts.length === 0) return null

  return (
    <div className="pointer-events-none fixed right-4 top-16 z-[100] flex max-w-sm flex-col gap-2 sm:right-6 sm:top-20">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={cn(
            'pointer-events-auto flex items-start gap-2 rounded-lg border px-3 py-2.5 text-sm shadow-lg backdrop-blur-sm',
            t.variant === 'success' && 'border-emerald-200/90 bg-emerald-50/95 text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950/90 dark:text-emerald-100',
            t.variant === 'error' && 'border-red-200/90 bg-red-50/95 text-red-900 dark:border-red-900 dark:bg-red-950/90 dark:text-red-100',
            t.variant === 'info' && 'border-zinc-200/90 bg-white/95 text-zinc-900 dark:border-zinc-700 dark:bg-zinc-900/95 dark:text-zinc-100',
          )}
        >
          <p className="min-w-0 flex-1 leading-snug">{t.message}</p>
          <button
            type="button"
            className="shrink-0 rounded p-0.5 opacity-60 hover:opacity-100"
            onClick={() => dismiss(t.id)}
            aria-label="Закрыть"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      ))}
    </div>
  )
}
