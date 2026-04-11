import { cn } from '@/lib/utils'

import type { PacketTemplate } from '../model/types'

type Props = {
  templateByGroup: Map<string, PacketTemplate[]>
  selectedTemplateId: string | null
  selectedTemplate: PacketTemplate | null
  onPickTemplate: (id: string) => void
}

export function PacketTemplatesAside(props: Props) {
  const { templateByGroup, selectedTemplateId, selectedTemplate, onPickTemplate } = props

  return (
    <aside className="mt-8 flex min-h-0 flex-col rounded-2xl border border-zinc-200 bg-zinc-50/80 dark:border-zinc-800 dark:bg-zinc-900/40 lg:sticky lg:top-4 lg:mt-0 lg:max-h-[min(100dvh-5rem,920px)]">
      <div className="shrink-0 space-y-3 border-b border-zinc-200/90 bg-zinc-50/95 p-4 pb-3 backdrop-blur-sm dark:border-zinc-700/90 dark:bg-zinc-900/95">
        <h3 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">Шаблоны</h3>
        <p className="text-xs leading-relaxed text-zinc-500 dark:text-zinc-400">
          Быстрый старт: режим и черновик. Дальше всё можно изменить слева.
        </p>
        <div className="rounded-xl border border-zinc-200/80 bg-white/90 p-3 shadow-sm dark:border-zinc-700 dark:bg-zinc-950/80">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-blue-600 dark:text-blue-400">О шаблоне</div>
          <p className="mt-2 text-xs leading-relaxed text-zinc-700 dark:text-zinc-300">
            {selectedTemplate ? selectedTemplate.description : 'Выберите пункт в списке ниже.'}
          </p>
        </div>
      </div>
      <nav className="min-h-0 flex-1 overflow-y-auto overscroll-contain p-3 pt-3" aria-label="Список шаблонов пакетов">
        <div className="space-y-4">
          {Array.from(templateByGroup.entries()).map(([group, items]) => (
            <div key={group}>
              <div className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-zinc-400">{group}</div>
              <div className="flex flex-col gap-1">
                {items.map((t) => (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => onPickTemplate(t.id)}
                    className={cn(
                      'rounded-lg border px-3 py-2 text-left text-sm transition-colors',
                      selectedTemplateId === t.id
                        ? 'border-zinc-900 bg-white shadow-sm dark:border-zinc-100 dark:bg-zinc-950'
                        : 'border-transparent bg-white/60 hover:bg-white dark:bg-zinc-950/60 dark:hover:bg-zinc-950',
                    )}
                  >
                    {t.label}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      </nav>
    </aside>
  )
}
