import type { PacketTemplate } from '../model/types'

export function groupTemplatesByGroup(templates: PacketTemplate[]): Map<string, PacketTemplate[]> {
  const m = new Map<string, PacketTemplate[]>()
  for (const t of templates) {
    const list = m.get(t.group) ?? []
    list.push(t)
    m.set(t.group, list)
  }
  return m
}
