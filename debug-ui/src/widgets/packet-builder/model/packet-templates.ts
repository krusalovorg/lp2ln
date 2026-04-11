import type { PacketTemplate } from './types'

export const PACKET_TEMPLATES: PacketTemplate[] = [
  {
    id: 'raw_ping',
    group: 'Простое тело',
    label: 'ping',
    description: 'Короткий сигнал; часто в ответ приходит pong.',
  },
  {
    id: 'raw_pong',
    group: 'Простое тело',
    label: 'pong',
    description: 'Ответ на ping.',
  },
  {
    id: 'raw_empty',
    group: 'Простое тело',
    label: 'Пусто',
    description: 'Сообщение без содержимого.',
  },
  {
    id: 'nc_RequestPeers',
    group: 'Служебное (NetworkControl)',
    label: 'RequestPeers',
    description: 'Список пиров.',
  },
  {
    id: 'nc_RequestDescriptors',
    group: 'Служебное (NetworkControl)',
    label: 'RequestDescriptors',
    description: 'Карточки пиров.',
  },
  {
    id: 'nc_RequestAdjacency',
    group: 'Служебное (NetworkControl)',
    label: 'RequestAdjacency',
    description: 'Кто рядом в топологии.',
  },
  {
    id: 'nc_RequestCapabilities',
    group: 'Служебное (NetworkControl)',
    label: 'RequestCapabilities',
    description: 'Что умеют пиры.',
  },
  {
    id: 'nc_FindRelays',
    group: 'Служебное (NetworkControl)',
    label: 'FindRelays',
    description: 'Найти релеи.',
  },
  {
    id: 'nc_FindProviders',
    group: 'Служебное (NetworkControl)',
    label: 'FindProviders',
    description: 'Найти провайдеров данных.',
  },
  {
    id: 'nc_PingPeerQuality',
    group: 'Служебное (NetworkControl)',
    label: 'PingPeerQuality',
    description: 'Оценка задержки до пира.',
  },
]
