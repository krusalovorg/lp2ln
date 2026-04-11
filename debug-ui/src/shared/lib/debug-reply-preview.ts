import type { CommandResult } from '@/shared/types/debug'

function bytesToHexPreview(bytes: Uint8Array, max = 40): string {
  const n = Math.min(max, bytes.length)
  const parts: string[] = []
  for (let i = 0; i < n; i += 1) parts.push(bytes[i]!.toString(16).padStart(2, '0'))
  const tail = bytes.length > max ? ` … +${bytes.length - max}` : ''
  return parts.join(' ') + tail
}

/** Текст ответа пира для команд отправки при успехе */
export function decodeReplyPreview(result: CommandResult | null): string | null {
  if (!result || result.ok !== true) return null
  const cmd = result.cmd
  if (cmd !== 'send_packet' && cmd !== 'send_to_peer' && cmd !== 'send_to_session') return null
  const text = result.reply_text
  if (typeof text === 'string' && text.length > 0) return text
  const b64 = result.reply_base64
  if (typeof b64 !== 'string' || b64.length === 0) return null
  try {
    const bin = atob(b64)
    const bytes = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i)
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    } catch {
      return bytesToHexPreview(bytes, 96)
    }
  } catch {
    return '(не удалось разобрать reply_base64)'
  }
}

export function prettyFormatIfJson(text: string): string {
  const t = text.trim()
  if (t.length === 0) return text
  if (t[0] !== '{' && t[0] !== '[') return text
  try {
    return JSON.stringify(JSON.parse(t) as unknown, null, 2)
  } catch {
    return text
  }
}

export function commandResultSummary(result: CommandResult | null): string {
  if (!result) return ''
  const cmd = String(result.cmd ?? 'команда')
  if (result.ok === true) {
    const hint = decodeReplyPreview(result)
    if (hint) {
      const oneLine = hint.split(/\r?\n/)[0] ?? hint
      const short = oneLine.length > 80 ? `${oneLine.slice(0, 77)}…` : oneLine
      return `${cmd}: ответ получен — ${short}`
    }
    return `${cmd}: успех`
  }
  if (result.ok === false) return `${cmd}: ${String(result.error ?? 'ошибка')}`
  return cmd
}
