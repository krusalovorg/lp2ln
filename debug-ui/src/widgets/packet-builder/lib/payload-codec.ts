import type { PayloadEncoding } from '../model/types'

export function normalizeHex(input: string): string {
  let t = input.replace(/\s/g, '')
  if (t.startsWith('0x') || t.startsWith('0X')) t = t.slice(2)
  return t
}

export function parseHexToBytes(input: string): Uint8Array {
  const t = normalizeHex(input)
  if (t.length === 0) return new Uint8Array(0)
  if (t.length % 2 !== 0) throw new Error('hex: нечётная длина')
  const out = new Uint8Array(t.length / 2)
  for (let i = 0; i < t.length; i += 2) {
    const pair = t.slice(i, i + 2)
    const b = Number.parseInt(pair, 16)
    if (Number.isNaN(b)) throw new Error(`hex: неверный байт «${pair}»`)
    out[i / 2] = b
  }
  return out
}

export function parseBase64ToBytes(input: string): Uint8Array {
  const t = input.trim()
  if (t.length === 0) return new Uint8Array(0)
  try {
    const bin = atob(t)
    const out = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i)
    return out
  } catch {
    throw new Error('base64: неверная строка')
  }
}

export function payloadToBytes(body: string, enc: PayloadEncoding): Uint8Array {
  if (enc === 'utf8' || enc === 'json') return new TextEncoder().encode(body)
  if (enc === 'hex') return parseHexToBytes(body)
  return parseBase64ToBytes(body)
}

export function bytesToHexPreview(bytes: Uint8Array, max = 40): string {
  const n = Math.min(max, bytes.length)
  const parts: string[] = []
  for (let i = 0; i < n; i += 1) parts.push(bytes[i]!.toString(16).padStart(2, '0'))
  const tail = bytes.length > max ? ` … +${bytes.length - max}` : ''
  return parts.join(' ') + tail
}
