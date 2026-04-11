import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { cn } from '@/lib/utils'
import type { CommandResult, Snapshot } from '@/shared/types/debug'

import { applyTemplateId } from '../lib/apply-template'
import { groupTemplatesByGroup } from '../lib/group-templates'
import { bytesToHexPreview, normalizeHex, payloadToBytes } from '../lib/payload-codec'
import { fieldBaseClass } from '../model/field-styles'
import { PACKET_TEMPLATES } from '../model/packet-templates'
import type { PacketDest, PayloadEncoding } from '../model/types'

import { PacketBuilderProtocolDoc } from './packet-builder-protocol-doc'
import { PacketSendResult } from './packet-send-result'
import { PacketTemplatesAside } from './packet-templates-aside'
import { StepBadge } from './step-badge'

const DEFAULT_RAW = '{"type":"RequestAdjacency","payload":{}}'

export function PacketBuilderSection(props: {
  snapshot: Snapshot
  sendCommand: (payload: Record<string, unknown>) => boolean
  lastCommandResult: CommandResult | null
  clearLastCommandResult?: () => void
}) {
  const { snapshot, sendCommand, lastCommandResult, clearLastCommandResult } = props
  const [dest, setDest] = useState<PacketDest>('peer')
  const [peerId, setPeerId] = useState('')
  const [sessionId, setSessionId] = useState('')

  const [encoding, setEncoding] = useState<PayloadEncoding>('json')
  const [rawBody, setRawBody] = useState(DEFAULT_RAW)
  const [repeat, setRepeat] = useState('1')
  const [fillCount, setFillCount] = useState('64')
  const [fillByte, setFillByte] = useState('00')
  const [sendHint, setSendHint] = useState<string | null>(null)

  const [maxHops, setMaxHops] = useState('8')
  const [receiver, setReceiver] = useState('')
  const [waitReply, setWaitReply] = useState(true)
  const [timeoutMs, setTimeoutMs] = useState('10000')
  const [waitingPeerReply, setWaitingPeerReply] = useState(false)
  const peerReplyTimerRef = useRef<number | null>(null)

  const clearPeerReplyTimer = useCallback(() => {
    if (peerReplyTimerRef.current != null) {
      window.clearTimeout(peerReplyTimerRef.current)
      peerReplyTimerRef.current = null
    }
  }, [])

  useEffect(() => {
    if (!waitingPeerReply) return
    if (lastCommandResult?.cmd !== 'send_packet') return
    clearPeerReplyTimer()
    setWaitingPeerReply(false)
  }, [lastCommandResult, waitingPeerReply, clearPeerReplyTimer])

  useEffect(() => () => clearPeerReplyTimer(), [clearPeerReplyTimer])

  const [selectedTemplateId, setSelectedTemplateId] = useState<string | null>(null)

  const sessions = useMemo(() => snapshot.sessions ?? [], [snapshot.sessions])
  const selfPeer = snapshot.node?.peer_id ?? ''

  const peerSuggest = useMemo(() => {
    const ids = new Set<string>()
    if (selfPeer) ids.add(selfPeer)
    for (const s of sessions) {
      const p = s.peer_id
      if (p) ids.add(p)
    }
    for (const n of snapshot.topology?.neighbors ?? []) {
      if (n.peer_id) ids.add(n.peer_id)
    }
    return Array.from(ids)
  }, [sessions, selfPeer, snapshot.topology?.neighbors])

  const sessionOptions = useMemo(
    () =>
      sessions.map((s) => ({
        id: s.session_id,
        label: `${s.session_id.slice(0, 8)}… · ${(s.peer_id ?? '—').slice(0, 10)}…`,
      })),
    [sessions],
  )

  const templateByGroup = useMemo(() => groupTemplatesByGroup(PACKET_TEMPLATES), [])

  const selectedTemplate = selectedTemplateId ? PACKET_TEMPLATES.find((t) => t.id === selectedTemplateId) ?? null : null

  const wirePreview = useMemo(() => {
    const body = rawBody
    const enc = encoding
    if (enc === 'json') {
      const t = body.trim()
      if (t.length > 0) {
        try {
          JSON.parse(t)
        } catch (e) {
          return {
            ok: false as const,
            error: `Не JSON: ${e instanceof Error ? e.message : String(e)}`,
          }
        }
      }
    }
    try {
      const bytes = payloadToBytes(body, enc)
      const encodingLabel = enc === 'json' ? 'JSON (utf8)' : enc
      return {
        ok: true as const,
        body,
        encoding: enc,
        encodingLabel,
        len: bytes.length,
        hex: bytesToHexPreview(bytes),
      }
    } catch (e) {
      return { ok: false as const, error: e instanceof Error ? e.message : String(e) }
    }
  }, [rawBody, encoding])

  const pickTemplate = (id: string) => {
    setSelectedTemplateId(id)
    applyTemplateId(id, { setEncoding, setRawBody })
  }

  const applyRawQuick = (kind: 'empty' | 'utf8_ping' | 'hex_hello' | 'zeros') => {
    if (kind === 'empty') {
      setEncoding('hex')
      setRawBody('')
      return
    }
    if (kind === 'utf8_ping') {
      setEncoding('utf8')
      setRawBody('ping')
      return
    }
    if (kind === 'hex_hello') {
      setEncoding('hex')
      setRawBody('48 65 6c 6c 6f')
      return
    }
    setEncoding('hex')
    setRawBody('00'.repeat(32))
  }

  const applyHexFill = () => {
    const n = Number.parseInt(fillCount, 10)
    const hb = normalizeHex(fillByte)
    if (!Number.isFinite(n) || n < 0 || n > 65536) return
    if (hb.length !== 2) return
    const v = Number.parseInt(hb, 16)
    if (Number.isNaN(v)) return
    setEncoding('hex')
    setRawBody(v.toString(16).padStart(2, '0').repeat(n))
  }

  const send = () => {
    const id = dest === 'peer' ? peerId.trim() : sessionId.trim()
    if (!id) return
    if (!wirePreview.ok) return
    const times = waitReply ? 1 : Math.min(100, Math.max(1, Number.parseInt(repeat, 10) || 1))
    const body = wirePreview.body
    const enc = wirePreview.encoding === 'json' ? 'utf8' : wirePreview.encoding

    const peerWait = dest === 'peer' && waitReply
    if (peerWait) {
      clearLastCommandResult?.()
      clearPeerReplyTimer()
      setWaitingPeerReply(true)
      const t = Math.min(300_000, Math.max(100, Number.parseInt(timeoutMs, 10) || 10_000)) + 2500
      peerReplyTimerRef.current = window.setTimeout(() => {
        peerReplyTimerRef.current = null
        setWaitingPeerReply(false)
      }, t)
    }

    let ok = 0
    for (let i = 0; i < times; i += 1) {
      let sent = false
      if (dest === 'peer') {
        const mh = Number.parseInt(maxHops.trim(), 10)
        const payload: Record<string, unknown> = {
          cmd: 'send_packet',
          peer_id: id,
          data: body,
          encoding: enc,
          wait_reply: waitReply,
          timeout_ms: Math.min(300_000, Math.max(100, Number.parseInt(timeoutMs, 10) || 10_000)),
        }
        if (Number.isFinite(mh) && mh >= 0 && mh <= 255) payload.max_hops = mh
        const recv = receiver.trim()
        if (recv.length > 0) payload.receiver = recv
        sent = sendCommand(payload)
      } else {
        sent = sendCommand({
          cmd: 'send_to_session',
          session_id: id,
          data: body,
          encoding: enc,
        })
      }
      if (sent) ok += 1
    }

    if (peerWait && ok === 0) {
      clearPeerReplyTimer()
      setWaitingPeerReply(false)
    }

    if (ok === times) setSendHint(waitReply ? 'отправлено…' : `×${times}`)
    else if (ok === 0) setSendHint('WS недоступен')
    else setSendHint(`частично ${ok}/${times}`)
    window.setTimeout(() => setSendHint(null), waitReply ? 6000 : 3200)
  }

  const destOk = dest === 'peer' ? Boolean(peerId.trim()) : Boolean(sessionId.trim())

  return (
    <div className="mx-auto w-full max-w-6xl pb-10">
      <div className="mb-6 lg:grid lg:grid-cols-[minmax(0,1fr)_min(320px,34%)] lg:gap-8 lg:items-start">
        <div className="min-w-0 space-y-5">
          <div className="rounded-2xl border border-zinc-200/90 bg-white p-5 shadow-sm dark:border-zinc-800 dark:bg-zinc-950 sm:p-6">
            <p className="mb-3 text-sm text-zinc-500 dark:text-zinc-400">
              Отправка по WebSocket; ответ ноды —{' '}
              <span className="font-medium text-zinc-700 dark:text-zinc-300">внизу страницы</span>.
            </p>

            <PacketBuilderProtocolDoc />

            <div className="mb-6 flex gap-3">
              <StepBadge n={1} />
              <div className="min-w-0 flex-1 space-y-3">
                <div className="text-sm font-medium text-zinc-900 dark:text-zinc-100">Куда отправить</div>
                <div className="inline-flex rounded-full bg-zinc-100 p-0.5 dark:bg-zinc-900">
                  <button
                    type="button"
                    className={cn(
                      'rounded-full px-3 py-1.5 text-sm font-medium transition-colors',
                      dest === 'peer' ? 'bg-white text-zinc-900 shadow-sm dark:bg-zinc-800 dark:text-zinc-100' : 'text-zinc-500',
                    )}
                    onClick={() => setDest('peer')}
                  >
                    Peer
                  </button>
                  <button
                    type="button"
                    className={cn(
                      'rounded-full px-3 py-1.5 text-sm font-medium transition-colors',
                      dest === 'session' ? 'bg-white text-zinc-900 shadow-sm dark:bg-zinc-800 dark:text-zinc-100' : 'text-zinc-500',
                    )}
                    onClick={() => setDest('session')}
                  >
                    Сессия
                  </button>
                </div>

                <datalist id="packet-peer-ids">
                  {peerSuggest.map((pid) => (
                    <option key={pid} value={pid} />
                  ))}
                </datalist>
                <datalist id="packet-session-ids">
                  {sessions.map((s) => (
                    <option key={`s-${s.session_id}`} value={s.session_id} />
                  ))}
                </datalist>

                {dest === 'peer' ? (
                  <>
                    <Input
                      value={peerId}
                      onChange={(e) => setPeerId(e.target.value)}
                      placeholder="Peer ID получателя"
                      list="packet-peer-ids"
                      className={cn(fieldBaseClass, 'font-mono text-xs')}
                    />
                    <select
                      className={fieldBaseClass}
                      value=""
                      onChange={(e) => {
                        const v = e.target.value
                        if (v) setPeerId(v)
                        e.target.value = ''
                      }}
                    >
                      <option value="">Выбрать из известных…</option>
                      {peerSuggest.map((pid) => (
                        <option key={pid} value={pid}>
                          {pid.length > 40 ? `${pid.slice(0, 38)}…` : pid}
                        </option>
                      ))}
                    </select>
                    <div className="flex flex-wrap items-center gap-3 rounded-xl bg-zinc-50 px-3 py-2.5 dark:bg-zinc-900/50">
                      <label className="flex cursor-pointer items-center gap-2 text-sm text-zinc-700 dark:text-zinc-300">
                        <input type="checkbox" className="rounded border-zinc-300" checked={waitReply} onChange={(e) => setWaitReply(e.target.checked)} />
                        Ждать ответ
                      </label>
                      <div className="flex items-center gap-1.5 text-sm text-zinc-500">
                        <span>таймаут</span>
                        <Input
                          className="h-8 w-20 font-mono text-xs"
                          value={timeoutMs}
                          onChange={(e) => setTimeoutMs(e.target.value)}
                          disabled={!waitReply}
                        />
                        <span>мс</span>
                      </div>
                    </div>
                    <details className="text-sm text-zinc-500">
                      <summary className="cursor-pointer select-none hover:text-zinc-700 dark:hover:text-zinc-300">Дополнительно</summary>
                      <div className="mt-3 space-y-3 border-l-2 border-zinc-200 pl-3 dark:border-zinc-700">
                        <div>
                          <span className="mb-1 block text-xs text-zinc-400">Лимит прыжков по сети</span>
                          <Input className={cn(fieldBaseClass, 'h-9 font-mono text-xs')} value={maxHops} onChange={(e) => setMaxHops(e.target.value)} />
                        </div>
                        <div>
                          <span className="mb-1 block text-xs text-zinc-400">Другой получатель (пусто — как указанный пир)</span>
                          <div className="flex gap-2">
                            <Input
                              className={cn(fieldBaseClass, 'h-9 flex-1 font-mono text-xs')}
                              value={receiver}
                              onChange={(e) => setReceiver(e.target.value)}
                            />
                            <Button type="button" size="sm" variant="secondary" className="shrink-0" onClick={() => setReceiver(peerId.trim())} disabled={!peerId.trim()}>
                              как peer
                            </Button>
                          </div>
                        </div>
                      </div>
                    </details>
                  </>
                ) : (
                  <>
                    <Input
                      value={sessionId}
                      onChange={(e) => setSessionId(e.target.value)}
                      placeholder="Session ID"
                      list="packet-session-ids"
                      className={cn(fieldBaseClass, 'font-mono text-xs')}
                    />
                    <select
                      className={fieldBaseClass}
                      value=""
                      onChange={(e) => {
                        const v = e.target.value
                        if (v) setSessionId(v)
                        e.target.value = ''
                      }}
                    >
                      <option value="">Выбрать сессию…</option>
                      {sessionOptions.map((o) => (
                        <option key={o.id} value={o.id}>
                          {o.label}
                        </option>
                      ))}
                    </select>
                  </>
                )}
              </div>
            </div>

            <div className="mb-6 flex gap-3 border-t border-zinc-100 pt-6 dark:border-zinc-800">
              <StepBadge n={2} />
              <div className="min-w-0 flex-1 space-y-3">
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <div className="text-sm font-medium text-zinc-900 dark:text-zinc-100">Тело пакета</div>
                  <span className="text-xs text-zinc-400">Шаблоны справа</span>
                </div>
                <p className="text-xs text-zinc-500 dark:text-zinc-400">
                  То, что уйдёт в <code className="text-[10px]">Packet.data</code>. Кнопка{' '}
                  <span className="font-medium text-zinc-700 dark:text-zinc-300">JSON</span> — UTF-8 по проводу с проверкой синтаксиса (для{' '}
                  <code className="text-[10px]">NetworkControl</code>: <code className="text-[10px]">{'{ "type", "payload" }'}</code>).
                </p>
                <div className="flex flex-wrap gap-1">
                  {(
                    [
                      { enc: 'utf8' as const, label: 'utf8', title: 'Произвольный текст' },
                      { enc: 'json' as const, label: 'JSON', title: 'UTF-8, валидный JSON' },
                      { enc: 'hex' as const, label: 'hex', title: 'Шестнадцатеричные байты' },
                      { enc: 'base64' as const, label: 'base64', title: 'Base64' },
                    ] as const
                  ).map(({ enc, label, title }) => (
                    <Button
                      key={enc}
                      size="sm"
                      type="button"
                      title={title}
                      variant={encoding === enc ? 'default' : 'secondary'}
                      onClick={() => setEncoding(enc)}
                    >
                      {label}
                    </Button>
                  ))}
                </div>
                <textarea
                  value={rawBody}
                  onChange={(e) => setRawBody(e.target.value)}
                  spellCheck={false}
                  className={cn(fieldBaseClass, 'min-h-[160px] resize-y font-mono text-[11px] leading-relaxed')}
                />
                <details className="text-xs text-zinc-500">
                  <summary className="cursor-pointer hover:text-zinc-700 dark:hover:text-zinc-300">Быстро: ping, hex…</summary>
                  <div className="mt-2 flex flex-wrap gap-2">
                    <Button size="sm" type="button" variant="secondary" onClick={() => applyRawQuick('utf8_ping')}>
                      ping
                    </Button>
                    <Button size="sm" type="button" variant="secondary" onClick={() => applyRawQuick('hex_hello')}>
                      Hello
                    </Button>
                    <Button size="sm" type="button" variant="secondary" onClick={() => applyRawQuick('zeros')}>
                      32×00
                    </Button>
                    <Button size="sm" type="button" variant="secondary" onClick={() => applyRawQuick('empty')}>
                      пусто
                    </Button>
                    <span className="flex items-center gap-1">
                      <Input className="h-8 w-14 font-mono text-xs" value={fillCount} onChange={(e) => setFillCount(e.target.value)} />
                      <Input className="h-8 w-11 font-mono text-xs" value={fillByte} onChange={(e) => setFillByte(e.target.value)} />
                      <Button size="sm" type="button" variant="secondary" onClick={applyHexFill}>
                        hex
                      </Button>
                    </span>
                  </div>
                </details>
                {wirePreview.ok ? (
                  <p className="font-mono text-[10px] text-zinc-400">
                    {wirePreview.len} байт · {wirePreview.encodingLabel} · {wirePreview.hex}
                  </p>
                ) : (
                  <p className="text-sm text-amber-600 dark:text-amber-400">{wirePreview.error}</p>
                )}
              </div>
            </div>

            <div className="mt-6 flex flex-wrap items-center gap-3 border-t border-zinc-100 pt-5 dark:border-zinc-800">
              <Button className="h-10 min-w-[8rem]" onClick={send} disabled={!wirePreview.ok || !destOk || waitingPeerReply}>
                Отправить
              </Button>
              <div className="flex items-center gap-2 text-sm text-zinc-500">
                <span>Повтор</span>
                <Input
                  className="h-9 w-12 font-mono text-center text-xs"
                  value={repeat}
                  onChange={(e) => setRepeat(e.target.value)}
                  disabled={waitReply && dest === 'peer'}
                />
              </div>
              {sendHint ? <span className="text-xs text-zinc-500">{sendHint}</span> : null}
            </div>
          </div>
        </div>

        <PacketTemplatesAside
          templateByGroup={templateByGroup}
          selectedTemplateId={selectedTemplateId}
          selectedTemplate={selectedTemplate}
          onPickTemplate={pickTemplate}
        />
      </div>

      <PacketSendResult lastCommandResult={lastCommandResult} waitingForPeerReply={waitingPeerReply} />
    </div>
  )
}
