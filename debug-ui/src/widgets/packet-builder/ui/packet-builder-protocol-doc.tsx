import { useMemo } from 'react'

const pre =
  'overflow-x-auto rounded-lg border border-zinc-200 bg-white p-3 font-mono text-[10px] leading-relaxed text-zinc-800 shadow-inner dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-200'

function toHexBytes(n: number[]): string {
  return n.map((b) => b.toString(16).padStart(2, '0')).join(' ')
}

export function PacketBuilderProtocolDoc() {
  const x = useMemo(() => {
    const enc = new TextEncoder()
    const sender = 'SENDER_PEER_ID'
    const dest = 'DEST_PEER_ID'

    const rpcAdj = '{"type":"RequestAdjacency","payload":{}}'
    const rpcAdjBytes = Array.from(enc.encode(rpcAdj))

    const findProv = '{"type":"FindProviders","payload":{"limit":8}}'
    const findProvBytes = Array.from(enc.encode(findProv))

    const packetAdjObj = {
      signature: null as null,
      data: rpcAdjBytes,
      nodes: [] as string[],
      sender,
      receiver: dest,
      max_hops: 8,
    }
    const packetAdjJson = JSON.stringify(packetAdjObj, null, 2)
    const packetAdjWire = enc.encode(packetAdjJson)
    const packetAdjLen = packetAdjWire.length
    const lenBe = [
      (packetAdjLen >>> 24) & 0xff,
      (packetAdjLen >>> 16) & 0xff,
      (packetAdjLen >>> 8) & 0xff,
      packetAdjLen & 0xff,
    ]

    const pingUtf8 = 'ping'
    const pingBytes = Array.from(enc.encode(pingUtf8))
    const pingHexInput = '70696e67'
    const wsSendPacket = {
      cmd: 'send_packet',
      peer_id: dest,
      data: rpcAdj,
      encoding: 'utf8',
      max_hops: 8,
    }
    const wsSendSession = {
      cmd: 'send_to_session',
      session_id: 'SESSION_ID_UUID',
      data: rpcAdj,
      encoding: 'utf8',
    }
    const wsSendHex = {
      cmd: 'send_packet',
      peer_id: dest,
      data: pingHexInput,
      encoding: 'hex',
      max_hops: 8,
    }

    return {
      sender,
      dest,
      rpcAdjBytes,
      rpcAdjHex: toHexBytes(rpcAdjBytes),
      findProv,
      findProvBytes,
      packetAdjJson,
      packetAdjLen,
      lenBe,
      lenBeHex: toHexBytes(lenBe),
      pingUtf8,
      pingBytes,
      pingHexInput,
      wsSendPacket,
      wsSendSession,
      wsSendHex,
    }
  }, [])

  const wsPacketStr = JSON.stringify(x.wsSendPacket, null, 2)
  const wsSessionStr = JSON.stringify(x.wsSendSession, null, 2)
  const wsHexStr = JSON.stringify(x.wsSendHex, null, 2)

  return (
    <details className="mb-6 rounded-xl border border-zinc-200/90 bg-zinc-50/50 dark:border-zinc-700 dark:bg-zinc-900/40">
      <summary className="cursor-pointer select-none px-4 py-3 text-sm font-medium text-zinc-800 dark:text-zinc-200">
        Как устроен пакет: цепочка и примеры (промежуточные и итог на проводе)
      </summary>
      <div className="space-y-6 border-t border-zinc-200/80 px-4 pb-4 pt-4 text-xs leading-relaxed text-zinc-600 dark:border-zinc-700 dark:text-zinc-400">
        <section className="space-y-2">
          <h3 className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">Общая цепочка</h3>
          <ol className="list-decimal space-y-2.5 pl-4">
            <li>
              В браузере вы набираете <strong className="text-zinc-800 dark:text-zinc-200">текст тела</strong> (шаг 2 конструктора) → по WebSocket уходит JSON-команда
              (например <code className="font-mono text-[10px]">send_packet</code>) с полем{' '}
              <code className="rounded bg-zinc-200/80 px-1 font-mono text-[10px] dark:bg-zinc-800">data</code> (одна строка) и{' '}
              <code className="rounded bg-zinc-200/80 px-1 font-mono text-[10px] dark:bg-zinc-800">encoding</code> (как интерпретировать строку).
            </li>
            <li>
              Нода по <code className="font-mono text-[10px]">encoding</code> превращает строку <code className="font-mono text-[10px]">data</code> в{' '}
              <strong className="text-zinc-800 dark:text-zinc-200">Vec&lt;u8&gt;</strong> и кладёт байты в{' '}
              <code className="font-mono text-[10px]">Packet.data</code>. Содержимое байтов нода не валидирует — это уже логика получателя.
            </li>
            <li>
              К этим байтам добавляются служебные поля: собирается полный <code className="font-mono text-[10px]">Packet</code> (
              <code className="font-mono text-[10px]">sender</code>, <code className="font-mono text-[10px]">receiver</code>,{' '}
              <code className="font-mono text-[10px]">nodes</code>, <code className="font-mono text-[10px]">max_hops</code>, …) и целиком сериализуется в один JSON-текст.
            </li>
            <li>
              По TCP (и аналогично по UDP) в сокет записывается одна «запись»: сначала <strong className="text-zinc-800 dark:text-zinc-200">4 байта длины фрейма (big-endian)</strong>, затем{' '}
              <strong className="text-zinc-800 dark:text-zinc-200">UTF-8 байты этого JSON</strong> — без отдельного слоя вокруг полей пакета.
            </li>
          </ol>
          <p className="text-[11px] text-zinc-500">
            Служебные сообщения сети кодируются как JSON с полями <code className="font-mono text-[10px]">type</code> и <code className="font-mono text-[10px]">payload</code>{' '}
            (см. <code className="font-mono text-[10px]">NetworkControlPayload</code> в ядре) — это содержимое внутри байтов <code className="font-mono text-[10px]">Packet.data</code>.
          </p>
          <p className="text-[11px] text-zinc-500">
            Ниже числа и JSON посчитаны в браузере так же, как при отправке; длина TCP-фрейма — для примера с короткими плейсхолдерами peer id.
          </p>
        </section>

        <section className="space-y-3">
          <h3 className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
            Пример A — <code className="font-mono">RequestAdjacency</code>
          </h3>

          <div>
            <p className="mb-1 font-medium text-zinc-800 dark:text-zinc-200">
              A1. Одна JSON-команда по WebSocket: тело в строке <code className="font-mono">data</code> → байты в{' '}
              <code className="font-mono">Packet.data</code>
            </p>
            <p className="mb-2 text-[11px] text-zinc-500">
              Это то, что уходит с шага 2 конструктора: вложенный JSON (<code className="font-mono text-[10px]">RequestAdjacency</code>) — целиком в поле{' '}
              <code className="font-mono text-[10px]">data</code>, без второго отдельного блока.
            </p>
            <pre className={pre}>{wsPacketStr}</pre>
            <p className="mt-2 text-[11px] text-zinc-500">
              На ноде из этой строки получается ровно {x.rpcAdjBytes.length} байт UTF-8 — внутри сетевого пакета они как массив 0–255:
            </p>
            <pre className={`${pre} mt-2`}>{JSON.stringify(x.rpcAdjBytes)}</pre>
            <p className="mt-1 text-[11px] text-zinc-500">Hex: {x.rpcAdjHex}</p>
          </div>

          <div>
            <p className="mb-1 font-medium text-zinc-800 dark:text-zinc-200">
              A2. На проводе: JSON <code className="font-mono">Packet</code> + TCP-обрамление (длина BE)
            </p>
            <pre className={pre}>{x.packetAdjJson}</pre>
            <p className="mt-1 text-[11px] text-zinc-500">
              В реальности вместо плейсхолдеров — ваши peer id; роутер может добавить <code className="font-mono text-[10px]">request_id</code> и др.
            </p>
            <p className="mt-2 text-[11px]">
              Длина этого JSON: <strong className="text-zinc-800 dark:text-zinc-200">{x.packetAdjLen}</strong> байт. В сокет сначала 4 байта длины (big-endian):{' '}
              <code className="rounded bg-zinc-200/80 px-1 font-mono text-[10px] dark:bg-zinc-800">{x.lenBeHex}</code> ({x.lenBe.join(', ')}), затем UTF-8 байты JSON
              выше.
            </p>
          </div>
        </section>

        <section className="space-y-3">
          <h3 className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
            Пример B — <code className="font-mono">FindProviders</code>
          </h3>
          <p>Тело в UI:</p>
          <pre className={pre}>{x.findProv}</pre>
          <p className="text-[11px] text-zinc-500">
            Байт в <code className="font-mono text-[10px]">Packet.data</code>: {x.findProvBytes.length}. Команда WebSocket как в A1, но <code className="font-mono text-[10px]">data</code> = эта
            строка; <code className="font-mono text-[10px]">encoding</code>: <code className="font-mono text-[10px]">&quot;utf8&quot;</code> или <code className="font-mono text-[10px]">&quot;json&quot;</code>.
          </p>
        </section>

        <section className="space-y-3">
          <h3 className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">Пример C — отправка в сессию</h3>
          <pre className={pre}>{wsSessionStr}</pre>
        </section>

        <section className="space-y-3">
          <h3 className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">Пример D — тело как hex в команде</h3>
          <pre className={pre}>{wsHexStr}</pre>
          <p className="text-[11px] text-zinc-500">
            <code className="font-mono text-[10px]">70696e67</code> → <code className="font-mono text-[10px]">{JSON.stringify(x.pingBytes)}</code> («{x.pingUtf8}»).
          </p>
        </section>
      </div>
    </details>
  )
}
