import type { TemplateApplySetters } from '../model/types'

export function applyTemplateId(id: string, setters: TemplateApplySetters) {
  const { setEncoding, setRawBody } = setters
  if (id === 'raw_ping') {
    setEncoding('utf8')
    setRawBody('ping')
    return
  }
  if (id === 'raw_pong') {
    setEncoding('utf8')
    setRawBody('pong')
    return
  }
  if (id === 'raw_empty') {
    setEncoding('utf8')
    setRawBody('')
    return
  }
  const now = Date.now()
  const nc = (type: string, payload: Record<string, unknown>) => {
    setEncoding('json')
    setRawBody(JSON.stringify({ type, payload }, null, 0))
  }
  if (id === 'nc_RequestPeers') nc('RequestPeers', { limit: 16 })
  else if (id === 'nc_RequestDescriptors') nc('RequestDescriptors', { limit: 8 })
  else if (id === 'nc_RequestAdjacency') nc('RequestAdjacency', {})
  else if (id === 'nc_RequestCapabilities') nc('RequestCapabilities', { limit: 8 })
  else if (id === 'nc_FindRelays') nc('FindRelays', { limit: 8 })
  else if (id === 'nc_FindProviders') nc('FindProviders', { limit: 8 })
  else if (id === 'nc_PingPeerQuality') nc('PingPeerQuality', { nonce: now, timestamp_ms: now })
}
