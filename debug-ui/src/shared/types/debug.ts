export type Snapshot = {
  node?: {
    peer_id?: string
    role?: string
    active_peers?: number
    known_peers?: number
    descriptor_count?: number
    policy?: {
      min_active_peers?: number
      target_active_peers?: number
      max_active_peers?: number
    }
    score_weights?: Record<string, number>
  }
  sessions_by_protocol?: Array<{
    kind: string
    sessions: number
    packets_sent: number
    packets_received: number
    bytes_sent: number
    bytes_received: number
    send_errors: number
    receive_errors: number
  }>
  sessions?: Array<{
    session_id: string
    peer_id?: string | null
    protocol: string
    is_active: boolean
    packets_sent: number
    packets_received: number
    bytes_sent: number
    bytes_received: number
    send_errors: number
    receive_errors: number
    reconnections: number
    uptime_secs: number
    last_activity_secs_ago: number
  }>
  topology?: {
    self_peer_id?: string
    neighbors?: Array<{
      peer_id: string
      observed_addrs?: string[]
      active_connections?: number
      accepts_new_sessions?: boolean
      bootstrap_entry?: boolean
      is_connected?: boolean
    }>
    edges?: Array<{
      source: string
      target: string
      connected: boolean
    }>
  }
  db?: {
    enabled?: boolean
    path?: string
    db_file_bytes?: number
    blobs_bytes?: number
    stored_files_count?: number
    cached_descriptors_count?: number
    cached_peer_scores_count?: number
  }
}

export type CommandResult = {
  event?: string
  ts_ms?: number
  ok?: boolean
  cmd?: string
  error?: string
  [key: string]: unknown
}

export type HelloPayload = {
  event?: string
  ts_ms?: number
  peer_id?: string
  push_interval_ms?: number
  commands?: string[]
}

export type DbTables = {
  storage_files?: Array<Record<string, unknown>>
  peer_descriptors?: Array<Record<string, unknown>>
  peer_scores?: Array<Record<string, unknown>>
}

export type PeerRowsPayload = {
  event?: 'peer_rankings' | 'peer_rollup'
  ts_ms?: number
  rows?: Array<Record<string, unknown>>
}

export type FileLookupPayload = {
  event?: 'file_lookup'
  ts_ms?: number
  ok?: boolean
  found?: boolean
  error?: string
  file?: Record<string, unknown>
}

export type ThemeMode = 'dark' | 'light' | 'system'
