import { create } from 'zustand'

export type DashboardPageKey =
  | 'connections'
  | 'overview'
  | 'network'
  | 'sessions'
  | 'packets'
  | 'database'
  | 'operations'
  | 'node_config'
export type TableName = 'storage_files' | 'peer_descriptors' | 'peer_scores'

type DashboardState = {
  view: DashboardPageKey
  activeTable: TableName
  showAllTables: boolean
  connectTransport: string
  connectAddr: string
  disconnectPeerId: string
  rawCommand: string
  knownPeerId: string
  knownPeerTransport: string
  knownPeerAddr: string
  batchConnectTransport: string
  batchConnectAddrs: string
  batchDisconnectPeers: string
  fileHashQuery: string
  sessionQuery: string
  sessionProtocolFilter: string
  setView: (v: DashboardPageKey) => void
  setActiveTable: (v: TableName) => void
  setShowAllTables: (v: boolean) => void
  setConnectTransport: (v: string) => void
  setConnectAddr: (v: string) => void
  setDisconnectPeerId: (v: string) => void
  setRawCommand: (v: string) => void
  setKnownPeerId: (v: string) => void
  setKnownPeerTransport: (v: string) => void
  setKnownPeerAddr: (v: string) => void
  setBatchConnectTransport: (v: string) => void
  setBatchConnectAddrs: (v: string) => void
  setBatchDisconnectPeers: (v: string) => void
  setFileHashQuery: (v: string) => void
  setSessionQuery: (v: string) => void
  setSessionProtocolFilter: (v: string) => void
}

export const useDashboardStore = create<DashboardState>((set) => ({
  view: 'connections',
  activeTable: 'storage_files',
  showAllTables: false,
  connectTransport: 'tcp',
  connectAddr: '127.0.0.1:8080',
  disconnectPeerId: '',
  rawCommand: '{\n  "cmd": "refresh_snapshot"\n}',
  knownPeerId: '',
  knownPeerTransport: 'tcp',
  knownPeerAddr: '127.0.0.1:8080',
  batchConnectTransport: 'tcp',
  batchConnectAddrs: '127.0.0.1:8080\n127.0.0.1:8081',
  batchDisconnectPeers: '',
  fileHashQuery: '',
  sessionQuery: '',
  sessionProtocolFilter: 'all',
  setView: (v) => set({ view: v }),
  setActiveTable: (v) => set({ activeTable: v }),
  setShowAllTables: (v) => set({ showAllTables: v }),
  setConnectTransport: (v) => set({ connectTransport: v }),
  setConnectAddr: (v) => set({ connectAddr: v }),
  setDisconnectPeerId: (v) => set({ disconnectPeerId: v }),
  setRawCommand: (v) => set({ rawCommand: v }),
  setKnownPeerId: (v) => set({ knownPeerId: v }),
  setKnownPeerTransport: (v) => set({ knownPeerTransport: v }),
  setKnownPeerAddr: (v) => set({ knownPeerAddr: v }),
  setBatchConnectTransport: (v) => set({ batchConnectTransport: v }),
  setBatchConnectAddrs: (v) => set({ batchConnectAddrs: v }),
  setBatchDisconnectPeers: (v) => set({ batchDisconnectPeers: v }),
  setFileHashQuery: (v) => set({ fileHashQuery: v }),
  setSessionQuery: (v) => set({ sessionQuery: v }),
  setSessionProtocolFilter: (v) => set({ sessionProtocolFilter: v }),
}))
