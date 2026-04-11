export type PacketDest = 'peer' | 'session'

export type PayloadEncoding = 'utf8' | 'json' | 'hex' | 'base64'

export type PacketTemplate = {
  id: string
  label: string
  group: string
  description: string
}

export type TemplateApplySetters = {
  setEncoding: (e: PayloadEncoding) => void
  setRawBody: (s: string) => void
}
