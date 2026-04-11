import { create } from 'zustand'

type ToastVariant = 'success' | 'error' | 'info'

type ToastItem = { id: number; message: string; variant: ToastVariant }

type State = {
  toasts: ToastItem[]
  push: (message: string, variant: ToastVariant) => void
  dismiss: (id: number) => void
}

export const useDebugToastStore = create<State>((set, get) => ({
  toasts: [],
  push: (message, variant) => {
    const id = Date.now() + Math.random()
    set((s) => ({ toasts: [...s.toasts, { id, message, variant }] }))
    window.setTimeout(() => get().dismiss(id), 4200)
  },
  dismiss: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
}))
