// Auth method types matching Go
export type AuthMethod = 'pin' | 'password' | 'oidc' | "link"

// Page types
export type PageType = 'auth' | 'error'

// Error data structure
export interface ErrorData {
  code: number
  title: string
  message: string
}

// Data injected by Go templates
export interface Data {
  page?: PageType
  methods?: Partial<Record<AuthMethod, string>>
  error?: ErrorData
}

declare global {
  interface Window {
    __DATA__?: Data
  }
}

export function getData(): Data {
  return window.__DATA__ ?? {}
}
