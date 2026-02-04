// Auth method types matching Go
export type AuthMethod = 'pin' | 'password' | 'oidc' | "link"

// Data injected by Go templates
export interface Data {
  methods?: Partial<Record<AuthMethod, string>>
}

declare global {
  interface Window {
    __DATA__?: Data
  }
}

export function getData(): Data {
  return window.__DATA__ ?? {}
}
