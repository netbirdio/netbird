// Auth method types matching Go
export type AuthMethod = 'pin' | 'password' | 'oidc' | "link"

// Page types
export type PageType = 'auth' | 'error'

// Error data structure
export interface ErrorData {
  code: number
  title: string
  message: string
  proxy?: boolean
  peer?: boolean
  destination?: boolean
  requestId?: string
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
  const data = window.__DATA__ ?? {}

  // Dev mode: allow ?page=error query param to preview error page
  if (import.meta.env.DEV) {
    const params = new URLSearchParams(window.location.search)
    const page = params.get('page')
    if (page === 'error') {
      return {
        ...data,
        page: 'error',
        error: data.error ?? {
          code: 503,
          title: 'Service Unavailable',
          message: 'The service you are trying to access is temporarily unavailable. Please try again later.',
          proxy: true,
          peer: false,
          destination: false,
        },
      }
    }
  }

  return data
}
