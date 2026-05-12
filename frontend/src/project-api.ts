import { readStoredAuthSession } from './lib/auth-session'

export type ApiEnvelope<T> = {
  success: boolean
  message?: string
  data: T
}

type AuthMode = 'none' | 'optional' | 'required'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, '') ?? ''

export async function projectApiRequest<T>(
  path: string,
  init: RequestInit = {},
  authMode: AuthMode = 'none',
): Promise<T> {
  const headers = new Headers(init.headers)
  headers.set('Accept', 'application/json')

  if (init.body && !headers.has('Content-Type') && !(init.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json')
  }

  const session = readStoredAuthSession()
  if (session?.accessToken) {
    headers.set('Authorization', `${session.tokenType} ${session.accessToken}`)
  } else if (authMode === 'required') {
    throw new Error('로그인이 필요합니다.')
  }

  const response = await fetch(`${API_BASE_URL}${path}`, { ...init, headers })
  const payload = await response.json().catch(() => null) as ApiEnvelope<T> | null

  if (!response.ok || !payload?.success) {
    throw new Error(payload?.message ?? `Request failed with status ${response.status}`)
  }

  return payload.data
}
