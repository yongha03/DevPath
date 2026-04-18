import type { AuthSession, AuthTokenClaims, AuthTokenResponse } from '../types/auth'
import {
  EXPIRED_AUTH_TOAST_MESSAGE,
  LOGIN_SUCCESS_AUTH_TOAST_MESSAGE,
  LOGOUT_AUTH_TOAST_MESSAGE,
  queueAuthToast,
  showAuthToast,
} from './auth-toast'

const AUTH_STORAGE_KEY = 'devpath.auth.session'
const EXPIRY_SKEW_MS = 1000

let expiryTimeoutId: number | null = null

export const AUTH_SESSION_SYNC_EVENT = 'devpath:auth-session-sync'

type AuthToastOptions = {
  persistToast?: boolean
  toastMessage?: string | null
}

function decodeBase64Url(value: string) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
  const paddingLength = (4 - (normalized.length % 4)) % 4
  const padded = normalized.padEnd(normalized.length + paddingLength, '=')

  return window.atob(padded)
}

export function parseTokenClaims(accessToken: string): AuthTokenClaims {
  // 액세스 토큰에서 사용자 식별자와 권한 정보를 꺼낸다.
  try {
    const [, payload] = accessToken.split('.')

    if (!payload) {
      return { userId: null, role: null, exp: null }
    }

    const decoded = JSON.parse(decodeBase64Url(payload)) as {
      sub?: string
      role?: string
      exp?: number
    }

    const userId = decoded.sub ? Number(decoded.sub) : null

    return {
      userId: Number.isFinite(userId) ? userId : null,
      role: decoded.role ?? null,
      exp: decoded.exp ?? null,
    }
  } catch {
    return { userId: null, role: null, exp: null }
  }
}

function buildSession(
  response: AuthTokenResponse,
  storage: AuthSession['storage'],
): AuthSession {
  const claims = parseTokenClaims(response.accessToken)

  return {
    ...response,
    ...claims,
    storage,
  }
}

function writeToStorage(storage: Storage, session: AuthSession) {
  storage.setItem(AUTH_STORAGE_KEY, JSON.stringify(session))
}

function notifyAuthSessionChanged() {
  window.dispatchEvent(new Event(AUTH_SESSION_SYNC_EVENT))
}

function emitAuthToast(message: string | null | undefined, options?: AuthToastOptions) {
  if (!message) {
    return
  }

  if (options?.persistToast) {
    queueAuthToast(message)
    return
  }

  showAuthToast(message)
}

function readFromStorage(storage: Storage): AuthSession | null {
  const raw = storage.getItem(AUTH_STORAGE_KEY)

  if (!raw) {
    return null
  }

  try {
    return JSON.parse(raw) as AuthSession
  } catch {
    storage.removeItem(AUTH_STORAGE_KEY)
    return null
  }
}

function clearExpiryTimer() {
  if (expiryTimeoutId !== null) {
    window.clearTimeout(expiryTimeoutId)
    expiryTimeoutId = null
  }
}

function getStoredSessionRaw() {
  return readFromStorage(localStorage) ?? readFromStorage(sessionStorage)
}

function isSessionExpired(session: AuthSession, nowMs = Date.now()) {
  if (!session.exp) {
    return false
  }

  return session.exp * 1000 <= nowMs + EXPIRY_SKEW_MS
}

function scheduleSessionExpiry(session: AuthSession) {
  // 토큰 만료 시점에 맞춰 세션 정리 동작을 예약한다.
  clearExpiryTimer()

  if (!session.exp) {
    return
  }

  const expiresAtMs = session.exp * 1000
  const delayMs = expiresAtMs - Date.now() - EXPIRY_SKEW_MS

  if (delayMs <= 0) {
    expireStoredAuthSession({ reload: false })
    return
  }

  expiryTimeoutId = window.setTimeout(() => {
    expireStoredAuthSession({ reload: true })
  }, delayMs)
}

export function persistAuthSession(
  response: AuthTokenResponse,
  remember: boolean,
  options?: AuthToastOptions,
): AuthSession {
  const targetStorage = remember ? localStorage : sessionStorage
  const otherStorage = remember ? sessionStorage : localStorage
  const storage = remember ? 'local' : 'session'
  const session = buildSession(response, storage)

  otherStorage.removeItem(AUTH_STORAGE_KEY)
  writeToStorage(targetStorage, session)
  scheduleSessionExpiry(session)
  notifyAuthSessionChanged()
  emitAuthToast(options?.toastMessage ?? LOGIN_SUCCESS_AUTH_TOAST_MESSAGE, options)

  return session
}

export function readStoredAuthSession(): AuthSession | null {
  // 저장된 세션을 읽을 때마다 만료 여부를 다시 점검한다.
  const session = getStoredSessionRaw()

  if (!session) {
    clearExpiryTimer()
    return null
  }

  if (isSessionExpired(session)) {
    expireStoredAuthSession({ reload: false })
    return null
  }

  scheduleSessionExpiry(session)
  return session
}

export function clearStoredAuthSession(options?: AuthToastOptions) {
  clearExpiryTimer()
  localStorage.removeItem(AUTH_STORAGE_KEY)
  sessionStorage.removeItem(AUTH_STORAGE_KEY)
  notifyAuthSessionChanged()
  emitAuthToast(options?.toastMessage ?? LOGOUT_AUTH_TOAST_MESSAGE, options)
}

export function expireStoredAuthSession(options?: { reload?: boolean }) {
  const { reload = true } = options ?? {}
  const session = getStoredSessionRaw()

  clearExpiryTimer()

  if (!session) {
    return
  }

  localStorage.removeItem(AUTH_STORAGE_KEY)
  sessionStorage.removeItem(AUTH_STORAGE_KEY)
  notifyAuthSessionChanged()

  queueAuthToast(EXPIRED_AUTH_TOAST_MESSAGE)

  if (!reload) {
    showAuthToast(EXPIRED_AUTH_TOAST_MESSAGE)
  }

  if (reload) {
    window.location.reload()
  }
}

export function updateStoredAuthSession(patch: Partial<Pick<AuthSession, 'name'>>) {
  const session = readStoredAuthSession()

  if (!session) {
    return null
  }

  const nextSession: AuthSession = {
    ...session,
    ...patch,
  }

  const targetStorage = session.storage === 'local' ? localStorage : sessionStorage
  writeToStorage(targetStorage, nextSession)
  scheduleSessionExpiry(nextSession)
  notifyAuthSessionChanged()

  return nextSession
}

export function getRoleLabel(role: string | null) {
  switch (role) {
    case 'ROLE_ADMIN':
      return '\uAD00\uB9AC\uC790'
    case 'ROLE_INSTRUCTOR':
      return '\uAC15\uC0AC'
    case 'ROLE_LEARNER':
      return '\uD559\uC2B5\uC790'
    default:
      return '\uC0AC\uC6A9\uC790'
  }
}

export function getPostLoginRedirect(role: string | null) {
  // 관리자만 전용 HTML 엔트리로 보내고 나머지는 홈으로 유지한다.
  switch (role) {
    case 'ROLE_ADMIN':
      return '/admin-dashboard.html'
    case 'ROLE_INSTRUCTOR':
    case 'ROLE_LEARNER':
    default:
      return '/'
  }
}
