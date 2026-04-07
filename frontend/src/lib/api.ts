import { readStoredAuthSession } from './auth-session'
import type { AuthLoginRequest, AuthSignUpRequest, AuthTokenResponse } from '../types/auth'
import type { ApiResponse, HomeOverview } from '../types/home'
import type {
  RoadmapDetail,
  MyRoadmapSummary,
  RecommendationChange,
  RecommendationChangeHistory,
  ProofCardSummary,
} from '../types/roadmap'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, '') ?? ''

async function request<T>(
  path: string,
  init: RequestInit = {},
  options: { auth?: boolean } = {},
): Promise<T> {
  const headers = new Headers(init.headers)
  headers.set('Accept', 'application/json')

  if (init.body && !headers.has('Content-Type') && !(init.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json')
  }

  if (options.auth) {
    const session = readStoredAuthSession()

    if (session?.accessToken) {
      headers.set('Authorization', `${session.tokenType} ${session.accessToken}`)
    }
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers,
  })

  let payload: ApiResponse<T> | null = null

  try {
    payload = (await response.json()) as ApiResponse<T>
  } catch {
    payload = null
  }

  if (!response.ok || !payload?.success) {
    throw new Error(payload?.message ?? `Request failed with status ${response.status}`)
  }

  return payload.data
}

export const homeApi = {
  getOverview(signal?: AbortSignal) {
    return request<HomeOverview>('/api/home/overview', {
      method: 'GET',
      signal,
    })
  },
}

export const roadmapApi = {
  getMyRoadmaps(signal?: AbortSignal) {
    const session = readStoredAuthSession()
    const query = session?.userId ? `?userId=${session.userId}` : ''
    return request<{ roadmaps: MyRoadmapSummary[] }>(`/api/my-roadmaps${query}`, { method: 'GET', signal }, { auth: true })
  },
  getMyRoadmapDetail(customRoadmapId: number, signal?: AbortSignal) {
    const session = readStoredAuthSession()
    const query = session?.userId ? `?userId=${session.userId}` : ''
    return request<RoadmapDetail>(`/api/my-roadmaps/${customRoadmapId}${query}`, { method: 'GET', signal }, { auth: true })
  },
  copyRoadmap(originalRoadmapId: number) {
    const session = readStoredAuthSession()
    const query = session?.userId ? `?userId=${session.userId}` : ''
    return request<{ customRoadmapId: number }>(`/api/my-roadmaps/${originalRoadmapId}${query}`, { method: 'POST' }, { auth: true })
  },
  getPendingChanges(signal?: AbortSignal) {
    return request<RecommendationChange[]>('/api/me/recommendation-changes', { method: 'GET', signal }, { auth: true })
  },
  getChangeHistories(signal?: AbortSignal) {
    return request<RecommendationChangeHistory[]>('/api/me/recommendation-changes/histories', { method: 'GET', signal }, { auth: true })
  },
  applyChange(changeId: number) {
    return request<RecommendationChange>(`/api/me/recommendation-changes/${changeId}/apply`, { method: 'POST' }, { auth: true })
  },
  ignoreChange(changeId: number) {
    return request<RecommendationChange>(`/api/me/recommendation-changes/${changeId}/ignore`, { method: 'POST' }, { auth: true })
  },
  getProofCards(signal?: AbortSignal) {
    return request<ProofCardSummary[]>('/api/me/proof-cards', { method: 'GET', signal }, { auth: true })
  },
  clearNode(customRoadmapId: number, customNodeId: number) {
    const session = readStoredAuthSession()
    const query = session?.userId ? `?userId=${session.userId}` : ''
    return request<{ customNodeId: number; title: string }>(
      `/api/my-roadmaps/${customRoadmapId}/nodes/${customNodeId}/clear${query}`,
      { method: 'POST' },
      { auth: true },
    )
  },
}

export const authApi = {
  signUp(payload: AuthSignUpRequest) {
    return request<void>('/api/auth/signup', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
  },
  login(payload: AuthLoginRequest) {
    return request<AuthTokenResponse>(
      '/api/auth/login',
      {
        method: 'POST',
        body: JSON.stringify(payload),
      },
    )
  },
  logout(refreshToken: string) {
    return request<void>(
      '/api/auth/logout',
      {
        method: 'POST',
        body: JSON.stringify({ refreshToken }),
      },
      { auth: true },
    )
  },
}
