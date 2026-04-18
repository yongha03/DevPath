import type {
  AdminAccount,
  AdminDashboardOverview,
  AdminModerationReport,
  AdminPendingCourse,
  AdminRoadmapNode,
  AdminTag,
} from '../types/admin'
import type { ApiResponse } from '../types/home'
import { expireStoredAuthSession, readStoredAuthSession } from './auth-session'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, '') ?? ''

async function request<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  // 관리자 API 공통 요청에서 인증 헤더와 응답 검증을 함께 처리한다.
  const headers = new Headers(init.headers)
  headers.set('Accept', 'application/json')

  if (init.body && !headers.has('Content-Type') && !(init.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json')
  }

  const session = readStoredAuthSession()

  if (session?.accessToken) {
    headers.set('Authorization', `${session.tokenType} ${session.accessToken}`)
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

  if (response.status === 401) {
    expireStoredAuthSession({ reload: true })
    throw new Error('세션이 만료되었습니다. 다시 로그인해 주세요.')
  }

  if (!response.ok || !payload?.success) {
    throw new Error(payload?.message ?? `Request failed with status ${response.status}`)
  }

  return payload.data
}

function updateAccountStatus(userId: number, action: 'restrict' | 'restore', reason: string) {
  // 계정 제한과 복구는 같은 경로 구조를 공유한다.
  return request<void>(`/api/admin/accounts/${userId}/${action}`, {
    method: 'PATCH',
    body: JSON.stringify({ reason }),
  })
}

export const adminApi = {
  // 관리자 대시보드에서 쓰는 API만 한곳에 모은다.
  getOverview(signal?: AbortSignal) {
    return request<AdminDashboardOverview>('/api/admin/dashboard/overview', { method: 'GET', signal })
  },
  getTags(signal?: AbortSignal) {
    return request<AdminTag[]>('/api/admin/tags', { method: 'GET', signal })
  },
  createTag(payload: { name: string; description?: string | null }) {
    return request<AdminTag>('/api/admin/tags', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
  },
  mergeTags(sourceTagIds: number[], targetTagId: number) {
    return request<void>('/api/admin/tags/merge', {
      method: 'POST',
      body: JSON.stringify({ sourceTagIds, targetTagId }),
    })
  },
  getRoadmapNodes(signal?: AbortSignal) {
    return request<AdminRoadmapNode[]>('/api/admin/nodes', { method: 'GET', signal })
  },
  updateNodeRequiredTags(nodeId: number, requiredTags: string[]) {
    return request<void>(`/api/admin/nodes/${nodeId}/required-tags`, {
      method: 'PUT',
      body: JSON.stringify({ requiredTags }),
    })
  },
  updateNodeCompletionRule(
    nodeId: number,
    completionRuleDescription: string,
    requiredProgressRate: number,
  ) {
    return request<void>(`/api/admin/nodes/${nodeId}/completion-rule`, {
      method: 'PUT',
      body: JSON.stringify({ completionRuleDescription, requiredProgressRate }),
    })
  },
  getAccounts(signal?: AbortSignal) {
    return request<AdminAccount[]>('/api/admin/accounts', { method: 'GET', signal })
  },
  restrictAccount(userId: number, reason: string) {
    return updateAccountStatus(userId, 'restrict', reason)
  },
  restoreAccount(userId: number, reason: string) {
    return updateAccountStatus(userId, 'restore', reason)
  },
  getPendingCourses(signal?: AbortSignal) {
    return request<AdminPendingCourse[]>('/api/admin/courses/pending', { method: 'GET', signal })
  },
  approveCourse(courseId: number, reason: string) {
    return request<void>(`/api/admin/courses/${courseId}/approve`, {
      method: 'PATCH',
      body: JSON.stringify({ reason }),
    })
  },
  rejectCourse(courseId: number, reason: string) {
    return request<void>(`/api/admin/courses/${courseId}/reject`, {
      method: 'PATCH',
      body: JSON.stringify({ reason }),
    })
  },
  getReports(status = 'PENDING', signal?: AbortSignal) {
    return request<AdminModerationReport[]>(
      `/api/admin/moderations/reports?status=${encodeURIComponent(status)}`,
      { method: 'GET', signal },
    )
  },
  blindContent(contentId: number, reason: string) {
    return request<void>(`/api/admin/moderations/contents/${contentId}/blind`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    })
  },
  resolveReport(reportId: number, reason: string, action: 'WARNING' | 'SUSPEND' | 'DISMISS') {
    return request<void>(`/api/admin/moderations/reports/${reportId}/resolve`, {
      method: 'POST',
      body: JSON.stringify({ reason, action }),
    })
  },
}
