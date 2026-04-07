import type { AuthLoginRequest, AuthSignUpRequest, AuthTokenResponse } from '../types/auth'
import type {
  CourseEnrollResponse,
  CourseListItem,
  CourseReview,
  CourseWishlistMutationResponse,
} from '../types/course'
import type {
  InstructorChannel,
  InstructorSubscriptionResponse,
} from '../types/instructor'
import type {
  ApiResponse,
  HomeOverview,
} from '../types/home'
import type {
  AssignmentPrecheckRequest,
  AssignmentPrecheckResponse,
  AssignmentSubmissionResponse,
  CreateSubmissionRequest,
  LearningCourseDetail,
  LearningLessonProgress,
  LearningPlayerConfig,
  QuizAttemptResultResponse,
  SubmissionHistoryResponse,
  SubmitQuizAttemptRequest,
  TimestampNote,
  TimestampNotePayload,
} from '../types/learning'
import type {
  CertificateDetail,
  CertificateDownloadHistoryDetail,
  CertificatePdfDetail,
  DashboardStudyGroup,
  DashboardSummary,
  Enrollment,
  HeatmapEntry,
  LearningHistoryDetail,
  LearningHistorySummary,
  NotificationItem,
  PostPage,
  ProofCardDetail,
  ProofCardGalleryItem,
  ProofCardSummary,
  RefundItem,
  TechTag,
  UserPasswordChangeRequest,
  UserProfile,
  UserProfileUpdateRequest,
  WishlistCourse,
} from '../types/learner'
import type {
  RoadmapDetail,
  MyRoadmapSummary,
  RecommendationChange,
  RecommendationChangeHistory,
} from '../types/roadmap'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, '') ?? ''

type RequestOptions = {
  auth?: boolean
}

function buildQueryString(params: Record<string, string | number | boolean | null | undefined>) {
  const searchParams = new URLSearchParams()

  Object.entries(params).forEach(([key, value]) => {
    if (value === null || value === undefined || value === '') {
      return
    }

    searchParams.set(key, String(value))
  })

  const query = searchParams.toString()

  return query ? `?${query}` : ''
}

async function request<T>(
  path: string,
  init: RequestInit = {},
  options: RequestOptions = {},
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
    return request<HomeOverview>('/api/home/overview', { method: 'GET', signal })
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
    return request<AuthTokenResponse>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
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

export const dashboardApi = {
  getSummary(signal?: AbortSignal) {
    return request<DashboardSummary>('/api/me/dashboard/summary', { method: 'GET', signal }, { auth: true })
  },
  getHeatmap(signal?: AbortSignal) {
    return request<HeatmapEntry[]>('/api/me/dashboard/heatmap', { method: 'GET', signal }, { auth: true })
  },
  getStudyGroup(signal?: AbortSignal) {
    return request<DashboardStudyGroup>(
      '/api/me/dashboard/study-group',
      { method: 'GET', signal },
      { auth: true },
    )
  },
}

export const enrollmentApi = {
  enroll(courseId: number) {
    return request<CourseEnrollResponse>(
      '/api/me/enrollments',
      {
        method: 'POST',
        body: JSON.stringify({ courseId }),
      },
      { auth: true },
    )
  },
  getMyEnrollments(signal?: AbortSignal) {
    return request<Enrollment[]>('/api/me/enrollments', { method: 'GET', signal }, { auth: true })
  },
}

export const courseApi = {
  getCourses(signal?: AbortSignal) {
    return request<CourseListItem[]>('/api/courses', { method: 'GET', signal }, { auth: true })
  },
  getCourseDetail(courseId: number, signal?: AbortSignal) {
    return request<LearningCourseDetail>(`/api/courses/${courseId}`, { method: 'GET', signal }, { auth: true })
  },
}

export const lessonSessionApi = {
  startSession(lessonId: number, signal?: AbortSignal) {
    return request<LearningLessonProgress>(
      `/api/learning/sessions/${lessonId}/start`,
      { method: 'POST', signal },
      { auth: true },
    )
  },
  getProgress(lessonId: number, signal?: AbortSignal) {
    return request<LearningLessonProgress>(
      `/api/learning/sessions/${lessonId}/progress`,
      { method: 'GET', signal },
      { auth: true },
    )
  },
  saveProgress(lessonId: number, payload: { progressPercent: number; progressSeconds: number }) {
    return request<LearningLessonProgress>(
      `/api/learning/sessions/${lessonId}/progress`,
      {
        method: 'PUT',
        body: JSON.stringify(payload),
      },
      { auth: true },
    )
  },
}

export const learningPlayerApi = {
  getPlayerConfig(lessonId: number, signal?: AbortSignal) {
    return request<LearningPlayerConfig>(
      `/api/learning/player/${lessonId}/config`,
      { method: 'GET', signal },
      { auth: true },
    )
  },
  updatePlaybackRate(lessonId: number, defaultPlaybackRate: number) {
    return request<LearningPlayerConfig>(
      `/api/learning/player/${lessonId}/config`,
      {
        method: 'PUT',
        body: JSON.stringify({ defaultPlaybackRate }),
      },
      { auth: true },
    )
  },
  updatePipMode(lessonId: number, pipEnabled: boolean) {
    return request<LearningPlayerConfig>(
      `/api/learning/player/${lessonId}/config/pip`,
      {
        method: 'PATCH',
        body: JSON.stringify({ pipEnabled }),
      },
      { auth: true },
    )
  },
}

export const lessonNoteApi = {
  getNotes(lessonId: number, signal?: AbortSignal) {
    return request<TimestampNote[]>(
      `/api/learning/lessons/${lessonId}/notes`,
      { method: 'GET', signal },
      { auth: true },
    )
  },
  createNote(lessonId: number, payload: TimestampNotePayload) {
    return request<TimestampNote>(
      `/api/learning/lessons/${lessonId}/notes`,
      {
        method: 'POST',
        body: JSON.stringify(payload),
      },
      { auth: true },
    )
  },
  updateNote(lessonId: number, noteId: number, payload: TimestampNotePayload) {
    return request<TimestampNote>(
      `/api/learning/lessons/${lessonId}/notes/${noteId}`,
      {
        method: 'PUT',
        body: JSON.stringify(payload),
      },
      { auth: true },
    )
  },
  deleteNote(lessonId: number, noteId: number) {
    return request<void>(
      `/api/learning/lessons/${lessonId}/notes/${noteId}`,
      { method: 'DELETE' },
      { auth: true },
    )
  },
}

export const learnerAssignmentApi = {
  precheck(assignmentId: number, userId: number, payload: AssignmentPrecheckRequest) {
    return request<AssignmentPrecheckResponse>(
      `/api/evaluation/learner/assignments/${assignmentId}/precheck${buildQueryString({ userId })}`,
      {
        method: 'POST',
        body: JSON.stringify(payload),
      },
      { auth: true },
    )
  },
  submit(assignmentId: number, userId: number, payload: CreateSubmissionRequest) {
    return request<AssignmentSubmissionResponse>(
      `/api/evaluation/learner/assignments/${assignmentId}/submissions${buildQueryString({ userId })}`,
      {
        method: 'POST',
        body: JSON.stringify(payload),
      },
      { auth: true },
    )
  },
  getSubmissionHistory(userId: number, signal?: AbortSignal) {
    return request<SubmissionHistoryResponse>(
      `/api/evaluation/learner/assignments/submissions/history${buildQueryString({ userId })}`,
      { method: 'GET', signal },
      { auth: true },
    )
  },
}

export const learnerQuizApi = {
  submitAttempt(quizId: number, userId: number, payload: SubmitQuizAttemptRequest) {
    return request<QuizAttemptResultResponse>(
      `/api/evaluation/learner/quizzes/${quizId}/attempts${buildQueryString({ userId })}`,
      {
        method: 'POST',
        body: JSON.stringify(payload),
      },
      { auth: true },
    )
  },
  getAttemptResult(attemptId: number, userId: number, signal?: AbortSignal) {
    return request<QuizAttemptResultResponse>(
      `/api/evaluation/learner/quizzes/attempts/${attemptId}/result${buildQueryString({ userId })}`,
      { method: 'GET', signal },
      { auth: true },
    )
  },
}

export const learningHistoryApi = {
  getDetail(signal?: AbortSignal) {
    return request<LearningHistoryDetail>(
      '/api/me/learning-histories',
      { method: 'GET', signal },
      { auth: true },
    )
  },
  getSummary(signal?: AbortSignal) {
    return request<LearningHistorySummary>(
      '/api/me/learning-histories/summary',
      { method: 'GET', signal },
      { auth: true },
    )
  },
}

export const proofCardApi = {
  getCards(signal?: AbortSignal) {
    return request<ProofCardSummary[]>('/api/me/proof-cards', { method: 'GET', signal }, { auth: true })
  },
  getCard(proofCardId: number, signal?: AbortSignal) {
    return request<ProofCardDetail>(
      `/api/me/proof-cards/${proofCardId}`,
      { method: 'GET', signal },
      { auth: true },
    )
  },
  getGallery(signal?: AbortSignal) {
    return request<ProofCardGalleryItem[]>(
      '/api/me/proof-cards/gallery',
      { method: 'GET', signal },
      { auth: true },
    )
  },
}

export const certificateApi = {
  issue(proofCardId: number) {
    return request<CertificateDetail>(
      `/api/certificates/proof-cards/${proofCardId}`,
      { method: 'POST' },
      { auth: true },
    )
  },
  generatePdf(proofCardId: number) {
    return request<CertificatePdfDetail>(
      `/api/certificates/proof-cards/${proofCardId}/pdf`,
      { method: 'POST' },
      { auth: true },
    )
  },
  recordDownload(certificateId: number, reason: string) {
    return request<CertificateDownloadHistoryDetail>(
      `/api/certificates/${certificateId}/downloads`,
      {
        method: 'POST',
        body: JSON.stringify({ reason }),
      },
      { auth: true },
    )
  },
}

export const wishlistApi = {
  addCourse(courseId: number) {
    return request<CourseWishlistMutationResponse>(
      `/api/me/wishlist/courses/${courseId}`,
      { method: 'POST' },
      { auth: true },
    )
  },
  removeCourse(courseId: number) {
    return request<CourseWishlistMutationResponse>(
      `/api/me/wishlist/courses/${courseId}`,
      { method: 'DELETE' },
      { auth: true },
    )
  },
  getCourses(signal?: AbortSignal) {
    return request<WishlistCourse[]>(
      '/api/me/wishlist/courses',
      { method: 'GET', signal },
      { auth: true },
    )
  },
}

export const notificationApi = {
  getMine(signal?: AbortSignal) {
    return request<NotificationItem[]>('/api/notifications', { method: 'GET', signal }, { auth: true })
  },
  markAsRead(notificationId: number) {
    return request<void>(`/api/notifications/${notificationId}/read`, { method: 'PATCH' }, { auth: true })
  },
}

export const refundApi = {
  getMine(signal?: AbortSignal) {
    return request<RefundItem[]>('/api/refunds/me', { method: 'GET', signal }, { auth: true })
  },
}

export const communityApi = {
  searchPosts(
    params: {
      category?: string
      authorId?: number
      keyword?: string
      sort?: string
      page?: number
      size?: number
    },
    signal?: AbortSignal,
  ) {
    return request<PostPage>(
      `/api/posts${buildQueryString(params)}`,
      { method: 'GET', signal },
      { auth: false },
    )
  },
}

export const reviewApi = {
  getByCourse(courseId: number, signal?: AbortSignal) {
    return request<CourseReview[]>(
      `/api/reviews${buildQueryString({ courseId })}`,
      { method: 'GET', signal },
      { auth: false },
    )
  },
}

export const publicInstructorApi = {
  getChannel(instructorId: number, signal?: AbortSignal) {
    return request<InstructorChannel>(
      `/api/instructors/${instructorId}/channel`,
      { method: 'GET', signal },
      { auth: false },
    )
  },
}

export const instructorSubscriptionApi = {
  subscribe(channelId: number) {
    return request<InstructorSubscriptionResponse>(
      '/api/instructor/subscriptions',
      {
        method: 'POST',
        body: JSON.stringify({ channelId }),
      },
      { auth: true },
    )
  },
  unsubscribe(channelId: number) {
    return request<void>(
      `/api/instructor/subscriptions/${channelId}`,
      { method: 'DELETE' },
      { auth: true },
    )
  },
}

export const userApi = {
  getMyProfile(signal?: AbortSignal) {
    return request<UserProfile>('/api/users/me/profile', { method: 'GET', signal }, { auth: true })
  },
  updateMyProfile(payload: UserProfileUpdateRequest) {
    return request<UserProfile>(
      '/api/users/me/profile',
      {
        method: 'PUT',
        body: JSON.stringify(payload),
      },
      { auth: true },
    )
  },
  changePassword(payload: UserPasswordChangeRequest) {
    return request<void>(
      '/api/users/me/password',
      {
        method: 'PATCH',
        body: JSON.stringify(payload),
      },
      { auth: true },
    )
  },
  getOfficialTags(signal?: AbortSignal) {
    return request<TechTag[]>('/api/users/tags/official', { method: 'GET', signal }, { auth: true })
  },
}
