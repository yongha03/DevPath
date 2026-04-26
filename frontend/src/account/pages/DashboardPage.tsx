import { useEffect, useState } from 'react'
import { dashboardApi, enrollmentApi, learningHistoryApi, notificationApi, proofCardApi, roadmapApi } from '../../lib/api'
import { LearnerContentRow, LearnerPageShell, MyMenuSidebar } from '../template'
import type { AuthSession } from '../../types/auth'
import type {
  DashboardMentoring,
  DashboardStudyGroup,
  DashboardSummary,
  Enrollment,
  GrowthRecommendation,
  HeatmapEntry,
  LearningHistorySummary,
  NotificationItem,
  ProofCardGalleryItem,
} from '../../types/learner'
import type { MyRoadmapSummary, RoadmapDetail, RoadmapNodeItem } from '../../types/roadmap'

type DashboardState = {
  summary: DashboardSummary
  heatmap: HeatmapEntry[]
  mentoring: DashboardMentoring
  studyGroup: DashboardStudyGroup
  notifications: NotificationItem[]
  historySummary: LearningHistorySummary
  enrollments: Enrollment[]
  roadmapSummary: MyRoadmapSummary | null
  roadmap: RoadmapDetail | null
  proofCards: ProofCardGalleryItem[]
  growthRecommendation: GrowthRecommendation | null
}

const emptyState: DashboardState = {
  summary: {
    currentStreak: 0,
    totalStudyHours: 0,
    completedNodes: 0,
  },
  heatmap: [],
  mentoring: {
    joinedProjectCount: 0,
    applicationCount: 0,
    pendingApplicationCount: 0,
    latestProject: null,
    latestApplication: null,
  },
  studyGroup: {
    joinedGroupCount: 0,
    recruitingGroupCount: 0,
    inProgressGroupCount: 0,
    groups: [],
  },
  notifications: [],
  historySummary: {
    completedNodeCount: 0,
    proofCardCount: 0,
    tilCount: 0,
    publishedTilCount: 0,
    assignmentSubmissionCount: 0,
    passedAssignmentCount: 0,
    supplementRecommendationCount: 0,
  },
  enrollments: [],
  roadmapSummary: null,
  roadmap: null,
  proofCards: [],
  growthRecommendation: null,
}

function formatStudyTime(hoursValue: number | null | undefined) {
  const totalMinutes = Math.max(0, Math.round((hoursValue ?? 0) * 60))
  return {
    hours: Math.floor(totalMinutes / 60),
    minutes: totalMinutes % 60,
  }
}

function buildWeeklyBars(heatmap: HeatmapEntry[]) {
  const labels = ['월', '화', '수', '목', '금', '토', '일']
  const recent = heatmap.slice(-7)

  return labels.map((label, index) => {
    const item = recent[index]
    const activity = item?.activityLevel ?? 0
    const height = activity > 0 ? Math.max(10, Math.min(80, activity * 16)) : 0

    return {
      label,
      height,
      tone: activity >= 3 ? 'bg-brand' : activity >= 1 ? 'bg-green-300' : 'bg-gray-200',
      active: activity >= 1,
    }
  })
}

function buildSidebarNodes(nodes: RoadmapNodeItem[]) {
  const sorted = [...nodes]
    .filter((node) => node.branchGroup == null)
    .sort((left, right) => left.sortOrder - right.sortOrder)

  if (sorted.length <= 5) {
    return sorted
  }

  const currentIndex = sorted.findIndex((node) => node.status === 'IN_PROGRESS')
  const pendingIndex = sorted.findIndex((node) => node.status === 'PENDING')
  const anchorIndex = currentIndex >= 0 ? currentIndex : pendingIndex >= 0 ? pendingIndex : sorted.length - 1
  let start = Math.max(0, anchorIndex - 1)

  if (start + 5 > sorted.length) {
    start = sorted.length - 5
  }

  return sorted.slice(start, start + 5)
}

function getRoadmapFocusNode(nodes: RoadmapNodeItem[]) {
  const sorted = [...nodes]
    .filter((node) => node.branchGroup == null)
    .sort((left, right) => left.sortOrder - right.sortOrder)

  return (
    sorted.find((node) => node.status === 'IN_PROGRESS') ??
    sorted.find((node) => node.status === 'PENDING') ??
    sorted.at(-1) ??
    null
  )
}

function getRoadmapNodeStatusLabel(node: RoadmapNodeItem) {
  switch (node.status) {
    case 'COMPLETED':
      return '완료'
    case 'IN_PROGRESS':
      return '학습 중'
    case 'LOCKED':
      return '잠금'
    default:
      return '대기'
  }
}

function getRoadmapNodeTone(node: RoadmapNodeItem) {
  switch (node.status) {
    case 'COMPLETED':
      return {
        dot: 'border-emerald-500 bg-emerald-500 text-white shadow-emerald-100',
        card: 'border-emerald-100 bg-emerald-50/70 text-emerald-900',
        chip: 'bg-emerald-100 text-emerald-700',
      }
    case 'IN_PROGRESS':
      return {
        dot: 'border-sky-500 bg-white text-sky-500 shadow-sky-100',
        card: 'border-sky-200 bg-sky-50/80 text-slate-900',
        chip: 'bg-sky-100 text-sky-700',
      }
    case 'LOCKED':
      return {
        dot: 'border-slate-300 bg-slate-100 text-slate-400 shadow-slate-100',
        card: 'border-slate-200 bg-slate-50 text-slate-500',
        chip: 'bg-slate-200 text-slate-500',
      }
    default:
      return {
        dot: 'border-violet-300 bg-violet-50 text-violet-500 shadow-violet-100',
        card: 'border-violet-100 bg-violet-50/70 text-slate-800',
        chip: 'bg-violet-100 text-violet-700',
      }
  }
}

function getRoadmapActivityAt(roadmapSummary: MyRoadmapSummary | null) {
  return roadmapSummary?.lastStudiedAt ?? roadmapSummary?.updatedAt ?? roadmapSummary?.createdAt ?? null
}

function getRoadmapActivityTimestamp(roadmapSummary: MyRoadmapSummary) {
  const activityAt = roadmapSummary.lastStudiedAt ?? roadmapSummary.updatedAt ?? roadmapSummary.createdAt
  return activityAt ? new Date(activityAt).getTime() : 0
}

function formatRelativeTime(createdAt: string | null | undefined) {
  if (!createdAt) return ''

  const diffMs = Date.now() - new Date(createdAt).getTime()
  const minutes = Math.floor(diffMs / (1000 * 60))

  if (minutes < 60) return `${Math.max(1, minutes)}분 전`

  const hours = Math.floor(diffMs / (1000 * 60 * 60))
  if (hours < 24) return `${hours}시간 전`

  return `${Math.floor(diffMs / (1000 * 60 * 60 * 24))}일 전`
}

function calcDDay(plannedEndDate: string | null | undefined) {
  if (!plannedEndDate) return ''

  const diff = Math.ceil((new Date(plannedEndDate).getTime() - Date.now()) / (1000 * 60 * 60 * 24))
  if (diff < 0) return '종료'
  if (diff === 0) return 'D-Day'
  return `D-${diff}`
}

function statusClass(status: string | null | undefined) {
  switch (status) {
    case 'IN_PROGRESS':
      return 'bg-blue-50 text-blue-600'
    case 'RECRUITING':
      return 'bg-green-50 text-green-600'
    default:
      return 'bg-gray-100 text-gray-500'
  }
}

function mentoringStatusClass(status: string | null | undefined) {
  switch (status) {
    case 'APPROVED':
    case 'COMPLETED':
      return 'bg-green-50 text-green-600'
    case 'UNDER_REVIEW':
    case 'IN_PROGRESS':
      return 'bg-blue-50 text-blue-600'
    case 'PENDING':
      return 'bg-amber-50 text-amber-600'
    case 'REJECTED':
    case 'ON_HOLD':
      return 'bg-rose-50 text-rose-600'
    case 'PREPARING':
      return 'bg-gray-100 text-gray-600'
    default:
      return 'bg-gray-100 text-gray-500'
  }
}

function mentoringStatusLabel(status: string | null | undefined) {
  switch (status) {
    case 'APPROVED':
      return '승인됨'
    case 'UNDER_REVIEW':
      return '검토 중'
    case 'PENDING':
      return '대기 중'
    case 'REJECTED':
      return '반려됨'
    case 'PREPARING':
      return '준비 중'
    case 'IN_PROGRESS':
      return '진행 중'
    case 'COMPLETED':
      return '완료'
    case 'ON_HOLD':
      return '보류'
    default:
      return '신청 없음'
  }
}

function clampProgress(value: number | null | undefined) {
  return Math.max(0, Math.min(100, Math.round(value ?? 0)))
}

export default function DashboardPage({ session }: { session: AuthSession }) {
  const [state, setState] = useState<DashboardState>(emptyState)

  useEffect(() => {
    const controller = new AbortController()
    const { signal } = controller

    async function loadDashboard() {
      const [
        summaryResult,
        heatmapResult,
        mentoringResult,
        studyGroupResult,
        notificationResult,
        historySummaryResult,
        enrollmentResult,
        proofCardsResult,
        growthRecommendationResult,
      ] = await Promise.allSettled([
        dashboardApi.getSummary(signal),
        dashboardApi.getHeatmap(signal),
        dashboardApi.getMentoring(signal),
        dashboardApi.getStudyGroup(signal),
        notificationApi.getMine(signal),
        learningHistoryApi.getSummary(signal),
        enrollmentApi.getMyEnrollments(signal),
        proofCardApi.getGallery(signal),
        dashboardApi.getGrowthRecommendation(signal),
      ])

      setState((current) => ({
        ...current,
        summary: summaryResult.status === 'fulfilled' ? summaryResult.value : current.summary,
        heatmap: heatmapResult.status === 'fulfilled' ? heatmapResult.value : current.heatmap,
        mentoring: mentoringResult.status === 'fulfilled' ? mentoringResult.value : current.mentoring,
        studyGroup: studyGroupResult.status === 'fulfilled' ? studyGroupResult.value : current.studyGroup,
        notifications: notificationResult.status === 'fulfilled' ? notificationResult.value : current.notifications,
        historySummary:
          historySummaryResult.status === 'fulfilled' ? historySummaryResult.value : current.historySummary,
        enrollments: enrollmentResult.status === 'fulfilled' ? enrollmentResult.value : current.enrollments,
        proofCards: proofCardsResult.status === 'fulfilled' ? proofCardsResult.value : current.proofCards,
        growthRecommendation:
          growthRecommendationResult.status === 'fulfilled'
            ? growthRecommendationResult.value
            : current.growthRecommendation,
      }))
    }

    async function loadRoadmap() {
      try {
        const listResult = await roadmapApi.getMyRoadmaps(signal)
        const selectedRoadmap = [...listResult.roadmaps].sort(
          (left, right) => getRoadmapActivityTimestamp(right) - getRoadmapActivityTimestamp(left),
        )[0]
        if (!selectedRoadmap) {
          setState((current) => ({ ...current, roadmapSummary: null, roadmap: null }))
          return
        }

        const detail = await roadmapApi.getMyRoadmapDetail(selectedRoadmap.customRoadmapId, signal)
        setState((current) => ({ ...current, roadmapSummary: selectedRoadmap, roadmap: detail }))
      } catch {
        setState((current) => ({ ...current, roadmapSummary: null, roadmap: null }))
      }
    }

    void loadDashboard()
    void loadRoadmap()

    return () => controller.abort()
  }, [])

  const completedCourses = state.enrollments.filter((item) => item.status === 'COMPLETED').length
  const proofCardCount = state.historySummary.proofCardCount ?? 0
  const studyTime = formatStudyTime(state.summary.totalStudyHours)
  const recentEnrollment =
    [...state.enrollments].sort(
      (left, right) =>
        new Date(right.lastAccessedAt ?? right.enrolledAt ?? 0).getTime() -
        new Date(left.lastAccessedAt ?? left.enrolledAt ?? 0).getTime(),
    )[0] ?? null
  const weeklyBars = buildWeeklyBars(state.heatmap)
  const mentoring = state.mentoring
  const studyGroup = state.studyGroup.groups[0] ?? null
  const dDay = calcDDay(studyGroup?.plannedEndDate)
  const communityItems = state.notifications.slice(0, 2)
  const mentoringActivityAt = mentoring.latestApplication?.createdAt ?? mentoring.latestProject?.joinedAt
  const mentoringHasData = Boolean(mentoring.latestProject || mentoring.latestApplication)
  const roadmapProgress = state.roadmap
    ? clampProgress(state.roadmap.progressRate)
    : clampProgress(recentEnrollment?.progressPercentage)
  const sidebarNodes = state.roadmap ? buildSidebarNodes(state.roadmap.nodes) : []
  const roadmapFocusNode = state.roadmap ? getRoadmapFocusNode(state.roadmap.nodes) : null
  const roadmapFocusProgress =
    roadmapFocusNode?.status === 'IN_PROGRESS'
      ? clampProgress((roadmapFocusNode.lessonCompletionRate ?? 0) * 100)
      : null
  const roadmapActivityAt = getRoadmapActivityAt(state.roadmapSummary)
  const roadmapCompletedNodeCount = state.roadmap
    ? state.roadmap.nodes.filter((node) => node.status === 'COMPLETED').length
    : 0
  const roadmapEntryHref = state.roadmap ? `roadmap.html?id=${state.roadmap.customRoadmapId}` : 'roadmap-hub.html'
  const growthItems = state.growthRecommendation?.recommendations ?? []

  return (
    <LearnerPageShell>
      <LearnerContentRow>
        <MyMenuSidebar currentPageKey="dashboard" wrapperClassName="w-60 shrink-0 hidden lg:block" />

        <section className="min-w-0 flex-1 space-y-6">
          <header className="mb-2 flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-gray-900">반가워요, {session.name}님</h1>
              <p className="mt-1 text-sm text-gray-500">오늘 학습 현황을 한 번에 확인해 보세요.</p>
            </div>
          </header>

          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <div className="relative rounded-2xl border border-gray-200 bg-white px-5 py-4 shadow-sm transition hover:border-brand">
              <div className="flex items-start justify-between">
                <p className="mt-1 text-xs font-bold text-gray-500">연속 학습</p>
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-orange-50 text-orange-500">
                  <i className="fas fa-fire" />
                </div>
              </div>
              <div className="mt-2">
                <span className="text-2xl font-extrabold text-gray-900">{state.summary.currentStreak ?? 0}일</span>
              </div>
              <p className="mt-1 text-[10px] text-gray-400">실제 학습 기록 기준으로 집계됩니다.</p>
            </div>

            <div className="relative rounded-2xl border border-gray-200 bg-white px-5 py-4 shadow-sm">
              <div className="flex items-start justify-between">
                <p className="mt-1 text-xs font-bold text-gray-500">완료 강의</p>
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-50 text-blue-500">
                  <i className="fas fa-check-circle" />
                </div>
              </div>
              <div className="mt-2 flex items-baseline gap-1">
                <span className="text-2xl font-extrabold text-gray-900">{completedCourses}</span>
                <span className="text-sm font-medium text-gray-400">개 완료</span>
              </div>
              <p className="mt-1 text-[10px] text-gray-400">수강 중 {state.enrollments.length}개</p>
            </div>

            <div className="relative rounded-2xl border border-gray-200 bg-white px-5 py-4 shadow-sm">
              <div className="flex items-start justify-between">
                <p className="mt-1 text-xs font-bold text-gray-500">획득 Proof</p>
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-yellow-50 text-yellow-500">
                  <i className="fas fa-medal" />
                </div>
              </div>
              <div className="mt-2">
                <span className="text-2xl font-extrabold text-gray-900">{proofCardCount}개</span>
              </div>
              <a
                href="learning-log-gallery.html"
                className="mt-1 inline-block text-[10px] font-bold text-brand hover:underline"
              >
                Proof Card 확인
              </a>
            </div>

            <div className="relative rounded-2xl border border-gray-200 bg-white px-5 py-4 shadow-sm">
              <div className="flex items-start justify-between">
                <p className="mt-1 text-xs font-bold text-gray-500">총 학습</p>
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-purple-50 text-purple-500">
                  <i className="fas fa-clock" />
                </div>
              </div>
              <div className="mt-2">
                <span className="text-2xl font-extrabold text-gray-900">
                  {studyTime.hours}h <span className="text-lg text-gray-400">{studyTime.minutes}m</span>
                </span>
              </div>
              {state.summary.studyHoursDeltaMinutes != null && state.summary.studyHoursDeltaMinutes > 0 ? (
                <p className="mt-1 text-[10px] text-gray-400">
                  어제보다 {Math.floor(state.summary.studyHoursDeltaMinutes / 60) > 0
                    ? `${Math.floor(state.summary.studyHoursDeltaMinutes / 60)}h `
                    : ''}{state.summary.studyHoursDeltaMinutes % 60}m 증가
                </p>
              ) : (
                <p className="mt-1 text-[10px] text-gray-400">수업 진도와 학습 기록이 반영됩니다.</p>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
            <div className="relative overflow-hidden rounded-2xl border border-gray-200 bg-white p-6 shadow-sm lg:col-span-2">
              <div className="mb-4 flex items-center justify-between">
                <h3 className="flex items-center gap-2 font-bold text-gray-800">
                  <i className="fas fa-play-circle text-brand" /> 최근 학습 강의
                </h3>
                <a href="my-learning.html" className="text-xs text-gray-400 hover:text-brand">
                  전체보기
                </a>
              </div>

              {recentEnrollment ? (
                <div className="flex items-center gap-5">
                  <div className="flex h-20 w-32 shrink-0 items-center justify-center overflow-hidden rounded-lg bg-gray-100">
                    {recentEnrollment.thumbnailUrl ? (
                      <img
                        src={recentEnrollment.thumbnailUrl}
                        className="h-full w-full object-cover"
                        alt={recentEnrollment.courseTitle}
                      />
                    ) : (
                      <i className="fas fa-play-circle text-2xl text-gray-300" />
                    )}
                  </div>

                  <div className="flex-1">
                    <div className="mb-1 flex items-center justify-between gap-4">
                      <h4 className="text-sm font-bold text-gray-900">{recentEnrollment.courseTitle}</h4>
                      <span className="text-lg font-extrabold text-brand">
                        {clampProgress(recentEnrollment.progressPercentage)}%
                      </span>
                    </div>
                    {state.summary.lastLessonInfo ? (
                      <p className="mb-2 text-xs text-gray-500">{state.summary.lastLessonInfo}</p>
                    ) : (
                      <p className="mb-2 text-xs text-gray-500">최근 학습한 강의의 진도가 반영됩니다.</p>
                    )}
                    <div className="mb-1 h-2 w-full rounded-full bg-gray-100">
                      <div
                        className="h-2 rounded-full bg-brand transition-all duration-1000"
                        style={{ width: `${clampProgress(recentEnrollment.progressPercentage)}%` }}
                      />
                    </div>
                  </div>

                  <button
                    className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-gray-900 text-white shadow-lg transition hover:bg-brand"
                    onClick={() => {
                      window.location.href = 'my-learning.html'
                    }}
                  >
                    <i className="fas fa-play ml-1" />
                  </button>
                </div>
              ) : (
                <div className="flex min-h-[120px] flex-col items-center justify-center rounded-xl border border-dashed border-gray-200 bg-gray-50 text-center">
                  <i className="fas fa-book-open text-2xl text-gray-200" />
                  <p className="mt-3 text-sm font-bold text-gray-500">수강 중인 강의가 없습니다.</p>
                  <p className="mt-1 text-xs text-gray-400">실제 수강 데이터가 생기면 이 영역에 자동 반영됩니다.</p>
                </div>
              )}
            </div>

            <div className="flex flex-col rounded-2xl border border-gray-200 bg-white p-6 shadow-sm">
              <div className="mb-4 flex items-center justify-between">
                <h3 className="flex items-center gap-2 text-sm font-bold text-gray-800">
                  <i className="fas fa-chart-bar text-gray-400" /> 주간 학습량
                </h3>
                <span className="text-[10px] text-gray-400">최근 7일</span>
              </div>
              <div className="flex h-24 flex-1 items-end justify-between gap-2">
                {weeklyBars.map((bar) => (
                  <div key={bar.label} className="flex h-full w-full flex-col items-center justify-end gap-1">
                    <div className="chart-bar" style={{ height: `${bar.height}%` }}>
                      <div className={`chart-bar-fill h-full ${bar.tone}`} />
                    </div>
                    <span className={`text-[10px] ${bar.active ? 'font-bold text-gray-900' : 'text-gray-400'}`}>
                      {bar.label}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
            <div className="rounded-2xl border border-gray-200 bg-white p-6 shadow-sm">
              <div className="mb-4 flex items-center justify-between">
                <h3 className="flex items-center gap-2 text-sm font-bold text-gray-800">
                  <i className="fas fa-rocket text-blue-500" /> 진행 중인 스터디
                </h3>
                <a href="project-list.html" className="text-xs text-gray-400 hover:text-brand">
                  둘러보기
                </a>
              </div>

              {studyGroup ? (
                <div className="cursor-pointer rounded-xl border border-blue-100 bg-blue-50 p-4 transition hover:shadow-md">
                  <div>
                    <div className="mb-2 flex items-center gap-2">
                      <span className="shrink-0 rounded bg-blue-500 px-2 py-0.5 text-[10px] font-bold text-white">Team</span>
                      <span className="whitespace-nowrap text-sm font-bold text-gray-900">{studyGroup.name}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      {dDay ? (
                        <span className={`shrink-0 rounded border px-2 py-0.5 text-xs font-bold ${statusClass(studyGroup.status)}`}>
                          {dDay}
                        </span>
                      ) : null}
                      <p className="whitespace-nowrap text-[11px] text-gray-500">
                        {studyGroup.status === 'IN_PROGRESS' ? '진행 중' : '모집 중'}
                      </p>
                    </div>
                  </div>

                  <div className="mt-4 flex -space-x-2">
                    {(studyGroup.memberIds ?? []).slice(0, 4).map((memberId, index) => (
                      <img
                        key={memberId}
                        className="h-8 w-8 rounded-full border-2 border-white bg-gray-200"
                        src={`https://api.dicebear.com/7.x/avataaars/svg?seed=${memberId}`}
                        alt={`member-${index + 1}`}
                      />
                    ))}
                    {(studyGroup.currentMemberCount ?? 0) > (studyGroup.memberIds?.length ?? 0) && (
                      <div className="flex h-8 w-8 items-center justify-center rounded-full border-2 border-white bg-gray-100 text-[10px] font-bold text-gray-500">
                        +{(studyGroup.currentMemberCount ?? 0) - (studyGroup.memberIds?.length ?? 0)}
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="flex min-h-[148px] flex-col items-center justify-center rounded-xl border border-dashed border-gray-200 bg-gray-50 text-center">
                  <i className="fas fa-users text-2xl text-gray-200" />
                  <p className="mt-3 text-sm font-bold text-gray-500">참여 중인 스터디가 없습니다.</p>
                  <p className="mt-1 text-xs text-gray-400">DB에 연결된 스터디 정보가 생기면 여기 표시됩니다.</p>
                </div>
              )}
            </div>

            <div className="flex flex-col rounded-2xl border border-gray-200 bg-white p-6 shadow-sm">
              <div className="mb-4 flex items-center justify-between">
                <h3 className="flex items-center gap-2 text-sm font-bold text-gray-800">
                  <i className="fas fa-chalkboard-teacher text-purple-500" /> 멘토링
                </h3>
              </div>
              {mentoringHasData ? (
                <div className="flex flex-1 flex-col justify-between gap-4">
                  <div className="grid grid-cols-3 gap-2">
                    <div className="rounded-xl bg-purple-50 px-3 py-2">
                      <p className="text-[10px] font-bold text-purple-500">프로젝트</p>
                      <p className="mt-1 text-sm font-extrabold text-gray-900">{mentoring.joinedProjectCount ?? 0}개</p>
                    </div>
                    <div className="rounded-xl bg-blue-50 px-3 py-2">
                      <p className="text-[10px] font-bold text-blue-500">신청</p>
                      <p className="mt-1 text-sm font-extrabold text-gray-900">{mentoring.applicationCount ?? 0}건</p>
                    </div>
                    <div className="rounded-xl bg-amber-50 px-3 py-2">
                      <p className="text-[10px] font-bold text-amber-500">대기</p>
                      <p className="mt-1 text-sm font-extrabold text-gray-900">{mentoring.pendingApplicationCount ?? 0}건</p>
                    </div>
                  </div>

                  <div className="rounded-xl border border-purple-100 bg-purple-50/60 p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <p className="text-[10px] font-bold uppercase tracking-[0.08em] text-purple-500">Latest</p>
                        <h4 className="mt-1 text-sm font-bold text-gray-900">
                          {mentoring.latestProject?.name ?? '멘토링 프로젝트'}
                        </h4>
                      </div>
                      <span
                        className={`shrink-0 rounded px-2 py-1 text-[10px] font-bold ${mentoringStatusClass(
                          mentoring.latestApplication?.status ?? mentoring.latestProject?.status,
                        )}`}
                      >
                        {mentoringStatusLabel(mentoring.latestApplication?.status ?? mentoring.latestProject?.status)}
                      </span>
                    </div>

                    {mentoring.latestApplication ? (
                      <div className="mt-3 space-y-2 text-xs text-gray-500">
                        <p>
                          {mentoring.latestApplication.mentorName
                            ? `${mentoring.latestApplication.mentorName} 멘토에게 신청됨`
                            : '멘토링 신청 이력이 반영되었습니다.'}
                        </p>
                        {mentoring.latestApplication.message ? (
                          <p className="line-clamp-2 text-[11px] text-gray-400">{mentoring.latestApplication.message}</p>
                        ) : null}
                      </div>
                    ) : (
                      <p className="mt-3 text-xs text-gray-500">참여 중인 프로젝트 기준으로 집계되며, 아직 멘토링 신청 이력은 없습니다.</p>
                    )}

                    {mentoringActivityAt ? (
                      <p className="mt-3 text-[10px] text-gray-400">{formatRelativeTime(mentoringActivityAt)}</p>
                    ) : null}
                  </div>
                </div>
              ) : (
                <div className="flex flex-1 flex-col items-center justify-center py-2">
                  <div className="mb-2 flex h-10 w-10 items-center justify-center rounded-full bg-gray-50 text-gray-300">
                    <i className="fas fa-search" />
                  </div>
                  <p className="text-center text-xs leading-relaxed text-gray-400">
                    참여 중인 프로젝트나 멘토링 신청 이력이 없습니다.
                    <br />
                    실제 DB 기준으로 비어 있으면 이 상태로 표시됩니다.
                  </p>
                </div>
              )}
            </div>

            <div className="rounded-2xl border border-gray-200 bg-white p-6 shadow-sm">
              <div className="mb-4 flex items-center justify-between">
                <h3 className="flex items-center gap-2 text-sm font-bold text-gray-800">
                  <i className="fas fa-comment-dots text-orange-500" /> 알림 / 커뮤니티
                </h3>
                <a href="community-list.html" className="text-xs text-gray-400 hover:text-brand">
                  둘러보기
                </a>
              </div>

              {communityItems.length > 0 ? (
                <ul className="space-y-3">
                  {communityItems.map((item, index) => (
                    <li key={item.id} className="group flex cursor-pointer items-start gap-3">
                      <div className={`mt-1.5 h-1.5 w-1.5 rounded-full ${index === 0 ? 'bg-orange-400' : 'bg-gray-300'}`} />
                      <div>
                        <p className="line-clamp-1 text-sm text-gray-700 transition group-hover:text-brand">{item.message}</p>
                        <p className="mt-0.5 text-[10px] text-gray-400">{formatRelativeTime(item.createdAt)}</p>
                      </div>
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="flex min-h-[148px] flex-col items-center justify-center rounded-xl border border-dashed border-gray-200 bg-gray-50 text-center">
                  <i className="fas fa-bell-slash text-2xl text-gray-200" />
                  <p className="mt-3 text-sm font-bold text-gray-500">표시할 알림이 없습니다.</p>
                  <p className="mt-1 text-xs text-gray-400">실제 알림 데이터가 생성되면 여기에서 확인할 수 있습니다.</p>
                </div>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
            <div className="h-full rounded-2xl border border-gray-200 bg-white p-6 shadow-sm">
              <div className="mb-4 flex items-center justify-between">
                <h3 className="text-sm font-bold text-gray-900">보유 Proof</h3>
                <a href="learning-log-gallery.html" className="text-xs text-gray-400 hover:text-brand">전체</a>
              </div>
              <div className="space-y-3">
                {state.proofCards.length > 0 ? (
                  state.proofCards.slice(0, 2).map((card, index) => {
                    const colors = [
                      { icon: 'text-blue-500', badge: 'text-blue-600 bg-blue-50' },
                      { icon: 'text-purple-500', badge: 'text-purple-600 bg-purple-50' },
                    ]
                    const color = colors[index % colors.length]
                    const firstTag = card.tags?.[0]?.tagName ?? card.nodeTitle
                    const issuedDate = card.issuedAt
                      ? new Date(card.issuedAt).toLocaleDateString('ko-KR', { month: 'short', day: 'numeric' })
                      : ''

                    return (
                      <div key={card.proofCardId} className="flex items-center justify-between rounded-xl border border-gray-100 bg-gray-50 p-3">
                        <div className="flex items-center gap-3">
                          <div className={`flex h-10 w-10 items-center justify-center rounded-lg border border-gray-200 bg-white shadow-sm ${color.icon}`}>
                            <i className="fas fa-certificate" />
                          </div>
                          <div>
                            <p className="line-clamp-1 text-sm font-bold text-gray-900">{firstTag}</p>
                            <p className="text-[10px] text-gray-400">{card.nodeTitle}</p>
                          </div>
                        </div>
                        <div className="text-right">
                          <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${color.badge}`}>Proof</span>
                          {issuedDate ? <p className="mt-0.5 text-[10px] text-gray-400">{issuedDate}</p> : null}
                        </div>
                      </div>
                    )
                  })
                ) : (
                  <div className="flex flex-col items-center justify-center py-6 text-center">
                    <i className="fas fa-medal mb-2 text-2xl text-gray-200" />
                    <p className="text-xs text-gray-400">아직 획득한 Proof Card가 없습니다.</p>
                  </div>
                )}
              </div>
            </div>

            <div className="flex h-full flex-col justify-between rounded-2xl border border-gray-200 bg-white p-6 shadow-sm md:col-span-2">
              <div className="mb-4 flex items-center gap-2">
                <i className="fas fa-magic text-purple-500" />
                <h3 className="text-sm font-bold text-gray-900">AI 성장 제안</h3>
              </div>

              <div className="flex h-full flex-col gap-4 md:flex-row">
                {growthItems.length > 0 ? (
                  <div className="flex flex-1 flex-col justify-center gap-2 rounded-xl bg-purple-50 p-4">
                    <div className="flex items-center gap-3">
                      <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-white text-xl text-purple-600 shadow-sm">
                        <i className={`fas ${growthItems[0].iconClass}`} />
                      </div>
                      <div>
                        <p className="text-sm font-bold text-gray-900">{growthItems[0].courseTitle}</p>
                        <p className="text-[10px] text-gray-500">
                          매칭률 <span className="font-bold text-purple-600">+{growthItems[0].matchRateIncrease}%</span> 상승
                        </p>
                      </div>
                    </div>

                    {growthItems[1] ? (
                      <div className="flex items-center gap-3 rounded-lg border border-purple-100 bg-white px-3 py-2">
                        <i className={`fas ${growthItems[1].iconClass} text-sm text-purple-400`} />
                        <div>
                          <p className="text-xs font-bold text-gray-800">{growthItems[1].courseTitle}</p>
                          <p className="text-[10px] text-gray-400">+{growthItems[1].matchRateIncrease}% 상승</p>
                        </div>
                      </div>
                    ) : null}
                  </div>
                ) : (
                  <div className="flex flex-1 flex-col items-center justify-center rounded-xl border border-dashed border-purple-100 bg-purple-50/60 p-4 text-center">
                    <i className="fas fa-sparkles text-2xl text-purple-200" />
                    <p className="mt-3 text-sm font-bold text-gray-500">추천할 성장 데이터가 아직 없습니다.</p>
                    <p className="mt-1 text-xs text-gray-400">Proof Card와 학습 이력이 쌓이면 실제 추천이 생성됩니다.</p>
                  </div>
                )}

                <div className="flex flex-1 flex-col justify-center rounded-xl bg-slate-900 p-4 text-white">
                  <div className="mb-2 flex items-center gap-2">
                    <span className="text-lg text-yellow-400">
                      <i className="fas fa-robot" />
                    </span>
                    <span className="text-xs font-bold text-gray-300">Analysis</span>
                  </div>
                  <p className="text-xs leading-relaxed text-gray-300">
                    {growthItems.length > 0 && state.growthRecommendation?.analysisText
                      ? state.growthRecommendation.analysisText
                      : '추천을 생성할 실제 학습 데이터가 아직 충분하지 않습니다.'}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </section>

        <aside className="hidden w-80 shrink-0 xl:block">
          <div
            className="sticky-roadmap overflow-hidden rounded-[28px] border border-slate-200 bg-white shadow-sm"
            style={{ top: '96px' }}
          >
            <div className="border-b border-slate-200 bg-[linear-gradient(160deg,#ecfdf5_0%,#eff6ff_52%,#ffffff_100%)] p-6">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <p className="text-[11px] font-black uppercase tracking-[0.18em] text-emerald-700/80">
                    Last roadmap
                  </p>
                  <h3 className="mt-2 text-xl font-black text-slate-900">나의 학습자 로드맵</h3>
                  <p className="mt-2 text-xs leading-relaxed text-slate-600">
                    마지막으로 학습한 로드맵 기준으로 지금 위치를 미니 로드맵으로 보여줍니다.
                  </p>
                </div>

                <div className="shrink-0 rounded-2xl border border-white/90 bg-white/90 px-3 py-2 text-right shadow-sm">
                  <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-slate-400">Progress</p>
                  <p className="mt-1 text-2xl font-black text-slate-900">{roadmapProgress}%</p>
                </div>
              </div>

              <div className="mt-5 h-2 rounded-full bg-white/80">
                <div
                  className="h-2 rounded-full bg-[linear-gradient(90deg,#10b981,#38bdf8)]"
                  style={{ width: `${roadmapProgress}%` }}
                />
              </div>

              {state.roadmapSummary ? (
                <div className="mt-4 flex items-center justify-between gap-3 text-[11px] text-slate-500">
                  <span className="min-w-0 truncate font-semibold text-slate-700">{state.roadmapSummary.title}</span>
                  {roadmapActivityAt ? <span className="shrink-0">{formatRelativeTime(roadmapActivityAt)}</span> : null}
                </div>
              ) : null}
            </div>

            <div className="space-y-4 p-6">
              {state.roadmap ? (
                <>
                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <p className="text-[11px] font-bold uppercase tracking-[0.14em] text-slate-400">
                          Current focus
                        </p>
                        <h4 className="mt-2 line-clamp-2 text-sm font-bold text-slate-900">
                          {roadmapFocusNode?.title ?? '다음 학습 노드 준비 중'}
                        </h4>
                      </div>

                      {roadmapFocusNode ? (
                        <span
                          className={`shrink-0 rounded-full px-2.5 py-1 text-[10px] font-bold ${getRoadmapNodeTone(
                            roadmapFocusNode,
                          ).chip}`}
                        >
                          {getRoadmapNodeStatusLabel(roadmapFocusNode)}
                        </span>
                      ) : null}
                    </div>

                    {roadmapFocusProgress != null ? (
                      <div className="mt-4">
                        <div className="flex items-center justify-between text-[11px] font-semibold text-sky-700">
                          <span>현재 노드 진도</span>
                          <span>{roadmapFocusProgress}%</span>
                        </div>
                        <div className="mt-2 h-2 rounded-full bg-white">
                          <div
                            className="h-2 rounded-full bg-[linear-gradient(90deg,#0ea5e9,#22c55e)]"
                            style={{ width: `${roadmapFocusProgress}%` }}
                          />
                        </div>
                      </div>
                    ) : (
                      <p className="mt-4 text-xs leading-relaxed text-slate-500">
                        {roadmapFocusNode?.status === 'COMPLETED'
                          ? '최근 학습 로드맵의 메인 노드를 대부분 마쳤습니다. 다음 단계로 이어서 진행하면 됩니다.'
                          : '다음으로 이어질 메인 노드를 기준으로 한눈에 보기 좋은 흐름으로 정리했습니다.'}
                      </p>
                    )}
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-white p-4">
                    <div className="mb-4 flex items-center justify-between gap-3">
                      <div>
                        <p className="text-[11px] font-bold uppercase tracking-[0.14em] text-slate-400">
                          Mini roadmap
                        </p>
                        <p className="mt-1 text-xs text-slate-500">최근 학습 흐름 기준 핵심 메인 노드</p>
                      </div>
                      <span className="shrink-0 rounded-full bg-slate-100 px-2.5 py-1 text-[10px] font-bold text-slate-600">
                        {roadmapCompletedNodeCount}/{state.roadmap.nodes.length} 완료
                      </span>
                    </div>

                    {sidebarNodes.length > 0 ? (
                      <div className="space-y-3">
                        {sidebarNodes.map((node, index) => {
                          const tone = getRoadmapNodeTone(node)
                          const nodeProgress =
                            node.status === 'IN_PROGRESS'
                              ? clampProgress((node.lessonCompletionRate ?? 0) * 100)
                              : null
                          const isFocusNode = roadmapFocusNode?.customNodeId === node.customNodeId
                          const connectorTone =
                            node.status === 'COMPLETED'
                              ? 'bg-emerald-200'
                              : node.status === 'IN_PROGRESS'
                                ? 'bg-sky-200'
                                : 'bg-slate-200'

                          return (
                            <div key={node.customNodeId} className="relative pl-12">
                              {index < sidebarNodes.length - 1 ? (
                                <div
                                  className={`absolute left-[15px] top-9 w-px rounded-full ${connectorTone}`}
                                  style={{ height: 'calc(100% + 0.75rem)' }}
                                />
                              ) : null}

                              <div
                                className={`absolute left-0 top-0 z-10 flex h-8 w-8 items-center justify-center rounded-2xl border-2 text-xs shadow-sm ${tone.dot}`}
                              >
                                {node.status === 'COMPLETED' ? (
                                  <i className="fas fa-check" />
                                ) : node.status === 'IN_PROGRESS' ? (
                                  <i className="fas fa-play" />
                                ) : node.status === 'LOCKED' ? (
                                  <i className="fas fa-lock" />
                                ) : (
                                  <span className="text-[11px] font-black">{node.sortOrder}</span>
                                )}
                              </div>

                              <div
                                className={`rounded-[22px] border px-3.5 py-3 ${tone.card} ${
                                  isFocusNode ? 'ring-2 ring-sky-200 ring-offset-2 ring-offset-white' : ''
                                }`}
                              >
                                <div className="flex items-start justify-between gap-3">
                                  <div className="min-w-0">
                                    <p className="text-[10px] font-black uppercase tracking-[0.16em] text-slate-400">
                                      Step {String(node.sortOrder).padStart(2, '0')}
                                    </p>
                                    <p className="mt-1 line-clamp-2 text-sm font-bold leading-5">{node.title}</p>
                                  </div>

                                  <span className={`shrink-0 rounded-full px-2 py-1 text-[9px] font-bold ${tone.chip}`}>
                                    {getRoadmapNodeStatusLabel(node)}
                                  </span>
                                </div>

                                <div className="mt-2 flex flex-wrap items-center gap-2 text-[10px] text-slate-500">
                                  {isFocusNode ? (
                                    <span className="rounded-full bg-white/85 px-2 py-1 font-bold text-sky-700">
                                      현재 포커스
                                    </span>
                                  ) : null}
                                  {nodeProgress != null ? (
                                    <span className="font-semibold text-sky-700">{nodeProgress}% 진행</span>
                                  ) : null}
                                  {node.subTopics && node.subTopics.length > 0 ? (
                                    <span className="line-clamp-1">
                                      {node.subTopics.slice(0, 2).join(' · ')}
                                    </span>
                                  ) : null}
                                </div>
                              </div>
                            </div>
                          )
                        })}
                      </div>
                    ) : (
                      <div className="rounded-2xl border border-dashed border-slate-200 bg-slate-50 px-4 py-8 text-center">
                        <i className="fas fa-map text-2xl text-slate-300" />
                        <p className="mt-3 text-sm font-bold text-slate-500">로드맵 노드가 아직 없습니다.</p>
                        <p className="mt-1 text-xs text-slate-400">학습 이력이 쌓이면 여기에 미니 로드맵이 정리됩니다.</p>
                      </div>
                    )}
                  </div>

                  <div className="grid grid-cols-2 gap-2">
                    <button
                      className="rounded-2xl bg-slate-900 px-4 py-3 text-sm font-bold text-white transition hover:bg-black"
                      onClick={() => {
                        window.location.href = roadmapEntryHref
                      }}
                    >
                      로드맵 열기
                    </button>
                    <button
                      className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm font-bold text-slate-700 transition hover:bg-slate-50"
                      onClick={() => {
                        window.location.href = 'roadmap-hub.html'
                      }}
                    >
                      허브 보기
                    </button>
                  </div>
                </>
              ) : (
                <>
                  <div className="rounded-2xl border border-dashed border-slate-200 bg-slate-50 px-4 py-8 text-center">
                    <i className="fas fa-map text-3xl text-slate-300" />
                    <p className="mt-3 text-sm font-bold text-slate-500">최근 학습 로드맵이 아직 없습니다.</p>
                    <p className="mt-1 text-xs leading-relaxed text-slate-400">
                      로드맵 허브에서 로드맵을 시작하거나 직접 만든 커스텀 로드맵을 학습하면
                      <br />
                      여기에 마지막 학습 기준 미니 로드맵이 표시됩니다.
                    </p>
                  </div>

                  <button
                    className="w-full rounded-2xl bg-slate-900 px-4 py-3 text-sm font-bold text-white transition hover:bg-black"
                    onClick={() => {
                      window.location.href = 'roadmap-hub.html'
                    }}
                  >
                    로드맵 허브로 이동
                  </button>
                </>
              )}
            </div>

            <div className="hidden">
              <h3 className="flex items-center gap-2 font-bold text-gray-900">
                <i className="fas fa-map text-brand" /> 나의 학습 로드맵
              </h3>
              {state.roadmap ? (
                <span className="max-w-[120px] truncate rounded bg-gray-100 px-2 py-1 text-[10px] text-gray-500">
                  {state.roadmap.title}
                </span>
              ) : null}
            </div>

            <div className="hidden">
              <div className="roadmap-line" />
              <div className="roadmap-progress" style={{ height: `${roadmapProgress}%` }} />

              {sidebarNodes.length > 0 ? (
                <>
                  {sidebarNodes.map((node) => {
                    if (node.status === 'COMPLETED') {
                      return (
                        <div key={node.customNodeId} className="roadmap-item">
                          <div className="step-icon completed">
                            <i className="fas fa-check text-xs" />
                          </div>
                          <div className="pt-1.5">
                            <h4 className="text-sm font-bold text-gray-400 line-through">{node.title}</h4>
                          </div>
                        </div>
                      )
                    }

                    if (node.status === 'IN_PROGRESS') {
                      const progress = clampProgress((node.lessonCompletionRate ?? 0) * 100)

                      return (
                        <div key={node.customNodeId} className="roadmap-item">
                          <div className="step-icon current">
                            <div className="h-2.5 w-2.5 rounded-full bg-brand animate-pulse" />
                          </div>
                          <div className="relative -mt-1 rounded-lg border border-green-200 bg-green-50 p-2 shadow-sm">
                            <h4 className="mb-1 text-sm font-bold text-gray-900">{node.title}</h4>
                            <div className="h-1.5 w-full rounded-full border border-green-100 bg-white">
                              <div className="h-1.5 rounded-full bg-brand" style={{ width: `${progress}%` }} />
                            </div>
                            <p className="mt-1 text-right text-[10px] text-gray-500">{progress}% 완료</p>
                          </div>
                        </div>
                      )
                    }

                    return (
                      <div key={node.customNodeId} className="roadmap-item">
                        <div className="step-icon waiting">
                          <i className="fas fa-lock text-[10px]" />
                        </div>
                        <div className="pt-1.5">
                          <h4 className="text-sm font-bold text-gray-400">{node.title}</h4>
                        </div>
                      </div>
                    )
                  })}

                  <div className="roadmap-item mt-6">
                    <div className="step-icon border-2 border-yellow-400 bg-yellow-100 text-yellow-600 shadow-sm">
                      <i className="fas fa-flag text-xs" />
                    </div>
                    <div className="pt-1.5">
                      <h4 className="text-sm font-bold text-gray-900">로드맵 완주</h4>
                    </div>
                  </div>
                </>
              ) : (
                <div className="flex flex-col items-center justify-center py-8 text-center">
                  <i className="fas fa-map mb-3 text-3xl text-gray-200" />
                  <p className="text-xs text-gray-400">
                    연결된 로드맵이 없거나
                    <br />
                    아직 불러올 데이터가 없습니다.
                  </p>
                </div>
              )}
            </div>

            <button
              className="hidden"
              onClick={() => {
                window.location.href = 'roadmap-hub.html'
              }}
            >
              로드맵 전체 보기
            </button>
          </div>
        </aside>
      </LearnerContentRow>
    </LearnerPageShell>
  )
}
