import { useEffect, useState } from 'react'
import { dashboardApi, enrollmentApi, learningHistoryApi, notificationApi, proofCardApi, roadmapApi } from '../../lib/api'
import { LearnerContentRow, LearnerPageShell, MyMenuSidebar } from '../template'
import type { AuthSession } from '../../types/auth'
import type {
  DashboardStudyGroup,
  DashboardSummary,
  Enrollment,
  GrowthRecommendation,
  HeatmapEntry,
  LearningHistorySummary,
  NotificationItem,
  ProofCardGalleryItem,
} from '../../types/learner'
import type { RoadmapDetail, RoadmapNodeItem } from '../../types/roadmap'

type DashboardState = {
  summary: DashboardSummary
  heatmap: HeatmapEntry[]
  studyGroup: DashboardStudyGroup
  notifications: NotificationItem[]
  historySummary: LearningHistorySummary
  enrollments: Enrollment[]
  roadmap: RoadmapDetail | null
  proofCards: ProofCardGalleryItem[]
  growthRecommendation: GrowthRecommendation | null
}

const fallbackState: DashboardState = {
  summary: {
    currentStreak: 12,
    totalStudyHours: 42.5,
    completedNodes: 14,
  },
  heatmap: [
    { date: '2026-02-03', activityLevel: 2 },
    { date: '2026-02-04', activityLevel: 4 },
    { date: '2026-02-05', activityLevel: 1 },
    { date: '2026-02-06', activityLevel: 5 },
    { date: '2026-02-07', activityLevel: 3 },
    { date: '2026-02-08', activityLevel: 1 },
    { date: '2026-02-09', activityLevel: 1 },
  ],
  studyGroup: {
    joinedGroupCount: 1,
    recruitingGroupCount: 0,
    inProgressGroupCount: 1,
    groups: [
      {
        groupId: 1,
        name: '2026 졸업작품 팀 A',
        status: 'IN_PROGRESS',
        maxMembers: 5,
        joinedAt: '2026-01-15T00:00:00',
        plannedEndDate: null,
      currentMemberCount: null,
      },
    ],
  },
  notifications: [
    {
      id: 1,
      type: 'COMMUNITY',
      message: '스프링 부트 JPA 관련 질문있습니다!',
      isRead: false,
      createdAt: '2026-02-09T10:00:00',
    },
    {
      id: 2,
      type: 'COMMUNITY',
      message: '졸업작품 주제 추천 부탁드립니다.',
      isRead: true,
      createdAt: '2026-02-08T10:00:00',
    },
  ],
  historySummary: {
    completedNodeCount: 14,
    proofCardCount: 3,
    tilCount: 0,
    publishedTilCount: 0,
    assignmentSubmissionCount: 0,
    passedAssignmentCount: 0,
    supplementRecommendationCount: 0,
  },
  enrollments: [
    {
      enrollmentId: 1,
      courseId: 1,
      courseTitle: 'Java 프로그래밍 (Backend Basic)',
      instructorName: 'DevPath',
      thumbnailUrl: 'https://images.unsplash.com/photo-1587620962725-abab7fe55159?w=400&q=80',
      price: 99000,
      originalPrice: 99000,
      currency: 'KRW',
      hasCertificate: true,
      status: 'ACTIVE',
      progressPercentage: 60,
      enrolledAt: '2026-01-05T00:00:00',
      completedAt: null,
      lastAccessedAt: '2026-02-09T12:00:00',
    },
    {
      enrollmentId: 2,
      courseId: 2,
      courseTitle: 'Docker & K8s 실전 배포',
      instructorName: 'DevPath',
      thumbnailUrl: 'https://images.unsplash.com/photo-1607799275518-d580e811cc0e?w=400&q=80',
      price: 55000,
      originalPrice: 55000,
      currency: 'KRW',
      hasCertificate: false,
      status: 'COMPLETED',
      progressPercentage: 100,
      enrolledAt: '2026-01-10T00:00:00',
      completedAt: '2026-01-25T00:00:00',
      lastAccessedAt: '2026-01-25T12:00:00',
    },
  ],
  roadmap: null,
  proofCards: [],
  growthRecommendation: null,
}

function formatStudyTime(hoursValue: number | null | undefined) {
  const totalMinutes = Math.max(0, Math.round((hoursValue ?? 42.5) * 60))
  const hours = Math.floor(totalMinutes / 60)
  const minutes = totalMinutes % 60

  return {
    hours,
    minutes,
  }
}

function buildWeeklyBars(heatmap: HeatmapEntry[]) {
  const labels = ['월', '화', '수', '목', '금', '토', '일']
  const recent = heatmap.slice(-7)

  return labels.map((label, index) => {
    const item = recent[index]
    const activity = item?.activityLevel ?? 0
    const height = item ? Math.max(10, Math.min(80, activity * 16)) : 0

    return {
      label,
      height,
      tone:
        index === 4 ? 'bg-green-300' : activity >= 3 ? 'bg-brand' : activity >= 1 ? 'bg-brand' : 'bg-gray-200',
      active: activity >= 3 || index === 1 || index === 3,
    }
  })
}

function buildSidebarNodes(nodes: RoadmapNodeItem[]) {
  const sorted = [...nodes]
    .filter((n) => n.branchGroup == null)
    .sort((a, b) => a.sortOrder - b.sortOrder)
  const currentIndex = sorted.findIndex((n) => n.status === 'IN_PROGRESS')
  const start = currentIndex >= 0 ? Math.max(0, currentIndex - 2) : 0
  return sorted.slice(start, start + 5)
}

function formatRelativeTime(createdAt: string | null | undefined): string {
  if (!createdAt) return ''
  const diffMs = Date.now() - new Date(createdAt).getTime()
  const minutes = Math.floor(diffMs / (1000 * 60))
  if (minutes < 60) return `${Math.max(1, minutes)}분 전`
  const hours = Math.floor(diffMs / (1000 * 60 * 60))
  if (hours < 24) return `${hours}시간 전`
  return `${Math.floor(diffMs / (1000 * 60 * 60 * 24))}일 전`
}

function calcDDay(plannedEndDate: string | null | undefined): string {
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

export default function DashboardPage({ session }: { session: AuthSession }) {
  const [state, setState] = useState<DashboardState>(fallbackState)

  useEffect(() => {
    const controller = new AbortController()
    const { signal } = controller

    async function load() {
      const [
        summaryResult,
        heatmapResult,
        studyGroupResult,
        notificationResult,
        historySummaryResult,
        enrollmentResult,
        proofCardsResult,
        growthRecommendationResult,
      ] = await Promise.allSettled([
        dashboardApi.getSummary(signal),
        dashboardApi.getHeatmap(signal),
        dashboardApi.getStudyGroup(signal),
        notificationApi.getMine(signal),
        learningHistoryApi.getSummary(signal),
        enrollmentApi.getMyEnrollments(signal),
        proofCardApi.getGallery(signal),
        dashboardApi.getGrowthRecommendation(signal),
      ])

      setState((current) => ({
        summary:
          summaryResult.status === 'fulfilled'
            ? {
                currentStreak: summaryResult.value.currentStreak ?? current.summary.currentStreak,
                totalStudyHours: summaryResult.value.totalStudyHours ?? current.summary.totalStudyHours,
                completedNodes: summaryResult.value.completedNodes ?? current.summary.completedNodes,
              }
            : current.summary,
        heatmap:
          heatmapResult.status === 'fulfilled' && heatmapResult.value.length
            ? heatmapResult.value
            : current.heatmap,
        studyGroup:
          studyGroupResult.status === 'fulfilled'
            ? studyGroupResult.value
            : current.studyGroup,
        notifications:
          notificationResult.status === 'fulfilled' && notificationResult.value.length
            ? notificationResult.value
            : current.notifications,
        historySummary:
          historySummaryResult.status === 'fulfilled'
            ? historySummaryResult.value
            : current.historySummary,
        enrollments:
          enrollmentResult.status === 'fulfilled' && enrollmentResult.value.length
            ? enrollmentResult.value
            : current.enrollments,
        roadmap: current.roadmap,
        proofCards:
          proofCardsResult.status === 'fulfilled' && proofCardsResult.value.length
            ? proofCardsResult.value
            : current.proofCards,
        growthRecommendation:
          growthRecommendationResult.status === 'fulfilled'
            ? growthRecommendationResult.value
            : current.growthRecommendation,
      }))
    }

    async function loadRoadmap() {
      try {
        const listResult = await roadmapApi.getMyRoadmaps(signal)
        const first = listResult.roadmaps[0]
        if (!first) return
        const detail = await roadmapApi.getMyRoadmapDetail(first.customRoadmapId, signal)
        setState((current) => ({ ...current, roadmap: detail }))
      } catch {
        // 로드맵 없으면 사이드바 미표시 유지
      }
    }

    void load()
    void loadRoadmap()

    return () => controller.abort()
  }, [])

  const completedCourses =
    state.enrollments.filter((item) => item.status === 'COMPLETED').length || Number(state.summary.completedNodes ?? 14)
  const proofCardCount = state.historySummary.proofCardCount ?? 0
  const studyTime = formatStudyTime(state.summary.totalStudyHours)
  const recentEnrollment =
    [...state.enrollments]
      .sort((left, right) => new Date(right.lastAccessedAt ?? 0).getTime() - new Date(left.lastAccessedAt ?? 0).getTime())[0] ??
    fallbackState.enrollments[0]
  const weeklyBars = buildWeeklyBars(state.heatmap)
  const studyGroup = state.studyGroup.groups[0] ?? fallbackState.studyGroup.groups[0]
  const dDay = calcDDay(studyGroup.plannedEndDate)
  const communityItems = state.notifications.slice(0, 2)
  const roadmapProgress = state.roadmap?.progressRate ?? Math.max(0, Math.min(100, recentEnrollment.progressPercentage ?? 60))
  const sidebarNodes = state.roadmap ? buildSidebarNodes(state.roadmap.nodes) : []

  return (
    <LearnerPageShell>
      <LearnerContentRow>
        <MyMenuSidebar currentPageKey="dashboard" wrapperClassName="w-60 shrink-0 hidden lg:block" />

        <section className="min-w-0 flex-1 space-y-6">
          <header className="mb-2 flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-gray-900">반가워요, {session.name}님! 👋</h1>
              <p className="mt-1 text-sm text-gray-500">오늘도 목표를 향해 달려볼까요?</p>
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
                <span className="text-2xl font-extrabold text-gray-900">{state.summary.currentStreak ?? 12}일</span>
              </div>
              <p className="mt-1 text-[10px] text-gray-400">이대로 쭉 가보자고요!</p>
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
                <p className="mt-1 text-xs font-bold text-gray-500">획득 뱃지</p>
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
                Proof Card 확인 →
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
              <p className="mt-1 text-[10px] text-gray-400">어제보다 2시간 더함</p>
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
              <div className="flex items-center gap-5">
                <div className="h-20 w-32 shrink-0 overflow-hidden rounded-lg bg-gray-100">
                  <img
                    src={recentEnrollment.thumbnailUrl ?? fallbackState.enrollments[0].thumbnailUrl ?? ''}
                    className="h-full w-full object-cover"
                    alt="thumb"
                  />
                </div>
                <div className="flex-1">
                  <div className="mb-1 flex items-center justify-between">
                    <h4 className="text-sm font-bold text-gray-900">{recentEnrollment.courseTitle}</h4>
                    <span className="text-brand text-lg font-extrabold">{recentEnrollment.progressPercentage ?? 60}%</span>
                  </div>
                  <p className="mb-2 text-xs text-gray-500">섹션 5. 객체지향 심화 - 2강. 인터페이스</p>
                  <div className="mb-1 h-2 w-full rounded-full bg-gray-100">
                    <div
                      className="bg-brand h-2 rounded-full transition-all duration-1000"
                      style={{ width: `${recentEnrollment.progressPercentage ?? 60}%` }}
                    />
                  </div>
                </div>
                <button className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-gray-900 text-white shadow-lg transition hover:bg-brand">
                  <i className="fas fa-play ml-1" />
                </button>
              </div>
            </div>

            <div className="flex flex-col rounded-2xl border border-gray-200 bg-white p-6 shadow-sm">
              <div className="mb-4 flex items-center justify-between">
                <h3 className="flex items-center gap-2 text-sm font-bold text-gray-800">
                  <i className="fas fa-chart-bar text-gray-400" /> 주간 학습 시간
                </h3>
                <span className="text-[10px] text-gray-400">이번 주</span>
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
                  <i className="fas fa-rocket text-blue-500" /> 진행 중인 프로젝트
                </h3>
                <a href="project-list.html" className="text-xs text-gray-400 hover:text-brand">
                  더보기
                </a>
              </div>
              <div className="cursor-pointer rounded-xl border border-blue-100 bg-blue-50 p-4 transition hover:shadow-md">
                <div>
                  <div className="mb-2 flex items-center gap-2">
                    <span className="shrink-0 rounded bg-blue-500 px-2 py-0.5 text-[10px] font-bold text-white">Team</span>
                    <span className="whitespace-nowrap text-sm font-bold text-gray-900">{studyGroup.name}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {dDay && (
                      <span className={`shrink-0 rounded border px-2 py-0.5 text-xs font-bold ${statusClass(studyGroup.status)}`}>
                        {dDay}
                      </span>
                    )}
                    <p className="whitespace-nowrap text-[11px] text-gray-500">
                      {studyGroup.status === 'IN_PROGRESS' ? '진행 중' : '모집 중'}
                    </p>
                  </div>
                </div>
                <div className="mt-4 flex -space-x-2">
                  <img className="h-8 w-8 rounded-full border-2 border-white bg-gray-200" src="https://api.dicebear.com/7.x/avataaars/svg?seed=1" alt="m1" />
                  <img className="h-8 w-8 rounded-full border-2 border-white bg-gray-200" src="https://api.dicebear.com/7.x/avataaars/svg?seed=2" alt="m2" />
                  {(studyGroup.currentMemberCount ?? 0) > 2 && (
                    <div className="flex h-8 w-8 items-center justify-center rounded-full border-2 border-white bg-gray-100 text-[10px] font-bold text-gray-500">
                      +{(studyGroup.currentMemberCount ?? 0) - 2}
                    </div>
                  )}
                </div>
              </div>
            </div>

            <div className="flex flex-col rounded-2xl border border-gray-200 bg-white p-6 shadow-sm">
              <div className="mb-4 flex items-center justify-between">
                <h3 className="flex items-center gap-2 text-sm font-bold text-gray-800">
                  <i className="fas fa-chalkboard-teacher text-purple-500" /> 멘토링
                </h3>
                <a href="#" className="text-xs text-gray-400 hover:text-brand">
                  더보기
                </a>
              </div>
              <div className="flex flex-1 flex-col items-center justify-center py-2">
                <div className="mb-2 flex h-10 w-10 items-center justify-center rounded-full bg-gray-50 text-gray-300">
                  <i className="fas fa-search" />
                </div>
                <p className="text-center text-xs leading-relaxed text-gray-400">
                  현재 진행 중인
                  <br />
                  멘토링이 없습니다.
                </p>
                <button className="mt-3 rounded bg-purple-50 px-3 py-1.5 text-[10px] font-bold text-purple-600 transition hover:bg-purple-100">
                  멘토 찾기
                </button>
              </div>
            </div>

            <div className="rounded-2xl border border-gray-200 bg-white p-6 shadow-sm">
              <div className="mb-4 flex items-center justify-between">
                <h3 className="flex items-center gap-2 text-sm font-bold text-gray-800">
                  <i className="fas fa-comment-dots text-orange-500" /> 라운지 / 커뮤니티
                </h3>
                <a href="community-list.html" className="text-xs text-gray-400 hover:text-brand">
                  더보기
                </a>
              </div>
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
            </div>
          </div>

          <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
            <div className="h-full rounded-2xl border border-gray-200 bg-white p-6 shadow-sm">
              <div className="mb-4 flex items-center justify-between">
                <h3 className="text-sm font-bold text-gray-900">보유 스킬 (Proof)</h3>
                <a href="learning-log-gallery.html" className="text-xs text-gray-400 hover:text-brand">전체</a>
              </div>
              <div className="space-y-3">
                {state.proofCards.length > 0 ? (
                  state.proofCards.slice(0, 2).map((card, index) => {
                    const colors = [
                      { icon: 'text-blue-500', bg: 'bg-blue-50', badge: 'text-blue-600 bg-blue-50' },
                      { icon: 'text-purple-500', bg: 'bg-purple-50', badge: 'text-purple-600 bg-purple-50' },
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
                            <p className="text-sm font-bold text-gray-900 line-clamp-1">{firstTag}</p>
                            <p className="text-[10px] text-gray-400">{card.nodeTitle}</p>
                          </div>
                        </div>
                        <div className="text-right">
                          <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${color.badge}`}>Proof</span>
                          {issuedDate && <p className="mt-0.5 text-[10px] text-gray-400">{issuedDate}</p>}
                        </div>
                      </div>
                    )
                  })
                ) : (
                  <div className="flex flex-col items-center justify-center py-6 text-center">
                    <i className="fas fa-medal text-2xl text-gray-200 mb-2" />
                    <p className="text-xs text-gray-400">아직 획득한 Proof Card가<br />없습니다.</p>
                  </div>
                )}
              </div>
            </div>

            <div className="flex h-full flex-col justify-between rounded-2xl border border-gray-200 bg-white p-6 shadow-sm md:col-span-2">
              <div className="mb-4 flex items-center gap-2">
                <i className="fas fa-magic text-purple-500" />
                <h3 className="text-sm font-bold text-gray-900">AI 맞춤 성장 제안</h3>
              </div>

              <div className="flex h-full flex-col gap-4 md:flex-row">
                {state.growthRecommendation?.recommendations?.[0] && (
                  <div className="flex flex-1 flex-col justify-center gap-2 rounded-xl bg-purple-50 p-4">
                    <div className="flex items-center gap-3">
                      <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-white text-xl text-purple-600 shadow-sm">
                        <i className={`fas ${state.growthRecommendation.recommendations[0].iconClass}`} />
                      </div>
                      <div>
                        <p className="text-sm font-bold text-gray-900">
                          {state.growthRecommendation.recommendations[0].courseTitle}
                        </p>
                        <p className="text-[10px] text-gray-500">
                          매칭률{' '}
                          <span className="font-bold text-purple-600">
                            +{state.growthRecommendation.recommendations[0].matchRateIncrease}%
                          </span>{' '}
                          상승
                        </p>
                      </div>
                    </div>
                    {state.growthRecommendation.recommendations[1] && (
                      <div className="flex items-center gap-3 rounded-lg border border-purple-100 bg-white px-3 py-2">
                        <i className={`fas ${state.growthRecommendation.recommendations[1].iconClass} text-purple-400 text-sm`} />
                        <div>
                          <p className="text-xs font-bold text-gray-800">
                            {state.growthRecommendation.recommendations[1].courseTitle}
                          </p>
                          <p className="text-[10px] text-gray-400">
                            +{state.growthRecommendation.recommendations[1].matchRateIncrease}% 상승
                          </p>
                        </div>
                      </div>
                    )}
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
                    {state.growthRecommendation?.analysisText ?? '학습 데이터를 분석하여 성장 제안을 준비 중입니다.'}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </section>

        <aside className="hidden w-80 shrink-0 xl:block">
          <div className="sticky-roadmap mt-[80px] rounded-2xl border border-gray-200 bg-white p-6 shadow-sm">
            <div className="mb-6 flex items-center justify-between">
              <h3 className="flex items-center gap-2 font-bold text-gray-900">
                <i className="fas fa-map text-brand" /> 나의 학습 로드맵
              </h3>
              {state.roadmap && (
                <span className="max-w-[120px] truncate rounded bg-gray-100 px-2 py-1 text-[10px] text-gray-500">
                  {state.roadmap.title}
                </span>
              )}
            </div>

            <div className="roadmap-container relative pb-2">
              <div className="roadmap-line" />
              <div className="roadmap-progress" style={{ height: `${Math.max(50, roadmapProgress)}%` }} />

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
                      const progress = Math.round((node.lessonCompletionRate ?? 0) * 100)
                      return (
                        <div key={node.customNodeId} className="roadmap-item">
                          <div className="step-icon current">
                            <div className="bg-brand h-2.5 w-2.5 rounded-full animate-pulse" />
                          </div>
                          <div className="relative -mt-1 rounded-lg border border-green-200 bg-green-50 p-2 shadow-sm">
                            <h4 className="mb-1 text-sm font-bold text-gray-900">{node.title}</h4>
                            <div className="h-1.5 w-full rounded-full border border-green-100 bg-white">
                              <div className="bg-brand h-1.5 rounded-full" style={{ width: `${progress}%` }} />
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
                  <i className="fas fa-map text-3xl text-gray-200 mb-3" />
                  <p className="text-xs text-gray-400">
                    로드맵을 불러오는 중이거나
                    <br />
                    아직 로드맵이 없습니다.
                  </p>
                </div>
              )}
            </div>

            <button
              className="mt-6 w-full rounded-xl bg-gray-900 py-3 text-sm font-bold text-white transition hover:bg-black"
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
