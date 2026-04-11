import { useEffect, useRef, useState } from 'react'
import { ErrorCard, LoadingCard, formatNumber } from '../../account/ui'
import {
  instructorCourseApi,
  instructorMentoringApi,
  instructorNotificationApi,
  instructorQnaApi,
  instructorRevenueApi,
  instructorReviewApi,
} from '../../lib/api'
import type { AuthSession } from '../../types/auth'
import type {
  InstructorCourseListItem,
  InstructorMentoringBoard,
  InstructorNotificationItem,
  InstructorReviewListItem,
  InstructorReviewSummary,
} from '../../types/instructor'

type DashboardTabKey = 'learning' | 'mentoring'

const EMPTY_REVIEW_SUMMARY: InstructorReviewSummary = {
  totalReviews: 0,
  averageRating: 0,
  unansweredCount: 0,
  ratingDistribution: {},
}

const EMPTY_MENTORING_BOARD: InstructorMentoringBoard = {
  projects: [],
  requests: [],
  ongoingProjects: [],
}

function DashboardTabButton({
  active,
  onClick,
  children,
}: {
  active: boolean
  onClick: () => void
  children: string
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-xl px-6 py-2.5 text-sm font-bold transition ${
        active ? 'bg-gray-900 text-white' : 'text-gray-500 hover:bg-gray-100'
      }`}
    >
      {children}
    </button>
  )
}

function DashboardMetricCard({
  title,
  value,
  helper,
  helperTone,
  icon,
  iconTone,
  accent,
}: {
  title: string
  value: string
  helper: string
  helperTone: string
  icon: string
  iconTone: string
  accent?: string
}) {
  return (
    <article className={`rounded-2xl border border-gray-200 bg-white p-[18px] ${accent ?? ''}`}>
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-[10px] font-extrabold tracking-[0.04em] text-gray-400 uppercase">{title}</p>
          <h3 className="mt-1 text-[22px] leading-tight font-black text-gray-900">{value}</h3>
          <p className={`mt-1 text-[10px] font-bold ${helperTone}`}>{helper}</p>
        </div>
        <div className={`flex h-9 w-9 items-center justify-center rounded-xl text-base ${iconTone}`}>
          <i className={icon} />
        </div>
      </div>
    </article>
  )
}

function relativeTime(value: string | null) {
  if (!value) {
    return '방금 전'
  }

  const diffMinutes = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 60000))

  if (diffMinutes < 1) return '방금 전'
  if (diffMinutes < 60) return `${diffMinutes}분 전`
  if (diffMinutes < 1440) return `${Math.floor(diffMinutes / 60)}시간 전`
  return `${Math.floor(diffMinutes / 1440)}일 전`
}

function getNotificationTitle(item: InstructorNotificationItem) {
  switch (item.type) {
    case 'QNA':
      return '새 Q&A'
    case 'REVENUE':
      return '수익 업데이트'
    case 'REVIEW':
      return '리뷰 알림'
    default:
      return item.type
  }
}

function DonutChart({
  segments,
}: {
  segments: Array<{ label: string; value: number; color: string }>
}) {
  const radius = 58
  const circumference = 2 * Math.PI * radius
  let accumulated = 0

  return (
    <div className="flex items-center gap-5">
      <div className="relative h-40 w-40 shrink-0">
        <svg viewBox="0 0 160 160" className="h-full w-full -rotate-90">
          <circle cx="80" cy="80" r={radius} fill="transparent" stroke="#F3F4F6" strokeWidth="18" />
          {segments.map((segment) => {
            const dash = (segment.value / 100) * circumference
            const dashOffset = circumference - accumulated
            accumulated += dash

            return (
              <circle
                key={segment.label}
                cx="80"
                cy="80"
                r={radius}
                fill="transparent"
                stroke={segment.color}
                strokeWidth="18"
                strokeDasharray={`${dash} ${circumference - dash}`}
                strokeDashoffset={dashOffset}
                strokeLinecap="round"
              />
            )
          })}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-xs font-extrabold tracking-[0.18em] text-gray-400 uppercase">비중</span>
          <span className="mt-1 text-2xl font-black text-gray-900">100%</span>
        </div>
      </div>

      <div className="space-y-3">
        {segments.map((segment) => (
          <div key={segment.label} className="flex items-center gap-3 text-sm font-bold text-gray-700">
            <span className="h-3 w-3 rounded-full" style={{ backgroundColor: segment.color }} />
            <span className="min-w-16">{segment.label}</span>
            <span className="text-gray-400">{segment.value}%</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function SatisfactionBars({
  items,
}: {
  items: Array<{ label: string; value: number; color: string }>
}) {
  return (
    <div className="space-y-4">
      {items.map((item) => (
        <div key={item.label}>
          <div className="mb-2 flex items-center justify-between text-xs font-bold text-gray-600">
            <span>{item.label}</span>
            <span className="text-gray-900">{item.value.toFixed(1)}</span>
          </div>
          <div className="h-3 overflow-hidden rounded-full bg-gray-100">
            <div className={`h-full rounded-full ${item.color}`} style={{ width: `${(item.value / 5) * 100}%` }} />
          </div>
        </div>
      ))}
    </div>
  )
}

function buildCategorySegments(courses: InstructorCourseListItem[]) {
  const palette = ['#00C471', '#3B82F6', '#F59E0B', '#E5E7EB']
  const counts = new Map<string, number>()

  courses.forEach((course) => {
    const key = course.categoryLabel || '기타'
    counts.set(key, (counts.get(key) ?? 0) + 1)
  })

  const total = courses.length || 1
  return [...counts.entries()]
    .sort((left, right) => right[1] - left[1])
    .slice(0, 4)
    .map(([label, count], index) => ({
      label,
      value: Math.max(5, Math.round((count / total) * 100)),
      color: palette[index] ?? '#9CA3AF',
    }))
}

export default function InstructorDashboardPage({ session }: { session: AuthSession }) {
  const [activeTab, setActiveTab] = useState<DashboardTabKey>('learning')
  const [notifications, setNotifications] = useState<InstructorNotificationItem[]>([])
  const [courses, setCourses] = useState<InstructorCourseListItem[]>([])
  const [reviewSummary, setReviewSummary] = useState<InstructorReviewSummary | null>(null)
  const [reviews, setReviews] = useState<InstructorReviewListItem[]>([])
  const [unansweredQnaCount, setUnansweredQnaCount] = useState(0)
  const [netRevenue, setNetRevenue] = useState(0)
  const [mentoringBoard, setMentoringBoard] = useState<InstructorMentoringBoard | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [loadWarning, setLoadWarning] = useState<string | null>(null)
  const [notificationOpen, setNotificationOpen] = useState(false)
  const [tasks, setTasks] = useState([false, false])
  const notificationRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    if (!notificationOpen) {
      return
    }

    function handlePointerDown(event: MouseEvent) {
      if (!notificationRef.current?.contains(event.target as Node)) {
        setNotificationOpen(false)
      }
    }

    function handleEscape(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setNotificationOpen(false)
      }
    }

    document.addEventListener('mousedown', handlePointerDown)
    document.addEventListener('keydown', handleEscape)

    return () => {
      document.removeEventListener('mousedown', handlePointerDown)
      document.removeEventListener('keydown', handleEscape)
    }
  }, [notificationOpen])

  useEffect(() => {
    const controller = new AbortController()

    setLoading(true)
    setError(null)
    setLoadWarning(null)

    Promise.allSettled([
      instructorNotificationApi.getAll(controller.signal),
      instructorCourseApi.getCourses(controller.signal),
      instructorReviewApi.getSummary(controller.signal),
      instructorReviewApi.getReviews(controller.signal),
      instructorQnaApi.getInbox('UNANSWERED', controller.signal),
      instructorRevenueApi.getSummary(controller.signal),
      instructorMentoringApi.getBoard(controller.signal),
    ])
      .then((results) => {
        if (controller.signal.aborted) {
          return
        }

        const failures = results.filter((result) => result.status === 'rejected')

        if (failures.length === results.length) {
          const firstError = failures[0]
          setError(firstError.reason instanceof Error ? firstError.reason.message : '강사 대시보드 데이터를 불러오지 못했습니다.')
          return
        }

        const [
          notificationsResult,
          coursesResult,
          reviewSummaryResult,
          reviewsResult,
          qnaResult,
          revenueResult,
          mentoringBoardResult,
        ] = results

        setNotifications(notificationsResult.status === 'fulfilled' ? notificationsResult.value : [])
        setCourses(coursesResult.status === 'fulfilled' ? coursesResult.value : [])
        setReviewSummary(reviewSummaryResult.status === 'fulfilled' ? reviewSummaryResult.value : EMPTY_REVIEW_SUMMARY)
        setReviews(reviewsResult.status === 'fulfilled' ? reviewsResult.value : [])
        setUnansweredQnaCount(qnaResult.status === 'fulfilled' ? qnaResult.value.length : 0)
        setNetRevenue(revenueResult.status === 'fulfilled' ? revenueResult.value.netRevenue : 0)
        setMentoringBoard(mentoringBoardResult.status === 'fulfilled' ? mentoringBoardResult.value : EMPTY_MENTORING_BOARD)

        if (failures.length > 0) {
          setLoadWarning('일부 강사 대시보드 데이터만 불러왔습니다. 잠시 후 다시 새로고침해 주세요.')
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setLoading(false)
        }
      })

    return () => controller.abort()
  }, [])

  async function markNotificationRead(notificationId: number) {
    try {
      await instructorNotificationApi.markAsRead(notificationId)
      setNotifications((current) =>
        current.map((item) => (item.notificationId === notificationId ? { ...item, isRead: true } : item)),
      )
    } catch {
      // Ignore optimistic UI failures on dashboard interactions.
    }
  }

  async function markAllNotificationsRead() {
    const unread = notifications.filter((item) => !item.isRead)
    await Promise.all(unread.map((item) => instructorNotificationApi.markAsRead(item.notificationId).catch(() => null)))
    setNotifications((current) => current.map((item) => ({ ...item, isRead: true })))
  }

  function toggleTask(index: number) {
    setTasks((current) => current.map((checked, currentIndex) => (currentIndex === index ? !checked : checked)))
  }

  if (loading) {
    return (
      <div className="p-6">
        <LoadingCard label="강사 대시보드를 불러오는 중입니다." />
      </div>
    )
  }

  if (error || !reviewSummary || !mentoringBoard) {
    return (
      <div className="p-6">
        <ErrorCard message={error ?? '대시보드를 불러오지 못했습니다.'} />
      </div>
    )
  }

  const unreadCount = notifications.reduce((count, item) => count + (item.isRead ? 0 : 1), 0)
  const unreadLabel = unreadCount > 0 ? `읽지 않은 알림 ${unreadCount}개가 있습니다.` : '새 알림이 없습니다.'
  const averageProgress =
    courses.length > 0 ? courses.reduce((sum, item) => sum + item.averageProgressPercent, 0) / courses.length : 0
  const categorySegments = buildCategorySegments(courses)
  const topCourses = [...courses]
    .sort((left, right) => right.averageRating - left.averageRating)
    .slice(0, 3)
    .map((item, index) => ({
      label: item.title,
      value: item.averageRating,
      color: index === 0 ? 'bg-brand' : index === 1 ? 'bg-blue-500' : 'bg-violet-500',
    }))
  const latestReview = reviews[0]
  const pendingMentoringRequests = mentoringBoard.requests.length
  const recruitingProjects = mentoringBoard.projects.length
  const ongoingProjects = mentoringBoard.ongoingProjects.length
  const mentoringFillRate =
    mentoringBoard.projects.length > 0
      ? Math.round(
          (mentoringBoard.projects.reduce((sum, item) => sum + item.current, 0) /
            Math.max(1, mentoringBoard.projects.reduce((sum, item) => sum + item.total, 0))) *
            100,
        )
      : 0

  return (
    <div className="flex min-h-[calc(100vh-64px)] flex-col bg-[#F3F4F6]">
      <header className="sticky top-0 z-30 border-b border-gray-200 bg-white px-8 py-4">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-gray-900">{session.name} 강사 대시보드</h1>
            <p className="mt-1 text-xs text-gray-500">{unreadLabel}</p>
          </div>

          <div ref={notificationRef} className="relative">
            <button
              type="button"
              onClick={() => setNotificationOpen((current) => !current)}
              className="relative flex h-10 w-10 items-center justify-center rounded-full bg-gray-100 text-gray-500 transition hover:bg-gray-200"
              aria-expanded={notificationOpen}
              aria-haspopup="menu"
            >
              <i className="fas fa-bell" />
              {unreadCount > 0 ? <span className="absolute top-2 right-2.5 h-2 w-2 rounded-full border-2 border-white bg-red-500" /> : null}
            </button>

            {notificationOpen ? (
              <div className="absolute right-0 z-50 mt-3 w-[340px] overflow-hidden rounded-2xl border border-gray-200 bg-white shadow-2xl shadow-gray-900/10">
                <div className="flex items-center justify-between gap-3 border-b border-gray-100 px-4 py-3">
                  <h4 className="text-sm font-black text-gray-900">알림</h4>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={markAllNotificationsRead}
                      className="rounded-lg border border-gray-200 bg-white px-2.5 py-1.5 text-[11px] font-black text-gray-700 transition hover:bg-gray-50"
                    >
                      모두 읽음
                    </button>
                  </div>
                </div>

                <div className="max-h-80 overflow-y-auto">
                  {notifications.length > 0 ? (
                    notifications.map((item) => (
                      <button
                        key={item.notificationId}
                        type="button"
                        onClick={() => markNotificationRead(item.notificationId)}
                        className="flex w-full items-start gap-3 px-4 py-3 text-left transition hover:bg-gray-50"
                      >
                        <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${item.isRead ? 'bg-gray-300' : 'bg-red-500'}`} />
                        <span className="min-w-0">
                          <span className="block text-sm font-extrabold text-gray-900">{getNotificationTitle(item)}</span>
                          <span className="mt-1 block text-xs leading-5 text-gray-500">{item.message}</span>
                          <span className="mt-2 block text-[11px] text-gray-400">{relativeTime(item.createdAt)}</span>
                        </span>
                      </button>
                    ))
                  ) : (
                    <div className="px-6 py-8 text-center">
                      <p className="text-sm font-extrabold text-gray-400">표시할 알림이 없습니다.</p>
                    </div>
                  )}
                </div>
              </div>
            ) : null}
          </div>
        </div>

        <div className="flex gap-2">
          <DashboardTabButton active={activeTab === 'learning'} onClick={() => setActiveTab('learning')}>
            학습
          </DashboardTabButton>
          <DashboardTabButton active={activeTab === 'mentoring'} onClick={() => setActiveTab('mentoring')}>
            프로젝트
          </DashboardTabButton>
        </div>
      </header>

      <div className="flex-1 p-6">
        {loadWarning ? (
          <div className="mb-5 rounded-2xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm font-semibold text-amber-800">
            {loadWarning}
          </div>
        ) : null}

        {activeTab === 'learning' ? (
          <div>
            <div className="mb-5 grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-4">
              <DashboardMetricCard
                title="총 수강생"
                value={`${formatNumber(courses.reduce((sum, item) => sum + item.studentCount, 0))}`}
                helper={`공개 강의 ${courses.length}개`}
                helperTone="text-green-600"
                icon="fas fa-users"
                iconTone="bg-blue-50 text-blue-500"
              />
              <DashboardMetricCard
                title="평균 평점"
                value={reviewSummary.averageRating.toFixed(1)}
                helper={`/ 5.0 기준 · 리뷰 ${reviewSummary.totalReviews}개`}
                helperTone="text-gray-400"
                icon="fas fa-star"
                iconTone="bg-yellow-50 text-yellow-500"
              />
              <DashboardMetricCard
                title="미답변 Q&A"
                value={`${unansweredQnaCount}`}
                helper="답변 필요"
                helperTone="text-gray-500"
                icon="fas fa-comment-dots"
                iconTone="bg-red-50 text-red-500"
                accent="border-l-4 border-l-red-500"
              />
              <DashboardMetricCard
                title="평균 진도율"
                value={`${averageProgress.toFixed(0)}%`}
                helper={`순수익 ${formatNumber(netRevenue)}`}
                helperTone="text-brand"
                icon="fas fa-chart-line"
                iconTone="bg-green-50 text-brand"
              />
            </div>

            <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
              <div className="space-y-5 xl:col-span-2">
                <article className="rounded-2xl border border-green-200 bg-gradient-to-br from-green-50 to-white p-5">
                  <div className="flex items-start gap-4">
                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-brand text-white shadow-sm">
                      <i className="fas fa-robot" />
                    </div>
                    <div>
                      <h3 className="mb-1 text-[15px] font-extrabold text-gray-900">AI 강의 인사이트</h3>
                      <p className="text-sm leading-6 text-gray-600">
                        {courses.length > 0
                          ? `${courses[0].title} 강의에 미답변 질문 ${courses[0].pendingQuestionCount}건이 있고 평균 진도율은 ${courses[0].averageProgressPercent.toFixed(0)}%입니다.`
                          : '첫 강의가 공개되면 강의 데이터가 여기에 표시됩니다.'}
                      </p>
                    </div>
                  </div>
                </article>

                <div className="grid grid-cols-1 gap-5 md:grid-cols-2">
                  <article className="rounded-2xl border border-gray-200 bg-white p-5">
                    <h3 className="mb-4 flex items-center gap-2 text-sm font-extrabold text-gray-900">
                      <i className="fas fa-id-badge text-blue-500" /> 강의 구성
                    </h3>
                    <DonutChart segments={categorySegments.length > 0 ? categorySegments : [{ label: '기타', value: 100, color: '#00C471' }]} />
                  </article>

                  <article className="rounded-2xl border border-gray-200 bg-white p-5">
                    <h3 className="mb-4 flex items-center gap-2 text-sm font-extrabold text-gray-900">
                      <i className="fas fa-thumbs-up text-yellow-500" /> 평점 상위 강의
                    </h3>
                    <SatisfactionBars items={topCourses.length > 0 ? topCourses : [{ label: '강의 없음', value: 0, color: 'bg-gray-300' }]} />
                  </article>
                </div>
              </div>

              <div className="space-y-5">
                <article className="rounded-2xl border border-gray-200 bg-white p-5">
                  <h3 className="mb-3 text-sm font-extrabold text-gray-900">오늘 할 일</h3>
                  <div className="space-y-2">
                    {[`Q&A 답변 (${unansweredQnaCount})`, `리뷰 피드백 (${reviewSummary.unansweredCount})`].map((task, index) => (
                      <label
                        key={task}
                        className="flex cursor-pointer items-center gap-3 rounded-lg p-2 transition hover:bg-gray-50"
                      >
                        <input
                          type="checkbox"
                          checked={tasks[index]}
                          onChange={() => toggleTask(index)}
                          className="h-4 w-4 accent-green-500"
                        />
                        <span className="text-sm text-gray-700">{task}</span>
                      </label>
                    ))}
                  </div>
                </article>

                <article className="rounded-2xl bg-gray-900 p-5 text-white">
                  <h3 className="mb-3 text-sm font-extrabold">
                    <i className="fas fa-heart mr-2 text-red-500" /> 최근 리뷰
                  </h3>
                  <div className="rounded-xl bg-white/10 p-4">
                    <p className="text-xs leading-relaxed text-gray-200">{latestReview?.content ?? '아직 작성된 리뷰가 없습니다.'}</p>
                    <p className="mt-2 text-right text-[10px] text-gray-400">
                      - {latestReview?.learnerName ?? 'DevPath'}
                    </p>
                  </div>
                </article>
              </div>
            </div>
          </div>
        ) : (
          <div>
            <div className="mb-5 grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-4">
              <DashboardMetricCard
                title="모집 중"
                value={`${recruitingProjects}`}
                helper={`대기 신청 ${pendingMentoringRequests}건`}
                helperTone="text-blue-600"
                icon="fas fa-layer-group"
                iconTone="bg-blue-50 text-blue-500"
              />
              <DashboardMetricCard
                title="진행 중"
                value={`${ongoingProjects}`}
                helper="현재 운영 중"
                helperTone="text-gray-500"
                icon="fas fa-video"
                iconTone="bg-purple-50 text-purple-500"
                accent="border-l-4 border-l-purple-500"
              />
              <DashboardMetricCard
                title="검토 중"
                value={`${pendingMentoringRequests}`}
                helper="신청서 검토 대기"
                helperTone="text-gray-500"
                icon="fas fa-project-diagram"
                iconTone="bg-gray-50 text-gray-400"
              />
              <DashboardMetricCard
                title="충원율"
                value={`${mentoringFillRate}%`}
                helper="프로젝트 좌석 충원"
                helperTone="text-green-600"
                icon="fas fa-thumbs-up"
                iconTone="bg-green-50 text-green-500"
              />
            </div>

            <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
              <div className="space-y-5 xl:col-span-2">
                <article className="rounded-2xl border border-blue-200 bg-gradient-to-br from-blue-50 to-white p-5">
                  <div className="flex items-start gap-4">
                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-blue-500 text-white">
                      <i className="fas fa-lightbulb" />
                    </div>
                    <div>
                      <h3 className="mb-1 text-[15px] font-extrabold text-gray-900">AI 멘토링 브리프</h3>
                      <p className="text-sm leading-6 text-gray-600">
                        {pendingMentoringRequests > 0
                          ? `새 신청 ${pendingMentoringRequests}건이 대기 중입니다. 오늘 몇 건만 승인해도 온보딩 속도가 빨라집니다.`
                          : '대기 중인 신청이 없습니다. 진행 중인 프로젝트는 안정적입니다.'}
                      </p>
                    </div>
                  </div>
                </article>

                <article className="rounded-2xl border border-gray-200 bg-white p-5">
                  <h3 className="mb-6 flex items-center gap-2 text-base font-extrabold text-gray-900">
                    <i className="fas fa-users text-sm text-gray-400" /> 프로젝트 진행 현황
                  </h3>
                  <div className="space-y-8">
                    {mentoringBoard.ongoingProjects.slice(0, 2).map((project) => (
                      <div key={project.id}>
                        <div className="mb-3 flex items-end justify-between">
                          <div>
                            <h4 className="text-sm font-extrabold text-gray-900">{project.title}</h4>
                            <p className="mt-1 text-[11px] text-gray-400">{project.subtitle}</p>
                          </div>
                          <span className="rounded bg-blue-50 px-2 py-1 text-[11px] font-extrabold text-blue-600">
                            {project.week}주차 ({project.progress}%)
                          </span>
                        </div>
                        <div className="h-2 overflow-hidden rounded-full bg-gray-100">
                          <div className="h-full rounded-full bg-blue-500" style={{ width: `${project.progress}%` }} />
                        </div>
                      </div>
                    ))}
                  </div>
                </article>

                <article className="overflow-hidden rounded-2xl border border-gray-200 bg-white">
                  <div className="border-b border-gray-100 bg-white p-5">
                    <h3 className="text-base font-extrabold text-gray-900">신청 대기열</h3>
                  </div>
                  <table className="w-full text-left text-sm">
                    <tbody className="divide-y divide-gray-100">
                      {mentoringBoard.requests.slice(0, 3).map((request) => (
                        <tr key={request.id} className="transition hover:bg-gray-50">
                          <td className="w-16 px-6 py-4">
                            <span className="rounded bg-gray-100 px-2 py-1 text-[10px] font-extrabold uppercase">{request.mode}</span>
                          </td>
                          <td className="px-4 font-extrabold">{request.projectTitle}</td>
                          <td className="px-4 text-xs text-gray-400">{request.role}</td>
                          <td className="px-6 text-right font-extrabold text-blue-500">{request.applicantName}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </article>
              </div>

              <div className="space-y-5">
                <article className="rounded-2xl border border-gray-200 bg-white p-5">
                  <h3 className="mb-5 flex items-center gap-2 text-sm font-extrabold text-gray-900">
                    <i className="fas fa-calendar-alt text-brand" /> 멘토링 타임라인
                  </h3>
                  <div className="space-y-4">
                    {mentoringBoard.ongoingProjects.slice(0, 2).map((project, index) => (
                      <div
                        key={project.id}
                        className={`relative rounded-2xl border p-4 ${index === 0 ? 'border-blue-100 bg-blue-50' : 'border-gray-100 bg-gray-50 opacity-70'}`}
                      >
                        <p className={`mb-1 text-xs font-black ${index === 0 ? 'text-blue-600' : 'text-gray-400'}`}>{project.week}주차</p>
                        <p className="text-sm font-extrabold text-gray-900">{project.primaryAction}</p>
                      </div>
                    ))}
                  </div>
                </article>

                <article className="flex flex-col items-center justify-center rounded-2xl border-2 border-dashed border-gray-200 bg-gray-50/50 py-10">
                  <div className="mb-3 flex h-11 w-11 items-center justify-center rounded-full bg-gray-200 text-lg">
                    <i className="fas fa-plus" />
                  </div>
                  <p className="mb-3 text-sm font-extrabold text-gray-400">새 멘토링 프로젝트 시작</p>
                  <button type="button" className="rounded-xl border border-gray-300 bg-white px-6 py-2 text-xs font-extrabold shadow-sm">
                    멘토링 보드 열기
                  </button>
                </article>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
