import { useEffect, useState } from 'react'
import { ErrorCard, LoadingCard, formatDate } from '../../account/ui'
import { instructorReviewApi } from '../../lib/api'
import type { AuthSession } from '../../types/auth'
import type {
  InstructorReviewHelpful,
  InstructorReviewListItem,
  InstructorReviewSummary,
  InstructorReviewTemplate,
} from '../../types/instructor'

type ReviewTabKey = 'all' | 'unreplied' | 'low'
type TemplateOption = {
  key: string
  title: string
  description: string
  content: string
}

const fallbackReplyTemplates: TemplateOption[] = [
  {
    key: 'thanks',
    title: '감사 인사',
    description: '소중한 수강평에 감사 인사를 남깁니다.',
    content: '소중한 수강평 감사합니다. 완강까지 꾸준히 학습하실 수 있도록 계속 보완하겠습니다.',
  },
  {
    key: 'apology',
    title: '사과 및 개선 약속',
    description: '불편을 겪은 수강생에게 빠르게 응답합니다.',
    content: '불편을 드려 죄송합니다. 말씀해주신 내용은 바로 확인해서 개선하겠습니다.',
  },
  {
    key: 'guide',
    title: '학습 가이드 제안',
    description: '다음 학습 흐름이나 보충 자료를 안내합니다.',
    content: '어려움을 느끼셨다면 해당 구간의 보충 자료와 이전 섹션을 함께 복습해보시는 것을 권장드립니다.',
  },
  {
    key: 'review',
    title: '만족 리뷰 응답',
    description: '긍정적인 리뷰에 따뜻하게 응답합니다.',
    content: '도움이 되셨다니 다행입니다. 더 좋은 강의 경험을 드릴 수 있도록 계속 업데이트하겠습니다.',
  },
]

function StarRow({ rating }: { rating: number }) {
  const fullStars = Math.floor(rating)
  const hasHalfStar = rating % 1 !== 0

  return (
    <div className="flex text-xs text-yellow-400">
      {Array.from({ length: 5 }).map((_, index) => {
        if (index < fullStars) {
          return <i key={index} className="fas fa-star" />
        }

        if (index === fullStars && hasHalfStar) {
          return <i key={index} className="fas fa-star-half-alt" />
        }

        return <i key={index} className="far fa-star" />
      })}
    </div>
  )
}

function toneClass(tone: 'orange' | 'red' | 'gray' | 'green' | 'blue') {
  switch (tone) {
    case 'orange':
      return 'border-orange-200 bg-orange-100 text-orange-600'
    case 'red':
      return 'border-red-100 bg-red-50 text-red-600'
    case 'green':
      return 'border-green-100 bg-green-50 text-green-700'
    case 'blue':
      return 'border-blue-100 bg-blue-50 text-blue-700'
    default:
      return 'border-gray-200 bg-gray-100 text-gray-500'
  }
}

function sortReviews(reviews: InstructorReviewListItem[], sort: string) {
  const next = [...reviews]

  next.sort((left, right) => {
    const leftTime = new Date(left.createdAt ?? 0).getTime()
    const rightTime = new Date(right.createdAt ?? 0).getTime()

    if (sort === 'oldest') {
      return leftTime - rightTime
    }

    if (sort === 'high') {
      return right.rating - left.rating
    }

    if (sort === 'low') {
      return left.rating - right.rating
    }

    return rightTime - leftTime
  })

  return next
}

function relativeDateLabel(value: string | null) {
  if (!value) {
    return '날짜 없음'
  }

  const diffMinutes = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 60000))

  if (diffMinutes < 1) return '방금 전'
  if (diffMinutes < 60) return `${diffMinutes}분 전`
  if (diffMinutes < 1440) return `${Math.floor(diffMinutes / 60)}시간 전`
  if (diffMinutes < 10080) return `${Math.floor(diffMinutes / 1440)}일 전`
  return formatDate(value)
}

function getIssueMeta(review: InstructorReviewListItem) {
  if (review.reply) {
    return {
      tone: 'gray' as const,
      label: '답변완료',
      status: 'replied' as const,
      icon: 'fa-check',
    }
  }

  if (review.status === 'UNSATISFIED' || review.rating <= 2) {
    return {
      tone: 'red' as const,
      label: '불만족',
      status: 'unreplied' as const,
      icon: 'fa-exclamation-triangle',
    }
  }

  return {
    tone: 'orange' as const,
    label: '미답변',
    status: 'unreplied' as const,
    icon: 'fa-exclamation-circle',
  }
}

function buildKeywordTags(reviews: InstructorReviewListItem[]) {
  const counts = new Map<string, number>()

  reviews.forEach((review) => {
    review.issueTags.forEach((tag) => {
      const normalized = tag.trim()
      if (!normalized) {
        return
      }

      counts.set(normalized, (counts.get(normalized) ?? 0) + 1)
    })
  })

  if (counts.size === 0) {
    const unansweredCount = reviews.filter((review) => !review.reply).length
    const lowRatingCount = reviews.filter((review) => review.rating <= 3).length
    const fallback = []

    if (unansweredCount > 0) {
      fallback.push({ label: `#답글_대기 (${unansweredCount})`, issue: true })
    }

    if (lowRatingCount > 0) {
      fallback.push({ label: `#저평점 (${lowRatingCount})`, issue: true })
    }

    return fallback
  }

  return [...counts.entries()]
    .sort((left, right) => right[1] - left[1])
    .slice(0, 6)
    .map(([label, count]) => ({
      label: `#${label.replace(/\s+/g, '_')} (${count})`,
      issue: true,
    }))
}

async function fetchReviewData(signal?: AbortSignal) {
  return Promise.all([
    instructorReviewApi.getReviews(signal),
    instructorReviewApi.getSummary(signal),
    instructorReviewApi.getHelpful(signal),
    instructorReviewApi.getTemplates(signal),
  ])
}

export default function InstructorReviewsPage({ session }: { session: AuthSession }) {
  const [reviews, setReviews] = useState<InstructorReviewListItem[]>([])
  const [summary, setSummary] = useState<InstructorReviewSummary | null>(null)
  const [helpful, setHelpful] = useState<InstructorReviewHelpful | null>(null)
  const [templates, setTemplates] = useState<InstructorReviewTemplate[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [currentTab, setCurrentTab] = useState<ReviewTabKey>('all')
  const [courseFilter, setCourseFilter] = useState('all')
  const [sortFilter, setSortFilter] = useState('latest')
  const [starFilter, setStarFilter] = useState('all')
  const [search, setSearch] = useState('')
  const [openReplyFormId, setOpenReplyFormId] = useState<number | null>(null)
  const [templateModalOpen, setTemplateModalOpen] = useState(false)
  const [activeReplyTargetId, setActiveReplyTargetId] = useState<number | null>(null)
  const [replyDrafts, setReplyDrafts] = useState<Record<number, string>>({})

  useEffect(() => {
    const controller = new AbortController()

    setLoading(true)
    setError(null)

    fetchReviewData(controller.signal)
      .then(([nextReviews, nextSummary, nextHelpful, nextTemplates]) => {
        setReviews(nextReviews)
        setSummary(nextSummary)
        setHelpful(nextHelpful)
        setTemplates(nextTemplates)
      })
      .catch((nextError: Error) => {
        if (controller.signal.aborted) {
          return
        }

        setError(nextError.message)
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setLoading(false)
        }
      })

    return () => controller.abort()
  }, [])

  async function refreshReviewData() {
    const [nextReviews, nextSummary, nextHelpful, nextTemplates] = await fetchReviewData()
    setReviews(nextReviews)
    setSummary(nextSummary)
    setHelpful(nextHelpful)
    setTemplates(nextTemplates)
  }

  const filteredReviews = sortReviews(
    reviews.filter((review) => {
      const issueMeta = getIssueMeta(review)

      if (courseFilter !== 'all' && String(review.courseId) !== courseFilter) {
        return false
      }

      if (currentTab === 'unreplied' && issueMeta.status !== 'unreplied') {
        return false
      }

      if (currentTab === 'low' && review.rating > 3) {
        return false
      }

      if (starFilter === '5' && review.rating !== 5) {
        return false
      }

      if (starFilter === '4' && review.rating < 4) {
        return false
      }

      if (starFilter === '3' && review.rating > 3) {
        return false
      }

      if (search.trim()) {
        const searchText = `${review.courseTitle} ${review.learnerName} ${review.content} ${review.issueTags.join(' ')}`.toLowerCase()
        if (!searchText.includes(search.trim().toLowerCase())) {
          return false
        }
      }

      return true
    }),
    sortFilter,
  )

  const courseOptions = Array.from(
    new Map(reviews.map((review) => [String(review.courseId), review.courseTitle])).entries(),
  )
  const keywordTags = buildKeywordTags(reviews)
  const totalReviewCount = summary?.totalReviews ?? reviews.length
  const unansweredCount = helpful?.unansweredCount ?? reviews.filter((review) => !review.reply).length
  const lowRatingCount = reviews.filter((review) => review.rating <= 3).length
  const ratingRows = [5, 4, 3, 2, 1].map((stars) => {
    const count = Number(summary?.ratingDistribution?.[String(stars)] ?? 0)
    const percent = totalReviewCount > 0 ? Math.round((count / totalReviewCount) * 100) : 0

    return {
      stars,
      percent,
      tone:
        stars === 5
          ? 'bg-green-500'
          : stars === 4
            ? 'bg-green-400'
            : stars === 3
              ? 'bg-yellow-400'
              : stars === 2
                ? 'bg-orange-400'
                : 'bg-red-400',
      active: stars >= 4,
    }
  })
  const templateOptions: TemplateOption[] =
    templates.length > 0
      ? templates.map((template) => ({
          key: String(template.id),
          title: template.title,
          description: template.content.length > 60 ? `${template.content.slice(0, 60)}...` : template.content,
          content: template.content,
        }))
      : fallbackReplyTemplates

  function setUnrepliedFilter() {
    setCurrentTab('unreplied')
  }

  function toggleReplyForm(review: InstructorReviewListItem) {
    setOpenReplyFormId((current) => (current === review.reviewId ? null : review.reviewId))
    setReplyDrafts((current) => ({
      ...current,
      [review.reviewId]: current[review.reviewId] ?? review.reply?.content ?? '',
    }))
  }

  function updateDraft(reviewId: number, value: string) {
    setReplyDrafts((current) => ({ ...current, [reviewId]: value }))
  }

  function openTemplateModal(reviewId: number) {
    setActiveReplyTargetId(reviewId)
    setTemplateModalOpen(true)
  }

  function insertTemplate(template: TemplateOption) {
    if (!activeReplyTargetId) {
      return
    }

    setReplyDrafts((current) => ({
      ...current,
      [activeReplyTargetId]: current[activeReplyTargetId]
        ? `${current[activeReplyTargetId].trimEnd()}\n\n${template.content}`
        : template.content,
    }))
    setTemplateModalOpen(false)
  }

  async function submitReply(reviewId: number) {
    const review = reviews.find((item) => item.reviewId === reviewId)
    const draft = replyDrafts[reviewId]?.trim()

    if (!review) {
      return
    }

    if (!draft) {
      window.alert('답글 내용을 입력해 주세요.')
      return
    }

    try {
      if (review.reply) {
        await instructorReviewApi.updateReply(reviewId, review.reply.replyId, draft)
      } else {
        await instructorReviewApi.createReply(reviewId, draft)
      }

      await refreshReviewData()
      setOpenReplyFormId(null)
    } catch (nextError) {
      window.alert(nextError instanceof Error ? nextError.message : '답글 저장에 실패했습니다.')
    }
  }

  async function registerIssue(reviewId: number) {
    const review = reviews.find((item) => item.reviewId === reviewId)
    if (!review) {
      return
    }

    const nextTags =
      review.issueTags.length > 0
        ? review.issueTags
        : [review.rating <= 2 ? 'urgent-follow-up' : 'follow-up']

    try {
      await instructorReviewApi.addIssueTags(reviewId, nextTags)
      await refreshReviewData()
    } catch (nextError) {
      window.alert(nextError instanceof Error ? nextError.message : '이슈 등록에 실패했습니다.')
    }
  }

  if (loading) {
    return (
      <div className="p-6">
        <LoadingCard label="수강평 데이터를 불러오는 중입니다." />
      </div>
    )
  }

  if (error || !summary || !helpful) {
    return (
      <div className="p-6">
        <ErrorCard message={error ?? '수강평 데이터를 불러오지 못했습니다.'} />
      </div>
    )
  }

  return (
    <div className="p-6">
      <div className="mx-auto max-w-[1320px]">
        <div className="mb-6 flex flex-col justify-between gap-4 md:flex-row md:items-end">
          <div>
            <h1 className="mb-1 text-2xl font-black tracking-tight text-gray-900">수강평 관리</h1>
            <p className="text-sm font-medium text-gray-500">수강생의 피드백을 확인하고 소통하여 강의 퀄리티를 높여보세요.</p>
          </div>
          <div className="flex items-center gap-2">
            <div className="relative">
              <select
                value={courseFilter}
                onChange={(event) => setCourseFilter(event.target.value)}
                className="min-w-[240px] cursor-pointer appearance-none rounded-lg border border-gray-200 bg-white py-2 pl-4 pr-10 text-sm font-bold text-gray-700 shadow-sm outline-none focus:border-green-500"
              >
                <option value="all">📚 전체 강좌 보기</option>
                {courseOptions.map(([courseId, courseTitle]) => (
                  <option key={courseId} value={courseId}>
                    {courseTitle}
                  </option>
                ))}
              </select>
              <i className="fas fa-chevron-down pointer-events-none absolute top-3 right-3 text-xs text-gray-400" />
            </div>

            <div className="flex items-center gap-2 rounded-lg border border-gray-200 bg-white px-3 py-2 shadow-sm">
              <i className="fas fa-search text-gray-400" />
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                type="text"
                placeholder="검색"
                className="w-32 text-sm font-bold text-gray-600 outline-none"
              />
            </div>
          </div>
        </div>

        <div className="mb-8 grid grid-cols-1 gap-5 md:grid-cols-3">
          <article className="rounded-[28px] border border-gray-200 bg-white p-6 shadow-sm">
            <div className="mb-4 flex items-center justify-between">
              <span className="text-xs font-extrabold tracking-[0.22em] text-gray-400 uppercase">Average Rating</span>
              <span className="rounded bg-green-100 px-2 py-1 text-[10px] font-bold text-green-700">전체 기준</span>
            </div>
            <div className="flex items-baseline gap-2">
              <span className="text-4xl font-black text-gray-900">{summary.averageRating.toFixed(1)}</span>
              <span className="text-sm font-bold text-gray-400">/ 5.0</span>
            </div>
            <div className="mt-4 space-y-2">
              {ratingRows.map((row) => (
                <div key={row.stars} className="flex items-center gap-2 text-xs font-bold text-gray-500">
                  <span className="w-3">{row.stars}</span>
                  <i className={`fas fa-star text-[10px] ${row.active ? 'text-yellow-400' : 'text-gray-300'}`} />
                  <div className="h-2 flex-1 overflow-hidden rounded-full bg-gray-100">
                    <div className={`h-full ${row.tone}`} style={{ width: `${row.percent}%` }} />
                  </div>
                  <span className="w-8 text-right">{row.percent}%</span>
                </div>
              ))}
            </div>
          </article>

          <article className="relative overflow-hidden rounded-[28px] border border-gray-200 bg-white p-6 shadow-sm">
            <div className="absolute top-0 right-0 p-4 opacity-10">
              <i className="fas fa-comment-dots text-8xl text-orange-500" />
            </div>
            <div className="relative z-10 mb-4 flex items-center justify-between">
              <span className="text-xs font-extrabold tracking-[0.22em] text-gray-400 uppercase">Pending Replies</span>
              <span className="rounded bg-orange-100 px-2 py-1 text-[10px] font-bold text-orange-700">Action Needed</span>
            </div>
            <div className="relative z-10">
              <div className="mb-1 text-4xl font-black text-gray-900">
                {unansweredCount}
                <span className="ml-1 text-lg font-bold text-gray-400">건</span>
              </div>
              <p className="text-xs font-bold text-gray-500">답변을 기다리는 수강평이 있습니다.</p>
            </div>
            <div className="relative z-10 mt-6">
              <button
                type="button"
                onClick={setUnrepliedFilter}
                className="w-full rounded-lg bg-orange-500 py-2 text-xs font-bold text-white shadow-md transition hover:bg-orange-600"
              >
                미답변 리뷰 모아보기 <i className="fas fa-arrow-right ml-1" />
              </button>
            </div>
          </article>

          <article className="rounded-[28px] border border-gray-200 bg-white p-6 shadow-sm">
            <div className="mb-4 flex items-center justify-between">
              <span className="text-xs font-extrabold tracking-[0.22em] text-gray-400 uppercase">Review Keywords</span>
              <i className="fas fa-lightbulb text-yellow-400" />
            </div>
            <div className="flex min-h-[108px] flex-wrap content-start gap-2">
              {keywordTags.length > 0 ? (
                keywordTags.map(({ label, issue }) => (
                  <span
                    key={label}
                    className={`rounded-full px-3 py-1 text-xs font-bold ${
                      issue ? 'bg-orange-50 text-orange-600 ring-1 ring-orange-100' : 'bg-gray-100 text-gray-600'
                    }`}
                  >
                    {label}
                  </span>
                ))
              ) : (
                <span className="text-xs font-bold text-gray-400">아직 집계된 이슈 태그가 없습니다.</span>
              )}
            </div>
            <p className="mt-2 text-right text-[10px] font-bold text-gray-400">* 전체 리뷰 분석</p>
          </article>
        </div>

        <div className="mb-4 flex flex-wrap gap-2 rounded-[24px] border border-gray-200 bg-white p-2 shadow-sm">
          {[
            { key: 'all', label: '전체 수강평', count: String(totalReviewCount) },
            { key: 'unreplied', label: '미답변', count: String(unansweredCount) },
            { key: 'low', label: '별점 3점 이하', count: String(lowRatingCount) },
          ].map((tab) => (
            <button
              key={tab.key}
              type="button"
              onClick={() => setCurrentTab(tab.key as ReviewTabKey)}
              className={`rounded-2xl px-4 py-3 text-sm font-bold transition ${
                currentTab === tab.key ? 'bg-gray-900 text-white' : 'text-gray-500 hover:bg-gray-50 hover:text-gray-800'
              }`}
            >
              {tab.label}{' '}
              <span
                className={`ml-1 rounded-full px-2 py-0.5 text-[11px] font-extrabold ${
                  currentTab === tab.key
                    ? 'bg-white/15 text-white'
                    : tab.key === 'unreplied'
                      ? 'bg-orange-100 text-orange-600'
                      : 'bg-gray-100 text-gray-600'
                }`}
              >
                {tab.count}
              </span>
            </button>
          ))}
        </div>

        <div className="mb-5 flex flex-col gap-3 rounded-[24px] border border-gray-200 bg-white px-4 py-3 shadow-sm md:flex-row md:items-center md:justify-between">
          <div className="flex gap-2">
            <select
              value={sortFilter}
              onChange={(event) => setSortFilter(event.target.value)}
              className="rounded-xl border border-gray-200 bg-white px-3 py-2 text-sm font-bold text-gray-600 outline-none focus:border-brand"
            >
              <option value="latest">🕒 최신순</option>
              <option value="oldest">오래된순</option>
              <option value="high">별점 높은순</option>
              <option value="low">별점 낮은순</option>
            </select>
            <select
              value={starFilter}
              onChange={(event) => setStarFilter(event.target.value)}
              className="rounded-xl border border-gray-200 bg-white px-3 py-2 text-sm font-bold text-gray-600 outline-none focus:border-brand"
            >
              <option value="all">⭐ 별점 전체</option>
              <option value="5">5점만</option>
              <option value="4">4점만</option>
              <option value="3">3점 이하</option>
            </select>
          </div>
          <div className="text-xs font-bold text-gray-400">
            총 <span className="text-gray-900">{filteredReviews.length}</span>개의 리뷰가 표시됩니다.
          </div>
        </div>

        <div className="space-y-4">
          {filteredReviews.map((review) => {
            const issueMeta = getIssueMeta(review)
            const replyDateLabel = review.reply ? relativeDateLabel(review.reply.updatedAt ?? review.reply.createdAt) : ''

            return (
              <article key={review.reviewId} className="rounded-[28px] border border-gray-200 bg-white p-6 shadow-sm">
                <div className="flex items-start justify-between">
                  <div>
                    <span className="inline-flex rounded-full bg-emerald-50 px-3 py-1 text-xs font-extrabold text-emerald-700 ring-1 ring-emerald-100">
                      {review.courseTitle}
                    </span>
                    <div className="mt-2 mb-2 flex items-center gap-2">
                      <StarRow rating={review.rating} />
                      <span className="text-sm font-black text-gray-900">{review.rating.toFixed(1)}</span>
                      <span className="text-xs font-bold text-gray-400">·</span>
                      <span className="text-xs font-bold text-gray-500">{review.learnerName}</span>
                      <span className="text-xs font-bold text-gray-300">{relativeDateLabel(review.createdAt)}</span>
                    </div>
                  </div>
                  <span className={`rounded-full border px-2 py-1 text-[10px] font-bold ${toneClass(issueMeta.tone)}`}>
                    <i className={`fas ${issueMeta.icon} mr-1`} />
                    {issueMeta.label}
                  </span>
                </div>

                <p className="mb-3 text-sm leading-relaxed font-medium text-gray-700">{review.content}</p>

                {review.issueTags.length > 0 ? (
                  <div className="mb-4 flex gap-2">
                    {review.issueTags.map((tag) => (
                      <span
                        key={tag}
                        className="rounded-full bg-orange-50 px-3 py-1 text-xs font-bold text-orange-600 ring-1 ring-orange-100"
                      >
                        #{tag}
                      </span>
                    ))}
                  </div>
                ) : null}

                {review.reply ? (
                  <div className="mt-5 rounded-2xl bg-gray-50 p-4">
                    <div className="flex items-start gap-3">
                      <div className="flex flex-col items-center gap-1">
                        <img
                          src="https://api.dicebear.com/7.x/avataaars/svg?seed=Felix"
                          className="h-8 w-8 rounded-full border border-gray-200 bg-white shadow-sm"
                          alt="Instructor avatar"
                        />
                        <div className="my-1 h-full w-px bg-gray-200" />
                      </div>
                      <div className="min-w-0 flex-1 rounded-2xl border border-green-100 bg-white px-4 py-3">
                        <div className="mb-1 flex items-center justify-between">
                          <span className="text-xs font-black text-green-700">{review.reply.authorName || `${session.name} (Instructor)`}</span>
                          <span className="text-[10px] font-bold text-gray-400">{replyDateLabel}</span>
                        </div>
                        <p className="text-sm text-gray-700">{review.reply.content}</p>
                        <div className="mt-2 text-right">
                          <button
                            type="button"
                            onClick={() => toggleReplyForm(review)}
                            className="text-[10px] font-bold text-gray-400 underline transition hover:text-gray-600"
                          >
                            수정
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                ) : null}

                {openReplyFormId === review.reviewId ? (
                  <div className="mt-4 rounded-2xl border border-gray-100 bg-gray-50 p-4">
                    <div className="flex items-start gap-3">
                      <img
                        src="https://api.dicebear.com/7.x/avataaars/svg?seed=Felix"
                        className="h-8 w-8 rounded-full border border-gray-200 bg-white"
                        alt="Instructor avatar"
                      />
                      <div className="flex-1">
                        <textarea
                          rows={review.rating <= 3 ? 4 : 3}
                          value={replyDrafts[review.reviewId] ?? ''}
                          onChange={(event) => updateDraft(review.reviewId, event.target.value)}
                          placeholder={
                            review.rating <= 3
                              ? '학습 로드맵을 제안하거나 보충 자료를 안내해 드려보세요.'
                              : '수강생에게 격려의 말이나 해결책을 답변해주세요.'
                          }
                          className="w-full rounded-xl border border-gray-200 bg-white px-4 py-3 text-sm font-medium text-gray-700 outline-none transition focus:border-brand focus:shadow-[0_0_0_3px_rgba(0,196,113,0.12)]"
                        />
                        <div className="mt-2 flex items-center justify-between">
                          <button
                            type="button"
                            onClick={() => openTemplateModal(review.reviewId)}
                            className="rounded border border-green-100 bg-green-50 px-2 py-1 text-xs font-bold text-green-600 transition hover:text-green-800"
                          >
                            <i className="fas fa-bolt mr-1" /> 템플릿 불러오기
                          </button>
                          <button
                            type="button"
                            onClick={() => submitReply(review.reviewId)}
                            className="rounded-xl bg-brand px-4 py-2 text-xs font-extrabold text-white shadow-sm transition hover:bg-green-600"
                          >
                            {review.reply ? '답글 수정' : '답글 등록'}
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                ) : null}

                {!review.reply ? (
                  <div className="mt-4 flex gap-2">
                    <button
                      type="button"
                      onClick={() => toggleReplyForm(review)}
                      className="rounded-xl border border-brand bg-green-50 px-4 py-2 text-xs font-bold text-brand transition hover:bg-green-100"
                    >
                      <i className="fas fa-reply mr-1" /> 답글 작성
                    </button>
                    <button
                      type="button"
                      onClick={() => registerIssue(review.reviewId)}
                      className="rounded-xl border border-gray-200 bg-white px-4 py-2 text-xs font-bold text-gray-600 transition hover:bg-gray-50"
                    >
                      <i className="fas fa-flag mr-1" /> 이슈 등록
                    </button>
                  </div>
                ) : null}
              </article>
            )
          })}
        </div>

        <div className="py-6 text-center">
          <button type="button" className="text-sm font-bold text-gray-500 transition hover:text-gray-800">
            더 불러오기 <i className="fas fa-chevron-down ml-1" />
          </button>
        </div>
      </div>

      {templateModalOpen ? (
        <div className="fixed inset-0 z-[2500] flex items-center justify-center bg-black/50 px-4">
          <div className="w-full max-w-md overflow-hidden rounded-[28px] bg-white shadow-2xl">
            <div className="flex items-center justify-between border-b border-gray-100 bg-gray-50 px-4 py-4">
              <h3 className="text-sm font-black text-gray-900">
                <i className="fas fa-bolt mr-2 text-yellow-400" />
                빠른 답변 템플릿
              </h3>
              <button type="button" onClick={() => setTemplateModalOpen(false)} className="text-gray-400 transition hover:text-gray-600">
                <i className="fas fa-times" />
              </button>
            </div>
            <div className="max-h-[300px] overflow-y-auto">
              {templateOptions.map((template) => (
                <button
                  key={template.key}
                  type="button"
                  onClick={() => insertTemplate(template)}
                  className="w-full border-b border-gray-100 px-5 py-4 text-left transition hover:bg-gray-50"
                >
                  <div className="text-sm font-black text-gray-900">{template.title}</div>
                  <div className="mt-1 text-xs text-gray-500">{template.description}</div>
                </button>
              ))}
            </div>
          </div>
        </div>
      ) : null}
    </div>
  )
}
