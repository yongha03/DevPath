import { useEffect, useState } from 'react'
import { ErrorCard, LoadingCard, formatDate } from '../../account/ui'
import { instructorAnnouncementApi, instructorCourseApi } from '../../lib/api'
import type {
  InstructorAnnouncementDetail,
  InstructorCourseListItem,
} from '../../types/instructor'

type CourseStatus = 'published' | 'draft' | 'review'

function mapCourseStatus(status: string | null): CourseStatus {
  switch (status) {
    case 'PUBLISHED':
      return 'published'
    case 'IN_REVIEW':
      return 'review'
    case 'DRAFT':
    default:
      return 'draft'
  }
}

function getStatusMeta(status: CourseStatus) {
  switch (status) {
    case 'published':
      return {
        label: '공개 중',
        tone: 'bg-green-100 text-green-700',
      }
    case 'review':
      return {
        label: '심사 중',
        tone: 'bg-yellow-100 text-yellow-700',
      }
    case 'draft':
    default:
      return {
        label: '초안',
        tone: 'bg-gray-100 text-gray-600',
      }
  }
}

function formatDuration(durationSeconds: number | null) {
  if (!durationSeconds || durationSeconds <= 0) {
    return '-'
  }

  const hours = Math.floor(durationSeconds / 3600)
  const minutes = Math.floor((durationSeconds % 3600) / 60)

  if (hours > 0) {
    return `${hours}시간 ${minutes}분`
  }

  return `${minutes}분`
}

export default function CourseManagementPage() {
  const [filterStatus, setFilterStatus] = useState<'all' | 'published' | 'draft'>('all')
  const [search, setSearch] = useState('')
  const [sort, setSort] = useState('latest')
  const [courses, setCourses] = useState<InstructorCourseListItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [noticeModalCourseId, setNoticeModalCourseId] = useState<number | null>(null)
  const [notices, setNotices] = useState<InstructorAnnouncementDetail[]>([])
  const [noticesLoading, setNoticesLoading] = useState(false)
  const [createNoticeOpen, setCreateNoticeOpen] = useState(false)
  const [expandedNoticeIds, setExpandedNoticeIds] = useState<number[]>([])
  const [newNoticeTitle, setNewNoticeTitle] = useState('')
  const [newNoticeContent, setNewNoticeContent] = useState('')
  const [showTitleError, setShowTitleError] = useState(false)
  const [showContentError, setShowContentError] = useState(false)

  useEffect(() => {
    const controller = new AbortController()

    setLoading(true)
    setError(null)

    instructorCourseApi
      .getCourses(controller.signal)
      .then((nextCourses) => {
        setCourses(nextCourses)
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

  const visibleCourses = [...courses]
    .filter((course) => {
      const status = mapCourseStatus(course.status)

      if (filterStatus !== 'all' && status !== filterStatus) {
        return false
      }

      if (search.trim()) {
        const haystack = `${course.title} ${course.categoryLabel} ${course.levelLabel}`.toLowerCase()
        return haystack.includes(search.trim().toLowerCase())
      }

      return true
    })
    .sort((left, right) => {
      if (sort === 'students') {
        return right.studentCount - left.studentCount
      }

      if (sort === 'rating') {
        return right.averageRating - left.averageRating
      }

      return (right.publishedAt ?? '').localeCompare(left.publishedAt ?? '')
    })

  const selectedCourse = courses.find((course) => course.courseId === noticeModalCourseId) ?? null

  async function openNoticeModal(courseId: number) {
    setNoticeModalCourseId(courseId)
    setExpandedNoticeIds([])
    setNoticesLoading(true)

    try {
      const summaries = await instructorAnnouncementApi.getByCourse(courseId)
      const details = await Promise.all(summaries.map((item) => instructorAnnouncementApi.getDetail(item.announcementId)))
      setNotices(details)
    } catch (nextError) {
      window.alert(nextError instanceof Error ? nextError.message : '공지 목록을 불러오지 못했습니다.')
      setNotices([])
    } finally {
      setNoticesLoading(false)
    }
  }

  function closeNoticeModal() {
    setNoticeModalCourseId(null)
    setCreateNoticeOpen(false)
    setExpandedNoticeIds([])
    setNotices([])
  }

  function toggleNoticeExpansion(id: number) {
    setExpandedNoticeIds((current) => (current.includes(id) ? current.filter((item) => item !== id) : [...current, id]))
  }

  function openCreateNoticeModal() {
    setCreateNoticeOpen(true)
    setNewNoticeTitle('')
    setNewNoticeContent('')
    setShowTitleError(false)
    setShowContentError(false)
  }

  async function createNotice() {
    const trimmedTitle = newNoticeTitle.trim()
    const trimmedContent = newNoticeContent.trim()

    setShowTitleError(!trimmedTitle)
    setShowContentError(!trimmedContent)

    if (!trimmedTitle || !trimmedContent || !noticeModalCourseId) {
      return
    }

    try {
      await instructorAnnouncementApi.create(noticeModalCourseId, {
        type: 'normal',
        title: trimmedTitle,
        content: trimmedContent,
        pinned: false,
        displayOrder: notices.length,
      })
      await openNoticeModal(noticeModalCourseId)
      setCreateNoticeOpen(false)
    } catch (nextError) {
      window.alert(nextError instanceof Error ? nextError.message : '공지 등록에 실패했습니다.')
    }
  }

  if (loading) {
    return (
      <div className="p-6">
        <LoadingCard label="강의 목록을 불러오는 중입니다." />
      </div>
    )
  }

  if (error) {
    return (
      <div className="p-6">
        <ErrorCard message={error} />
      </div>
    )
  }

  return (
    <div className="p-6">
      <div className="mx-auto max-w-[1200px]">
        <div className="mb-5 rounded-3xl border border-green-100 bg-gradient-to-br from-green-50 to-white p-5">
          <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
            <div>
              <h1 className="text-2xl font-black tracking-tight text-gray-900">강의 관리</h1>
              <p className="mt-1 text-sm text-gray-500">등록한 강의와 공지, 학습 현황을 한 번에 관리합니다.</p>
            </div>
            <button
              type="button"
              onClick={() => {
                window.location.href = 'course-editor.html'
              }}
              className="inline-flex items-center gap-2 rounded-2xl bg-brand px-4 py-2.5 text-sm font-black text-white shadow-lg shadow-green-500/20 transition hover:bg-green-600"
            >
              <i className="fas fa-plus" /> 새 강의 만들기
            </button>
          </div>
        </div>

        <div className="mb-5 grid grid-cols-1 gap-3 md:grid-cols-3">
          {[
            ['총 수강생', `${courses.reduce((sum, item) => sum + item.studentCount, 0)}명`, 'bg-blue-50 text-blue-600', 'fas fa-user-plus'],
            ['강의 수', `${courses.length}개`, 'bg-green-50 text-green-600', 'fas fa-users'],
            ['평균 평점', `${(courses.reduce((sum, item) => sum + item.averageRating, 0) / Math.max(courses.length, 1)).toFixed(1)} / 5.0`, 'bg-yellow-50 text-yellow-500', 'fas fa-star'],
          ].map(([label, value, tone, icon]) => (
            <article key={label} className="flex items-center justify-between rounded-2xl border border-gray-200 bg-white p-4 shadow-sm">
              <div>
                <p className="text-[11px] font-extrabold tracking-[0.04em] text-gray-500 uppercase">{label}</p>
                <h3 className="mt-1 text-xl font-black text-gray-900">{value}</h3>
              </div>
              <div className={`flex h-10 w-10 items-center justify-center rounded-2xl ${tone}`}>
                <i className={icon} />
              </div>
            </article>
          ))}
        </div>

        <div className="mb-4 flex flex-col items-center justify-between gap-3 rounded-3xl border border-gray-200 bg-white p-3 shadow-sm md:flex-row">
          <div className="flex w-full gap-1 md:w-auto">
            {[
              ['all', '전체'],
              ['published', '공개 중'],
              ['draft', '초안 / 심사'],
            ].map(([key, label]) => (
              <button
                key={key}
                type="button"
                onClick={() => setFilterStatus(key as 'all' | 'published' | 'draft')}
                className={`rounded-xl px-4 py-2 text-sm transition ${
                  filterStatus === key ? 'bg-green-50 font-bold text-brand' : 'font-medium text-gray-500 hover:bg-gray-50'
                }`}
              >
                {label}
              </button>
            ))}
          </div>
          <div className="flex w-full gap-2 md:w-auto">
            <div className="relative flex-1 md:w-72">
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                type="text"
                placeholder="강의명, 카테고리 검색"
                className="w-full rounded-xl border border-gray-200 py-2 pr-4 pl-9 text-sm outline-none focus:border-brand"
              />
              <i className="fas fa-search absolute top-1/2 left-3 -translate-y-1/2 text-xs text-gray-400" />
            </div>
            <select
              value={sort}
              onChange={(event) => setSort(event.target.value)}
              className="rounded-xl border border-gray-200 px-3 py-2 text-sm text-gray-600 outline-none focus:border-brand"
            >
              <option value="latest">최신순</option>
              <option value="students">수강생순</option>
              <option value="rating">평점순</option>
            </select>
          </div>
        </div>

        <div className="space-y-3">
          {visibleCourses.map((course) => {
            const status = mapCourseStatus(course.status)
            const statusMeta = getStatusMeta(status)

            return (
              <article key={course.courseId} className="rounded-2xl border border-gray-200 bg-white p-[18px] shadow-sm transition hover:border-gray-300">
                <div className="flex flex-col gap-5 md:flex-row">
                  <div className="flex h-[110px] w-full shrink-0 items-center justify-center overflow-hidden rounded-2xl border border-gray-200 bg-gray-50 text-gray-400 md:w-[168px]">
                    {course.thumbnailUrl ? (
                      <img src={course.thumbnailUrl} alt={course.title} className="h-full w-full object-cover" />
                    ) : (
                      <i className="fas fa-play-circle text-3xl" />
                    )}
                  </div>

                  <div className="min-w-0 flex-1">
                    <div className="mb-2 flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                      <div className="min-w-0">
                        <div className="mb-2 flex flex-wrap items-center gap-2">
                          <span className={`rounded-full px-3 py-1 text-[11px] font-bold ${statusMeta.tone}`}>{statusMeta.label}</span>
                          <span className="border-l border-gray-200 pl-2 text-xs text-gray-400">
                            공개일: {formatDate(course.publishedAt)}
                          </span>
                        </div>

                        <h3 className={`truncate text-[16px] leading-tight font-black ${status === 'draft' ? 'text-gray-500' : 'text-gray-900'}`}>
                          {course.title}
                        </h3>

                        <div className="mt-2 flex flex-wrap gap-2">
                          <span className="rounded border border-gray-200 bg-gray-50 px-2 py-1 text-[11px] text-gray-600">
                            <i className="fas fa-tag mr-1" /> {course.categoryLabel}
                          </span>
                          <span className="rounded border border-gray-200 bg-gray-50 px-2 py-1 text-[11px] text-gray-600">
                            <i className="fas fa-layer-group mr-1" /> {course.levelLabel}
                          </span>
                          <span className="rounded border border-gray-200 bg-gray-50 px-2 py-1 text-[11px] text-gray-600">
                            <i className="fas fa-clock mr-1" /> {formatDuration(course.durationSeconds)}
                          </span>
                          <span className="rounded border border-gray-200 bg-gray-50 px-2 py-1 text-[11px] text-gray-600">
                            <i className="fas fa-list-ul mr-1" /> {course.lessonCount}개 레슨
                          </span>
                        </div>
                      </div>

                      <div className="flex shrink-0 gap-2">
                        {status === 'published' ? (
                          <>
                            <button
                              type="button"
                              title="통계"
                              onClick={() => window.alert('학생 분석 탭에서 확인할 수 있습니다.')}
                              className="flex h-[34px] w-[34px] items-center justify-center rounded-xl border border-gray-200 text-gray-500 transition hover:bg-gray-50 hover:text-gray-900"
                            >
                              <i className="fas fa-chart-bar" />
                            </button>
                            <button
                              type="button"
                              title="공지사항"
                              onClick={() => openNoticeModal(course.courseId)}
                              className="flex h-[34px] w-[34px] items-center justify-center rounded-xl border border-gray-200 text-gray-500 transition hover:bg-gray-50 hover:text-gray-900"
                            >
                              <i className="fas fa-bullhorn" />
                            </button>
                            <button
                              type="button"
                              onClick={() => {
                                window.location.href = `instructor-course-detail.html?courseId=${course.courseId}`
                              }}
                              className="rounded-xl bg-gray-900 px-4 py-2 text-xs font-black text-white transition hover:bg-black"
                            >
                              관리 / 수정
                            </button>
                          </>
                        ) : status === 'draft' ? (
                          <button
                            type="button"
                            onClick={() => {
                              window.location.href = `course-editor.html?courseId=${course.courseId}`
                            }}
                            className="rounded-xl bg-brand px-4 py-2 text-xs font-black text-white transition hover:bg-green-600"
                          >
                            이어서 작성
                          </button>
                        ) : (
                          <button
                            type="button"
                            disabled
                            className="cursor-not-allowed rounded-xl border border-gray-200 px-4 py-2 text-xs font-black text-gray-400"
                          >
                            심사 중
                          </button>
                        )}
                      </div>
                    </div>

                    {status === 'published' ? (
                      <div className="mt-3 grid grid-cols-2 gap-3 border-t border-slate-100 pt-3 lg:grid-cols-4">
                        <div className="rounded-lg border border-slate-100 bg-slate-50 px-3 py-3">
                          <p className="mb-1 text-[10px] font-bold text-gray-500">총 수강생</p>
                          <p className="text-sm font-black text-gray-900">{course.studentCount}명</p>
                        </div>
                        <div className="rounded-lg border border-slate-100 bg-slate-50 px-3 py-3">
                          <p className="mb-1 text-[10px] font-bold text-gray-500">평균 진도율</p>
                          <p className="text-sm font-black text-gray-900">{course.averageProgressPercent.toFixed(1)}%</p>
                        </div>
                        <div className="rounded-lg border border-slate-100 border-l-4 border-l-red-400 bg-slate-50 px-3 py-3">
                          <p className="mb-1 text-[10px] font-bold text-gray-500">미답변 질문</p>
                          <p className="text-sm font-black text-red-500">{course.pendingQuestionCount}건</p>
                        </div>
                        <div className="rounded-lg border border-slate-100 bg-slate-50 px-3 py-3">
                          <p className="mb-1 text-[10px] font-bold text-gray-500">평점</p>
                          <p className="text-sm font-black text-gray-900">{course.averageRating.toFixed(1)}</p>
                        </div>
                      </div>
                    ) : status === 'draft' ? (
                      <div className="mt-3 border-t border-slate-100 pt-3">
                        <div className="mb-1 flex justify-between text-xs">
                          <span className="font-black text-gray-600">콘텐츠 구성도</span>
                          <span className="font-black text-brand">{Math.min(100, course.lessonCount * 10)}%</span>
                        </div>
                        <div className="h-2.5 rounded-full bg-gray-100">
                          <div className="h-2.5 rounded-full bg-brand" style={{ width: `${Math.min(100, course.lessonCount * 10)}%` }} />
                        </div>
                        <p className="mt-2 text-[10px] font-bold text-gray-400">
                          <i className="fas fa-info-circle mr-1" /> 초안 강의는 lesson과 소개 정보를 채운 뒤 심사로 넘길 수 있습니다.
                        </p>
                      </div>
                    ) : (
                      <div className="mt-3 inline-block w-full rounded-xl border border-yellow-100 bg-yellow-50 p-3">
                        <p className="flex items-center gap-2 text-xs font-bold text-yellow-800">
                          <i className="fas fa-clock" /> 운영팀이 강의 내용을 검토하고 있습니다.
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              </article>
            )
          })}
        </div>
      </div>

      {selectedCourse ? (
        <div className="fixed inset-0 z-[2200] flex items-center justify-center bg-black/45 px-4">
          <div className="w-full max-w-[720px] overflow-hidden rounded-[28px] border border-gray-200 bg-white shadow-2xl">
            <div className="flex items-center justify-between border-b border-gray-100 px-5 py-4">
              <div className="flex items-center gap-2 text-sm font-black text-gray-900">
                <i className="fas fa-bullhorn text-brand" />
                <span>{selectedCourse.title} 공지사항</span>
              </div>
              <button type="button" onClick={closeNoticeModal} className="flex h-9 w-9 items-center justify-center rounded-xl border border-gray-200 transition hover:bg-gray-50">
                <i className="fas fa-times text-gray-500" />
              </button>
            </div>

            <div className="max-h-[440px] overflow-y-auto p-5">
              {noticesLoading ? (
                <LoadingCard label="공지 목록을 불러오는 중입니다." />
              ) : (
                <div className="space-y-3">
                  {notices.map((notice) => {
                    const expanded = expandedNoticeIds.includes(notice.announcementId)

                    return (
                      <button
                        key={notice.announcementId}
                        type="button"
                        onClick={() => toggleNoticeExpansion(notice.announcementId)}
                        className="w-full rounded-2xl border border-gray-200 bg-white px-4 py-3 text-left transition hover:bg-gray-50"
                      >
                        <div className="flex items-center justify-between gap-4">
                          <div className="text-sm font-black text-gray-900">{notice.title}</div>
                          <div className="text-[11px] font-extrabold text-gray-400">{formatDate(notice.publishedAt)}</div>
                        </div>
                        {expanded ? <div className="mt-2 text-xs leading-6 text-gray-500">{notice.content}</div> : null}
                      </button>
                    )
                  })}
                </div>
              )}
            </div>

            <div className="flex items-center justify-end gap-2 border-t border-gray-100 px-5 py-4">
              <button
                type="button"
                onClick={() => setExpandedNoticeIds([])}
                className="rounded-xl border border-gray-200 bg-white px-4 py-2 text-xs font-black text-gray-700 transition hover:bg-gray-50"
              >
                접기
              </button>
              <button
                type="button"
                onClick={() => setExpandedNoticeIds(notices.map((notice) => notice.announcementId))}
                className="rounded-xl border border-gray-200 bg-white px-4 py-2 text-xs font-black text-gray-700 transition hover:bg-gray-50"
              >
                전체 펼치기
              </button>
              <button
                type="button"
                onClick={openCreateNoticeModal}
                className="rounded-xl bg-brand px-4 py-2 text-xs font-black text-white transition hover:bg-green-600"
              >
                새 공지 작성
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {selectedCourse && createNoticeOpen ? (
        <div className="fixed inset-0 z-[2300] flex items-center justify-center bg-black/55 px-4">
          <div className="w-full max-w-[640px] overflow-hidden rounded-[28px] border border-gray-200 bg-white shadow-2xl">
            <div className="flex items-center justify-between border-b border-gray-100 px-5 py-4">
              <div className="flex items-center gap-2 text-sm font-black text-gray-900">
                <i className="fas fa-pen-nib text-brand" />
                <span>{selectedCourse.title} 공지 작성</span>
              </div>
              <button
                type="button"
                onClick={() => setCreateNoticeOpen(false)}
                className="flex h-9 w-9 items-center justify-center rounded-xl border border-gray-200 transition hover:bg-gray-50"
              >
                <i className="fas fa-times text-gray-500" />
              </button>
            </div>

            <div className="space-y-4 p-5">
              <label className="block">
                <div className="mb-2 text-sm font-black text-gray-900">제목</div>
                <input
                  value={newNoticeTitle}
                  onChange={(event) => setNewNoticeTitle(event.target.value)}
                  maxLength={60}
                  placeholder="공지 제목"
                  className="w-full rounded-xl border border-gray-200 px-4 py-3 text-sm outline-none focus:border-brand focus:shadow-[0_0_0_3px_rgba(0,196,113,0.12)]"
                />
                {showTitleError ? <div className="mt-1 text-[11px] font-black text-red-500">제목을 입력해 주세요.</div> : null}
              </label>

              <label className="block">
                <div className="mb-2 text-sm font-black text-gray-900">내용</div>
                <textarea
                  value={newNoticeContent}
                  onChange={(event) => setNewNoticeContent(event.target.value)}
                  maxLength={800}
                  placeholder="공지 내용을 입력해 주세요."
                  className="min-h-[140px] w-full rounded-xl border border-gray-200 px-4 py-3 text-sm outline-none focus:border-brand focus:shadow-[0_0_0_3px_rgba(0,196,113,0.12)]"
                />
                {showContentError ? <div className="mt-1 text-[11px] font-black text-red-500">내용을 입력해 주세요.</div> : null}
              </label>
            </div>

            <div className="flex items-center justify-end gap-2 border-t border-gray-100 px-5 py-4">
              <button
                type="button"
                onClick={() => setCreateNoticeOpen(false)}
                className="rounded-xl border border-gray-200 bg-white px-4 py-2 text-xs font-black text-gray-700 transition hover:bg-gray-50"
              >
                취소
              </button>
              <button
                type="button"
                onClick={createNotice}
                className="rounded-xl bg-brand px-4 py-2 text-xs font-black text-white transition hover:bg-green-600"
              >
                등록
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  )
}
