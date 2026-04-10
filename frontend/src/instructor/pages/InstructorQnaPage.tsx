import { useEffect, useState } from 'react'
import UserAvatar from '../../components/UserAvatar'
import type { AuthSession } from '../../types/auth'
import { instructorQnaApi } from '../../lib/api'
import type { InstructorQnaInboxItem, InstructorQnaTemplate, InstructorQnaTimeline } from '../../types/instructor'

type QuestionStatus = 'pending' | 'answered'

const templates = {
  classic: `핵심 요약\n- 질문의 핵심을 먼저 정리합니다.\n\n이유\n- 동작 원인과 배경을 설명합니다.\n\n예시 / 주의\n- 짧은 예시 코드나 주의 포인트를 함께 남깁니다.`,
  steps: `해결 순서\n1) 현재 상태 확인\n2) 설정값 점검\n3) 재현 로그 확인\n4) 수정 적용\n5) 결과 재검증`,
  code: `추천 코드\n\`\`\`java\n// example\n\`\`\`\n\n설명\n- 왜 이 방식이 안전한지\n- 어디까지 적용해야 하는지`,
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

function Modal({
  title,
  icon,
  onClose,
  children,
}: {
  title: string
  icon: string
  onClose: () => void
  children: React.ReactNode
}) {
  return (
    <div className="fixed inset-0 z-[2400] flex items-center justify-center bg-black/60 px-4">
      <div className="w-full max-w-[560px] overflow-hidden rounded-[28px] bg-white shadow-2xl">
        <div className="flex items-center justify-between border-b border-gray-100 bg-gray-50 px-6 py-4">
          <h3 className="flex items-center gap-2 text-lg font-extrabold text-gray-900">
            <i className={`${icon} text-brand`} /> {title}
          </h3>
          <button type="button" onClick={onClose} className="flex h-8 w-8 items-center justify-center rounded-full border border-gray-200 bg-white">
            <i className="fas fa-times text-gray-400" />
          </button>
        </div>
        {children}
      </div>
    </div>
  )
}

export default function InstructorQnaPage({ session }: { session: AuthSession }) {
  const [questions, setQuestions] = useState<InstructorQnaInboxItem[]>([])
  const [timeline, setTimeline] = useState<InstructorQnaTimeline | null>(null)
  const [statusFilter, setStatusFilter] = useState<QuestionStatus>('pending')
  const [search, setSearch] = useState('')
  const [lectureFilter, setLectureFilter] = useState('all')
  const [sortFilter, setSortFilter] = useState<'latest' | 'oldest'>('latest')
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [draftText, setDraftText] = useState('')
  const [quickReplies, setQuickReplies] = useState<InstructorQnaTemplate[]>([])
  const [toast, setToast] = useState<string | null>(null)
  const [templateOpen, setTemplateOpen] = useState(false)
  const [quickOpen, setQuickOpen] = useState(false)
  const [editingId, setEditingId] = useState<number | null>(null)
  const [quickTitle, setQuickTitle] = useState('')
  const [quickBody, setQuickBody] = useState('')
  const [loading, setLoading] = useState(true)
  const [timelineLoading, setTimelineLoading] = useState(false)
  const [editingAnswer, setEditingAnswer] = useState(false)

  useEffect(() => {
    const controller = new AbortController()

    setLoading(true)

    Promise.all([
      instructorQnaApi.getInbox(statusFilter === 'pending' ? 'UNANSWERED' : 'ANSWERED', controller.signal),
      instructorQnaApi.getTemplates(controller.signal),
    ])
      .then(([nextQuestions, nextTemplates]) => {
        setQuestions(nextQuestions)
        setQuickReplies(nextTemplates)
      })
      .catch((error: Error) => {
        if (!controller.signal.aborted) {
          setToast(error.message)
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setLoading(false)
        }
      })

    return () => controller.abort()
  }, [statusFilter])

  const visibleQuestions = [...questions]
    .filter((question) => {
      if (lectureFilter !== 'all' && String(question.courseId) !== lectureFilter) {
        return false
      }

      if (search.trim()) {
        const haystack = `${question.title} ${question.content} ${question.learnerName ?? ''} ${question.courseTitle ?? ''}`.toLowerCase()
        return haystack.includes(search.trim().toLowerCase())
      }

      return true
    })
    .sort((left, right) =>
      sortFilter === 'latest'
        ? (right.createdAt ?? '').localeCompare(left.createdAt ?? '')
        : (left.createdAt ?? '').localeCompare(right.createdAt ?? ''),
    )

  useEffect(() => {
    if (!visibleQuestions.some((question) => question.questionId === selectedId)) {
      setSelectedId(visibleQuestions[0]?.questionId ?? null)
    }
  }, [selectedId, visibleQuestions])

  useEffect(() => {
    if (!selectedId) {
      setTimeline(null)
      setDraftText('')
      return
    }

    const controller = new AbortController()
    setTimelineLoading(true)
    setEditingAnswer(false)

    instructorQnaApi
      .getTimeline(selectedId, controller.signal)
      .then((nextTimeline) => {
        setTimeline(nextTimeline)
        setDraftText(nextTimeline.draft?.draftContent ?? nextTimeline.publishedAnswer?.content ?? '')
      })
      .catch((error: Error) => {
        if (!controller.signal.aborted) {
          setToast(error.message)
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setTimelineLoading(false)
        }
      })

    return () => controller.abort()
  }, [selectedId])

  useEffect(() => {
    if (!toast) return
    const timeoutId = window.setTimeout(() => setToast(null), 3000)
    return () => window.clearTimeout(timeoutId)
  }, [toast])

  const current = timeline?.question ?? visibleQuestions.find((question) => question.questionId === selectedId) ?? null
  const showAnswerForm = current ? current.status === 'UNANSWERED' || editingAnswer : false

  function appendReply(value: string) {
    if (!current) {
      return
    }

    setDraftText((existing) => (existing.trim() ? `${existing.trimEnd()}\n\n${value}` : value))
  }

  async function saveDraft() {
    if (!current) {
      return
    }

    await instructorQnaApi.saveDraft(current.questionId, draftText)
    setToast('임시 저장되었습니다.')
  }

  async function submitAnswer() {
    if (!current) {
      return
    }

    const content = draftText.trim()
    if (!content) {
      window.alert('답변 내용을 입력해 주세요.')
      return
    }

    try {
      if (timeline?.publishedAnswer) {
        await instructorQnaApi.updateAnswer(current.questionId, timeline.publishedAnswer.answerId, content)
      } else {
        await instructorQnaApi.createAnswer(current.questionId, content)
      }

      const [nextQuestions, nextTimeline] = await Promise.all([
        instructorQnaApi.getInbox(statusFilter === 'pending' ? 'UNANSWERED' : 'ANSWERED'),
        instructorQnaApi.getTimeline(current.questionId),
      ])
      setQuestions(nextQuestions)
      setTimeline(nextTimeline)
      setDraftText(nextTimeline.publishedAnswer?.content ?? '')
      setEditingAnswer(false)
      setToast('답변이 등록되었습니다.')
    } catch (error) {
      setToast(error instanceof Error ? error.message : '답변 저장에 실패했습니다.')
    }
  }

  function openQuickModal(reply?: InstructorQnaTemplate) {
    setEditingId(reply?.id ?? null)
    setQuickTitle(reply?.title ?? '')
    setQuickBody(reply?.content ?? '')
    setQuickOpen(true)
  }

  async function saveQuickReply() {
    if (!quickTitle.trim() || !quickBody.trim()) {
      window.alert('제목과 내용을 모두 입력해 주세요.')
      return
    }

    try {
      const saved = editingId
        ? await instructorQnaApi.updateTemplate(editingId, { title: quickTitle.trim(), content: quickBody.trim() })
        : await instructorQnaApi.createTemplate({ title: quickTitle.trim(), content: quickBody.trim() })

      setQuickReplies((state) =>
        editingId ? state.map((reply) => (reply.id === editingId ? saved : reply)) : [...state, saved],
      )
      setQuickOpen(false)
      setToast('빠른 답변이 저장되었습니다.')
    } catch (error) {
      setToast(error instanceof Error ? error.message : '템플릿 저장에 실패했습니다.')
    }
  }

  async function deleteQuickReply(replyId: number) {
    if (!window.confirm('이 템플릿을 삭제할까요?')) return

    try {
      await instructorQnaApi.deleteTemplate(replyId)
      setQuickReplies((state) => state.filter((reply) => reply.id !== replyId))
    } catch (error) {
      setToast(error instanceof Error ? error.message : '템플릿 삭제에 실패했습니다.')
    }
  }

  const courseOptions = Array.from(
    new Map(
      questions
        .filter((question) => question.courseId !== null)
        .map((question) => [String(question.courseId), question.courseTitle ?? `강의 #${question.courseId}`]),
    ).entries(),
  )

  return (
    <div className="min-h-[calc(100vh-64px)] bg-[#F8F9FA]">
      {toast ? (
        <div className="pointer-events-none fixed top-24 left-1/2 z-[9999] -translate-x-1/2 rounded-full border border-gray-700 bg-gray-800 px-6 py-3 text-sm font-bold text-white shadow-2xl">
          <i className="fas fa-info-circle mr-2 text-brand" /> {toast}
        </div>
      ) : null}

      <div className="flex min-h-[calc(100vh-64px)]">
        <section className="hidden w-[400px] shrink-0 flex-col border-r border-gray-200 bg-white xl:flex">
          <div className="border-b border-gray-100 p-6">
            <div className="mb-5 flex items-center justify-between">
              <h2 className="text-xl font-extrabold text-gray-900">수강생 Q&A</h2>
              <span className="rounded-full border border-orange-200 bg-orange-50 px-2 py-1 text-[10px] font-extrabold text-orange-700">
                미답변 {questions.filter((question) => question.status === 'UNANSWERED').length}건
              </span>
            </div>
            <div className="space-y-3">
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                className="w-full rounded-xl border border-gray-200 bg-gray-50 px-4 py-2.5 text-xs font-bold outline-none focus:border-brand"
                placeholder="제목, 이름, 내용 검색"
              />
              <div className="grid grid-cols-2 gap-2">
                <select
                  value={lectureFilter}
                  onChange={(event) => setLectureFilter(event.target.value)}
                  className="rounded-xl border border-gray-200 bg-gray-50 px-3 py-2.5 text-xs font-bold outline-none focus:border-brand"
                >
                  <option value="all">전체 강의</option>
                  {courseOptions.map(([value, label]) => (
                    <option key={value} value={value}>
                      {label}
                    </option>
                  ))}
                </select>
                <select
                  value={sortFilter}
                  onChange={(event) => setSortFilter(event.target.value as 'latest' | 'oldest')}
                  className="rounded-xl border border-gray-200 bg-gray-50 px-3 py-2.5 text-xs font-bold outline-none focus:border-brand"
                >
                  <option value="latest">최신순</option>
                  <option value="oldest">오래된순</option>
                </select>
              </div>
              <div className="flex gap-2 pt-2">
                {[
                  ['pending', '미답변'],
                  ['answered', '답변 완료'],
                ].map(([key, label]) => (
                  <button
                    key={key}
                    type="button"
                    onClick={() => setStatusFilter(key as QuestionStatus)}
                    className={`flex-1 rounded-xl border py-2 text-xs font-bold ${
                      statusFilter === key ? 'border-gray-200 bg-white text-gray-900 shadow-sm' : 'border-transparent text-gray-500'
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>
          </div>
          <div className="flex-1 overflow-y-auto bg-[#F8F9FA] p-4">
            {loading ? (
              <div className="rounded-xl border border-gray-200 bg-white p-4 text-xs font-bold text-gray-400">목록을 불러오는 중입니다.</div>
            ) : (
              visibleQuestions.map((question) => (
                <button
                  key={question.questionId}
                  type="button"
                  onClick={() => setSelectedId(question.questionId)}
                  className={`mb-3 w-full rounded-xl border p-4 text-left ${
                    selectedId === question.questionId ? 'border-brand bg-green-50 shadow-sm' : 'border-gray-200 bg-white'
                  }`}
                >
                  <div className="mb-2 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <img
                        src={`https://api.dicebear.com/7.x/avataaars/svg?seed=${question.learnerAvatarSeed ?? question.learnerName ?? question.questionId}`}
                        className="h-6 w-6 rounded-full border border-gray-200 bg-white"
                        alt={question.learnerName ?? '수강생'}
                      />
                      <span className="text-xs font-bold text-gray-900">{question.learnerName ?? '수강생'}</span>
                    </div>
                    <span className="text-[10px] font-bold text-gray-400">{relativeTime(question.createdAt)}</span>
                  </div>
                  <h4 className="mb-1.5 line-clamp-1 text-sm font-extrabold text-gray-900">{question.title}</h4>
                  <p className="mb-3 line-clamp-2 text-xs leading-relaxed text-gray-500">{question.content}</p>
                  <div className="flex items-center justify-between">
                    <span className="rounded border border-gray-200 bg-gray-100 px-2 py-0.5 text-[9px] font-bold text-gray-600">
                      {question.courseTitle ?? '공통'}
                    </span>
                    <span
                      className={`rounded-full px-2 py-1 text-[10px] font-extrabold ${
                        question.status === 'UNANSWERED'
                          ? 'border border-orange-200 bg-orange-50 text-orange-700'
                          : 'border border-green-200 bg-green-50 text-green-700'
                      }`}
                    >
                      {question.status === 'UNANSWERED' ? '미답변' : '답변 완료'}
                    </span>
                  </div>
                </button>
              ))
            )}
          </div>
        </section>

        {current ? (
          <section className="flex min-w-0 flex-1 flex-col">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-gray-200 bg-white px-8 py-4 shadow-sm">
              <div className="flex flex-wrap items-center gap-2">
                <span className="rounded-lg border border-gray-200 bg-gray-100 px-3 py-1.5 text-xs font-bold text-gray-600">
                  {current.courseTitle ?? '공통'}
                </span>
                {timeline?.lectureTitle ? (
                  <>
                    <i className="fas fa-chevron-right text-[10px] text-gray-300" />
                    <span className="rounded-lg border border-gray-200 bg-gray-100 px-3 py-1.5 text-xs font-bold text-gray-600">
                      {timeline.lectureTitle}
                    </span>
                  </>
                ) : null}
                {timeline?.lectureTimestamp ? (
                  <span className="rounded-lg border border-green-200 bg-green-50 px-3 py-1.5 text-xs font-bold text-brand">{timeline.lectureTimestamp}</span>
                ) : null}
              </div>
              <button
                type="button"
                onClick={() => window.alert('학습 플레이어 링크는 다음 단계에서 연결합니다.')}
                className="rounded-lg border border-gray-200 bg-white px-3 py-1.5 text-xs font-bold text-gray-500 shadow-sm hover:text-brand"
              >
                <i className="fas fa-external-link-alt mr-1" /> 강의 화면 보기
              </button>
            </div>

            <div className="flex flex-1 flex-col xl:flex-row">
              <div className="flex-1 overflow-y-auto p-6 lg:p-8">
                <div className="rounded-[28px] border border-gray-200 bg-white p-6 shadow-sm lg:p-8">
                  <div className="mb-5 flex items-center justify-between border-b border-gray-100 pb-5">
                    <div className="flex items-center gap-4">
                      <img
                        src={`https://api.dicebear.com/7.x/avataaars/svg?seed=${current.learnerAvatarSeed ?? current.learnerName ?? current.questionId}`}
                        className="h-11 w-11 rounded-full border border-gray-200 bg-gray-50 shadow-sm"
                        alt={current.learnerName ?? '수강생'}
                      />
                      <div>
                        <p className="text-sm font-extrabold text-gray-900">{current.learnerName ?? '수강생'}</p>
                        <p className="mt-1 text-[11px] font-bold text-gray-400">{relativeTime(current.createdAt)}</p>
                      </div>
                    </div>
                    <span
                      className={`rounded-full px-3 py-1.5 text-xs font-extrabold ${
                        current.status === 'UNANSWERED'
                          ? 'border border-orange-200 bg-orange-50 text-orange-700'
                          : 'border border-green-200 bg-green-50 text-green-700'
                      }`}
                    >
                      {current.status === 'UNANSWERED' ? '미답변' : '답변 완료'}
                    </span>
                  </div>
                  <h3 className="mb-4 text-lg font-black text-gray-900 lg:text-xl">{current.title}</h3>
                  <div className="whitespace-pre-line rounded-xl border border-gray-100 bg-gray-50 p-5 text-sm leading-relaxed font-medium text-gray-700">
                    {current.content}
                  </div>
                </div>

                {timelineLoading ? (
                  <div className="mt-6 rounded-[28px] border border-gray-200 bg-white p-6 text-sm text-gray-400 shadow-sm">답변 데이터를 불러오는 중입니다.</div>
                ) : showAnswerForm ? (
                  <div className="mt-6 overflow-hidden rounded-[28px] border border-gray-200 bg-white shadow-sm">
                    <div className="flex items-center justify-between border-b border-gray-200 bg-gray-50 px-4 py-3">
                      <div className="text-sm text-gray-500">
                        <i className="fas fa-code mr-2" /> 마크다운 지원
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="text-[11px] font-bold text-gray-400">{draftText.length} / 1000</span>
                        <button
                          type="button"
                          onClick={() => setTemplateOpen(true)}
                          className="rounded-lg border border-gray-200 bg-white px-3 py-1.5 text-xs font-extrabold text-gray-700 shadow-sm hover:text-brand"
                        >
                          템플릿 사용
                        </button>
                      </div>
                    </div>
                    <textarea
                      value={draftText}
                      onChange={(event) => setDraftText(event.target.value)}
                      maxLength={1000}
                      placeholder="명확한 답변을 작성해 주세요."
                      className="h-56 w-full resize-none p-6 text-sm leading-relaxed text-gray-800 outline-none"
                    />
                    <div className="flex items-center justify-between border-t border-gray-100 p-4">
                      <div className="text-[11px] font-bold text-gray-400">저장 후 언제든 다시 수정할 수 있습니다.</div>
                      <div className="flex gap-2">
                        <button type="button" onClick={saveDraft} className="rounded-xl bg-gray-100 px-5 py-2.5 text-xs font-extrabold text-gray-600">
                          초안 저장
                        </button>
                        <button type="button" onClick={submitAnswer} className="rounded-xl bg-brand px-8 py-2.5 text-xs font-extrabold text-white shadow-md">
                          {timeline?.publishedAnswer ? '답변 수정' : '답변 등록'}
                        </button>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="mt-6 rounded-[28px] border border-green-200 bg-white p-6 shadow-sm lg:p-8">
                    <div className="mb-5 flex items-center justify-between border-b border-gray-100 pb-4">
                      <div className="flex items-center gap-3">
                        <UserAvatar
                          name={session.name}
                          imageUrl={null}
                          className="h-10 w-10 shadow-sm"
                          alt={session.name}
                        />
                        <div>
                          <p className="text-sm font-extrabold text-gray-900">{session.name}</p>
                          <p className="mt-1 text-[10px] font-bold text-gray-400">답변 완료</p>
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={() => setEditingAnswer(true)}
                        className="rounded-lg border border-gray-200 bg-gray-50 px-3 py-1.5 text-xs font-bold text-gray-500"
                      >
                        수정
                      </button>
                    </div>
                    <pre className="whitespace-pre-wrap font-sans text-sm leading-relaxed font-medium text-gray-700">
                      {timeline?.publishedAnswer?.content}
                    </pre>
                  </div>
                )}
              </div>

              <aside className="w-full shrink-0 border-l border-gray-200 bg-white xl:w-[320px]">
                <div className="border-b border-gray-100 bg-gray-50/50 p-5">
                  <h3 className="text-sm font-extrabold text-gray-900">
                    <i className="fas fa-bolt mr-2 text-yellow-500" /> 빠른 답변
                  </h3>
                </div>
                <div className="space-y-6 p-5">
                  <div>
                    <h4 className="mb-3 text-[10px] font-extrabold tracking-wider text-gray-400 uppercase">추천 템플릿</h4>
                    {(['classic', 'steps', 'code'] as Array<keyof typeof templates>).map((key) => (
                      <button
                        key={key}
                        type="button"
                        onClick={() => appendReply(templates[key])}
                        className="mb-2 flex w-full items-start justify-between rounded-xl border border-gray-200 bg-white p-3.5 text-left hover:bg-gray-50"
                      >
                        <div>
                          <div className="text-[13px] font-black text-gray-900">
                            {key === 'classic' ? '핵심 요약 템플릿' : key === 'steps' ? '문제 해결 순서' : '코드 예시 템플릿'}
                          </div>
                          <div className="mt-1 text-[11px] font-semibold text-gray-500">
                            {key === 'classic' ? '질문 설명 + 이유 + 예시' : key === 'steps' ? '점검 순서를 단계별로 안내' : '코드와 설명을 함께 전달'}
                          </div>
                        </div>
                        <i className="fas fa-plus-circle mt-1 text-lg text-gray-300" />
                      </button>
                    ))}
                  </div>

                  <div>
                    <div className="mb-3 flex items-center justify-between">
                      <h4 className="text-[10px] font-extrabold tracking-wider text-gray-400 uppercase">저장한 빠른 답변</h4>
                      <span className="rounded-md border border-gray-200 bg-gray-100 px-2 py-0.5 text-[10px] font-extrabold text-gray-600">{quickReplies.length}</span>
                    </div>
                    <div className="mb-3 space-y-2">
                      {quickReplies.length > 0 ? (
                        quickReplies.map((reply) => (
                          <button
                            key={reply.id}
                            type="button"
                            onClick={() => appendReply(reply.content)}
                            className="group w-full rounded-xl border border-gray-200 bg-white p-3.5 text-left hover:border-brand hover:shadow-sm"
                          >
                            <div className="flex items-start justify-between gap-2">
                              <div className="line-clamp-1 flex-1 text-xs font-extrabold text-gray-900">{reply.title}</div>
                              <div className="flex gap-1 opacity-0 transition group-hover:opacity-100">
                                <button
                                  type="button"
                                  onClick={(event) => {
                                    event.stopPropagation()
                                    openQuickModal(reply)
                                  }}
                                  className="flex h-6 w-6 items-center justify-center rounded border border-gray-200 bg-gray-50 text-gray-500"
                                >
                                  <i className="fas fa-pen text-[10px]" />
                                </button>
                                <button
                                  type="button"
                                  onClick={(event) => {
                                    event.stopPropagation()
                                    deleteQuickReply(reply.id)
                                  }}
                                  className="flex h-6 w-6 items-center justify-center rounded border border-red-100 bg-red-50 text-red-500"
                                >
                                  <i className="fas fa-trash text-[10px]" />
                                </button>
                              </div>
                            </div>
                            <div className="mt-1 line-clamp-2 text-[11px] leading-relaxed font-medium text-gray-500">{reply.content}</div>
                          </button>
                        ))
                      ) : (
                        <div className="rounded-xl border border-dashed border-gray-300 bg-white p-4 text-center text-[11px] font-bold text-gray-400">
                          저장한 답변 템플릿이 없습니다.
                        </div>
                      )}
                    </div>
                    <button
                      type="button"
                      onClick={() => openQuickModal()}
                      className="w-full rounded-xl border border-dashed border-gray-300 py-2.5 text-xs font-extrabold text-gray-500 hover:border-brand hover:bg-green-50 hover:text-brand"
                    >
                      빠른 답변 추가하기
                    </button>
                  </div>
                </div>
              </aside>
            </div>
          </section>
        ) : null}
      </div>

      {quickOpen ? (
        <Modal title="빠른 답변 저장" icon="fas fa-bookmark" onClose={() => setQuickOpen(false)}>
          <div className="space-y-4 bg-[#F8F9FA] p-6">
            <input
              value={quickTitle}
              onChange={(event) => setQuickTitle(event.target.value)}
              maxLength={30}
              className="w-full rounded-xl border border-gray-200 px-4 py-3 text-sm font-bold outline-none focus:border-brand"
              placeholder="템플릿 제목"
            />
            <textarea
              value={quickBody}
              onChange={(event) => setQuickBody(event.target.value)}
              maxLength={1000}
              className="h-48 w-full resize-none rounded-xl border border-gray-200 px-4 py-3 text-sm font-medium outline-none focus:border-brand"
              placeholder="버튼 클릭 시 본문에 들어갈 답변을 작성해 주세요."
            />
          </div>
          <div className="flex items-center justify-between border-t border-gray-100 bg-gray-50 px-5 py-4">
            <button type="button" onClick={() => setQuickBody(draftText)} className="rounded-xl border border-gray-200 bg-white px-4 py-2.5 text-xs font-extrabold text-gray-600 shadow-sm">
              현재 답변 가져오기
            </button>
            <div className="flex gap-2">
              <button type="button" onClick={() => setQuickOpen(false)} className="rounded-xl px-5 py-2.5 text-xs font-bold text-gray-500">
                취소
              </button>
              <button type="button" onClick={saveQuickReply} className="rounded-xl bg-gray-900 px-6 py-2.5 text-xs font-extrabold text-white shadow-md">
                저장하기
              </button>
            </div>
          </div>
        </Modal>
      ) : null}

      {templateOpen ? (
        <Modal title="답변 템플릿 선택" icon="fas fa-magic" onClose={() => setTemplateOpen(false)}>
          <div className="space-y-3 bg-[#F8F9FA] p-6">
            {(['classic', 'steps', 'code'] as Array<keyof typeof templates>).map((key) => (
              <button
                key={key}
                type="button"
                onClick={() => {
                  appendReply(templates[key])
                  setTemplateOpen(false)
                }}
                className="flex w-full items-start justify-between gap-3 rounded-xl border border-gray-200 bg-white p-4 text-left hover:bg-gray-50"
              >
                <div>
                  <div className="text-sm font-black text-gray-900">
                    {key === 'classic' ? '핵심 요약 템플릿' : key === 'steps' ? '문제 해결 순서' : '코드 예시 템플릿'}
                  </div>
                  <div className="mt-1 text-xs font-medium text-gray-500">
                    {key === 'classic' ? '질문 설명과 원인, 예시까지 빠르게 정리' : key === 'steps' ? '점검 항목을 단계별로 전달' : '코드와 설명을 함께 제공'}
                  </div>
                </div>
                <i className="fas fa-check-circle mt-1 text-xl text-gray-300" />
              </button>
            ))}
          </div>
        </Modal>
      ) : null}
    </div>
  )
}
