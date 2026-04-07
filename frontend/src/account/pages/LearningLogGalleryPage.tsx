import { useEffect, useMemo, useState } from 'react'
import { certificateApi, proofCardApi } from '../../lib/api'
import { LearnerContentRow, LearnerPageShell, MyMenuSidebar } from '../template'
import { downloadBase64File } from '../ui'
import type { ProofCardDetail, ProofCardGalleryItem } from '../../types/learner'

type ProofCardViewItem = ProofCardGalleryItem & {
  type: 'language' | 'cs' | 'framework' | 'backend'
  score: number
}

const fallbackItems: ProofCardViewItem[] = [
  {
    proofCardId: 1,
    title: 'Java 기초 문법',
    nodeTitle: 'Java Fundamentals',
    issuedAt: '2025-12-10T00:00:00',
    tags: [
      { tagId: 1, tagName: 'JVM', evidenceType: 'QUIZ' },
      { tagId: 2, tagName: 'Collection', evidenceType: 'QUIZ' },
      { tagId: 3, tagName: 'Lambda', evidenceType: 'QUIZ' },
    ],
    type: 'language',
    score: 92,
  },
  {
    proofCardId: 2,
    title: '운영체제 (OS)',
    nodeTitle: 'Operating System',
    issuedAt: '2026-01-20T00:00:00',
    tags: [
      { tagId: 4, tagName: 'Process', evidenceType: 'QUIZ' },
      { tagId: 5, tagName: 'Thread', evidenceType: 'QUIZ' },
      { tagId: 6, tagName: 'Deadlock', evidenceType: 'QUIZ' },
    ],
    type: 'cs',
    score: 88,
  },
  {
    proofCardId: 3,
    title: 'Spring Boot 핵심',
    nodeTitle: 'Spring Boot Core',
    issuedAt: '2026-02-01T00:00:00',
    tags: [
      { tagId: 7, tagName: 'DI', evidenceType: 'PROJECT' },
      { tagId: 8, tagName: 'Spring MVC', evidenceType: 'PROJECT' },
      { tagId: 9, tagName: 'JPA', evidenceType: 'PROJECT' },
    ],
    type: 'framework',
    score: 95,
  },
]

function formatShortDate(value: string | null | undefined) {
  if (!value) {
    return '-'
  }

  const date = new Date(value)

  return `${date.getFullYear()}. ${String(date.getMonth() + 1).padStart(2, '0')}. ${String(date.getDate()).padStart(2, '0')}`
}

function inferType(title: string): ProofCardViewItem['type'] {
  const normalized = title.toLowerCase()

  if (normalized.includes('java')) {
    return 'language'
  }

  if (normalized.includes('spring')) {
    return 'framework'
  }

  if (normalized.includes('운영체제') || normalized.includes('network') || normalized.includes('os')) {
    return 'cs'
  }

  return 'backend'
}

function buildScore(index: number) {
  return 82 + (index % 5) * 3
}

function cardTheme(type: ProofCardViewItem['type']) {
  switch (type) {
    case 'language':
      return {
        front: 'from-orange-500 to-red-600',
        badge: '언어 (Language)',
        icon: 'fab fa-java',
        action: 'bg-primary hover:bg-green-600',
        marker: 'marker:text-primary text-primary',
      }
    case 'cs':
      return {
        front: 'from-slate-700 to-slate-900',
        badge: 'CS 전공지식',
        icon: 'fas fa-server',
        action: 'bg-blue-600 hover:bg-blue-700',
        marker: 'marker:text-blue-500 text-blue-400',
      }
    case 'framework':
      return {
        front: 'from-green-500 to-emerald-600',
        badge: '프레임워크',
        icon: 'fas fa-leaf',
        action: 'bg-green-600 hover:bg-green-700',
        marker: 'marker:text-green-500 text-green-400',
      }
    default:
      return {
        front: 'from-gray-700 to-gray-900',
        badge: 'Backend Track',
        icon: 'fas fa-code',
        action: 'bg-primary hover:bg-green-600',
        marker: 'marker:text-primary text-primary',
      }
  }
}

export default function LearningLogGalleryPage() {
  const [items, setItems] = useState<ProofCardViewItem[]>(fallbackItems)
  const [details, setDetails] = useState<Record<number, ProofCardDetail>>({})
  const [flippedIds, setFlippedIds] = useState<number[]>([])
  const [filterOpen, setFilterOpen] = useState(false)
  const [certificateOpen, setCertificateOpen] = useState(false)
  const [categoryFilter, setCategoryFilter] = useState<'all' | 'backend' | 'framework' | 'language' | 'cs'>('all')
  const [sortOrder, setSortOrder] = useState<'latest' | 'score'>('latest')
  const [selectedCard, setSelectedCard] = useState<ProofCardViewItem | null>(null)
  const [message, setMessage] = useState('')

  useEffect(() => {
    async function load() {
      try {
        const response = await proofCardApi.getGallery()

        if (response.length) {
          setItems(
            response.map((item, index) => ({
              ...item,
              type: inferType(item.title),
              score: buildScore(index),
            })),
          )
        }
      } catch {
        // 원본 Proof Card 화면을 유지하기 위해 API 실패 시 기본 데이터를 사용합니다.
      }
    }

    void load()
  }, [])

  const visibleCards = useMemo(() => {
    const filtered = items.filter((item) => categoryFilter === 'all' || item.type === categoryFilter)

    return [...filtered].sort((left, right) => {
      if (sortOrder === 'score') {
        return right.score - left.score
      }

      return new Date(right.issuedAt ?? 0).getTime() - new Date(left.issuedAt ?? 0).getTime()
    })
  }, [categoryFilter, items, sortOrder])

  async function handleFlip(card: ProofCardViewItem) {
    setFlippedIds((current) =>
      current.includes(card.proofCardId)
        ? current.filter((proofCardId) => proofCardId !== card.proofCardId)
        : [...current, card.proofCardId],
    )

    if (!details[card.proofCardId]) {
      try {
        const detail = await proofCardApi.getCard(card.proofCardId)
        setDetails((current) => ({ ...current, [card.proofCardId]: detail }))
      } catch {
        // 상세 내용은 카드 템플릿의 기본 태그 목록으로 대체합니다.
      }
    }
  }

  async function handleDownloadCertificate(card: ProofCardViewItem) {
    setSelectedCard(card)
    setCertificateOpen(true)

    try {
      const certificate = await certificateApi.issue(card.proofCardId)
      const pdf = await certificateApi.generatePdf(card.proofCardId)
      downloadBase64File(pdf.fileName, pdf.mimeType, pdf.base64Content)
      await certificateApi.recordDownload(certificate.certificateId, 'portfolio')
      setMessage('증명서가 다운로드되었습니다.')
    } catch {
      setMessage('증명서 발급 또는 다운로드에 실패했습니다.')
    }
  }

  return (
    <LearnerPageShell>
      <LearnerContentRow>
        <MyMenuSidebar currentPageKey="learning-log-gallery" wrapperClassName="w-60 shrink-0 hidden lg:block -ml-0" />

        <section className="min-w-0 flex-1">
          <div className="mb-8 flex flex-col items-end justify-between gap-4 md:flex-row">
            <div>
              <h1 className="mb-2 text-3xl font-bold text-gray-900">나의 증명 카드 (Proof Cards)</h1>
              <p className="text-gray-500">
                완료한 <span className="font-bold text-brand">부모 노드(Module)</span>에 대한 인증서입니다.
              </p>
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => setFilterOpen(true)}
                className="rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-bold text-gray-700 shadow-sm transition hover:bg-gray-50"
              >
                <i className="fas fa-filter mr-1" /> 필터
              </button>
            </div>
          </div>

          {message ? <div className="mb-6 text-sm font-bold text-brand">{message}</div> : null}

          <div id="cardGrid" className="grid grid-cols-1 gap-8 md:grid-cols-2 lg:grid-cols-3">
            {visibleCards.map((item) => {
              const theme = cardTheme(item.type)
              const detail = details[item.proofCardId]
              const flipped = flippedIds.includes(item.proofCardId)
              const detailTags = detail?.tags.length ? detail.tags : item.tags

              return (
                <div
                  key={item.proofCardId}
                  className={`group perspective card-item h-[420px] w-full cursor-pointer ${flipped ? 'flipped' : ''}`}
                  onClick={() => void handleFlip(item)}
                >
                  <div className="card-inner relative rounded-2xl shadow-xl">
                    <div className="card-front flex flex-col border border-gray-200 bg-white">
                      <div className={`relative flex h-44 flex-col justify-between bg-gradient-to-br ${theme.front} p-6`}>
                        <div className="flex items-start justify-between">
                          <span className="rounded border border-white/10 bg-white/20 px-2 py-1 text-[10px] font-bold tracking-wider text-white backdrop-blur">
                            {theme.badge}
                          </span>
                        </div>
                        <i className={`${theme.icon} absolute right-[-5px] bottom-[-10px] text-7xl text-white/20`} />
                        <div className="relative z-10 text-white">
                          <h3 className="text-2xl font-extrabold tracking-tight">{item.title}</h3>
                          <p className="mt-1 text-xs font-medium text-white/80">Verified</p>
                        </div>
                      </div>
                      <div className="flex flex-1 flex-col justify-between bg-white p-6">
                        <div>
                          <p className="mb-2 text-xs font-bold text-gray-400 uppercase">학습 완료일</p>
                          <p className="text-sm font-bold text-gray-800">{formatShortDate(item.issuedAt)}</p>
                        </div>
                        <div className="mt-2 border-t border-gray-100 pt-4">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-medium text-gray-500">AI 코드 리뷰 통과</span>
                            <span className="text-2xl font-bold text-gray-900">
                              {item.score} <span className="text-xs font-normal text-gray-400">/ 100</span>
                            </span>
                          </div>
                        </div>
                        <div className="mt-4 text-center">
                          <span className="flex items-center justify-center gap-1 text-xs text-gray-400 animate-pulse">
                            <i className="fas fa-sync-alt" /> 클릭하여 상세 내용 보기
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="card-back flex flex-col border border-gray-700 bg-gray-900 p-7 text-white">
                      <div className="mb-4 border-b border-gray-700 pb-3">
                        <h3 className="text-lg font-bold text-white">{detail?.title ?? item.title}</h3>
                        <p className="mt-1 text-xs text-gray-400">{detail?.description ?? item.nodeTitle}</p>
                      </div>
                      <div className="custom-scrollbar flex-1 overflow-y-auto pr-2">
                        <p className={`mb-2 text-[10px] font-bold tracking-wider uppercase ${theme.marker}`}>
                          포함된 핵심 개념
                        </p>
                        <ul className={`list-inside list-disc space-y-2 text-sm text-gray-300 ${theme.marker}`}>
                          {detailTags.map((tag) => (
                            <li key={`${item.proofCardId}-${tag.tagId}`}>{tag.tagName}</li>
                          ))}
                        </ul>
                      </div>
                      <div className="mt-4 grid grid-cols-2 gap-3 border-t border-gray-700 pt-4">
                        <button
                          onClick={(event) => {
                            event.stopPropagation()
                            window.location.href = 'roadmap-hub.html'
                          }}
                          className="rounded-lg border border-gray-600 bg-gray-800 py-2 text-xs font-bold text-white transition hover:bg-gray-700"
                        >
                          로드맵 보기
                        </button>
                        <button
                          onClick={(event) => {
                            event.stopPropagation()
                            void handleDownloadCertificate(item)
                          }}
                          className={`rounded-lg py-2 text-xs font-bold text-white transition shadow-lg ${theme.action}`}
                        >
                          증명서 발급
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </section>
      </LearnerContentRow>

      <div className={`modal fixed inset-0 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm ${filterOpen ? 'active' : ''}`}>
        <div className="modal-enter relative w-full max-w-sm overflow-hidden rounded-2xl bg-white p-6 shadow-2xl">
          <div className="mb-6 flex items-center justify-between">
            <h3 className="text-lg font-bold text-gray-900">필터 및 정렬</h3>
            <button onClick={() => setFilterOpen(false)} className="text-gray-400 transition hover:text-gray-900">
              <i className="fas fa-times" />
            </button>
          </div>
          <div className="space-y-6">
            <div>
              <label className="mb-2 block text-xs font-bold text-gray-500 uppercase">카테고리</label>
              <select
                value={categoryFilter}
                onChange={(event) =>
                  setCategoryFilter(event.target.value as 'all' | 'backend' | 'framework' | 'language' | 'cs')
                }
                className="w-full rounded-xl border border-gray-200 bg-white px-4 py-3 text-sm outline-none focus:border-brand"
              >
                <option value="all">전체 보기</option>
                <option value="backend">Backend Track</option>
                <option value="framework">Framework</option>
                <option value="language">Language</option>
                <option value="cs">CS (Computer Science)</option>
              </select>
            </div>
            <div>
              <label className="mb-2 block text-xs font-bold text-gray-500 uppercase">정렬 기준</label>
              <select
                value={sortOrder}
                onChange={(event) => setSortOrder(event.target.value as 'latest' | 'score')}
                className="w-full rounded-xl border border-gray-200 bg-white px-4 py-3 text-sm outline-none focus:border-brand"
              >
                <option value="latest">최신순 (Date)</option>
                <option value="score">점수 높은순 (Score)</option>
              </select>
            </div>
          </div>
          <div className="mt-8">
            <button onClick={() => setFilterOpen(false)} className="bg-brand w-full rounded-xl py-3 text-sm font-bold text-white shadow-md transition hover:bg-green-600">
              적용하기
            </button>
          </div>
        </div>
      </div>

      <div className={`modal fixed inset-0 z-[60] flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm ${certificateOpen ? 'active' : ''}`}>
        <div className="modal-enter relative w-full max-w-3xl overflow-hidden rounded bg-white shadow-2xl">
          <button
            onClick={() => setCertificateOpen(false)}
            className="absolute top-4 right-4 z-10 text-gray-400 transition hover:text-gray-900"
          >
            <i className="fas fa-times text-xl" />
          </button>

          <div className="relative m-2 border-[12px] border-double border-gray-200 p-10">
            <i className="fas fa-code-branch absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-[300px] text-gray-50 opacity-10" />

            <div className="relative z-10 text-center">
              <div className="text-brand mb-8 flex items-center justify-center gap-2 opacity-80">
                <i className="fas fa-code-branch text-2xl" />
                <span className="text-xl font-bold">DevPath</span>
              </div>

              <h1 className="mb-2 text-4xl font-bold tracking-wide text-gray-900" style={{ fontFamily: "'Noto Serif KR', serif" }}>
                수 료 증
              </h1>
              <p className="mb-10 text-sm tracking-[0.2em] text-gray-500 uppercase" style={{ fontFamily: "'Noto Serif KR', serif" }}>
                CERTIFICATE OF COMPLETION
              </p>

              <p className="mb-2 italic text-gray-500">위 사람은 DevPath에서 제공하는</p>
              <h3 className="text-brand mb-2 text-2xl font-bold">{selectedCard?.title ?? '과정명'}</h3>
              <p className="mb-4 italic text-gray-500">
                과정을 성실히 수행하고, 소정의 평가 기준을 통과하였으므로
                <br />
                이 증서를 수여합니다.
              </p>

              <h2 className="mt-6 mb-8 inline-block border-b border-gray-300 px-10 pb-2 text-3xl font-bold text-gray-800">
                나(사용자)
              </h2>

              <div className="mb-12 flex justify-center gap-12 text-sm text-gray-600">
                <div className="text-center">
                  <p className="font-bold text-gray-900">{formatShortDate(selectedCard?.issuedAt)}</p>
                  <p className="mt-1 text-xs text-gray-400 uppercase">발급일 (Date)</p>
                </div>
                <div className="text-center">
                  <p className="font-bold text-gray-900">{selectedCard?.score ?? 0} / 100</p>
                  <p className="mt-1 text-xs text-gray-400 uppercase">최종 점수 (Score)</p>
                </div>
              </div>

              <div className="flex items-end justify-between px-10">
                <div className="text-center">
                  <img src="https://api.dicebear.com/7.x/initials/svg?seed=DevPath" className="mx-auto mb-2 h-16 w-16 grayscale opacity-50" />
                  <div className="w-32 border-t border-gray-400" />
                  <p className="mt-2 text-xs font-bold text-gray-900">DevPath AI</p>
                  <p className="text-[10px] text-gray-500">Instructor</p>
                </div>

                <div className="relative text-yellow-500">
                  <i className="fas fa-certificate text-6xl shadow-sm" />
                  <i className="fas fa-check absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-xl text-white" />
                </div>

                <div className="text-center">
                  <div className="mb-2 text-2xl italic text-gray-600" style={{ fontFamily: "'Noto Serif KR', serif" }}>
                    DevPath
                  </div>
                  <div className="w-32 border-t border-gray-400" />
                  <p className="mt-2 text-xs font-bold text-gray-900">DevPath Inc.</p>
                  <p className="text-[10px] text-gray-500">Platform</p>
                </div>
              </div>
            </div>
          </div>

          <div className="flex justify-center gap-3 border-t border-gray-200 bg-gray-50 p-4">
            <button
              onClick={() => {
                if (selectedCard) {
                  void handleDownloadCertificate(selectedCard)
                }
              }}
              className="flex items-center gap-2 rounded-lg bg-gray-800 px-6 py-2.5 text-sm font-bold text-white transition hover:bg-gray-900"
            >
              <i className="fas fa-download" /> PDF 다운로드
            </button>
            <button
              onClick={async () => {
                if (!selectedCard) {
                  return
                }

                await navigator.clipboard.writeText(`${window.location.origin}/learning-log-gallery.html#${selectedCard.proofCardId}`)
                setMessage('링크가 복사되었습니다.')
              }}
              className="flex items-center gap-2 rounded-lg border border-gray-300 bg-white px-6 py-2.5 text-sm font-bold text-gray-700 transition hover:bg-gray-100"
            >
              <i className="fas fa-share-alt" /> 공유하기
            </button>
          </div>
        </div>
      </div>
    </LearnerPageShell>
  )
}
