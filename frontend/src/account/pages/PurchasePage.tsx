import { useEffect, useState } from 'react'
import { enrollmentApi, proofCardApi, wishlistApi } from '../../lib/api'
import { LearnerContentRow, LearnerPageShell, MyMenuSidebar } from '../template'
import type { Enrollment, ProofCardGalleryItem, WishlistCourse } from '../../types/learner'

const fallbackEnrollments: Enrollment[] = [
  {
    enrollmentId: 1,
    courseId: 1,
    courseTitle: 'Docker & K8s 실전 배포',
    instructorName: 'DevPath',
    thumbnailUrl: null,
    price: 55000,
    originalPrice: 55000,
    currency: 'KRW',
    hasCertificate: true,
    status: 'COMPLETED',
    progressPercentage: 100,
    enrolledAt: '2026-01-25T00:00:00',
    completedAt: '2026-01-25T00:00:00',
    lastAccessedAt: '2026-01-25T00:00:00',
  },
  {
    enrollmentId: 2,
    courseId: 2,
    courseTitle: 'Java 마스터 클래스',
    instructorName: 'DevPath',
    thumbnailUrl: null,
    price: 99000,
    originalPrice: 99000,
    currency: 'KRW',
    hasCertificate: true,
    status: 'COMPLETED',
    progressPercentage: 100,
    enrolledAt: '2026-01-10T00:00:00',
    completedAt: '2026-01-10T00:00:00',
    lastAccessedAt: '2026-01-10T00:00:00',
  },
]

const fallbackWishlist: WishlistCourse[] = [
  {
    wishlistId: 1,
    courseId: 3,
    courseTitle: 'Spring Security 실전 인증/인가',
    instructorName: 'DevPath',
    thumbnailUrl: null,
    price: 45000,
    addedAt: '2026-02-01T00:00:00',
  },
]

function formatShortDate(value: string | null | undefined) {
  if (!value) {
    return '-'
  }

  const date = new Date(value)

  return `${date.getFullYear()}.${String(date.getMonth() + 1).padStart(2, '0')}.${String(date.getDate()).padStart(2, '0')}`
}

function formatCurrency(value: number | null | undefined) {
  if (value === null || value === undefined) {
    return '₩0'
  }

  return new Intl.NumberFormat('ko-KR', {
    style: 'currency',
    currency: 'KRW',
    maximumFractionDigits: 0,
  }).format(value)
}

function purchaseStatusLabel(status: string) {
  if (status === 'COMPLETED' || status === 'ACTIVE') {
    return '결제 완료'
  }

  return status
}

export default function PurchasePage() {
  const [tab, setTab] = useState<'history' | 'vault'>('history')
  const [enrollments, setEnrollments] = useState<Enrollment[]>(fallbackEnrollments)
  const [wishlist, setWishlist] = useState<WishlistCourse[]>(fallbackWishlist)
  const [proofCards, setProofCards] = useState<ProofCardGalleryItem[]>([])

  useEffect(() => {
    async function load() {
      try {
        const [enrollmentResponse, wishlistResponse, proofCardResponse] = await Promise.all([
          enrollmentApi.getMyEnrollments(),
          wishlistApi.getCourses(),
          proofCardApi.getGallery(),
        ])

        if (enrollmentResponse.length) {
          setEnrollments(enrollmentResponse)
        }

        if (wishlistResponse.length) {
          setWishlist(wishlistResponse)
        }

        if (proofCardResponse.length) {
          setProofCards(proofCardResponse)
        }
      } catch {
        // 원본 구매/보관함 레이아웃을 유지하기 위해 API 실패 시 기본 데이터를 사용합니다.
      }
    }

    void load()
  }, [])

  return (
    <LearnerPageShell>
      <LearnerContentRow>
        <MyMenuSidebar
          currentPageKey="purchase"
          wrapperClassName="w-60 shrink-0 hidden lg:block -ml-0"
          spacerClassName="h-[64px]"
        />

        <section className="min-w-0 flex-1">
          <h2 className="mb-6 text-2xl font-bold text-gray-900">구매 / 보관함</h2>

          <div className="mb-6 flex border-b border-gray-200">
            <button type="button" className={`tab-btn ${tab === 'history' ? 'active' : ''}`} onClick={() => setTab('history')}>
              구매 내역
            </button>
            <button type="button" className={`tab-btn ${tab === 'vault' ? 'active' : ''}`} onClick={() => setTab('vault')}>
              보관함 (스크랩)
            </button>
          </div>

          {tab === 'history' ? (
            <div className="overflow-hidden rounded-xl border border-gray-200 bg-white shadow-sm">
              <table className="w-full text-left text-sm">
                <thead className="border-b border-gray-200 bg-gray-50 text-gray-500">
                  <tr>
                    <th className="px-6 py-4 font-medium">구매일</th>
                    <th className="px-6 py-4 font-medium">강의명</th>
                    <th className="px-6 py-4 font-medium">결제 금액</th>
                    <th className="px-6 py-4 text-center font-medium">상태</th>
                    <th className="px-6 py-4 text-center font-medium">영수증</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {enrollments.map((item) => (
                    <tr key={item.enrollmentId} className="transition hover:bg-gray-50">
                      <td className="px-6 py-4 text-gray-500">{formatShortDate(item.enrolledAt)}</td>
                      <td className="px-6 py-4 font-bold text-gray-800">{item.courseTitle}</td>
                      <td className="px-6 py-4 text-gray-900">{formatCurrency(item.price)}</td>
                      <td className="px-6 py-4 text-center">
                        <span className="rounded bg-green-100 px-2 py-1 text-xs font-bold text-green-700">
                          {purchaseStatusLabel(item.status)}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-center">
                        <button className="text-gray-400 transition hover:text-gray-600" type="button">
                          <i className="fas fa-file-invoice" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="space-y-6">
              <div className="grid gap-4 lg:grid-cols-2">
                {wishlist.map((item) => (
                  <div key={item.wishlistId} className="rounded-xl border border-gray-200 bg-white p-5 shadow-sm">
                    <div className="mb-2 flex items-start justify-between gap-3">
                      <div>
                        <span className="rounded bg-gray-100 px-2 py-1 text-[10px] font-bold text-gray-500">스크랩</span>
                        <h3 className="mt-3 text-base font-bold text-gray-900">{item.courseTitle}</h3>
                        <p className="mt-1 text-xs text-gray-500">{item.instructorName}</p>
                      </div>
                      <div className="text-sm font-bold text-gray-900">{formatCurrency(item.price)}</div>
                    </div>
                    <p className="text-xs text-gray-400">보관일 {formatShortDate(item.addedAt)}</p>
                  </div>
                ))}
              </div>

              {proofCards.length ? (
                <div className="grid gap-4 lg:grid-cols-2">
                  {proofCards.slice(0, 2).map((item) => (
                    <div
                      key={item.proofCardId}
                      className="rounded-xl border border-gray-200 bg-gradient-to-br from-gray-900 to-gray-800 p-5 text-white shadow-sm"
                    >
                      <span className="rounded border border-white/10 bg-white/10 px-2 py-1 text-[10px] font-bold tracking-wider uppercase">
                        Proof Card
                      </span>
                      <h3 className="mt-3 text-lg font-bold">{item.title}</h3>
                      <p className="mt-1 text-xs text-white/70">{item.nodeTitle}</p>
                      <div className="mt-4 flex flex-wrap gap-2">
                        {item.tags.slice(0, 3).map((tag) => (
                          <span key={tag.tagId} className="rounded-full bg-white/10 px-2 py-1 text-[10px] font-bold">
                            {tag.tagName}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              ) : null}
            </div>
          )}
        </section>
      </LearnerContentRow>
    </LearnerPageShell>
  )
}
