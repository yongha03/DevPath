import { useEffect, useMemo, useState } from 'react'
import { enrollmentApi, wishlistApi } from '../../lib/api'
import { LearnerContentRow, LearnerPageShell, MyMenuSidebar } from '../template'
import type { Enrollment, WishlistCourse } from '../../types/learner'

const fallbackEnrollments: Enrollment[] = [
  {
    enrollmentId: 1,
    courseId: 1,
    courseTitle: 'Java 프로그래밍 (Backend Basic)',
    instructorName: 'DevPath',
    thumbnailUrl: 'https://images.unsplash.com/photo-1587620962725-abab7fe55159?w=500&q=80',
    price: 99000,
    originalPrice: 99000,
    currency: 'KRW',
    hasCertificate: true,
    status: 'ACTIVE',
    progressPercentage: 60,
    enrolledAt: '2026-01-25T00:00:00',
    completedAt: null,
    lastAccessedAt: '2026-02-09T10:00:00',
  },
  {
    enrollmentId: 2,
    courseId: 2,
    courseTitle: '비전공자도 이해할 수 있는 Docker 입문/실전',
    instructorName: 'DevPath',
    thumbnailUrl: 'https://images.unsplash.com/photo-1607799275518-d580e811cc0e?w=500&q=80',
    price: 55000,
    originalPrice: 55000,
    currency: 'KRW',
    hasCertificate: false,
    status: 'ACTIVE',
    progressPercentage: 12,
    enrolledAt: '2026-01-12T00:00:00',
    completedAt: null,
    lastAccessedAt: '2026-02-08T10:00:00',
  },
  {
    enrollmentId: 3,
    courseId: 3,
    courseTitle: 'React + TypeScript 실전 프로젝트',
    instructorName: 'DevPath',
    thumbnailUrl: 'https://images.unsplash.com/photo-1515879218367-8466d910aaa4?w=500&q=80',
    price: 65000,
    originalPrice: 65000,
    currency: 'KRW',
    hasCertificate: false,
    status: 'ACTIVE',
    progressPercentage: 35,
    enrolledAt: '2026-01-08T00:00:00',
    completedAt: null,
    lastAccessedAt: '2026-02-06T10:00:00',
  },
]

const fallbackWishlist: WishlistCourse[] = [
  {
    wishlistId: 1,
    courseId: 4,
    courseTitle: 'Spring Security 실전 인증/인가',
    instructorName: 'DevPath',
    thumbnailUrl: 'https://images.unsplash.com/photo-1555949963-aa79dcee981c?w=500&q=80',
    price: 45000,
    addedAt: '2026-02-01T00:00:00',
  },
]

function getCategoryLabel(courseTitle: string) {
  if (courseTitle.toLowerCase().includes('docker') || courseTitle.toLowerCase().includes('k8s')) {
    return 'DevOps'
  }

  if (courseTitle.toLowerCase().includes('react')) {
    return 'Frontend'
  }

  return 'Backend'
}

function formatRelativeLabel(index: number, lastAccessedAt: string | null | undefined) {
  if (!lastAccessedAt) {
    return '마지막 학습: 최근'
  }

  if (index === 0) {
    return '마지막 학습: 2시간 전'
  }

  if (index === 1) {
    return '마지막 학습: 어제'
  }

  return '마지막 학습: 3일 전'
}

export default function MyLearningPage() {
  const [tab, setTab] = useState<'active' | 'completed' | 'wishlist'>('active')
  const [enrollments, setEnrollments] = useState<Enrollment[]>(fallbackEnrollments)
  const [wishlist, setWishlist] = useState<WishlistCourse[]>(fallbackWishlist)

  useEffect(() => {
    async function load() {
      try {
        const [enrollmentResponse, wishlistResponse] = await Promise.all([
          enrollmentApi.getMyEnrollments(),
          wishlistApi.getCourses(),
        ])

        if (enrollmentResponse.length) {
          setEnrollments(enrollmentResponse)
        }

        if (wishlistResponse.length) {
          setWishlist(wishlistResponse)
        }
      } catch {
        // 원본 내 학습 화면을 그대로 유지하기 위해 실패 시 기본 템플릿 데이터를 사용합니다.
      }
    }

    void load()
  }, [])

  const filteredCourses = useMemo(() => {
    if (tab === 'completed') {
      return enrollments.filter((item) => item.status === 'COMPLETED')
    }

    if (tab === 'wishlist') {
      return wishlist
    }

    return enrollments.filter((item) => item.status !== 'COMPLETED')
  }, [enrollments, tab, wishlist])

  return (
    <LearnerPageShell>
      <LearnerContentRow>
        <MyMenuSidebar
          currentPageKey="my-learning"
          wrapperClassName="w-60 shrink-0 hidden lg:block -ml-0"
          wrapperStyle={{ transform: 'translateX(-7.5px)' }}
        />

        <section className="min-w-0 flex-1">
          <h2 className="mb-6 text-2xl font-bold text-gray-900">내 학습</h2>

          <div className="mb-6 flex border-b border-gray-200">
            <button type="button" className={`tab-btn ${tab === 'active' ? 'active' : ''}`} onClick={() => setTab('active')}>
              학습 중 ({enrollments.filter((item) => item.status !== 'COMPLETED').length})
            </button>
            <button type="button" className={`tab-btn ${tab === 'completed' ? 'active' : ''}`} onClick={() => setTab('completed')}>
              완강 ({enrollments.filter((item) => item.status === 'COMPLETED').length})
            </button>
            <button type="button" className={`tab-btn ${tab === 'wishlist' ? 'active' : ''}`} onClick={() => setTab('wishlist')}>
              찜한 강의
            </button>
          </div>

          <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
            {filteredCourses.length ? (
              filteredCourses.map((item, index) => {
                const isWishlist = tab === 'wishlist'
                const courseTitle = 'courseTitle' in item ? item.courseTitle : ''
                const thumbnailUrl = item.thumbnailUrl ?? fallbackEnrollments[index % fallbackEnrollments.length]?.thumbnailUrl ?? ''

                return (
                  <div
                    key={`${item.courseId}-${index}`}
                    className="group cursor-pointer overflow-hidden rounded-xl border border-gray-200 bg-white transition hover:shadow-lg"
                  >
                    <div className="relative aspect-video bg-gray-100">
                      <img src={thumbnailUrl} className="h-full w-full object-cover" alt="thumb" />
                      {!isWishlist ? (
                        <div className="absolute bottom-0 left-0 h-1 w-full bg-gray-200">
                          <div className="bg-brand h-full" style={{ width: `${(item as Enrollment).progressPercentage ?? 0}%` }} />
                        </div>
                      ) : null}
                    </div>

                    <div className="p-5">
                      <div className="mb-2 flex items-start justify-between">
                        <span className="rounded bg-gray-100 px-2 py-1 text-[10px] font-bold text-gray-500">
                          {getCategoryLabel(courseTitle)}
                        </span>
                        {!isWishlist ? (
                          <span className="text-brand text-xs font-bold">{(item as Enrollment).progressPercentage ?? 0}%</span>
                        ) : (
                          <span className="text-xs font-bold text-gray-400">스크랩</span>
                        )}
                      </div>

                      <h3 className="mb-4 line-clamp-2 h-12 font-bold text-gray-900">{courseTitle}</h3>

                      <div className="mt-4 flex items-center justify-between">
                        <span className="text-xs text-gray-400">
                          {isWishlist
                            ? '보관함에 저장됨'
                            : formatRelativeLabel(index, (item as Enrollment).lastAccessedAt)}
                        </span>
                        <a href={`learning.html?courseId=${item.courseId}`} className="bg-brand rounded-lg px-4 py-2 text-xs font-bold text-white transition hover:bg-green-600">
                          {isWishlist ? '보러가기' : '이어하기'}
                        </a>
                      </div>
                    </div>
                  </div>
                )
              })
            ) : (
              <div className="rounded-xl border border-gray-200 bg-white px-6 py-10 text-sm text-gray-500">
                표시할 강의가 없습니다.
              </div>
            )}
          </div>
        </section>
      </LearnerContentRow>
    </LearnerPageShell>
  )
}
