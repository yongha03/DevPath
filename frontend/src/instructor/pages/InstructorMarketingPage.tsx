import { useEffect, useState } from 'react'
import { ErrorCard, LoadingCard, formatDate, formatNumber } from '../../account/ui'
import { instructorCourseApi, instructorMarketingApi } from '../../lib/api'
import type {
  InstructorConversionSummary,
  InstructorCouponItem,
  InstructorCourseListItem,
  InstructorPromotionItem,
} from '../../types/instructor'

const quickActions = [
  {
    title: '추천 코드 생성',
    description: '강사용 추천 코드를 빠르게 배포할 수 있도록 다음 단계에서 연결합니다.',
    pills: ['추천코드', '자동적용'],
    containerTone: 'from-yellow-50 to-orange-50 border-orange-100',
    iconTone: 'text-orange-400',
    icon: 'fas fa-user-plus',
  },
  {
    title: '타임 세일 설정',
    description: '짧은 시간 집중 전환을 만드는 세일 설정도 같은 흐름으로 연결 가능합니다.',
    pills: ['48H', '전환율'],
    containerTone: 'from-blue-50 to-cyan-50 border-cyan-100',
    iconTone: 'text-cyan-500',
    icon: 'fas fa-stopwatch',
  },
]

function getCouponStatusLabel(active: boolean, expiresAt: string | null) {
  if (!active) {
    return 'Inactive'
  }

  if (expiresAt && new Date(expiresAt).getTime() < Date.now()) {
    return 'Expired'
  }

  return 'Active'
}

function getCouponStatusTone(active: boolean, expiresAt: string | null) {
  const status = getCouponStatusLabel(active, expiresAt)

  if (status === 'Expired') {
    return 'bg-gray-200 text-gray-700'
  }

  if (status === 'Inactive') {
    return 'bg-yellow-100 text-yellow-700'
  }

  return 'bg-green-100 text-green-800'
}

function formatDiscount(coupon: InstructorCouponItem) {
  if (coupon.discountType === 'AMOUNT') {
    return `${formatNumber(coupon.discountValue)}원`
  }

  return `${coupon.discountValue}%`
}

export default function InstructorMarketingPage() {
  const [courses, setCourses] = useState<InstructorCourseListItem[]>([])
  const [coupons, setCoupons] = useState<InstructorCouponItem[]>([])
  const [promotions, setPromotions] = useState<InstructorPromotionItem[]>([])
  const [conversions, setConversions] = useState<InstructorConversionSummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()

    setLoading(true)
    setError(null)

    Promise.all([
      instructorCourseApi.getCourses(controller.signal),
      instructorMarketingApi.getCoupons(controller.signal),
      instructorMarketingApi.getPromotions(controller.signal),
      instructorMarketingApi.getConversions(controller.signal),
    ])
      .then(([nextCourses, nextCoupons, nextPromotions, nextConversions]) => {
        setCourses(nextCourses)
        setCoupons(nextCoupons)
        setPromotions(nextPromotions)
        setConversions(nextConversions)
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

  if (loading) {
    return (
      <div className="p-6">
        <LoadingCard label="마케팅 데이터를 불러오는 중입니다." />
      </div>
    )
  }

  if (error || !conversions) {
    return (
      <div className="p-6">
        <ErrorCard message={error ?? '마케팅 데이터를 불러오지 못했습니다.'} />
      </div>
    )
  }

  const activeCoupons = coupons.filter((item) => item.active)
  const activePromotions = promotions.filter((item) => item.active)

  return (
    <div className="p-6">
      <div className="mx-auto max-w-[1280px]">
        <div className="mb-5 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <h1 className="text-lg font-black tracking-tight text-gray-900">마케팅 & 쿠폰 관리</h1>
            <p className="mt-1 text-sm text-gray-500">쿠폰, 프로모션, 전환 지표를 한 화면에서 확인할 수 있습니다.</p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <label className="inline-flex items-center gap-2 rounded-full border border-gray-200 bg-white px-3 py-2 text-sm font-extrabold text-gray-700">
              <i className="fas fa-book text-brand" />
              <select className="bg-transparent outline-none">
                <option>전체 강의</option>
                {courses.map((course) => (
                  <option key={course.courseId}>{course.title}</option>
                ))}
              </select>
            </label>

            <button
              type="button"
              onClick={() => window.alert('쿠폰 발행 폼은 다음 단계에서 연결합니다.')}
              className="inline-flex items-center gap-2 rounded-xl bg-gray-900 px-5 py-2.5 text-sm font-extrabold text-white shadow-md transition hover:bg-black"
            >
              <i className="fas fa-plus" /> 쿠폰 발행
            </button>
          </div>
        </div>

        <div className="mb-6 grid grid-cols-1 gap-5 md:grid-cols-4">
          {[
            ['Visitors', formatNumber(conversions.totalVisitors), 'fas fa-eye', 'bg-blue-50 text-blue-600'],
            ['Signups', formatNumber(conversions.totalSignups), 'fas fa-user-plus', 'bg-yellow-50 text-yellow-600'],
            ['Purchases', formatNumber(conversions.totalPurchases), 'fas fa-credit-card', 'bg-green-50 text-green-600'],
            ['Purchase Rate', `${conversions.purchaseRate.toFixed(1)}%`, 'fas fa-bolt', 'bg-purple-50 text-purple-600'],
          ].map(([label, value, icon, tone]) => (
            <article key={label} className="rounded-3xl border border-gray-200 bg-white p-5 shadow-sm">
              <div className="flex items-center justify-between">
                <p className="text-xs font-black uppercase tracking-[0.18em] text-gray-400">{label}</p>
                <div className={`flex h-10 w-10 items-center justify-center rounded-2xl ${tone}`}>
                  <i className={icon} />
                </div>
              </div>
              <p className="mt-4 text-3xl font-black text-gray-900">{value}</p>
            </article>
          ))}
        </div>

        <section className="mb-6 rounded-3xl border border-gray-200 bg-white p-6 shadow-sm">
          <div className="mb-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <div>
              <h3 className="font-extrabold text-gray-900">진행 중인 쿠폰</h3>
              <p className="mt-1 text-xs text-gray-500">
                Active coupons {activeCoupons.length}개, active promotions {activePromotions.length}개
              </p>
            </div>
            <button
              type="button"
              onClick={() => window.alert('CSV 내보내기는 다음 단계에서 연결합니다.')}
              className="inline-flex items-center gap-2 rounded-full border border-gray-200 bg-white px-3 py-2 text-sm font-extrabold text-gray-700 transition hover:bg-gray-50"
            >
              <i className="fas fa-file-export text-brand" /> 내보내기
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-gray-500">
              <thead className="border-b border-gray-100 bg-gray-50 text-xs text-gray-700 uppercase">
                <tr>
                  <th className="rounded-l-lg px-4 py-3">쿠폰 / 코드</th>
                  <th className="px-4 py-3">적용 강의</th>
                  <th className="px-4 py-3">할인</th>
                  <th className="px-4 py-3">사용 현황</th>
                  <th className="px-4 py-3">만료일</th>
                  <th className="rounded-r-lg px-4 py-3">상태</th>
                </tr>
              </thead>
              <tbody className="font-bold">
                {coupons.map((item) => (
                  <tr key={item.id} className="border-b border-gray-50 bg-white transition hover:bg-gray-50">
                    <td className="px-4 py-4 font-extrabold text-gray-900">
                      <div>{item.targetCourseTitle}</div>
                      <div className="mt-1 font-mono text-xs text-gray-400">{item.couponCode}</div>
                    </td>
                    <td className="px-4 py-4">{item.targetCourseTitle}</td>
                    <td className="px-4 py-4 font-extrabold text-brand">{formatDiscount(item)}</td>
                    <td className="px-4 py-4">
                      <div className="flex items-center gap-2">
                        <span className="font-extrabold text-gray-900">{item.usageCount}</span> / {item.maxUsageCount ?? '∞'}
                        <div className="h-2 w-20 overflow-hidden rounded-full bg-gray-200">
                          <div
                            className="h-full bg-brand"
                            style={{
                              width: `${item.maxUsageCount ? Math.min(100, Math.round((item.usageCount / item.maxUsageCount) * 100)) : 20}%`,
                            }}
                          />
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-4">{formatDate(item.expiresAt)}</td>
                    <td className="px-4 py-4">
                      <span className={`rounded-full px-2.5 py-1 text-xs font-extrabold ${getCouponStatusTone(item.active, item.expiresAt)}`}>
                        {getCouponStatusLabel(item.active, item.expiresAt)}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <div className="mb-6 grid grid-cols-1 gap-5 lg:grid-cols-2">
          <section className="rounded-3xl border border-gray-200 bg-white p-6 shadow-sm">
            <h3 className="mb-4 font-extrabold text-gray-900">프로모션 현황</h3>
            <div className="space-y-4">
              {promotions.map((item) => (
                <div key={item.id} className="rounded-2xl border border-gray-100 bg-gray-50 px-4 py-4">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="text-sm font-black text-gray-900">{item.courseTitle}</p>
                      <p className="mt-1 text-xs text-gray-500">
                        {item.promotionType} · {item.discountRate}% · {formatDate(item.startAt)} - {formatDate(item.endAt)}
                      </p>
                    </div>
                    <span className={`rounded-full px-2.5 py-1 text-xs font-extrabold ${item.active ? 'bg-green-100 text-green-700' : 'bg-gray-200 text-gray-700'}`}>
                      {item.active ? 'Active' : 'Inactive'}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </section>

          <section className="rounded-3xl border border-gray-200 bg-white p-6 shadow-sm">
            <h3 className="mb-4 font-extrabold text-gray-900">강의별 전환율</h3>
            <div className="space-y-5">
              {conversions.courseConversions.map((item) => (
                <div key={item.courseId}>
                  <div className="mb-2 flex items-center justify-between text-sm font-bold text-gray-700">
                    <span>{item.courseTitle ?? `Course #${item.courseId}`}</span>
                    <span className="text-gray-900">{item.purchaseRate.toFixed(1)}%</span>
                  </div>
                  <div className="h-2 overflow-hidden rounded-full bg-gray-100">
                    <div className="h-full rounded-full bg-brand" style={{ width: `${Math.min(100, item.purchaseRate)}%` }} />
                  </div>
                  <p className="mt-1 text-xs font-bold text-gray-400">
                    Visitors {formatNumber(item.totalVisitors)} / Purchases {formatNumber(item.totalPurchases)}
                  </p>
                </div>
              ))}
            </div>
          </section>
        </div>

        <div className="grid grid-cols-1 gap-5 md:grid-cols-2">
          {quickActions.map((item) => (
            <button
              key={item.title}
              type="button"
              onClick={() => window.alert(`${item.title} 기능은 다음 단계에서 연결합니다.`)}
              className={`flex cursor-pointer items-center justify-between rounded-3xl border bg-gradient-to-r p-6 text-left transition hover:shadow-md ${item.containerTone}`}
            >
              <div>
                <h3 className="font-extrabold text-gray-800">{item.title}</h3>
                <p className="mt-1 text-sm text-gray-500">{item.description}</p>
                <div className="mt-3 flex gap-2">
                  {item.pills.map((pill) => (
                    <span
                      key={pill}
                      className="inline-flex items-center gap-2 rounded-full border border-gray-200 bg-white px-3 py-2 text-sm font-extrabold text-gray-700"
                    >
                      {pill}
                    </span>
                  ))}
                </div>
              </div>
              <div className={`flex h-11 w-11 items-center justify-center rounded-full bg-white shadow-sm ${item.iconTone}`}>
                <i className={item.icon} />
              </div>
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}
