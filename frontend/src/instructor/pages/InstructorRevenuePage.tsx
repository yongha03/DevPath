import { useEffect, useState } from 'react'
import { ErrorCard, LoadingCard, formatCurrency, formatDateTime } from '../../account/ui'
import { instructorRevenueApi } from '../../lib/api'
import type { InstructorRevenueSummary, InstructorSettlementItem } from '../../types/instructor'

function getStatusTone(status: string) {
  switch (status) {
    case 'COMPLETED':
      return 'bg-green-100 text-green-700'
    case 'HELD':
      return 'bg-gray-200 text-gray-700'
    case 'PENDING':
    default:
      return 'bg-yellow-100 text-yellow-700'
  }
}

function getStatusLabel(status: string) {
  switch (status) {
    case 'COMPLETED':
      return 'Completed'
    case 'HELD':
      return 'Held'
    case 'PENDING':
    default:
      return 'Pending'
  }
}

function getMonthLabel(value: string) {
  return new Intl.DateTimeFormat('ko-KR', { month: 'numeric' }).format(new Date(value))
}

function buildMonthlyRevenue(settlements: InstructorSettlementItem[]) {
  const monthMap = new Map<string, number>()

  settlements.forEach((item) => {
    const base = item.settledAt ?? null
    if (!base) {
      return
    }

    const date = new Date(base)
    const key = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`
    monthMap.set(key, (monthMap.get(key) ?? 0) + item.amount)
  })

  const sortedKeys = [...monthMap.keys()].sort().slice(-6)
  const maxAmount = Math.max(...sortedKeys.map((key) => monthMap.get(key) ?? 0), 1)

  return sortedKeys.map((key, index) => {
    const [year, month] = key.split('-')
    const date = new Date(Number(year), Number(month) - 1, 1)
    const amount = monthMap.get(key) ?? 0

    return {
      key,
      month: getMonthLabel(date.toISOString()),
      amount,
      height: `${Math.max(18, Math.round((amount / maxAmount) * 100))}%`,
      current: index === sortedKeys.length - 1,
    }
  })
}

function buildSettlementShare(summary: InstructorRevenueSummary) {
  const entries = [
    { label: 'Pending', amount: summary.pendingSettlementAmount, tone: 'bg-yellow-400' },
    { label: 'Held', amount: summary.heldSettlementAmount, tone: 'bg-gray-400' },
    {
      label: 'Completed',
      amount: Math.max(0, summary.totalRevenue - summary.pendingSettlementAmount - summary.heldSettlementAmount),
      tone: 'bg-brand',
    },
  ]
  const total = entries.reduce((sum, item) => sum + item.amount, 0) || 1

  return entries.map((item) => ({
    ...item,
    percent: Math.round((item.amount / total) * 100),
  }))
}

export default function InstructorRevenuePage() {
  const [summary, setSummary] = useState<InstructorRevenueSummary | null>(null)
  const [settlements, setSettlements] = useState<InstructorSettlementItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()

    setLoading(true)
    setError(null)

    Promise.all([
      instructorRevenueApi.getSummary(controller.signal),
      instructorRevenueApi.getSettlements(controller.signal),
    ])
      .then(([nextSummary, nextSettlements]) => {
        setSummary(nextSummary)
        setSettlements(nextSettlements)
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
        <LoadingCard label="수익 데이터를 불러오는 중입니다." />
      </div>
    )
  }

  if (error || !summary) {
    return (
      <div className="p-6">
        <ErrorCard message={error ?? '수익 데이터를 불러오지 못했습니다.'} />
      </div>
    )
  }

  const monthlyRevenue = buildMonthlyRevenue(settlements)
  const settlementShare = buildSettlementShare(summary)

  return (
    <div className="p-6">
      <div className="mx-auto max-w-[1280px]">
        <div className="mb-5 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <h1 className="text-lg font-black tracking-tight text-gray-900">수익 리포트</h1>
            <p className="mt-1 text-sm text-gray-500">최근 정산 흐름과 보류 금액을 한 번에 확인할 수 있습니다.</p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <label className="inline-flex items-center gap-2 rounded-full border border-gray-200 bg-white px-3 py-2 text-sm font-extrabold text-gray-700">
              <i className="fas fa-calendar-alt text-brand" />
              <select className="bg-transparent outline-none">
                <option>최근 30일</option>
              </select>
            </label>
            <button
              type="button"
              onClick={() => window.alert('다운로드 기능은 다음 단계에서 연결합니다.')}
              className="inline-flex items-center gap-2 rounded-full border border-gray-200 bg-white px-3 py-2 text-sm font-extrabold text-gray-700 transition hover:bg-gray-50"
            >
              <i className="fas fa-download text-brand" /> 리포트 다운로드
            </button>
          </div>
        </div>

        <div className="mb-6 grid grid-cols-1 gap-5 md:grid-cols-3">
          <div className="relative overflow-hidden rounded-3xl border border-gray-800 bg-gradient-to-br from-gray-900 to-gray-800 p-6 text-white shadow-lg">
            <div className="absolute top-0 right-0 -mt-10 -mr-10 h-32 w-32 rounded-full bg-white/5 blur-2xl" />
            <p className="mb-2 text-xs font-black text-gray-300 uppercase">Net Revenue</p>
            <h3 className="mb-4 text-3xl font-extrabold">{formatCurrency(summary.netRevenue)}</h3>
            <button
              type="button"
              onClick={() => window.alert('정산 요청 UI는 다음 단계에서 연결합니다.')}
              className="w-full rounded-xl bg-brand py-2.5 text-sm font-extrabold text-white shadow-md transition hover:bg-green-600"
            >
              정산 요청하기
            </button>
            <p className="mt-3 text-[11px] text-gray-300">플랫폼 수수료 {Math.round(summary.platformFeeRate * 100)}% 적용 후 금액입니다.</p>
          </div>

          <div className="flex flex-col justify-between rounded-3xl border border-gray-200 bg-white p-6 shadow-sm">
            <div>
              <div className="flex items-center justify-between">
                <p className="mb-2 text-xs font-black text-gray-500 uppercase">Monthly Revenue</p>
                <span className="rounded-full bg-green-50 px-2 py-0.5 text-[11px] font-extrabold text-green-600">
                  {summary.completedSettlementCount} completed
                </span>
              </div>
              <h3 className="text-3xl font-extrabold text-gray-900">{formatCurrency(summary.monthlyRevenue)}</h3>
            </div>
            <div className="mt-4 flex justify-between border-t border-gray-100 pt-4 text-xs font-bold text-gray-500">
              <span>Total: {formatCurrency(summary.totalRevenue)}</span>
              <span>Pending: {summary.pendingSettlementCount}</span>
            </div>
          </div>

          <div className="flex flex-col justify-between rounded-3xl border border-gray-200 bg-white p-6 shadow-sm">
            <div>
              <p className="mb-2 text-xs font-black text-gray-500 uppercase">Held Settlement</p>
              <h3 className="text-3xl font-extrabold text-gray-400">{formatCurrency(summary.heldSettlementAmount)}</h3>
            </div>
            <div className="mt-4">
              <div className="mb-2 h-1.5 w-full overflow-hidden rounded-full bg-gray-100">
                <div
                  className="h-full rounded-full bg-yellow-400"
                  style={{
                    width: `${summary.totalRevenue > 0 ? Math.round((summary.heldSettlementAmount / summary.totalRevenue) * 100) : 0}%`,
                  }}
                />
              </div>
              <p className="text-xs font-bold text-gray-400">보류 중인 정산은 환불 검토가 끝나면 자동으로 갱신됩니다.</p>
            </div>
          </div>
        </div>

        <div className="mb-6 grid grid-cols-1 gap-5 lg:grid-cols-3">
          <div className="rounded-3xl border border-gray-200 bg-white p-6 shadow-sm lg:col-span-2">
            <div className="mb-6 flex items-center justify-between">
              <h3 className="font-extrabold text-gray-900">월별 정산 추이</h3>
              <select className="rounded-lg border border-gray-300 bg-white p-2 text-xs font-bold outline-none">
                <option>{new Date().getFullYear()}</option>
              </select>
            </div>

            <div className="flex h-64 items-end justify-between gap-4 px-2">
              {monthlyRevenue.map((item) => (
                <div key={item.key} className="group flex flex-1 cursor-pointer flex-col items-center gap-2">
                  <div className="relative h-full w-full overflow-hidden rounded-t-xl border border-gray-100 bg-gray-100">
                    <div
                      className={`absolute bottom-0 w-full rounded-t-xl transition-all ${
                        item.current ? 'bg-brand' : 'bg-brand/60 group-hover:bg-brand/80'
                      }`}
                      style={{ height: item.height }}
                    />
                    <div className="absolute top-2 left-1/2 -translate-x-1/2 rounded-full bg-gray-900 px-2 py-1 text-[10px] font-bold text-white opacity-0 transition group-hover:opacity-100">
                      {formatCurrency(item.amount)}
                    </div>
                  </div>
                  <span className={`text-xs font-bold ${item.current ? 'text-brand' : 'text-gray-400'}`}>{item.month}월</span>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-3xl border border-gray-200 bg-white p-6 shadow-sm">
            <h3 className="mb-6 font-extrabold text-gray-900">정산 상태 분포</h3>
            <div className="space-y-6">
              {settlementShare.map((item) => (
                <div key={item.label}>
                  <div className="mb-1 flex justify-between text-sm">
                    <span className="font-bold text-gray-700">{item.label}</span>
                    <span className="font-extrabold text-gray-900">{item.percent}%</span>
                  </div>
                  <div className="h-2 w-full overflow-hidden rounded-full bg-gray-100">
                    <div className={`h-full rounded-full ${item.tone}`} style={{ width: `${item.percent}%` }} />
                  </div>
                  <p className="mt-1 text-xs font-bold text-gray-400">{formatCurrency(item.amount)}</p>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="overflow-hidden rounded-3xl border border-gray-200 bg-white shadow-sm">
          <div className="flex flex-col gap-3 border-b border-gray-100 bg-gray-50 px-6 py-4 md:flex-row md:items-center md:justify-between">
            <h3 className="font-extrabold text-gray-900">최근 정산 내역</h3>
            <div className="flex items-center gap-2">
              <label className="inline-flex items-center gap-2 rounded-full border border-gray-200 bg-white px-3 py-2 text-sm font-extrabold text-gray-700">
                <i className="fas fa-filter text-brand" />
                <select className="bg-transparent outline-none">
                  <option>전체 상태</option>
                </select>
              </label>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-gray-100 bg-white text-xs text-gray-500 uppercase">
                <tr>
                  <th className="px-6 py-3">Date</th>
                  <th className="px-6 py-3">Settlement</th>
                  <th className="px-6 py-3">Gross</th>
                  <th className="px-6 py-3">Fee</th>
                  <th className="px-6 py-3">Net</th>
                  <th className="px-6 py-3">Status</th>
                </tr>
              </thead>
              <tbody className="font-bold text-gray-600">
                {settlements.map((item) => {
                  const gross = Math.round(item.amount / (1 - summary.platformFeeRate))
                  const fee = gross - item.amount

                  return (
                    <tr key={item.settlementId} className="border-b border-gray-50 bg-white transition hover:bg-gray-50">
                      <td className="px-6 py-4">{formatDateTime(item.settledAt)}</td>
                      <td className="px-6 py-4 font-extrabold text-gray-900">Settlement #{item.settlementId}</td>
                      <td className="px-6 py-4">{formatCurrency(gross)}</td>
                      <td className="px-6 py-4 text-red-400">- {formatCurrency(fee)}</td>
                      <td className="px-6 py-4 font-extrabold text-brand">{formatCurrency(item.amount)}</td>
                      <td className="px-6 py-4">
                        <span className={`rounded-full px-2.5 py-1 text-[11px] font-extrabold ${getStatusTone(item.status)}`}>
                          {getStatusLabel(item.status)}
                        </span>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  )
}
