import type { ReactNode } from 'react'

const SETTINGS_STORAGE_KEY = 'devpath.account.preferences'

export type LocalPreferences = {
  emailAlerts: boolean
  marketingAlerts: boolean
}

export function readLocalPreferences(): LocalPreferences {
  try {
    const raw = localStorage.getItem(SETTINGS_STORAGE_KEY)

    if (!raw) {
      return {
        emailAlerts: true,
        marketingAlerts: false,
      }
    }

    return JSON.parse(raw) as LocalPreferences
  } catch {
    return {
      emailAlerts: true,
      marketingAlerts: false,
    }
  }
}

export function getAvatarUrl(name: string, image?: string | null) {
  if (image) {
    return image
  }

  return `https://api.dicebear.com/9.x/glass/svg?seed=${encodeURIComponent(name)}`
}

export function formatDate(value: string | null | undefined) {
  if (!value) {
    return '정보 없음'
  }

  return new Intl.DateTimeFormat('ko-KR', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  }).format(new Date(value))
}

export function formatDateTime(value: string | null | undefined) {
  if (!value) {
    return '정보 없음'
  }

  return new Intl.DateTimeFormat('ko-KR', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  }).format(new Date(value))
}

export function formatNumber(value: number | null | undefined) {
  return new Intl.NumberFormat('ko-KR').format(value ?? 0)
}

export function formatCurrency(value: number | null | undefined, currency: string | null | undefined = 'KRW') {
  if (value === null || value === undefined) {
    return '미정'
  }

  return new Intl.NumberFormat('ko-KR', {
    style: 'currency',
    currency: currency || 'KRW',
    maximumFractionDigits: 0,
  }).format(value)
}

export function getStatusBadgeTone(status: string | null | undefined) {
  switch (status) {
    case 'COMPLETED':
    case 'PDF_READY':
    case 'APPROVED':
      return 'bg-emerald-50 text-emerald-700 ring-1 ring-emerald-100'
    case 'ACTIVE':
    case 'ISSUED':
    case 'PENDING':
    case 'RECRUITING':
      return 'bg-sky-50 text-sky-700 ring-1 ring-sky-100'
    case 'CANCELLED':
    case 'REJECTED':
      return 'bg-rose-50 text-rose-700 ring-1 ring-rose-100'
    default:
      return 'bg-gray-100 text-gray-600 ring-1 ring-gray-200'
  }
}

export function getStatusLabel(status: string | null | undefined) {
  switch (status) {
    case 'ACTIVE':
      return '학습 중'
    case 'COMPLETED':
      return '완료'
    case 'CANCELLED':
      return '취소'
    case 'ISSUED':
      return '발급 완료'
    case 'PDF_READY':
      return 'PDF 준비'
    case 'PENDING':
      return '처리 중'
    case 'APPROVED':
      return '승인'
    case 'RECRUITING':
      return '모집 중'
    case 'IN_PROGRESS':
      return '진행 중'
    case 'GRADED':
      return '채점 완료'
    default:
      return status ?? '미정'
  }
}

export function getCategoryLabel(category: string) {
  switch (category) {
    case 'TECH_SHARE':
      return '기술 공유'
    case 'CAREER':
      return '커리어'
    case 'FREE':
      return '자유'
    default:
      return category
  }
}

export function getNotificationTypeLabel(type: string) {
  switch (type) {
    case 'STUDY_GROUP':
      return '스터디'
    case 'PLANNER':
      return '플래너'
    case 'STREAK':
      return '스트릭'
    case 'PROJECT':
      return '프로젝트'
    case 'SYSTEM':
      return '시스템'
    default:
      return type
  }
}

export function getHeatmapTone(level: number) {
  if (level >= 4) {
    return 'bg-emerald-500'
  }

  if (level === 3) {
    return 'bg-emerald-400'
  }

  if (level === 2) {
    return 'bg-emerald-300'
  }

  if (level === 1) {
    return 'bg-emerald-200'
  }

  return 'bg-gray-100'
}

export function downloadBase64File(fileName: string, mimeType: string, base64Content: string) {
  const binary = window.atob(base64Content)
  const bytes = new Uint8Array(binary.length)

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index)
  }

  const blob = new Blob([bytes], { type: mimeType })
  const blobUrl = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = blobUrl
  link.download = fileName
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(blobUrl)
}

export function BrandLink() {
  return (
    <a href="home.html" className="group flex items-center gap-2 text-xl font-extrabold text-gray-900">
      <i className="fas fa-code-branch text-emerald-500 transition group-hover:rotate-12" />
      DevPath
    </a>
  )
}

export function LoadingCard({ label = '불러오는 중...' }: { label?: string }) {
  return (
    <div className="rounded-[28px] border border-gray-200 bg-white px-6 py-10 text-center text-sm font-medium text-gray-500 shadow-sm">
      {label}
    </div>
  )
}

export function ErrorCard({
  message,
  onRetry,
}: {
  message: string
  onRetry?: () => void
}) {
  return (
    <div className="rounded-[28px] border border-rose-100 bg-rose-50 px-6 py-10 text-center shadow-sm">
      <div className="text-base font-bold text-rose-700">데이터를 불러오지 못했습니다.</div>
      <div className="mt-2 text-sm text-rose-600">{message}</div>
      {onRetry ? (
        <button
          type="button"
          onClick={onRetry}
          className="mt-5 rounded-full bg-rose-600 px-5 py-2 text-sm font-bold text-white transition hover:bg-rose-700"
        >
          다시 시도
        </button>
      ) : null}
    </div>
  )
}

export function EmptyCard({
  title,
  description,
  action,
}: {
  title: string
  description: string
  action?: ReactNode
}) {
  return (
    <div className="rounded-[28px] border border-dashed border-gray-300 bg-white px-6 py-12 text-center shadow-sm">
      <div className="text-lg font-bold text-gray-900">{title}</div>
      <div className="mt-2 text-sm leading-6 text-gray-500">{description}</div>
      {action ? <div className="mt-5">{action}</div> : null}
    </div>
  )
}

export function SectionHeading({
  title,
  description,
  action,
}: {
  title: string
  description?: string
  action?: ReactNode
}) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <h2 className="text-2xl font-black tracking-tight text-gray-900">{title}</h2>
        {description ? <p className="mt-1 text-sm text-gray-500">{description}</p> : null}
      </div>
      {action}
    </div>
  )
}

export function StatusBadge({ status }: { status: string | null | undefined }) {
  return (
    <span className={`inline-flex rounded-full px-3 py-1 text-xs font-bold ${getStatusBadgeTone(status)}`}>
      {getStatusLabel(status)}
    </span>
  )
}

export function MetricTile({
  label,
  value,
  icon,
}: {
  label: string
  value: string
  icon: string
}) {
  return (
    <div className="rounded-[28px] border border-white/10 bg-white/10 px-4 py-4 backdrop-blur">
      <div className="flex items-center justify-between gap-4">
        <div className="text-xs font-black uppercase tracking-[0.2em] text-white/60">{label}</div>
        <i className={`fas ${icon} text-sm text-emerald-200`} />
      </div>
      <div className="mt-3 text-2xl font-black text-white">{value}</div>
    </div>
  )
}

export function HighlightCard({
  title,
  value,
  helper,
  icon,
  tone,
}: {
  title: string
  value: string
  helper: string
  icon: string
  tone: 'emerald' | 'sky' | 'amber'
}) {
  const toneClass =
    tone === 'emerald'
      ? 'bg-emerald-50 text-emerald-600'
      : tone === 'sky'
        ? 'bg-sky-50 text-sky-600'
        : 'bg-amber-50 text-amber-600'

  return (
    <article className="rounded-[28px] border border-gray-200 bg-gray-50 p-5">
      <div className="flex items-center justify-between gap-4">
        <div className="text-sm font-black text-gray-900">{title}</div>
        <div className={`flex h-11 w-11 items-center justify-center rounded-2xl ${toneClass}`}>
          <i className={`fas ${icon}`} />
        </div>
      </div>
      <div className="mt-4 text-3xl font-black text-gray-900">{value}</div>
      <div className="mt-2 text-sm text-gray-500">{helper}</div>
    </article>
  )
}

export function MiniCounter({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-[24px] bg-gray-50 px-4 py-4 text-center">
      <div className="text-xs font-black uppercase tracking-[0.22em] text-gray-400">{label}</div>
      <div className="mt-2 text-2xl font-black text-gray-900">{formatNumber(value)}</div>
    </div>
  )
}

export function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean
  onClick: () => void
  children: ReactNode
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-full px-4 py-2 text-sm font-bold transition ${
        active ? 'bg-gray-900 text-white' : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
      }`}
    >
      {children}
    </button>
  )
}

export function Field({
  label,
  children,
}: {
  label: string
  children: ReactNode
}) {
  return (
    <label className="block">
      <div className="mb-2 text-sm font-black text-gray-900">{label}</div>
      {children}
    </label>
  )
}

export function PreferenceToggle({
  title,
  description,
  checked,
  onChange,
}: {
  title: string
  description: string
  checked: boolean
  onChange: (checked: boolean) => void
}) {
  return (
    <div className="flex items-center justify-between gap-4 rounded-[28px] bg-gray-50 px-5 py-4">
      <div>
        <div className="text-sm font-black text-gray-900">{title}</div>
        <div className="mt-1 text-sm text-gray-500">{description}</div>
      </div>
      <button
        type="button"
        onClick={() => onChange(!checked)}
        className={`relative inline-flex h-8 w-14 rounded-full transition ${
          checked ? 'bg-emerald-500' : 'bg-gray-300'
        }`}
      >
        <span
          className={`absolute top-1 h-6 w-6 rounded-full bg-white shadow-sm transition ${
            checked ? 'left-7' : 'left-1'
          }`}
        />
      </button>
    </div>
  )
}

export function InfoPill({
  icon,
  label,
  value,
}: {
  icon: string
  label: string
  value: string
}) {
  return (
    <div className="rounded-2xl bg-gray-50 px-3 py-4">
      <i className={`fas ${icon} text-gray-400`} />
      <div className="mt-2 text-[11px] font-black uppercase tracking-[0.18em] text-gray-400">{label}</div>
      <div className="mt-1 text-lg font-black text-gray-900">{value}</div>
    </div>
  )
}
