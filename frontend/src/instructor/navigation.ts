export type InstructorPageKey =
  | 'dashboard'
  | 'course-management'
  | 'mentoring'
  | 'student-analytics'
  | 'qna'
  | 'reviews'
  | 'revenue'
  | 'marketing'

export interface InstructorNavItem {
  key: InstructorPageKey
  href: string
  label: string
  icon: string
  section: '개요' | '소통' | '관리'
  badge?: string
}

export const instructorNavItems: InstructorNavItem[] = [
  { key: 'dashboard', href: 'instructor-dashboard.html', label: '대시보드', icon: 'fas fa-th-large', section: '개요' },
  { key: 'course-management', href: 'course-management.html', label: '강의 관리', icon: 'fas fa-video', section: '개요' },
  { key: 'mentoring', href: 'instructor-mentoring.html', label: '멘토링 관리', icon: 'fas fa-users-cog', section: '개요' },
  { key: 'student-analytics', href: 'student-analytics.html', label: '수강생 분석', icon: 'fas fa-user-graduate', section: '개요' },
  { key: 'qna', href: 'instructor-qna.html', label: '질문 게시판', icon: 'fas fa-question-circle', section: '소통', badge: '5' },
  { key: 'reviews', href: 'instructor-reviews.html', label: '수강평 관리', icon: 'fas fa-star', section: '소통' },
  { key: 'revenue', href: 'instructor-revenue.html', label: '정산 관리', icon: 'fas fa-wallet', section: '관리' },
  { key: 'marketing', href: 'instructor-marketing.html', label: '마케팅 관리', icon: 'fas fa-ad', section: '관리' },
]

const pageKeyByFileName = new Map(
  instructorNavItems.map((item) => [item.href.replace('.html', ''), item.key] as const),
)

export function getCurrentInstructorPageKey(): InstructorPageKey {
  const fileName = window.location.pathname.split('/').pop()?.replace('.html', '') ?? 'instructor-dashboard'
  return pageKeyByFileName.get(fileName) ?? 'dashboard'
}

export function getInstructorPageMeta(key: InstructorPageKey) {
  return instructorNavItems.find((item) => item.key === key) ?? instructorNavItems[0]
}
