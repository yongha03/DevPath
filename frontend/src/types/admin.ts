// 관리자 카드에서 공통으로 쓰는 수치 모델이다.
export interface AdminDashboardSummaryMetric {
  value: number
  suffix: string
  progressPercent: number
  changeLabel: string
  changeTone: string
}

// 유입 추이 라인 차트의 한 점이다.
export interface AdminDashboardTrafficPoint {
  label: string
  learners: number
  instructors: number
}

// 카테고리 분포 도넛 차트 항목이다.
export interface AdminDashboardCategoryDistribution {
  label: string
  count: number
  percentage: number
}

// 관리자 대시보드 개요 응답 전체 구조다.
export interface AdminDashboardOverview {
  weeklyActiveUsers: AdminDashboardSummaryMetric
  pendingCourseReviews: AdminDashboardSummaryMetric
  issuedCertificates: AdminDashboardSummaryMetric
  pendingReports: AdminDashboardSummaryMetric
  trafficTrend: AdminDashboardTrafficPoint[]
  courseCategoryDistribution: AdminDashboardCategoryDistribution[]
}

// 태그 관리 표에 표시하는 태그 항목이다.
export interface AdminTag {
  id: number
  name: string
  description: string | null
  createdAt?: string | null
}

// 로드맵 관리 표에 표시하는 노드 요약 정보다.
export interface AdminRoadmapNode {
  nodeId: number
  roadmapId: number
  roadmapTitle: string
  title: string
  nodeType: string | null
  required: boolean
  requiredTagCount: number
  requiredTags: string[]
  completionRuleDescription: string | null
  requiredProgressRate: number | null
}

// 회원 통합 관리 표에서 사용하는 계정 정보다.
export interface AdminAccount {
  userId: number
  email: string
  nickname: string
  role: string
  accountStatus: string | null
  createdAt: string | null
  lastLoginAt: string | null
}

// 강의 검수 대기열에 필요한 최소 정보다.
export interface AdminPendingCourse {
  courseId: number
  instructorId: number
  instructorName: string | null
  title: string
  submittedAt: string | null
}

// 신고 접수 표에서 사용하는 신고 요약 정보다.
export interface AdminModerationReport {
  reportId: number
  targetType: string
  targetId: number | null
  contentId: number | null
  targetLabel: string
  targetSummary: string
  reporterName: string | null
  reporterEmail: string | null
  targetUserName: string | null
  targetUserEmail: string | null
  contentTitle: string | null
  contentPreview: string | null
  reason: string
  status: string
  createdAt: string | null
}
