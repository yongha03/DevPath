import { Chart, registerables } from 'chart.js'
import { adminApi } from './lib/admin-api'
import { authApi } from './lib/api'
import { clearStoredAuthSession, readStoredAuthSession } from './lib/auth-session'
import type {
  AdminAccount,
  AdminDashboardCategoryDistribution,
  AdminDashboardOverview,
  AdminDashboardSummaryMetric,
  AdminModerationReport,
  AdminPendingCourse,
  AdminRoadmapNode,
  AdminTag,
} from './types/admin'
import type {
  CourseCatalogCategory,
  CourseCatalogGroup,
  CourseCatalogGroupItem,
  CourseCatalogMegaMenuItem,
  CourseCatalogMenu,
} from './types/course-catalog'
import './index.css'

Chart.register(...registerables)

// 관리자 화면에서 사용하는 탭 키를 고정한다.
type AdminTabKey = 'dashboard' | 'tags' | 'roadmaps' | 'catalog-menu' | 'users' | 'reports'

type DashboardFilterState = {
  tagQuery: string
  nodeQuery: string
  nodeType: string
  accountQuery: string
  accountRole: string
  accountStatus: string
}

declare global {
  interface Window {
    refreshCurrentTab: () => void
    logout: () => Promise<void>
    createTag: () => Promise<void>
    mergeTag: (tagId: number) => Promise<void>
    updateNodeTags: (nodeId: number) => Promise<void>
    updateNodeRules: (nodeId: number) => Promise<void>
    toggleAccountStatus: (userId: number, accountStatus: string) => Promise<void>
    approveCourse: (courseId: number) => Promise<void>
    rejectCourse: (courseId: number) => Promise<void>
    blindContent: (reportId: number) => Promise<void>
    resolveReport: (reportId: number) => Promise<void>
    createCatalogCategory: () => void
    saveCourseCatalogMenu: () => Promise<void>
    moveCatalogCategory: (categoryIndex: number, direction: number) => void
    deleteCatalogCategory: (categoryIndex: number) => void
    updateCatalogCategoryField: (categoryIndex: number, field: string, value: string) => void
    updateCatalogCategoryActive: (categoryIndex: number, checked: boolean) => void
    addCatalogMegaMenuItem: (categoryIndex: number) => void
    updateCatalogMegaMenuItemLabel: (categoryIndex: number, itemIndex: number, value: string) => void
    moveCatalogMegaMenuItem: (categoryIndex: number, itemIndex: number, direction: number) => void
    removeCatalogMegaMenuItem: (categoryIndex: number, itemIndex: number) => void
    addCatalogGroup: (categoryIndex: number) => void
    updateCatalogGroupField: (categoryIndex: number, groupIndex: number, field: string, value: string) => void
    moveCatalogGroup: (categoryIndex: number, groupIndex: number, direction: number) => void
    removeCatalogGroup: (categoryIndex: number, groupIndex: number) => void
    addCatalogGroupItem: (categoryIndex: number, groupIndex: number) => void
    updateCatalogGroupItemField: (categoryIndex: number, groupIndex: number, itemIndex: number, field: string, value: string) => void
    moveCatalogGroupItem: (categoryIndex: number, groupIndex: number, itemIndex: number, direction: number) => void
    removeCatalogGroupItem: (categoryIndex: number, groupIndex: number, itemIndex: number) => void
  }
}

const TAB_META: Record<AdminTabKey, { title: string; description: string }> = {
  dashboard: { title: '플랫폼 실시간 현황', description: 'DevPath 관리자 운영 지표 요약' },
  tags: { title: '기술 태그 데이터베이스', description: '공식 태그를 조회하고 병합합니다.' },
  roadmaps: { title: '마스터 로드맵 노드', description: '노드 필수 태그와 완료 기준을 관리합니다.' },
  'catalog-menu': { title: '강의 목록 메뉴 관리', description: 'lecture-list 상단 카테고리와 필터 구성을 수정합니다.' },
  users: { title: '회원 통합 관리', description: '회원 상태와 권한을 운영 관점에서 관리합니다.' },
  reports: { title: '검수 및 신고', description: '강의 검수와 사용자 신고를 처리합니다.' },
}

const CATEGORY_COLORS = ['#4F46E5', '#06B6D4', '#10B981', '#F59E0B']

let currentActiveTab: AdminTabKey = 'dashboard'
let trafficChart: Chart | null = null
let categoryChart: Chart | null = null
let roadmapNodeMap = new Map<number, AdminRoadmapNode>()
let reportMap = new Map<number, AdminModerationReport>()
let tagItems: AdminTag[] = []
let nodeItems: AdminRoadmapNode[] = []
let accountItems: AdminAccount[] = []
let courseCatalogMenu: CourseCatalogMenu = { categories: [] }
let courseCatalogMenuLoading = false
let courseCatalogMenuSaving = false
let courseCatalogMenuError: string | null = null

const filterState: DashboardFilterState = {
  tagQuery: '',
  nodeQuery: '',
  nodeType: '',
  accountQuery: '',
  accountRole: '',
  accountStatus: '',
}

function getElement<T extends HTMLElement>(id: string) {
  const element = document.getElementById(id)

  if (!element) {
    throw new Error(`${id} element was not found`)
  }

  return element as T
}

function escapeHtml(value: string | number | null | undefined) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

// 필터 비교는 공백 제거와 소문자 변환 기준으로 통일한다.
function normalizeText(value: string | number | null | undefined) {
  return String(value ?? '').trim().toLowerCase()
}

function matchesKeyword(keyword: string, values: Array<string | number | null | undefined>) {
  if (!keyword) {
    return true
  }

  return values.some((value) => normalizeText(value).includes(keyword))
}

function formatNumber(value: number) {
  return new Intl.NumberFormat('ko-KR').format(value)
}

function formatDateTime(value: string | null | undefined) {
  if (!value) {
    return '-'
  }

  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value
  }

  return new Intl.DateTimeFormat('ko-KR', {
    month: 'numeric',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date)
}

function toneClassName(tone: string) {
  switch (tone) {
    case 'positive':
      return 'bg-emerald-50 text-emerald-500'
    case 'warning':
      return 'bg-amber-50 text-amber-600'
    case 'negative':
      return 'bg-rose-50 text-rose-600'
    default:
      return 'bg-slate-100 text-slate-500'
  }
}

function roleLabel(role: string) {
  switch (role) {
    case 'ROLE_ADMIN':
      return '관리자'
    case 'ROLE_INSTRUCTOR':
      return '강사'
    case 'ROLE_LEARNER':
      return '학습자'
    default:
      return role
  }
}

function roleBadgeClassName(role: string) {
  switch (role) {
    case 'ROLE_ADMIN':
      return 'border border-purple-100 bg-purple-50 text-purple-700'
    case 'ROLE_INSTRUCTOR':
      return 'border border-blue-100 bg-blue-50 text-blue-700'
    default:
      return 'border border-slate-200 bg-slate-100 text-slate-500'
  }
}

function nodeTypeLabel(nodeType: string | null | undefined) {
  switch ((nodeType ?? '').toUpperCase()) {
    case 'CONCEPT':
      return '개념'
    case 'PRACTICE':
      return '실습'
    case 'PROJECT':
      return '프로젝트'
    case 'REVIEW':
      return '복습'
    case 'EXAM':
      return '평가'
    default:
      return nodeType || '미정'
  }
}

function accountStatusLabel(status: string | null | undefined) {
  switch ((status ?? '').toUpperCase()) {
    case 'ACTIVE':
      return '활성'
    case 'RESTRICTED':
      return '제한'
    case 'INACTIVE':
      return '비활성'
    default:
      return status || '미확인'
  }
}

function reportTargetLabel(report: AdminModerationReport) {
  if (report.targetLabel?.trim()) {
    return report.targetLabel
  }

  switch (report.targetType) {
    case 'USER':
      return '회원 신고'
    case 'CONTENT':
      return '콘텐츠 신고'
    default:
      return '대상 미확인'
  }
}

function reportTargetSummary(report: AdminModerationReport) {
  if (report.targetSummary?.trim()) {
    return report.targetSummary
  }

  if (report.targetType === 'USER') {
    return `회원 ID #${report.targetId ?? '-'}`
  }

  if (report.targetType === 'CONTENT') {
    return `콘텐츠 ID #${report.targetId ?? report.contentId ?? '-'}`
  }

  return '신고 대상 정보를 찾을 수 없습니다.'
}

function reportReporterSummary(report: AdminModerationReport) {
  if (report.reporterName && report.reporterEmail) {
    return `${report.reporterName} (${report.reporterEmail})`
  }

  if (report.reporterEmail) {
    return report.reporterEmail
  }

  return '신고자 정보 없음'
}

function reportContentContext(report: AdminModerationReport) {
  const contexts = [report.contentTitle, report.contentPreview].filter(
    (value): value is string => Boolean(value?.trim()),
  )

  if (contexts.length === 0) {
    return null
  }

  return contexts.join(' / ')
}

function buildLoadingRow(colspan: number, message = '데이터를 불러오는 중입니다...') {
  return `<tr><td colspan="${colspan}" class="py-10 text-center text-xs text-slate-400"><i class="fas fa-circle-notch fa-spin mr-2"></i>${escapeHtml(message)}</td></tr>`
}

function buildEmptyRow(colspan: number, message = '표시할 데이터가 없습니다.') {
  return `<tr><td colspan="${colspan}" class="py-10 text-center text-xs text-slate-400">${escapeHtml(message)}</td></tr>`
}

function buildErrorRow(colspan: number, message = '데이터를 불러오지 못했습니다.') {
  return `<tr><td colspan="${colspan}" class="py-10 text-center text-xs text-rose-500">${escapeHtml(message)}</td></tr>`
}

// 필터 결과 개수를 각 섹션 요약 문구로 보여준다.
function updateFilterSummary(elementId: string, totalCount: number, filteredCount: number) {
  const message =
    totalCount === filteredCount
      ? `전체 ${formatNumber(totalCount)}개`
      : `전체 ${formatNumber(totalCount)}개 중 ${formatNumber(filteredCount)}개`

  getElement(elementId).textContent = message
}

function updateMetric(prefix: string, metric: AdminDashboardSummaryMetric, fallbackSuffix = '') {
  getElement(prefix + '-value').textContent = formatNumber(metric.value)

  const suffixElement = document.getElementById(prefix + '-suffix')
  if (suffixElement) {
    suffixElement.textContent = metric.suffix || fallbackSuffix
  }

  const changeElement = getElement(prefix + '-change')
  changeElement.textContent = metric.changeLabel
  changeElement.className = `rounded px-1.5 py-0.5 text-xs font-bold ${toneClassName(metric.changeTone)}`
  getElement(prefix + '-progress').setAttribute('style', `width: ${metric.progressPercent}%`)
}

// 차트는 매번 새 데이터를 받을 때 기존 인스턴스를 정리하고 다시 만든다.
function renderTrafficChart(points: AdminDashboardOverview['trafficTrend']) {
  const canvas = document.getElementById('trafficChart') as HTMLCanvasElement | null
  const ctx = canvas?.getContext('2d')

  if (!ctx) {
    return
  }

  trafficChart?.destroy()

  const gradientBlue = ctx.createLinearGradient(0, 0, 0, 300)
  gradientBlue.addColorStop(0, 'rgba(79, 70, 229, 0.2)')
  gradientBlue.addColorStop(1, 'rgba(79, 70, 229, 0)')

  const gradientTeal = ctx.createLinearGradient(0, 0, 0, 300)
  gradientTeal.addColorStop(0, 'rgba(6, 182, 212, 0.2)')
  gradientTeal.addColorStop(1, 'rgba(6, 182, 212, 0)')

  trafficChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: points.map((point) => point.label),
      datasets: [
        {
          label: '학습자',
          data: points.map((point) => point.learners),
          borderColor: '#4F46E5',
          backgroundColor: gradientBlue,
          borderWidth: 2,
          tension: 0.4,
          fill: true,
        },
        {
          label: '강사',
          data: points.map((point) => point.instructors),
          borderColor: '#06B6D4',
          backgroundColor: gradientTeal,
          borderWidth: 2,
          tension: 0.4,
          fill: true,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'top',
          align: 'end',
        },
      },
    },
  })
}

function renderCategoryChart(categories: AdminDashboardCategoryDistribution[]) {
  const chartData = categories.length > 0 ? categories : [{ label: '기타', count: 1, percentage: 100 }]
  const canvas = document.getElementById('categoryChart') as HTMLCanvasElement | null
  const ctx = canvas?.getContext('2d')

  if (!ctx) {
    return
  }

  categoryChart?.destroy()
  categoryChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: chartData.map((category) => category.label),
      datasets: [
        {
          data: chartData.map((category) => category.count),
          backgroundColor: chartData.map((_, index) => CATEGORY_COLORS[index % CATEGORY_COLORS.length]),
          borderWidth: 0,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '75%',
      plugins: { legend: { display: false } },
    },
  })

  getElement('categoryLegend').innerHTML = chartData
    .map(
      (category, index) =>
        `<div class="flex items-center gap-1.5"><div class="h-2 w-2 rounded-full" style="background:${CATEGORY_COLORS[index % CATEGORY_COLORS.length]}"></div>${escapeHtml(category.label)} (${category.percentage}%)</div>`,
    )
    .join('')
}

function renderOverview(overview: AdminDashboardOverview) {
  updateMetric('weekly-active-users', overview.weeklyActiveUsers)
  updateMetric('pending-course-reviews', overview.pendingCourseReviews, '건')
  updateMetric('issued-certificates', overview.issuedCertificates)
  updateMetric('pending-reports', overview.pendingReports, '건')
  renderTrafficChart(overview.trafficTrend)
  renderCategoryChart(overview.courseCategoryDistribution)
  getElement('nav-report-badge').textContent = String(overview.pendingReports.value)
}

async function fetchOverview() {
  renderOverview(await adminApi.getOverview())
}

function renderTagRows(tags: AdminTag[]) {
  const tbody = getElement('tagTableBody')
  tbody.innerHTML = tags.length
    ? tags
        .map(
          (tag) => `
            <tr class="border-b border-slate-100 transition-colors hover:bg-slate-50/70">
              <td class="px-6 py-3 font-mono text-xs text-slate-400">#${tag.id}</td>
              <td class="px-6 py-3 font-bold text-slate-800">${escapeHtml(tag.name)}</td>
              <td class="px-6 py-3 text-slate-500">${escapeHtml(tag.description || '설명 없음')}</td>
              <td class="px-6 py-3"><span class="rounded bg-emerald-50 px-2 py-0.5 text-[10px] font-bold tracking-wide text-emerald-600">ACTIVE</span></td>
              <td class="px-6 py-3 text-right"><button onclick="mergeTag(${tag.id})" class="rounded bg-indigo-50 px-3 py-1.5 text-xs font-medium text-indigo-600 transition hover:bg-indigo-100 hover:text-indigo-800" type="button">병합</button></td>
            </tr>`,
        )
        .join('')
    : buildEmptyRow(5, '조건에 맞는 태그가 없습니다.')
}

function applyTagFilters() {
  const keyword = normalizeText(filterState.tagQuery)
  const filteredTags = tagItems.filter((tag) => matchesKeyword(keyword, [tag.id, tag.name, tag.description]))

  renderTagRows(filteredTags)
  updateFilterSummary('tagFilterSummary', tagItems.length, filteredTags.length)
}

async function fetchTags() {
  const tbody = getElement('tagTableBody')
  tbody.innerHTML = buildLoadingRow(5)

  try {
    tagItems = await adminApi.getTags()
    applyTagFilters()
  } catch (error) {
    tbody.innerHTML = buildErrorRow(5, error instanceof Error ? error.message : '태그를 불러오지 못했습니다.')
    updateFilterSummary('tagFilterSummary', 0, 0)
  }
}

function renderNodeRows(nodes: AdminRoadmapNode[]) {
  const tbody = getElement('nodeTableBody')
  tbody.innerHTML = nodes.length
    ? nodes
        .map(
          (node) => `
            <tr class="border-b border-slate-100 transition-colors hover:bg-slate-50/70">
              <td class="px-6 py-3 font-mono text-xs text-slate-400">#${node.nodeId}</td>
              <td class="px-6 py-3"><div class="font-bold text-slate-800">${escapeHtml(node.title)}</div><div class="mt-0.5 text-[10px] text-slate-400">Roadmap #${node.roadmapId}</div></td>
              <td class="px-6 py-3"><div class="font-medium text-slate-700">${escapeHtml(node.roadmapTitle)}</div><div class="mt-0.5 inline-flex rounded bg-blue-50 px-2 py-0.5 text-[10px] font-bold tracking-wide text-blue-600">${escapeHtml(nodeTypeLabel(node.nodeType))}</div></td>
              <td class="px-6 py-3 text-xs text-slate-500"><div>${node.requiredTagCount > 0 ? `필수 태그 ${node.requiredTagCount}개` : '필수 태그 없음'}</div><div class="mt-1">${escapeHtml(node.completionRuleDescription || '완료 기준 없음')}${node.requiredProgressRate !== null ? ` / ${node.requiredProgressRate}%` : ''}</div></td>
              <td class="space-x-1 px-6 py-3 text-right"><button onclick="updateNodeTags(${node.nodeId})" class="rounded border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-600 transition hover:bg-slate-50" type="button">태그 매핑</button><button onclick="updateNodeRules(${node.nodeId})" class="rounded bg-indigo-50 px-3 py-1.5 text-xs font-medium text-indigo-600 transition hover:bg-indigo-100 hover:text-indigo-800" type="button">완료 기준</button></td>
            </tr>`,
        )
        .join('')
    : buildEmptyRow(5, '조건에 맞는 노드가 없습니다.')
}

function applyNodeFilters() {
  const keyword = normalizeText(filterState.nodeQuery)
  const nodeType = filterState.nodeType.trim().toUpperCase()
  const filteredNodes = nodeItems.filter((node) => {
    const matchesText = matchesKeyword(keyword, [node.nodeId, node.title, node.roadmapTitle, node.roadmapId])
    const matchesType = !nodeType || (node.nodeType ?? '').toUpperCase() === nodeType

    return matchesText && matchesType
  })

  renderNodeRows(filteredNodes)
  updateFilterSummary('nodeFilterSummary', nodeItems.length, filteredNodes.length)
}

async function fetchNodes() {
  const tbody = getElement('nodeTableBody')
  tbody.innerHTML = buildLoadingRow(5)

  try {
    nodeItems = await adminApi.getRoadmapNodes()
    roadmapNodeMap = new Map(nodeItems.map((node) => [node.nodeId, node]))
    applyNodeFilters()
  } catch (error) {
    tbody.innerHTML = buildErrorRow(5, error instanceof Error ? error.message : '노드를 불러오지 못했습니다.')
    updateFilterSummary('nodeFilterSummary', 0, 0)
  }
}

function renderAccountRows(accounts: AdminAccount[]) {
  const tbody = getElement('accountTableBody')
  tbody.innerHTML = accounts.length
    ? accounts
        .map(
          (account) => `
            <tr class="border-b border-slate-100 transition-colors hover:bg-slate-50/70">
              <td class="px-6 py-3 font-mono text-xs text-slate-400">#${account.userId}</td>
              <td class="px-6 py-3 font-medium text-slate-600">${escapeHtml(account.email)}</td>
              <td class="px-6 py-3 font-bold text-slate-800">${escapeHtml(account.nickname)}</td>
              <td class="px-6 py-3"><span class="rounded px-2 py-0.5 text-[10px] font-bold tracking-wide ${roleBadgeClassName(account.role)}">${escapeHtml(roleLabel(account.role))}</span></td>
              <td class="px-6 py-3"><span class="${account.accountStatus === 'ACTIVE' ? 'text-emerald-500' : 'text-rose-500'} text-xs font-bold"><i class="fas fa-circle mr-1 text-[8px]"></i>${escapeHtml(accountStatusLabel(account.accountStatus))}</span></td>
              <td class="px-6 py-3 text-right"><button onclick="toggleAccountStatus(${account.userId}, '${escapeHtml(account.accountStatus || 'INACTIVE')}')" class="rounded ${account.accountStatus === 'ACTIVE' ? 'bg-rose-50 text-rose-600 hover:bg-rose-100 hover:text-rose-800' : 'bg-emerald-50 text-emerald-600 hover:bg-emerald-100 hover:text-emerald-800'} px-3 py-1.5 text-xs font-medium transition" type="button">${account.accountStatus === 'ACTIVE' ? '제한' : '복구'}</button></td>
            </tr>`,
        )
        .join('')
    : buildEmptyRow(6, '조건에 맞는 계정이 없습니다.')
}

function applyAccountFilters() {
  const keyword = normalizeText(filterState.accountQuery)
  const role = filterState.accountRole.trim().toUpperCase()
  const status = filterState.accountStatus.trim().toUpperCase()
  const filteredAccounts = accountItems.filter((account) => {
    const matchesText = matchesKeyword(keyword, [account.userId, account.email, account.nickname])
    const matchesRole = !role || account.role.toUpperCase() === role
    const matchesStatus = !status || (account.accountStatus ?? 'UNKNOWN').toUpperCase() === status

    return matchesText && matchesRole && matchesStatus
  })

  renderAccountRows(filteredAccounts)
  updateFilterSummary('accountFilterSummary', accountItems.length, filteredAccounts.length)
}

async function fetchAccounts() {
  const tbody = getElement('accountTableBody')
  tbody.innerHTML = buildLoadingRow(6)

  try {
    accountItems = await adminApi.getAccounts()
    applyAccountFilters()
  } catch (error) {
    tbody.innerHTML = buildErrorRow(6, error instanceof Error ? error.message : '계정을 불러오지 못했습니다.')
    updateFilterSummary('accountFilterSummary', 0, 0)
  }
}

async function fetchPendingCourses() {
  const tbody = getElement('courseTableBody')
  tbody.innerHTML = buildLoadingRow(3, '강의 검수 목록을 불러오는 중입니다...')

  try {
    const courses = await adminApi.getPendingCourses()
    tbody.innerHTML = courses.length
      ? courses
          .map(
            (course: AdminPendingCourse) => `
              <tr class="border-b border-slate-100 transition-colors hover:bg-slate-50/70">
                <td class="px-6 py-3"><div class="font-bold text-slate-800">${escapeHtml(course.title)}</div><div class="mt-0.5 font-mono text-[10px] text-slate-400">ID: #${course.courseId}</div></td>
                <td class="px-6 py-3 text-xs font-medium text-slate-600">${escapeHtml(course.instructorName || `강사 #${course.instructorId}`)}<div class="mt-1 text-[10px] text-slate-400">${escapeHtml(formatDateTime(course.submittedAt))}</div></td>
                <td class="space-x-1 px-6 py-3 text-right"><button onclick="approveCourse(${course.courseId})" class="rounded bg-indigo-600 px-3 py-1.5 text-xs font-bold text-white shadow-sm transition hover:bg-indigo-700" type="button">승인</button><button onclick="rejectCourse(${course.courseId})" class="rounded border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-600 transition hover:bg-slate-50" type="button">반려</button></td>
              </tr>`,
          )
          .join('')
      : buildEmptyRow(3, '검수 대기 중인 강의가 없습니다.')
  } catch (error) {
    tbody.innerHTML = buildErrorRow(3, error instanceof Error ? error.message : '강의 검수 목록을 불러오지 못했습니다.')
  }
}

async function fetchReports() {
  const tbody = getElement('reportTableBody')
  tbody.innerHTML = buildLoadingRow(3, '신고 목록을 불러오는 중입니다...')

  try {
    const reports = await adminApi.getReports()
    reportMap = new Map(reports.map((report) => [report.reportId, report]))
    tbody.innerHTML = reports.length
      ? reports
          .map((report: AdminModerationReport) => {
            const blindAction = report.contentId
              ? `<button onclick="blindContent(${report.reportId})" class="rounded bg-rose-50 px-3 py-1.5 text-xs font-bold text-rose-600 transition hover:bg-rose-100 hover:text-rose-800" type="button">블라인드</button>`
              : '<span class="px-3 py-1.5 text-xs text-slate-300">콘텐츠 없음</span>'

            const contentContext = reportContentContext(report)
            const contentContextRow = contentContext
              ? `<div class="mt-1 text-[11px] leading-5 text-slate-400">${escapeHtml(contentContext)}</div>`
              : ''

            return `
              <tr class="border-b border-slate-100 transition-colors hover:bg-rose-50/40">
                <td class="px-6 py-3">
                  <div class="flex flex-wrap items-center gap-1.5">
                    <span class="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] font-bold text-slate-500">${escapeHtml(reportTargetLabel(report))}</span>
                    <span class="font-mono text-[10px] text-slate-400">신고 #${report.reportId}</span>
                  </div>
                  <div class="mt-1 text-xs font-semibold text-slate-700">${escapeHtml(reportTargetSummary(report))}</div>
                  <div class="mt-1 text-[11px] text-slate-500">신고자 ${escapeHtml(reportReporterSummary(report))}</div>
                  ${contentContextRow}
                  <div class="mt-1 text-[10px] text-slate-400">${escapeHtml(formatDateTime(report.createdAt))}</div>
                </td>
                <td class="px-6 py-3 text-xs font-medium leading-5 text-slate-800">${escapeHtml(report.reason)}</td>
                <td class="space-x-1 px-6 py-3 text-right">
                  ${blindAction}
                  <button onclick="resolveReport(${report.reportId})" class="rounded px-3 py-1.5 text-xs font-medium text-slate-500 transition hover:bg-slate-100 hover:text-slate-700" type="button">무시</button>
                </td>
              </tr>`
          })
          .join('')
      : buildEmptyRow(3, '접수된 신고가 없습니다.')
  } catch (error) {
    tbody.innerHTML = buildErrorRow(3, error instanceof Error ? error.message : '신고 목록을 불러오지 못했습니다.')
  }
}

function cloneCourseCatalogMenu(menu: CourseCatalogMenu): CourseCatalogMenu {
  return {
    categories: menu.categories.map((category) => ({
      ...category,
      megaMenuItems: category.megaMenuItems.map((item) => ({ ...item })),
      groups: category.groups.map((group) => ({
        ...group,
        items: group.items.map((item) => ({ ...item })),
      })),
    })),
  }
}

// 배열 순서를 화면 표시 순서와 저장 순서로 그대로 맞춘다.
function reindexCourseCatalogMenu(menu: CourseCatalogMenu): CourseCatalogMenu {
  const categories = [...(menu.categories ?? [])]
    .map((category, categoryIndex) => ({
      ...category,
      sortOrder: categoryIndex,
      megaMenuItems: [...(category.megaMenuItems ?? [])]
        .map((item, itemIndex) => ({
          ...item,
          label: item.label ?? '',
          sortOrder: itemIndex,
        })),
      groups: [...(category.groups ?? [])]
        .map((group, groupIndex) => ({
          ...group,
          name: group.name ?? '',
          sortOrder: groupIndex,
          items: [...(group.items ?? [])]
            .map((item, itemIndex) => ({
              ...item,
              name: item.name ?? '',
              linkedCategoryKey: item.linkedCategoryKey ?? null,
              sortOrder: itemIndex,
            })),
        })),
    }))

  return { categories }
}

function createEmptyCatalogMegaMenuItem(): CourseCatalogMegaMenuItem {
  return { label: '', sortOrder: 0 }
}

function createEmptyCatalogGroupItem(): CourseCatalogGroupItem {
  return { name: '', linkedCategoryKey: null, sortOrder: 0 }
}

function createEmptyCatalogGroup(): CourseCatalogGroup {
  return { name: '', sortOrder: 0, items: [createEmptyCatalogGroupItem()] }
}

function createEmptyCatalogCategory(nextIndex: number): CourseCatalogCategory {
  return {
    categoryKey: `category-${nextIndex + 1}`,
    label: '새 카테고리',
    title: '새 강의 목록',
    iconClass: 'fas fa-folder',
    sortOrder: nextIndex,
    active: true,
    megaMenuItems: [createEmptyCatalogMegaMenuItem()],
    groups: [createEmptyCatalogGroup()],
  }
}

function moveArrayItem<T>(items: T[], index: number, direction: number) {
  const nextIndex = index + direction
  if (nextIndex < 0 || nextIndex >= items.length) {
    return
  }

  const [movedItem] = items.splice(index, 1)
  items.splice(nextIndex, 0, movedItem)
}

function updateCatalogMenu(mutator: (menu: CourseCatalogMenu) => void) {
  const nextMenu = cloneCourseCatalogMenu(courseCatalogMenu)
  mutator(nextMenu)
  courseCatalogMenu = reindexCourseCatalogMenu(nextMenu)
  courseCatalogMenuError = null
  renderCourseCatalogMenuEditor()
}

function updateCatalogMenuSaveButton() {
  const button = document.getElementById('catalogMenuSaveButton') as HTMLButtonElement | null
  if (!button) {
    return
  }

  button.disabled = courseCatalogMenuSaving
  button.classList.toggle('opacity-70', courseCatalogMenuSaving)
  button.classList.toggle('cursor-not-allowed', courseCatalogMenuSaving)
  button.innerHTML = courseCatalogMenuSaving
    ? '<i class="fas fa-circle-notch fa-spin mr-1"></i> 저장 중'
    : '<i class="fas fa-save mr-1"></i> 전체 저장'
}

function updateCatalogMenuSummary() {
  const summaryElement = document.getElementById('catalogMenuSummary')
  if (!summaryElement) {
    return
  }

  const categoryCount = courseCatalogMenu.categories.length
  const groupCount = courseCatalogMenu.categories.reduce((sum, category) => sum + category.groups.length, 0)
  const itemCount = courseCatalogMenu.categories.reduce(
    (sum, category) => sum + category.groups.reduce((groupSum, group) => groupSum + group.items.length, 0),
    0,
  )
  summaryElement.textContent = `카테고리 ${formatNumber(categoryCount)}개 · 그룹 ${formatNumber(groupCount)}개 · 항목 ${formatNumber(itemCount)}개`
}

function renderCourseCatalogMenuEditor() {
  const container = getElement('catalogMenuEditor')
  updateCatalogMenuSaveButton()
  updateCatalogMenuSummary()

  if (courseCatalogMenuLoading) {
    container.innerHTML = `
      <div class="rounded-2xl border border-slate-200 bg-white px-6 py-10 text-center text-sm text-slate-400">
        <i class="fas fa-circle-notch fa-spin mr-2"></i> 강의 메뉴를 불러오는 중입니다.
      </div>
    `
    return
  }

  if (courseCatalogMenuError) {
    container.innerHTML = `
      <div class="rounded-2xl border border-rose-200 bg-rose-50 px-6 py-10 text-center text-sm text-rose-600">
        <div class="font-semibold">${escapeHtml(courseCatalogMenuError)}</div>
        <button onclick="refreshCurrentTab()" class="mt-4 rounded-lg border border-rose-200 bg-white px-4 py-2 text-xs font-bold text-rose-600 transition hover:bg-rose-50" type="button">
          다시 불러오기
        </button>
      </div>
    `
    return
  }

  if (courseCatalogMenu.categories.length === 0) {
    container.innerHTML = `
      <div class="rounded-2xl border border-dashed border-slate-300 bg-white px-6 py-10 text-center text-sm text-slate-500">
        등록된 강의 메뉴가 없습니다.
      </div>
    `
    return
  }

  container.innerHTML = courseCatalogMenu.categories
    .map((category, categoryIndex) => renderCatalogCategoryCard(category, categoryIndex))
    .join('')
}

function renderCatalogCategoryCard(category: CourseCatalogCategory, categoryIndex: number) {
  const groupsHtml = category.groups.length
    ? category.groups.map((group, groupIndex) => renderCatalogGroupCard(categoryIndex, group, groupIndex)).join('')
    : `
      <div class="rounded-xl border border-dashed border-slate-200 bg-white px-4 py-6 text-center text-xs text-slate-400">
        등록된 그룹이 없습니다.
      </div>
    `

  const megaMenuHtml = category.megaMenuItems.length
    ? category.megaMenuItems
        .map(
          (item, itemIndex) => `
            <div class="flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2">
              <input
                value="${escapeHtml(item.label)}"
                oninput="updateCatalogMegaMenuItemLabel(${categoryIndex}, ${itemIndex}, this.value)"
                type="text"
                class="flex-1 bg-transparent text-sm text-slate-700 outline-none"
                placeholder="메가메뉴 라벨"
              />
              <div class="flex items-center gap-1 text-slate-400">
                <button onclick="moveCatalogMegaMenuItem(${categoryIndex}, ${itemIndex}, -1)" class="rounded p-1 transition hover:bg-slate-100 hover:text-slate-700" type="button">
                  <i class="fas fa-arrow-up text-xs"></i>
                </button>
                <button onclick="moveCatalogMegaMenuItem(${categoryIndex}, ${itemIndex}, 1)" class="rounded p-1 transition hover:bg-slate-100 hover:text-slate-700" type="button">
                  <i class="fas fa-arrow-down text-xs"></i>
                </button>
                <button onclick="removeCatalogMegaMenuItem(${categoryIndex}, ${itemIndex})" class="rounded p-1 transition hover:bg-rose-50 hover:text-rose-600" type="button">
                  <i class="fas fa-trash text-xs"></i>
                </button>
              </div>
            </div>`,
        )
        .join('')
    : `
      <div class="rounded-lg border border-dashed border-slate-200 bg-white px-4 py-5 text-center text-xs text-slate-400">
        등록된 메가메뉴 항목이 없습니다.
      </div>
    `

  return `
    <section class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
      <div class="flex flex-col gap-4 border-b border-slate-100 pb-5 xl:flex-row xl:items-start xl:justify-between">
        <div>
          <div class="flex items-center gap-2">
            <span class="rounded-full bg-indigo-50 px-2.5 py-1 text-[11px] font-bold text-indigo-600">카테고리 ${categoryIndex + 1}</span>
            <span class="rounded-full px-2.5 py-1 text-[11px] font-bold ${category.active ? 'bg-emerald-50 text-emerald-600' : 'bg-slate-100 text-slate-500'}">${category.active ? '활성' : '비활성'}</span>
          </div>
          <h3 class="mt-3 text-lg font-bold text-slate-900">${escapeHtml(category.label || '새 카테고리')}</h3>
          <p class="mt-1 text-xs text-slate-500">key: ${escapeHtml(category.categoryKey || '-')}</p>
        </div>
        <div class="flex flex-wrap items-center gap-2">
          <button onclick="moveCatalogCategory(${categoryIndex}, -1)" class="rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-bold text-slate-500 transition hover:bg-slate-50 hover:text-slate-700" type="button">
            <i class="fas fa-arrow-up mr-1"></i> 위로
          </button>
          <button onclick="moveCatalogCategory(${categoryIndex}, 1)" class="rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-bold text-slate-500 transition hover:bg-slate-50 hover:text-slate-700" type="button">
            <i class="fas fa-arrow-down mr-1"></i> 아래로
          </button>
          <button onclick="deleteCatalogCategory(${categoryIndex})" class="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-xs font-bold text-rose-600 transition hover:bg-rose-100" type="button">
            <i class="fas fa-trash mr-1"></i> 삭제
          </button>
        </div>
      </div>

      <div class="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <label class="block">
          <span class="mb-1 block text-[11px] font-bold text-slate-500">key</span>
          <input
            value="${escapeHtml(category.categoryKey)}"
            oninput="updateCatalogCategoryField(${categoryIndex}, 'categoryKey', this.value)"
            type="text"
            class="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-700 outline-none transition focus:border-indigo-400 focus:ring-2 focus:ring-indigo-100"
            placeholder="예: dev"
          />
        </label>
        <label class="block">
          <span class="mb-1 block text-[11px] font-bold text-slate-500">라벨</span>
          <input
            value="${escapeHtml(category.label)}"
            oninput="updateCatalogCategoryField(${categoryIndex}, 'label', this.value)"
            type="text"
            class="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-700 outline-none transition focus:border-indigo-400 focus:ring-2 focus:ring-indigo-100"
            placeholder="예: 개발"
          />
        </label>
        <label class="block">
          <span class="mb-1 block text-[11px] font-bold text-slate-500">타이틀</span>
          <input
            value="${escapeHtml(category.title)}"
            oninput="updateCatalogCategoryField(${categoryIndex}, 'title', this.value)"
            type="text"
            class="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-700 outline-none transition focus:border-indigo-400 focus:ring-2 focus:ring-indigo-100"
            placeholder="예: 개발 강의"
          />
        </label>
        <label class="block">
          <span class="mb-1 block text-[11px] font-bold text-slate-500">아이콘 클래스</span>
          <input
            value="${escapeHtml(category.iconClass)}"
            oninput="updateCatalogCategoryField(${categoryIndex}, 'iconClass', this.value)"
            type="text"
            class="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-700 outline-none transition focus:border-indigo-400 focus:ring-2 focus:ring-indigo-100"
            placeholder="예: fas fa-laptop-code"
          />
        </label>
        <label class="flex items-center gap-3 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
          <input
            ${category.active ? 'checked' : ''}
            onchange="updateCatalogCategoryActive(${categoryIndex}, this.checked)"
            type="checkbox"
            class="h-4 w-4 accent-indigo-600"
          />
          <span class="text-sm font-medium text-slate-700">공개 메뉴에서 사용</span>
        </label>
      </div>

      <div class="mt-6 grid gap-5 xl:grid-cols-[360px_minmax(0,1fr)]">
        <div class="rounded-2xl border border-slate-200 bg-slate-50 p-4">
          <div class="mb-3 flex items-center justify-between">
            <h4 class="text-sm font-bold text-slate-800">메가메뉴 항목</h4>
            <button onclick="addCatalogMegaMenuItem(${categoryIndex})" class="rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[11px] font-bold text-slate-600 transition hover:bg-slate-50" type="button">
              <i class="fas fa-plus mr-1"></i> 항목 추가
            </button>
          </div>
          <div class="space-y-2">${megaMenuHtml}</div>
        </div>

        <div class="rounded-2xl border border-slate-200 bg-slate-50 p-4">
          <div class="mb-3 flex items-center justify-between">
            <h4 class="text-sm font-bold text-slate-800">필터 그룹</h4>
            <button onclick="addCatalogGroup(${categoryIndex})" class="rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[11px] font-bold text-slate-600 transition hover:bg-slate-50" type="button">
              <i class="fas fa-plus mr-1"></i> 그룹 추가
            </button>
          </div>
          <div class="space-y-4">${groupsHtml}</div>
        </div>
      </div>
    </section>
  `
}

function buildCatalogCategoryOptions(selectedValue: string | null) {
  const normalizedValue = selectedValue ?? ''

  return [
    `<option value="">직접 텍스트 필터</option>`,
    ...courseCatalogMenu.categories.map(
      (category) => `
        <option value="${escapeHtml(category.categoryKey)}" ${normalizedValue === category.categoryKey ? 'selected' : ''}>
          ${escapeHtml(category.label)} (${escapeHtml(category.categoryKey)})
        </option>`,
    ),
  ].join('')
}

function renderCatalogGroupCard(categoryIndex: number, group: CourseCatalogGroup, groupIndex: number) {
  const itemsHtml = group.items.length
    ? group.items.map((item, itemIndex) => renderCatalogGroupItemRow(categoryIndex, groupIndex, item, itemIndex)).join('')
    : `
      <div class="rounded-lg border border-dashed border-slate-200 bg-white px-4 py-5 text-center text-xs text-slate-400">
        등록된 필터 항목이 없습니다.
      </div>
    `

  return `
    <div class="rounded-xl border border-slate-200 bg-white p-4">
      <div class="flex flex-col gap-3 border-b border-slate-100 pb-4 lg:flex-row lg:items-center lg:justify-between">
        <div class="flex items-center gap-2">
          <span class="rounded-full bg-slate-100 px-2.5 py-1 text-[11px] font-bold text-slate-500">그룹 ${groupIndex + 1}</span>
          <input
            value="${escapeHtml(group.name)}"
            oninput="updateCatalogGroupField(${categoryIndex}, ${groupIndex}, 'name', this.value)"
            type="text"
            class="w-64 rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-700 outline-none transition focus:border-indigo-400 focus:ring-2 focus:ring-indigo-100"
            placeholder="예: 언어 (Language)"
          />
        </div>
        <div class="flex flex-wrap items-center gap-2">
          <button onclick="moveCatalogGroup(${categoryIndex}, ${groupIndex}, -1)" class="rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-bold text-slate-500 transition hover:bg-slate-50 hover:text-slate-700" type="button">
            <i class="fas fa-arrow-up mr-1"></i> 위로
          </button>
          <button onclick="moveCatalogGroup(${categoryIndex}, ${groupIndex}, 1)" class="rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-bold text-slate-500 transition hover:bg-slate-50 hover:text-slate-700" type="button">
            <i class="fas fa-arrow-down mr-1"></i> 아래로
          </button>
          <button onclick="addCatalogGroupItem(${categoryIndex}, ${groupIndex})" class="rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-bold text-slate-600 transition hover:bg-slate-50" type="button">
            <i class="fas fa-plus mr-1"></i> 항목 추가
          </button>
          <button onclick="removeCatalogGroup(${categoryIndex}, ${groupIndex})" class="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-xs font-bold text-rose-600 transition hover:bg-rose-100" type="button">
            <i class="fas fa-trash mr-1"></i> 그룹 삭제
          </button>
        </div>
      </div>

      <div class="mt-4 space-y-3">${itemsHtml}</div>
    </div>
  `
}

function renderCatalogGroupItemRow(
  categoryIndex: number,
  groupIndex: number,
  item: CourseCatalogGroupItem,
  itemIndex: number,
) {
  return `
    <div class="rounded-lg border border-slate-200 bg-slate-50 p-3">
      <div class="grid gap-3 xl:grid-cols-[minmax(0,1fr)_260px_auto]">
        <label class="block">
          <span class="mb-1 block text-[11px] font-bold text-slate-500">항목명</span>
          <input
            value="${escapeHtml(item.name)}"
            oninput="updateCatalogGroupItemField(${categoryIndex}, ${groupIndex}, ${itemIndex}, 'name', this.value)"
            type="text"
            class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700 outline-none transition focus:border-indigo-400 focus:ring-2 focus:ring-indigo-100"
            placeholder="예: Java"
          />
        </label>
        <label class="block">
          <span class="mb-1 block text-[11px] font-bold text-slate-500">연결 카테고리</span>
          <select
            onchange="updateCatalogGroupItemField(${categoryIndex}, ${groupIndex}, ${itemIndex}, 'linkedCategoryKey', this.value)"
            class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700 outline-none transition focus:border-indigo-400 focus:ring-2 focus:ring-indigo-100"
          >
            ${buildCatalogCategoryOptions(item.linkedCategoryKey)}
          </select>
        </label>
        <div class="flex items-end justify-end gap-1 text-slate-400">
          <button onclick="moveCatalogGroupItem(${categoryIndex}, ${groupIndex}, ${itemIndex}, -1)" class="rounded p-2 transition hover:bg-white hover:text-slate-700" type="button">
            <i class="fas fa-arrow-up text-xs"></i>
          </button>
          <button onclick="moveCatalogGroupItem(${categoryIndex}, ${groupIndex}, ${itemIndex}, 1)" class="rounded p-2 transition hover:bg-white hover:text-slate-700" type="button">
            <i class="fas fa-arrow-down text-xs"></i>
          </button>
          <button onclick="removeCatalogGroupItem(${categoryIndex}, ${groupIndex}, ${itemIndex})" class="rounded p-2 transition hover:bg-rose-50 hover:text-rose-600" type="button">
            <i class="fas fa-trash text-xs"></i>
          </button>
        </div>
      </div>
      <p class="mt-2 text-[11px] text-slate-400">
        연결 카테고리를 지정하면 상위 메뉴에서 해당 카테고리 필터로 바로 연결됩니다.
      </p>
    </div>
  `
}

async function fetchCourseCatalogMenu() {
  courseCatalogMenuLoading = true
  courseCatalogMenuError = null
  renderCourseCatalogMenuEditor()

  try {
    const response = await adminApi.getCourseCatalogMenu()
    courseCatalogMenu = reindexCourseCatalogMenu(response)
  } catch (error) {
    courseCatalogMenuError = error instanceof Error ? error.message : '강의 메뉴를 불러오지 못했습니다.'
  } finally {
    courseCatalogMenuLoading = false
    renderCourseCatalogMenuEditor()
  }
}

async function saveCourseCatalogMenu() {
  if (courseCatalogMenu.categories.length === 0) {
    window.alert('최소 한 개 이상의 카테고리가 필요합니다.')
    return
  }

  courseCatalogMenuSaving = true
  renderCourseCatalogMenuEditor()

  try {
    const savedMenu = await adminApi.updateCourseCatalogMenu(reindexCourseCatalogMenu(courseCatalogMenu))
    courseCatalogMenu = reindexCourseCatalogMenu(savedMenu)
    courseCatalogMenuError = null
    renderCourseCatalogMenuEditor()
    window.alert('강의 메뉴를 저장했습니다.')
  } catch (error) {
    courseCatalogMenuError = error instanceof Error ? error.message : '강의 메뉴를 저장하지 못했습니다.'
    renderCourseCatalogMenuEditor()
    window.alert(courseCatalogMenuError)
  } finally {
    courseCatalogMenuSaving = false
    renderCourseCatalogMenuEditor()
  }
}

async function refreshActiveTab() {
  switch (currentActiveTab) {
    case 'dashboard':
      await fetchOverview()
      break
    case 'tags':
      await fetchTags()
      break
    case 'roadmaps':
      await fetchNodes()
      break
    case 'catalog-menu':
      await fetchCourseCatalogMenu()
      break
    case 'users':
      await fetchAccounts()
      break
    case 'reports':
      await Promise.all([fetchPendingCourses(), fetchReports(), fetchOverview()])
      break
  }
}

function setActiveTab(nextTab: AdminTabKey) {
  currentActiveTab = nextTab

  document.querySelectorAll<HTMLElement>('.nav-btn').forEach((button) => {
    const isActive = button.dataset.target === nextTab
    const icon = button.querySelector('i')

    button.classList.toggle('bg-indigo-600', isActive)
    button.classList.toggle('text-white', isActive)
    button.classList.toggle('shadow-md', isActive)
    button.classList.toggle('shadow-indigo-900/40', isActive)
    button.classList.toggle('text-slate-400', !isActive)
    icon?.classList.toggle('opacity-80', isActive)
    icon?.classList.toggle('opacity-70', !isActive)
  })

  const pageMeta = TAB_META[nextTab]
  getElement('page-title').textContent = pageMeta.title
  getElement('page-desc').textContent = pageMeta.description

  document.querySelectorAll<HTMLElement>('.view-section').forEach((section) => {
    section.classList.toggle('block', section.id === `view-${nextTab}`)
    section.classList.toggle('hidden', section.id !== `view-${nextTab}`)
  })
}

function initNavigation() {
  document.querySelectorAll<HTMLButtonElement>('.nav-btn').forEach((button) => {
    button.addEventListener('click', () => {
      const target = button.dataset.target as AdminTabKey | undefined
      if (!target) {
        return
      }

      setActiveTab(target)
      void runAdminAction(async () => {
        await refreshActiveTab()
      })
    })
  })
}

// 필터 입력은 서버 재호출 없이 현재 내려받은 목록만 다시 그린다.
function initFilters() {
  const tagFilterInput = getElement<HTMLInputElement>('tagFilterInput')
  tagFilterInput.addEventListener('input', () => {
    filterState.tagQuery = tagFilterInput.value
    applyTagFilters()
  })

  const nodeFilterInput = getElement<HTMLInputElement>('nodeFilterInput')
  nodeFilterInput.addEventListener('input', () => {
    filterState.nodeQuery = nodeFilterInput.value
    applyNodeFilters()
  })

  const nodeTypeFilter = getElement<HTMLSelectElement>('nodeTypeFilter')
  nodeTypeFilter.addEventListener('change', () => {
    filterState.nodeType = nodeTypeFilter.value
    applyNodeFilters()
  })

  const accountFilterInput = getElement<HTMLInputElement>('accountFilterInput')
  accountFilterInput.addEventListener('input', () => {
    filterState.accountQuery = accountFilterInput.value
    applyAccountFilters()
  })

  const accountRoleFilter = getElement<HTMLSelectElement>('accountRoleFilter')
  accountRoleFilter.addEventListener('change', () => {
    filterState.accountRole = accountRoleFilter.value
    applyAccountFilters()
  })

  const accountStatusFilter = getElement<HTMLSelectElement>('accountStatusFilter')
  accountStatusFilter.addEventListener('change', () => {
    filterState.accountStatus = accountStatusFilter.value
    applyAccountFilters()
  })
}

async function runAdminAction(task: () => Promise<void>) {
  try {
    await task()
  } catch (error) {
    window.alert(error instanceof Error ? error.message : '처리 중 오류가 발생했습니다.')
  }
}

// HTML 인라인 버튼에서 호출하는 액션을 전역 함수로 연결한다.
function installGlobalActions() {
  window.refreshCurrentTab = () => {
    void runAdminAction(async () => {
      await refreshActiveTab()
    })
  }

  window.logout = async () => {
    await runAdminAction(async () => {
      const currentSession = readStoredAuthSession()
      try {
        if (currentSession?.refreshToken) {
          await authApi.logout(currentSession.refreshToken)
        }
      } finally {
        clearStoredAuthSession()
        window.location.replace('/home.html')
      }
    })
  }

  window.createTag = async () => {
    await runAdminAction(async () => {
      const name = window.prompt('등록할 태그명을 입력하세요.')
      if (!name?.trim()) {
        return
      }

      const description = window.prompt('태그 설명을 입력하세요. 선택 사항입니다.')?.trim() ?? ''
      await adminApi.createTag({ name: name.trim(), description: description || null })
      await fetchTags()
    })
  }

  window.mergeTag = async (tagId: number) => {
    await runAdminAction(async () => {
      const targetId = window.prompt('병합할 대상 태그 ID를 입력하세요.')
      if (!targetId?.trim()) {
        return
      }

      const parsedTargetId = Number(targetId)
      if (!Number.isFinite(parsedTargetId)) {
        window.alert('숫자 ID를 입력하세요.')
        return
      }

      await adminApi.mergeTags([tagId], parsedTargetId)
      await fetchTags()
    })
  }

  window.updateNodeTags = async (nodeId: number) => {
    await runAdminAction(async () => {
      const node = roadmapNodeMap.get(nodeId)
      const input = window.prompt('필수 태그명을 쉼표로 구분해서 입력하세요.', node?.requiredTags.join(', ') ?? '')
      if (input === null) {
        return
      }

      const requiredTags = input
        .split(',')
        .map((value) => value.trim())
        .filter(Boolean)

      if (requiredTags.length === 0) {
        window.alert('하나 이상의 태그를 입력하세요.')
        return
      }

      await adminApi.updateNodeRequiredTags(nodeId, requiredTags)
      await fetchNodes()
    })
  }

  window.updateNodeRules = async (nodeId: number) => {
    await runAdminAction(async () => {
      const node = roadmapNodeMap.get(nodeId)
      const description = window.prompt(
        '완료 기준 코드를 입력하세요. 예: QUIZ_PASS',
        node?.completionRuleDescription ?? 'QUIZ_PASS',
      )
      if (!description?.trim()) {
        return
      }

      const progressInput = window.prompt(
        '필수 진행률을 0부터 100 사이 숫자로 입력하세요.',
        String(node?.requiredProgressRate ?? 100),
      )
      if (progressInput === null || progressInput.trim() === '') {
        return
      }

      const requiredProgressRate = Number(progressInput)
      if (!Number.isFinite(requiredProgressRate)) {
        window.alert('숫자 진행률을 입력하세요.')
        return
      }

      await adminApi.updateNodeCompletionRule(nodeId, description.trim(), requiredProgressRate)
      await fetchNodes()
    })
  }

  window.toggleAccountStatus = async (userId: number, accountStatus: string) => {
    await runAdminAction(async () => {
      const reason = window.prompt(`${accountStatus === 'ACTIVE' ? '제한' : '복구'} 사유를 입력하세요.`)
      if (!reason?.trim()) {
        return
      }

      if (accountStatus === 'ACTIVE') {
        await adminApi.restrictAccount(userId, reason.trim())
      } else {
        await adminApi.restoreAccount(userId, reason.trim())
      }

      await Promise.all([fetchAccounts(), fetchOverview()])
    })
  }

  window.approveCourse = async (courseId: number) => {
    await runAdminAction(async () => {
      if (!window.confirm('이 강의를 승인하시겠습니까?')) {
        return
      }

      await adminApi.approveCourse(courseId, '관리자 승인')
      await Promise.all([fetchPendingCourses(), fetchOverview()])
    })
  }

  window.rejectCourse = async (courseId: number) => {
    await runAdminAction(async () => {
      const reason = window.prompt('반려 사유를 입력하세요.')
      if (!reason?.trim()) {
        return
      }

      await adminApi.rejectCourse(courseId, reason.trim())
      await Promise.all([fetchPendingCourses(), fetchOverview()])
    })
  }

  window.blindContent = async (reportId: number) => {
    await runAdminAction(async () => {
      const report = reportMap.get(reportId)
      if (!report?.contentId) {
        window.alert('블라인드 처리할 콘텐츠가 없습니다.')
        return
      }

      const reason = window.prompt('블라인드 사유를 입력하세요.', report.reason)
      if (!reason?.trim()) {
        return
      }

      await adminApi.blindContent(report.contentId, reason.trim())
      await Promise.all([fetchReports(), fetchOverview()])
    })
  }

  window.resolveReport = async (reportId: number) => {
    await runAdminAction(async () => {
      const reason = window.prompt('처리 메모를 입력하세요.', '문제 없음')
      if (!reason?.trim()) {
        return
      }

      await adminApi.resolveReport(reportId, reason.trim(), 'DISMISS')
      await Promise.all([fetchReports(), fetchOverview()])
    })
  }

  window.createCatalogCategory = () => {
    updateCatalogMenu((menu) => {
      menu.categories.push(createEmptyCatalogCategory(menu.categories.length))
    })
  }

  window.saveCourseCatalogMenu = async () => {
    await saveCourseCatalogMenu()
  }

  window.moveCatalogCategory = (categoryIndex: number, direction: number) => {
    updateCatalogMenu((menu) => {
      moveArrayItem(menu.categories, categoryIndex, direction)
    })
  }

  window.deleteCatalogCategory = (categoryIndex: number) => {
    if (!window.confirm('이 카테고리를 삭제하시겠습니까?')) {
      return
    }

    updateCatalogMenu((menu) => {
      menu.categories.splice(categoryIndex, 1)
    })
  }

  window.updateCatalogCategoryField = (categoryIndex: number, field: string, value: string) => {
    updateCatalogMenu((menu) => {
      const category = menu.categories[categoryIndex]
      if (!category) {
        return
      }

      switch (field) {
        case 'categoryKey':
          category.categoryKey = value.trim()
          break
        case 'label':
          category.label = value
          break
        case 'title':
          category.title = value
          break
        case 'iconClass':
          category.iconClass = value
          break
      }
    })
  }

  window.updateCatalogCategoryActive = (categoryIndex: number, checked: boolean) => {
    updateCatalogMenu((menu) => {
      const category = menu.categories[categoryIndex]
      if (category) {
        category.active = checked
      }
    })
  }

  window.addCatalogMegaMenuItem = (categoryIndex: number) => {
    updateCatalogMenu((menu) => {
      menu.categories[categoryIndex]?.megaMenuItems.push(createEmptyCatalogMegaMenuItem())
    })
  }

  window.updateCatalogMegaMenuItemLabel = (categoryIndex: number, itemIndex: number, value: string) => {
    updateCatalogMenu((menu) => {
      const item = menu.categories[categoryIndex]?.megaMenuItems[itemIndex]
      if (item) {
        item.label = value
      }
    })
  }

  window.moveCatalogMegaMenuItem = (categoryIndex: number, itemIndex: number, direction: number) => {
    updateCatalogMenu((menu) => {
      const items = menu.categories[categoryIndex]?.megaMenuItems
      if (items) {
        moveArrayItem(items, itemIndex, direction)
      }
    })
  }

  window.removeCatalogMegaMenuItem = (categoryIndex: number, itemIndex: number) => {
    updateCatalogMenu((menu) => {
      menu.categories[categoryIndex]?.megaMenuItems.splice(itemIndex, 1)
    })
  }

  window.addCatalogGroup = (categoryIndex: number) => {
    updateCatalogMenu((menu) => {
      menu.categories[categoryIndex]?.groups.push(createEmptyCatalogGroup())
    })
  }

  window.updateCatalogGroupField = (categoryIndex: number, groupIndex: number, field: string, value: string) => {
    updateCatalogMenu((menu) => {
      const group = menu.categories[categoryIndex]?.groups[groupIndex]
      if (!group) {
        return
      }

      if (field === 'name') {
        group.name = value
      }
    })
  }

  window.moveCatalogGroup = (categoryIndex: number, groupIndex: number, direction: number) => {
    updateCatalogMenu((menu) => {
      const groups = menu.categories[categoryIndex]?.groups
      if (groups) {
        moveArrayItem(groups, groupIndex, direction)
      }
    })
  }

  window.removeCatalogGroup = (categoryIndex: number, groupIndex: number) => {
    if (!window.confirm('이 그룹을 삭제하시겠습니까?')) {
      return
    }

    updateCatalogMenu((menu) => {
      menu.categories[categoryIndex]?.groups.splice(groupIndex, 1)
    })
  }

  window.addCatalogGroupItem = (categoryIndex: number, groupIndex: number) => {
    updateCatalogMenu((menu) => {
      menu.categories[categoryIndex]?.groups[groupIndex]?.items.push(createEmptyCatalogGroupItem())
    })
  }

  window.updateCatalogGroupItemField = (
    categoryIndex: number,
    groupIndex: number,
    itemIndex: number,
    field: string,
    value: string,
  ) => {
    updateCatalogMenu((menu) => {
      const item = menu.categories[categoryIndex]?.groups[groupIndex]?.items[itemIndex]
      if (!item) {
        return
      }

      if (field === 'name') {
        item.name = value
      }

      if (field === 'linkedCategoryKey') {
        item.linkedCategoryKey = value.trim() ? value.trim() : null
      }
    })
  }

  window.moveCatalogGroupItem = (categoryIndex: number, groupIndex: number, itemIndex: number, direction: number) => {
    updateCatalogMenu((menu) => {
      const items = menu.categories[categoryIndex]?.groups[groupIndex]?.items
      if (items) {
        moveArrayItem(items, itemIndex, direction)
      }
    })
  }

  window.removeCatalogGroupItem = (categoryIndex: number, groupIndex: number, itemIndex: number) => {
    updateCatalogMenu((menu) => {
      menu.categories[categoryIndex]?.groups[groupIndex]?.items.splice(itemIndex, 1)
    })
  }
}

async function bootstrap() {
  const session = readStoredAuthSession()
  if (!session) {
    window.location.replace('/home.html?auth=login')
    return
  }

  if (session.role !== 'ROLE_ADMIN') {
    window.location.replace('/home.html')
    return
  }

  installGlobalActions()
  initNavigation()
  initFilters()
  setActiveTab('dashboard')
  await refreshActiveTab()
}

document.addEventListener('DOMContentLoaded', () => {
  void runAdminAction(async () => {
    await bootstrap()
  })
})
