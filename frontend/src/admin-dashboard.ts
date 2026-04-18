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
import './index.css'

Chart.register(...registerables)

// 관리자 화면에서 사용하는 탭 키를 고정한다.
type AdminTabKey = 'dashboard' | 'tags' | 'roadmaps' | 'users' | 'reports'

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
  }
}

const TAB_META: Record<AdminTabKey, { title: string; description: string }> = {
  dashboard: { title: '플랫폼 실시간 현황', description: 'DevPath 관리자 운영 지표 요약' },
  tags: { title: '기술 태그 데이터베이스', description: '공식 태그를 조회하고 병합한다.' },
  roadmaps: { title: '마스터 로드맵 노드', description: '노드 필수 태그와 완료 기준을 관리한다.' },
  users: { title: '회원 통합 관리', description: '회원 상태와 권한을 운영 관점에서 관리한다.' },
  reports: { title: '검수 및 신고', description: '강의 검수와 사용자 신고를 처리한다.' },
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
      return nodeType || '미지정'
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

function buildErrorRow(colspan: number, message = '데이터를 불러오지 못했다.') {
  return `<tr><td colspan="${colspan}" class="py-10 text-center text-xs text-rose-500">${escapeHtml(message)}</td></tr>`
}

// 필터 적용 결과를 섹션 우측 보조 문구로 보여준다.
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

// 차트는 새 데이터를 받을 때마다 인스턴스를 정리하고 다시 만든다.
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
    tbody.innerHTML = buildErrorRow(5, error instanceof Error ? error.message : '태그를 불러오지 못했다.')
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
    tbody.innerHTML = buildErrorRow(5, error instanceof Error ? error.message : '노드를 불러오지 못했다.')
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
    tbody.innerHTML = buildErrorRow(6, error instanceof Error ? error.message : '계정을 불러오지 못했다.')
    updateFilterSummary('accountFilterSummary', 0, 0)
  }
}

async function fetchPendingCourses() {
  const tbody = getElement('courseTableBody')
  tbody.innerHTML = buildLoadingRow(3, '강의 검수 목록을 불러오는 중이다...')

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
    tbody.innerHTML = buildErrorRow(3, error instanceof Error ? error.message : '강의 검수 목록을 불러오지 못했다.')
  }
}

async function fetchReports() {
  const tbody = getElement('reportTableBody')
  tbody.innerHTML = buildLoadingRow(3, '신고 목록을 불러오는 중이다...')

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
    tbody.innerHTML = buildErrorRow(3, error instanceof Error ? error.message : '신고 목록을 불러오지 못했다.')
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
      void refreshActiveTab()
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

// HTML 버튼에서 호출하는 액션을 전역 함수로 노출한다.
function installGlobalActions() {
  window.refreshCurrentTab = () => {
    void refreshActiveTab()
  }

  window.logout = async () => {
    const currentSession = readStoredAuthSession()
    try {
      if (currentSession?.refreshToken) {
        await authApi.logout(currentSession.refreshToken)
      }
    } catch {
      // 로그아웃 API 실패와 무관하게 브라우저 세션은 비운다.
    } finally {
      clearStoredAuthSession()
      window.location.replace('/home.html')
    }
  }

  window.createTag = async () => {
    const name = window.prompt('등록할 태그명을 입력하세요.')
    if (!name?.trim()) {
      return
    }

    const description = window.prompt('태그 설명을 입력하세요. (선택)')?.trim() ?? ''
    await adminApi.createTag({ name: name.trim(), description: description || null })
    await fetchTags()
  }

  window.mergeTag = async (tagId: number) => {
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
  }

  window.updateNodeTags = async (nodeId: number) => {
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
  }

  window.updateNodeRules = async (nodeId: number) => {
    const node = roadmapNodeMap.get(nodeId)
    const description = window.prompt(
      '완료 기준 코드를 입력하세요. 예: QUIZ_PASS',
      node?.completionRuleDescription ?? 'QUIZ_PASS',
    )
    if (!description?.trim()) {
      return
    }

    const progressInput = window.prompt(
      '필수 진행률을 0-100 사이로 입력하세요.',
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
  }

  window.toggleAccountStatus = async (userId: number, accountStatus: string) => {
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
  }

  window.approveCourse = async (courseId: number) => {
    if (!window.confirm('이 강의를 승인할까?')) {
      return
    }

    await adminApi.approveCourse(courseId, '관리자 승인')
    await Promise.all([fetchPendingCourses(), fetchOverview()])
  }

  window.rejectCourse = async (courseId: number) => {
    const reason = window.prompt('반려 사유를 입력하세요.')
    if (!reason?.trim()) {
      return
    }

    await adminApi.rejectCourse(courseId, reason.trim())
    await Promise.all([fetchPendingCourses(), fetchOverview()])
  }

  window.blindContent = async (reportId: number) => {
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
  }

  window.resolveReport = async (reportId: number) => {
    const reason = window.prompt('처리 메모를 입력하세요.', '문제 없음')
    if (!reason?.trim()) {
      return
    }

    await adminApi.resolveReport(reportId, reason.trim(), 'DISMISS')
    await Promise.all([fetchReports(), fetchOverview()])
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
  await fetchOverview()
}

document.addEventListener('DOMContentLoaded', () => {
  void bootstrap()
})
