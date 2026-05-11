import { useEffect, useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import AccountUserMenu from './components/AccountUserMenu'
import { authApi } from './lib/api'
import { clearStoredAuthSession, readStoredAuthSession } from './lib/auth-session'

type ApiEnvelope<T> = {
  success: boolean
  message?: string
  data: T
}

type UserProfileResponse = {
  name?: string | null
  nickname?: string | null
  profileImage?: string | null
  jobTitle?: string | null
  position?: string | null
}

type WorkspaceResponse = {
  workspaceId: number
  name: string
  type?: string | null
  status?: string | null
  memberCount?: number | null
}

type ProjectMemberResponse = {
  memberId: number
  learnerId: number
  roleType: string
  joinedAt?: string | null
}

type ProjectResponse = {
  projectId: number
  ownerId?: number | null
  name: string
  description?: string | null
  intro?: string | null
  projectType?: string | null
  status?: string | null
  visibility?: string | null
  recruitingStatus?: string | null
  createdAt?: string | null
  updatedAt?: string | null
  members?: ProjectMemberResponse[] | null
}

type IdeaPostResponse = {
  id: number
  authorId: number
  title: string
  content: string
  createdAt?: string | null
  updatedAt?: string | null
}

type StudyGroupResponse = {
  id: number
  name: string
  description?: string | null
  status?: string | null
  maxMembers?: number | null
  createdAt?: string | null
}

type LoungeApplicationSummary = {
  applicationId: number
  type: 'SQUAD_APPLICATION' | 'SQUAD_PROPOSAL'
  targetId: number
  targetTitle: string
  senderId: number
  senderName: string
  receiverId: number
  receiverName: string
  title: string
  status: 'PENDING' | 'APPROVED' | 'REJECTED'
  createdAt?: string | null
}

type LoungeMessage = {
  messageId: number
  loungeId: number
  senderId: number
  senderName: string
  isMine?: boolean | null
  content: string
  createdAt?: string | null
}

type CardKind = 'PROJECT' | 'WISH' | 'STUDY'
type TabKey = 'ALL' | CardKind | 'MINE'
type SortKey = 'LATEST' | 'TITLE' | 'OPEN'
type CreateKind = 'PROJECT' | 'IDEA' | 'STUDY'

type LoungeCard = {
  id: number
  kind: CardKind
  title: string
  description: string
  ownerId?: number | null
  status?: string | null
  createdAt?: string | null
  updatedAt?: string | null
  maxMembers?: number | null
  members?: ProjectMemberResponse[] | null
  sourceLabel: string
  accentClassName: string
  iconClassName: string
  canApply: boolean
}

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, '') ?? ''
const PROJECT_LOUNGE_ID = Number(import.meta.env.VITE_PROJECT_LOUNGE_ID ?? 1)
const PAGE_SIZE = 6

const headerLinks = [
  { href: 'roadmap-hub.html', label: '로드맵' },
  { href: 'lecture-list.html', label: '강의' },
  { href: 'lounge-dashboard.html', label: '프로젝트' },
  { href: 'job-matching.html', label: '채용분석' },
  { href: 'community-list.html', label: '커뮤니티' },
]

const tabs: Array<{ key: TabKey; label: string }> = [
  { key: 'ALL', label: '전체' },
  { key: 'PROJECT', label: '프로젝트' },
  { key: 'WISH', label: '참여 희망' },
  { key: 'STUDY', label: '스터디' },
  { key: 'MINE', label: '내가 쓴 글' },
]

const sortOptions: Array<{ key: SortKey; label: string }> = [
  { key: 'LATEST', label: '최신순' },
  { key: 'OPEN', label: '모집중 우선' },
  { key: 'TITLE', label: '이름순' },
]

const applicationStatusLabel: Record<LoungeApplicationSummary['status'], string> = {
  PENDING: '대기중',
  APPROVED: '승인됨',
  REJECTED: '거절됨',
}

function isFulfilled<T>(result: PromiseSettledResult<T>): result is PromiseFulfilledResult<T> {
  return result.status === 'fulfilled'
}

function goTo(path: string) {
  window.location.href = path
}

function getErrorMessage(error: unknown) {
  return error instanceof Error ? error.message : '요청을 처리하지 못했습니다.'
}

function getAuthHeader() {
  const session = readStoredAuthSession()

  if (!session?.accessToken) {
    throw new Error('로그인이 필요합니다.')
  }

  return `${session.tokenType} ${session.accessToken}`
}

async function apiRequest<T>(path: string, init: RequestInit = {}, auth = false): Promise<T> {
  const headers = new Headers(init.headers)
  headers.set('Accept', 'application/json')

  if (init.body && !headers.has('Content-Type') && !(init.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json')
  }

  if (auth) {
    headers.set('Authorization', getAuthHeader())
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers,
  })
  const payload = (await response.json().catch(() => null)) as ApiEnvelope<T> | null

  if (!response.ok || !payload?.success) {
    throw new Error(payload?.message ?? `Request failed with status ${response.status}`)
  }

  return payload.data
}

function normalize(value: string) {
  return value.trim().toLowerCase()
}

function formatDate(value?: string | null) {
  if (!value) {
    return '날짜 없음'
  }

  const date = new Date(value)

  if (Number.isNaN(date.getTime())) {
    return '날짜 없음'
  }

  return new Intl.DateTimeFormat('ko-KR', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date)
}

function getRelativeTime(value?: string | null) {
  if (!value) {
    return '방금 전'
  }

  const date = new Date(value)
  const diffMinutes = Math.max(0, Math.floor((Date.now() - date.getTime()) / 60000))

  if (Number.isNaN(date.getTime()) || diffMinutes < 1) {
    return '방금 전'
  }
  if (diffMinutes < 60) {
    return `${diffMinutes}분 전`
  }
  if (diffMinutes < 1440) {
    return `${Math.floor(diffMinutes / 60)}시간 전`
  }
  return `${Math.floor(diffMinutes / 1440)}일 전`
}

function mapProject(project: ProjectResponse): LoungeCard {
  const isOpen = project.recruitingStatus === 'OPEN'

  return {
    id: project.projectId,
    kind: 'PROJECT',
    title: project.name,
    description: project.intro?.trim() || project.description?.trim() || '프로젝트 소개가 아직 등록되지 않았습니다.',
    ownerId: project.ownerId,
    status: project.recruitingStatus ?? project.status ?? null,
    createdAt: project.createdAt,
    updatedAt: project.updatedAt,
    members: project.members ?? null,
    sourceLabel: project.projectType === 'SOLO' ? '솔로 프로젝트' : '프로젝트 모집',
    accentClassName: isOpen ? 'bg-brand' : 'bg-gray-400',
    iconClassName: 'fas fa-rocket text-brand',
    canApply: isOpen,
  }
}

function mapIdeaPost(post: IdeaPostResponse): LoungeCard {
  return {
    id: post.id,
    kind: 'WISH',
    title: post.title,
    description: post.content,
    ownerId: post.authorId,
    status: 'PUBLISHED',
    createdAt: post.createdAt,
    updatedAt: post.updatedAt,
    sourceLabel: '참여 희망',
    accentClassName: 'bg-blue-500',
    iconClassName: 'fas fa-lightbulb text-blue-500',
    canApply: true,
  }
}

function mapStudyGroup(group: StudyGroupResponse): LoungeCard {
  const isOpen = group.status === 'RECRUITING'

  return {
    id: group.id,
    kind: 'STUDY',
    title: group.name,
    description: group.description?.trim() || '스터디 소개가 아직 등록되지 않았습니다.',
    status: group.status ?? null,
    createdAt: group.createdAt,
    maxMembers: group.maxMembers ?? null,
    sourceLabel: '스터디',
    accentClassName: isOpen ? 'bg-purple-500' : 'bg-gray-400',
    iconClassName: 'fas fa-book-open text-purple-500',
    canApply: isOpen,
  }
}

function getStatusText(card: LoungeCard) {
  if (card.kind === 'WISH') {
    return '제안 가능'
  }

  switch (card.status) {
    case 'OPEN':
    case 'RECRUITING':
      return '모집중'
    case 'CLOSED':
      return '마감'
    case 'COMPLETED':
      return '완료'
    case 'CANCELLED':
      return '취소'
    default:
      return card.status ?? '상태 없음'
  }
}

function getStatusClassName(card: LoungeCard) {
  if (card.canApply) {
    return 'bg-green-50 text-brand border-green-100'
  }

  return 'bg-gray-100 text-gray-500 border-gray-200'
}

function getApplicationBadgeClassName(status: LoungeApplicationSummary['status']) {
  switch (status) {
    case 'APPROVED':
      return 'bg-green-50 text-brand'
    case 'REJECTED':
      return 'bg-red-50 text-red-500'
    default:
      return 'bg-yellow-50 text-yellow-600'
  }
}

function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex min-h-[280px] flex-col items-center justify-center rounded-2xl border-2 border-dashed border-gray-200 bg-white p-8 text-center">
      <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-gray-100 text-xl text-gray-400">
        <i className="fas fa-inbox" />
      </div>
      <p className="text-sm font-bold text-gray-800">{message}</p>
      <p className="mt-1 text-xs text-gray-400">새 모집글이 등록되면 이곳에 바로 표시됩니다.</p>
    </div>
  )
}

function CommunityLoungeApp() {
  const [session, setSession] = useState(() => readStoredAuthSession())
  const [profile, setProfile] = useState<UserProfileResponse | null>(null)
  const [workspaces, setWorkspaces] = useState<WorkspaceResponse[]>([])
  const [projects, setProjects] = useState<ProjectResponse[]>([])
  const [ideas, setIdeas] = useState<IdeaPostResponse[]>([])
  const [studyGroups, setStudyGroups] = useState<StudyGroupResponse[]>([])
  const [sentApplications, setSentApplications] = useState<LoungeApplicationSummary[]>([])
  const [receivedApplications, setReceivedApplications] = useState<LoungeApplicationSummary[]>([])
  const [messages, setMessages] = useState<LoungeMessage[]>([])
  const [loading, setLoading] = useState(true)
  const [notice, setNotice] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<TabKey>('ALL')
  const [sortKey, setSortKey] = useState<SortKey>('LATEST')
  const [keyword, setKeyword] = useState('')
  const [page, setPage] = useState(1)
  const [selectedCard, setSelectedCard] = useState<LoungeCard | null>(null)
  const [applyCard, setApplyCard] = useState<LoungeCard | null>(null)
  const [applicationTitle, setApplicationTitle] = useState('')
  const [applicationContent, setApplicationContent] = useState('')
  const [createOpen, setCreateOpen] = useState(false)
  const [createKind, setCreateKind] = useState<CreateKind>('PROJECT')
  const [createTitle, setCreateTitle] = useState('')
  const [createDescription, setCreateDescription] = useState('')
  const [createMaxMembers, setCreateMaxMembers] = useState(4)
  const [statusOpen, setStatusOpen] = useState(false)
  const [messagePopupOpen, setMessagePopupOpen] = useState(false)
  const [notiPopupOpen, setNotiPopupOpen] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [chatInput, setChatInput] = useState('')

  const currentUserId = session?.userId ?? null
  const userName = profile?.name?.trim() || profile?.nickname?.trim() || session?.name || '사용자'
  const profileImage = profile?.profileImage ?? null
  const pendingReceivedCount = receivedApplications.filter((application) => application.status === 'PENDING').length

  const cards = useMemo<LoungeCard[]>(() => {
    return [
      ...projects.map(mapProject),
      ...ideas.map(mapIdeaPost),
      ...studyGroups.map(mapStudyGroup),
    ]
  }, [ideas, projects, studyGroups])

  const filteredCards = useMemo(() => {
    const normalizedKeyword = normalize(keyword)
    const result = cards.filter((card) => {
      const matchesTab =
        activeTab === 'ALL'
        || (activeTab === 'MINE' && currentUserId !== null && card.ownerId === currentUserId)
        || card.kind === activeTab
      const matchesKeyword =
        !normalizedKeyword
        || normalize(card.title).includes(normalizedKeyword)
        || normalize(card.description).includes(normalizedKeyword)
        || normalize(card.sourceLabel).includes(normalizedKeyword)

      return matchesTab && matchesKeyword
    })

    return [...result].sort((left, right) => {
      if (sortKey === 'TITLE') {
        return left.title.localeCompare(right.title, 'ko-KR')
      }
      if (sortKey === 'OPEN') {
        return Number(right.canApply) - Number(left.canApply)
      }

      const rightTime = new Date(right.createdAt ?? right.updatedAt ?? 0).getTime()
      const leftTime = new Date(left.createdAt ?? left.updatedAt ?? 0).getTime()
      return rightTime - leftTime
    })
  }, [activeTab, cards, currentUserId, keyword, sortKey])

  const totalPages = Math.max(1, Math.ceil(filteredCards.length / PAGE_SIZE))
  const visibleCards = filteredCards.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

  async function loadData(signal?: AbortSignal) {
    setLoading(true)
    setNotice(null)

    const currentSession = readStoredAuthSession()
    const useAuthForLists = Boolean(currentSession?.accessToken)
    const publicResults = await Promise.allSettled([
      apiRequest<ProjectResponse[]>('/api/projects', { method: 'GET', signal }, useAuthForLists),
      apiRequest<IdeaPostResponse[]>('/api/project-ideas', { method: 'GET', signal }, useAuthForLists),
      apiRequest<StudyGroupResponse[]>('/api/study-groups', { method: 'GET', signal }, useAuthForLists),
    ])

    const [projectResult, ideaResult, studyResult] = publicResults

    if (isFulfilled(projectResult) && Array.isArray(projectResult.value)) {
      setProjects(projectResult.value)
    }
    if (isFulfilled(ideaResult) && Array.isArray(ideaResult.value)) {
      setIdeas(ideaResult.value)
    }
    if (isFulfilled(studyResult) && Array.isArray(studyResult.value)) {
      setStudyGroups(studyResult.value)
    }

    if (!currentSession?.accessToken) {
      setProfile(null)
      setWorkspaces([])
      setSentApplications([])
      setReceivedApplications([])
      setMessages([])
      setLoading(false)
      return
    }

    const authResults = await Promise.allSettled([
      apiRequest<UserProfileResponse>('/api/users/me/profile', { method: 'GET', signal }, true),
      apiRequest<WorkspaceResponse[]>('/api/workspaces/projects/me', { method: 'GET', signal }, true),
      apiRequest<LoungeApplicationSummary[]>('/api/lounge/applications/sent', { method: 'GET', signal }, true),
      apiRequest<LoungeApplicationSummary[]>('/api/lounge/applications/received', { method: 'GET', signal }, true),
      apiRequest<LoungeMessage[]>(
        `/api/lounge/chats/messages?loungeId=${PROJECT_LOUNGE_ID}&sort=OLDEST`,
        { method: 'GET', signal },
        true,
      ),
    ])

    const [profileResult, workspaceResult, sentResult, receivedResult, messageResult] = authResults

    if (isFulfilled(profileResult)) {
      setProfile(profileResult.value)
    }
    if (isFulfilled(workspaceResult) && Array.isArray(workspaceResult.value)) {
      setWorkspaces(workspaceResult.value)
    }
    if (isFulfilled(sentResult) && Array.isArray(sentResult.value)) {
      setSentApplications(sentResult.value)
    }
    if (isFulfilled(receivedResult) && Array.isArray(receivedResult.value)) {
      setReceivedApplications(receivedResult.value)
    }
    if (isFulfilled(messageResult) && Array.isArray(messageResult.value)) {
      setMessages(messageResult.value)
    }

    setLoading(false)
  }

  useEffect(() => {
    document.title = 'DevPath - 프로젝트 라운지'
  }, [])

  useEffect(() => {
    const controller = new AbortController()

    void loadData(controller.signal).catch((error) => {
      if (!controller.signal.aborted) {
        setNotice(getErrorMessage(error))
        setLoading(false)
      }
    })

    return () => {
      controller.abort()
    }
  }, [])

  useEffect(() => {
    setPage(1)
  }, [activeTab, keyword, sortKey])

  useEffect(() => {
    if (page > totalPages) {
      setPage(totalPages)
    }
  }, [page, totalPages])

  async function handleLogout() {
    const currentSession = readStoredAuthSession()

    try {
      if (currentSession?.refreshToken) {
        await authApi.logout(currentSession.refreshToken)
      }
    } catch {
      // 서버 로그아웃 실패와 관계없이 브라우저 세션은 정리한다.
    } finally {
      clearStoredAuthSession()
      setSession(null)
      setProfile(null)
    }
  }

  async function refreshAfterMutation(message: string) {
    setNotice(message)
    await loadData()
  }

  function openApplyModal(card: LoungeCard) {
    if (!session?.accessToken) {
      goTo('login.html')
      return
    }

    setApplyCard(card)
    setApplicationTitle(`${card.title} ${card.kind === 'WISH' ? '협업 제안' : '참여 신청'}`)
    setApplicationContent('')
  }

  async function handleApplySubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()

    if (!applyCard) {
      return
    }

    setSubmitting(true)

    try {
      if (applyCard.kind === 'STUDY') {
        await apiRequest(`/api/study-groups/${applyCard.id}/applications`, { method: 'POST' }, true)
      } else {
        if (!applyCard.ownerId) {
          throw new Error('신청을 받을 사용자를 확인할 수 없습니다.')
        }

        await apiRequest('/api/lounge/applications', {
          method: 'POST',
          body: JSON.stringify({
            receiverId: applyCard.ownerId,
            type: applyCard.kind === 'WISH' ? 'SQUAD_PROPOSAL' : 'SQUAD_APPLICATION',
            targetId: applyCard.id,
            targetTitle: applyCard.title,
            title: applicationTitle,
            content: applicationContent,
          }),
        }, true)
      }

      setApplyCard(null)
      await refreshAfterMutation('신청이 접수되었습니다.')
    } catch (error) {
      setNotice(getErrorMessage(error))
    } finally {
      setSubmitting(false)
    }
  }

  async function handleCreateSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setSubmitting(true)

    try {
      if (createKind === 'PROJECT') {
        const project = await apiRequest<ProjectResponse>('/api/projects', {
          method: 'POST',
          body: JSON.stringify({
            name: createTitle,
            description: createDescription,
          }),
        }, true)

        await Promise.allSettled([
          apiRequest(`/api/projects/${project.projectId}/visibility`, {
            method: 'PATCH',
            body: JSON.stringify({ visibility: 'PUBLIC' }),
          }, true),
          apiRequest(`/api/projects/${project.projectId}/recruiting-status`, {
            method: 'PATCH',
            body: JSON.stringify({ recruitingStatus: 'OPEN' }),
          }, true),
        ])
      }

      if (createKind === 'IDEA') {
        await apiRequest('/api/project-ideas', {
          method: 'POST',
          body: JSON.stringify({
            title: createTitle,
            content: createDescription,
          }),
        }, true)
      }

      if (createKind === 'STUDY') {
        await apiRequest('/api/study-groups', {
          method: 'POST',
          body: JSON.stringify({
            name: createTitle,
            description: createDescription,
            maxMembers: createMaxMembers,
          }),
        }, true)
      }

      setCreateOpen(false)
      setCreateTitle('')
      setCreateDescription('')
      await refreshAfterMutation('게시글이 등록되었습니다.')
    } catch (error) {
      setNotice(getErrorMessage(error))
    } finally {
      setSubmitting(false)
    }
  }

  async function handleApplicationAction(applicationId: number, action: 'approve' | 'reject') {
    setSubmitting(true)

    try {
      await apiRequest(`/api/lounge/applications/${applicationId}/${action}`, {
        method: 'PATCH',
        body: action === 'reject' ? JSON.stringify({ rejectReason: '요청이 거절되었습니다.' }) : JSON.stringify({}),
      }, true)
      await refreshAfterMutation(action === 'approve' ? '신청을 승인했습니다.' : '신청을 거절했습니다.')
    } catch (error) {
      setNotice(getErrorMessage(error))
    } finally {
      setSubmitting(false)
    }
  }

  async function handleChatSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()

    const content = chatInput.trim()

    if (!content) {
      return
    }

    try {
      const message = await apiRequest<LoungeMessage>('/api/lounge/chats/messages', {
        method: 'POST',
        body: JSON.stringify({
          loungeId: PROJECT_LOUNGE_ID,
          content,
        }),
      }, true)
      setMessages((current) => [...current, message])
      setChatInput('')
    } catch (error) {
      setNotice(getErrorMessage(error))
    }
  }

  return (
    <div className="flex h-screen overflow-hidden text-gray-800">
      <aside className="group z-50 flex w-20 shrink-0 flex-col border-r border-gray-200 bg-white shadow-xl transition-all duration-300 ease-in-out hover:w-64">
        <div className="flex h-20 shrink-0 cursor-pointer items-center border-b border-gray-100 px-5 transition hover:bg-gray-50" onClick={() => goTo('home.html')}>
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-gray-900 text-xl text-brand shadow-md">
            <i className="fas fa-layer-group" />
          </div>
          <div className="sidebar-text flex flex-col">
            <p className="text-lg font-bold tracking-tight text-gray-900">DevSquad</p>
            <p className="text-[10px] text-gray-400">Team Building</p>
          </div>
        </div>

        <nav className="mt-4 flex-1 space-y-2 overflow-y-auto overflow-x-hidden px-3">
          <p className="sidebar-section-title px-4 text-xs font-bold text-gray-400">MENU</p>
          <a href="lounge-dashboard.html" className="nav-item">
            <i className="fas fa-home w-6 text-center text-lg" />
            <span className="sidebar-text">대시보드</span>
          </a>
          <a href="community-lounge.html" className="nav-item active">
            <i className="fas fa-rocket w-6 text-center text-lg" />
            <span className="sidebar-text">라운지 (팀 찾기)</span>
          </a>
          <a href="mentoring-hub.html" className="nav-item">
            <i className="fas fa-chalkboard-teacher w-6 text-center text-lg" />
            <span className="sidebar-text">멘토링 찾기</span>
          </a>
          <a href="workspace-hub.html" className="nav-item">
            <i className="fas fa-laptop-code w-6 text-center text-lg" />
            <span className="sidebar-text">워크스페이스</span>
          </a>
          <a href="dev-showcase.html" className="nav-item">
            <i className="fas fa-trophy w-6 text-center text-lg" />
            <span className="sidebar-text">런칭 쇼케이스</span>
          </a>

          <p className="sidebar-section-title px-4 text-xs font-bold text-gray-400">MY SQUADS</p>
          {workspaces.length > 0 ? (
            workspaces.slice(0, 3).map((workspace) => (
              <a key={workspace.workspaceId} href="workspace-hub.html" className="nav-item">
                <span className="mx-2 h-2.5 w-2.5 shrink-0 rounded-full bg-blue-500" />
                <span className="sidebar-text truncate">{workspace.name}</span>
              </a>
            ))
          ) : (
            <div className="nav-item cursor-default opacity-50 hover:bg-transparent">
              <i className="fas fa-inbox w-6 text-center text-sm" />
              <span className="sidebar-text text-[11px]">참여 중인 팀 없음</span>
            </div>
          )}
        </nav>
      </aside>

      <div className="flex h-screen min-w-0 flex-1 flex-col overflow-hidden">
        <header className="sticky top-0 z-30 flex h-16 shrink-0 items-center border-b border-gray-200 bg-white px-8 shadow-sm">
          <div className="flex-1" />
          <nav className="hidden items-center gap-10 text-sm font-bold text-gray-500 md:flex">
            {headerLinks.map((link) => (
              <a
                key={link.href}
                href={link.href}
                className={link.label === '프로젝트' ? 'border-b-2 border-brand pb-1 text-brand transition' : 'transition hover:text-brand'}
              >
                {link.label}
              </a>
            ))}
          </nav>

          <div className="flex flex-1 items-center justify-end gap-2">
            <div className="relative">
              <button
                type="button"
                className="relative cursor-pointer rounded-full p-2.5 text-gray-500 transition hover:bg-gray-100 hover:text-brand"
                onClick={() => {
                  setMessagePopupOpen((open) => !open)
                  setNotiPopupOpen(false)
                }}
                aria-label="받은 메시지"
              >
                <i className="far fa-envelope text-lg" />
                {messages.length > 0 ? <span className="absolute right-2 top-[5px] h-2 w-2 rounded-full border border-white bg-red-500" /> : null}
              </button>
              {messagePopupOpen ? (
                <div className="absolute right-0 z-50 mt-2 w-80 overflow-hidden rounded-2xl border border-gray-100 bg-white text-left shadow-xl">
                  <div className="flex items-center justify-between border-b border-gray-50 p-4">
                    <h3 className="text-sm font-bold">라운지 메시지</h3>
                    <span className="text-xs text-gray-400">{messages.length}건</span>
                  </div>
                  <div className="max-h-60 overflow-y-auto p-2">
                    {messages.length > 0 ? (
                      messages.slice(-5).map((message) => (
                        <div key={message.messageId} className="rounded-xl p-3 hover:bg-gray-50">
                          <p className="truncate text-xs font-bold text-gray-900" title={message.senderName}>{message.senderName}</p>
                          <p className="truncate text-xs text-gray-500" title={message.content}>{message.content}</p>
                        </div>
                      ))
                    ) : (
                      <p className="p-4 text-center text-xs font-bold text-gray-400">새로운 메시지가 없습니다.</p>
                    )}
                  </div>
                </div>
              ) : null}
            </div>

            <div className="relative">
              <button
                type="button"
                className="relative cursor-pointer rounded-full p-2.5 text-gray-500 transition hover:bg-gray-100 hover:text-brand"
                onClick={() => {
                  setNotiPopupOpen((open) => !open)
                  setMessagePopupOpen(false)
                }}
                aria-label="알림"
              >
                <i className="far fa-bell text-lg" />
                {pendingReceivedCount > 0 ? <span className="absolute right-2 top-[5px] h-2 w-2 rounded-full border border-white bg-red-500" /> : null}
              </button>
              {notiPopupOpen ? (
                <div className="absolute right-0 z-50 mt-2 w-80 overflow-hidden rounded-2xl border border-gray-100 bg-white text-left shadow-xl">
                  <div className="flex items-center justify-between border-b border-gray-50 p-4">
                    <h3 className="text-sm font-bold">알림</h3>
                    <span className="text-xs text-gray-400">{pendingReceivedCount}건 대기</span>
                  </div>
                  <div className="max-h-60 overflow-y-auto p-2">
                    {receivedApplications.length > 0 ? (
                      receivedApplications.slice(0, 5).map((application) => (
                        <button
                          key={application.applicationId}
                          type="button"
                          className="w-full rounded-xl p-3 text-left hover:bg-gray-50"
                          onClick={() => setStatusOpen(true)}
                        >
                          <p className="truncate text-xs text-gray-800" title={application.title}>{application.title}</p>
                          <span className="text-[10px] text-gray-400">{applicationStatusLabel[application.status]}</span>
                        </button>
                      ))
                    ) : (
                      <p className="p-4 text-center text-xs font-bold text-gray-400">새로운 알림이 없습니다.</p>
                    )}
                  </div>
                </div>
              ) : null}
            </div>

            <div className="mx-4 h-6 w-px bg-gray-200" />
            {session ? (
              <AccountUserMenu
                session={{ ...session, name: userName }}
                profileImage={profileImage}
                onLogout={handleLogout}
              />
            ) : (
              <button
                type="button"
                className="rounded-full bg-gray-900 px-4 py-2 text-xs font-bold text-white transition hover:bg-gray-800"
                onClick={() => goTo('login.html')}
              >
                로그인
              </button>
            )}
          </div>
        </header>

        <main className="custom-scrollbar flex-1 overflow-y-auto bg-[#F8F9FA] p-4 md:p-8">
          <div className="mx-auto max-w-7xl space-y-8">
            <section className="fade-in overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 to-gray-900 p-6 shadow-lg lg:p-8">
              <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
                <div className="max-w-3xl text-white">
                  <span className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/10 px-3 py-1 text-[11px] font-bold text-white">
                    <i className="fas fa-bolt text-yellow-300" />
                    프로젝트 라운지
                  </span>
                  <h1 className="mt-4 text-2xl font-black tracking-tight text-white lg:text-3xl">
                    새 프로젝트와 스터디를 찾고 신청을 한곳에서 관리하세요.
                  </h1>
                  <p className="mt-3 max-w-2xl text-sm leading-6 text-gray-300">
                    관심 있는 모집글을 확인하고 바로 신청하거나 협업 제안을 보낼 수 있습니다.
                  </p>
                </div>
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    className="flex items-center gap-2 rounded-xl bg-brand px-5 py-3 text-xs font-bold text-white shadow-[0_4px_15px_rgba(0,196,113,0.3)] transition hover:bg-green-600"
                    onClick={() => {
                      if (!session?.accessToken) {
                        goTo('login.html')
                        return
                      }
                      setCreateOpen(true)
                    }}
                  >
                    <i className="fas fa-plus" />
                    모집글 작성
                  </button>
                  <button
                    type="button"
                    className="flex items-center gap-2 rounded-xl border border-white/20 bg-white/10 px-5 py-3 text-xs font-bold text-white backdrop-blur-md transition hover:bg-white/20"
                    onClick={() => setStatusOpen(true)}
                  >
                    <i className="fas fa-list-check" />
                    신청 현황
                  </button>
                </div>
              </div>
            </section>

            {notice ? (
              <div className="flex items-center justify-between rounded-2xl border border-gray-200 bg-white px-5 py-4 text-sm text-gray-700 shadow-sm">
                <span className="truncate" title={notice}>{notice}</span>
                <button type="button" className="text-xs font-bold text-gray-400 hover:text-gray-700" onClick={() => setNotice(null)}>
                  닫기
                </button>
              </div>
            ) : null}

            <section className="grid grid-cols-1 gap-8 xl:grid-cols-[minmax(0,1fr)_360px]">
              <div className="space-y-5">
                <div className="rounded-2xl border border-gray-200 bg-white p-4 shadow-sm">
                  <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                    <div className="flex min-w-0 flex-1 items-center gap-2 rounded-xl border border-gray-200 bg-gray-50 px-4 py-3">
                      <i className="fas fa-search text-sm text-gray-400" />
                      <input
                        value={keyword}
                        onChange={(event) => setKeyword(event.target.value)}
                        className="w-full bg-transparent text-sm font-medium text-gray-700 outline-none placeholder:text-gray-400"
                        placeholder="기술 스택, 제목, 설명 검색"
                      />
                    </div>
                    <select
                      value={sortKey}
                      onChange={(event) => setSortKey(event.target.value as SortKey)}
                      className="rounded-xl border border-gray-200 bg-white px-4 py-3 text-sm font-bold text-gray-600 outline-none transition focus:border-brand"
                    >
                      {sortOptions.map((option) => (
                        <option key={option.key} value={option.key}>{option.label}</option>
                      ))}
                    </select>
                  </div>
                  <div className="hide-scroll mt-4 flex gap-2 overflow-x-auto">
                    {tabs.map((tab) => (
                      <button
                        key={tab.key}
                        type="button"
                        className={`shrink-0 rounded-full px-4 py-2 text-xs font-extrabold transition ${
                          activeTab === tab.key
                            ? 'bg-gray-900 text-white shadow-md'
                            : 'bg-gray-100 text-gray-500 hover:bg-gray-200 hover:text-gray-900'
                        }`}
                        onClick={() => setActiveTab(tab.key)}
                      >
                        {tab.label}
                      </button>
                    ))}
                  </div>
                </div>

                {loading ? (
                  <div className="grid grid-cols-1 gap-5 md:grid-cols-2">
                    {Array.from({ length: 4 }, (_, index) => (
                      <div key={index} className="h-64 animate-pulse rounded-2xl border border-gray-200 bg-white" />
                    ))}
                  </div>
                ) : visibleCards.length > 0 ? (
                  <div className="grid grid-cols-1 gap-5 md:grid-cols-2">
                    {visibleCards.map((card) => (
                      <article key={`${card.kind}-${card.id}`} className="hover-card relative flex h-[260px] flex-col justify-between overflow-hidden rounded-2xl bg-white p-5 shadow-sm">
                        <div className={`absolute left-0 top-0 h-full w-1 ${card.accentClassName}`} />
                        <div className="min-w-0">
                          <div className="mb-3 flex items-center justify-between gap-3">
                            <span className="inline-flex items-center gap-1.5 rounded-full bg-gray-50 px-2.5 py-1 text-[10px] font-extrabold text-gray-600">
                              <i className={card.iconClassName} />
                              {card.sourceLabel}
                            </span>
                            <span className={`shrink-0 rounded-full border px-2.5 py-1 text-[10px] font-black ${getStatusClassName(card)}`}>
                              {getStatusText(card)}
                            </span>
                          </div>
                          <h2 className="truncate text-lg font-black text-gray-900" title={card.title}>{card.title}</h2>
                          <p className="mt-2 line-clamp-3 min-h-[60px] text-xs leading-5 text-gray-500" title={card.description}>{card.description}</p>
                        </div>

                        <div className="space-y-4">
                          <div className="flex items-center justify-between text-[11px] font-bold text-gray-400">
                            <span>{formatDate(card.createdAt)}</span>
                            {card.maxMembers ? <span>최대 {card.maxMembers}명</span> : null}
                            {card.members?.length ? <span>{card.members.length}명 참여</span> : null}
                          </div>
                          <div className="flex gap-2">
                            <button
                              type="button"
                              className="flex-1 rounded-xl border border-gray-200 px-4 py-2.5 text-xs font-bold text-gray-700 transition hover:border-gray-300 hover:bg-gray-50"
                              onClick={() => setSelectedCard(card)}
                            >
                              자세히
                            </button>
                            <button
                              type="button"
                              className={`flex-1 rounded-xl px-4 py-2.5 text-xs font-bold transition ${
                                card.canApply
                                  ? 'bg-brand text-white hover:bg-green-600'
                                  : 'cursor-not-allowed bg-gray-100 text-gray-400'
                              }`}
                              onClick={() => card.canApply && openApplyModal(card)}
                              disabled={!card.canApply}
                            >
                              {card.kind === 'WISH' ? '제안하기' : '신청하기'}
                            </button>
                          </div>
                        </div>
                      </article>
                    ))}
                  </div>
                ) : (
                  <EmptyState message="조건에 맞는 모집글이 없습니다." />
                )}

                <div className="flex items-center justify-center gap-2">
                  <button
                    type="button"
                    className="rounded-lg border border-gray-200 bg-white px-3 py-2 text-xs font-bold text-gray-500 disabled:opacity-40"
                    onClick={() => setPage((current) => Math.max(1, current - 1))}
                    disabled={page === 1}
                  >
                    이전
                  </button>
                  <span className="rounded-lg bg-gray-900 px-3 py-2 text-xs font-bold text-white">{page} / {totalPages}</span>
                  <button
                    type="button"
                    className="rounded-lg border border-gray-200 bg-white px-3 py-2 text-xs font-bold text-gray-500 disabled:opacity-40"
                    onClick={() => setPage((current) => Math.min(totalPages, current + 1))}
                    disabled={page === totalPages}
                  >
                    다음
                  </button>
                </div>
              </div>

              <aside className="space-y-5">
                <div className="rounded-2xl border border-gray-200 bg-white p-5 shadow-sm">
                  <div className="mb-4 flex items-center justify-between">
                    <h2 className="text-sm font-extrabold text-gray-900">라운지 채팅</h2>
                    <span className="rounded-full bg-gray-100 px-2 py-1 text-[10px] font-bold text-gray-500">{messages.length}건</span>
                  </div>
                  <div className="custom-scrollbar flex h-[300px] flex-col gap-3 overflow-y-auto pr-1">
                    {messages.length > 0 ? (
                      messages.map((message) => (
                        <div key={message.messageId} className={`flex ${message.isMine ? 'justify-end' : 'justify-start'}`}>
                          <div className={`max-w-[86%] rounded-2xl px-3 py-2 ${message.isMine ? 'bg-brand text-white' : 'bg-gray-100 text-gray-800'}`}>
                            <p className="mb-1 truncate text-[10px] font-bold opacity-80" title={message.senderName}>{message.senderName}</p>
                            <p className="text-xs leading-5" title={message.content}>{message.content}</p>
                            <p className="mt-1 text-[9px] opacity-70">{getRelativeTime(message.createdAt)}</p>
                          </div>
                        </div>
                      ))
                    ) : (
                      <div className="flex h-full flex-col items-center justify-center text-center">
                        <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-full bg-gray-50 text-gray-300">
                          <i className="fas fa-comments" />
                        </div>
                        <p className="text-xs font-bold text-gray-600">아직 채팅이 없습니다</p>
                        <p className="mt-1 text-[10px] leading-4 text-gray-400">로그인 후 첫 메시지를 남길 수 있습니다.</p>
                      </div>
                    )}
                  </div>
                  <form className="mt-4 flex gap-2" onSubmit={handleChatSubmit}>
                    <input
                      value={chatInput}
                      onChange={(event) => setChatInput(event.target.value)}
                      className="min-w-0 flex-1 rounded-xl border border-gray-200 px-3 py-2 text-xs outline-none focus:border-brand"
                      placeholder={session ? '메시지 입력' : '로그인이 필요합니다'}
                      disabled={!session}
                    />
                    <button
                      type="submit"
                      className="rounded-xl bg-gray-900 px-4 py-2 text-xs font-bold text-white disabled:cursor-not-allowed disabled:bg-gray-200"
                      disabled={!session || !chatInput.trim()}
                    >
                      전송
                    </button>
                  </form>
                </div>

                <div className="rounded-2xl border border-gray-200 bg-white p-5 shadow-sm">
                  <h2 className="mb-4 text-sm font-extrabold text-gray-900">신청 요약</h2>
                  <div className="grid grid-cols-2 gap-3">
                    <button type="button" className="rounded-2xl bg-gray-50 p-4 text-left transition hover:bg-gray-100" onClick={() => setStatusOpen(true)}>
                      <p className="text-[10px] font-bold text-gray-400">보낸 신청</p>
                      <p className="mt-2 text-2xl font-black text-gray-900">{sentApplications.length}</p>
                    </button>
                    <button type="button" className="rounded-2xl bg-gray-50 p-4 text-left transition hover:bg-gray-100" onClick={() => setStatusOpen(true)}>
                      <p className="text-[10px] font-bold text-gray-400">받은 요청</p>
                      <p className="mt-2 text-2xl font-black text-gray-900">{receivedApplications.length}</p>
                    </button>
                  </div>
                </div>
              </aside>
            </section>
          </div>
        </main>
      </div>

      {selectedCard ? (
        <div className="fixed inset-0 z-[70] flex items-center justify-center bg-black/40 p-4">
          <div className="w-full max-w-2xl overflow-hidden rounded-2xl bg-white shadow-2xl">
            <div className="border-b border-gray-100 p-6">
              <div className="mb-3 flex items-center justify-between gap-3">
                <span className="rounded-full bg-gray-100 px-3 py-1 text-xs font-bold text-gray-500">{selectedCard.sourceLabel}</span>
                <button type="button" className="text-gray-400 hover:text-gray-700" onClick={() => setSelectedCard(null)}>
                  <i className="fas fa-times" />
                </button>
              </div>
              <h2 className="text-2xl font-black text-gray-900">{selectedCard.title}</h2>
              <p className="mt-2 text-sm text-gray-500">{formatDate(selectedCard.createdAt)}</p>
            </div>
            <div className="custom-scrollbar max-h-[50vh] overflow-y-auto p-6">
              <p className="whitespace-pre-wrap text-sm leading-7 text-gray-700">{selectedCard.description}</p>
            </div>
            <div className="flex gap-2 border-t border-gray-100 p-4">
              <button type="button" className="flex-1 rounded-xl bg-gray-100 py-3 text-sm font-bold text-gray-600" onClick={() => setSelectedCard(null)}>
                닫기
              </button>
              <button
                type="button"
                className="flex-1 rounded-xl bg-brand py-3 text-sm font-bold text-white disabled:cursor-not-allowed disabled:bg-gray-200"
                disabled={!selectedCard.canApply}
                onClick={() => {
                  setSelectedCard(null)
                  openApplyModal(selectedCard)
                }}
              >
                {selectedCard.kind === 'WISH' ? '제안하기' : '신청하기'}
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {applyCard ? (
        <div className="fixed inset-0 z-[70] flex items-center justify-center bg-black/40 p-4">
          <form className="w-full max-w-lg overflow-hidden rounded-2xl bg-white shadow-2xl" onSubmit={handleApplySubmit}>
            <div className="border-b border-gray-100 p-6">
              <h2 className="text-xl font-black text-gray-900">{applyCard.kind === 'WISH' ? '협업 제안' : '참여 신청'}</h2>
              <p className="mt-1 truncate text-sm text-gray-500" title={applyCard.title}>{applyCard.title}</p>
            </div>
            <div className="space-y-4 p-6">
              <label className="block">
                <span className="mb-2 block text-xs font-bold text-gray-500">제목</span>
                <input
                  value={applicationTitle}
                  onChange={(event) => setApplicationTitle(event.target.value)}
                  className="w-full rounded-xl border border-gray-200 px-4 py-3 text-sm outline-none focus:border-brand"
                  required
                  maxLength={150}
                />
              </label>
              <label className="block">
                <span className="mb-2 block text-xs font-bold text-gray-500">내용</span>
                <textarea
                  value={applicationContent}
                  onChange={(event) => setApplicationContent(event.target.value)}
                  className="min-h-36 w-full resize-none rounded-xl border border-gray-200 px-4 py-3 text-sm leading-6 outline-none focus:border-brand"
                  required
                  maxLength={3000}
                  placeholder="경험, 가능한 역할, 연락 가능 시간 등을 작성하세요."
                />
              </label>
            </div>
            <div className="flex gap-2 border-t border-gray-100 p-4">
              <button type="button" className="flex-1 rounded-xl bg-gray-100 py-3 text-sm font-bold text-gray-600" onClick={() => setApplyCard(null)}>
                취소
              </button>
              <button type="submit" className="flex-1 rounded-xl bg-brand py-3 text-sm font-bold text-white disabled:bg-gray-300" disabled={submitting}>
                보내기
              </button>
            </div>
          </form>
        </div>
      ) : null}

      {createOpen ? (
        <div className="fixed inset-0 z-[70] flex items-center justify-center bg-black/40 p-4">
          <form className="w-full max-w-lg overflow-hidden rounded-2xl bg-white shadow-2xl" onSubmit={handleCreateSubmit}>
            <div className="border-b border-gray-100 p-6">
              <h2 className="text-xl font-black text-gray-900">모집글 작성</h2>
              <p className="mt-1 text-sm text-gray-500">프로젝트 모집, 참여 희망, 스터디 중 하나로 등록됩니다.</p>
            </div>
            <div className="space-y-4 p-6">
              <label className="block">
                <span className="mb-2 block text-xs font-bold text-gray-500">유형</span>
                <select
                  value={createKind}
                  onChange={(event) => setCreateKind(event.target.value as CreateKind)}
                  className="w-full rounded-xl border border-gray-200 px-4 py-3 text-sm font-bold outline-none focus:border-brand"
                >
                  <option value="PROJECT">프로젝트 모집</option>
                  <option value="IDEA">참여 희망</option>
                  <option value="STUDY">스터디</option>
                </select>
              </label>
              <label className="block">
                <span className="mb-2 block text-xs font-bold text-gray-500">제목</span>
                <input
                  value={createTitle}
                  onChange={(event) => setCreateTitle(event.target.value)}
                  className="w-full rounded-xl border border-gray-200 px-4 py-3 text-sm outline-none focus:border-brand"
                  required
                  maxLength={100}
                />
              </label>
              <label className="block">
                <span className="mb-2 block text-xs font-bold text-gray-500">소개</span>
                <textarea
                  value={createDescription}
                  onChange={(event) => setCreateDescription(event.target.value)}
                  className="min-h-36 w-full resize-none rounded-xl border border-gray-200 px-4 py-3 text-sm leading-6 outline-none focus:border-brand"
                  required
                  maxLength={3000}
                />
              </label>
              {createKind === 'STUDY' ? (
                <label className="block">
                  <span className="mb-2 block text-xs font-bold text-gray-500">최대 인원</span>
                  <input
                    type="number"
                    min={2}
                    value={createMaxMembers}
                    onChange={(event) => setCreateMaxMembers(Number(event.target.value))}
                    className="w-full rounded-xl border border-gray-200 px-4 py-3 text-sm outline-none focus:border-brand"
                    required
                  />
                </label>
              ) : null}
            </div>
            <div className="flex gap-2 border-t border-gray-100 p-4">
              <button type="button" className="flex-1 rounded-xl bg-gray-100 py-3 text-sm font-bold text-gray-600" onClick={() => setCreateOpen(false)}>
                취소
              </button>
              <button type="submit" className="flex-1 rounded-xl bg-gray-900 py-3 text-sm font-bold text-white disabled:bg-gray-300" disabled={submitting}>
                등록
              </button>
            </div>
          </form>
        </div>
      ) : null}

      {statusOpen ? (
        <div className="fixed inset-0 z-[70] flex items-center justify-center bg-black/40 p-4">
          <div className="w-full max-w-3xl overflow-hidden rounded-2xl bg-white shadow-2xl">
            <div className="flex items-center justify-between border-b border-gray-100 p-6">
              <h2 className="text-xl font-black text-gray-900">신청 현황</h2>
              <button type="button" className="text-gray-400 hover:text-gray-700" onClick={() => setStatusOpen(false)}>
                <i className="fas fa-times" />
              </button>
            </div>
            <div className="grid max-h-[70vh] gap-6 overflow-y-auto p-6 md:grid-cols-2">
              <div>
                <h3 className="mb-3 text-sm font-extrabold text-gray-900">보낸 신청</h3>
                <div className="space-y-2">
                  {sentApplications.length > 0 ? (
                    sentApplications.map((application) => (
                      <div key={application.applicationId} className="rounded-2xl border border-gray-100 bg-gray-50 p-4">
                        <div className="mb-2 flex items-center justify-between gap-2">
                          <p className="truncate text-sm font-bold text-gray-900" title={application.targetTitle}>{application.targetTitle}</p>
                          <span className={`shrink-0 rounded-full px-2 py-1 text-[10px] font-bold ${getApplicationBadgeClassName(application.status)}`}>
                            {applicationStatusLabel[application.status]}
                          </span>
                        </div>
                        <p className="truncate text-xs text-gray-500" title={application.title}>{application.title}</p>
                      </div>
                    ))
                  ) : (
                    <p className="rounded-2xl bg-gray-50 p-5 text-center text-xs font-bold text-gray-400">보낸 신청이 없습니다.</p>
                  )}
                </div>
              </div>
              <div>
                <h3 className="mb-3 text-sm font-extrabold text-gray-900">받은 요청</h3>
                <div className="space-y-2">
                  {receivedApplications.length > 0 ? (
                    receivedApplications.map((application) => (
                      <div key={application.applicationId} className="rounded-2xl border border-gray-100 bg-gray-50 p-4">
                        <div className="mb-2 flex items-center justify-between gap-2">
                          <p className="truncate text-sm font-bold text-gray-900" title={application.senderName}>{application.senderName}</p>
                          <span className={`shrink-0 rounded-full px-2 py-1 text-[10px] font-bold ${getApplicationBadgeClassName(application.status)}`}>
                            {applicationStatusLabel[application.status]}
                          </span>
                        </div>
                        <p className="truncate text-xs text-gray-500" title={application.title}>{application.title}</p>
                        {application.status === 'PENDING' ? (
                          <div className="mt-3 flex gap-2">
                            <button
                              type="button"
                              className="flex-1 rounded-lg bg-brand py-2 text-xs font-bold text-white disabled:bg-gray-300"
                              disabled={submitting}
                              onClick={() => void handleApplicationAction(application.applicationId, 'approve')}
                            >
                              승인
                            </button>
                            <button
                              type="button"
                              className="flex-1 rounded-lg bg-gray-900 py-2 text-xs font-bold text-white disabled:bg-gray-300"
                              disabled={submitting}
                              onClick={() => void handleApplicationAction(application.applicationId, 'reject')}
                            >
                              거절
                            </button>
                          </div>
                        ) : null}
                      </div>
                    ))
                  ) : (
                    <p className="rounded-2xl bg-gray-50 p-5 text-center text-xs font-bold text-gray-400">받은 요청이 없습니다.</p>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  )
}

export default CommunityLoungeApp
