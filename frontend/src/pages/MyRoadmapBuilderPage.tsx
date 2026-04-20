import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { readStoredAuthSession } from '../lib/auth-session'

// ────────────────────────────────────────────
// 타입 정의
// ────────────────────────────────────────────

interface SkillModule {
  dbId: number        // builder_modules.id (저장 요청 시 사용)
  id: string          // moduleId 문자열 (중복 방지 키)
  title: string
  category: string
  icon: string
  color: string
  bgColor: string
  topics: string[]
}

interface BuilderNode {
  instanceId: string
  module: SkillModule
  sortOrder: number        // 타임라인 위치 (1부터)
  branchGroup: number | null  // null=척추, 1=왼쪽, 2=오른쪽
}

interface TimelineRow {
  sortOrder: number
  nodes: BuilderNode[]
  isBranching: boolean
}

// ────────────────────────────────────────────
// 카테고리 옵션
// ────────────────────────────────────────────

const CATEGORY_OPTIONS = [
  { value: 'frontend',      label: '프런트엔드 (Frontend)' },
  { value: 'backend',       label: '백엔드 (Backend) ⭐추천' },
  { value: 'devops',        label: '데브옵스 (DevOps)' },
  { value: 'fullstack',     label: '풀스택 (Full Stack)' },
  { value: 'ai',            label: 'AI 엔지니어 (AI Engineer)' },
  { value: 'data_engineer', label: '데이터 엔지니어 (Data Engineer)' },
  { value: 'android',       label: '안드로이드 (Android)' },
  { value: 'ios',           label: 'iOS (iOS)' },
  { value: 'game',          label: '게임 개발자 (Game Developer)' },
  { value: 'blockchain',    label: '블록체인 (Blockchain)' },
]

function makeInstanceId() {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`
}

// ────────────────────────────────────────────
// 메인 컴포넌트
// ────────────────────────────────────────────

function MyRoadmapBuilderPage() {
  const [session] = useState(() => readStoredAuthSession())
  const [category, setCategory] = useState('backend')
  const [search, setSearch] = useState('')
  const [items, setItems] = useState<SkillModule[]>([])
  const [loading, setLoading] = useState(false)
  const [fetchError, setFetchError] = useState<string | null>(null)
  const [nodes, setNodes] = useState<BuilderNode[]>([])
  const [branchTarget, setBranchTarget] = useState<number | null>(null)
  const [saveModalOpen, setSaveModalOpen] = useState(false)
  const [roadmapTitle, setRoadmapTitle] = useState('')
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [saveSuccess, setSaveSuccess] = useState(false)
  const mainRef = useRef<HTMLDivElement>(null)
  const titleInputRef = useRef<HTMLInputElement>(null)

  // ── 카테고리 변경 시 API 호출 ──
  useEffect(() => {
    setLoading(true)
    setFetchError(null)
    fetch(`/api/builder/modules?category=${category}`, {
      headers: { Authorization: `Bearer ${session?.accessToken ?? ''}` },
    })
      .then((res) => {
        if (!res.ok) throw new Error(`서버 오류 (${res.status})`)
        return res.json()
      })
      .then((data) => {
        const raw = (data.data ?? []) as Array<{
          id: number; moduleId: string; category: string; title: string
          icon: string; color: string; bgColor: string; topics: string[]
        }>
        setItems(raw.map((m) => ({
          dbId: m.id,
          id: m.moduleId,
          title: m.title,
          category: m.category,
          icon: m.icon,
          color: m.color,
          bgColor: m.bgColor,
          topics: m.topics,
        })))
      })
      .catch((err: Error) => setFetchError(err.message))
      .finally(() => setLoading(false))
  }, [category])

  // 모달 열릴 때 포커스
  useEffect(() => {
    if (saveModalOpen) {
      setTimeout(() => titleInputRef.current?.focus(), 50)
    }
  }, [saveModalOpen])

  // dbId 기준 중복 방지 (크로스 카테고리 혼합 시에도 정확)
  const usedIds = useMemo(() => new Set(nodes.map((n) => n.module.dbId)), [nodes])

  const maxSortOrder = useMemo(
    () => (nodes.length === 0 ? 0 : Math.max(...nodes.map((n) => n.sortOrder))),
    [nodes],
  )

  // sortOrder 기준 rows 그룹화
  const rows = useMemo<TimelineRow[]>(() => {
    const map = new Map<number, BuilderNode[]>()
    for (const node of nodes) {
      const arr = map.get(node.sortOrder) ?? []
      arr.push(node)
      map.set(node.sortOrder, arr)
    }
    return Array.from(map.entries())
      .sort(([a], [b]) => a - b)
      .map(([sortOrder, rowNodes]) => ({
        sortOrder,
        nodes: [...rowNodes].sort((a, b) => (a.branchGroup ?? 0) - (b.branchGroup ?? 0)),
        isBranching: rowNodes.some((n) => n.branchGroup !== null),
      }))
  }, [nodes])

  // 좌측 패널 필터링
  const filteredItems = useMemo(() => {
    const q = search.toLowerCase()
    if (!q) return items
    return items.filter(
      (item) =>
        item.title.toLowerCase().includes(q) ||
        item.category.toLowerCase().includes(q) ||
        item.topics.some((t) => t.toLowerCase().includes(q)),
    )
  }, [items, search])

  // 모듈 추가 (척추 or 분기)
  const handleAdd = useCallback(
    (module: SkillModule) => {
      if (usedIds.has(module.dbId)) return

      if (branchTarget === null) {
        setNodes((prev) => [
          ...prev,
          { instanceId: makeInstanceId(), module, sortOrder: maxSortOrder + 1, branchGroup: null },
        ])
        setTimeout(() => {
          mainRef.current?.scrollTo({ top: mainRef.current.scrollHeight, behavior: 'smooth' })
        }, 50)
      } else {
        setNodes((prev) => {
          const updated = prev.map((n) =>
            n.sortOrder === branchTarget && n.branchGroup === null
              ? { ...n, branchGroup: 1 }
              : n,
          )
          return [
            ...updated,
            { instanceId: makeInstanceId(), module, sortOrder: branchTarget, branchGroup: 2 },
          ]
        })
        setBranchTarget(null)
      }
    },
    [usedIds, branchTarget, maxSortOrder],
  )

  // 분기 모드 진입
  const handleBranchActivate = useCallback(
    (sortOrder: number) => {
      const rowNodes = nodes.filter((n) => n.sortOrder === sortOrder)
      if (rowNodes.some((n) => n.branchGroup !== null)) {
        alert('이미 분기가 존재하는 위치입니다. 분기는 위치당 최대 2개까지 가능합니다.')
        return
      }
      setBranchTarget(sortOrder)
    },
    [nodes],
  )

  // 노드 삭제 + 후처리
  const handleRemove = useCallback((instanceId: string) => {
    setNodes((prev) => {
      const target = prev.find((n) => n.instanceId === instanceId)
      if (!target) return prev

      const { sortOrder, branchGroup } = target
      const sameRow = prev.filter((n) => n.sortOrder === sortOrder && n.instanceId !== instanceId)

      let updated: BuilderNode[]

      if (branchGroup === null) {
        // 척추 노드 삭제 → 이후 sortOrder 전부 -1 재정렬
        updated = prev
          .filter((n) => n.instanceId !== instanceId)
          .map((n) => (n.sortOrder > sortOrder ? { ...n, sortOrder: n.sortOrder - 1 } : n))
      } else {
        if (sameRow.length === 1) {
          // 분기 하나 남음 → 척추로 복원
          updated = prev
            .filter((n) => n.instanceId !== instanceId)
            .map((n) => (n.sortOrder === sortOrder ? { ...n, branchGroup: null } : n))
        } else {
          // 마지막 분기 노드 삭제 → row 제거 + 이후 재정렬
          updated = prev
            .filter((n) => n.instanceId !== instanceId)
            .map((n) => (n.sortOrder > sortOrder ? { ...n, sortOrder: n.sortOrder - 1 } : n))
        }
      }

      return updated
    })
  }, [])

  const handleClear = useCallback(() => {
    if (nodes.length === 0) return
    if (window.confirm('진행 중인 커리큘럼 설계를 모두 초기화하시겠습니까?')) {
      setNodes([])
      setBranchTarget(null)
    }
  }, [nodes.length])

  // 저장 모달 열기
  const openSaveModal = useCallback(() => {
    setSaveError(null)
    setRoadmapTitle('')
    setSaveModalOpen(true)
  }, [])

  // 로드맵 저장
  const handleSave = useCallback(async () => {
    if (!session?.userId) return
    if (!roadmapTitle.trim()) {
      setSaveError('로드맵 이름을 입력해주세요.')
      return
    }

    setSaving(true)
    setSaveError(null)

    try {
      const res = await fetch(`/api/builder/roadmaps?userId=${session.userId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: roadmapTitle.trim(),
          modules: nodes.map((n) => ({
            builderModuleId: n.module.dbId,
            sortOrder: n.sortOrder,
            branchGroup: n.branchGroup,
          })),
        }),
      })

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}))
        throw new Error((errData as { message?: string }).message ?? `저장 실패 (${res.status})`)
      }

      setSaveModalOpen(false)
      setNodes([])
      setBranchTarget(null)
      setRoadmapTitle('')
      setSaveSuccess(true)
      setTimeout(() => setSaveSuccess(false), 3000)
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : '저장 중 오류가 발생했습니다.')
    } finally {
      setSaving(false)
    }
  }, [session?.userId, roadmapTitle, nodes])

  // ────────────────────────────────────────────
  // 미로그인 가드
  // ────────────────────────────────────────────

  if (!session?.userId) {
    return (
      <div className="flex h-screen items-center justify-center bg-[#F8FAFC]">
        <div className="rounded-2xl border border-gray-200 bg-white p-10 text-center shadow-lg">
          <i className="fas fa-lock mb-4 block text-4xl text-gray-300" />
          <h2 className="mb-2 text-xl font-bold text-gray-800">로그인이 필요합니다</h2>
          <p className="mb-6 text-sm text-gray-500">나만의 로드맵 빌더를 사용하려면 먼저 로그인해주세요.</p>
          <a
            href="/login.html"
            className="inline-block rounded-lg bg-[#00C471] px-6 py-2.5 text-sm font-bold text-white transition hover:bg-green-600"
          >
            로그인하러 가기
          </a>
        </div>
      </div>
    )
  }

  // ────────────────────────────────────────────
  // 렌더
  // ────────────────────────────────────────────

  return (
    <div className="flex h-screen flex-col overflow-hidden bg-[#F8FAFC] text-[#0F172A]">

      {/* 저장 성공 토스트 */}
      {saveSuccess && (
        <div className="pointer-events-none fixed bottom-6 left-1/2 z-50 -translate-x-1/2 rounded-xl bg-gray-900 px-6 py-3 text-sm font-bold text-white shadow-xl">
          <i className="fas fa-check-circle mr-2 text-[#00C471]" />
          로드맵이 저장되었습니다!
        </div>
      )}

      {/* 저장 모달 */}
      {saveModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-2xl bg-white p-8 shadow-2xl">
            <h2 className="mb-1 text-xl font-extrabold text-gray-900">로드맵 저장</h2>
            <p className="mb-6 text-sm text-gray-500">나만의 로드맵 이름을 입력해주세요.</p>
            <input
              ref={titleInputRef}
              type="text"
              value={roadmapTitle}
              onChange={(e) => setRoadmapTitle(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') handleSave() }}
              placeholder="예: 내 백엔드 개발자 로드맵"
              maxLength={200}
              className="w-full rounded-lg border border-gray-300 px-4 py-3 text-sm font-medium focus:border-[#00C471] focus:outline-none focus:ring-2 focus:ring-[#00C471]/20"
            />
            {saveError && (
              <p className="mt-2 text-xs font-bold text-red-500">
                <i className="fas fa-exclamation-circle mr-1" />{saveError}
              </p>
            )}
            <div className="mt-6 flex justify-end gap-3">
              <button
                type="button"
                onClick={() => setSaveModalOpen(false)}
                disabled={saving}
                className="rounded-lg border border-gray-300 px-5 py-2.5 text-sm font-bold text-gray-600 transition hover:bg-gray-50 disabled:opacity-50"
              >
                취소
              </button>
              <button
                type="button"
                onClick={handleSave}
                disabled={saving || !roadmapTitle.trim()}
                className="flex items-center gap-2 rounded-lg bg-[#00C471] px-5 py-2.5 text-sm font-bold text-white transition hover:bg-green-600 disabled:opacity-50"
              >
                {saving ? <><i className="fas fa-spinner fa-spin" /> 저장 중...</> : <><i className="fas fa-save" /> 저장</>}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 헤더 */}
      <header className="z-50 flex h-16 shrink-0 items-center justify-between border-b border-gray-200 bg-white px-6 shadow-sm">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gray-900 text-white shadow-sm">
            <i className="fas fa-layer-group text-sm" />
          </div>
          <h1 className="text-xl font-bold tracking-tight text-gray-900">
            DevPath <span className="font-medium text-gray-400">마스터 빌더</span>
          </h1>
        </div>
        <div className="flex items-center gap-4">
          <div className="rounded-lg border border-gray-200 bg-gray-100 px-3 py-1.5 text-sm font-bold text-gray-500">
            총 <span className="font-black text-[#00C471]">{rows.length}</span> 챕터
          </div>
          <button
            type="button"
            onClick={handleClear}
            disabled={nodes.length === 0}
            className="rounded-lg border border-transparent px-4 py-2 text-sm font-bold text-gray-600 transition hover:bg-red-50 hover:text-red-500 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <i className="fas fa-rotate-right mr-1" /> 초기화
          </button>
          <button
            type="button"
            onClick={openSaveModal}
            disabled={nodes.length === 0}
            className="flex items-center gap-2 rounded-lg bg-[#00C471] px-5 py-2 text-sm font-bold text-white shadow-md transition hover:bg-green-600 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <i className="fas fa-save" /> 로드맵 저장
          </button>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">

        {/* ── 좌측 사이드바 ── */}
        <aside className="z-10 flex w-80 flex-col border-r border-gray-200 bg-white shadow-lg md:w-96">

          {/* 카테고리 선택 */}
          <div className="shrink-0 border-b border-gray-200 bg-gray-50 p-4">
            <label className="mb-2 block text-[10px] font-black uppercase tracking-widest text-gray-400">
              로드맵 템플릿 선택
            </label>
            <div className="relative">
              <select
                value={category}
                onChange={(e) => { setCategory(e.target.value); setBranchTarget(null) }}
                className="w-full cursor-pointer appearance-none rounded-lg border border-gray-300 bg-white px-3 py-2.5 pr-8 text-sm font-bold text-gray-900 shadow-sm focus:border-transparent focus:outline-none focus:ring-2 focus:ring-[#00C471]"
              >
                {CATEGORY_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>{opt.label}</option>
                ))}
              </select>
              <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-3 text-gray-400">
                <i className="fas fa-chevron-down text-xs" />
              </div>
            </div>
          </div>

          {/* 분기 모드 배너 */}
          {branchTarget !== null && (
            <div className="shrink-0 border-b border-amber-200 bg-amber-50 px-4 py-3">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <p className="text-xs font-black text-amber-700">
                    <i className="fas fa-code-branch mr-1" />
                    {branchTarget}번 위치에 분기 추가 중
                  </p>
                  <p className="mt-0.5 text-[11px] text-amber-600">
                    왼쪽 모듈을 클릭하면 분기 노드로 추가됩니다.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setBranchTarget(null)}
                  className="shrink-0 rounded-md border border-amber-300 bg-white px-2 py-1 text-[11px] font-bold text-amber-600 transition hover:bg-amber-100"
                >
                  취소
                </button>
              </div>
            </div>
          )}

          {/* 검색 */}
          <div className="shrink-0 border-b border-gray-100 bg-white p-4">
            <div className="relative">
              <i className="fas fa-search absolute left-3 top-1/2 -translate-y-1/2 text-sm text-gray-400" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="학습 주제 검색..."
                className="w-full rounded-lg border border-gray-200 bg-gray-50 py-2.5 pl-9 pr-3 text-sm font-medium transition focus:border-[#00C471] focus:bg-white focus:outline-none"
              />
            </div>
          </div>

          {/* 모듈 목록 */}
          <div className="flex-1 overflow-y-auto bg-gray-50 p-4">
            {loading ? (
              <div className="flex flex-col items-center justify-center gap-3 py-16 text-gray-400">
                <i className="fas fa-spinner fa-spin text-2xl" />
                <p className="text-sm font-medium">모듈 불러오는 중...</p>
              </div>
            ) : fetchError ? (
              <div className="flex flex-col items-center justify-center gap-3 py-16 text-center text-red-400">
                <i className="fas fa-exclamation-triangle text-2xl" />
                <p className="text-sm font-bold">모듈을 불러오지 못했습니다.</p>
                <p className="text-xs text-gray-400">{fetchError}</p>
                <button
                  type="button"
                  onClick={() => setCategory((c) => c)}
                  className="mt-1 rounded-lg border border-red-200 px-4 py-1.5 text-xs font-bold text-red-500 transition hover:bg-red-50"
                >
                  다시 시도
                </button>
              </div>
            ) : filteredItems.length === 0 ? (
              <div className="flex flex-col items-center justify-center gap-2 py-16 text-gray-400">
                <i className="fas fa-search text-2xl" />
                <p className="text-sm font-medium">검색 결과가 없습니다.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {filteredItems.map((module) => {
                  const isUsed = usedIds.has(module.dbId)
                  const isAvailableForBranch = branchTarget !== null && !isUsed
                  return (
                    <div
                      key={module.dbId}
                      onClick={() => handleAdd(module)}
                      className={[
                        'group flex cursor-pointer items-start gap-3 rounded-xl border bg-white p-[14px] shadow-[0_1px_2px_rgba(0,0,0,0.02)] transition-all duration-200',
                        isUsed
                          ? 'cursor-not-allowed border-dashed border-[#CBD5E1] bg-[#F1F5F9] opacity-60'
                          : isAvailableForBranch
                            ? 'border-amber-300 hover:-translate-y-0.5 hover:border-amber-400 hover:shadow-[0_4px_12px_rgba(245,158,11,0.15)]'
                            : 'border-[#E2E8F0] hover:-translate-y-0.5 hover:border-[#00C471] hover:shadow-[0_4px_12px_rgba(0,196,113,0.1)] active:scale-[0.98]',
                      ].join(' ')}
                    >
                      <div className={[
                        'flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-gray-100',
                        isUsed ? 'bg-gray-100' : `${module.bgColor} transition-transform group-hover:scale-110`,
                      ].join(' ')}>
                        <i className={`${module.icon} ${isUsed ? 'text-gray-400' : module.color} text-lg`} />
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="mb-1 flex items-center justify-between">
                          <h4 className={`truncate text-sm font-bold ${isUsed ? 'text-gray-500' : 'text-gray-800'}`}>
                            {module.title}
                          </h4>
                          <span className="ml-2 whitespace-nowrap rounded bg-gray-100 px-1.5 py-0.5 text-[10px] font-bold text-gray-500">
                            {module.category}
                          </span>
                        </div>
                        <p className="line-clamp-2 text-[11px] leading-tight text-gray-400">
                          <span className={`font-semibold ${isUsed ? 'text-gray-400' : isAvailableForBranch ? 'text-amber-500' : 'text-[#00C471]'}`}>
                            {isAvailableForBranch ? '+ 분기:' : '포함:'}
                          </span>{' '}
                          {module.topics.join(', ')}
                        </p>
                      </div>
                      {isUsed ? (
                        <div className="mt-2 flex h-6 w-6 items-center justify-center rounded-full bg-green-100 text-xs text-[#00C471]">
                          <i className="fas fa-check" />
                        </div>
                      ) : (
                        <i className={`mt-2 fas ${isAvailableForBranch ? 'fa-code-branch text-amber-400' : 'fa-plus-circle text-gray-300 group-hover:text-[#00C471]'} transition-colors`} />
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </aside>

        {/* ── 메인 캔버스 ── */}
        <main ref={mainRef} className="builder-dot-pattern relative flex-1 overflow-y-auto p-8">
          <div className="mx-auto max-w-3xl">
            <div className="mb-12 text-center">
              <h2 className="text-2xl font-extrabold text-gray-900">My Learning Roadmap</h2>
              <p className="mt-2 text-sm text-gray-500">
                왼쪽 템플릿에서 직군을 넘나들며 필요한 기술을 클릭해 나만의 로드맵을 완성하세요.
              </p>
            </div>

            <div className="builder-timeline relative pb-40 pl-8">

              {/* 시작 노드 */}
              <div className="relative z-10 mb-10 flex items-center">
                <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-full border-4 border-white bg-gray-900 text-white shadow-xl ring-1 ring-gray-100">
                  <i className="fas fa-flag-checkered text-xl" />
                </div>
                <div className="relative ml-8 w-full rounded-2xl border border-gray-200 bg-white p-5 shadow-sm">
                  <div className="absolute -left-2 top-1/2 h-4 w-4 -translate-y-1/2 rotate-45 border-b border-l border-gray-200 bg-white" />
                  <h3 className="text-lg font-bold text-gray-900">로드맵 설계 시작</h3>
                  <p className="mt-1 text-sm text-gray-500">
                    왼쪽 목록에서 원하는 챕터를{' '}
                    <strong className="text-[#00C471]">클릭</strong>하여 추가하세요.
                    척추 노드의 <i className="fas fa-code-branch text-amber-400" /> 버튼으로 분기를 만들 수 있습니다.
                  </p>
                </div>
              </div>

              {/* rows 렌더링 */}
              {rows.map((row) => (
                <div key={row.sortOrder} className="group relative z-10 mb-8 builder-step-enter">
                  {row.isBranching ? (
                    // ── 분기 row ──
                    <div className="flex items-start">
                      <div className="z-10 flex h-14 w-14 shrink-0 items-center justify-center rounded-full border-2 border-amber-400 bg-white text-xl font-black text-amber-500 shadow-lg">
                        {row.sortOrder}
                      </div>
                      <div className="ml-8 grid flex-1 grid-cols-2 gap-4">
                        {row.nodes.map((node, idx) => (
                          <BranchCard
                            key={node.instanceId}
                            node={node}
                            label={idx === 0 ? 'A' : 'B'}
                            onRemove={handleRemove}
                          />
                        ))}
                      </div>
                    </div>
                  ) : (
                    // ── 척추 row ──
                    <div className="flex items-start">
                      <div className="z-10 flex h-14 w-14 shrink-0 items-center justify-center rounded-full border-2 border-[#00C471] bg-white text-xl font-black text-[#00C471] shadow-lg transition-colors duration-300 group-hover:border-red-400 group-hover:bg-red-50 group-hover:text-red-500">
                        {row.sortOrder}
                      </div>
                      <SpineCard
                        node={row.nodes[0]}
                        onRemove={handleRemove}
                        onBranch={handleBranchActivate}
                        isBranchActive={branchTarget === row.sortOrder}
                      />
                    </div>
                  )}
                </div>
              ))}

              {/* 추가 유도 영역 */}
              <div className="relative z-10 mt-6 flex items-center">
                <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-full border-2 border-dashed border-gray-300 bg-white text-gray-300">
                  <i className="fas fa-mouse-pointer" />
                </div>
                <div className="ml-8 flex-1 rounded-2xl border-2 border-dashed border-[#CBD5E1] bg-white p-6 text-center font-bold text-[#94A3B8] shadow-sm">
                  <i className="fas fa-hand-pointer mb-2 block text-2xl text-gray-300" />
                  왼쪽 패널에서 학습할 모듈을 클릭하세요
                </div>
              </div>

            </div>
          </div>
        </main>
      </div>
    </div>
  )
}

// ────────────────────────────────────────────
// 척추 카드 컴포넌트
// ────────────────────────────────────────────

function SpineCard({
  node,
  onRemove,
  onBranch,
  isBranchActive,
}: {
  node: BuilderNode
  onRemove: (id: string) => void
  onBranch: (sortOrder: number) => void
  isBranchActive: boolean
}) {
  const { module, sortOrder, instanceId } = node
  return (
    <div className="group/card relative ml-8 w-full cursor-pointer rounded-2xl border border-gray-200 bg-white p-5 shadow-sm transition-all duration-300 hover:-translate-y-1 hover:border-[#00C471] hover:shadow-xl">
      <div className="absolute -left-2 top-7 h-4 w-4 -translate-y-1/2 rotate-45 border-b border-l border-gray-200 bg-white transition-colors duration-300 group-hover/card:border-[#00C471]" />

      <div className="absolute right-4 top-4 z-20 flex items-center gap-2 opacity-0 transition-all group-hover/card:opacity-100">
        <button
          type="button"
          onClick={(e) => { e.stopPropagation(); onBranch(sortOrder) }}
          title="이 위치에 분기 추가"
          className={[
            'rounded-md px-2 py-1 text-[11px] font-bold transition',
            isBranchActive
              ? 'bg-amber-100 text-amber-600'
              : 'text-amber-400 hover:bg-amber-50 hover:text-amber-500',
          ].join(' ')}
        >
          <i className="fas fa-code-branch mr-1" />분기
        </button>
        <button
          type="button"
          onClick={(e) => { e.stopPropagation(); onRemove(instanceId) }}
          className="text-gray-300 transition hover:text-red-500"
        >
          <i className="fas fa-trash-alt text-lg" />
        </button>
      </div>

      <div className="flex items-start gap-4">
        <div className={`mt-1 flex h-12 w-12 shrink-0 items-center justify-center rounded-xl border border-gray-100 text-2xl shadow-inner ${module.bgColor}`}>
          <i className={`${module.icon} ${module.color}`} />
        </div>
        <div className="min-w-0 flex-1 pr-24">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <h3 className="text-lg font-bold text-gray-900">{module.title}</h3>
            <span className="rounded-full border border-gray-200 bg-gray-100 px-2 py-0.5 text-[10px] font-bold text-gray-500">
              {module.category}
            </span>
          </div>
          <div className="mt-3 flex flex-wrap gap-1.5">
            {module.topics.map((topic) => (
              <span key={topic} className="inline-flex items-center rounded-md border border-gray-200 bg-gray-100 px-2 py-1 text-[10px] font-medium text-gray-600 shadow-sm">
                # {topic}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

// ────────────────────────────────────────────
// 분기 카드 컴포넌트
// ────────────────────────────────────────────

const BRANCH_COLORS: Record<string, { border: string; badge: string }> = {
  A: { border: 'border-amber-300 hover:border-amber-400', badge: 'bg-amber-100 text-amber-600' },
  B: { border: 'border-purple-300 hover:border-purple-400', badge: 'bg-purple-100 text-purple-600' },
}

function BranchCard({
  node,
  label,
  onRemove,
}: {
  node: BuilderNode
  label: 'A' | 'B'
  onRemove: (id: string) => void
}) {
  const { module, instanceId } = node
  const colors = BRANCH_COLORS[label]
  return (
    <div className={`group/card relative cursor-pointer rounded-2xl border bg-white p-4 shadow-sm transition-all duration-300 hover:-translate-y-1 hover:shadow-lg ${colors.border}`}>
      <span className={`absolute -top-2.5 left-4 rounded-full px-2 py-0.5 text-[10px] font-black ${colors.badge}`}>
        {label}
      </span>
      <button
        type="button"
        onClick={(e) => { e.stopPropagation(); onRemove(instanceId) }}
        className="absolute right-3 top-3 z-10 text-gray-300 opacity-0 transition-all group-hover/card:opacity-100 hover:text-red-500"
      >
        <i className="fas fa-trash-alt" />
      </button>

      <div className="flex items-start gap-3 pt-1">
        <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-gray-100 text-xl shadow-inner ${module.bgColor}`}>
          <i className={`${module.icon} ${module.color}`} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="mb-1.5 flex flex-wrap items-center gap-1.5">
            <h3 className="text-sm font-bold text-gray-900">{module.title}</h3>
            <span className="rounded-full border border-gray-200 bg-gray-100 px-1.5 py-0.5 text-[10px] font-bold text-gray-500">
              {module.category}
            </span>
          </div>
          <div className="flex flex-wrap gap-1">
            {module.topics.map((topic) => (
              <span key={topic} className="inline-flex items-center rounded-md border border-gray-200 bg-gray-100 px-1.5 py-0.5 text-[10px] font-medium text-gray-600">
                # {topic}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

export default MyRoadmapBuilderPage