import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  DndContext,
  DragOverlay,
  PointerSensor,
  TouchSensor,
  useDraggable,
  useDroppable,
  useSensor,
  useSensors,
  type DragEndEvent,
  type DragStartEvent,
} from '@dnd-kit/core'
import { readStoredAuthSession } from '../lib/auth-session'
import { roadmapApi } from '../lib/api'
import type { RoadmapHubCatalog, RoadmapHubItem } from '../types/roadmap-hub'
import type { OfficialRoadmapDetail, OfficialRoadmapNode } from '../types/roadmap'

// ────────────────────────────────────────────
// 타입 정의
// ────────────────────────────────────────────

interface SkillModule {
  dbId: number
  source: 'BUILDER_MODULE' | 'OFFICIAL_NODE'
  builderModuleId: number | null
  originalNodeId: number | null
  id: string
  title: string
  category: string
  icon: string
  color: string
  bgColor: string
  topics: string[]
}

interface RoadmapTemplate {
  roadmapId: number
  label: string
  sectionTitle: string
  item: RoadmapHubItem
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

type ActiveDrag =
  | { kind: 'MODULE'; module: SkillModule }
  | { kind: 'NODE'; instanceId: string; sortOrder: number; branchGroup: number | null }

// ────────────────────────────────────────────
// 템플릿 매핑 유틸
// ────────────────────────────────────────────

function makeInstanceId() {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`
}

function getModuleUsageKey(module: SkillModule) {
  return `${module.source}:${module.source === 'OFFICIAL_NODE' ? module.originalNodeId : module.builderModuleId}`
}

function splitSubTopics(value?: string | null) {
  if (!value) return []
  return value
    .split(/[,;|]/)
    .map((topic) => topic.trim())
    .filter(Boolean)
}

function getNodeVisual(node: OfficialRoadmapNode) {
  if (node.branchGroup !== null && node.branchGroup !== undefined) {
    return { icon: 'fas fa-code-branch', color: 'text-amber-500', bgColor: 'bg-amber-50' }
  }

  switch ((node.nodeType ?? '').toUpperCase()) {
    case 'PRACTICE':
      return { icon: 'fas fa-laptop-code', color: 'text-blue-500', bgColor: 'bg-blue-50' }
    case 'PROJECT':
      return { icon: 'fas fa-cubes', color: 'text-violet-500', bgColor: 'bg-violet-50' }
    case 'ADVANCED':
      return { icon: 'fas fa-layer-group', color: 'text-rose-500', bgColor: 'bg-rose-50' }
    default:
      return { icon: 'fas fa-book-open', color: 'text-[#00C471]', bgColor: 'bg-green-50' }
  }
}

function mapOfficialNodeToModule(
  detail: OfficialRoadmapDetail,
  node: OfficialRoadmapNode,
  template: RoadmapTemplate | null,
): SkillModule {
  const visual = getNodeVisual(node)
  const topics = splitSubTopics(node.subTopics)

  return {
    dbId: -node.nodeId,
    source: 'OFFICIAL_NODE',
    builderModuleId: null,
    originalNodeId: node.nodeId,
    id: `official-${node.nodeId}`,
    title: node.title,
    category: template?.sectionTitle ?? detail.title,
    icon: visual.icon,
    color: visual.color,
    bgColor: visual.bgColor,
    topics: topics.length > 0 ? topics : [node.nodeType ?? detail.title],
  }
}

function mapDetailToModules(
  detail: OfficialRoadmapDetail,
  template: RoadmapTemplate | null,
) {
  return [...detail.nodes]
    .sort((a, b) => a.sortOrder - b.sortOrder || a.nodeId - b.nodeId)
    .map((node) => mapOfficialNodeToModule(detail, node, template))
}

function buildRoadmapTemplates(catalog: RoadmapHubCatalog): RoadmapTemplate[] {
  return catalog.sections
    .filter((section) => section.active)
    .sort((a, b) => a.sortOrder - b.sortOrder)
    .flatMap((section) =>
      section.items
        .filter((item) => item.active && item.linkedRoadmapId !== null)
        .sort((a, b) => a.sortOrder - b.sortOrder)
        .map((item) => ({
          roadmapId: item.linkedRoadmapId as number,
          label: item.title || item.linkedRoadmapTitle || `Roadmap ${item.linkedRoadmapId}`,
          sectionTitle: section.title,
          item,
        })),
    )
}

function filterRoadmapTemplates(
  templates: RoadmapTemplate[],
  section: string,
  keyword: string,
) {
  const q = keyword.trim().toLowerCase()
  return templates.filter((template) => {
    const matchesSection = section === 'ALL' || template.sectionTitle === section
    const matchesKeyword =
      !q ||
      template.label.toLowerCase().includes(q) ||
      template.sectionTitle.toLowerCase().includes(q) ||
      (template.item.subtitle ?? '').toLowerCase().includes(q) ||
      (template.item.linkedRoadmapTitle ?? '').toLowerCase().includes(q)

    return matchesSection && matchesKeyword
  })
}

// ────────────────────────────────────────────
// 메인 컴포넌트
// ────────────────────────────────────────────

function MyRoadmapBuilderPage() {
  const [session] = useState(() => readStoredAuthSession())
  const [templates, setTemplates] = useState<RoadmapTemplate[]>([])
  const [selectedRoadmapId, setSelectedRoadmapId] = useState<number | null>(null)
  const [templateSearch, setTemplateSearch] = useState('')
  const [templateSection, setTemplateSection] = useState('ALL')
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
  const [savedCustomRoadmapId, setSavedCustomRoadmapId] = useState<number | null>(null)
  const [showSuccessModal, setShowSuccessModal] = useState(false)
  const [activeDrag, setActiveDrag] = useState<ActiveDrag | null>(null)
  const mainRef = useRef<HTMLDivElement>(null)
  const titleInputRef = useRef<HTMLInputElement>(null)

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 8 } }),
    useSensor(TouchSensor, { activationConstraint: { delay: 250, tolerance: 5 } }),
  )

  // ── 로드맵 허브 템플릿 API 호출 ──
  const selectedTemplate = useMemo(
    () => templates.find((template) => template.roadmapId === selectedRoadmapId) ?? null,
    [templates, selectedRoadmapId],
  )

  const templateSections = useMemo(
    () => Array.from(new Set(templates.map((template) => template.sectionTitle))),
    [templates],
  )

  const filteredTemplates = useMemo(
    () => filterRoadmapTemplates(templates, templateSection, templateSearch),
    [templateSearch, templateSection, templates],
  )

  const templateOptions = filteredTemplates

  const loadSelectedRoadmap = useCallback(
    async (roadmapId: number, signal?: AbortSignal) => {
      setLoading(true)
      setFetchError(null)

      try {
        const detail = await roadmapApi.getOfficialRoadmapDetail(roadmapId, signal)
        const template = templates.find((item) => item.roadmapId === roadmapId) ?? null
        setItems(mapDetailToModules(detail, template))
        setBranchTarget(null)
      } catch (err) {
        if (err instanceof DOMException && err.name === 'AbortError') return
        setFetchError(err instanceof Error ? err.message : 'Failed to load roadmap template.')
      } finally {
        if (!signal?.aborted) setLoading(false)
      }
    },
    [templates],
  )

  const loadRoadmapCatalog = useCallback(async (signal?: AbortSignal) => {
    setLoading(true)
    setFetchError(null)

    try {
      const catalog = await roadmapApi.getHubCatalog(signal)
      const nextTemplates = buildRoadmapTemplates(catalog)
      setTemplates(nextTemplates)
      setSelectedRoadmapId((current) =>
        nextTemplates.some((template) => template.roadmapId === current)
          ? current
          : nextTemplates[0]?.roadmapId ?? null,
      )
      if (nextTemplates.length === 0) {
        setItems([])
        setNodes([])
      }
    } catch (err) {
      if (err instanceof DOMException && err.name === 'AbortError') return
      setFetchError(err instanceof Error ? err.message : 'Failed to load roadmap catalog.')
    } finally {
      if (!signal?.aborted) setLoading(false)
    }
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    void loadRoadmapCatalog(controller.signal)
    return () => controller.abort()
  }, [loadRoadmapCatalog])

  useEffect(() => {
    if (selectedRoadmapId === null || templates.length === 0) return
    const controller = new AbortController()
    void loadSelectedRoadmap(selectedRoadmapId, controller.signal)
    return () => controller.abort()
  }, [loadSelectedRoadmap, selectedRoadmapId, templates.length])

  const handleTemplateChange = useCallback((roadmapId: number) => {
    if (!Number.isFinite(roadmapId) || roadmapId <= 0) return
    setSelectedRoadmapId(roadmapId)
    setSearch('')
    setBranchTarget(null)
  }, [])

  const resetTemplateSelection = useCallback((nextSection: string, nextSearch: string) => {
    const nextTemplates = filterRoadmapTemplates(templates, nextSection, nextSearch)
    const nextRoadmapId = nextTemplates[0]?.roadmapId ?? null
    setSelectedRoadmapId(nextRoadmapId)
    setSearch('')
    setBranchTarget(null)

    if (nextRoadmapId === null) {
      setItems([])
    }
  }, [templates])

  const handleTemplateSearchChange = useCallback((value: string) => {
    setTemplateSearch(value)
    resetTemplateSelection(templateSection, value)
  }, [resetTemplateSelection, templateSection])

  const handleTemplateSectionChange = useCallback((value: string) => {
    setTemplateSection(value)
    resetTemplateSelection(value, templateSearch)
  }, [resetTemplateSelection, templateSearch])

  const reloadSelectedTemplate = useCallback(() => {
    if (selectedRoadmapId !== null) {
      void loadSelectedRoadmap(selectedRoadmapId)
    } else {
      void loadRoadmapCatalog()
    }
  }, [loadRoadmapCatalog, loadSelectedRoadmap, selectedRoadmapId])

  // 모달 열릴 때 포커스
  useEffect(() => {
    if (saveModalOpen) {
      setTimeout(() => titleInputRef.current?.focus(), 50)
    }
  }, [saveModalOpen])

  // dbId 기준 중복 방지 (크로스 카테고리 혼합 시에도 정확)
  const usedIds = useMemo(() => new Set(nodes.map((n) => getModuleUsageKey(n.module))), [nodes])

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
      if (usedIds.has(getModuleUsageKey(module))) return

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

  const handleSwapBranch = useCallback((sortOrder: number) => {
    setNodes((prev) =>
      prev.map((n) =>
        n.sortOrder === sortOrder && n.branchGroup !== null
          ? { ...n, branchGroup: n.branchGroup === 1 ? 2 : 1 }
          : n,
      ),
    )
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
      const res = await fetch(`/api/builder/roadmaps`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.accessToken ?? ''}`,
        },
        body: JSON.stringify({
          title: roadmapTitle.trim(),
          modules: nodes.map((n) => ({
            builderModuleId: n.module.source === 'BUILDER_MODULE' ? n.module.builderModuleId : null,
            originalNodeId: n.module.source === 'OFFICIAL_NODE' ? n.module.originalNodeId : null,
            sortOrder: n.sortOrder,
            branchGroup: n.branchGroup,
          })),
        }),
      })

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}))
        throw new Error((errData as { message?: string }).message ?? `저장 실패 (${res.status})`)
      }

      const data = await res.json()
      const customRoadmapId = (data.data as { customRoadmapId?: number }).customRoadmapId ?? null
      setSavedCustomRoadmapId(customRoadmapId)
      setSaveModalOpen(false)
      setNodes([])
      setBranchTarget(null)
      setRoadmapTitle('')
      setShowSuccessModal(true)
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : '저장 중 오류가 발생했습니다.')
    } finally {
      setSaving(false)
    }
  }, [session?.accessToken, roadmapTitle, nodes])

  // ── 드래그 핸들러 ──
  function handleDragStart(event: DragStartEvent) {
    setActiveDrag(event.active.data.current as ActiveDrag)
  }

  function handleDragEnd(event: DragEndEvent) {
    setActiveDrag(null)
    const { active, over } = event
    if (!over) return

    const drag = active.data.current as ActiveDrag
    const overId = String(over.id)

    if (drag.kind === 'MODULE') {
      if (usedIds.has(getModuleUsageKey(drag.module))) return

      if (overId.startsWith('gap-')) {
        const insertAfter = parseInt(overId.slice(4))
        const newSortOrder = insertAfter + 1
        setNodes((prev) => {
          const shifted = prev.map((n) =>
            n.sortOrder >= newSortOrder ? { ...n, sortOrder: n.sortOrder + 1 } : n,
          )
          return [
            ...shifted,
            { instanceId: makeInstanceId(), module: drag.module, sortOrder: newSortOrder, branchGroup: null },
          ]
        })
      } else if (overId.startsWith('on-spine-')) {
        const targetSortOrder = parseInt(overId.slice(9))
        setNodes((prev) => {
          const hasExistingBranch = prev.some(
            (n) => n.sortOrder === targetSortOrder && n.branchGroup !== null,
          )
          if (hasExistingBranch) return prev
          const updated = prev.map((n) =>
            n.sortOrder === targetSortOrder && n.branchGroup === null
              ? { ...n, branchGroup: 1 }
              : n,
          )
          return [
            ...updated,
            { instanceId: makeInstanceId(), module: drag.module, sortOrder: targetSortOrder, branchGroup: 2 },
          ]
        })
      }
    } else if (drag.kind === 'NODE') {
      if (overId === 'trash') {
        handleRemove(drag.instanceId)
      } else if (overId.startsWith('gap-') && drag.branchGroup === null) {
        const insertAfter = parseInt(overId.slice(4))
        const movingSortOrder = drag.sortOrder
        if (insertAfter === movingSortOrder) return
        setNodes((prev) => {
          const sortOrders = [...new Set(prev.map((n) => n.sortOrder))].sort((a, b) => a - b)
          const idx = sortOrders.indexOf(movingSortOrder)
          if (idx === -1) return prev
          sortOrders.splice(idx, 1)
          let insertIdx: number
          if (insertAfter === 0) {
            insertIdx = 0
          } else {
            insertIdx = sortOrders.findIndex((s) => s > insertAfter)
            if (insertIdx === -1) insertIdx = sortOrders.length
          }
          sortOrders.splice(insertIdx, 0, movingSortOrder)
          const mapping = new Map(sortOrders.map((old, i) => [old, i + 1]))
          return prev.map((n) => ({ ...n, sortOrder: mapping.get(n.sortOrder) ?? n.sortOrder }))
        })
      } else if (overId.startsWith('branch-swap-')) {
        const targetInstanceId = overId.slice(12)
        if (drag.branchGroup !== null) {
          setNodes((prev) => {
            const dragNode = prev.find((n) => n.instanceId === drag.instanceId)
            const targetNode = prev.find((n) => n.instanceId === targetInstanceId)
            if (!dragNode || !targetNode || dragNode.sortOrder !== targetNode.sortOrder) return prev
            return prev.map((n) => {
              if (n.instanceId === drag.instanceId) return { ...n, branchGroup: targetNode.branchGroup }
              if (n.instanceId === targetInstanceId) return { ...n, branchGroup: dragNode.branchGroup }
              return n
            })
          })
        }
      }
      // NODE → on-spine, 분기 NODE → gap: 무시
    }
  }

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

  // ── DnD 파생값 ──
  const isDraggingModule    = activeDrag?.kind === 'MODULE'
  const isDraggingNode      = activeDrag?.kind === 'NODE'
  const isDraggingSpineNode = activeDrag?.kind === 'NODE' && activeDrag.branchGroup === null
  const showGaps            = activeDrag !== null
  const draggedModule       = activeDrag?.kind === 'MODULE' ? activeDrag.module : null
  const terminalGapId       = rows.length === 0 ? 'gap-0' : `gap-${maxSortOrder}`

  // ────────────────────────────────────────────
  // 렌더
  // ────────────────────────────────────────────

  return (
    <DndContext sensors={sensors} onDragStart={handleDragStart} onDragEnd={handleDragEnd}>
    <div className="flex h-screen flex-col overflow-hidden bg-[#F8FAFC] text-[#0F172A]">

      {/* 저장 성공 모달 */}
      {showSuccessModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
          <div className="w-full max-w-sm rounded-2xl bg-white p-8 text-center shadow-2xl">
            <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-green-100">
              <i className="fas fa-check text-2xl text-[#00C471]" />
            </div>
            <h2 className="mb-1 text-xl font-extrabold text-gray-900">저장 완료!</h2>
            <p className="mb-6 text-sm text-gray-500">나만의 로드맵이 성공적으로 저장되었습니다.</p>
            <div className="flex flex-col gap-3">
              {savedCustomRoadmapId != null && (
                <button
                  type="button"
                  onClick={() => { window.location.href = `roadmap.html?id=${savedCustomRoadmapId}` }}
                  className="w-full rounded-lg bg-[#00C471] px-5 py-2.5 text-sm font-bold text-white transition hover:bg-green-600"
                >
                  <i className="fas fa-map mr-2" />나의 학습 로드맵으로 이동
                </button>
              )}
              <button
                type="button"
                onClick={() => setShowSuccessModal(false)}
                className="w-full rounded-lg border border-gray-300 px-5 py-2.5 text-sm font-bold text-gray-600 transition hover:bg-gray-50"
              >
                계속 편집하기
              </button>
            </div>
          </div>
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
            <div className="mb-2 grid grid-cols-1 gap-2">
              <div className="relative">
                <i className="fas fa-search absolute left-3 top-1/2 -translate-y-1/2 text-xs text-gray-400" />
                <input
                  type="text"
                  value={templateSearch}
                  onChange={(e) => handleTemplateSearchChange(e.target.value)}
                  placeholder="템플릿 검색"
                  className="w-full rounded-lg border border-gray-200 bg-white py-2 pl-8 pr-3 text-xs font-bold text-gray-700 shadow-sm transition focus:border-[#00C471] focus:outline-none focus:ring-2 focus:ring-[#00C471]/20"
                />
              </div>
              <select
                value={templateSection}
                onChange={(e) => handleTemplateSectionChange(e.target.value)}
                disabled={templates.length === 0}
                className="w-full min-w-0 cursor-pointer rounded-lg border border-gray-200 bg-white px-3 py-2 text-xs font-bold text-gray-700 shadow-sm focus:border-[#00C471] focus:outline-none focus:ring-2 focus:ring-[#00C471]/20"
              >
                <option value="ALL">전체 분야</option>
                {templateSections.map((section) => (
                  <option key={section} value={section}>{section}</option>
                ))}
              </select>
            </div>
            <div className="relative">
              <select
                value={selectedRoadmapId ?? ''}
                onChange={(e) => handleTemplateChange(Number(e.target.value))}
                disabled={templates.length === 0}
                className="w-full cursor-pointer appearance-none rounded-lg border border-gray-300 bg-white px-3 py-2.5 pr-8 text-sm font-bold text-gray-900 shadow-sm focus:border-transparent focus:outline-none focus:ring-2 focus:ring-[#00C471]"
              >
                {templates.length === 0 && <option value="">로드맵 템플릿 없음</option>}
                {templates.length > 0 && templateOptions.length === 0 && <option value="">필터 결과 없음</option>}
                {templateOptions.map((template) => (
                  <option key={template.roadmapId} value={template.roadmapId}>
                    {template.label} - {template.sectionTitle}
                  </option>
                ))}
              </select>
              <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-3 text-gray-400">
                <i className="fas fa-chevron-down text-xs" />
              </div>
            </div>
            {selectedTemplate && (
              <p className="mt-2 line-clamp-2 text-[11px] font-medium leading-relaxed text-gray-500">
                {selectedTemplate.item.subtitle ?? selectedTemplate.label}
              </p>
            )}
            {templates.length > 0 && (
              <p className="mt-2 text-[10px] font-bold text-gray-400">
                {filteredTemplates.length} / {templates.length}
              </p>
            )}
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
                    모듈을 클릭하거나 드래그하면 분기 노드로 추가됩니다.
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
                  onClick={reloadSelectedTemplate}
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
                  const isUsed = usedIds.has(getModuleUsageKey(module))
                  const isAvailableForBranch = branchTarget !== null && !isUsed
                  return (
                    <DraggableModuleCard
                      key={getModuleUsageKey(module)}
                      module={module}
                      isUsed={isUsed}
                      isAvailableForBranch={isAvailableForBranch}
                      onAdd={handleAdd}
                    />
                  )
                })}
              </div>
            )}
          </div>

          {/* 하단 드래그 힌트 */}
          <div className="shrink-0 border-t border-gray-100 bg-gray-50 px-4 py-2.5">
            <p className="text-center text-[11px] text-gray-400">
              <i className="fas fa-hand-pointer mr-1 text-[#00C471]" />클릭으로 추가 ·
              <i className="fas fa-arrows-alt mx-1 text-blue-400" />드래그로 위치 지정 · 순서 변경 · 분기 생성
            </p>
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
                    왼쪽 목록에서 모듈을{' '}
                    <strong className="text-[#00C471]">클릭</strong>하거나{' '}
                    <strong className="text-blue-500">드래그</strong>하여 원하는 위치에 추가하세요.
                    척추 노드 위에 드래그하면 분기를 만들 수 있습니다.
                  </p>
                </div>
              </div>

              {/* gap-0: rows 있을 때만 (없으면 TerminalDropZone이 gap-0 커버) */}
              {rows.length > 0 && (
                <DroppableGap id="gap-0" forModule={isDraggingModule} forSpineNode={isDraggingSpineNode} draggedModule={draggedModule} />
              )}

              {/* rows 렌더링 */}
              {rows.map((row, idx) => {
                const isDraggingThisRowBranch =
                  activeDrag?.kind === 'NODE' &&
                  activeDrag.branchGroup !== null &&
                  activeDrag.sortOrder === row.sortOrder
                const nodeA = row.nodes[0]
                const nodeB = row.nodes[1]

                return (
                  <div key={row.sortOrder}>
                    <div className="group relative z-10 mb-2 builder-step-enter">
                      {row.isBranching ? (
                        // ── 분기 row ──
                        <div className="flex items-start">
                          <div className="z-10 flex h-14 w-14 shrink-0 items-center justify-center rounded-full border-2 border-amber-400 bg-white text-xl font-black text-amber-500 shadow-lg">
                            {row.sortOrder}
                          </div>
                          <div className="relative ml-8 grid flex-1 grid-cols-2 gap-4">
                            {/* ⇄ 스왑 버튼 */}
                            {row.nodes.length === 2 && (
                              <button
                                type="button"
                                onClick={() => handleSwapBranch(row.sortOrder)}
                                className="absolute -top-3 left-1/2 z-20 -translate-x-1/2 rounded-full border border-gray-200 bg-white px-2.5 py-0.5 text-[11px] font-bold text-gray-400 opacity-0 shadow-sm transition-all group-hover:opacity-100 hover:border-amber-300 hover:text-amber-500"
                              >
                                ⇄ 순서 변경
                              </button>
                            )}
                            {row.nodes.length === 2 ? (
                              <>
                                <DraggableBranchCard
                                  node={nodeA}
                                  label="A"
                                  onRemove={handleRemove}
                                  isDraggingBranchSibling={isDraggingThisRowBranch && activeDrag?.instanceId !== nodeA.instanceId}
                                />
                                <DraggableBranchCard
                                  node={nodeB}
                                  label="B"
                                  onRemove={handleRemove}
                                  isDraggingBranchSibling={isDraggingThisRowBranch && activeDrag?.instanceId !== nodeB.instanceId}
                                />
                              </>
                            ) : (
                              row.nodes.map((node, i) => (
                                <DraggableBranchCard
                                  key={node.instanceId}
                                  node={node}
                                  label={i === 0 ? 'A' : 'B'}
                                  onRemove={handleRemove}
                                  isDraggingBranchSibling={false}
                                />
                              ))
                            )}
                          </div>
                        </div>
                      ) : (
                        // ── 척추 row ──
                        <div className="flex items-start">
                          <div className="z-10 flex h-14 w-14 shrink-0 items-center justify-center rounded-full border-2 border-[#00C471] bg-white text-xl font-black text-[#00C471] shadow-lg transition-colors duration-300 group-hover:border-red-400 group-hover:bg-red-50 group-hover:text-red-500">
                            {row.sortOrder}
                          </div>
                          <DraggableSpineCard
                            node={row.nodes[0]}
                            onRemove={handleRemove}
                            onBranch={handleBranchActivate}
                            isBranchActive={branchTarget === row.sortOrder}
                            isDraggingModule={isDraggingModule}
                          />
                        </div>
                      )}
                    </div>
                    {/* 마지막 row gap은 TerminalDropZone이 커버하므로 스킵 */}
                    {idx < rows.length - 1 && (
                      <DroppableGap
                        id={`gap-${row.sortOrder}`}
                        forModule={isDraggingModule}
                        forSpineNode={isDraggingSpineNode}
                        draggedModule={draggedModule}
                      />
                    )}
                  </div>
                )
              })}

              {/* TerminalDropZone: 힌트 박스 대체, 항상 렌더 */}
              <TerminalDropZone
                id={terminalGapId}
                showGaps={showGaps}
                forModule={isDraggingModule}
                forSpineNode={isDraggingSpineNode}
                draggedModule={draggedModule}
              />

            </div>
          </div>
        </main>
      </div>

      {/* TrashZone: 노드 드래그 중에만 표시 (fixed 우하단) */}
      {isDraggingNode && <TrashZone />}

      {/* DragOverlay */}
      <DragOverlay dropAnimation={null}>
        {activeDrag?.kind === 'MODULE' && (
          <MiniDragPreview
            title={activeDrag.module.title}
            icon={activeDrag.module.icon}
            color={activeDrag.module.color}
            bgColor={activeDrag.module.bgColor}
          />
        )}
        {activeDrag?.kind === 'NODE' && (
          <div className="flex cursor-grabbing items-center gap-2 rounded-xl border border-gray-200 bg-white px-4 py-3 text-sm font-bold text-gray-700 shadow-2xl">
            <i className="fas fa-grip-vertical text-gray-400" />
            {nodes.find((n) => n.instanceId === activeDrag.instanceId)?.module.title ?? ''}
          </div>
        )}
      </DragOverlay>

    </div>
    </DndContext>
  )
}

// ────────────────────────────────────────────
// TrashZone
// ────────────────────────────────────────────

function TrashZone() {
  const { isOver, setNodeRef } = useDroppable({ id: 'trash' })
  return (
    <div
      ref={setNodeRef}
      className={[
        'fixed bottom-8 right-8 z-50 flex items-center gap-2 rounded-2xl border-2 border-dashed px-6 py-4 text-sm font-bold shadow-2xl transition-all duration-200',
        isOver
          ? 'scale-110 border-red-400 bg-red-100 text-red-600'
          : 'border-red-300 bg-white text-red-400',
      ].join(' ')}
    >
      <i className={`fas fa-trash-alt text-lg ${isOver ? 'animate-bounce' : ''}`} />
      {isOver ? '놓아서 삭제' : '드래그하여 삭제'}
    </div>
  )
}

// ────────────────────────────────────────────
// TerminalDropZone (힌트 박스 대체, 항상 렌더)
// ────────────────────────────────────────────

function TerminalDropZone({
  id,
  showGaps,
  forModule,
  forSpineNode,
  draggedModule,
}: {
  id: string
  showGaps: boolean
  forModule: boolean
  forSpineNode: boolean
  draggedModule: SkillModule | null
}) {
  const { isOver, setNodeRef } = useDroppable({ id })

  // 드래그 없음 → 기존 힌트 박스
  if (!showGaps) {
    return (
      <div ref={setNodeRef} className="relative z-10 mt-6 flex items-center">
        <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-full border-2 border-dashed border-gray-300 bg-white text-gray-300">
          <i className="fas fa-mouse-pointer" />
        </div>
        <div className="ml-8 flex-1 rounded-2xl border-2 border-dashed border-[#CBD5E1] bg-white p-6 text-center font-bold text-[#94A3B8] shadow-sm">
          <i className="fas fa-hand-pointer mb-2 block text-2xl text-gray-300" />
          왼쪽 패널에서 모듈을 클릭하거나 드래그하세요
        </div>
      </div>
    )
  }

  // MODULE 드래그 + hover → 반투명 미리보기
  if (isOver && forModule && draggedModule) {
    return (
      <div ref={setNodeRef} className="z-20 mt-6">
        <ModuleDropPreview module={draggedModule} />
      </div>
    )
  }

  // MODULE 드래그 중 (not hover) → 초록 점선 초대
  if (forModule) {
    return (
      <div ref={setNodeRef} className="relative z-10 mt-6 flex items-center">
        <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-full border-2 border-dashed border-[#00C471] bg-white text-xl text-[#00C471]">
          <i className="fas fa-plus" />
        </div>
        <div className="ml-8 flex-1 rounded-2xl border-2 border-dashed border-[#00C471] bg-green-50 p-6 text-center font-bold text-[#00C471]">
          <i className="fas fa-arrow-down mb-2 block text-2xl opacity-60" />
          여기에 드래그하여 끝에 추가
        </div>
      </div>
    )
  }

  // Spine NODE 드래그 + hover → 파란 강조
  if (isOver && forSpineNode) {
    return (
      <div ref={setNodeRef} className="relative z-10 mt-6 flex items-center">
        <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-full border-2 border-blue-400 bg-blue-50 text-xl text-blue-500">
          <i className="fas fa-arrows-alt-v" />
        </div>
        <div className="ml-8 flex-1 rounded-2xl border-2 border-blue-400 bg-blue-50 p-6 text-center font-bold text-blue-500">
          여기에 놓기
        </div>
      </div>
    )
  }

  // Spine NODE 드래그 중 (not hover) → 연한 파란 점선
  return (
    <div ref={setNodeRef} className="relative z-10 mt-6 flex items-center">
      <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-full border-2 border-dashed border-blue-300 bg-white text-xl text-blue-300">
        <i className="fas fa-arrows-alt-v" />
      </div>
      <div className="ml-8 flex-1 rounded-2xl border-2 border-dashed border-blue-200 bg-white p-6 text-center font-bold text-blue-300">
        <i className="fas fa-arrow-down mb-2 block text-2xl opacity-40" />
        여기에 드래그하여 끝으로 이동
      </div>
    </div>
  )
}

// ────────────────────────────────────────────
// DroppableGap
// ────────────────────────────────────────────

function DroppableGap({
  id,
  forModule,
  forSpineNode,
  draggedModule,
}: {
  id: string
  forModule: boolean
  forSpineNode: boolean
  draggedModule: SkillModule | null
}) {
  const active = forModule || forSpineNode
  const { isOver, setNodeRef } = useDroppable({ id })

  // MODULE 드래그 중 hover → 반투명 미리보기
  if (isOver && forModule && draggedModule) {
    return (
      <div ref={setNodeRef} className="z-20 my-3">
        <ModuleDropPreview module={draggedModule} />
      </div>
    )
  }

  return (
    <div
      ref={setNodeRef}
      className={[
        'relative z-20 flex items-center justify-center transition-all duration-150',
        active ? 'my-2 min-h-[56px]' : 'h-2',
      ].join(' ')}
    >
      {active && (
        isOver && forSpineNode ? (
          <div className="mx-8 w-full rounded-xl border-2 border-blue-400 bg-blue-50 py-2 text-center text-xs font-bold text-blue-500">
            <i className="fas fa-arrows-alt-v mr-1" />여기에 이동
          </div>
        ) : (
          <div className={[
            'absolute inset-x-0 mx-8 rounded-full transition-all duration-150',
            forModule ? 'border border-dashed border-[#00C471] opacity-40' : 'border border-dashed border-blue-300 opacity-40',
          ].join(' ')} />
        )
      )}
    </div>
  )
}

// ────────────────────────────────────────────
// MiniDragPreview
// ────────────────────────────────────────────

function MiniDragPreview({
  title, icon, color, bgColor,
}: {
  title: string; icon: string; color: string; bgColor: string
}) {
  return (
    <div className="flex cursor-grabbing items-center gap-3 rounded-xl border border-gray-200 bg-white px-4 py-3 shadow-2xl">
      <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${bgColor}`}>
        <i className={`${icon} ${color} text-lg`} />
      </div>
      <span className="text-sm font-bold text-gray-800">{title}</span>
    </div>
  )
}

// ────────────────────────────────────────────
// ModuleDropPreview
// ────────────────────────────────────────────

function ModuleDropPreview({ module }: { module: SkillModule }) {
  return (
    <div className="pointer-events-none flex items-start opacity-50">
      <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-full border-2 border-dashed border-[#00C471] bg-white text-xl text-[#00C471]">
        <i className="fas fa-plus" />
      </div>
      <div className="relative ml-8 w-full rounded-2xl border-2 border-dashed border-[#00C471] bg-green-50 p-5">
        <div className="flex items-start gap-4">
          <div className={`mt-1 flex h-12 w-12 shrink-0 items-center justify-center rounded-xl border border-gray-100 text-2xl ${module.bgColor}`}>
            <i className={`${module.icon} ${module.color}`} />
          </div>
          <div className="min-w-0 flex-1">
            <h3 className="mb-2 text-lg font-bold text-gray-700">{module.title}</h3>
            <div className="flex flex-wrap gap-1.5">
              {module.topics.map((topic) => (
                <span key={topic} className="inline-flex items-center rounded-md bg-green-100 px-2 py-1 text-[10px] font-medium text-gray-500">
                  # {topic}
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ────────────────────────────────────────────
// DraggableModuleCard
// ────────────────────────────────────────────

function DraggableModuleCard({
  module,
  isUsed,
  isAvailableForBranch,
  onAdd,
}: {
  module: SkillModule
  isUsed: boolean
  isAvailableForBranch: boolean
  onAdd: (module: SkillModule) => void
}) {
  const { attributes, listeners, setNodeRef, isDragging } = useDraggable({
    id: `module-${getModuleUsageKey(module)}`,
    data: { kind: 'MODULE', module } as ActiveDrag,
    disabled: isUsed,
  })

  return (
    <div
      ref={setNodeRef}
      onClick={() => !isUsed && onAdd(module)}
      className={[
        'group flex items-start gap-3 rounded-xl border bg-white p-[14px] shadow-[0_1px_2px_rgba(0,0,0,0.02)] transition-all duration-200',
        isUsed
          ? 'cursor-not-allowed border-dashed border-[#CBD5E1] bg-[#F1F5F9] opacity-60'
          : isAvailableForBranch
            ? 'cursor-pointer border-amber-300 hover:-translate-y-0.5 hover:border-amber-400 hover:shadow-[0_4px_12px_rgba(245,158,11,0.15)]'
            : 'cursor-grab border-[#E2E8F0] hover:-translate-y-0.5 hover:border-[#00C471] hover:shadow-[0_4px_12px_rgba(0,196,113,0.1)]',
        isDragging ? 'opacity-40 scale-95' : '',
      ].join(' ')}
      {...(!isUsed ? attributes : {})}
      {...(!isUsed ? listeners : {})}
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
}

// ────────────────────────────────────────────
// DraggableSpineCard
// ────────────────────────────────────────────

function DraggableSpineCard({
  node,
  onRemove,
  onBranch,
  isBranchActive,
  isDraggingModule,
}: {
  node: BuilderNode
  onRemove: (id: string) => void
  onBranch: (sortOrder: number) => void
  isBranchActive: boolean
  isDraggingModule: boolean
}) {
  const { module, sortOrder, instanceId } = node

  const {
    attributes,
    listeners,
    setNodeRef: setDragRef,
    isDragging,
  } = useDraggable({
    id: `node-${instanceId}`,
    data: { kind: 'NODE', instanceId, sortOrder, branchGroup: null } as ActiveDrag,
  })

  const { isOver, setNodeRef: setDropRef } = useDroppable({
    id: `on-spine-${sortOrder}`,
  })

  const setRef = useCallback(
    (el: HTMLDivElement | null) => {
      setDragRef(el)
      setDropRef(el)
    },
    [setDragRef, setDropRef],
  )

  const showBranchHighlight = isOver && isDraggingModule

  return (
    <div
      ref={setRef}
      {...attributes}
      {...listeners}
      className={[
        'group/card relative ml-8 w-full cursor-grab rounded-2xl border bg-white p-5 shadow-sm transition-all duration-200 active:cursor-grabbing',
        isDragging
          ? 'scale-[0.98] border-dashed border-blue-300 opacity-30'
          : showBranchHighlight
            ? '-translate-y-0.5 border-amber-400 bg-amber-50 shadow-[0_4px_16px_rgba(245,158,11,0.2)]'
            : 'border-gray-200 hover:-translate-y-1 hover:border-[#00C471] hover:shadow-xl',
      ].join(' ')}
    >
      {/* 분기 드롭 힌트 오버레이 */}
      {showBranchHighlight && (
        <div className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center rounded-2xl">
          <span className="rounded-full bg-amber-500 px-3 py-1 text-xs font-black text-white shadow-lg">
            <i className="fas fa-code-branch mr-1" />여기에 분기 추가
          </span>
        </div>
      )}

      <div className="absolute -left-2 top-7 h-4 w-4 -translate-y-1/2 rotate-45 border-b border-l border-gray-200 bg-white transition-colors duration-300 group-hover/card:border-[#00C471]" />

      {/* 우측 액션 버튼 */}
      <div className="absolute right-4 top-4 z-20 flex items-center gap-2 opacity-0 transition-all group-hover/card:opacity-100">
        <button
          type="button"
          onPointerDown={(e) => e.stopPropagation()}
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
          onPointerDown={(e) => e.stopPropagation()}
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
// DraggableBranchCard
// ────────────────────────────────────────────

const BRANCH_COLORS: Record<string, { border: string; badge: string }> = {
  A: { border: 'border-amber-300 hover:border-amber-400', badge: 'bg-amber-100 text-amber-600' },
  B: { border: 'border-purple-300 hover:border-purple-400', badge: 'bg-purple-100 text-purple-600' },
}

function DraggableBranchCard({
  node,
  label,
  onRemove,
  isDraggingBranchSibling,
}: {
  node: BuilderNode
  label: 'A' | 'B'
  onRemove: (id: string) => void
  isDraggingBranchSibling: boolean
}) {
  const { module, instanceId, sortOrder, branchGroup } = node
  const colors = BRANCH_COLORS[label]

  const { attributes, listeners, setNodeRef: setDragRef, isDragging } = useDraggable({
    id: `node-${instanceId}`,
    data: { kind: 'NODE', instanceId, sortOrder, branchGroup } as ActiveDrag,
  })

  const { isOver: isSwapOver, setNodeRef: setSwapRef } = useDroppable({
    id: `branch-swap-${instanceId}`,
    disabled: !isDraggingBranchSibling,
  })

  const setRef = useCallback(
    (el: HTMLDivElement | null) => {
      setDragRef(el)
      setSwapRef(el)
    },
    [setDragRef, setSwapRef],
  )

  const showSwapHighlight = isSwapOver && isDraggingBranchSibling

  return (
    <div
      ref={setRef}
      {...attributes}
      {...listeners}
      className={[
        `group/card relative cursor-grab rounded-2xl border bg-white p-4 shadow-sm transition-all duration-200 active:cursor-grabbing ${colors.border}`,
        isDragging
          ? 'scale-[0.98] border-dashed opacity-30'
          : showSwapHighlight
            ? '-translate-y-0.5 border-amber-400 bg-amber-50 shadow-lg'
            : 'hover:-translate-y-1 hover:shadow-lg',
      ].join(' ')}
    >
      {/* 스왑 하이라이트 오버레이 */}
      {showSwapHighlight && (
        <div className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center rounded-2xl">
          <span className="rounded-full bg-amber-500 px-3 py-1 text-[11px] font-black text-white shadow-lg">
            <i className="fas fa-exchange-alt mr-1" />여기로 이동
          </span>
        </div>
      )}

      <span className={`absolute -top-2.5 left-4 rounded-full px-2 py-0.5 text-[10px] font-black ${colors.badge}`}>
        {label}
      </span>

      <button
        type="button"
        onPointerDown={(e) => e.stopPropagation()}
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
