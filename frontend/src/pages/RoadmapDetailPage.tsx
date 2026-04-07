import { type CSSProperties, useEffect, useRef, useState } from 'react'
import { roadmapApi } from '../lib/api'
import type {
  RoadmapDetail,
  RoadmapNodeItem,
  RecommendationChange,
  RecommendationChangeHistory,
  ProofCardSummary,
  NodeStatus,
  ChangeType,
} from '../types/roadmap'

// ── 헬퍼 ─────────────────────────────────────────────────────────────────────

function getNodeBoxClass(status: NodeStatus, change?: RecommendationChange): string {
  if (change) {
    if (change.nodeChangeType === 'ADD')    return 'node-box node-change-add'
    if (change.nodeChangeType === 'MODIFY') return 'node-box node-change-modify'
    if (change.nodeChangeType === 'DELETE') return 'node-box node-change-delete'
  }
  if (status === 'COMPLETED')   return 'node-box status-done'
  if (status === 'IN_PROGRESS') return 'node-box status-active'
  if (status === 'LOCKED')      return 'node-box status-locked'
  return 'node-box'  // PENDING: 기본 스타일 (클릭 가능)
}

function getChangeItemClass(type: ChangeType) {
  if (type === 'ADD')    return 'change-item new'
  if (type === 'MODIFY') return 'change-item modified'
  return 'change-item delete'
}

function changeBadgeStyle(type: ChangeType): CSSProperties {
  if (type === 'ADD')    return { background: '#3b82f6' }
  if (type === 'MODIFY') return { background: '#f59e0b' }
  return { background: '#ef4444' }
}

function changeTypeLabel(type: ChangeType) {
  if (type === 'ADD')    return '추가 제안'
  if (type === 'MODIFY') return '수정 제안'
  return '삭제 제안'
}

function changeTypeIcon(type: ChangeType) {
  if (type === 'ADD')    return 'fa-plus'
  if (type === 'MODIFY') return 'fa-edit'
  return 'fa-trash'
}

function changeChipStyle(type: ChangeType): string {
  if (type === 'ADD')    return 'text-xs font-bold text-blue-600 bg-blue-50 px-2 py-0.5 rounded'
  if (type === 'MODIFY') return 'text-xs font-bold text-orange-600 bg-orange-50 px-2 py-0.5 rounded'
  return 'text-xs font-bold text-red-600 bg-red-50 px-2 py-0.5 rounded'
}

function changeChipLabel(type: ChangeType) {
  if (type === 'ADD')    return '추가'
  if (type === 'MODIFY') return '수정'
  return '삭제'
}

// ── 서브 컴포넌트들 ───────────────────────────────────────────────────────────

interface ProofCardBadgeProps {
  card: ProofCardSummary
  side: 'left' | 'right'
}

function ProofCardBadge({ card, side }: ProofCardBadgeProps) {
  return (
    <div className={`proof-card-wrapper ${side}`} onClick={(e) => e.stopPropagation()}>
      {side === 'left' && (
        <>
          <div className="proof-card-box">
            <i className="fas fa-medal" style={{ color: '#f59e0b' }} />
            {card.title}
          </div>
          <div className="proof-card-line" />
        </>
      )}
      {side === 'right' && (
        <>
          <div className="proof-card-line" />
          <div className="proof-card-box">
            <i className="fas fa-medal" style={{ color: '#f59e0b' }} />
            {card.title}
          </div>
        </>
      )}
    </div>
  )
}

interface ChangeLabelProps {
  change: RecommendationChange
}

function ChangeLabel({ change }: ChangeLabelProps) {
  return (
    <div
      className="absolute flex items-center gap-1 px-3 py-1 rounded-full text-xs font-bold text-white shadow-lg"
      style={{
        top: '-32px',
        left: '50%',
        transform: 'translateX(-50%)',
        whiteSpace: 'nowrap',
        zIndex: 30,
        ...changeBadgeStyle(change.nodeChangeType),
      }}
    >
      <i className={`fas ${changeTypeIcon(change.nodeChangeType)}`} />
      {changeTypeLabel(change.nodeChangeType)}
    </div>
  )
}

interface NodeRowProps {
  node: RoadmapNodeItem
  index: number
  isFirst: boolean
  isLast: boolean
  proofCard?: ProofCardSummary
  pendingChange?: RecommendationChange
  onNodeClick?: (node: RoadmapNodeItem) => void
}

interface GhostAddNodeProps {
  change: RecommendationChange
  index: number
  isLast: boolean
  processing: boolean
  onApply: (id: number) => void
  onIgnore: (id: number) => void
}
function GhostAddNode({ change, index, isLast, processing, onApply, onIgnore }: GhostAddNodeProps) {
  const side = index % 2 === 0 ? 'right' : 'left'
  return (
    <div className={`roadmap-row${isLast ? ' node-last' : ''}`}>
      <div className="node-box node-change-add" style={{ color: '#1e40af' }}>
        <ChangeLabel change={change} />
        <div className="rule-badge" style={{ background: '#eff6ff', color: '#1e40af', borderColor: '#3b82f6' }}>
          ✨ 신규
        </div>
        <div className="node-header">
          <div className="node-title-group">
            <i className="fas fa-plus-circle text-blue-500" />
            <span>{change.nodeTitle}</span>
          </div>
        </div>
        <div className="node-desc">{change.contextSummary}</div>
        <div className="flex gap-2 mt-2">
          <button
            disabled={processing}
            onClick={() => onApply(change.changeId)}
            className="text-xs bg-blue-500 text-white px-3 py-1 rounded-lg font-bold hover:bg-blue-600 disabled:opacity-50"
          >
            추가 적용
          </button>
          <button
            disabled={processing}
            onClick={() => onIgnore(change.changeId)}
            className="text-xs bg-white text-gray-500 px-3 py-1 rounded-lg font-bold border border-gray-300 hover:bg-gray-100 disabled:opacity-50"
          >
            무시
          </button>
        </div>
      </div>
      <div className={`connector ${side}`} style={{ opacity: 0.3 }} />
    </div>
  )
}

function NodeRow({ node, index, isFirst, isLast, proofCard, pendingChange, onNodeClick }: NodeRowProps) {
  const side = index % 2 === 0 ? 'right' : 'left'
  const boxClass = [
    getNodeBoxClass(node.status, pendingChange),
    isFirst ? 'node-first' : '',
    isLast ? 'node-last' : '',
  ].filter(Boolean).join(' ')

  const wrapClass = [
    'roadmap-row',
    isFirst ? 'node-first' : '',
    isLast ? 'node-last' : '',
  ].filter(Boolean).join(' ')

  function handleClick() {
    if (node.status === 'LOCKED') {
      alert('이전 노드를 먼저 완료해야 합니다.')
      return
    }
    onNodeClick?.(node)
  }

  return (
    <div className={wrapClass}>
      <div className={boxClass} onClick={handleClick}>
        {/* 변경사항 라벨 */}
        {pendingChange && <ChangeLabel change={pendingChange} />}

        {/* Proof Card 배지 */}
        {proofCard && node.status === 'COMPLETED' && (
          <ProofCardBadge card={proofCard} side={side === 'right' ? 'left' : 'right'} />
        )}

        {/* 필수/선택 배지 */}
        <div className="rule-badge rule-all">✅ 필수</div>

        {/* 노드 헤더 */}
        <div className="node-header">
          <div className="node-title-group">
            {node.status === 'COMPLETED' && (
              <i className="fas fa-check-circle" style={{ color: '#00c471' }} />
            )}
            {node.status === 'IN_PROGRESS' && (
              <i className="fas fa-spinner" style={{ color: '#eab308' }} />
            )}
            {node.status === 'LOCKED' && (
              <i className="fas fa-lock" style={{ color: '#94a3b8' }} />
            )}
            {node.status === 'PENDING' && (
              <i className="fas fa-circle" style={{ color: '#cbd5e1' }} />
            )}
            <span>{node.title}</span>
          </div>
          {node.status === 'IN_PROGRESS' && (
            <div className="node-meta">
              <span className="meta-tag">진행중</span>
            </div>
          )}
        </div>

        {/* 노드 설명 */}
        {node.content && <div className="node-desc">{node.content}</div>}

        {/* 서브토픽 칩 */}
        {node.subTopics && node.subTopics.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-2">
            {node.subTopics.map((t) => (
              <span
                key={t}
                className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-slate-100 text-slate-500 border border-slate-200"
              >
                {t}
              </span>
            ))}
          </div>
        )}

        {/* 진행률 바 (IN_PROGRESS 전용) */}
        {node.status === 'IN_PROGRESS' && (
          <div className="progress-container">
            <div className="node-progress-bg">
              <div className="node-progress-bar" style={{ width: '40%' }} />
            </div>
            <span className="progress-pct">진행중</span>
          </div>
        )}
      </div>

      {/* 가로 연결선 + 서브노드 — Proof Card 태그를 서브노드로 표시 */}
      {proofCard && node.status === 'COMPLETED' && (
        <>
          <div className={`connector ${side}`} />
          <div className={`sub-group ${side}`}>
            <div className="sub-row">
              <div className="sub-node checked">
                <i className="fas fa-check text-xs mr-1" />
                증명 완료
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

// ── 노드 드로어 ───────────────────────────────────────────────────────────────

interface NodeDrawerProps {
  node: RoadmapNodeItem | null
  customRoadmapId: number
  onClose: () => void
  onCleared: () => void
}

function NodeDrawer({ node, customRoadmapId, onClose, onCleared }: NodeDrawerProps) {
  const [clearing, setClearing] = useState(false)

  if (!node) return null

  async function handleClear() {
    if (!node) return
    if (!confirm(`"${node.title}" 노드를 완료 처리하시겠습니까?`)) return
    setClearing(true)
    try {
      await roadmapApi.clearNode(customRoadmapId, node.customNodeId)
      onCleared()
      onClose()
    } catch (err) {
      alert((err as Error).message)
    } finally {
      setClearing(false)
    }
  }

  const canClear = node.status === 'PENDING' || node.status === 'IN_PROGRESS'

  return (
    <>
      <div className="drawer-overlay" onClick={onClose} />
      <aside className={`side-drawer${node ? ' open' : ''}`}>
        <div className="px-6 py-5 border-b border-gray-100 flex justify-between items-start bg-gray-50 shrink-0">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="text-[10px] font-bold text-white bg-black px-2 py-1 rounded">Topic</span>
              {node.status === 'COMPLETED' && (
                <span className="text-[10px] font-bold text-white bg-[#00c471] px-2 py-1 rounded">완료</span>
              )}
              {node.status === 'IN_PROGRESS' && (
                <span className="text-[10px] font-bold text-white bg-yellow-400 px-2 py-1 rounded">진행중</span>
              )}
            </div>
            <h2 className="text-3xl font-bold text-gray-900 leading-tight">{node.title}</h2>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 p-2">
            <i className="fas fa-times text-xl" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto custom-scrollbar p-6">
          <div className="text-gray-700 text-sm leading-7 mb-8">
            {node.content ?? '상세 내용 준비 중입니다.'}
          </div>
          <div className="mb-8">
            <h3 className="font-bold text-sm text-[#00c471] border-b border-gray-100 pb-2 mb-3">
              추천 무료 자료
            </h3>
            <p className="text-sm text-gray-400 text-center py-4">추천 자료 준비 중입니다.</p>
          </div>
        </div>
        <div className="p-6 border-t border-gray-100 bg-white space-y-3 shrink-0 shadow-[0_-4px_20px_rgba(0,0,0,0.05)]">
          {canClear && (
            <button
              onClick={handleClear}
              disabled={clearing}
              className="w-full bg-[#00c471] hover:bg-green-600 disabled:opacity-50 text-white py-4 rounded-xl font-bold text-sm flex justify-center items-center gap-2 transition"
            >
              {clearing
                ? <><i className="fas fa-spinner fa-spin" /> 처리 중...</>
                : <><i className="fas fa-check-circle" /> 이 노드 완료하기</>
              }
            </button>
          )}
          <button
            onClick={() => { window.location.href = 'lecture-list.html' }}
            className="w-full bg-white border border-gray-300 hover:bg-gray-50 text-gray-700 py-4 rounded-xl font-bold text-sm flex justify-center items-center gap-2 transition"
          >
            <i className="fas fa-list" /> 전체 강좌 목록 보기
          </button>
        </div>
      </aside>
    </>
  )
}

// ── 변경사항 패널 ─────────────────────────────────────────────────────────────

interface ChangesPanelProps {
  open: boolean
  onClose: () => void
  pendingChanges: RecommendationChange[]
  histories: RecommendationChangeHistory[]
  onApply: (changeId: number) => void
  onIgnore: (changeId: number) => void
  onApplyAll: () => void
  processing: boolean
}

type FilterType = 'all' | 'ADD' | 'MODIFY' | 'DELETE'

function ChangesPanel({
  open,
  onClose,
  pendingChanges,
  histories,
  onApply,
  onIgnore,
  onApplyAll,
  processing,
}: ChangesPanelProps) {
  const [tab, setTab] = useState<'pending' | 'history'>('pending')
  const [filter, setFilter] = useState<FilterType>('all')

  const filtered = filter === 'all'
    ? pendingChanges
    : pendingChanges.filter((c) => c.nodeChangeType === filter)

  return (
    <div id="changesPanel" className={`changes-panel${open ? ' open' : ''}`}>
      {/* 패널 헤더 */}
      <div className="flex justify-between items-center px-5 py-4 border-b border-gray-100 bg-gray-50">
        <h2 className="font-bold text-lg text-gray-900">로드맵 관리</h2>
        <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
          <i className="fas fa-times text-xl" />
        </button>
      </div>

      {/* 탭 */}
      <div className="flex border-b border-gray-100 bg-white">
        <button
          className={`tab-btn${tab === 'pending' ? ' active' : ''}`}
          onClick={() => setTab('pending')}
        >
          대기중 ({pendingChanges.length})
        </button>
        <button
          className={`tab-btn${tab === 'history' ? ' active' : ''}`}
          onClick={() => setTab('history')}
        >
          완료됨 ({histories.length})
        </button>
      </div>

      {/* 필터 (pending 탭에서만) */}
      {tab === 'pending' && (
        <div className="flex gap-2 p-3 bg-white border-b border-gray-100 overflow-x-auto">
          {(['all', 'ADD', 'MODIFY', 'DELETE'] as const).map((f) => (
            <button
              key={f}
              className={`filter-chip${filter === f ? ' active' : ''}`}
              onClick={() => setFilter(f)}
            >
              {f === 'all' ? '전체' : f === 'ADD' ? '추가' : f === 'MODIFY' ? '수정' : '삭제'}
            </button>
          ))}
        </div>
      )}

      {/* 목록 */}
      <div className="flex-1 overflow-y-auto p-4 custom-scrollbar bg-slate-50">
        {tab === 'pending' && (
          <div className="space-y-3">
            {filtered.length === 0 && (
              <div className="text-center text-xs text-gray-400 py-8">변경사항이 없습니다.</div>
            )}
            {filtered.map((change) => (
              <div key={change.changeId} className={getChangeItemClass(change.nodeChangeType)}>
                <div className="flex items-start gap-3">
                  <div
                    className="w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0"
                    style={{
                      background:
                        change.nodeChangeType === 'ADD' ? '#dbeafe' :
                        change.nodeChangeType === 'MODIFY' ? '#fed7aa' : '#fee2e2',
                    }}
                  >
                    <i
                      className={`fas ${changeTypeIcon(change.nodeChangeType)} text-sm`}
                      style={{
                        color:
                          change.nodeChangeType === 'ADD' ? '#2563eb' :
                          change.nodeChangeType === 'MODIFY' ? '#d97706' : '#dc2626',
                      }}
                    />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={changeChipStyle(change.nodeChangeType)}>
                        {changeChipLabel(change.nodeChangeType)}
                      </span>
                    </div>
                    <h4 className="font-bold text-sm text-gray-900 mb-1">
                      {change.nodeChangeType === 'DELETE' ? (
                        <span className="line-through opacity-60">{change.nodeTitle}</span>
                      ) : (
                        change.nodeTitle
                      )}
                    </h4>
                    <p className="text-xs text-gray-600 mb-3 line-clamp-2">{change.reason}</p>
                    <div className="flex gap-2">
                      <button
                        disabled={processing}
                        onClick={() => onApply(change.changeId)}
                        className="text-xs bg-[#00c471] text-white px-3 py-1.5 rounded-lg font-bold hover:bg-green-600 transition disabled:opacity-50"
                      >
                        적용
                      </button>
                      <button
                        disabled={processing}
                        onClick={() => onIgnore(change.changeId)}
                        className="text-xs bg-white text-gray-600 px-3 py-1.5 rounded-lg font-bold border border-gray-300 hover:bg-gray-100 transition disabled:opacity-50"
                      >
                        무시
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {tab === 'history' && (
          <div className="space-y-3">
            {histories.length === 0 && (
              <div className="text-center text-xs text-gray-400 py-8">적용된 변경사항이 없습니다.</div>
            )}
            {histories.map((h) => (
              <div key={h.changeId} className="bg-white rounded-lg border border-gray-200 p-3">
                <div className="flex items-center gap-2 mb-1">
                  <span className={changeChipStyle(h.nodeChangeType)}>{changeChipLabel(h.nodeChangeType)}</span>
                  <span className="text-xs text-gray-400">
                    {h.decisionStatus === 'APPLIED' ? '✅ 적용됨' : '🚫 무시됨'}
                  </span>
                </div>
                <p className="font-bold text-sm text-gray-800">{h.nodeTitle}</p>
                <p className="text-xs text-gray-400 mt-1">
                  {new Date(h.updatedAt).toLocaleDateString('ko-KR')}
                </p>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 하단 버튼 */}
      {tab === 'pending' && pendingChanges.length > 0 && (
        <div className="p-4 border-t border-gray-100 bg-white space-y-2">
          <button
            disabled={processing}
            onClick={onApplyAll}
            className="w-full bg-[#00c471] hover:bg-green-600 text-white py-3 rounded-xl font-bold text-sm shadow transition disabled:opacity-50 flex items-center justify-center gap-2"
          >
            <i className="fas fa-check" />
            변경사항 모두 적용하기
          </button>
        </div>
      )}
    </div>
  )
}

// ── 메인 페이지 ───────────────────────────────────────────────────────────────

export default function RoadmapDetailPage() {
  const params = new URLSearchParams(window.location.search)
  const customRoadmapId = Number(params.get('id'))
  const originalRoadmapId = Number(params.get('original'))

  const [roadmap, setRoadmap]       = useState<RoadmapDetail | null>(null)
  const [changes, setChanges]       = useState<RecommendationChange[]>([])
  const [histories, setHistories]   = useState<RecommendationChangeHistory[]>([])
  const [proofCards, setProofCards] = useState<ProofCardSummary[]>([])
  const [loading, setLoading]       = useState(true)
  const [error, setError]           = useState<string | null>(null)
  const [panelOpen, setPanelOpen]   = useState(false)
  const [infoOpen, setInfoOpen]     = useState(false)
  const [processing, setProcessing] = useState(false)
  const [drawerNode, setDrawerNode] = useState<RoadmapNodeItem | null>(null)
  const abortRef = useRef<AbortController | null>(null)

  useEffect(() => {
    const ctrl = new AbortController()
    abortRef.current = ctrl

    if (!customRoadmapId) {
      ;(async () => {
        try {
          if (originalRoadmapId) {
            try {
              const data = await roadmapApi.copyRoadmap(originalRoadmapId)
              window.location.replace(`roadmap.html?id=${data.customRoadmapId}`)
            } catch {
              // 이미 복사된 경우 기존 로드맵으로 이동
              const list = await roadmapApi.getMyRoadmaps(ctrl.signal)
              if (list.roadmaps.length > 0) {
                window.location.replace(`roadmap.html?id=${list.roadmaps[0].customRoadmapId}`)
              } else {
                window.location.replace('roadmap-hub.html')
              }
            }
          } else {
            const list = await roadmapApi.getMyRoadmaps(ctrl.signal)
            if (list.roadmaps.length > 0) {
              window.location.replace(`roadmap.html?id=${list.roadmaps[0].customRoadmapId}`)
            } else {
              window.location.replace('roadmap-hub.html')
            }
          }
        } catch {
          window.location.replace('roadmap-hub.html')
        }
      })()
      return () => ctrl.abort()
    }

    abortRef.current = new AbortController()
    const signal = abortRef.current.signal

    Promise.all([
      roadmapApi.getMyRoadmapDetail(customRoadmapId, signal),
      roadmapApi.getPendingChanges(signal),
      roadmapApi.getChangeHistories(signal),
      roadmapApi.getProofCards(signal),
    ])
      .then(([roadmapData, changesData, historiesData, proofCardsData]) => {
        setRoadmap(roadmapData)
        setChanges(changesData)
        setHistories(historiesData)
        setProofCards(proofCardsData)

        if (changesData.length > 0) {
          setTimeout(() => setPanelOpen(true), 800)
        }
      })
      .catch((err: Error) => {
        if (err.name !== 'AbortError') setError(err.message)
      })
      .finally(() => setLoading(false))

    return () => abortRef.current?.abort()
  }, [customRoadmapId])

  // ── 이벤트 핸들러 ────────────────────────────────────────────────────────────

  async function handleApply(changeId: number) {
    setProcessing(true)
    try {
      await roadmapApi.applyChange(changeId)
      const applied = changes.find((c) => c.changeId === changeId)
      setChanges((prev) => prev.filter((c) => c.changeId !== changeId))
      if (applied) {
        setHistories((prev) => [
          {
            changeId: applied.changeId,
            nodeId: applied.nodeId,
            nodeTitle: applied.nodeTitle,
            nodeChangeType: applied.nodeChangeType,
            decisionStatus: 'APPLIED',
            updatedAt: new Date().toISOString(),
          },
          ...prev,
        ])
      }
      // 로드맵 새로고침 (DELETE인 경우 백엔드가 아직 노드를 제거하지 않으므로 로컬에서 필터링)
      const updated = await roadmapApi.getMyRoadmapDetail(customRoadmapId)
      if (applied?.nodeChangeType === 'DELETE') {
        setRoadmap({ ...updated, nodes: updated.nodes.filter((n) => n.originalNodeId !== applied.nodeId) })
      } else {
        setRoadmap(updated)
      }
    } catch (err) {
      alert((err as Error).message)
    } finally {
      setProcessing(false)
    }
  }

  async function handleIgnore(changeId: number) {
    setProcessing(true)
    try {
      await roadmapApi.ignoreChange(changeId)
      const ignored = changes.find((c) => c.changeId === changeId)
      setChanges((prev) => prev.filter((c) => c.changeId !== changeId))
      if (ignored) {
        setHistories((prev) => [
          {
            changeId: ignored.changeId,
            nodeId: ignored.nodeId,
            nodeTitle: ignored.nodeTitle,
            nodeChangeType: ignored.nodeChangeType,
            decisionStatus: 'IGNORED',
            updatedAt: new Date().toISOString(),
          },
          ...prev,
        ])
      }
    } catch (err) {
      alert((err as Error).message)
    } finally {
      setProcessing(false)
    }
  }

  async function handleApplyAll() {
    if (!confirm(`${changes.length}개의 변경사항을 모두 적용하시겠습니까?`)) return
    setProcessing(true)
    try {
      for (const c of changes) {
        await roadmapApi.applyChange(c.changeId)
      }
      setHistories((prev) => [
        ...changes.map((c) => ({
          changeId: c.changeId,
          nodeId: c.nodeId,
          nodeTitle: c.nodeTitle,
          nodeChangeType: c.nodeChangeType,
          decisionStatus: 'APPLIED' as const,
          updatedAt: new Date().toISOString(),
        })),
        ...prev,
      ])
      const deleteNodeIds = new Set(changes.filter((c) => c.nodeChangeType === 'DELETE').map((c) => c.nodeId))
      setChanges([])
      const updated = await roadmapApi.getMyRoadmapDetail(customRoadmapId)
      if (deleteNodeIds.size > 0) {
        setRoadmap({ ...updated, nodes: updated.nodes.filter((n) => !deleteNodeIds.has(n.originalNodeId)) })
      } else {
        setRoadmap(updated)
      }
    } catch (err) {
      alert((err as Error).message)
    } finally {
      setProcessing(false)
    }
  }

  // ── 파생 데이터 ──────────────────────────────────────────────────────────────

  const proofCardByNodeId = Object.fromEntries(proofCards.map((p) => [p.nodeId, p]))
  const changeByNodeId = Object.fromEntries(
    changes
      .filter((c) => c.nodeChangeType !== 'ADD')
      .map((c) => [c.nodeId, c]),
  )
  const addChanges = changes.filter((c) => c.nodeChangeType === 'ADD')

  const totalNodes = (roadmap?.nodes.length ?? 0) + addChanges.length
  const doneNodes  = roadmap?.nodes.filter((n) => n.status === 'COMPLETED').length ?? 0
  const progressPct = roadmap ? Math.round(roadmap.progressRate) : 0

  // ── 렌더 ─────────────────────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-50">
        <div className="text-center">
          <i className="fas fa-spinner fa-spin text-3xl text-[#00c471] mb-3" />
          <p className="text-sm text-gray-500">로드맵을 불러오는 중...</p>
        </div>
      </div>
    )
  }

  if (error || !roadmap) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-50">
        <div className="text-center">
          <i className="fas fa-exclamation-circle text-3xl text-red-400 mb-3" />
          <p className="text-sm text-gray-600">{error ?? '로드맵을 불러올 수 없습니다.'}</p>
          <button
            onClick={() => window.location.reload()}
            className="mt-4 px-4 py-2 bg-[#00c471] text-white text-sm font-bold rounded-lg"
          >
            다시 시도
          </button>
        </div>
      </div>
    )
  }

  const sortedNodes = [...roadmap.nodes].sort((a, b) => a.sortOrder - b.sortOrder)

  // ── 분기 레이아웃 계산 ─────────────────────────────────────────────────────
  const leftBranchNodes  = sortedNodes.filter((n) => n.branchGroup === 1)
  const rightBranchNodes = sortedNodes.filter((n) => n.branchGroup === 2)
  const hasBranch = leftBranchNodes.length > 0 || rightBranchNodes.length > 0

  const branchSortOrders = new Set(
    [...leftBranchNodes, ...rightBranchNodes].map((n) => n.sortOrder),
  )
  const preSpineNodes  = hasBranch ? sortedNodes.filter((n) => n.branchGroup == null && !branchSortOrders.has(n.sortOrder) && n.sortOrder < Math.min(...branchSortOrders)) : sortedNodes
  const postSpineNodes = hasBranch ? sortedNodes.filter((n) => n.branchGroup == null && !branchSortOrders.has(n.sortOrder) && n.sortOrder > Math.max(...branchSortOrders)) : []

  // 연속 인덱스 맵 (렌더 중 mutation 방지)
  const nodeIndexMap = new Map<number, number>()
  let _idx = 0
  ;(hasBranch ? preSpineNodes : sortedNodes).forEach((n) => { nodeIndexMap.set(n.customNodeId, _idx++) })
  if (hasBranch) {
    const branchStart = _idx
    leftBranchNodes.forEach((n, i) => nodeIndexMap.set(n.customNodeId, branchStart + i))
    rightBranchNodes.forEach((n, i) => nodeIndexMap.set(n.customNodeId, branchStart + i))
    _idx += Math.max(leftBranchNodes.length, rightBranchNodes.length)
    postSpineNodes.forEach((n) => { nodeIndexMap.set(n.customNodeId, _idx++) })
  }
  const addChangesStartIdx = _idx

  // ADD 변경사항을 nodeSortOrder 기준으로 정렬 후 분기 전/후로 분류
  type SpineItem =
    | { kind: 'node'; node: RoadmapNodeItem }
    | { kind: 'add'; change: RecommendationChange }

  const minBranchOrder = hasBranch ? Math.min(...branchSortOrders) : Infinity
  const maxBranchOrder = hasBranch ? Math.max(...branchSortOrders) : -Infinity
  const sortedAddChanges = [...addChanges].sort(
    (a, b) => (a.nodeSortOrder ?? 999) - (b.nodeSortOrder ?? 999),
  )
  const preAddChanges  = hasBranch
    ? sortedAddChanges.filter((c) => (c.nodeSortOrder ?? 999) < minBranchOrder)
    : sortedAddChanges
  const postAddChanges = hasBranch
    ? sortedAddChanges.filter((c) => (c.nodeSortOrder ?? 999) > maxBranchOrder)
    : []

  const makeSpineItems = (nodes: RoadmapNodeItem[], adds: RecommendationChange[]): SpineItem[] =>
    [
      ...nodes.map((n) => ({ kind: 'node' as const, node: n })),
      ...adds.map((c) => ({ kind: 'add' as const, change: c })),
    ].sort((a, b) => {
      const aOrd = a.kind === 'node' ? a.node.sortOrder : (a.change.nodeSortOrder ?? 999)
      const bOrd = b.kind === 'node' ? b.node.sortOrder : (b.change.nodeSortOrder ?? 999)
      return aOrd - bOrd
    })

  const preSpineItems  = makeSpineItems(hasBranch ? preSpineNodes : sortedNodes, preAddChanges)
  const postSpineItems = makeSpineItems(postSpineNodes, postAddChanges)

  // [DEBUG] 브라우저 콘솔에서 확인 후 삭제
  console.log('[DEBUG] hasBranch:', hasBranch, 'minBranchOrder:', minBranchOrder, 'maxBranchOrder:', maxBranchOrder)
  console.log('[DEBUG] addChanges:', addChanges.map(c => ({ title: c.nodeTitle, nodeSortOrder: c.nodeSortOrder, type: c.nodeChangeType })))
  console.log('[DEBUG] preAddChanges:', preAddChanges.length, 'postAddChanges:', postAddChanges.length)

  return (
    <div className="overflow-x-hidden text-gray-800">

      {/* ── 헤더 ──────────────────────────────────────────────────────────────── */}
      <header className="app-header">
        <div className="max-w-[1600px] mx-auto w-full px-6 h-full grid items-center gap-4" style={{ gridTemplateColumns: 'auto 1fr auto' }}>
          {/* 왼쪽: 뒤로 + 로고 */}
          <div className="flex items-center gap-4 shrink-0">
            <a
              href="roadmap-hub.html"
              className="text-gray-500 hover:text-gray-800 font-bold text-sm flex items-center gap-1"
            >
              <i className="fas fa-arrow-left" /> 목록
            </a>
            <a href="home.html" className="flex items-center gap-2 font-bold text-gray-900">
              <i className="fas fa-code-branch text-[#00c471]" />
              <span>DevPath</span>
            </a>
          </div>

          {/* 가운데: 네비게이션 */}
          <nav className="flex justify-center overflow-x-auto">
            <div className="header-nav-links text-sm font-bold text-gray-500">
              <a href="roadmap-hub.html" className="text-[#00c471] border-b-2 border-[#00c471] pb-1 transition">로드맵</a>
              <a href="lecture-list.html" className="hover:text-[#00c471] transition">강의</a>
              <a href="project-list.html" className="hover:text-[#00c471] transition">프로젝트</a>
              <a href="community-list.html" className="hover:text-[#00c471] transition">커뮤니티</a>
              <a href="job-matching.html" className="hover:text-[#00c471] transition">채용분석</a>
            </div>
          </nav>

          {/* 오른쪽: 변경사항 버튼 + 노드 카운트 + 진행률 + 프로필 */}
          <div className="flex items-center gap-3 shrink-0">
            {/* 변경사항 버튼 */}
            <button
              onClick={() => setPanelOpen((v) => !v)}
              className="relative flex items-center gap-2 px-3 py-1.5 bg-slate-100 text-slate-700 rounded-lg hover:bg-slate-200 transition text-xs font-bold"
            >
              <i className="fas fa-history" />
              <span>변경사항</span>
              {changes.length > 0 && (
                <span className="badge-pulse absolute -top-1 -right-1 bg-red-500 text-white text-[10px] w-4 h-4 rounded-full flex items-center justify-center font-bold shadow-sm">
                  {changes.length}
                </span>
              )}
            </button>

            {/* 노드 카운트 */}
            <div className="node-count-wrap" title="전체 / 완료">
              <div className="node-count-card total">
                <span className="node-count-number">{totalNodes}</span>
                <span className="node-count-label">전체</span>
              </div>
              <div className="node-count-card done">
                <span className="node-count-number">{doneNodes}</span>
                <span className="node-count-label">완료</span>
              </div>
            </div>

            {/* 진행률 */}
            <div className="flex items-center gap-2 pl-3 border-l border-gray-200">
              <span className="text-xs text-gray-500">진행률</span>
              <div className="w-20 h-2 bg-gray-100 rounded-full overflow-hidden">
                <div className="h-full bg-[#00c471]" style={{ width: `${progressPct}%` }} />
              </div>
              <span className="text-xs font-bold text-[#00c471]">{progressPct}%</span>
            </div>

            {/* 프로필 */}
            <div
              className="flex items-center gap-2 cursor-pointer ml-1"
              onClick={() => { window.location.href = 'profile.html' }}
            >
              <img
                src="https://api.dicebear.com/7.x/avataaars/svg?seed=Felix"
                className="w-9 h-9 rounded-full border border-gray-200 shadow-sm"
                alt="me"
              />
            </div>
          </div>
        </div>
      </header>

      {/* ── 노드 드로어 ──────────────────────────────────────────────────────── */}
      <NodeDrawer
        node={drawerNode}
        customRoadmapId={customRoadmapId}
        onClose={() => setDrawerNode(null)}
        onCleared={async () => {
          const updated = await roadmapApi.getMyRoadmapDetail(customRoadmapId)
          setRoadmap(updated)
        }}
      />

      {/* ── 변경사항 패널 ─────────────────────────────────────────────────────── */}
      <ChangesPanel
        open={panelOpen}
        onClose={() => setPanelOpen(false)}
        pendingChanges={changes}
        histories={histories}
        onApply={handleApply}
        onIgnore={handleIgnore}
        onApplyAll={handleApplyAll}
        processing={processing}
      />

      {/* ── 메인 콘텐츠 ───────────────────────────────────────────────────────── */}
      <main className="relative pt-28 pb-24 w-full max-w-[1400px] mx-auto min-h-screen">

        {/* 로드맵 카테고리 라벨 */}
        <div className="fixed left-8 top-[76px] z-[60]">
          <div className="flex items-center gap-2 text-sm font-extrabold text-gray-800 bg-white/80 backdrop-blur px-3 py-2 rounded-lg border border-gray-200 shadow-sm">
            <i className="fas fa-server text-[#00c471]" />
            <span>{roadmap.title}</span>
          </div>
        </div>

        <div className="relative flex flex-col items-center w-full">

          {/* ── 정보 아코디언 ────────────────────────────────────────────────── */}
          <div className="w-full max-w-4xl px-4 mb-16 relative z-20">
            <div className="bg-white border border-gray-200 rounded-lg shadow-sm overflow-hidden">
              <div
                className="flex justify-between items-center p-4 cursor-pointer hover:bg-gray-50 transition"
                onClick={() => setInfoOpen((v) => !v)}
              >
                <div className="flex items-center gap-2 font-bold text-gray-800">
                  <i className="fas fa-info-circle text-gray-400" />
                  이 로드맵이란 무엇인가요?
                </div>
                <i className={`fas fa-chevron-down text-gray-400 chevron${infoOpen ? ' rotate' : ''}`} />
              </div>
              <div className={`info-accordion${infoOpen ? ' open' : ''} bg-gray-50 border-t border-gray-100`}>
                <div className="p-6 text-sm text-gray-700 leading-relaxed space-y-3">
                  <p>
                    <strong className="text-gray-900">{roadmap.title}</strong>는 DevPath에서 제공하는
                    학습 로드맵입니다. AI가 학습 이력을 분석해 노드 변경사항을 제안하며,
                    각 노드를 완료하면 <strong>Proof Card</strong>가 발급됩니다.
                  </p>
                  <p className="text-xs text-gray-500">
                    생성일: {new Date(roadmap.createdAt).toLocaleDateString('ko-KR')}
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* ── 로드맵 트리 ─────────────────────────────────────────────────── */}
          <div className="relative w-full">

            {/* 척추 앞부분 (ADD ghost 노드 포함) */}
            {preSpineItems.map((item, i) => {
              if (item.kind === 'add') {
                const change = item.change
                return <GhostAddNode key={`add-${change.changeId}`} change={change} index={i} isLast={false} processing={processing} onApply={handleApply} onIgnore={handleIgnore} />
              }
              const node = item.node
              const idx = nodeIndexMap.get(node.customNodeId) ?? 0
              return (
                <NodeRow
                  key={node.customNodeId}
                  node={node}
                  index={idx}
                  isFirst={idx === 0}
                  isLast={false}
                  proofCard={proofCardByNodeId[node.originalNodeId]}
                  pendingChange={changeByNodeId[node.originalNodeId]}
                  onNodeClick={setDrawerNode}
                />
              )
            })}

            {/* 분기 구간 */}
            {hasBranch && (() => {
              return (
                <div
                  className={[
                    'tree-branch-container',
                    preSpineNodes.length === 0 ? 'branch-first' : '',
                    postSpineItems.length === 0 ? 'branch-last' : '',
                  ].filter(Boolean).join(' ')}
                >
                  {/* 왼쪽 가지 */}
                  <div className="tree-branch branch-left">
                    {leftBranchNodes.map((node) => (
                      <NodeRow
                        key={node.customNodeId}
                        node={node}
                        index={nodeIndexMap.get(node.customNodeId) ?? 0}
                        isFirst={false}
                        isLast={false}
                        proofCard={proofCardByNodeId[node.originalNodeId]}
                        pendingChange={changeByNodeId[node.originalNodeId]}
                        onNodeClick={setDrawerNode}
                      />
                    ))}
                  </div>

                  <div className="branch-divider" />

                  {/* 오른쪽 가지 */}
                  <div className="tree-branch branch-right">
                    {rightBranchNodes.map((node) => (
                      <NodeRow
                        key={node.customNodeId}
                        node={node}
                        index={nodeIndexMap.get(node.customNodeId) ?? 0}
                        isFirst={false}
                        isLast={false}
                        proofCard={proofCardByNodeId[node.originalNodeId]}
                        pendingChange={changeByNodeId[node.originalNodeId]}
                        onNodeClick={setDrawerNode}
                      />
                    ))}
                  </div>
                </div>
              )
            })()}

            {/* 척추 뒷부분 (ADD ghost 노드 포함) */}
            {postSpineItems.map((item, i) => {
              const isLast = i === postSpineItems.length - 1
              if (item.kind === 'add') {
                const change = item.change
                return <GhostAddNode key={`add-${change.changeId}`} change={change} index={addChangesStartIdx + i} isLast={isLast} processing={processing} onApply={handleApply} onIgnore={handleIgnore} />
              }
              const node = item.node
              const idx = nodeIndexMap.get(node.customNodeId) ?? 0
              return (
                <NodeRow
                  key={node.customNodeId}
                  node={node}
                  index={idx}
                  isFirst={false}
                  isLast={isLast && addChanges.length === 0}
                  proofCard={proofCardByNodeId[node.originalNodeId]}
                  pendingChange={changeByNodeId[node.originalNodeId]}
                  onNodeClick={setDrawerNode}
                />
              )
            })}

          </div>

          {/* ── 완료 섹션 ──────────────────────────────────────────────────── */}
          <div className="flex justify-center items-center py-8 relative z-20">
            {progressPct === 100 ? (
              <div className="text-center">
                <div className="inline-flex items-center justify-center w-20 h-20 rounded-full bg-gradient-to-br from-[#00c471] to-[#00e887] shadow-lg mb-6 animate-pulse">
                  <i className="fas fa-trophy text-white text-3xl" />
                </div>
                <h3 className="text-2xl font-black text-gray-900 mb-3">🎉 로드맵 완료!</h3>
                <p className="text-gray-600 text-sm max-w-md mx-auto leading-relaxed">
                  {roadmap.title}의 모든 과정을 마스터하셨습니다.<br />
                  이제 실전 프로젝트로 나아갈 준비가 되었습니다!
                </p>
                <div className="mt-8 flex gap-3 justify-center">
                  <button
                    onClick={() => { window.location.href = 'project-list.html' }}
                    className="px-6 py-3 bg-[#00c471] hover:bg-green-600 text-white rounded-xl font-bold text-sm shadow-lg transition flex items-center gap-2"
                  >
                    <i className="fas fa-rocket" /> 프로젝트 시작하기
                  </button>
                  <button
                    onClick={() => { window.location.href = 'roadmap-hub.html' }}
                    className="px-6 py-3 bg-white hover:bg-gray-50 text-gray-700 rounded-xl font-bold text-sm border-2 border-gray-200 transition flex items-center gap-2"
                  >
                    <i className="fas fa-map" /> 다른 로드맵 보러가기
                  </button>
                </div>
              </div>
            ) : (
              <div className="text-center opacity-30">
                <i className="fas fa-trophy text-4xl text-gray-400 mb-2" />
                <p className="text-xs text-gray-400 font-bold">모든 노드를 완료하면 트로피를 받습니다</p>
              </div>
            )}
          </div>

        </div>
      </main>
    </div>
  )
}
