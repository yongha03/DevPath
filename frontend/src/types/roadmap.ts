export type NodeStatus = 'COMPLETED' | 'IN_PROGRESS' | 'LOCKED' | 'PENDING'
export type ChangeType = 'ADD' | 'MODIFY' | 'DELETE'
export type DecisionStatus = 'PENDING' | 'APPLIED' | 'IGNORED'

export interface RoadmapNodeItem {
  customNodeId: number
  originalNodeId: number
  title: string
  sortOrder: number
  status: NodeStatus
  prerequisiteCustomNodeIds: number[]
  content?: string
  subTopics?: string[]
  branchGroup?: number | null
}

export interface RoadmapDetail {
  customRoadmapId: number
  originalRoadmapId: number
  title: string
  progressRate: number
  createdAt: string
  nodes: RoadmapNodeItem[]
}

export interface RecommendationChange {
  changeId: number
  sourceRecommendationId: number | null
  nodeId: number
  nodeTitle: string
  reason: string
  contextSummary: string
  nodeChangeType: ChangeType
  decisionStatus: DecisionStatus
  suggestedAt: string
  appliedAt: string | null
  ignoredAt: string | null
}

export interface RecommendationChangeHistory {
  changeId: number
  nodeId: number
  nodeTitle: string
  nodeChangeType: ChangeType
  decisionStatus: DecisionStatus
  updatedAt: string
}

export interface MyRoadmapSummary {
  customRoadmapId: number
  originalRoadmapId: number
  title: string
  createdAt: string
}

export interface ProofCardTagItem {
  tagId: number
  tagName: string
  evidenceType: string
}

export interface ProofCardSummary {
  proofCardId: number
  nodeId: number
  nodeTitle: string
  title: string
  status: string
  issuedAt: string
}
