// 로드맵 허브 공개 화면과 관리자 편집기에서 공통으로 쓰는 카탈로그 구조다.
export interface RoadmapHubCatalog {
  sections: RoadmapHubSection[]
}

// 허브 한 섹션은 레이아웃 타입과 표시 순서를 함께 가진다.
export interface RoadmapHubSection {
  sectionKey: string
  title: string
  description: string | null
  layoutType: 'CARD_GRID' | 'CHIP_GRID' | 'LINK_LIST' | string
  sortOrder: number
  active: boolean
  items: RoadmapHubItem[]
}

// 허브 항목은 표시 텍스트와 연결할 공식 로드맵 정보를 함께 가진다.
export interface RoadmapHubItem {
  title: string
  subtitle: string | null
  iconClass: string | null
  iconColor: string | null
  sortOrder: number
  active: boolean
  featured: boolean
  linkedRoadmapId: number | null
  linkedRoadmapTitle: string | null
}

// 관리자 편집기에서는 공식 로드맵 선택 목록도 함께 내려받는다.
export interface AdminRoadmapHubCatalog extends RoadmapHubCatalog {
  officialRoadmaps: AdminRoadmapHubOption[]
}

export interface AdminRoadmapHubOption {
  roadmapId: number
  title: string
}
