// 강의 목록 메뉴 구성 전체를 내려받는 응답 구조다.
export interface CourseCatalogMenu {
  categories: CourseCatalogCategory[]
}

// 상단 네비게이션 한 칸에 해당하는 카테고리 구조다.
export interface CourseCatalogCategory {
  categoryKey: string
  label: string
  title: string
  iconClass: string
  sortOrder: number
  active: boolean
  megaMenuItems: CourseCatalogMegaMenuItem[]
  groups: CourseCatalogGroup[]
}

// 메가메뉴 컬럼 안에 노출되는 요약 항목이다.
export interface CourseCatalogMegaMenuItem {
  label: string
  sortOrder: number
}

// 카테고리 하단 필터 영역의 그룹 구조다.
export interface CourseCatalogGroup {
  name: string
  sortOrder: number
  items: CourseCatalogGroupItem[]
}

// 실제 필터 버튼 하나에 해당하는 항목이다.
export interface CourseCatalogGroupItem {
  name: string
  linkedCategoryKey: string | null
  sortOrder: number
}
