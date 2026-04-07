import type { CourseDifficulty, CourseListItem } from './types/course'

export type LectureCategoryKey = 'all' | 'dev' | 'ai' | 'data' | 'infra' | 'mobile' | 'career'
export type LectureSortKey = 'recommended' | 'latest' | 'priceAsc' | 'priceDesc' | 'title'
export type LectureDifficultyFilter = 'ALL' | Exclude<CourseDifficulty, null>
export type LecturePriceFilter = 'ALL' | 'FREE' | 'UNDER_50000' | 'UNDER_100000' | 'OVER_100000'

export type LectureCategoryGroup = {
  name: string
  tags: string[]
}

export type LectureCategoryConfig = {
  key: LectureCategoryKey
  label: string
  icon: string
  title: string
  megaMenuItems: string[]
  groups: LectureCategoryGroup[]
}

export type LectureCourse = CourseListItem & {
  categoryKey: Exclude<LectureCategoryKey, 'all'>
  categoryLabel: string
  displayCategory: string
  rating: number
  reviewCount: number
  badge: string | null
  roadmapLinked: boolean
  searchIndex: string
}

export const lectureCategoryConfigs: LectureCategoryConfig[] = [
  {
    key: 'all',
    label: '전체',
    icon: 'fas fa-th-large',
    title: '전체 강의',
    megaMenuItems: [],
    groups: [
      { name: '탐색 분야', tags: ['웹 개발', 'AI/머신러닝', '데이터 분석', '인프라', '모바일 앱', '커리어'] },
    ],
  },
  {
    key: 'dev',
    label: '개발',
    icon: 'fas fa-laptop-code',
    title: '개발 · 프로그래밍',
    megaMenuItems: ['웹 개발 (Web)', '프론트엔드', '백엔드', '풀스택', '게임 개발', '프로그래밍 언어'],
    groups: [
      { name: '언어 (Language)', tags: ['Java', 'Python', 'JavaScript', 'TypeScript', 'C++', 'C#', 'Go', 'Rust', 'Kotlin', 'Swift'] },
      { name: '프론트엔드', tags: ['React', 'Vue.js', 'Angular', 'Svelte', 'Next.js', 'HTML/CSS', 'Tailwind'] },
      { name: '백엔드', tags: ['Spring Boot', 'Node.js', 'Django', 'FastAPI', 'NestJS', 'ASP.NET', 'PHP'] },
      { name: 'CS & 기타', tags: ['자료구조/알고리즘', '테스트', '게임 개발', '아키텍처'] },
    ],
  },
  {
    key: 'ai',
    label: 'AI',
    icon: 'fas fa-robot',
    title: '인공지능(AI)',
    megaMenuItems: ['AI Engineer', 'Data Scientist', '머신러닝 (ML)', '딥러닝 (DL)', 'ChatGPT / LLM', '프롬프트 엔지니어링'],
    groups: [
      { name: '직무별', tags: ['AI Engineer', 'Data Scientist', 'MLOps', 'Researcher'] },
      { name: '핵심 기술', tags: ['Machine Learning', 'Deep Learning', 'NLP', 'Computer Vision', 'Reinforcement Learning'] },
      { name: 'LLM & 프롬프트', tags: ['ChatGPT', 'LangChain', 'Prompt Engineering', 'RAG', 'Fine-tuning'] },
      { name: '라이브러리', tags: ['PyTorch', 'TensorFlow', 'Keras', 'Scikit-learn', 'HuggingFace'] },
    ],
  },
  {
    key: 'data',
    label: '데이터',
    icon: 'fas fa-database',
    title: '데이터 사이언스',
    megaMenuItems: ['데이터 분석', '데이터 엔지니어링', 'SQL / DB', 'NoSQL (Mongo)', '시각화 (Tableau)', '빅데이터'],
    groups: [
      { name: '직무별', tags: ['Data Analyst', 'Data Engineer', 'DBA', 'Big Data Engineer'] },
      { name: '데이터베이스', tags: ['MySQL', 'PostgreSQL', 'Oracle', 'MongoDB', 'Redis', 'Elasticsearch'] },
      { name: '분석 & 시각화', tags: ['Tableau', 'Power BI', 'Excel', 'Google Analytics', 'Pandas'] },
      { name: '빅데이터', tags: ['Hadoop', 'Spark', 'Kafka', 'Airflow', 'Data Lake'] },
    ],
  },
  {
    key: 'infra',
    label: '인프라',
    icon: 'fas fa-server',
    title: '인프라 · 보안',
    megaMenuItems: ['DevOps', 'AWS / Cloud', 'Docker / K8s', '보안 (Security)', 'Linux / Shell', '네트워크'],
    groups: [
      { name: 'DevOps', tags: ['DevOps General', 'DevSecOps', 'AWS', 'Azure', 'GCP', 'System Design'] },
      { name: '컨테이너', tags: ['Docker', 'Kubernetes', 'Terraform', 'CI/CD Pipelines'] },
      { name: '시스템', tags: ['Linux', 'Shell Script', 'Network Administration'] },
      { name: '보안', tags: ['Cyber Security', 'Web Hacking', 'Cloud Security'] },
    ],
  },
  {
    key: 'mobile',
    label: '모바일',
    icon: 'fas fa-mobile-alt',
    title: '모바일 앱 개발',
    megaMenuItems: ['Android App', 'iOS App', 'Flutter', 'React Native', 'Kotlin / Swift'],
    groups: [
      { name: '네이티브', tags: ['Android (Kotlin)', 'iOS (Swift)', 'SwiftUI', 'Jetpack Compose'] },
      { name: '크로스 플랫폼', tags: ['Flutter', 'React Native', 'Xamarin'] },
      { name: '기타', tags: ['Mobile Design', 'App Store Release'] },
    ],
  },
  {
    key: 'career',
    label: '커리어',
    icon: 'fas fa-briefcase',
    title: '커리어 · 자기계발',
    megaMenuItems: ['취업 / 이직', '이력서 / 면접', '기획 (PM/PO)', 'UX / UI 디자인', '비즈니스 스킬', '개발자 글쓰기'],
    groups: [
      { name: '매니지먼트', tags: ['Product Manager', 'Engineering Manager', 'Developer Relations'] },
      { name: '기획/디자인', tags: ['UX / UI Design', 'Figma', 'Technical Writer', 'IT 서비스 기획'] },
      { name: '취업', tags: ['이력서', '자소서', '기술 면접', '포트폴리오', '연봉 협상'] },
      { name: '오피스', tags: ['개발자 글쓰기', '커뮤니케이션', '문서화'] },
    ],
  },
]

const broadTagToCategoryKey: Record<string, Exclude<LectureCategoryKey, 'all'>> = {
  '웹 개발': 'dev',
  'ai/머신러닝': 'ai',
  '데이터 분석': 'data',
  인프라: 'infra',
  '모바일 앱': 'mobile',
  커리어: 'career',
}

const categoryMatchRules: Array<{ key: Exclude<LectureCategoryKey, 'all'>; tokens: string[] }> = [
  { key: 'ai', tokens: ['ai', 'ml', 'dl', 'llm', 'nlp', 'rag', 'langchain', 'chatgpt', 'pytorch', 'tensorflow'] },
  { key: 'data', tokens: ['data', 'sql', 'pandas', 'tableau', 'power bi', 'postgres', 'mysql', 'mongo', 'redis', 'spark', 'kafka'] },
  { key: 'infra', tokens: ['devops', 'aws', 'azure', 'gcp', 'docker', 'kubernetes', 'k8s', 'terraform', 'linux', 'security', 'network'] },
  { key: 'mobile', tokens: ['android', 'ios', 'swift', 'kotlin', 'flutter', 'react native', 'mobile'] },
  { key: 'career', tokens: ['career', 'resume', 'portfolio', 'interview', 'pm', 'po', 'ux', 'ui', 'figma', '취업', '면접', '이력서'] },
]

const categoryLabelMap: Record<Exclude<LectureCategoryKey, 'all'>, string> = {
  dev: '개발',
  ai: 'AI',
  data: '데이터',
  infra: '인프라',
  mobile: '모바일',
  career: '커리어',
}

export const fallbackLectureCourses: CourseListItem[] = [
  { courseId: 301, title: '실무 Spring Boot 백엔드 입문', thumbnailUrl: 'https://images.unsplash.com/photo-1515879218367-8466d910aaa4?w=1200&q=80', instructorName: '홍태민', instructorChannelName: 'Hong Backend Lab', price: 129000, discountPrice: 89000, difficulty: 'BEGINNER', tags: ['Java', 'Spring Boot', 'JPA'], isBookmarked: false, isEnrolled: true, status: 'PUBLISHED' },
  { courseId: 302, title: 'React 19 프론트엔드 실전 가이드', thumbnailUrl: 'https://images.unsplash.com/photo-1498050108023-c5249f4df085?w=1200&q=80', instructorName: '김소연', instructorChannelName: 'Frontend Craft', price: 119000, discountPrice: 79000, difficulty: 'INTERMEDIATE', tags: ['React', 'TypeScript', 'Tailwind'], isBookmarked: true, isEnrolled: false, status: 'PUBLISHED' },
  { courseId: 303, title: 'ChatGPT API와 RAG 서비스 만들기', thumbnailUrl: 'https://images.unsplash.com/photo-1677442136019-21780ecad995?w=1200&q=80', instructorName: '이민수', instructorChannelName: 'AI Studio', price: 149000, discountPrice: 99000, difficulty: 'INTERMEDIATE', tags: ['AI', 'LLM', 'RAG', 'LangChain'], isBookmarked: false, isEnrolled: false, status: 'PUBLISHED' },
  { courseId: 304, title: 'SQL로 끝내는 데이터 분석 기본기', thumbnailUrl: 'https://images.unsplash.com/photo-1551288049-bebda4e38f71?w=1200&q=80', instructorName: '박윤서', instructorChannelName: 'Data Ground', price: 89000, discountPrice: 49000, difficulty: 'BEGINNER', tags: ['SQL', 'Pandas', '데이터'], isBookmarked: false, isEnrolled: false, status: 'PUBLISHED' },
  { courseId: 305, title: 'Docker & Kubernetes 운영 실전', thumbnailUrl: 'https://images.unsplash.com/photo-1667372393119-3d4c48d07fc9?w=1200&q=80', instructorName: '정우성', instructorChannelName: 'Cloud Ops', price: 159000, discountPrice: 109000, difficulty: 'ADVANCED', tags: ['Docker', 'Kubernetes', 'DevOps'], isBookmarked: false, isEnrolled: false, status: 'PUBLISHED' },
  { courseId: 306, title: 'Flutter로 MVP 앱 출시하기', thumbnailUrl: 'https://images.unsplash.com/photo-1512941937669-90a1b58e7e9c?w=1200&q=80', instructorName: '윤가희', instructorChannelName: 'Mobile Ship', price: 99000, discountPrice: 69000, difficulty: 'BEGINNER', tags: ['Flutter', '모바일', '앱 출시'], isBookmarked: true, isEnrolled: false, status: 'PUBLISHED' },
  { courseId: 307, title: '개발자 이력서와 기술 면접 패키지', thumbnailUrl: 'https://images.unsplash.com/photo-1454165804606-c3d57bc86b40?w=1200&q=80', instructorName: '최하늘', instructorChannelName: 'Career Boost', price: 59000, discountPrice: 0, difficulty: 'BEGINNER', tags: ['이력서', '기술 면접', '포트폴리오'], isBookmarked: false, isEnrolled: false, status: 'PUBLISHED' },
  { courseId: 308, title: 'Next.js 14 제품 개발 실전', thumbnailUrl: 'https://images.unsplash.com/photo-1555949963-aa79dcee981c?w=1200&q=80', instructorName: '문지후', instructorChannelName: 'Product Front', price: 139000, discountPrice: 99000, difficulty: 'INTERMEDIATE', tags: ['Next.js', 'React', '테스트'], isBookmarked: false, isEnrolled: true, status: 'PUBLISHED' },
]

export function normalizeLectureCourses(items: CourseListItem[]) {
  return items.map((item) => normalizeLectureCourse(item))
}

export function normalizeLectureCourse(item: CourseListItem): LectureCourse {
  const categoryKey = inferLectureCategory(item)
  const ratingSeed = item.courseId % 7
  const rating = Math.min(5, 4.4 + ratingSeed * 0.08)
  const reviewCount = 120 + (item.courseId % 15) * 19

  return {
    ...item,
    categoryKey,
    categoryLabel: categoryLabelMap[categoryKey],
    displayCategory: `${categoryLabelMap[categoryKey]} · ${item.tags[0] ?? '실전'}`,
    rating: Number(rating.toFixed(1)),
    reviewCount,
    badge: resolveLectureBadge(item),
    roadmapLinked: item.tags.length > 0,
    searchIndex: `${item.title} ${item.instructorName} ${item.instructorChannelName ?? ''} ${item.tags.join(' ')}`.toLowerCase(),
  }
}

export function inferLectureCategory(item: CourseListItem): Exclude<LectureCategoryKey, 'all'> {
  const haystack = `${item.title} ${item.tags.join(' ')} ${item.instructorChannelName ?? ''}`.toLowerCase()

  for (const rule of categoryMatchRules) {
    if (rule.tokens.some((token) => haystack.includes(token.toLowerCase()))) {
      return rule.key
    }
  }

  return 'dev'
}

export function getCourseDisplayPrice(item: Pick<CourseListItem, 'price' | 'discountPrice'>) {
  if (item.discountPrice !== null && item.discountPrice !== undefined) {
    return item.discountPrice
  }
  return item.price
}

export function isFreeCourse(item: Pick<CourseListItem, 'price' | 'discountPrice'>) {
  return (getCourseDisplayPrice(item) ?? 0) <= 0
}

export function formatCoursePrice(value: number | null) {
  if (value === null || value === undefined || value <= 0) {
    return '무료'
  }
  return `${new Intl.NumberFormat('ko-KR').format(value)}원`
}

export function formatDifficultyLabel(value: CourseDifficulty) {
  if (value === 'BEGINNER') return '입문'
  if (value === 'INTERMEDIATE') return '중급'
  if (value === 'ADVANCED') return '고급'
  return '전체'
}

export function matchesLectureTag(course: LectureCourse, selectedCategoryKey: LectureCategoryKey, selectedTag: string | null) {
  if (!selectedTag) return true

  const normalizedTag = selectedTag.toLowerCase()
  const broadCategoryKey = broadTagToCategoryKey[normalizedTag]
  if (selectedCategoryKey === 'all' && broadCategoryKey) {
    return course.categoryKey === broadCategoryKey
  }

  return course.searchIndex.includes(normalizedTag)
}

export function sortLectureCourses(courses: LectureCourse[], sortKey: LectureSortKey) {
  const sorted = [...courses]

  sorted.sort((left, right) => {
    if (sortKey === 'priceAsc') {
      return (getCourseDisplayPrice(left) ?? 0) - (getCourseDisplayPrice(right) ?? 0)
    }
    if (sortKey === 'priceDesc') {
      return (getCourseDisplayPrice(right) ?? 0) - (getCourseDisplayPrice(left) ?? 0)
    }
    if (sortKey === 'title') {
      return left.title.localeCompare(right.title, 'ko')
    }
    if (sortKey === 'latest') {
      return right.courseId - left.courseId
    }

    const leftScore = Number(left.isBookmarked) * 2 + left.rating
    const rightScore = Number(right.isBookmarked) * 2 + right.rating
    return rightScore - leftScore || right.courseId - left.courseId
  })

  return sorted
}

function resolveLectureBadge(item: CourseListItem) {
  if (isFreeCourse(item)) return 'Free'
  if (item.tags.some((tag) => ['Java', 'Spring Boot'].includes(tag))) return 'Best Seller'
  if (item.tags.some((tag) => ['React', 'AI', 'Docker'].includes(tag))) return 'Hot'
  return 'New'
}
