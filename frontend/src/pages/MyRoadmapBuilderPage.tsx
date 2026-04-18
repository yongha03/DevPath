import { useCallback, useMemo, useRef, useState } from 'react'

// ────────────────────────────────────────────
// 타입 정의
// ────────────────────────────────────────────

interface SkillModule {
  id: string
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
// 모듈 데이터베이스 (하드코딩 — 추후 API 연동)
// ────────────────────────────────────────────

const DB: Record<string, SkillModule[]> = {
  frontend: [
    { id: 'cs-net', title: '인터넷 & 네트워크', category: 'CS 기초', icon: 'fas fa-globe', color: 'text-blue-500', bgColor: 'bg-blue-50', topics: ['HTTP/HTTPS', 'DNS 작동원리', '도메인 & 호스팅'] },
    { id: 'fe-html', title: 'HTML / CSS', category: '웹 마크업', icon: 'fab fa-html5', color: 'text-orange-500', bgColor: 'bg-orange-50', topics: ['시맨틱 태그', 'Flexbox & Grid', '반응형 웹', 'SEO 기초'] },
    { id: 'fe-js', title: 'JavaScript', category: '언어 기초', icon: 'fab fa-js', color: 'text-yellow-500', bgColor: 'bg-yellow-50', topics: ['ES6+', 'DOM 조작', '비동기(Promise/Async)', '이벤트 루프'] },
    { id: 'fe-ts', title: 'TypeScript', category: '언어 심화', icon: 'fas fa-file-code', color: 'text-blue-600', bgColor: 'bg-blue-50', topics: ['정적 타이핑', '인터페이스', '제네릭'] },
    { id: 'fe-react', title: 'React', category: '프레임워크', icon: 'fab fa-react', color: 'text-cyan-500', bgColor: 'bg-cyan-50', topics: ['컴포넌트 생명주기', 'React Hooks', '상태 관리', '라우팅'] },
    { id: 'fe-next', title: 'Next.js', category: '풀스택 웹', icon: 'fas fa-n', color: 'text-black', bgColor: 'bg-gray-200', topics: ['SSR / SSG', 'App Router', 'API Routes', '최적화'] },
  ],
  backend: [
    { id: 'cs-net', title: '인터넷 & 네트워크', category: 'CS 기초', icon: 'fas fa-globe', color: 'text-blue-500', bgColor: 'bg-blue-50', topics: ['TCP/IP', 'HTTP 메서드', 'CORS', '웹 소켓'] },
    { id: 'cs-os', title: 'OS 및 일반 지식', category: 'CS 기초', icon: 'fas fa-terminal', color: 'text-gray-700', bgColor: 'bg-gray-200', topics: ['터미널 명령어', '프로세스와 스레드', '메모리 관리', '동시성'] },
    { id: 'be-java', title: 'Java Programming', category: '언어 기초', icon: 'fab fa-java', color: 'text-red-500', bgColor: 'bg-red-50', topics: ['객체지향(OOP)', 'JVM 메모리 구조', '컬렉션 프레임워크', '스트림 API'] },
    { id: 'be-spring', title: 'Spring Boot', category: '프레임워크', icon: 'fas fa-leaf', color: 'text-green-500', bgColor: 'bg-green-50', topics: ['의존성 주입(DI)', 'AOP', 'Spring MVC', 'JPA / Hibernate'] },
    { id: 'db-rdb', title: '관계형 데이터베이스', category: '데이터베이스', icon: 'fas fa-database', color: 'text-indigo-500', bgColor: 'bg-indigo-50', topics: ['PostgreSQL / MySQL', '정규화', '트랜잭션(ACID)', '인덱스 최적화'] },
    { id: 'be-api', title: 'API 설계', category: '웹 개발', icon: 'fas fa-network-wired', color: 'text-purple-500', bgColor: 'bg-purple-50', topics: ['RESTful 설계', 'GraphQL', 'JWT 인증', 'OAuth 2.0'] },
    { id: 'be-redis', title: 'Redis & 캐싱', category: '데이터베이스', icon: 'fas fa-memory', color: 'text-red-500', bgColor: 'bg-red-50', topics: ['In-Memory DB', '세션 관리', '캐싱 전략', 'Pub/Sub'] },
    { id: 'infra-docker', title: 'Docker', category: 'DevOps', icon: 'fab fa-docker', color: 'text-blue-600', bgColor: 'bg-blue-50', topics: ['컨테이너화', 'Dockerfile', 'Docker Compose', '볼륨 관리'] },
  ],
  devops: [
    { id: 'cs-os', title: 'Linux Administration', category: 'OS', icon: 'fab fa-linux', color: 'text-black', bgColor: 'bg-gray-200', topics: ['쉘 스크립트', '권한 관리(chmod)', '시스템 모니터링', 'SSH'] },
    { id: 'infra-docker', title: 'Docker 심화', category: '컨테이너', icon: 'fab fa-docker', color: 'text-blue-600', bgColor: 'bg-blue-50', topics: ['멀티스테이지 빌드', '네트워크 브릿지', '이미지 경량화'] },
    { id: 'do-cicd', title: 'CI/CD 파이프라인', category: '자동화', icon: 'fas fa-sync-alt', color: 'text-teal-500', bgColor: 'bg-teal-50', topics: ['GitHub Actions', 'Jenkins', '파이프라인 구축', '자동 배포'] },
    { id: 'do-k8s', title: 'Kubernetes', category: '오케스트레이션', icon: 'fas fa-dharmachakra', color: 'text-blue-500', bgColor: 'bg-blue-50', topics: ['Pod & Service', 'Deployment', 'Ingress', 'Helm Chart'] },
    { id: 'do-aws', title: 'AWS 인프라', category: '클라우드', icon: 'fab fa-aws', color: 'text-orange-400', bgColor: 'bg-orange-50', topics: ['EC2 & VPC', 'S3 스토리지', 'IAM 권한', 'RDS & ElastiCache'] },
  ],
  fullstack: [
    { id: 'fe-react', title: 'React / Next.js', category: '프론트엔드', icon: 'fab fa-react', color: 'text-cyan-500', bgColor: 'bg-cyan-50', topics: ['클라이언트 UI', '상태 관리', '서버 사이드 렌더링'] },
    { id: 'fs-node', title: 'Node.js / Express', category: '백엔드', icon: 'fab fa-node-js', color: 'text-green-600', bgColor: 'bg-green-50', topics: ['JavaScript 런타임', '미들웨어', 'REST API 구축'] },
    { id: 'be-spring', title: 'Spring Boot (선택)', category: '백엔드', icon: 'fas fa-leaf', color: 'text-green-500', bgColor: 'bg-green-50', topics: ['엔터프라이즈 백엔드', 'JPA 연동', '보안 설정'] },
    { id: 'db-rdb', title: 'PostgreSQL', category: '데이터베이스', icon: 'fas fa-database', color: 'text-indigo-500', bgColor: 'bg-indigo-50', topics: ['RDBMS 기본', '데이터 모델링'] },
    { id: 'infra-docker', title: 'Docker', category: '배포', icon: 'fab fa-docker', color: 'text-blue-600', bgColor: 'bg-blue-50', topics: ['풀스택 앱 컨테이너화', 'Compose 연동'] },
  ],
  ai: [
    { id: 'ai-py', title: 'Python Programming', category: '언어 기초', icon: 'fab fa-python', color: 'text-blue-500', bgColor: 'bg-blue-50', topics: ['데이터 타입', 'Numpy', 'Pandas', '데이터 전처리'] },
    { id: 'ai-math', title: '수학 및 통계', category: '기초 지식', icon: 'fas fa-square-root-alt', color: 'text-gray-700', bgColor: 'bg-gray-200', topics: ['선형대수학', '미적분', '확률과 통계'] },
    { id: 'ai-ml', title: 'Machine Learning', category: '인공지능', icon: 'fas fa-robot', color: 'text-orange-500', bgColor: 'bg-orange-50', topics: ['Scikit-learn', '지도 학습', '비지도 학습', '모델 평가'] },
    { id: 'ai-dl', title: 'Deep Learning', category: '인공지능', icon: 'fas fa-brain', color: 'text-purple-500', bgColor: 'bg-purple-50', topics: ['PyTorch / TensorFlow', '신경망 기초', 'CNN', 'RNN / LSTM'] },
    { id: 'ai-nlp', title: 'NLP & LLM', category: '자연어 처리', icon: 'fas fa-language', color: 'text-green-600', bgColor: 'bg-green-50', topics: ['트랜스포머 아키텍처', 'Hugging Face', '프롬프트 엔지니어링', 'RAG'] },
  ],
  data_engineer: [
    { id: 'ai-py', title: 'Python / Scala', category: '언어 기초', icon: 'fab fa-python', color: 'text-blue-500', bgColor: 'bg-blue-50', topics: ['데이터 파이프라인 개발', '분산 처리 기초'] },
    { id: 'db-rdb', title: 'Advanced SQL', category: '데이터베이스', icon: 'fas fa-database', color: 'text-indigo-500', bgColor: 'bg-indigo-50', topics: ['복잡한 조인', '윈도우 함수', '쿼리 실행 계획 튜닝'] },
    { id: 'de-dw', title: 'Data Warehouse', category: '데이터 저장소', icon: 'fas fa-cubes', color: 'text-blue-400', bgColor: 'bg-blue-50', topics: ['BigQuery', 'Snowflake', '데이터 마트 설계'] },
    { id: 'de-spark', title: 'Apache Spark', category: '분산 처리', icon: 'fas fa-bolt', color: 'text-orange-500', bgColor: 'bg-orange-50', topics: ['RDD', 'Spark SQL', '대용량 데이터 변환'] },
    { id: 'de-kafka', title: 'Apache Kafka', category: '스트리밍', icon: 'fas fa-stream', color: 'text-black', bgColor: 'bg-gray-200', topics: ['이벤트 스트리밍', 'Pub/Sub 구조', '실시간 파이프라인'] },
  ],
  android: [
    { id: 'app-kt', title: 'Kotlin Programming', category: '언어 기초', icon: 'fas fa-code', color: 'text-purple-600', bgColor: 'bg-purple-50', topics: ['코틀린 문법', 'Null 안정성', '컬렉션 및 람다'] },
    { id: 'app-and', title: 'Android Studio', category: '환경 구성', icon: 'fab fa-android', color: 'text-green-500', bgColor: 'bg-green-50', topics: ['IDE 활용', 'Gradle 빌드', '에뮬레이터'] },
    { id: 'app-ui', title: 'Jetpack Compose', category: 'UI 개발', icon: 'fas fa-layer-group', color: 'text-blue-500', bgColor: 'bg-blue-50', topics: ['선언형 UI', '상태 호이스팅', '애니메이션', '레이아웃'] },
    { id: 'app-coroutine', title: 'Coroutines & Flow', category: '비동기', icon: 'fas fa-water', color: 'text-cyan-500', bgColor: 'bg-cyan-50', topics: ['비동기 프로그래밍', '백그라운드 스레드', '데이터 스트림'] },
    { id: 'app-arch', title: 'Architecture (MVVM)', category: '아키텍처', icon: 'fas fa-project-diagram', color: 'text-orange-500', bgColor: 'bg-orange-50', topics: ['ViewModel', 'LiveData', '의존성 주입(Hilt)'] },
  ],
  ios: [
    { id: 'app-swift', title: 'Swift Programming', category: '언어 기초', icon: 'fab fa-apple', color: 'text-black', bgColor: 'bg-gray-200', topics: ['옵셔널', '구조체와 클래스', '프로토콜 지향 프로그래밍'] },
    { id: 'app-swiftui', title: 'SwiftUI', category: 'UI 개발', icon: 'fas fa-layer-group', color: 'text-blue-500', bgColor: 'bg-blue-50', topics: ['선언형 뷰', '상태 관리(@State)', '네비게이션'] },
    { id: 'app-combine', title: 'Combine', category: '반응형', icon: 'fas fa-stream', color: 'text-purple-500', bgColor: 'bg-purple-50', topics: ['Publisher / Subscriber', '데이터 바인딩'] },
    { id: 'app-coredata', title: 'Core Data', category: '데이터베이스', icon: 'fas fa-database', color: 'text-indigo-500', bgColor: 'bg-indigo-50', topics: ['로컬 데이터 저장', '엔티티 관리', '마이그레이션'] },
  ],
  game: [
    { id: 'game-math', title: '3D Math & Physics', category: '기초 지식', icon: 'fas fa-square-root-alt', color: 'text-gray-700', bgColor: 'bg-gray-200', topics: ['벡터와 행렬', '쿼터니언 회전', '충돌 처리', '물리 엔진'] },
    { id: 'game-cs', title: 'C# Programming', category: '언어 기초', icon: 'fas fa-code', color: 'text-purple-600', bgColor: 'bg-purple-50', topics: ['C# 문법', '이벤트와 델리게이트', '가비지 컬렉션'] },
    { id: 'game-unity', title: 'Unity Engine', category: '엔진 활용', icon: 'fab fa-unity', color: 'text-black', bgColor: 'bg-gray-200', topics: ['컴포넌트 패턴', '씬 관리', '애니메이터', 'UI 시스템'] },
    { id: 'game-cpp', title: 'C++ Programming', category: '언어 심화', icon: 'fas fa-file-code', color: 'text-blue-600', bgColor: 'bg-blue-50', topics: ['포인터와 참조', '메모리 관리', 'STL 라이브러리'] },
    { id: 'game-unreal', title: 'Unreal Engine', category: '엔진 활용', icon: 'fas fa-gamepad', color: 'text-orange-500', bgColor: 'bg-orange-50', topics: ['블루프린트', '액터 시스템', '메테리얼 에디터'] },
  ],
  blockchain: [
    { id: 'bc-crypto', title: 'Cryptography', category: '암호학', icon: 'fas fa-key', color: 'text-yellow-600', bgColor: 'bg-yellow-50', topics: ['해시 함수', '공개키/개인키', '디지털 서명'] },
    { id: 'bc-basics', title: 'Blockchain Basics', category: '블록체인', icon: 'fas fa-link', color: 'text-gray-700', bgColor: 'bg-gray-200', topics: ['P2P 네트워크', '합의 알고리즘(PoW/PoS)', '분산 원장'] },
    { id: 'bc-sol', title: 'Solidity', category: '스마트 컨트랙트', icon: 'fab fa-ethereum', color: 'text-purple-500', bgColor: 'bg-purple-50', topics: ['EVM', '토큰 표준(ERC-20)', '가스비 최적화'] },
    { id: 'bc-web3', title: 'Web3.js / Ethers.js', category: '프론트엔드 연동', icon: 'fas fa-plug', color: 'text-blue-500', bgColor: 'bg-blue-50', topics: ['DApp 구축', '지갑 연동(Metamask)', 'RPC 통신'] },
  ],
}

const CATEGORY_OPTIONS = [
  { value: 'frontend', label: '프런트엔드 (Frontend)' },
  { value: 'backend', label: '백엔드 (Backend) ⭐추천' },
  { value: 'devops', label: '데브옵스 (DevOps)' },
  { value: 'fullstack', label: '풀스택 (Full Stack)' },
  { value: 'ai', label: 'AI 엔지니어 (AI Engineer)' },
  { value: 'data_engineer', label: '데이터 엔지니어 (Data Engineer)' },
  { value: 'android', label: '안드로이드 (Android)' },
  { value: 'ios', label: 'iOS (iOS)' },
  { value: 'game', label: '게임 개발자 (Game Developer)' },
  { value: 'blockchain', label: '블록체인 (Blockchain)' },
]

function makeInstanceId() {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`
}

// ────────────────────────────────────────────
// 메인 컴포넌트
// ────────────────────────────────────────────

function MyRoadmapBuilderPage() {
  const [category, setCategory] = useState('backend')
  const [search, setSearch] = useState('')
  const [nodes, setNodes] = useState<BuilderNode[]>([])
  const [branchTarget, setBranchTarget] = useState<number | null>(null)
  const mainRef = useRef<HTMLDivElement>(null)

  // 이미 사용된 모듈 ID 집합
  const usedIds = useMemo(() => new Set(nodes.map((n) => n.module.id)), [nodes])

  // 현재 최대 sortOrder
  const maxSortOrder = useMemo(
    () => (nodes.length === 0 ? 0 : Math.max(...nodes.map((n) => n.sortOrder))),
    [nodes],
  )

  // sortOrder 기준으로 rows 그룹화
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
    const items = DB[category] ?? []
    const q = search.toLowerCase()
    if (!q) return items
    return items.filter(
      (item) =>
        item.title.toLowerCase().includes(q) ||
        item.category.toLowerCase().includes(q) ||
        item.topics.some((t) => t.toLowerCase().includes(q)),
    )
  }, [category, search])

  // C-2: 모듈 추가 (척추 or 분기)
  const handleAdd = useCallback(
    (module: SkillModule) => {
      if (usedIds.has(module.id)) return

      if (branchTarget === null) {
        // 척추 노드 추가
        setNodes((prev) => [
          ...prev,
          { instanceId: makeInstanceId(), module, sortOrder: maxSortOrder + 1, branchGroup: null },
        ])
        setTimeout(() => {
          mainRef.current?.scrollTo({ top: mainRef.current.scrollHeight, behavior: 'smooth' })
        }, 50)
      } else {
        // 분기 추가: 기존 척추를 branchGroup=1로 전환, 새 모듈을 branchGroup=2로 추가
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

  // C-2: 분기 모드 진입
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

  // C-2: 노드 삭제 + 후처리
  const handleRemove = useCallback((instanceId: string) => {
    setNodes((prev) => {
      const target = prev.find((n) => n.instanceId === instanceId)
      if (!target) return prev

      const { sortOrder, branchGroup } = target
      const sameRow = prev.filter((n) => n.sortOrder === sortOrder && n.instanceId !== instanceId)

      let updated: BuilderNode[]

      if (branchGroup === null) {
        // 척추 노드 삭제 → 해당 sortOrder 이후 전체 -1 재정렬
        updated = prev
          .filter((n) => n.instanceId !== instanceId)
          .map((n) => (n.sortOrder > sortOrder ? { ...n, sortOrder: n.sortOrder - 1 } : n))
      } else {
        // 분기 노드 삭제
        const remaining = sameRow
        if (remaining.length === 1) {
          // 분기 하나 남음 → 척추로 복원
          updated = prev
            .filter((n) => n.instanceId !== instanceId)
            .map((n) => (n.sortOrder === sortOrder ? { ...n, branchGroup: null } : n))
        } else {
          // 분기 둘 다 삭제되는 경우 (이미 마지막 하나)
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

  // ────────────────────────────────────────────
  // 렌더
  // ────────────────────────────────────────────

  return (
    <div className="flex h-screen flex-col overflow-hidden bg-[#F8FAFC] text-[#0F172A]">

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
            className="rounded-lg border border-transparent px-4 py-2 text-sm font-bold text-gray-600 transition hover:bg-red-50 hover:text-red-500"
          >
            <i className="fas fa-rotate-right mr-1" /> 초기화
          </button>
          <button
            type="button"
            onClick={() => alert('로드맵이 저장되었습니다!')}
            className="flex items-center gap-2 rounded-lg bg-[#00C471] px-5 py-2 text-sm font-bold text-white shadow-md transition hover:bg-green-600"
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

          {/* C-3: 분기 모드 배너 */}
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
          <div className="flex-1 space-y-3 overflow-y-auto bg-gray-50 p-4">
            {filteredItems.map((module) => {
              const isUsed = usedIds.has(module.id)
              const isAvailableForBranch = branchTarget !== null && !isUsed
              return (
                <div
                  key={module.id}
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

              {/* C-4: rows 렌더링 */}
              {rows.map((row) => (
                <div key={row.sortOrder} className="group relative z-10 mb-8 builder-step-enter">
                  {row.isBranching ? (
                    // ── 분기 row ──
                    <div className="flex items-start">
                      {/* 번호 */}
                      <div className="z-10 flex h-14 w-14 shrink-0 items-center justify-center rounded-full border-2 border-amber-400 bg-white text-xl font-black text-amber-500 shadow-lg">
                        {row.sortOrder}
                      </div>
                      {/* 두 카드 나란히 */}
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
// C-5: 척추 카드 컴포넌트
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

      {/* 액션 버튼 */}
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
// C-5: 분기 카드 컴포넌트
// ────────────────────────────────────────────

const BRANCH_COLORS: Record<string, { border: string; badge: string; dot: string }> = {
  A: { border: 'border-amber-300 hover:border-amber-400', badge: 'bg-amber-100 text-amber-600', dot: 'border-amber-300 bg-white' },
  B: { border: 'border-purple-300 hover:border-purple-400', badge: 'bg-purple-100 text-purple-600', dot: 'border-purple-300 bg-white' },
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
      {/* 분기 라벨 뱃지 */}
      <span className={`absolute -top-2.5 left-4 rounded-full px-2 py-0.5 text-[10px] font-black ${colors.badge}`}>
        {label}
      </span>
      {/* 삭제 버튼 */}
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