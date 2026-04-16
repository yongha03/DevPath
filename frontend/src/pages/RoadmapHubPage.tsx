interface RoleCard {
  title: string
  subtitle: string
  icon: string
  href: string
  originalRoadmapId?: number  // 공식 로드맵 ID (없으면 미준비)
  featured?: boolean
}

const ROLE_CARDS: RoleCard[] = [
  { title: '프런트엔드', subtitle: 'Frontend', icon: 'fa-desktop', href: 'roadmap.html?original=2', originalRoadmapId: 2 },
  { title: '백엔드', subtitle: 'Backend (추천)', icon: 'fa-server', href: 'roadmap.html?original=1', originalRoadmapId: 1, featured: true },
  { title: '데브옵스', subtitle: 'DevOps', icon: 'fa-infinity', href: '#' },
  { title: '풀스택', subtitle: 'Full Stack', icon: 'fa-layer-group', href: '#' },
  { title: 'AI 엔지니어', subtitle: 'AI Engineer', icon: 'fa-brain', href: '#' },
  { title: '데이터 엔지니어', subtitle: 'Data Engineer', icon: 'fa-database', href: '#' },
  { title: '데이터 분석가', subtitle: 'Data Analyst', icon: 'fa-chart-line', href: '#' },
  { title: '안드로이드', subtitle: 'Android', icon: 'fa-android', href: '#' },
  { title: 'iOS', subtitle: 'iOS', icon: 'fa-apple', href: '#' },
  { title: '게임 개발자', subtitle: 'Game Developer', icon: 'fa-gamepad', href: '#' },
  { title: '블록체인', subtitle: 'Blockchain', icon: 'fa-link', href: '#' },
  { title: '소프트웨어 아키텍트', subtitle: 'Software Architect', icon: 'fa-sitemap', href: '#' },
  { title: 'QA 엔지니어', subtitle: 'Quality Assurance', icon: 'fa-vial', href: '#' },
  { title: '사이버 보안', subtitle: 'Cyber Security', icon: 'fa-user-shield', href: '#' },
  { title: 'DevSecOps', subtitle: 'DevSecOps', icon: 'fa-shield-halved', href: '#' },
  { title: 'MLOps', subtitle: 'MLOps', icon: 'fa-gears', href: '#' },
  { title: '프로덕트 매니저', subtitle: 'Product Manager (PM)', icon: 'fa-clipboard-list', href: '#' },
  { title: '테크니컬 라이터', subtitle: 'Technical Writer', icon: 'fa-pen-fancy', href: '#' },
]

const SKILLS = [
  'Python (파이썬)', 'Java (자바)', 'JavaScript', 'TypeScript', 'Go (고 언어)', 'Rust (러스트)',
  'C++', 'SQL', 'Kotlin (코틀린)', 'Swift',
  'React (리액트)', 'Vue (뷰)', 'Angular (앵귤러)', 'Next.js', 'Node.js', 'Spring Boot',
  'Django (장고)', 'Laravel (라라벨)', 'ASP.NET Core', 'Flutter (플러터)', 'React Native',
  'AWS', 'Docker (도커)', 'Kubernetes', 'Terraform', 'Linux (리눅스)', 'MongoDB',
  'Redis (레디스)', 'Elasticsearch', 'GraphQL',
  'Git & GitHub', 'CS (컴퓨터 과학)', 'System Design', '디자인 패턴', '프롬프트 엔지니어링',
  'AI 에이전트', 'Ruby on Rails', 'AI 레드팀',
]

const PROJECT_IDEAS = [
  '프런트엔드 초급~고급 프로젝트',
  '백엔드 API 구축 실습',
  '데브옵스 파이프라인 구축',
  '풀스택 클론 코딩',
]

const BEST_PRACTICES = [
  'AWS 아키텍처 모범 사례',
  'API 보안 가이드 (JWT, OAuth)',
  '백엔드 성능 최적화',
  '프런트엔드 렌더링 최적화',
  '코드 리뷰 체크리스트',
]

function RoadmapHubPage() {
  return (
    <div className="h-screen min-w-0 overflow-hidden bg-gray-50 text-gray-900">
      <div className="hub-header-rail" />

      <div className="flex h-screen min-w-0 flex-1 flex-col overflow-hidden">
        <header className="hub-header">
          <div className="app-responsive-container flex h-full items-center gap-4 lg:gap-8">
            <div
              className="hidden w-60 items-center px-4 lg:flex"
              style={{ transform: 'translateX(var(--logo-nudge))' }}
            >
              <a href="home.html" className="group flex items-center gap-2 text-xl font-bold text-gray-900">
                <i className="fas fa-code-branch text-brand transition group-hover:rotate-12" /> DevPath
              </a>
            </div>
            <div className="flex items-center lg:hidden">
              <a href="home.html" className="group flex items-center gap-2 text-xl font-bold text-gray-900">
                <i className="fas fa-code-branch text-brand transition group-hover:rotate-12" /> DevPath
              </a>
            </div>

            <div className="hidden flex-1 items-center justify-center gap-10 text-sm font-bold text-gray-500 md:flex">
              <a href="roadmap-hub.html" className="border-b-2 border-brand pb-1 text-brand transition">
                로드맵
              </a>
              <a href="lecture-list.html" className="transition hover:text-brand">강의</a>
              <a href="project-list.html" className="transition hover:text-brand">프로젝트</a>
              <a href="community-list.html" className="transition hover:text-brand">커뮤니티</a>
              <a href="job-matching.html" className="transition hover:text-brand">채용분석</a>
            </div>

            <div className="ml-auto flex min-w-0 items-center justify-end gap-2 md:w-60">
              <div
                className="flex cursor-pointer items-center gap-2"
                onClick={() => { window.location.href = 'profile.html' }}
              >
                <span className="text-sm font-bold text-gray-700">나(사용자)</span>
                <img
                  src="https://api.dicebear.com/7.x/avataaars/svg?seed=Felix"
                  className="h-9 w-9 rounded-full border border-gray-200 shadow-sm"
                  alt="me"
                />
              </div>
            </div>
          </div>
        </header>

        <main className="hub-main flex-1">
          <header className="border-b border-gray-100 bg-gradient-to-b from-white to-gray-50 px-4 py-20 text-center">
            <h1 className="mb-6 text-4xl font-bold text-gray-900 md:text-6xl">
              <span className="bg-gradient-to-r from-purple-600 to-green-500 bg-clip-text text-transparent">
                개발자 로드맵
              </span>
            </h1>
            <p className="mx-auto mb-10 max-w-3xl text-lg leading-relaxed text-gray-500">
              <span className="font-bold text-brand">DevPath</span>는 개발자들이 학습 방향을 잡을 수 있도록 돕습니다.
              <br />
              역할별, 기술별로 정리된 최신 로드맵을 확인하고 성장을 시작하세요.
            </p>
            <div className="flex flex-col justify-center gap-4 sm:flex-row">
              <button
                type="button"
                onClick={() => { window.location.href = 'my-roadmap.html' }}
                className="group relative flex items-center justify-center gap-3 rounded-full bg-brand px-8 py-4 font-bold text-white shadow-lg transition-all duration-300 hover:-translate-y-1 hover:bg-green-600 hover:shadow-xl"
              >
                <div className="h-2 w-2 animate-pulse rounded-full bg-white" />
                <span className="text-lg">나만의 로드맵 만들기</span>
                <i className="fas fa-pen-ruler ml-1 transition-transform group-hover:rotate-12" />
              </button>
              <button
                type="button"
                onClick={() => { window.location.href = 'roadmap.html' }}
                className="group relative flex items-center justify-center gap-3 rounded-full bg-gray-800 px-8 py-4 font-bold text-white shadow-lg transition-all duration-300 hover:-translate-y-1 hover:bg-gray-900 hover:shadow-xl"
              >
                <span className="text-lg">나의 학습 로드맵으로 이동</span>
                <i className="fas fa-arrow-right transition-transform group-hover:translate-x-1" />
              </button>
              {/* roadmap.html 진입 시 ID 없으면 자동으로 기존 로드맵 조회 or 허브로 돌아옴 */}
            </div>
          </header>

          <div className="mx-auto mt-12 max-w-7xl space-y-20 px-6 pb-32">
            <section>
              <div className="mb-8 flex items-center gap-4">
                <span className="h-8 w-1 rounded-full bg-brand" />
                <h2 className="text-2xl font-bold text-gray-900">역할 기반 로드맵 (Role Based)</h2>
              </div>
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                {ROLE_CARDS.map((card) =>
                  card.featured ? (
                    <a
                      key={card.title}
                      href={card.href}
                      className="roadmap-hub-card relative overflow-hidden rounded-lg border-2 border-brand bg-green-50/30 p-5 shadow-md"
                    >
                      <div className="relative mb-2 flex justify-between">
                        <h3 className="font-bold text-brand">{card.title}</h3>
                        <i className={`fas ${card.icon} text-brand`} />
                      </div>
                      <p className="relative text-xs text-gray-500">{card.subtitle}</p>
                      <div className="absolute top-2 right-2 h-2 w-2 animate-ping rounded-full bg-red-500" />
                    </a>
                  ) : (
                    <a
                      key={card.title}
                      href={card.href}
                      className="roadmap-hub-card rounded-lg border border-gray-200 p-5 shadow-sm"
                    >
                      <div className="mb-2 flex justify-between">
                        <h3 className="font-bold text-gray-900">{card.title}</h3>
                        <i className={`fas ${card.icon} text-gray-400`} />
                      </div>
                      <p className="text-xs text-gray-500">{card.subtitle}</p>
                    </a>
                  )
                )}
              </div>
            </section>

            <section>
              <div className="mb-8 flex items-center gap-4">
                <span className="h-8 w-1 rounded-full bg-yellow-400" />
                <h2 className="text-2xl font-bold text-gray-900">기술 기반 로드맵 (Skill Based)</h2>
              </div>
              <div className="grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-6">
                {SKILLS.map((skill) => (
                  <button
                    key={skill}
                    type="button"
                    className="skill-btn rounded border border-gray-200 px-4 py-2 text-left text-sm text-gray-700 shadow-sm"
                  >
                    {skill}
                  </button>
                ))}
              </div>
            </section>

            <div className="grid grid-cols-1 gap-12 md:grid-cols-2">
              <section>
                <h2 className="mb-4 flex items-center gap-2 border-b border-gray-200 pb-2 text-xl font-bold text-gray-900">
                  <i className="fas fa-lightbulb text-yellow-400" /> 프로젝트 아이디어
                </h2>
                <ul className="space-y-2">
                  {PROJECT_IDEAS.map((idea) => (
                    <li key={idea}>
                      <a
                        href="#"
                        className="flex justify-between rounded border border-gray-200 bg-white p-3 shadow-sm transition hover:bg-gray-50"
                      >
                        <span>{idea}</span>
                        <i className="fas fa-chevron-right mt-1.5 text-xs text-gray-400" />
                      </a>
                    </li>
                  ))}
                </ul>
              </section>

              <section>
                <h2 className="mb-4 flex items-center gap-2 border-b border-gray-200 pb-2 text-xl font-bold text-gray-900">
                  <i className="fas fa-check-circle text-brand" /> 모범 사례 (Best Practices)
                </h2>
                <ul className="space-y-2">
                  {BEST_PRACTICES.map((practice) => (
                    <li key={practice}>
                      <a
                        href="#"
                        className="block rounded border border-gray-200 bg-white p-3 shadow-sm transition hover:bg-gray-50"
                      >
                        {practice}
                      </a>
                    </li>
                  ))}
                </ul>
              </section>
            </div>
          </div>
        </main>
      </div>
    </div>
  )
}

export default RoadmapHubPage
