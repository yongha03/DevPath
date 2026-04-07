import { useState } from 'react'

type Screen = 'start' | 'question' | 'loading' | 'result'

interface QuestionOption {
  text: string
  scores: Record<string, number>
}

interface Question {
  id: number
  text: string
  options: QuestionOption[]
}

interface RoadmapData {
  title: string
  desc: string
  icon: string
}

const QUESTIONS: Question[] = [
  {
    id: 1,
    text: '가장 흥미를 느끼거나 만들고 싶은 것은 무엇인가요?',
    options: [
      { text: '사용자가 직접 보고 사용하는 웹사이트 화면', scores: { frontend: 5, fullstack: 3, ux: 2 } },
      { text: '보이지 않는 곳에서 데이터를 처리하는 서버 시스템', scores: { backend: 5, fullstack: 3, data_eng: 2 } },
      { text: '스마트폰에서 돌아가는 애플리케이션', scores: { android: 3, ios: 3, frontend: 1 } },
      { text: '스스로 학습하고 예측하는 인공지능 모델', scores: { ai_engineer: 5, data_scientist: 4, ml: 4 } },
      { text: '게임이나 가상 현실 세계', scores: { game: 5, frontend: 1 } },
      { text: '해킹 방어, 시스템 보안 및 안전성', scores: { security: 5, devsecops: 5, backend: 1 } },
    ],
  },
  {
    id: 2,
    text: '선호하는 작업 환경이나 도구는 무엇인가요?',
    options: [
      { text: '시각적 디자인과 UI 레이아웃 도구 (Figma 등)', scores: { ux: 5, frontend: 3 } },
      { text: '터미널(검은 화면)과 시스템 명령어', scores: { devops: 5, devsecops: 4, backend: 2 } },
      { text: '데이터 통계 툴, 엑셀, 시각화 도구', scores: { data_analyst: 5, data_scientist: 4 } },
      { text: '코드 에디터에서 복잡한 로직 문제 해결', scores: { backend: 3, frontend: 3, qa: 2 } },
    ],
  },
  {
    id: 3,
    text: '만약 앱(App)을 만든다면 어떤 기기용으로 만들고 싶나요?',
    options: [
      { text: '아이폰/아이패드 (Apple 생태계)', scores: { ios: 5 } },
      { text: '갤럭시 등 안드로이드 폰', scores: { android: 5 } },
      { text: '모바일 앱보다는 웹서비스가 좋다', scores: { frontend: 2, backend: 2, fullstack: 2 } },
      { text: '기기보다는 인프라나 데이터가 더 중요하다', scores: { devops: 3, devsecops: 3, data_eng: 3 } },
    ],
  },
  {
    id: 4,
    text: '팀 프로젝트에서 어떤 역할을 맡고 싶으신가요?',
    options: [
      { text: '제품의 방향을 정하고 팀원을 리드하기', scores: { engineering_manager: 5, pm: 4, ux: 2 } },
      { text: '개발 및 배포 프로세스를 효율화하고 자동화', scores: { devops: 5, devsecops: 4, qa: 3 } },
      { text: '전체적인 시스템 구조 설계 및 기술 결정', scores: { architect: 5, fullstack: 3 } },
      { text: '주어진 기능을 완벽하게 코드로 구현', scores: { frontend: 3, backend: 3 } },
    ],
  },
  {
    id: 5,
    text: '특별히 관심 있는 최신 기술 분야가 있나요?',
    options: [
      { text: '블록체인, 비트코인, Web3', scores: { blockchain: 5 } },
      { text: '대규모 데이터 처리 (Big Data)', scores: { data_eng: 5, data_scientist: 3, data_analyst: 3 } },
      { text: '클라우드 보안 및 자동화', scores: { devsecops: 5, devops: 3, security: 3 } },
      { text: '딱히 없다. 꼼꼼한 테스트와 품질이 최고다.', scores: { qa: 5, engineering_manager: 2 } },
    ],
  },
  {
    id: 6,
    text: '개발 외에 가장 중요하게 생각하는 가치는 무엇인가요? (추가 질문)',
    options: [
      { text: '데이터를 통한 비즈니스 인사이트 도출', scores: { data_analyst: 5, data_scientist: 2, pm: 2 } },
      { text: '팀원들의 성장과 조직의 건강한 문화', scores: { engineering_manager: 5, pm: 3 } },
      { text: '버그 없는 완벽한 소프트웨어 품질', scores: { qa: 5, backend: 1, frontend: 1 } },
      { text: '개발 속도를 늦추지 않는 철저한 보안', scores: { devsecops: 5, security: 4 } },
    ],
  },
]

// 설문 결과 키 → 공식 로드맵 ID 매핑 (추후 로드맵 추가 시 확장)
const SURVEY_KEY_TO_ROADMAP_ID: Record<string, number> = {
  frontend: 2,
  backend: 1,
  // 그 외는 아직 공식 로드맵 미준비, 기본값 1(백엔드)로 폴백
}

const ROADMAPS: Record<string, RoadmapData> = {
  frontend: { title: '프론트엔드', desc: '웹사이트의 화면을 만들고 사용자와 상호작용합니다. React, Vue 등을 사용합니다.', icon: 'fa-desktop' },
  backend: { title: '백엔드', desc: '서버와 데이터베이스를 구축하고 비즈니스 로직을 처리합니다.', icon: 'fa-server' },
  fullstack: { title: '풀스택', desc: '프론트엔드와 백엔드를 모두 다루며 전체적인 서비스를 구현합니다.', icon: 'fa-layer-group' },
  devops: { title: '데브옵스', desc: '개발과 운영을 연결하고 배포 파이프라인(CI/CD)을 자동화합니다.', icon: 'fa-infinity' },
  devsecops: { title: 'DevSecOps', desc: 'DevOps에 보안(Security)을 결합하여 개발 모든 단계에서 보안을 자동화합니다.', icon: 'fa-user-shield' },
  android: { title: '안드로이드', desc: 'Kotlin을 사용하여 갤럭시 등 안드로이드용 앱을 개발합니다.', icon: 'fa-robot' },
  ios: { title: 'iOS', desc: 'Swift를 사용하여 아이폰, 아이패드용 앱을 개발합니다.', icon: 'fa-apple' },
  ai_engineer: { title: 'AI 엔지니어', desc: '머신러닝/딥러닝 모델을 개발하고 서비스에 적용합니다.', icon: 'fa-brain' },
  data_scientist: { title: '데이터 과학자', desc: '데이터를 분석하고 모델링하여 비즈니스 문제를 해결합니다.', icon: 'fa-microscope' },
  data_analyst: { title: '데이터 분석가', desc: '데이터를 수집 및 시각화하여 비즈니스 의사결정을 돕는 인사이트를 제공합니다.', icon: 'fa-chart-pie' },
  data_eng: { title: '데이터 엔지니어', desc: '대규모 데이터 처리를 위한 파이프라인과 시스템을 구축합니다.', icon: 'fa-database' },
  security: { title: '사이버 보안', desc: '해킹 공격을 방어하고 시스템의 취약점을 분석합니다.', icon: 'fa-shield-alt' },
  qa: { title: 'QA 엔지니어', desc: '소프트웨어의 버그를 찾고 품질을 보증하며 테스트 자동화를 구축합니다.', icon: 'fa-vial' },
  ux: { title: 'UX 디자인', desc: '사용자 경험을 설계하고 화면의 흐름을 기획합니다.', icon: 'fa-pen-nib' },
  game: { title: '게임 개발자', desc: 'Unity나 Unreal 엔진을 사용하여 PC, 모바일 게임을 만듭니다.', icon: 'fa-gamepad' },
  blockchain: { title: '블록체인', desc: '스마트 컨트랙트와 탈중앙화 시스템(DApp)을 개발합니다.', icon: 'fa-link' },
  pm: { title: '제품 관리자', desc: '제품의 비전을 수립하고 개발팀과 협업하여 프로젝트를 이끕니다.', icon: 'fa-tasks' },
  engineering_manager: { title: '엔지니어링 매니저', desc: '개발 팀을 관리하고 엔지니어의 성장과 채용, 조직 문화를 책임집니다.', icon: 'fa-users-cog' },
  architect: { title: '소프트웨어 아키텍트', desc: '복잡한 시스템의 전체 구조를 설계하고 기술 표준을 정합니다.', icon: 'fa-sitemap' },
}

function initScores(): Record<string, number> {
  return Object.fromEntries(Object.keys(ROADMAPS).map(k => [k, 0]))
}

function SurveyPage() {
  const [screen, setScreen] = useState<Screen>('start')
  const [currentStep, setCurrentStep] = useState(0)
  const [scores, setScores] = useState<Record<string, number>>(initScores)
  const [results, setResults] = useState<[string, number][]>([])

  function startSurvey() {
    setScores(initScores())
    setCurrentStep(0)
    setScreen('question')
  }

  function selectOption(optionScores: Record<string, number>) {
    const newScores = { ...scores }
    for (const [key, value] of Object.entries(optionScores)) {
      if (key in newScores) {
        newScores[key] += value
      }
    }
    setScores(newScores)

    const nextStep = currentStep + 1
    if (nextStep < QUESTIONS.length) {
      setCurrentStep(nextStep)
    } else {
      setScreen('loading')
      setTimeout(() => {
        const sorted = Object.entries(newScores).sort(([, a], [, b]) => b - a)
        setResults(sorted)
        setScreen('result')
      }, 1500)
    }
  }

  function resetSurvey() {
    setScreen('start')
    setCurrentStep(0)
    setScores(initScores())
    setResults([])
  }

  const progress = Math.round((currentStep / QUESTIONS.length) * 100)
  const question = QUESTIONS[currentStep]
  const topResult = results[0] ? ROADMAPS[results[0][0]] : null

  return (
    <div className="flex min-h-screen flex-col bg-white text-gray-900">
      <nav className="sticky top-0 z-50 flex items-center justify-between border-b border-gray-200 bg-white/90 px-6 py-4 backdrop-blur">
        <a href="roadmap-hub.html" className="flex items-center gap-2 text-2xl font-bold">
          <i className="fas fa-code-branch text-brand" /> DevPath
        </a>
        <a
          href="roadmap-hub.html"
          className="rounded px-3 py-2 text-sm text-gray-500 transition hover:bg-gray-100 hover:text-black"
        >
          <i className="fas fa-arrow-left mr-2" />목록으로 돌아가기
        </a>
      </nav>

      <main className="mx-auto flex w-full max-w-3xl flex-grow flex-col items-center justify-center p-6">
        {screen === 'question' && (
          <div className="mb-12 w-full">
            <div className="mb-2 flex justify-between text-xs text-gray-500">
              <span>Start</span>
              <span>{progress}%</span>
              <span>Finish</span>
            </div>
            <div className="h-2.5 w-full rounded-full bg-gray-200">
              <div
                className="bg-brand h-2.5 rounded-full transition-all duration-300"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>
        )}

        {screen === 'start' && (
          <div className="fade-in py-10 text-center">
            <div className="mb-6 inline-flex h-20 w-20 items-center justify-center rounded-full bg-gray-100">
              <i className="fas fa-compass text-4xl text-brand" />
            </div>
            <h1 className="mb-6 text-3xl font-bold text-gray-900 md:text-5xl">
              나에게 맞는 개발 로드맵 찾기
            </h1>
            <p className="mx-auto mb-10 max-w-xl text-lg text-gray-600">
              몇 가지 간단한 질문에 답해주시면, 당신의 성향과 목표에 가장 적합한 기술 로드맵을 AI
              알고리즘이 분석하여 추천해 드립니다.
            </p>
            <button
              type="button"
              onClick={startSurvey}
              className="bg-brand rounded-lg px-10 py-4 text-lg font-bold text-white shadow-lg shadow-green-500/30 transition hover:scale-105 hover:bg-green-600"
            >
              추천 받기 시작
            </button>
          </div>
        )}

        {screen === 'question' && (
          <div key={currentStep} className="fade-in w-full">
            <div className="mb-8">
              <span className="mb-2 block text-sm font-bold tracking-widest text-brand uppercase">
                Question {currentStep + 1}
              </span>
              <h2 className="text-2xl font-bold leading-tight text-gray-900 md:text-3xl">
                {question.text}
              </h2>
            </div>
            <div className="space-y-4">
              {question.options.map((option, i) => (
                <div
                  key={i}
                  className="option-card group flex items-center justify-between rounded-lg border border-gray-200 bg-white p-5 text-left shadow-sm hover:shadow-md"
                  onClick={() => selectOption(option.scores)}
                >
                  <span className="text-lg font-medium text-gray-800">{option.text}</span>
                  <i className="fas fa-chevron-right text-gray-400 transition group-hover:text-brand" />
                </div>
              ))}
            </div>
          </div>
        )}

        {screen === 'loading' && (
          <div className="fade-in py-20 text-center">
            <div className="border-brand mb-6 inline-block h-16 w-16 animate-spin rounded-full border-t-4 border-b-4" />
            <h2 className="mb-2 text-2xl font-bold text-gray-900">결과 분석 중...</h2>
            <p className="text-gray-500">당신의 성향을 로드맵 데이터베이스와 매칭하고 있습니다.</p>
          </div>
        )}

        {screen === 'result' && topResult && (
          <div className="fade-in w-full text-center">
            <h2 className="mb-2 text-3xl font-bold text-gray-900">분석 완료!</h2>
            <p className="mb-10 text-gray-500">당신에게 가장 추천하는 로드맵입니다.</p>

            <div className="border-brand relative mx-auto mb-10 max-w-md overflow-hidden rounded-xl border-2 bg-white p-8 shadow-2xl shadow-green-900/10">
              <div className="absolute inset-0 bg-green-500/5" />
              <div className="relative mb-6 flex justify-center">
                <div className="border-brand flex h-20 w-20 items-center justify-center rounded-full border border-gray-200 bg-gray-50 text-4xl shadow-sm text-brand">
                  <i className={`fas ${topResult.icon}`} />
                </div>
              </div>
              <h3 className="relative mb-4 text-3xl font-bold text-brand">{topResult.title}</h3>
              <p className="relative mb-6 leading-relaxed text-gray-600">{topResult.desc}</p>
              <div className="relative flex flex-col gap-3">
                <a
                  href={`roadmap.html?original=${SURVEY_KEY_TO_ROADMAP_ID[results[0]?.[0]] ?? 1}`}
                  className="bg-brand block w-full rounded-lg py-3 font-bold text-white shadow-md transition hover:bg-green-600"
                >
                  로드맵 보러 가기
                </a>
                <button
                  type="button"
                  onClick={resetSurvey}
                  className="block w-full rounded-lg bg-gray-100 py-3 font-bold text-gray-700 transition hover:bg-gray-200"
                >
                  다시 테스트하기
                </button>
              </div>
            </div>

            <div className="mt-8 border-t border-gray-200 pt-8">
              <p className="mb-4 text-sm text-gray-500">다른 추천 로드맵</p>
              <div className="flex flex-wrap justify-center gap-4">
                {results.slice(1, 4).filter(([, score]) => score > 0).map(([key]) => {
                  const data = ROADMAPS[key]
                  return data ? (
                    <a
                      key={key}
                      href="#"
                      className="survey-result-card flex items-center gap-2 rounded border border-gray-200 bg-white px-4 py-2 text-sm text-gray-700 shadow-sm hover:bg-gray-50"
                    >
                      <i className={`fas ${data.icon} text-gray-400`} /> {data.title}
                    </a>
                  ) : null
                })}
              </div>
            </div>
          </div>
        )}
      </main>

      <footer className="mt-auto border-t border-gray-200 py-6 text-center text-sm text-gray-500">
        &copy; 2024 DevPath. All rights reserved.
      </footer>
    </div>
  )
}

export default SurveyPage
