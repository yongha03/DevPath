import { useEffect, useRef, useState } from 'react'
import './learning-player-mock.css'

type TabKey = 'curriculum' | 'qna' | 'note'
type QnaFilter = 'all' | 'me' | 'unresolved'
type SectionKey = 'sec1' | 'sec2'

type QnaListItem = {
  id: string
  status: 'resolved' | 'unresolved'
  statusLabel: string
  badgeClassName: string
  title: string
  excerpt: string
  author: 'me' | 'other'
  authorName: string
  timeAgo: string
  commentCount: number
}

type NoteItem = {
  id: string
  timestamp: string
  text: string
  isNew?: boolean
}

const tabBaseClass =
  'tab-btn flex-1 py-4 text-sm font-medium text-gray-500 hover:text-gray-800 border-b-2 border-transparent transition'
const tabActiveClass =
  'tab-btn flex-1 py-4 text-sm font-bold text-[#00C471] border-b-2 border-[#00C471] bg-green-50/50 transition'

const filterBaseClass =
  'qna-filter-btn px-3.5 py-1.5 text-xs font-medium rounded-full bg-gray-100 text-gray-600 hover:bg-gray-200 transition shrink-0'
const filterActiveClass =
  'qna-filter-btn px-3.5 py-1.5 text-xs font-bold rounded-full bg-gray-900 text-white transition shrink-0'

const initialQnaItems: QnaListItem[] = [
  {
    id: 'q1',
    status: 'resolved',
    statusLabel: '해결됨',
    badgeClassName: 'bg-[#00C471] text-white',
    title: '프로세스와 프로그램의 정확한 차이가 뭔가요?',
    excerpt:
      '강의 내용 중에서 프로세스는 실행 중인 프로그램이라고 하셨는데, 메모리에 올라가면 무조건 프로세스라고 부를 수 있는 건가요?',
    author: 'me',
    authorName: '김태형 (나)',
    timeAgo: '2시간 전',
    commentCount: 1,
  },
  {
    id: 'q2',
    status: 'unresolved',
    statusLabel: '답변대기',
    badgeClassName: 'bg-gray-200 text-gray-600',
    title: '12:30 부분에서 컨텍스트 스위칭 질문이요!',
    excerpt: 'PCB에 저장되는 레지스터 값들은 구체적으로 어떤 것들이 있나요?',
    author: 'other',
    authorName: '이학생',
    timeAgo: '1일 전',
    commentCount: 0,
  },
]

export default function LearningPlayerMock() {
  const [activeTab, setActiveTab] = useState<TabKey>('qna')
  const [openSections, setOpenSections] = useState<Record<SectionKey, boolean>>({
    sec1: false,
    sec2: true,
  })
  const [qnaFilter, setQnaFilter] = useState<QnaFilter>('all')
  const [qnaDetailMounted, setQnaDetailMounted] = useState(false)
  const [qnaDetailSlid, setQnaDetailSlid] = useState(false)
  const [bottomBtnStyle, setBottomBtnStyle] = useState<{
    display?: 'none' | 'block'
    transform?: string
  }>({})
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [newNoteOpen, setNewNoteOpen] = useState(false)
  const [noteText, setNoteText] = useState('')
  const [notes, setNotes] = useState<NoteItem[]>([
    {
      id: 'note-initial',
      timestamp: '01:20',
      text: '인터럽트: 주변 장치나 예외 상황 발생 시 CPU에 신호를 보내는 메커니즘.',
    },
  ])
  const [questionModalOpen, setQuestionModalOpen] = useState(false)

  const settingsBtnRef = useRef<HTMLButtonElement | null>(null)
  const settingsMenuRef = useRef<HTMLDivElement | null>(null)
  const noteTextareaRef = useRef<HTMLTextAreaElement | null>(null)

  useEffect(() => {
    const handleDocClick = (event: MouseEvent) => {
      const target = event.target as Node | null
      if (!target) return
      if (settingsMenuRef.current?.contains(target)) return
      if (settingsBtnRef.current?.contains(target)) return
      setSettingsOpen(false)
    }
    document.addEventListener('click', handleDocClick)
    return () => document.removeEventListener('click', handleDocClick)
  }, [])

  useEffect(() => {
    if (newNoteOpen) {
      noteTextareaRef.current?.focus()
    }
  }, [newNoteOpen])

  const closeQnaDetail = () => {
    setQnaDetailSlid(false)
    setBottomBtnStyle((prev) => ({ ...prev, display: 'block' }))
    window.setTimeout(() => {
      setBottomBtnStyle((prev) => ({ ...prev, transform: 'translateY(0)' }))
    }, 10)
    window.setTimeout(() => {
      setQnaDetailMounted(false)
    }, 300)
  }

  const openQnaDetail = () => {
    setQnaDetailMounted(true)
    window.setTimeout(() => setQnaDetailSlid(true), 10)
    setBottomBtnStyle((prev) => ({ ...prev, transform: 'translateY(100%)' }))
    window.setTimeout(() => {
      setBottomBtnStyle((prev) => ({ ...prev, display: 'none' }))
    }, 300)
  }

  const switchTab = (target: TabKey) => {
    setActiveTab(target)
    if (target === 'qna') {
      closeQnaDetail()
    }
    setBottomBtnStyle((prev) => ({ ...prev, display: 'block' }))
  }

  const toggleAccordion = (id: SectionKey) => {
    setOpenSections((prev) => ({ ...prev, [id]: !prev[id] }))
  }

  const toggleSettings = () => setSettingsOpen((prev) => !prev)

  const filterQna = (filter: QnaFilter) => setQnaFilter(filter)

  const isQnaItemVisible = (item: QnaListItem) => {
    if (qnaFilter === 'all') return true
    if (qnaFilter === 'me') return item.author === 'me'
    if (qnaFilter === 'unresolved') return item.status === 'unresolved'
    return true
  }

  const toggleNewNote = () => setNewNoteOpen((prev) => !prev)

  const saveNote = () => {
    if (!noteText.trim()) {
      window.alert('노트 내용을 입력해주세요.')
      return
    }
    setNotes((prev) => [
      { id: `note-${Date.now()}`, timestamp: '05:12', text: noteText, isNew: true },
      ...prev,
    ])
    setNoteText('')
    setNewNoteOpen(false)
  }

  const openQuestionModal = () => setQuestionModalOpen(true)
  const closeQuestionModal = () => setQuestionModalOpen(false)
  const submitQuestion = () => {
    window.alert('질문이 성공적으로 등록되었습니다!')
    closeQuestionModal()
  }

  return (
    <div className="lpm-root h-screen flex flex-col overflow-hidden">
      {/* Header */}
      <header className="bg-gray-900 text-white h-14 flex items-center justify-between px-6 shrink-0 z-50 border-b border-gray-800">
        <div className="flex items-center gap-4">
          <a href="course-detail.html" className="text-gray-400 hover:text-white transition text-sm">
            <i className="fas fa-chevron-left mr-2"></i>로드맵으로 돌아가기
          </a>
          <div className="h-4 w-[1px] bg-gray-700"></div>
          <span className="text-sm font-bold text-gray-100">Unit 2. 컴퓨터 시스템의 동작원리</span>
        </div>
        <div className="flex items-center gap-4 text-sm">
          <div className="flex items-center gap-2 text-gray-400">
            <div className="w-32 h-2 bg-gray-700 rounded-full overflow-hidden">
              <div className="h-full bg-[#00C471] w-[45%]"></div>
            </div>
            <span className="text-xs">45% 완료</span>
          </div>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">
        {/* Main Content (동영상 플레이어 영역) */}
        <main className="flex-1 bg-black flex flex-col min-w-0">
          <div className="flex-1 relative flex flex-col justify-center items-center w-full overflow-hidden group">
            {/* Video Player Placeholder */}
            <div className="w-full h-full relative flex items-center justify-center bg-gray-900">
              <img
                src="https://images.unsplash.com/photo-1550439062-609e1531270e?ixlib=rb-1.2.1&auto=format&fit=crop&w=1600&q=80"
                alt=""
                className="w-full h-full object-cover opacity-60"
              />

              {/* 재생 버튼 (가운데) */}
              <button className="absolute text-white/80 hover:text-[#00C471] transition transform hover:scale-110">
                <i className="far fa-play-circle text-7xl drop-shadow-lg"></i>
              </button>

              {/* 강의 제목 워터마크 표시 */}
              <div className="absolute top-6 left-6 text-white/80 font-bold text-xl drop-shadow-md">
                1. 인터럽트 메커니즘
              </div>
            </div>

            {/* Video Player Controls */}
            <div className="absolute bottom-0 left-0 right-0 h-16 bg-gradient-to-t from-black/80 to-transparent flex items-end px-6 pb-4 gap-4 opacity-0 group-hover:opacity-100 transition-opacity duration-300 z-20">
              <button className="text-white hover:text-[#00C471] transition">
                <i className="fas fa-pause"></i>
              </button>
              <div className="flex-1 h-1.5 bg-gray-600 rounded-full overflow-hidden cursor-pointer relative mb-1">
                <div className="h-full bg-[#00C471] w-[25%]"></div>
              </div>
              <span className="text-xs text-white font-mono mb-1">05:12 / 22:00</span>
              <button className="text-white hover:text-[#00C471] transition">
                <i className="fas fa-volume-up"></i>
              </button>

              {/* 설정 (Settings) 버튼 & 팝업 메뉴 */}
              <div className="relative">
                <button
                  ref={settingsBtnRef}
                  onClick={toggleSettings}
                  className="text-white hover:text-[#00C471] transition"
                >
                  <i className="fas fa-cog"></i>
                </button>

                {/* 설정 팝업 */}
                <div
                  ref={settingsMenuRef}
                  className={`absolute bottom-full right-0 mb-4 w-40 bg-gray-900 border border-gray-700 rounded-lg shadow-xl ${settingsOpen ? 'flex' : 'hidden'} flex-col overflow-hidden animate-fade-in z-50`}
                >
                  <div className="px-3 py-2 border-b border-gray-700">
                    <span className="text-xs text-gray-400 font-bold">재생 속도</span>
                  </div>
                  <button className="text-left px-4 py-2 text-sm text-gray-200 hover:bg-gray-800 hover:text-white transition">
                    0.5x
                  </button>
                  <button className="text-left px-4 py-2 text-sm text-[#00C471] bg-gray-800 font-bold flex justify-between items-center transition">
                    1.0x <i className="fas fa-check text-xs"></i>
                  </button>
                  <button className="text-left px-4 py-2 text-sm text-gray-200 hover:bg-gray-800 hover:text-white transition">
                    1.5x
                  </button>
                  <button className="text-left px-4 py-2 text-sm text-gray-200 hover:bg-gray-800 hover:text-white transition">
                    2.0x
                  </button>

                  <div className="px-3 py-2 border-b border-t border-gray-700 mt-1">
                    <span className="text-xs text-gray-400 font-bold">화질</span>
                  </div>
                  <button className="text-left px-4 py-2 text-sm text-[#00C471] bg-gray-800 font-bold flex justify-between items-center transition">
                    1080p <i className="fas fa-check text-xs"></i>
                  </button>
                  <button className="text-left px-4 py-2 text-sm text-gray-200 hover:bg-gray-800 hover:text-white transition">
                    720p
                  </button>
                </div>
              </div>

              <button className="text-white hover:text-[#00C471] transition">
                <i className="fas fa-expand"></i>
              </button>
            </div>
          </div>

          <div className="h-20 bg-gray-900 border-t border-gray-800 flex items-center justify-center gap-6 shrink-0 z-30 relative">
            <button className="flex items-center gap-3 px-8 py-3 rounded-xl bg-gray-800 hover:bg-gray-700 text-gray-300 font-bold transition hover:text-white border border-gray-700">
              <i className="fas fa-chevron-left"></i> 이전 강의
            </button>

            <button className="flex items-center gap-3 px-8 py-3 rounded-xl bg-[#00C471] hover:bg-green-600 text-white font-bold transition shadow-lg hover:shadow-green-500/30 transform hover:-translate-y-0.5">
              다음 강의 <i className="fas fa-chevron-right"></i>
            </button>
          </div>
        </main>

        {/* Right Sidebar */}
        <aside className="w-[400px] bg-white border-l border-gray-200 flex flex-col shrink-0 z-40 relative">
          {/* 탭 메뉴 버튼 */}
          <div className="flex border-b border-gray-200 shrink-0">
            <button
              onClick={() => switchTab('curriculum')}
              className={activeTab === 'curriculum' ? tabActiveClass : tabBaseClass}
              data-target="curriculum"
            >
              커리큘럼
            </button>
            <button
              onClick={() => switchTab('qna')}
              className={activeTab === 'qna' ? tabActiveClass : tabBaseClass}
              data-target="qna"
            >
              Q&amp;A
            </button>
            <button
              onClick={() => switchTab('note')}
              className={activeTab === 'note' ? tabActiveClass : tabBaseClass}
              data-target="note"
            >
              노트
            </button>
          </div>

          {/* 탭 콘텐츠 영역 */}
          <div className="flex-1 overflow-hidden relative bg-gray-50/30 flex flex-col">
            {/* 1. 커리큘럼 탭 내용 */}
            <div
              className={`tab-content ${activeTab === 'curriculum' ? 'block' : 'hidden'} h-full overflow-y-auto custom-scrollbar p-4 animate-fade-in`}
            >
              <div className="bg-white border border-gray-200 rounded-xl overflow-hidden shadow-sm">
                {/* 섹션 1 */}
                <div className="border-b border-gray-200">
                  <button
                    onClick={() => toggleAccordion('sec1')}
                    className="w-full px-5 py-4 flex justify-between items-center bg-white hover:bg-gray-50 transition"
                  >
                    <div className="flex flex-col items-start">
                      <span className="text-xs font-bold text-gray-400 mb-1">SECTION 1</span>
                      <span className="font-bold text-gray-800">운영체제 개요</span>
                    </div>
                    <i
                      className={`fas ${openSections.sec1 ? 'fa-chevron-up' : 'fa-chevron-down'} text-gray-400 transition-transform`}
                    ></i>
                  </button>
                  <div
                    className={`accordion-content ${openSections.sec1 ? 'open' : ''} bg-gray-50 border-t border-gray-100`}
                  >
                    <div className="p-3 space-y-2">
                      <div className="p-3 rounded-lg flex justify-between items-center bg-white border border-gray-200 opacity-60">
                        <span className="text-sm font-medium text-gray-700">
                          <i className="fas fa-check-circle text-[#00C471] mr-2"></i>1. 운영체제란?
                        </span>
                        <span className="text-xs text-gray-400">12:30</span>
                      </div>
                      <div className="p-3 rounded-lg flex justify-between items-center bg-white border border-gray-200 opacity-60">
                        <span className="text-sm font-medium text-gray-700">
                          <i className="fas fa-check-circle text-[#00C471] mr-2"></i>2. 컴퓨터 시스템의 구조
                        </span>
                        <span className="text-xs text-gray-400">18:15</span>
                      </div>
                      <div className="p-3 rounded-lg flex justify-between items-center bg-white border border-gray-200 opacity-60">
                        <span className="text-sm font-medium text-gray-700">
                          <i className="fas fa-check-circle text-[#00C471] mr-2"></i>섹션 1 마무리 퀴즈
                        </span>
                        <span className="text-xs text-[#00C471] font-bold">제출완료</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* 섹션 2 (현재 수강중) */}
                <div>
                  <button
                    onClick={() => toggleAccordion('sec2')}
                    className="w-full px-5 py-4 flex justify-between items-center bg-green-50/50 hover:bg-green-50 transition border-l-4 border-[#00C471]"
                  >
                    <div className="flex flex-col items-start -ml-1">
                      <span className="text-xs font-bold text-[#00C471] mb-1">SECTION 2 (현재 수강중)</span>
                      <span className="font-bold text-gray-900">컴퓨터 시스템의 동작원리</span>
                    </div>
                    <i
                      className={`fas ${openSections.sec2 ? 'fa-chevron-up' : 'fa-chevron-down'} text-[#00C471] transition-transform`}
                    ></i>
                  </button>
                  <div
                    className={`accordion-content ${openSections.sec2 ? 'open' : ''} bg-gray-50 border-t border-gray-100`}
                  >
                    <div className="p-3 space-y-2">
                      <div className="p-3 rounded-lg flex justify-between items-center bg-green-50 border border-[#00C471] shadow-sm relative overflow-hidden cursor-pointer">
                        <div className="absolute left-0 top-0 bottom-0 w-1 bg-[#00C471]"></div>
                        <span className="text-sm font-bold text-gray-900 ml-2">
                          <i className="fas fa-play-circle text-[#00C471] mr-2"></i>1. 인터럽트 메커니즘
                        </span>
                        <span className="text-xs bg-[#00C471] text-white px-2 py-1 rounded-full font-bold animate-pulse">
                          수강중
                        </span>
                      </div>

                      <div className="p-3 rounded-lg flex justify-between items-center bg-white border border-gray-200 opacity-60 hover:opacity-100 transition cursor-pointer">
                        <span className="text-sm font-medium text-gray-700">
                          <i className="fas fa-lock text-gray-400 mr-2"></i>2. 동기식 입출력과 비동기식 입출력
                        </span>
                        <span className="text-xs text-gray-400">19:40</span>
                      </div>

                      <div className="p-3 rounded-lg flex justify-between items-center bg-white border border-gray-200 opacity-60 hover:opacity-100 transition cursor-pointer">
                        <span className="text-sm font-medium text-gray-700">
                          <i className="fas fa-lock text-gray-400 mr-2"></i>C언어 인터럽트 구현 실습 (과제)
                        </span>
                        <span className="text-xs text-gray-400">미제출</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* 2. Q&A 탭 내용 */}
            <div
              className={`tab-content ${activeTab === 'qna' ? 'block' : 'hidden'} h-full relative overflow-hidden`}
            >
              {/* [A] Q&A 목록 뷰 */}
              <div className="absolute inset-0 flex flex-col p-6 overflow-y-auto custom-scrollbar bg-gray-50/30 transition-transform duration-300">
                <div className="flex justify-between items-center mb-4">
                  <h3 className="font-bold text-gray-900 text-lg">질문 및 답변</h3>
                  <span className="text-sm text-gray-500">총 12개</span>
                </div>

                <div className="relative mb-4 shrink-0">
                  <input
                    type="text"
                    className="w-full border border-gray-200 rounded-lg py-2.5 pl-10 pr-4 text-sm focus:outline-none focus:border-[#00C471] focus:ring-1 focus:ring-[#00C471]"
                    placeholder="궁금한 내용을 검색해보세요."
                  />
                  <i className="fas fa-search absolute left-3.5 top-3.5 text-gray-400"></i>
                </div>

                {/* Q&A 필터 칩 */}
                <div className="flex gap-2 mb-6 overflow-x-auto custom-scrollbar pb-1 shrink-0">
                  <button
                    onClick={() => filterQna('all')}
                    className={qnaFilter === 'all' ? filterActiveClass : filterBaseClass}
                  >
                    전체 질문
                  </button>
                  <button
                    onClick={() => filterQna('me')}
                    className={qnaFilter === 'me' ? filterActiveClass : filterBaseClass}
                  >
                    내 질문
                  </button>
                  <button
                    onClick={() => filterQna('unresolved')}
                    className={qnaFilter === 'unresolved' ? filterActiveClass : filterBaseClass}
                  >
                    답변 대기중
                  </button>
                </div>

                <div className="space-y-3 pb-20">
                  {initialQnaItems.map((item) => (
                    <div
                      key={item.id}
                      onClick={openQnaDetail}
                      className="qna-item p-4 bg-white border border-gray-200 rounded-xl hover:border-[#00C471] transition cursor-pointer shadow-sm group"
                      data-author={item.author}
                      data-status={item.status}
                      style={{ display: isQnaItemVisible(item) ? undefined : 'none' }}
                    >
                      <div className="flex gap-2 items-start mb-2">
                        <span
                          className={`${item.badgeClassName} text-[10px] font-bold px-1.5 py-0.5 rounded`}
                        >
                          {item.statusLabel}
                        </span>
                        <h4 className="text-sm font-bold text-gray-800 leading-tight group-hover:text-[#00C471] transition">
                          {item.title}
                        </h4>
                      </div>
                      <p className="text-xs text-gray-500 line-clamp-2 mb-3">{item.excerpt}</p>
                      <div className="flex justify-between items-center text-xs text-gray-400">
                        <span className={item.author === 'me' ? 'font-bold text-[#00C471]' : ''}>
                          {item.authorName} • {item.timeAgo}
                        </span>
                        <span>
                          <i className="far fa-comment-dots mr-1"></i>
                          {item.commentCount}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* [B] Q&A 상세 뷰 */}
              <div
                className={`absolute inset-0 bg-white z-10 flex flex-col ${qnaDetailMounted ? '' : 'hidden'} transform transition-transform duration-300 ${qnaDetailSlid ? '' : 'translate-x-full'}`}
              >
                {/* 상단 헤더 (뒤로 가기) */}
                <div className="px-4 py-4 border-b border-gray-100 flex items-center gap-3 bg-white shrink-0">
                  <button
                    onClick={closeQnaDetail}
                    className="text-gray-400 hover:text-gray-800 transition w-8 h-8 flex items-center justify-center rounded-full hover:bg-gray-100"
                  >
                    <i className="fas fa-arrow-left"></i>
                  </button>
                  <h3 className="font-bold text-gray-900 text-sm">질문 상세</h3>
                </div>

                {/* 질문 & 답변 내용 영역 */}
                <div className="flex-1 overflow-y-auto custom-scrollbar p-6 bg-gray-50/50">
                  {/* 질문 원문 */}
                  <div className="mb-8">
                    <div className="flex gap-2 items-start mb-3">
                      <span className="bg-[#00C471] text-white text-[10px] font-bold px-1.5 py-0.5 rounded shrink-0 mt-0.5">
                        해결됨
                      </span>
                      <h4 className="text-lg font-bold text-gray-800 leading-tight">
                        프로세스와 프로그램의 정확한 차이가 뭔가요?
                      </h4>
                    </div>

                    <div className="flex items-center text-xs text-gray-400 mb-4 gap-2 flex-wrap">
                      <span className="font-bold text-[#00C471]">김태형 (나)</span>
                      <span>•</span>
                      <span>2시간 전</span>
                      <span>•</span>
                      <span className="bg-green-50 text-[#00C471] border border-green-200 px-1.5 py-0.5 rounded cursor-pointer hover:bg-green-100 transition">
                        <i className="fas fa-play mr-1 text-[10px]"></i>05:12 구간 재생
                      </span>
                    </div>

                    <div className="text-sm text-gray-700 leading-relaxed bg-white p-5 rounded-xl border border-gray-200 shadow-sm">
                      강의 내용 중에서 프로세스는 실행 중인 프로그램이라고 하셨는데, 보조기억장치에서 메모리에 올라가면 무조건 프로세스라고 부를 수 있는 건가요? 스레드랑 헷갈려서 질문 남깁니다!
                    </div>
                  </div>

                  {/* 답변 목록 */}
                  <div>
                    <h5 className="font-bold text-gray-800 text-sm mb-4 flex items-center gap-2">
                      <i className="far fa-comments text-gray-400"></i> 답변{' '}
                      <span className="text-[#00C471]">1</span>
                    </h5>

                    <div className="space-y-4">
                      {/* 강사 답변 */}
                      <div className="flex gap-3">
                        <div className="w-8 h-8 rounded-full bg-green-100 text-[#00C471] flex items-center justify-center shrink-0 text-sm border border-green-200">
                          <i className="fas fa-chalkboard-teacher"></i>
                        </div>
                        <div className="flex-1 bg-white border border-gray-200 p-4 rounded-xl shadow-sm relative">
                          {/* 지식공유자 뱃지 */}
                          <div className="absolute -top-2.5 right-4 bg-gray-800 text-white text-[10px] px-2 py-0.5 rounded-full font-bold shadow-sm">
                            지식공유자
                          </div>

                          <div className="flex justify-between items-center mb-2">
                            <span className="font-bold text-sm text-gray-800">이강사</span>
                            <span className="text-[10px] text-gray-400">1시간 전</span>
                          </div>
                          <p className="text-sm text-gray-700 leading-relaxed">
                            네, 김태형님! 맞습니다. <br />
                            <br />
                            보조기억장치(하드디스크 등)에 저장된 정적인 코드를 <b>'프로그램'</b>이라고 하고, 이것이 실행되어 메모리(RAM)에 적재되고 CPU의 할당을 받을 수 있는 동적인 상태가 되면 <b>'프로세스'</b>라고 부릅니다.
                            <br />
                            <br />
                            스레드는 이 프로세스 '내부'에서 실행되는 더 작은 작업의 단위라고 보시면 됩니다. 다음 섹션에서 자세히 다룰 예정이니 참고해 주세요! 😊
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* 댓글 입력창 */}
                <div className="p-4 border-t border-gray-200 bg-white shrink-0 shadow-[0_-4px_6px_-1px_rgba(0,0,0,0.02)]">
                  <div className="relative">
                    <textarea
                      className="w-full border border-gray-200 bg-gray-50 rounded-xl py-3 pl-4 pr-12 text-sm focus:outline-none focus:border-[#00C471] focus:ring-1 focus:ring-[#00C471] resize-none h-[52px] custom-scrollbar"
                      placeholder="추가 답변이나 댓글을 남겨주세요."
                    />
                    <button className="absolute right-2 top-2 w-9 h-9 bg-[#00C471] text-white rounded-lg focus:outline-none hover:bg-green-600 transition flex items-center justify-center shadow-sm">
                      <i className="fas fa-paper-plane text-xs"></i>
                    </button>
                  </div>
                </div>
              </div>
            </div>

            {/* 3. 노트 탭 내용 */}
            <div
              className={`tab-content ${activeTab === 'note' ? 'block' : 'hidden'} h-full overflow-y-auto custom-scrollbar p-6 animate-fade-in`}
            >
              <div className="flex justify-between items-center mb-6">
                <h3 className="font-bold text-gray-900 text-lg">내 노트</h3>
                <button
                  onClick={toggleNewNote}
                  className="text-[#00C471] hover:text-green-600 text-sm font-bold transition flex items-center"
                >
                  <i className="fas fa-plus mr-1"></i>새 노트
                </button>
              </div>

              <div
                className={`${newNoteOpen ? '' : 'hidden'} bg-white border border-[#00C471] rounded-xl p-4 shadow-sm mb-6 animate-fade-in-up`}
              >
                <div className="flex items-center gap-2 mb-3">
                  <span className="bg-green-100 text-[#00C471] text-xs font-bold px-2 py-1 rounded">
                    05:12
                  </span>
                  <span className="text-xs text-gray-500">현재 재생 시간에 추가됩니다.</span>
                </div>
                <textarea
                  ref={noteTextareaRef}
                  value={noteText}
                  onChange={(e) => setNoteText(e.target.value)}
                  className="w-full h-24 p-3 border border-gray-200 rounded-lg text-sm mb-3 focus:outline-none focus:border-[#00C471] focus:ring-1 focus:ring-[#00C471] resize-none"
                  placeholder="강의를 들으며 중요한 점을 메모해보세요."
                />
                <div className="flex justify-end gap-2">
                  <button
                    onClick={toggleNewNote}
                    className="px-4 py-2 text-sm font-medium text-gray-600 bg-gray-100 rounded-lg hover:bg-gray-200 transition"
                  >
                    취소
                  </button>
                  <button
                    onClick={saveNote}
                    className="px-4 py-2 text-sm font-bold text-white bg-[#00C471] rounded-lg hover:bg-green-600 shadow-sm transition"
                  >
                    저장하기
                  </button>
                </div>
              </div>

              <div className="space-y-4 pb-20">
                {notes.map((note) => (
                  <div
                    key={note.id}
                    className={`p-4 border border-gray-200 bg-white shadow-sm rounded-xl hover:border-gray-300 transition${note.isNew ? ' animate-fade-in-up' : ''}`}
                  >
                    <div className="flex justify-between items-center mb-2">
                      <div className="text-xs text-[#00C471] font-bold bg-green-50 px-2 py-1 rounded cursor-pointer hover:bg-green-100">
                        <i className="fas fa-play mr-1"></i>
                        {note.timestamp}
                      </div>
                      <div className="flex gap-2 text-gray-400">
                        <button className="hover:text-gray-600">
                          <i className="fas fa-pen text-xs"></i>
                        </button>
                        <button className="hover:text-red-400">
                          <i className="fas fa-trash text-xs"></i>
                        </button>
                      </div>
                    </div>
                    <p className="text-sm text-gray-800 leading-relaxed">
                      {note.text.split('\n').map((line, idx, arr) => (
                        <span key={idx}>
                          {line}
                          {idx < arr.length - 1 ? <br /> : null}
                        </span>
                      ))}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* 하단 질문하기 버튼 (고정) */}
          <div
            className="absolute bottom-0 left-0 w-full p-4 border-t border-gray-200 bg-white shadow-[0_-4px_6px_-1px_rgba(0,0,0,0.05)] z-20"
            style={bottomBtnStyle}
          >
            <button
              onClick={openQuestionModal}
              className="w-full bg-gray-900 hover:bg-gray-800 text-white py-3.5 rounded-xl font-bold text-sm transition shadow-md hover:shadow-lg transform active:scale-95 flex justify-center items-center gap-2"
            >
              <i className="far fa-comment-dots"></i> 커뮤니티에 질문하기
            </button>
          </div>
        </aside>
      </div>

      {/* 질문하기 모달창 */}
      <div
        className={`fixed inset-0 bg-gray-900/60 backdrop-blur-sm ${questionModalOpen ? '' : 'hidden'} flex items-center justify-center z-[100] animate-fade-in`}
      >
        <div className="bg-white rounded-2xl w-[90%] max-w-[500px] shadow-2xl overflow-hidden transform transition-all">
          <div className="px-6 py-4 border-b border-gray-100 flex justify-between items-center bg-gray-50">
            <h3 className="text-lg font-bold text-gray-800">새로운 질문 작성</h3>
            <button
              onClick={closeQuestionModal}
              className="text-gray-400 hover:text-gray-600 transition"
            >
              <i className="fas fa-times text-lg"></i>
            </button>
          </div>
          <div className="p-6">
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-1">제목</label>
              <input
                type="text"
                className="w-full border border-gray-300 rounded-lg p-2.5 text-sm focus:outline-none focus:border-[#00C471] focus:ring-1 focus:ring-[#00C471]"
                placeholder="질문 제목을 입력하세요."
              />
            </div>
            <div className="mb-2">
              <label className="block text-sm font-medium text-gray-700 mb-1">내용</label>
              <textarea
                className="w-full h-32 border border-gray-300 rounded-lg p-2.5 text-sm focus:outline-none focus:border-[#00C471] focus:ring-1 focus:ring-[#00C471] resize-none"
                placeholder="어떤 부분이 이해가 안 되시나요? 구체적으로 적어주시면 더 좋은 답변을 받을 수 있습니다."
              />
            </div>
            <div className="flex items-center gap-2 mb-6 text-sm text-gray-500 bg-gray-50 p-2 rounded">
              <input
                type="checkbox"
                id="attach-time"
                className="rounded text-[#00C471] focus:ring-[#00C471]"
                defaultChecked
              />
              <label htmlFor="attach-time" className="cursor-pointer">
                현재 재생 시간(05:12) 첨부하기
              </label>
            </div>

            <div className="flex justify-end gap-3">
              <button
                onClick={closeQuestionModal}
                className="px-5 py-2.5 text-sm font-medium text-gray-600 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition"
              >
                취소
              </button>
              <button
                onClick={submitQuestion}
                className="px-5 py-2.5 text-sm font-bold text-white bg-[#00C471] rounded-lg hover:bg-green-600 transition shadow-md"
              >
                등록하기
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}