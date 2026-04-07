import { Suspense, useEffect, useEffectEvent, useMemo, useRef, useState } from 'react'
import LearningOcrPanel from './components/LearningOcrPanel'
import { useVideoOCR } from './hooks/useVideoOCR'
import { courseApi, learnerAssignmentApi, learningPlayerApi, lessonNoteApi, lessonSessionApi } from './lib/api'
import {
  buildFallbackAssignment,
  buildFallbackQuiz,
  buildSubmissionFiles,
  checklistItems,
  createDefaultAssignmentForm,
  createDefaultProgress,
  DEFAULT_VIDEO_URL,
  fallbackCourseDetail,
  formatDateLabel,
  formatDurationLabel,
  formatTime,
  getFlattenedLessons,
  getNotesStorageKey,
  getProgressStorageKey,
  getQuizResultStorageKey,
  normalizeCourseDetail,
  PLAYER_SPEEDS,
  readJsonStorage,
  readNumberSearchParam,
  resolveMaterialDownloadHref,
  simulateAssignmentPrecheck,
  simulateAssignmentSubmission,
  simulateQuizAttempt,
  syncLearningUrl,
  writeJsonStorage,
  type AssignmentFormState,
  type QuizAnswerState,
} from './learning-support'
import { AUTH_SESSION_SYNC_EVENT, readStoredAuthSession } from './lib/auth-session'
import type { AuthSession } from './types/auth'
import type {
  AssignmentPrecheckResponse,
  AssignmentSubmissionResponse,
  LearningCourseDetail,
  LearningLessonProgress,
  LearningPlayerConfig,
  QuizAttemptResultResponse,
  TimestampNote,
} from './types/learning'

type TabKey = 'curriculum' | 'assignment' | 'notes' | 'ocr'
const COURSE_LOAD_TIMEOUT_MS = 2500
const LESSON_LOAD_TIMEOUT_MS = 1800

function isAbortError(error: unknown) {
  return error instanceof DOMException && error.name === 'AbortError'
}

async function requestWithTimeout<T>(
  timeoutMs: number,
  executor: (signal: AbortSignal) => Promise<T>,
) {
  const controller = new AbortController()
  const timeoutId = window.setTimeout(() => controller.abort(), timeoutMs)

  try {
    return await executor(controller.signal)
  } finally {
    window.clearTimeout(timeoutId)
  }
}

function LoginRequiredView() {
  return (
    <div className="min-h-screen bg-[#0b1110] px-4 py-14 text-white">
      <div className="mx-auto max-w-xl rounded-[32px] border border-white/10 bg-white/5 px-8 py-10 text-center backdrop-blur">
        <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-emerald-500/15 text-emerald-300">
          <i className="fas fa-user-lock text-2xl" />
        </div>
        <h1 className="mt-6 text-3xl font-black">로그인이 필요합니다</h1>
        <p className="mt-3 text-sm leading-7 text-white/70">학습 플레이어는 로그인된 사용자만 사용할 수 있습니다.</p>
        <div className="mt-8 flex flex-col gap-3 sm:flex-row sm:justify-center">
          <a href="home.html?auth=login" className="rounded-full bg-[#00c471] px-6 py-3 text-sm font-bold text-white">로그인하러 가기</a>
          <a href="home.html" className="rounded-full border border-white/15 px-6 py-3 text-sm font-bold text-white/80">홈으로 이동</a>
        </div>
      </div>
    </div>
  )
}

export default function LearningPlayerApp() {
  const initialSearchParams = useMemo(() => ({
    courseId: readNumberSearchParam('courseId'),
    lessonId: readNumberSearchParam('lessonId'),
    assignmentId: readNumberSearchParam('assignmentId'),
  }), [])
  const initialCourseId = initialSearchParams.courseId
  const initialLessonId = initialSearchParams.lessonId
  const assignmentId = initialSearchParams.assignmentId
  const [session, setSession] = useState<AuthSession | null>(() => readStoredAuthSession())
  const [course, setCourse] = useState<LearningCourseDetail | null>(null)
  const [selectedLessonId, setSelectedLessonId] = useState<number | null>(initialLessonId)
  const [activeTab, setActiveTab] = useState<TabKey>('assignment')
  const [notice, setNotice] = useState<string | null>(null)
  const [loadingCourse, setLoadingCourse] = useState(true)
  const [loadingLesson, setLoadingLesson] = useState(false)
  const [progress, setProgress] = useState<LearningLessonProgress | null>(null)
  const [playerConfig, setPlayerConfig] = useState<LearningPlayerConfig | null>(null)
  const [notes, setNotes] = useState<TimestampNote[]>([])
  const [noteContent, setNoteContent] = useState('')
  const [noteMessage, setNoteMessage] = useState<string | null>(null)
  const [assignmentForm, setAssignmentForm] = useState<AssignmentFormState>(createDefaultAssignmentForm)
  const [assignmentPrecheck, setAssignmentPrecheck] = useState<AssignmentPrecheckResponse | null>(null)
  const [assignmentSubmission, setAssignmentSubmission] = useState<AssignmentSubmissionResponse | null>(null)
  const [assignmentMessage, setAssignmentMessage] = useState<string | null>(null)
  const [assignmentBusy, setAssignmentBusy] = useState(false)
  const [quizAnswers, setQuizAnswers] = useState<QuizAnswerState>({})
  const [quizResult, setQuizResult] = useState<QuizAttemptResultResponse | null>(null)
  const [quizMessage, setQuizMessage] = useState<string | null>(null)
  const [quizBusy, setQuizBusy] = useState(false)
  const [currentTime, setCurrentTime] = useState(0)
  const [duration, setDuration] = useState(0)
  const [isPlaying, setIsPlaying] = useState(false)
  const [videoFailed, setVideoFailed] = useState(false)
  const videoRef = useRef<HTMLVideoElement | null>(null)
  const frameRef = useRef<HTMLDivElement | null>(null)
  const resumeTimeRef = useRef(0)
  const lastRenderedSecondRef = useRef(-1)

  const lessons = useMemo(() => (course ? getFlattenedLessons(course) : []), [course])
  const lesson = useMemo(
    () => lessons.find((item) => item.lessonId === selectedLessonId) ?? lessons[0] ?? null,
    [lessons, selectedLessonId],
  )
  const assignment = useMemo(() => buildFallbackAssignment(lesson, assignmentId), [assignmentId, lesson])
  const quiz = useMemo(() => buildFallbackQuiz(lesson), [lesson])
  const sessionUserId = session?.userId ?? null
  const ocr = useVideoOCR(lesson?.lessonId ?? null, currentTime)
  const getPlaybackLimit = (video: HTMLVideoElement | null) => {
    const metadataDuration = video && Number.isFinite(video.duration) && video.duration > 0 ? Math.floor(video.duration) : 0
    const declaredDuration = lesson?.durationSeconds ?? 0

    if (metadataDuration > 0 && declaredDuration > 0) {
      return Math.min(metadataDuration, declaredDuration)
    }

    return metadataDuration || declaredDuration
  }

  useEffect(() => {
    document.title = 'DevPath - 학습 플레이어'
    const syncSession = () => setSession(readStoredAuthSession())
    window.addEventListener('storage', syncSession)
    window.addEventListener(AUTH_SESSION_SYNC_EVENT, syncSession)
    return () => {
      window.removeEventListener('storage', syncSession)
      window.removeEventListener(AUTH_SESSION_SYNC_EVENT, syncSession)
    }
  }, [])

  useEffect(() => {
    let cancelled = false
    async function loadCourse() {
      setLoadingCourse(true)
      if (!initialCourseId) {
        setCourse(fallbackCourseDetail)
        setSelectedLessonId(fallbackCourseDetail.sections[0]?.lessons[0]?.lessonId ?? null)
        setNotice('courseId가 없어 샘플 강의로 실행 중입니다.')
        setLoadingCourse(false)
        return
      }
      try {
        const response = await requestWithTimeout(
          COURSE_LOAD_TIMEOUT_MS,
          (signal) => courseApi.getCourseDetail(initialCourseId, signal),
        )
        if (cancelled) return
        const nextCourse = normalizeCourseDetail(response)
        const resolved = nextCourse.sections.length ? nextCourse : fallbackCourseDetail
        setCourse(resolved)
        setSelectedLessonId((initialLessonId && getFlattenedLessons(resolved).some((item) => item.lessonId === initialLessonId)) ? initialLessonId : getFlattenedLessons(resolved)[0]?.lessonId ?? null)
      } catch (error) {
        if (cancelled) return
        setCourse(fallbackCourseDetail)
        setSelectedLessonId(fallbackCourseDetail.sections[0]?.lessons[0]?.lessonId ?? null)
        if (isAbortError(error)) {
          setNotice('강의 정보를 기다리다 지연되어 샘플 강의로 먼저 열었습니다.')
        } else {
        setNotice('실제 강의 정보를 불러오지 못해 샘플 강의 데이터로 표시 중입니다.')
        }
      } finally {
        if (!cancelled) setLoadingCourse(false)
      }
    }
    void loadCourse()
    return () => {
      cancelled = true
    }
  }, [initialCourseId, initialLessonId])

  useEffect(() => {
    if (course && lesson) syncLearningUrl(course.courseId, lesson.lessonId)
  }, [course?.courseId, lesson?.lessonId])

  useEffect(() => {
    let cancelled = false
    async function loadLesson() {
      if (!lesson) return
      setLoadingLesson(true)
      setAssignmentForm(createDefaultAssignmentForm())
      setAssignmentPrecheck(null)
      setAssignmentSubmission(null)
      setQuizAnswers({})
      setQuizMessage(null)
      const storedProgress = readJsonStorage(getProgressStorageKey(lesson.lessonId), createDefaultProgress(lesson.lessonId))
      resumeTimeRef.current = storedProgress.progressSeconds
      lastRenderedSecondRef.current = storedProgress.progressSeconds
      setProgress(storedProgress)
      setPlayerConfig({ lessonId: storedProgress.lessonId, defaultPlaybackRate: storedProgress.defaultPlaybackRate, pipEnabled: storedProgress.pipEnabled })
      setNotes(readJsonStorage(getNotesStorageKey(lesson.lessonId), [] as TimestampNote[]))
      setQuizResult(readJsonStorage(getQuizResultStorageKey(lesson.lessonId), null as QuizAttemptResultResponse | null))
      setCurrentTime(storedProgress.progressSeconds)
      try {
        const [sessionProgress, config, fetchedNotes] = await Promise.all([
          requestWithTimeout(
            LESSON_LOAD_TIMEOUT_MS,
            (signal) => lessonSessionApi.startSession(lesson.lessonId, signal),
          ),
          requestWithTimeout(
            LESSON_LOAD_TIMEOUT_MS,
            (signal) => learningPlayerApi.getPlayerConfig(lesson.lessonId, signal),
          ).catch(() => null),
          requestWithTimeout(
            LESSON_LOAD_TIMEOUT_MS,
            (signal) => lessonNoteApi.getNotes(lesson.lessonId, signal),
          ).catch(() => null),
        ])
        if (cancelled) return
        const nextProgress = { ...sessionProgress, defaultPlaybackRate: config?.defaultPlaybackRate ?? sessionProgress.defaultPlaybackRate ?? 1, pipEnabled: config?.pipEnabled ?? sessionProgress.pipEnabled ?? false }
        resumeTimeRef.current = nextProgress.progressSeconds
        lastRenderedSecondRef.current = nextProgress.progressSeconds
        setProgress(nextProgress)
        setPlayerConfig({ lessonId: nextProgress.lessonId, defaultPlaybackRate: nextProgress.defaultPlaybackRate, pipEnabled: nextProgress.pipEnabled })
        setCurrentTime(nextProgress.progressSeconds)
        writeJsonStorage(getProgressStorageKey(lesson.lessonId), nextProgress)
        if (fetchedNotes) {
          setNotes(fetchedNotes)
          writeJsonStorage(getNotesStorageKey(lesson.lessonId), fetchedNotes)
        }
      } catch (error) {
        if (!cancelled && isAbortError(error)) {
          setNotice('학습 진행 정보 응답이 늦어서 저장된 로컬 상태로 먼저 표시했습니다.')
        }
      }
      if (!cancelled) setLoadingLesson(false)
    }
    void loadLesson()
    return () => {
      cancelled = true
    }
  }, [lesson?.lessonId])

  useEffect(() => {
    const video = videoRef.current
    if (!video || !lesson) return
    video.playbackRate = playerConfig?.defaultPlaybackRate ?? 1
    const handleLoadedMetadata = () => {
      const total = getPlaybackLimit(video)
      setDuration(total)
      if (resumeTimeRef.current > 0) {
        video.currentTime = Math.min(resumeTimeRef.current, total || resumeTimeRef.current)
      }
    }
    const handleTimeUpdate = () => {
      const total = getPlaybackLimit(video)
      if (total > 0 && video.currentTime >= total) {
        if (Math.floor(video.currentTime) !== total) {
          video.currentTime = total
        }
        if (!video.paused) {
          video.pause()
        }
      }
      const nextSecond = total > 0 ? Math.min(Math.floor(video.currentTime), total) : Math.floor(video.currentTime)
      if (nextSecond === lastRenderedSecondRef.current) return
      lastRenderedSecondRef.current = nextSecond
      setCurrentTime(nextSecond)
    }
    const handlePlay = () => setIsPlaying(true)
    const handlePause = () => setIsPlaying(false)
    video.addEventListener('loadedmetadata', handleLoadedMetadata)
    video.addEventListener('timeupdate', handleTimeUpdate)
    video.addEventListener('play', handlePlay)
    video.addEventListener('pause', handlePause)
    return () => {
      video.removeEventListener('loadedmetadata', handleLoadedMetadata)
      video.removeEventListener('timeupdate', handleTimeUpdate)
      video.removeEventListener('play', handlePlay)
      video.removeEventListener('pause', handlePause)
    }
  }, [lesson?.lessonId, lesson?.durationSeconds, playerConfig?.defaultPlaybackRate])

  const persistProgress = useEffectEvent(async (lessonId: number) => {
    if (!lesson || lesson.lessonId !== lessonId) return
    const video = videoRef.current
    const total = getPlaybackLimit(video)
    const currentSeconds = video ? Math.floor(video.currentTime) : Math.floor(currentTime)
    const seconds = total > 0 ? Math.min(currentSeconds, total) : currentSeconds
    const percent = total > 0 ? Math.max(0, Math.min(100, Math.round((seconds / total) * 100))) : 0
    const next = { lessonId, progressPercent: percent, progressSeconds: seconds, defaultPlaybackRate: playerConfig?.defaultPlaybackRate ?? 1, pipEnabled: playerConfig?.pipEnabled ?? false, isCompleted: percent >= 95, lastWatchedAt: new Date().toISOString() }
    setProgress(next)
    writeJsonStorage(getProgressStorageKey(lessonId), next)
    try {
      await lessonSessionApi.saveProgress(lessonId, { progressPercent: percent, progressSeconds: seconds })
    } catch {
      // Local cache already updated.
    }
  })

  useEffect(() => {
    if (!lesson) return
    const lessonId = lesson.lessonId
    const intervalId = window.setInterval(() => void persistProgress(lessonId), 15000)
    const handlePageHide = () => void persistProgress(lessonId)
    window.addEventListener('pagehide', handlePageHide)
    return () => {
      window.clearInterval(intervalId)
      window.removeEventListener('pagehide', handlePageHide)
      void persistProgress(lessonId)
    }
  }, [lesson?.lessonId, persistProgress])

  async function handleTogglePlay() {
    const video = videoRef.current
    if (!video) return
    if (video.paused) {
      const playbackLimit = getPlaybackLimit(video)
      if (playbackLimit > 0 && video.currentTime >= playbackLimit) {
        video.currentTime = 0
        lastRenderedSecondRef.current = 0
        setCurrentTime(0)
      }
      try {
        await video.play()
      } catch {
        setNotice('브라우저 정책으로 자동 재생이 차단되었습니다. 영상을 다시 눌러 주세요.')
      }
      return
    }
    video.pause()
  }

  async function handleTogglePip() {
    if (!lesson || !playerConfig) return
    const video = videoRef.current as (HTMLVideoElement & { requestPictureInPicture?: () => Promise<unknown> }) | null
    if (!video) return
    const next = !playerConfig.pipEnabled
    try {
      if ('pictureInPictureEnabled' in document && video.requestPictureInPicture) {
        if (document.pictureInPictureElement) await document.exitPictureInPicture()
        else await video.requestPictureInPicture()
      }
    } catch {
      // Keep local preference even if browser PIP is unavailable.
    }
    setPlayerConfig({ ...playerConfig, pipEnabled: next })
    try {
      await learningPlayerApi.updatePipMode(lesson.lessonId, next)
    } catch {
      // Local config stays active.
    }
  }

  function handleSeek(nextSeconds: number) {
    const video = videoRef.current
    if (!video) return
    const bounded = Math.max(0, Math.min(getPlaybackLimit(video) || nextSeconds, nextSeconds))
    video.currentTime = bounded
    setCurrentTime(bounded)
  }

  function handleOpenOcrTab() {
    setActiveTab('ocr')
  }

  async function handleRunCurrentFrameOcr() {
    setActiveTab('ocr')
    await ocr.runFullFrameOcr(videoRef.current)
  }

  function handleStartRegionOcr() {
    videoRef.current?.pause()
    setActiveTab('ocr')
    ocr.beginRegionSelection()
  }

  async function handleSaveNote() {
    if (!lesson || !noteContent.trim()) return
    const payload = { timestampSecond: Math.floor(currentTime), content: noteContent.trim() }
    try {
      const created = await lessonNoteApi.createNote(lesson.lessonId, payload)
      const nextNotes = [...notes, created].sort((a, b) => a.timestampSecond - b.timestampSecond)
      setNotes(nextNotes)
      writeJsonStorage(getNotesStorageKey(lesson.lessonId), nextNotes)
      setNoteMessage('노트를 저장했습니다.')
    } catch {
      const nextNotes = [...notes, { noteId: -Date.now(), lessonId: lesson.lessonId, timestampSecond: payload.timestampSecond, seekSecond: payload.timestampSecond, timestampLabel: formatTime(payload.timestampSecond), content: payload.content, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() }].sort((a, b) => a.timestampSecond - b.timestampSecond)
      setNotes(nextNotes)
      writeJsonStorage(getNotesStorageKey(lesson.lessonId), nextNotes)
      setNoteMessage('백엔드 연결 없이 로컬 노트로 저장했습니다.')
    }
    setNoteContent('')
  }

  async function handleDeleteNote(note: TimestampNote) {
    if (!lesson) return
    try {
      if (note.noteId > 0) await lessonNoteApi.deleteNote(lesson.lessonId, note.noteId)
    } catch {
      // Local fallback handles removal.
    }
    const nextNotes = notes.filter((item) => item.noteId !== note.noteId)
    setNotes(nextNotes)
    writeJsonStorage(getNotesStorageKey(lesson.lessonId), nextNotes)
  }

  async function handlePrecheckAssignment() {
    const payload = { ...assignmentForm, files: buildSubmissionFiles(assignmentForm.files) }
    setAssignmentBusy(true)
    try {
      const response = assignment.assignmentId && sessionUserId
        ? await learnerAssignmentApi.precheck(assignment.assignmentId, sessionUserId, payload)
        : simulateAssignmentPrecheck(assignment, payload)
      setAssignmentPrecheck(response)
      setAssignmentMessage(assignment.assignmentId ? '백엔드 precheck 결과를 반영했습니다.' : 'assignmentId가 없어 로컬 precheck로 실행했습니다.')
    } catch {
      setAssignmentPrecheck(simulateAssignmentPrecheck(assignment, payload))
      setAssignmentMessage('백엔드 precheck 실패로 로컬 검증 결과를 표시합니다.')
    }
    setAssignmentBusy(false)
  }

  async function handleSubmitAssignment() {
    const payload = { ...assignmentForm, files: buildSubmissionFiles(assignmentForm.files) }
    setAssignmentBusy(true)
    try {
      const response = assignment.assignmentId && sessionUserId
        ? await learnerAssignmentApi.submit(assignment.assignmentId, sessionUserId, payload)
        : simulateAssignmentSubmission(assignment, sessionUserId, payload)
      setAssignmentSubmission(response)
      setAssignmentMessage(assignment.assignmentId ? '과제를 제출했습니다.' : 'assignmentId가 없어 로컬 제출 모드로 처리했습니다.')
    } catch {
      setAssignmentSubmission(simulateAssignmentSubmission(assignment, sessionUserId, payload))
      setAssignmentMessage('백엔드 제출 실패로 로컬 제출 결과를 저장했습니다.')
    }
    setAssignmentBusy(false)
  }

  function handleSubmitQuiz() {
    if (!lesson) return
    setQuizBusy(true)
    const result = simulateQuizAttempt(quiz, quizAnswers)
    setQuizResult(result)
    writeJsonStorage(getQuizResultStorageKey(lesson.lessonId), result)
    setQuizMessage('현재는 퀴즈 상세 조회 API가 없어 로컬 채점 모드로 실행했습니다.')
    setQuizBusy(false)
  }

  if (!session) return <LoginRequiredView />

  return (
    <div className="min-h-screen bg-[#050606] text-white">
      <div className="flex min-h-screen flex-col lg:flex-row">
        <section className="relative flex min-h-[60vh] flex-1 flex-col bg-black lg:min-h-screen">
          <div className="absolute inset-x-0 top-0 z-20 flex items-center justify-between bg-gradient-to-b from-black/85 via-black/45 to-transparent px-4 py-4 lg:px-6">
            <button type="button" onClick={() => (window.history.length > 1 ? window.history.back() : (window.location.href = 'my-learning.html'))} className="flex items-center gap-2 text-sm font-bold text-white/70 hover:text-[#00c471]"><i className="fas fa-chevron-left" />내 학습으로 돌아가기</button>
            <div className="hidden max-w-xl truncate text-center text-sm font-bold text-white/75 sm:block">{course?.title ?? fallbackCourseDetail.title} · {lesson?.title ?? '강의 재생'}</div>
            <div className="flex items-center gap-2">
              <button type="button" onClick={handleOpenOcrTab} className="rounded-full border border-white/10 bg-white/10 px-3 py-1.5 text-xs font-semibold text-white/80">OCR</button>
              <button type="button" onClick={() => setActiveTab('notes')} className="rounded-full border border-white/10 bg-white/10 px-3 py-1.5 text-xs font-semibold text-white/80">노트 열기</button>
            </div>
          </div>
          <div ref={frameRef} className="relative flex flex-1 items-center justify-center bg-[#0b0f0f]">
            <video ref={videoRef} src={videoFailed ? DEFAULT_VIDEO_URL : lesson?.videoUrl ?? DEFAULT_VIDEO_URL} poster={lesson?.thumbnailUrl ?? course?.thumbnailUrl ?? undefined} className="h-full w-full object-contain" playsInline preload="none" crossOrigin="anonymous" onError={() => setVideoFailed(true)} onClick={() => void handleTogglePlay()} />
            <button type="button" onClick={() => void handleTogglePlay()} className="absolute inset-0 flex items-center justify-center"><span className="flex h-24 w-24 items-center justify-center rounded-full border border-white/15 bg-black/50 text-white"><i className={`fas ${isPlaying ? 'fa-pause' : 'fa-play'} text-4xl`} /></span></button>
            {ocr.selecting ? <div className="absolute inset-0 z-30 cursor-crosshair bg-black/10" onPointerDown={ocr.handleOverlayPointerDown} onPointerMove={ocr.handleOverlayPointerMove} onPointerUp={(event) => void ocr.handleOverlayPointerUp(event, videoRef.current)} onPointerLeave={ocr.cancelRegionSelection}><div className="absolute left-1/2 top-6 -translate-x-1/2 rounded-full border border-[#00c471]/30 bg-[#00c471]/15 px-4 py-2 text-xs font-semibold text-emerald-100">드래그해서 OCR할 영역을 선택하세요</div>{ocr.selectionRect ? <div className="absolute border-2 border-[#00c471] bg-[#00c471]/12" style={{ left: `${ocr.selectionRect.x}px`, top: `${ocr.selectionRect.y}px`, width: `${ocr.selectionRect.width}px`, height: `${ocr.selectionRect.height}px` }} /> : null}</div> : null}
            <button type="button" onClick={() => void handleTogglePip()} className="absolute right-4 top-20 rounded-xl border border-white/10 bg-black/55 px-3 py-2 text-xs font-semibold text-white/80 lg:right-8"><i className="fas fa-external-link-alt mr-2" />PIP 모드</button>
            <button type="button" onClick={() => void handleRunCurrentFrameOcr()} className="absolute right-4 top-[8.75rem] rounded-xl border border-white/10 bg-black/55 px-3 py-2 text-xs font-semibold text-white/80 lg:right-8"><i className="fas fa-language mr-2" />OCR</button>
            {notice ? <div className="absolute bottom-24 left-4 right-4 rounded-2xl border border-amber-400/30 bg-amber-400/10 px-4 py-3 text-xs text-amber-100 lg:left-8 lg:right-auto lg:max-w-md">{notice}</div> : null}
          </div>
          <div className="border-t border-white/6 bg-[#0f1212] px-4 py-4 lg:px-6">
            <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
              <div className="flex flex-1 items-center gap-4">
                <button type="button" onClick={() => void handleTogglePlay()} className="text-lg text-white/75"><i className={`fas ${isPlaying ? 'fa-pause' : 'fa-play'}`} /></button>
                <span className="min-w-14 text-xs font-mono text-white/60">{formatTime(currentTime)}</span>
                <input type="range" min={0} max={Math.max(duration, lesson?.durationSeconds ?? 0, 1)} step={1} value={Math.min(currentTime, Math.max(duration, lesson?.durationSeconds ?? 0, 1))} onChange={(event) => handleSeek(Number(event.target.value))} className="h-1 flex-1 cursor-pointer appearance-none rounded-full bg-white/15 accent-[#00c471]" />
                <span className="min-w-14 text-xs font-mono text-white/60">{formatTime(duration || (lesson?.durationSeconds ?? 0))}</span>
              </div>
              <div className="flex items-center gap-4 text-sm text-white/65">
                <button type="button" onClick={() => handleSeek(currentTime - 10)}>-10s</button>
                <button type="button" onClick={() => handleSeek(currentTime + 10)}>+10s</button>
                <button type="button" onClick={() => { if (!lesson || !playerConfig) return; const index = PLAYER_SPEEDS.indexOf(playerConfig.defaultPlaybackRate as (typeof PLAYER_SPEEDS)[number]); const next = PLAYER_SPEEDS[(index + 1) % PLAYER_SPEEDS.length]; setPlayerConfig({ ...playerConfig, defaultPlaybackRate: next }); if (videoRef.current) videoRef.current.playbackRate = next; void learningPlayerApi.updatePlaybackRate(lesson.lessonId, next).catch(() => null) }}>{(playerConfig?.defaultPlaybackRate ?? 1).toFixed(2).replace(/\.00$/, '')}x</button>
                <button type="button" onClick={() => void frameRef.current?.requestFullscreen()}><i className="fas fa-expand" /></button>
              </div>
            </div>
          </div>
        </section>

        <aside className="flex w-full flex-col border-l border-white/8 bg-[#f8f9fa] text-gray-900 lg:min-h-screen lg:w-[420px]">
          <div className="border-b border-gray-200 bg-white"><div className="flex">{(['curriculum', 'assignment', 'notes', 'ocr'] as TabKey[]).map((tab) => <button key={tab} type="button" onClick={() => setActiveTab(tab)} className={`flex-1 px-4 py-4 text-sm font-bold ${activeTab === tab ? 'border-b-2 border-[#00c471] bg-emerald-50/60 text-[#00c471]' : 'text-gray-400'}`}>{tab === 'curriculum' ? '커리큘럼' : tab === 'assignment' ? '과제/퀴즈' : tab === 'notes' ? '노트' : 'OCR'}</button>)}</div></div>
          <div className="relative flex-1 overflow-y-auto bg-[#f8f9fa] p-5 lg:p-6">
            {loadingLesson ? <div className="absolute inset-0 z-20 flex items-center justify-center bg-white/80"><div className="h-12 w-12 animate-spin rounded-full border-4 border-[#00c471] border-t-transparent" /></div> : null}
            {activeTab === 'curriculum' ? <div className="space-y-6">
              <section className="rounded-[24px] border border-gray-200 bg-white p-5 shadow-sm"><div className="flex items-start justify-between gap-4"><div><div className="text-xs font-bold uppercase tracking-[0.18em] text-[#00c471]">Current Course</div><h2 className="mt-2 text-xl font-black text-gray-900">{course?.title ?? fallbackCourseDetail.title}</h2><p className="mt-2 text-sm leading-6 text-gray-600">{course?.description ?? fallbackCourseDetail.description}</p></div><div className="rounded-2xl bg-gray-900 px-3 py-2 text-right text-white"><div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-white/60">Progress</div><div className="mt-1 text-lg font-black">{progress?.progressPercent ?? 0}%</div></div></div></section>
              <section className="rounded-[24px] border border-gray-200 bg-white p-5 shadow-sm"><div className="space-y-4">{(course?.sections ?? fallbackCourseDetail.sections).map((section) => <div key={section.sectionId}><div className="mb-2 text-xs font-black uppercase tracking-[0.16em] text-gray-400">{section.title}</div><div className="space-y-2">{section.lessons.map((item) => <button key={item.lessonId} type="button" onClick={() => setSelectedLessonId(item.lessonId)} className={`flex w-full items-center gap-3 rounded-2xl border px-4 py-3 text-left ${item.lessonId === lesson?.lessonId ? 'border-[#00c471]/40 bg-emerald-50/80' : 'border-gray-200 bg-gray-50'}`}><span className={`flex h-10 w-10 items-center justify-center rounded-full text-sm ${item.lessonId === lesson?.lessonId ? 'bg-[#00c471] text-white' : 'bg-white text-gray-400'}`}><i className="fas fa-play" /></span><span className="min-w-0 flex-1"><span className="block truncate text-sm font-bold text-gray-900">{item.title}</span><span className="mt-1 block text-xs text-gray-500">{formatDurationLabel(item.durationSeconds)}</span></span></button>)}</div></div>)}</div></section>
              <section className="rounded-[24px] border border-gray-200 bg-white p-5 shadow-sm">{lesson?.materials.length ? <div className="space-y-3">{lesson.materials.map((material) => <a key={material.materialId} href={resolveMaterialDownloadHref(lesson.lessonId, material.materialId)} className="flex items-center justify-between rounded-2xl border border-gray-200 bg-gray-50 px-4 py-3"><span><span className="block text-sm font-bold text-gray-900">{material.originalFileName}</span><span className="mt-1 block text-xs text-gray-500">{material.materialType}</span></span><i className="fas fa-download text-sm text-gray-400" /></a>)}</div> : <div className="rounded-2xl border border-dashed border-gray-200 bg-gray-50 px-4 py-6 text-sm text-gray-500">현재 레슨에 연결된 학습 자료가 없습니다.</div>}</section>
            </div> : null}
            {activeTab === 'assignment' ? <div className="space-y-6">
              <section className="rounded-[24px] border border-gray-200 bg-white p-5 shadow-sm"><div className="mb-3 flex items-center gap-2"><span className="rounded-full border border-rose-200 bg-rose-50 px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.16em] text-rose-600">필수 과제</span><span className="text-xs font-semibold text-gray-400">{assignment.assignmentId ? `API #${assignment.assignmentId}` : '로컬 실행'}</span></div><h2 className="text-xl font-black text-gray-900">{assignment.title}</h2><p className="mt-3 text-sm leading-6 text-gray-600">{assignment.description}</p><textarea value={assignmentForm.submissionText} onChange={(event) => setAssignmentForm((current) => ({ ...current, submissionText: event.target.value }))} rows={5} placeholder="이번 과제에서 구현한 내용과 테스트 결과를 정리해 주세요." className="input-shell mt-4 resize-none" /><input value={assignmentForm.submissionUrl} onChange={(event) => setAssignmentForm((current) => ({ ...current, submissionUrl: event.target.value }))} placeholder="제출 URL을 입력하세요." className="input-shell mt-4" /><div className="mt-4 grid gap-3 sm:grid-cols-3">{checklistItems.map((item) => <label key={item.key} className="flex items-center justify-between rounded-2xl border border-gray-200 bg-gray-50 px-4 py-3 text-sm font-semibold text-gray-700">{item.label}<input type="checkbox" checked={assignmentForm[item.key]} onChange={(event) => setAssignmentForm((current) => ({ ...current, [item.key]: event.target.checked }))} className="h-4 w-4 accent-[#00c471]" /></label>)}</div><label className="mt-4 block rounded-[22px] border-2 border-dashed border-gray-300 bg-gray-50 px-4 py-6 text-center"><input type="file" multiple className="hidden" onChange={(event) => setAssignmentForm((current) => ({ ...current, files: Array.from(event.target.files ?? []) }))} /><div className="text-3xl text-gray-300"><i className="fas fa-cloud-upload-alt" /></div><div className="mt-2 text-sm font-bold text-gray-600">과제 파일 업로드</div></label><div className="mt-5 flex flex-col gap-3 sm:flex-row"><button type="button" onClick={() => void handlePrecheckAssignment()} disabled={assignmentBusy} className="flex-1 rounded-2xl border border-gray-200 bg-white px-4 py-3 text-sm font-bold text-gray-800">{assignmentBusy ? '검증 중...' : '과제 사전 검증'}</button><button type="button" onClick={() => void handleSubmitAssignment()} disabled={assignmentBusy} className="flex-1 rounded-2xl bg-[#00c471] px-4 py-3 text-sm font-bold text-white">{assignmentBusy ? '제출 중...' : '과제 제출'}</button></div>{assignmentMessage ? <div className="mt-4 rounded-2xl border border-emerald-100 bg-emerald-50 px-4 py-3 text-sm text-emerald-700">{assignmentMessage}</div> : null}{assignmentPrecheck ? <div className="mt-4 rounded-[22px] border border-gray-200 bg-gray-50 p-4"><div className="text-sm text-gray-600">점수: {assignmentPrecheck.qualityScore ?? '--'} / 100</div><div className="mt-2 text-sm text-gray-500">{assignmentPrecheck.message}</div></div> : null}{assignmentSubmission ? <div className="mt-4 rounded-[22px] border border-gray-200 bg-white p-4 shadow-sm"><div className="text-base font-black text-gray-900">{assignmentSubmission.totalScore ?? '--'}점</div><div className="mt-1 text-xs text-gray-400">{formatDateLabel(assignmentSubmission.submittedAt)}</div></div> : null}</section>
              <section className="rounded-[24px] border border-gray-200 bg-white p-5 shadow-sm"><div className="mb-3 flex items-center gap-2"><span className="rounded-full border border-sky-200 bg-sky-50 px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.16em] text-sky-600">퀴즈</span><span className="text-xs font-semibold text-gray-400">로컬 채점 모드</span></div><div className="space-y-4">{quiz.questions.map((question, index) => <div key={question.questionId} className="rounded-[22px] border border-gray-200 bg-gray-50 p-4"><div className="text-xs font-black uppercase tracking-[0.18em] text-gray-400">Question {index + 1}</div><div className="mt-2 text-sm font-bold leading-6 text-gray-900">{question.questionText}</div>{question.questionType === 'MULTIPLE_CHOICE' ? <div className="mt-4 space-y-2">{question.options.map((option) => <label key={option.optionId} className="flex cursor-pointer items-center gap-3 rounded-2xl border border-gray-200 bg-white px-4 py-3 text-sm text-gray-700"><input type="radio" name={`quiz-${question.questionId}`} checked={quizAnswers[question.questionId]?.selectedOptionId === option.optionId} onChange={() => setQuizAnswers((current) => ({ ...current, [question.questionId]: { selectedOptionId: option.optionId } }))} className="h-4 w-4 accent-[#00c471]" /><span>{option.optionText}</span></label>)}</div> : <textarea rows={3} value={quizAnswers[question.questionId]?.textAnswer ?? ''} onChange={(event) => setQuizAnswers((current) => ({ ...current, [question.questionId]: { textAnswer: event.target.value } }))} className="input-shell mt-4 resize-none" />}</div>)}</div><button type="button" onClick={handleSubmitQuiz} disabled={quizBusy} className="mt-5 w-full rounded-2xl bg-gray-900 px-4 py-3 text-sm font-bold text-white">{quizBusy ? '채점 중...' : '퀴즈 제출'}</button>{quizMessage ? <div className="mt-4 rounded-2xl border border-sky-100 bg-sky-50 px-4 py-3 text-sm text-sky-700">{quizMessage}</div> : null}{quizResult ? <div className="mt-4 rounded-[22px] border border-gray-200 bg-gray-50 p-4"><div className="text-4xl font-black text-[#00c471]">{quizResult.score}<span className="ml-1 text-lg font-medium text-gray-400">/ {quizResult.maxScore}</span></div><div className="mt-4 space-y-3">{quizResult.questionResults.map((item) => <div key={item.questionId} className="rounded-2xl bg-white p-4"><div className="text-sm font-bold text-gray-900">{item.questionText}</div><div className="mt-2 text-xs leading-6 text-gray-500">내 답변: {item.selectedOptionText ?? item.textAnswer ?? '미응답'}</div><div className="text-xs leading-6 text-gray-500">정답: {item.correctAnswerText ?? '정보 없음'}</div><div className="mt-2 text-xs leading-6 text-gray-600">{item.explanation ?? ''}</div></div>)}</div></div> : null}</section>
            </div> : null}
            {activeTab === 'notes' ? <div className="space-y-6">
              <section className="rounded-[24px] border border-gray-200 bg-white p-5 shadow-sm"><div className="mb-4 flex items-center justify-between gap-4"><div><div className="text-xs font-black uppercase tracking-[0.18em] text-[#00c471]">Timestamp Notes</div><h2 className="mt-2 text-xl font-black text-gray-900">영상 노트</h2></div><button type="button" onClick={() => setNoteMessage(`현재 시점 ${formatTime(currentTime)}`)} className="rounded-full border border-gray-200 bg-gray-50 px-3 py-2 text-xs font-bold text-gray-700">현재 시점 확인</button></div><div className="rounded-2xl border border-gray-200 bg-gray-50 px-4 py-3 text-sm text-gray-600">현재 타임스탬프: <span className="font-black text-gray-900">{formatTime(currentTime)}</span></div><textarea rows={5} value={noteContent} onChange={(event) => setNoteContent(event.target.value)} className="input-shell mt-4 resize-none" placeholder="핵심 개념, 다시 볼 포인트, 실습 메모를 기록하세요." /><button type="button" onClick={() => void handleSaveNote()} className="mt-4 w-full rounded-2xl bg-[#00c471] px-4 py-3 text-sm font-bold text-white">노트 저장</button>{noteMessage ? <div className="mt-4 rounded-2xl border border-emerald-100 bg-emerald-50 px-4 py-3 text-sm text-emerald-700">{noteMessage}</div> : null}</section>
              <section className="rounded-[24px] border border-gray-200 bg-white p-5 shadow-sm">{notes.length ? <div className="space-y-3">{notes.map((note) => <div key={note.noteId} className="rounded-[22px] border border-gray-200 bg-gray-50 p-4"><div className="flex items-start justify-between gap-4"><button type="button" onClick={() => handleSeek(note.seekSecond)} className="rounded-full bg-gray-900 px-3 py-1.5 text-xs font-bold text-white">{note.timestampLabel}</button><button type="button" onClick={() => void handleDeleteNote(note)} className="text-xs text-gray-400 hover:text-rose-500">삭제</button></div><p className="mt-3 text-sm leading-6 text-gray-700">{note.content}</p><div className="mt-3 text-xs text-gray-400">{formatDateLabel(note.updatedAt ?? note.createdAt)}</div></div>)}</div> : <div className="rounded-2xl border border-dashed border-gray-200 bg-gray-50 px-4 py-6 text-sm text-gray-500">아직 저장된 노트가 없습니다.</div>}</section>
            </div> : null}
            {activeTab === 'ocr' ? (
              <Suspense
                fallback={
                  <section className="rounded-[24px] border border-gray-200 bg-white p-5 shadow-sm">
                    <div className="flex items-center gap-3 text-sm text-gray-500">
                      <div className="h-5 w-5 animate-spin rounded-full border-2 border-[#00c471] border-t-transparent" />
                      OCR 패널을 불러오는 중입니다.
                    </div>
                  </section>
                }
              >
                <LearningOcrPanel
                  busy={ocr.busy}
                  selecting={ocr.selecting}
                  statusTone={ocr.statusTone}
                  statusMessage={ocr.statusMessage}
                  progressPercent={ocr.progressPercent}
                  result={ocr.result}
                  onRunCurrentFrame={() => void handleRunCurrentFrameOcr()}
                  onStartRegionSelection={handleStartRegionOcr}
                  onCancelSelection={ocr.cancelRegionSelection}
                  onCopy={() => void ocr.copyRecognizedText()}
                />
              </Suspense>
            ) : null}
          </div>
        </aside>
      </div>
      {loadingCourse ? <div className="fixed inset-0 z-[1000] flex items-center justify-center bg-black/70 backdrop-blur-sm"><div className="h-14 w-14 animate-spin rounded-full border-4 border-[#00c471] border-t-transparent" /></div> : null}
    </div>
  )
}
