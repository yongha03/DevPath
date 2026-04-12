import { startTransition, useDeferredValue, useEffect, useEffectEvent, useMemo, useRef, useState } from 'react'
import { courseApi, learningPlayerApi, lessonNoteApi, lessonSessionApi, qnaApi } from './lib/api'
import { AUTH_SESSION_SYNC_EVENT, readStoredAuthSession } from './lib/auth-session'
import {
  createDefaultProgress,
  formatDateLabel,
  formatDurationLabel,
  formatTime,
  getFlattenedLessons,
  getNotesStorageKey,
  getProgressStorageKey,
  normalizeCourseDetail,
  PLAYER_SPEEDS,
  readJsonStorage,
  readNumberSearchParam,
  resolveMaterialDownloadHref,
  syncLearningUrl,
  writeJsonStorage,
} from './learning-support'
import type { AuthSession } from './types/auth'
import type { LearningCourseDetail, LearningLessonProgress, LearningPlayerConfig, TimestampNote } from './types/learning'
import type {
  CreateQnaQuestionRequest,
  QnaDifficulty,
  QnaQuestionDetail,
  QnaQuestionSummary,
  QnaQuestionTemplate,
} from './types/qna'

type TabKey = 'curriculum' | 'qna' | 'notes'
type QnaStatusFilter = 'ALL' | 'ANSWERED' | 'UNANSWERED'
type QuestionFormState = {
  templateType: string
  difficulty: QnaDifficulty
  title: string
  content: string
  attachTimestamp: boolean
}

type PipDocument = Document & {
  pictureInPictureElement?: Element | null
  pictureInPictureEnabled?: boolean
  exitPictureInPicture?: () => Promise<void>
}

type PipVideoElement = HTMLVideoElement & {
  requestPictureInPicture?: () => Promise<unknown>
}

const COURSE_LOAD_TIMEOUT_MS = 4000
const LESSON_LOAD_TIMEOUT_MS = 2500
const QNA_LOAD_TIMEOUT_MS = 2500

function isAbortError(error: unknown) {
  return error instanceof DOMException && error.name === 'AbortError'
}

async function requestWithTimeout<T>(timeoutMs: number, executor: (signal: AbortSignal) => Promise<T>) {
  const controller = new AbortController()
  const timeoutId = window.setTimeout(() => controller.abort(), timeoutMs)

  try {
    return await executor(controller.signal)
  } finally {
    window.clearTimeout(timeoutId)
  }
}

function createDefaultPlayerConfig(lessonId: number): LearningPlayerConfig {
  return { lessonId, defaultPlaybackRate: 1, pipEnabled: false }
}

function createQuestionFormState(): QuestionFormState {
  return { templateType: '', difficulty: 'MEDIUM', title: '', content: '', attachTimestamp: true }
}

function isQuestionAnswered(question: Pick<QnaQuestionSummary, 'qnaStatus' | 'adoptedAnswerId' | 'answerCount'>) {
  return question.qnaStatus === 'ANSWERED' || Boolean(question.adoptedAnswerId) || question.answerCount > 0
}

function formatRelativeTime(value: string | null) {
  if (!value) return 'just now'

  const parsed = new Date(value)
  const diffMs = Date.now() - parsed.getTime()
  if (!Number.isFinite(diffMs) || diffMs < 0) return formatDateLabel(value)

  const minuteMs = 60 * 1000
  const hourMs = 60 * minuteMs
  const dayMs = 24 * hourMs

  if (diffMs < hourMs) return `${Math.max(1, Math.floor(diffMs / minuteMs))}m ago`
  if (diffMs < dayMs) return `${Math.max(1, Math.floor(diffMs / hourMs))}h ago`
  return `${Math.max(1, Math.floor(diffMs / dayMs))}d ago`
}

function toQuestionSummary(question: QnaQuestionDetail): QnaQuestionSummary {
  return {
    id: question.id,
    authorId: question.authorId,
    authorName: question.authorName,
    courseId: question.courseId,
    templateType: question.templateType,
    difficulty: question.difficulty,
    title: question.title,
    adoptedAnswerId: question.adoptedAnswerId,
    lectureTimestamp: question.lectureTimestamp,
    qnaStatus: question.qnaStatus,
    answerCount: question.answerCount,
    viewCount: question.viewCount,
    createdAt: question.createdAt,
  }
}

function EmptyState(props: { iconClassName: string; title: string; description: string }) {
  return (
    <div className="rounded-[24px] border border-dashed border-gray-200 bg-white px-6 py-10 text-center shadow-sm">
      <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-gray-100 text-gray-400">
        <i className={props.iconClassName} />
      </div>
      <h3 className="mt-4 text-sm font-black text-gray-900">{props.title}</h3>
      <p className="mt-2 text-sm leading-6 text-gray-500">{props.description}</p>
    </div>
  )
}

function LoadingOverlay() {
  return (
    <div className="fixed inset-0 z-[1000] flex items-center justify-center bg-black/65 backdrop-blur-sm">
      <div className="h-14 w-14 animate-spin rounded-full border-4 border-[#00c471] border-t-transparent" />
    </div>
  )
}

function LoginRequiredView() {
  return (
    <div className="min-h-screen bg-[#0a100f] px-4 py-16 text-white">
      <div className="mx-auto max-w-xl rounded-[32px] border border-white/10 bg-white/5 px-8 py-10 text-center backdrop-blur">
        <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-emerald-500/15 text-emerald-300">
          <i className="fas fa-user-lock text-2xl" />
        </div>
        <h1 className="mt-6 text-3xl font-black">Login Required</h1>
        <p className="mt-3 text-sm leading-7 text-white/70">This learning player is available only to signed-in users.</p>
        <div className="mt-8 flex flex-col gap-3 sm:flex-row sm:justify-center">
          <a href="home.html?auth=login" className="rounded-full bg-[#00c471] px-6 py-3 text-sm font-bold text-white">Go to Login</a>
          <a href="lecture-list.html" className="rounded-full border border-white/15 px-6 py-3 text-sm font-bold text-white/80">Course List</a>
        </div>
      </div>
    </div>
  )
}

function ErrorView(props: { title: string; message: string; actionHref: string; actionLabel: string }) {
  return (
    <div className="min-h-screen bg-[#0a100f] px-4 py-16 text-white">
      <div className="mx-auto max-w-xl rounded-[32px] border border-white/10 bg-white/5 px-8 py-10 text-center backdrop-blur">
        <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-rose-500/15 text-rose-300">
          <i className="fas fa-circle-exclamation text-2xl" />
        </div>
        <h1 className="mt-6 text-3xl font-black">{props.title}</h1>
        <p className="mt-3 text-sm leading-7 text-white/70">{props.message}</p>
        <div className="mt-8">
          <a href={props.actionHref} className="inline-flex rounded-full bg-[#00c471] px-6 py-3 text-sm font-bold text-white">
            {props.actionLabel}
          </a>
        </div>
      </div>
    </div>
  )
}

export default function LearningPlayerApp() {
  const initialCourseId = useMemo(() => readNumberSearchParam('courseId'), [])
  const initialLessonId = useMemo(() => readNumberSearchParam('lessonId'), [])

  const [session, setSession] = useState<AuthSession | null>(() => readStoredAuthSession())
  const [course, setCourse] = useState<LearningCourseDetail | null>(null)
  const [courseError, setCourseError] = useState<string | null>(null)
  const [selectedLessonId, setSelectedLessonId] = useState<number | null>(initialLessonId)
  const [activeTab, setActiveTab] = useState<TabKey>('curriculum')
  const [notice, setNotice] = useState<string | null>(null)
  const [loadingCourse, setLoadingCourse] = useState(true)
  const [loadingLesson, setLoadingLesson] = useState(false)
  const [progress, setProgress] = useState<LearningLessonProgress | null>(null)
  const [playerConfig, setPlayerConfig] = useState<LearningPlayerConfig | null>(null)
  const [notes, setNotes] = useState<TimestampNote[]>([])
  const [noteContent, setNoteContent] = useState('')
  const [noteMessage, setNoteMessage] = useState<string | null>(null)
  const [currentTime, setCurrentTime] = useState(0)
  const [duration, setDuration] = useState(0)
  const [isPlaying, setIsPlaying] = useState(false)
  const [videoFailed, setVideoFailed] = useState(false)
  const [qnaTemplates, setQnaTemplates] = useState<QnaQuestionTemplate[]>([])
  const [qnaQuestions, setQnaQuestions] = useState<QnaQuestionSummary[]>([])
  const [qnaDetails, setQnaDetails] = useState<Record<number, QnaQuestionDetail>>({})
  const [loadingQna, setLoadingQna] = useState(false)
  const [qnaError, setQnaError] = useState<string | null>(null)
  const [qnaStatusFilter, setQnaStatusFilter] = useState<QnaStatusFilter>('ALL')
  const [qnaSearch, setQnaSearch] = useState('')
  const [openQuestionId, setOpenQuestionId] = useState<number | null>(null)
  const [loadingQuestionId, setLoadingQuestionId] = useState<number | null>(null)
  const [questionForm, setQuestionForm] = useState<QuestionFormState>(createQuestionFormState)
  const [questionMessage, setQuestionMessage] = useState<string | null>(null)
  const [questionBusy, setQuestionBusy] = useState(false)

  const videoRef = useRef<HTMLVideoElement | null>(null)
  const frameRef = useRef<HTMLDivElement | null>(null)
  const resumeTimeRef = useRef(0)
  const lastRenderedSecondRef = useRef(-1)

  const lessons = useMemo(() => (course ? getFlattenedLessons(course) : []), [course])
  const lesson = useMemo(
    () => lessons.find((item) => item.lessonId === selectedLessonId) ?? lessons[0] ?? null,
    [lessons, selectedLessonId],
  )
  const lessonIndex = useMemo(
    () => (lesson ? lessons.findIndex((item) => item.lessonId === lesson.lessonId) + 1 : 0),
    [lesson, lessons],
  )
  const totalDurationSeconds = useMemo(
    () => lessons.reduce((sum, item) => sum + (item.durationSeconds ?? 0), 0),
    [lessons],
  )
  const sessionUserId = session?.userId ?? null
  const courseDetailHref = initialCourseId
    ? `course-detail.html?courseId=${course?.courseId ?? initialCourseId}`
    : 'lecture-list.html'
  const deferredQnaSearch = useDeferredValue(qnaSearch.trim().toLowerCase())
  const templateOptions = useMemo(
    () => [...qnaTemplates].sort((a, b) => a.sortOrder - b.sortOrder || a.name.localeCompare(b.name)),
    [qnaTemplates],
  )
  const selectedTemplate = useMemo(
    () => templateOptions.find((item) => item.templateType === questionForm.templateType) ?? null,
    [questionForm.templateType, templateOptions],
  )
  const visibleQuestions = useMemo(() => (
    qnaQuestions.filter((item) => {
      const answered = isQuestionAnswered(item)
      const statusMatched = qnaStatusFilter === 'ALL'
        || (qnaStatusFilter === 'ANSWERED' && answered)
        || (qnaStatusFilter === 'UNANSWERED' && !answered)
      const searchTarget = [item.authorName, item.title, item.lectureTimestamp ?? '', qnaDetails[item.id]?.content ?? '']
        .join(' ')
        .toLowerCase()
      return statusMatched && (!deferredQnaSearch || searchTarget.includes(deferredQnaSearch))
    })
  ), [deferredQnaSearch, qnaDetails, qnaQuestions, qnaStatusFilter])

  const getPlaybackLimit = (video: HTMLVideoElement | null) => {
    const metadataDuration = video && Number.isFinite(video.duration) && video.duration > 0 ? Math.floor(video.duration) : 0
    const declaredDuration = lesson?.durationSeconds ?? 0
    if (metadataDuration > 0 && declaredDuration > 0) return Math.min(metadataDuration, declaredDuration)
    return metadataDuration || declaredDuration
  }

  useEffect(() => {
    const syncSession = () => setSession(readStoredAuthSession())
    window.addEventListener('storage', syncSession)
    window.addEventListener(AUTH_SESSION_SYNC_EVENT, syncSession)
    return () => {
      window.removeEventListener('storage', syncSession)
      window.removeEventListener(AUTH_SESSION_SYNC_EVENT, syncSession)
    }
  }, [])

  useEffect(() => {
    if (course && lesson) {
      document.title = `DevPath - ${course.title} | ${lesson.title}`
      syncLearningUrl(course.courseId, lesson.lessonId)
      return
    }

    document.title = 'DevPath - Learning Player'
  }, [course, lesson])

  useEffect(() => {
    if (!session) {
      setLoadingCourse(false)
      return
    }

    let cancelled = false

    async function loadCourse() {
      setLoadingCourse(true)
      setCourseError(null)

      if (!initialCourseId) {
        setCourse(null)
        setCourseError('Missing courseId.')
        setLoadingCourse(false)
        return
      }

      try {
        const response = await requestWithTimeout(COURSE_LOAD_TIMEOUT_MS, (signal) => courseApi.getCourseDetail(initialCourseId, signal))
        if (cancelled) return
        const normalizedCourse = normalizeCourseDetail(response)
        const nextLessons = getFlattenedLessons(normalizedCourse)

        if (!nextLessons.length) {
          setCourse(null)
          setCourseError('No published lessons are available for this course.')
          return
        }

        setCourse(normalizedCourse)
        setSelectedLessonId(
          (initialLessonId && nextLessons.some((item) => item.lessonId === initialLessonId))
            ? initialLessonId
            : nextLessons[0].lessonId,
        )
      } catch (error) {
        if (cancelled) return
        setCourse(null)
        setCourseError(isAbortError(error) ? 'Timed out while loading course data.' : 'Failed to load course data.')
      } finally {
        if (!cancelled) setLoadingCourse(false)
      }
    }

    void loadCourse()

    return () => {
      cancelled = true
    }
  }, [initialCourseId, initialLessonId, session])

  useEffect(() => {
    if (!session || !course?.courseId) return

    let cancelled = false
    const courseId = course.courseId

    async function loadQna() {
      setLoadingQna(true)
      setQnaError(null)
      setQnaDetails({})
      setOpenQuestionId(null)
      setQuestionForm(createQuestionFormState())

      const [questionsResult, templatesResult] = await Promise.allSettled([
        requestWithTimeout(QNA_LOAD_TIMEOUT_MS, (signal) => qnaApi.getQuestions(courseId, signal)),
        requestWithTimeout(QNA_LOAD_TIMEOUT_MS, (signal) => qnaApi.getTemplates(signal)),
      ])

      if (cancelled) return

      if (questionsResult.status === 'fulfilled') setQnaQuestions(questionsResult.value)
      else {
        setQnaQuestions([])
        setQnaError('Failed to load Q&A data.')
      }

      if (templatesResult.status === 'fulfilled') {
        setQnaTemplates(templatesResult.value)
        setQuestionForm((current) => ({
          ...current,
          templateType: current.templateType || templatesResult.value[0]?.templateType || '',
        }))
      } else {
        setQnaTemplates([])
      }

      setLoadingQna(false)
    }

    void loadQna()

    return () => {
      cancelled = true
    }
  }, [course?.courseId, session])

  useEffect(() => {
    if (!lesson) {
      setProgress(null)
      setPlayerConfig(null)
      setNotes([])
      setDuration(0)
      setCurrentTime(0)
      return
    }

    let cancelled = false

    async function loadLessonState() {
      setLoadingLesson(true)
      setNotice(null)
      setVideoFailed(false)
      setNoteContent('')
      setNoteMessage(null)

      const storedProgress = readJsonStorage(getProgressStorageKey(lesson.lessonId), createDefaultProgress(lesson.lessonId))
      const storedNotes = readJsonStorage(getNotesStorageKey(lesson.lessonId), [] as TimestampNote[])

      resumeTimeRef.current = storedProgress.progressSeconds
      lastRenderedSecondRef.current = storedProgress.progressSeconds
      setProgress(storedProgress)
      setPlayerConfig(createDefaultPlayerConfig(lesson.lessonId))
      setNotes(storedNotes)
      setCurrentTime(storedProgress.progressSeconds)
      setDuration(lesson.durationSeconds ?? 0)

      try {
        const [sessionProgress, config, fetchedNotes] = await Promise.all([
          requestWithTimeout(LESSON_LOAD_TIMEOUT_MS, (signal) => lessonSessionApi.startSession(lesson.lessonId, signal)),
          requestWithTimeout(LESSON_LOAD_TIMEOUT_MS, (signal) => learningPlayerApi.getPlayerConfig(lesson.lessonId, signal)).catch(() => null),
          requestWithTimeout(LESSON_LOAD_TIMEOUT_MS, (signal) => lessonNoteApi.getNotes(lesson.lessonId, signal)).catch(() => null),
        ])

        if (cancelled) return

        const nextProgress = {
          ...sessionProgress,
          defaultPlaybackRate: config?.defaultPlaybackRate ?? sessionProgress.defaultPlaybackRate ?? 1,
          pipEnabled: config?.pipEnabled ?? sessionProgress.pipEnabled ?? false,
        }

        resumeTimeRef.current = nextProgress.progressSeconds
        lastRenderedSecondRef.current = nextProgress.progressSeconds
        setProgress(nextProgress)
        setPlayerConfig({
          lessonId: lesson.lessonId,
          defaultPlaybackRate: nextProgress.defaultPlaybackRate,
          pipEnabled: nextProgress.pipEnabled,
        })
        setCurrentTime(nextProgress.progressSeconds)
        writeJsonStorage(getProgressStorageKey(lesson.lessonId), nextProgress)

        if (fetchedNotes) {
          setNotes(fetchedNotes)
          writeJsonStorage(getNotesStorageKey(lesson.lessonId), fetchedNotes)
        }
      } catch (error) {
        if (!cancelled && isAbortError(error)) setNotice('Loading lesson state took too long. Showing cached values.')
      } finally {
        if (!cancelled) setLoadingLesson(false)
      }
    }

    void loadLessonState()

    return () => {
      cancelled = true
    }
  }, [lesson])

  useEffect(() => {
    const video = videoRef.current
    if (!lesson) return

    if (!video || !lesson.videoUrl) {
      setDuration(lesson.durationSeconds ?? 0)
      setIsPlaying(false)
      return
    }

    video.playbackRate = playerConfig?.defaultPlaybackRate ?? 1

    const handleLoadedMetadata = () => {
      const total = getPlaybackLimit(video)
      setDuration(total)
      if (resumeTimeRef.current > 0) video.currentTime = Math.min(resumeTimeRef.current, total || resumeTimeRef.current)
    }

    const handleTimeUpdate = () => {
      const total = getPlaybackLimit(video)
      if (total > 0 && video.currentTime >= total) {
        if (Math.floor(video.currentTime) !== total) video.currentTime = total
        if (!video.paused) video.pause()
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
  }, [lesson, playerConfig?.defaultPlaybackRate])

  const persistProgress = useEffectEvent(async (lessonId: number) => {
    if (!lesson || lesson.lessonId !== lessonId) return

    const video = videoRef.current
    const total = getPlaybackLimit(video)
    const currentSeconds = video ? Math.floor(video.currentTime) : Math.floor(currentTime)
    const progressSeconds = total > 0 ? Math.min(currentSeconds, total) : currentSeconds
    const progressPercent = total > 0 ? Math.max(0, Math.min(100, Math.round((progressSeconds / total) * 100))) : 0

    const nextProgress: LearningLessonProgress = {
      lessonId,
      progressPercent,
      progressSeconds,
      defaultPlaybackRate: playerConfig?.defaultPlaybackRate ?? 1,
      pipEnabled: playerConfig?.pipEnabled ?? false,
      isCompleted: progressPercent >= 95,
      lastWatchedAt: new Date().toISOString(),
    }

    setProgress(nextProgress)
    writeJsonStorage(getProgressStorageKey(lessonId), nextProgress)

    try {
      await lessonSessionApi.saveProgress(lessonId, { progressPercent, progressSeconds })
    } catch {
      // Keep cached progress even when the request fails.
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
  }, [lesson, persistProgress])

  useEffect(() => {
    if (!noteMessage && !notice && !questionMessage) return
    const timeoutId = window.setTimeout(() => {
      setNoteMessage(null)
      setNotice(null)
      setQuestionMessage(null)
    }, 2600)
    return () => window.clearTimeout(timeoutId)
  }, [noteMessage, notice, questionMessage])

  async function handleTogglePlay() {
    const video = videoRef.current
    if (!video || !lesson?.videoUrl) return

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
        setNotice('Playback was blocked by browser autoplay policy.')
      }
      return
    }

    video.pause()
  }

  function handleSeek(nextSeconds: number) {
    const video = videoRef.current
    if (!video) return

    const upperBound = getPlaybackLimit(video) || (lesson?.durationSeconds ?? 0) || nextSeconds
    const bounded = Math.max(0, Math.min(upperBound, nextSeconds))
    video.currentTime = bounded
    lastRenderedSecondRef.current = Math.floor(bounded)
    setCurrentTime(Math.floor(bounded))
  }

  async function handleTogglePip() {
    if (!lesson || !playerConfig) return

    const pipDocument = document as PipDocument
    const video = videoRef.current as PipVideoElement | null
    if (!video) return

    const nextPipEnabled = !playerConfig.pipEnabled
    let pipUpdated = false

    try {
      if (pipDocument.pictureInPictureEnabled && video.requestPictureInPicture) {
        if (pipDocument.pictureInPictureElement && pipDocument.exitPictureInPicture) await pipDocument.exitPictureInPicture()
        else await video.requestPictureInPicture()
        pipUpdated = true
      } else {
        setNotice('Picture-in-Picture is not supported in this browser.')
      }
    } catch {
      setNotice('Failed to toggle Picture-in-Picture.')
    }

    if (!pipUpdated) return

    setPlayerConfig({ ...playerConfig, pipEnabled: nextPipEnabled })

    try {
      await learningPlayerApi.updatePipMode(lesson.lessonId, nextPipEnabled)
    } catch {
      // Keep local preference.
    }
  }

  async function handleCyclePlaybackRate() {
    if (!lesson || !playerConfig) return
    const currentIndex = PLAYER_SPEEDS.indexOf(playerConfig.defaultPlaybackRate as (typeof PLAYER_SPEEDS)[number])
    const nextRate = PLAYER_SPEEDS[(currentIndex + 1 + PLAYER_SPEEDS.length) % PLAYER_SPEEDS.length]
    setPlayerConfig({ ...playerConfig, defaultPlaybackRate: nextRate })
    if (videoRef.current) videoRef.current.playbackRate = nextRate
    try {
      await learningPlayerApi.updatePlaybackRate(lesson.lessonId, nextRate)
    } catch {
      // Keep local preference.
    }
  }

  async function handleToggleQuestion(questionId: number) {
    setOpenQuestionId((current) => (current === questionId ? null : questionId))
    if (qnaDetails[questionId] || loadingQuestionId === questionId) return

    setLoadingQuestionId(questionId)
    try {
      const detail = await qnaApi.getQuestionDetail(questionId)
      setQnaDetails((current) => ({ ...current, [questionId]: detail }))
      setQnaQuestions((current) => current.map((item) => (item.id === questionId ? toQuestionSummary(detail) : item)))
    } catch {
      setQnaError('Failed to load the question detail.')
    } finally {
      setLoadingQuestionId((current) => (current === questionId ? null : current))
    }
  }

  async function handleSaveNote() {
    if (!lesson || !noteContent.trim()) return

    try {
      const created = await lessonNoteApi.createNote(lesson.lessonId, {
        timestampSecond: Math.floor(currentTime),
        content: noteContent.trim(),
      })
      const nextNotes = [...notes, created].sort((a, b) => a.timestampSecond - b.timestampSecond)
      setNotes(nextNotes)
      writeJsonStorage(getNotesStorageKey(lesson.lessonId), nextNotes)
      setNoteContent('')
      setNoteMessage('Note saved.')
    } catch {
      setNoteMessage('Failed to save note.')
    }
  }

  async function handleDeleteNote(note: TimestampNote) {
    if (!lesson) return

    try {
      await lessonNoteApi.deleteNote(lesson.lessonId, note.noteId)
      const nextNotes = notes.filter((item) => item.noteId !== note.noteId)
      setNotes(nextNotes)
      writeJsonStorage(getNotesStorageKey(lesson.lessonId), nextNotes)
      setNoteMessage('Note deleted.')
    } catch {
      setNoteMessage('Failed to delete note.')
    }
  }

  async function handleSubmitQuestion() {
    if (!course || !sessionUserId || !questionForm.templateType) return

    const title = questionForm.title.trim()
    const content = questionForm.content.trim()
    if (!title || !content) {
      setQuestionMessage('Enter both a title and content.')
      return
    }

    const payload: CreateQnaQuestionRequest = {
      templateType: questionForm.templateType,
      difficulty: questionForm.difficulty,
      title,
      content,
      courseId: course.courseId,
      lectureTimestamp: questionForm.attachTimestamp ? formatTime(currentTime) : null,
    }

    setQuestionBusy(true)
    try {
      const created = await qnaApi.createQuestion(payload, sessionUserId)
      setQnaDetails((current) => ({ ...current, [created.id]: created }))
      setQnaQuestions((current) => [toQuestionSummary(created), ...current.filter((item) => item.id !== created.id)])
      setQuestionForm((current) => ({ ...current, title: '', content: '' }))
      setQuestionMessage('Question posted.')
      startTransition(() => {
        setActiveTab('qna')
        setOpenQuestionId(created.id)
      })
    } catch {
      setQuestionMessage('Failed to post the question.')
    } finally {
      setQuestionBusy(false)
    }
  }

  if (!session) return <LoginRequiredView />

  if (!loadingCourse && courseError) {
    return (
      <ErrorView
        title="Unable to open the learning page"
        message={courseError}
        actionHref={courseDetailHref}
        actionLabel={initialCourseId ? 'Back to Course Detail' : 'Go to Course List'}
      />
    )
  }

  if (!course || !lesson) return <LoadingOverlay />

  const hasVideoSource = Boolean(lesson.videoUrl) && !videoFailed

  return (
    <div className="min-h-screen bg-[#050908] text-white">
      <div className="flex min-h-screen flex-col lg:flex-row">
        <section className="relative flex min-h-[58vh] flex-1 flex-col bg-black lg:min-h-screen">
          <div className="absolute inset-x-0 top-0 z-20 bg-gradient-to-b from-black/90 via-black/50 to-transparent px-4 py-4 lg:px-6">
            <div className="flex items-start justify-between gap-4">
              <button
                type="button"
                onClick={() => (window.history.length > 1 ? window.history.back() : window.location.assign(courseDetailHref))}
                className="inline-flex items-center gap-2 text-sm font-bold text-white/70 transition hover:text-[#00c471]"
              >
                <i className="fas fa-chevron-left" />
                Back to course
              </button>
              <div className="hidden min-w-0 flex-1 flex-col items-center sm:flex">
                <div className="truncate text-sm font-black text-white/85">{course.title}</div>
                <div className="mt-1 truncate text-xs text-white/50">
                  Lesson {lessonIndex}/{lessons.length} | {lesson.title}
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => startTransition(() => setActiveTab('qna'))}
                  className="rounded-full border border-white/10 bg-white/10 px-3 py-1.5 text-xs font-semibold text-white/80 transition hover:bg-white/15"
                >
                  Q&A
                </button>
                <button
                  type="button"
                  onClick={() => startTransition(() => setActiveTab('notes'))}
                  className="rounded-full border border-white/10 bg-white/10 px-3 py-1.5 text-xs font-semibold text-white/80 transition hover:bg-white/15"
                >
                  Notes
                </button>
              </div>
            </div>
          </div>

          <div ref={frameRef} className="relative flex flex-1 items-center justify-center overflow-hidden bg-[#090f0d]">
            {hasVideoSource ? (
              <>
                <video
                  ref={videoRef}
                  src={lesson.videoUrl ?? undefined}
                  poster={lesson.thumbnailUrl ?? course.thumbnailUrl ?? undefined}
                  className="h-full w-full object-contain"
                  playsInline
                  preload="metadata"
                  onError={() => setVideoFailed(true)}
                  onClick={() => void handleTogglePlay()}
                />
                <button
                  type="button"
                  onClick={() => void handleTogglePlay()}
                  className="absolute inset-0 flex items-center justify-center"
                >
                  <span className="flex h-24 w-24 items-center justify-center rounded-full border border-white/15 bg-black/50 text-white shadow-2xl">
                    <i className={`fas ${isPlaying ? 'fa-pause' : 'fa-play'} text-4xl`} />
                  </span>
                </button>
              </>
            ) : (
              <div className="mx-6 w-full max-w-xl rounded-[28px] border border-white/10 bg-white/5 px-8 py-10 text-center backdrop-blur">
                <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-white/5 text-white/60">
                  <i className="fas fa-video-slash text-2xl" />
                </div>
                <h2 className="mt-6 text-2xl font-black">Video is not connected yet</h2>
                <p className="mt-3 text-sm leading-7 text-white/60">
                  This lesson does not have a real video URL yet.
                  <br />
                  Select another lesson or check the attached materials.
                </p>
              </div>
            )}

            <div className="absolute right-4 top-20 flex flex-col gap-2 lg:right-8">
              <button
                type="button"
                onClick={() => void handleTogglePip()}
                className="rounded-xl border border-white/10 bg-black/55 px-3 py-2 text-xs font-semibold text-white/80 backdrop-blur transition hover:bg-black/70"
              >
                <i className="fas fa-external-link-alt mr-2" />
                {playerConfig?.pipEnabled ? 'Exit PIP' : 'PIP'}
              </button>
              <button
                type="button"
                onClick={() => startTransition(() => setActiveTab('notes'))}
                className="rounded-xl border border-white/10 bg-black/55 px-3 py-2 text-xs font-semibold text-white/80 backdrop-blur transition hover:bg-black/70"
              >
                <i className="fas fa-pen mr-2" />
                Quick note
              </button>
            </div>

            {notice ? (
              <div className="absolute bottom-24 left-4 right-4 rounded-2xl border border-amber-400/25 bg-amber-400/10 px-4 py-3 text-xs text-amber-100 lg:left-8 lg:right-auto lg:max-w-md">
                {notice}
              </div>
            ) : null}
          </div>

          <div className="border-t border-white/8 bg-[#0f1412] px-4 py-4 lg:px-6">
            <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
              <div className="flex flex-1 items-center gap-4">
                <button
                  type="button"
                  onClick={() => void handleTogglePlay()}
                  className="text-lg text-white/75 transition hover:text-white"
                >
                  <i className={`fas ${isPlaying ? 'fa-pause' : 'fa-play'}`} />
                </button>
                <span className="min-w-14 text-xs font-mono text-white/60">{formatTime(currentTime)}</span>
                <input
                  type="range"
                  min={0}
                  max={Math.max(duration, lesson.durationSeconds ?? 0, 1)}
                  step={1}
                  value={Math.min(currentTime, Math.max(duration, lesson.durationSeconds ?? 0, 1))}
                  onChange={(event) => handleSeek(Number(event.target.value))}
                  className="h-1 flex-1 cursor-pointer appearance-none rounded-full bg-white/15 accent-[#00c471]"
                />
                <span className="min-w-14 text-xs font-mono text-white/60">{formatTime(duration || (lesson.durationSeconds ?? 0))}</span>
              </div>
              <div className="flex items-center gap-4 text-sm text-white/65">
                <button type="button" onClick={() => handleSeek(currentTime - 10)} className="transition hover:text-white">-10s</button>
                <button type="button" onClick={() => handleSeek(currentTime + 10)} className="transition hover:text-white">+10s</button>
                <button type="button" onClick={() => void handleCyclePlaybackRate()} className="transition hover:text-white">
                  {(playerConfig?.defaultPlaybackRate ?? 1).toFixed(2).replace(/\.00$/, '')}x
                </button>
                <button
                  type="button"
                  onClick={() => void frameRef.current?.requestFullscreen().catch(() => setNotice('Failed to enter fullscreen.'))}
                  className="transition hover:text-white"
                >
                  <i className="fas fa-expand" />
                </button>
              </div>
            </div>
          </div>
        </section>

        <aside className="flex w-full flex-col border-l border-white/8 bg-[#f8f9fa] text-gray-900 lg:min-h-screen lg:w-[430px]">
          <div className="border-b border-gray-200 bg-white">
            <div className="flex">
              {(['curriculum', 'qna', 'notes'] as TabKey[]).map((tab) => (
                <button
                  key={tab}
                  type="button"
                  onClick={() => startTransition(() => setActiveTab(tab))}
                  className={`flex-1 px-4 py-4 text-sm font-bold transition ${
                    activeTab === tab
                      ? 'border-b-2 border-[#00c471] bg-emerald-50/60 text-[#00c471]'
                      : 'text-gray-400 hover:bg-gray-50'
                  }`}
                >
                  {tab === 'curriculum' ? 'Curriculum' : tab === 'qna' ? 'Q&A' : 'Notes'}
                </button>
              ))}
            </div>
          </div>

          <div className="relative flex-1 overflow-y-auto bg-[#f8f9fa] p-5 lg:p-6">
            {loadingLesson ? (
              <div className="absolute inset-0 z-20 flex items-center justify-center bg-white/80">
                <div className="h-12 w-12 animate-spin rounded-full border-4 border-[#00c471] border-t-transparent" />
              </div>
            ) : null}

            {activeTab === 'curriculum' ? (
              <div className="space-y-6">
                <section className="rounded-[26px] border border-gray-200 bg-white p-5 shadow-sm">
                  <div className="flex items-start justify-between gap-4">
                    <div className="min-w-0 flex-1">
                      <div className="text-xs font-black uppercase tracking-[0.2em] text-[#00c471]">Current Lesson</div>
                      <h2 className="mt-2 text-xl font-black text-gray-900">{lesson.title}</h2>
                      <p className="mt-2 text-sm leading-6 text-gray-600">{lesson.description || 'No lesson description is available.'}</p>
                    </div>
                    <div className="rounded-2xl bg-gray-900 px-3 py-2 text-right text-white">
                      <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-white/60">Progress</div>
                      <div className="mt-1 text-lg font-black">{progress?.progressPercent ?? 0}%</div>
                    </div>
                  </div>
                  <div className="mt-5 grid grid-cols-3 gap-3 text-center text-xs font-semibold text-gray-500">
                    <div className="rounded-2xl bg-gray-50 px-3 py-3">
                      <div className="text-[11px] uppercase tracking-[0.16em] text-gray-400">Sections</div>
                      <div className="mt-1 text-base font-black text-gray-900">{course.sections.length}</div>
                    </div>
                    <div className="rounded-2xl bg-gray-50 px-3 py-3">
                      <div className="text-[11px] uppercase tracking-[0.16em] text-gray-400">Lessons</div>
                      <div className="mt-1 text-base font-black text-gray-900">{lessons.length}</div>
                    </div>
                    <div className="rounded-2xl bg-gray-50 px-3 py-3">
                      <div className="text-[11px] uppercase tracking-[0.16em] text-gray-400">Runtime</div>
                      <div className="mt-1 text-base font-black text-gray-900">{formatDurationLabel(totalDurationSeconds)}</div>
                    </div>
                  </div>
                </section>

                <section className="rounded-[26px] border border-gray-200 bg-white p-5 shadow-sm">
                  <div className="space-y-5">
                    {course.sections.map((section) => (
                      <div key={section.sectionId}>
                        <div className="mb-3">
                          <div className="text-xs font-black uppercase tracking-[0.16em] text-gray-400">{section.title}</div>
                          {section.description ? <p className="mt-1 text-xs leading-5 text-gray-500">{section.description}</p> : null}
                        </div>
                        <div className="space-y-2">
                          {section.lessons.map((item) => {
                            const active = item.lessonId === lesson.lessonId
                            return (
                              <button
                                key={item.lessonId}
                                type="button"
                                onClick={() => startTransition(() => setSelectedLessonId(item.lessonId))}
                                className={`flex w-full items-center gap-3 rounded-[20px] border px-4 py-3 text-left transition ${
                                  active
                                    ? 'border-[#00c471]/35 bg-emerald-50/80 shadow-sm'
                                    : 'border-gray-200 bg-gray-50 hover:border-gray-300'
                                }`}
                              >
                                <span className={`flex h-11 w-11 items-center justify-center rounded-full text-sm ${
                                  active ? 'bg-[#00c471] text-white' : 'bg-white text-gray-400'
                                }`}>
                                  <i className={`fas ${active ? 'fa-play' : 'fa-circle-play'}`} />
                                </span>
                                <span className="min-w-0 flex-1">
                                  <span className={`block truncate text-sm font-bold ${active ? 'text-[#00a860]' : 'text-gray-900'}`}>{item.title}</span>
                                  <span className="mt-1 flex items-center gap-2 text-xs text-gray-500">
                                    <span>{formatDurationLabel(item.durationSeconds)}</span>
                                    {item.isPreview ? <span className="rounded-full bg-white px-2 py-0.5 font-bold text-[#00c471]">Preview</span> : null}
                                  </span>
                                </span>
                              </button>
                            )
                          })}
                        </div>
                      </div>
                    ))}
                  </div>
                </section>

                <section className="rounded-[26px] border border-gray-200 bg-white p-5 shadow-sm">
                  <div className="mb-4 flex items-center justify-between">
                    <div>
                      <div className="text-xs font-black uppercase tracking-[0.18em] text-[#00c471]">Materials</div>
                      <h3 className="mt-2 text-lg font-black text-gray-900">Lesson files</h3>
                    </div>
                    <span className="rounded-full bg-gray-100 px-3 py-1 text-[11px] font-bold text-gray-500">{lesson.materials.length}</span>
                  </div>
                  {lesson.materials.length ? (
                    <div className="space-y-3">
                      {lesson.materials.map((material) => (
                        <a
                          key={material.materialId}
                          href={resolveMaterialDownloadHref(lesson.lessonId, material.materialId)}
                          className="flex items-center justify-between rounded-[20px] border border-gray-200 bg-gray-50 px-4 py-3 transition hover:border-gray-300"
                        >
                          <span className="min-w-0">
                            <span className="block truncate text-sm font-bold text-gray-900">{material.originalFileName}</span>
                            <span className="mt-1 block text-xs text-gray-500">{material.materialType}</span>
                          </span>
                          <i className="fas fa-download text-sm text-gray-400" />
                        </a>
                      ))}
                    </div>
                  ) : (
                    <EmptyState iconClassName="fas fa-folder-open" title="No materials" description="There are no real lesson materials attached to this lesson yet." />
                  )}
                </section>
              </div>
            ) : null}
            {activeTab === 'qna' ? (
              <div className="space-y-6">
                <section className="rounded-[26px] border border-gray-200 bg-white p-5 shadow-sm">
                  <div className="flex flex-col gap-4">
                    <div className="flex items-center justify-between gap-4">
                      <div>
                        <div className="text-xs font-black uppercase tracking-[0.18em] text-[#00c471]">Q&A</div>
                        <h2 className="mt-2 text-lg font-black text-gray-900">Course discussion</h2>
                      </div>
                      <span className="rounded-full bg-gray-100 px-3 py-1 text-[11px] font-bold text-gray-500">
                        {qnaQuestions.length} posts
                      </span>
                    </div>

                    <label className="relative block">
                      <i className="fas fa-search pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-sm text-gray-300" />
                      <input
                        value={qnaSearch}
                        onChange={(event) => setQnaSearch(event.target.value)}
                        placeholder="Search title, author, or timestamp"
                        className="w-full rounded-[18px] border border-gray-200 bg-gray-50 py-3 pl-11 pr-4 text-sm text-gray-900 outline-none transition focus:border-[#00c471] focus:bg-white"
                      />
                    </label>

                    <div className="flex flex-wrap gap-2">
                      {([
                        { key: 'ALL' as const, label: 'All' },
                        { key: 'ANSWERED' as const, label: 'Answered' },
                        { key: 'UNANSWERED' as const, label: 'Waiting' },
                      ]).map((filter) => (
                        <button
                          key={filter.key}
                          type="button"
                          onClick={() => setQnaStatusFilter(filter.key)}
                          className={`rounded-full px-4 py-2 text-xs font-bold transition ${
                            qnaStatusFilter === filter.key
                              ? 'bg-[#00c471] text-white'
                              : 'bg-gray-100 text-gray-500 hover:bg-gray-200'
                          }`}
                        >
                          {filter.label}
                        </button>
                      ))}
                    </div>

                    {qnaError ? (
                      <div className="rounded-[18px] border border-rose-200 bg-rose-50 px-4 py-3 text-xs font-semibold text-rose-600">
                        {qnaError}
                      </div>
                    ) : null}
                  </div>
                </section>

                <section className="rounded-[26px] border border-gray-200 bg-white p-5 shadow-sm">
                  <div className="mb-4 flex items-center justify-between gap-4">
                    <div>
                      <div className="text-xs font-black uppercase tracking-[0.18em] text-[#00c471]">Ask</div>
                      <h3 className="mt-2 text-lg font-black text-gray-900">Post a question</h3>
                    </div>
                    <span className="rounded-full bg-gray-100 px-3 py-1 text-[11px] font-bold text-gray-500">
                      {questionForm.attachTimestamp ? formatTime(currentTime) : 'No timestamp'}
                    </span>
                  </div>

                  {selectedTemplate?.description || selectedTemplate?.guideExample ? (
                    <div className="mb-4 rounded-[20px] border border-emerald-100 bg-emerald-50/80 px-4 py-4">
                      {selectedTemplate?.description ? (
                        <p className="text-sm font-semibold text-emerald-800">{selectedTemplate.description}</p>
                      ) : null}
                      {selectedTemplate?.guideExample ? (
                        <p className="mt-2 text-xs leading-6 text-emerald-700/90">{selectedTemplate.guideExample}</p>
                      ) : null}
                    </div>
                  ) : null}

                  <div className="space-y-3">
                    <div className="grid gap-3 sm:grid-cols-2">
                      <label className="block">
                        <span className="mb-2 block text-[11px] font-black uppercase tracking-[0.16em] text-gray-400">Template</span>
                        <select
                          value={questionForm.templateType}
                          onChange={(event) => setQuestionForm((current) => ({ ...current, templateType: event.target.value }))}
                          className="w-full rounded-[18px] border border-gray-200 bg-gray-50 px-4 py-3 text-sm text-gray-900 outline-none transition focus:border-[#00c471] focus:bg-white"
                        >
                          {templateOptions.length ? (
                            templateOptions.map((template) => (
                              <option key={template.templateType} value={template.templateType}>
                                {template.name}
                              </option>
                            ))
                          ) : (
                            <option value="">No template available</option>
                          )}
                        </select>
                      </label>

                      <label className="block">
                        <span className="mb-2 block text-[11px] font-black uppercase tracking-[0.16em] text-gray-400">Difficulty</span>
                        <select
                          value={questionForm.difficulty}
                          onChange={(event) => setQuestionForm((current) => ({ ...current, difficulty: event.target.value as QnaDifficulty }))}
                          className="w-full rounded-[18px] border border-gray-200 bg-gray-50 px-4 py-3 text-sm text-gray-900 outline-none transition focus:border-[#00c471] focus:bg-white"
                        >
                          <option value="EASY">Easy</option>
                          <option value="MEDIUM">Medium</option>
                          <option value="HARD">Hard</option>
                        </select>
                      </label>
                    </div>

                    <label className="block">
                      <span className="mb-2 block text-[11px] font-black uppercase tracking-[0.16em] text-gray-400">Title</span>
                      <input
                        value={questionForm.title}
                        onChange={(event) => setQuestionForm((current) => ({ ...current, title: event.target.value }))}
                        placeholder="Summarize your question"
                        className="w-full rounded-[18px] border border-gray-200 bg-gray-50 px-4 py-3 text-sm text-gray-900 outline-none transition focus:border-[#00c471] focus:bg-white"
                      />
                    </label>

                    <label className="block">
                      <span className="mb-2 block text-[11px] font-black uppercase tracking-[0.16em] text-gray-400">Content</span>
                      <textarea
                        rows={5}
                        value={questionForm.content}
                        onChange={(event) => setQuestionForm((current) => ({ ...current, content: event.target.value }))}
                        placeholder="Describe what you do not understand in this lesson"
                        className="w-full rounded-[18px] border border-gray-200 bg-gray-50 px-4 py-3 text-sm leading-6 text-gray-900 outline-none transition focus:border-[#00c471] focus:bg-white"
                      />
                    </label>

                    <label className="flex items-center justify-between rounded-[18px] border border-gray-200 bg-gray-50 px-4 py-3">
                      <div>
                        <div className="text-sm font-bold text-gray-900">Attach current timestamp</div>
                        <div className="mt-1 text-xs text-gray-500">Link this question to the current playback position.</div>
                      </div>
                      <input
                        type="checkbox"
                        checked={questionForm.attachTimestamp}
                        onChange={(event) => setQuestionForm((current) => ({ ...current, attachTimestamp: event.target.checked }))}
                        className="h-4 w-4 rounded border-gray-300 accent-[#00c471]"
                      />
                    </label>

                    <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                      {questionMessage ? (
                        <div className="text-sm font-semibold text-gray-500">{questionMessage}</div>
                      ) : (
                        <div className="text-xs text-gray-400">Questions are loaded for course #{course.courseId}.</div>
                      )}
                      <button
                        type="button"
                        disabled={questionBusy || !templateOptions.length}
                        onClick={() => void handleSubmitQuestion()}
                        className="inline-flex items-center justify-center rounded-full bg-gray-900 px-5 py-3 text-sm font-black text-white transition hover:bg-black disabled:cursor-not-allowed disabled:bg-gray-300"
                      >
                        {questionBusy ? 'Posting...' : 'Post question'}
                      </button>
                    </div>
                  </div>
                </section>

                <section className="rounded-[26px] border border-gray-200 bg-white p-5 shadow-sm">
                  <div className="mb-4 flex items-center justify-between gap-4">
                    <div>
                      <div className="text-xs font-black uppercase tracking-[0.18em] text-[#00c471]">Threads</div>
                      <h3 className="mt-2 text-lg font-black text-gray-900">Questions for this course</h3>
                    </div>
                    <span className="rounded-full bg-gray-100 px-3 py-1 text-[11px] font-bold text-gray-500">
                      {visibleQuestions.length} visible
                    </span>
                  </div>

                  {loadingQna ? (
                    <div className="flex items-center justify-center rounded-[22px] border border-dashed border-gray-200 bg-gray-50 px-6 py-12">
                      <div className="h-10 w-10 animate-spin rounded-full border-4 border-[#00c471] border-t-transparent" />
                    </div>
                  ) : visibleQuestions.length ? (
                    <div className="space-y-3">
                      {visibleQuestions.map((question) => {
                        const answered = isQuestionAnswered(question)
                        const detail = qnaDetails[question.id]
                        const isOpen = openQuestionId === question.id

                        return (
                          <article key={question.id} className="overflow-hidden rounded-[22px] border border-gray-200 bg-gray-50">
                            <button
                              type="button"
                              onClick={() => void handleToggleQuestion(question.id)}
                              className="flex w-full flex-col gap-3 px-5 py-4 text-left transition hover:bg-white"
                            >
                              <div className="flex items-start justify-between gap-4">
                                <div className="flex flex-wrap items-center gap-2 text-[11px] font-bold">
                                  <span className={`rounded-full px-2.5 py-1 ${
                                    answered
                                      ? 'bg-emerald-100 text-emerald-700'
                                      : 'bg-amber-100 text-amber-700'
                                  }`}>
                                    {answered ? 'Answered' : 'Waiting'}
                                  </span>
                                  <span className="text-gray-700">{question.authorName}</span>
                                  <span className="text-gray-400">{formatRelativeTime(question.createdAt)}</span>
                                </div>
                                <span className="rounded-full bg-white px-3 py-1 text-[11px] font-bold text-gray-500">
                                  {question.answerCount} {question.answerCount === 1 ? 'answer' : 'answers'}
                                </span>
                              </div>

                              {question.lectureTimestamp ? (
                                <div className="inline-flex w-fit items-center gap-2 rounded-full border border-gray-200 bg-white px-3 py-1 text-[11px] font-bold text-gray-500">
                                  <i className="fas fa-play-circle text-[#00c471]" />
                                  {question.lectureTimestamp}
                                </div>
                              ) : null}

                              <div>
                                <h4 className="text-sm font-black text-gray-900">{question.title}</h4>
                                <p className="mt-2 text-sm leading-6 text-gray-600">
                                  {detail?.content ?? 'Open this thread to load the full question and answers.'}
                                </p>
                              </div>
                            </button>

                            {isOpen ? (
                              <div className="border-t border-gray-200 bg-white px-5 py-5">
                                {loadingQuestionId === question.id ? (
                                  <div className="flex items-center justify-center py-8">
                                    <div className="h-8 w-8 animate-spin rounded-full border-4 border-[#00c471] border-t-transparent" />
                                  </div>
                                ) : detail ? (
                                  <div className="space-y-4">
                                    <div className="rounded-[20px] border border-gray-200 bg-gray-50 px-4 py-4">
                                      <div className="text-[11px] font-black uppercase tracking-[0.16em] text-gray-400">Question</div>
                                      <p className="mt-3 text-sm leading-7 text-gray-700">{detail.content}</p>
                                    </div>

                                    <div>
                                      <div className="mb-3 flex items-center justify-between gap-4">
                                        <div className="text-sm font-black text-gray-900">Answers</div>
                                        <span className="text-xs font-semibold text-gray-400">{detail.viewCount} views</span>
                                      </div>

                                      {detail.answers.length ? (
                                        <div className="space-y-3">
                                          {detail.answers.map((answer) => (
                                            <div
                                              key={answer.id}
                                              className={`rounded-[20px] border px-4 py-4 ${
                                                answer.adopted
                                                  ? 'border-emerald-200 bg-emerald-50/70'
                                                  : 'border-gray-200 bg-gray-50'
                                              }`}
                                            >
                                              <div className="flex items-center justify-between gap-4">
                                                <div className="flex items-center gap-2 text-xs font-bold text-gray-600">
                                                  {answer.adopted ? (
                                                    <span className="rounded-full bg-[#00c471] px-2.5 py-1 text-white">Adopted</span>
                                                  ) : null}
                                                  <span>{answer.authorName}</span>
                                                </div>
                                                <span className="text-[11px] text-gray-400">{formatRelativeTime(answer.createdAt)}</span>
                                              </div>
                                              <p className="mt-3 text-sm leading-7 text-gray-700">{answer.content}</p>
                                            </div>
                                          ))}
                                        </div>
                                      ) : (
                                        <EmptyState
                                          iconClassName="fas fa-hourglass-half"
                                          title="No answer yet"
                                          description="This question is stored in the backend, but nobody has answered it yet."
                                        />
                                      )}
                                    </div>
                                  </div>
                                ) : (
                                  <div className="rounded-[20px] border border-dashed border-gray-200 bg-gray-50 px-4 py-6 text-center text-sm text-gray-500">
                                    Open this thread again if the detail request failed.
                                  </div>
                                )}
                              </div>
                            ) : null}
                          </article>
                        )
                      })}
                    </div>
                  ) : (
                    <EmptyState
                      iconClassName="fas fa-comments"
                      title="No questions found"
                      description="There are no Q&A items for the current filters or this course has no posts yet."
                    />
                  )}
                </section>
              </div>
            ) : null}

            {activeTab === 'notes' ? (
              <div className="space-y-6">
                <section className="rounded-[26px] border border-gray-200 bg-white p-5 shadow-sm">
                  <div className="mb-4 flex items-center justify-between gap-4">
                    <div>
                      <div className="text-xs font-black uppercase tracking-[0.18em] text-[#00c471]">Notes</div>
                      <h2 className="mt-2 text-lg font-black text-gray-900">Timestamp notes</h2>
                    </div>
                    <span className="rounded-full bg-gray-100 px-3 py-1 text-[11px] font-bold text-gray-500">
                      {formatTime(currentTime)}
                    </span>
                  </div>

                  <div className="rounded-[20px] border border-blue-100 bg-blue-50 px-4 py-4 text-sm text-blue-800">
                    Save notes with the current playback time. Each note stays tied to this lesson in the backend.
                  </div>

                  <div className="mt-4 space-y-3">
                    <textarea
                      rows={6}
                      value={noteContent}
                      onChange={(event) => setNoteContent(event.target.value)}
                      placeholder="Write what matters in this lesson."
                      className="w-full rounded-[18px] border border-gray-200 bg-gray-50 px-4 py-3 text-sm leading-6 text-gray-900 outline-none transition focus:border-[#00c471] focus:bg-white"
                    />

                    <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                      {noteMessage ? (
                        <div className="text-sm font-semibold text-gray-500">{noteMessage}</div>
                      ) : (
                        <div className="text-xs text-gray-400">Notes save to lesson #{lesson.lessonId}.</div>
                      )}
                      <button
                        type="button"
                        onClick={() => void handleSaveNote()}
                        disabled={!noteContent.trim()}
                        className="inline-flex items-center justify-center rounded-full bg-gray-900 px-5 py-3 text-sm font-black text-white transition hover:bg-black disabled:cursor-not-allowed disabled:bg-gray-300"
                      >
                        Save note
                      </button>
                    </div>
                  </div>
                </section>

                <section className="rounded-[26px] border border-gray-200 bg-white p-5 shadow-sm">
                  <div className="mb-4 flex items-center justify-between gap-4">
                    <div>
                      <div className="text-xs font-black uppercase tracking-[0.18em] text-[#00c471]">Archive</div>
                      <h3 className="mt-2 text-lg font-black text-gray-900">Saved notes</h3>
                    </div>
                    <span className="rounded-full bg-gray-100 px-3 py-1 text-[11px] font-bold text-gray-500">
                      {notes.length} saved
                    </span>
                  </div>

                  {notes.length ? (
                    <div className="space-y-3">
                      {[...notes].sort((a, b) => b.timestampSecond - a.timestampSecond).map((note) => (
                        <article key={note.noteId} className="rounded-[22px] border border-gray-200 bg-gray-50 px-4 py-4">
                          <div className="flex items-start justify-between gap-4">
                            <button
                              type="button"
                              onClick={() => handleSeek(note.seekSecond ?? note.timestampSecond)}
                              className="inline-flex items-center gap-2 rounded-full border border-gray-200 bg-white px-3 py-1.5 text-xs font-bold text-gray-600 transition hover:border-[#00c471] hover:text-[#00c471]"
                            >
                              <i className="fas fa-play-circle" />
                              {note.timestampLabel || formatTime(note.timestampSecond)}
                            </button>
                            <div className="flex items-center gap-2">
                              <span className="text-[11px] text-gray-400">{formatDateLabel(note.updatedAt ?? note.createdAt)}</span>
                              <button
                                type="button"
                                onClick={() => void handleDeleteNote(note)}
                                className="text-xs font-bold text-rose-500 transition hover:text-rose-600"
                              >
                                Delete
                              </button>
                            </div>
                          </div>
                          <p className="mt-3 text-sm leading-7 text-gray-700">{note.content}</p>
                        </article>
                      ))}
                    </div>
                  ) : (
                    <EmptyState
                      iconClassName="fas fa-note-sticky"
                      title="No notes yet"
                      description="Start writing while watching. Saved notes will appear here per lesson."
                    />
                  )}
                </section>
              </div>
            ) : null}
          </div>
        </aside>
      </div>

      {loadingCourse ? <LoadingOverlay /> : null}
    </div>
  )
}
