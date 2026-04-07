import type { PointerEvent as ReactPointerEvent } from 'react'
import { useEffect, useRef, useState } from 'react'
import { importWithPageReload } from '../lib/lazy-import'
import type { OcrProgressInfo, TesseractWorkerLike } from '../lib/ocr-runtime'
import type { OcrMode, OcrSelectionRect, VideoOcrResult } from '../lib/video-ocr'

type OcrTone = 'idle' | 'loading' | 'success' | 'error'

const MIN_SELECTION_SIZE = 24

type OcrRuntimeModule = typeof import('../lib/ocr-runtime')
type VideoOcrModule = typeof import('../lib/video-ocr')

export function useVideoOCR(lessonId: number | null, currentTime: number) {
  const workerRef = useRef<TesseractWorkerLike | null>(null)
  const workerPromiseRef = useRef<Promise<TesseractWorkerLike> | null>(null)
  const runtimeModulePromiseRef = useRef<Promise<OcrRuntimeModule> | null>(null)
  const videoOcrModulePromiseRef = useRef<Promise<VideoOcrModule> | null>(null)
  const cacheRef = useRef(new Map<string, VideoOcrResult>())
  const dragStartRef = useRef<{ x: number; y: number } | null>(null)
  const [busy, setBusy] = useState(false)
  const [selecting, setSelecting] = useState(false)
  const [selectionRect, setSelectionRect] = useState<OcrSelectionRect | null>(null)
  const [statusTone, setStatusTone] = useState<OcrTone>('idle')
  const [statusMessage, setStatusMessage] = useState('OCR 준비 대기 중입니다.')
  const [progressPercent, setProgressPercent] = useState(0)
  const [result, setResult] = useState<VideoOcrResult | null>(null)

  useEffect(() => {
    return () => {
      const worker = workerRef.current
      if (worker) {
        void worker.terminate().catch(() => null)
      }
    }
  }, [])

  useEffect(() => {
    setSelecting(false)
    setSelectionRect(null)
    setResult(null)
    setStatusTone('idle')
    setStatusMessage('현재 강의 기준으로 OCR을 실행할 수 있습니다.')
    setProgressPercent(0)
  }, [lessonId])

  function loadRuntimeModule() {
    if (!runtimeModulePromiseRef.current) {
      runtimeModulePromiseRef.current = importWithPageReload(
        () => import('../lib/ocr-runtime'),
        'learning-ocr-runtime',
      )
    }

    return runtimeModulePromiseRef.current
  }

  function loadVideoOcrModule() {
    if (!videoOcrModulePromiseRef.current) {
      videoOcrModulePromiseRef.current = importWithPageReload(
        () => import('../lib/video-ocr'),
        'learning-video-ocr',
      )
    }

    return videoOcrModulePromiseRef.current
  }

  async function getWorker() {
    if (workerRef.current) {
      return workerRef.current
    }

    if (!workerPromiseRef.current) {
      workerPromiseRef.current = (async () => {
        setStatusTone('loading')
        setStatusMessage('OCR 엔진을 불러오는 중입니다. 첫 실행은 조금 걸릴 수 있습니다.')

        const { loadTesseractGlobal } = await loadRuntimeModule()
        const globalTesseract = await loadTesseractGlobal()
        const worker = await globalTesseract.createWorker('eng+kor', 1, {
          logger: (info: OcrProgressInfo) => {
            if (info.status) {
              setStatusTone('loading')
              setStatusMessage(`OCR 엔진 작업 중: ${info.status}`)
            }
            if (Number.isFinite(info.progress)) {
              setProgressPercent(Math.round(info.progress * 100))
            }
          },
        })
        workerRef.current = worker
        return worker
      })().finally(() => {
        workerPromiseRef.current = null
      })
    }

    return workerPromiseRef.current
  }

  function beginRegionSelection() {
    if (busy) return
    setSelecting(true)
    setSelectionRect(null)
    setStatusTone('idle')
    setStatusMessage('영상 위에서 OCR할 영역을 드래그하세요.')
  }

  function cancelRegionSelection() {
    dragStartRef.current = null
    setSelecting(false)
    setSelectionRect(null)
    setStatusTone('idle')
    setStatusMessage('영역 선택을 취소했습니다.')
  }

  async function runOcr(video: HTMLVideoElement, mode: OcrMode, selection: OcrSelectionRect | null) {
    if (busy) return

    setBusy(true)
    setProgressPercent(0)
    setStatusTone('loading')
    setStatusMessage(mode === 'region' ? '선택 영역을 캡처하는 중입니다.' : '현재 프레임을 캡처하는 중입니다.')

    try {
      const videoOcr = await loadVideoOcrModule()
      const capture = videoOcr.captureVideoFrameForOcr(video, { mode, selection })
      const timestampSecond = Math.floor(currentTime)
      const cacheKey = videoOcr.buildOcrCacheKey(lessonId, mode, timestampSecond, capture.normalizedSelection)

      const cached = cacheRef.current.get(cacheKey)
      if (cached) {
        setResult(cached)
        setStatusTone('success')
        setStatusMessage('같은 프레임 OCR 결과를 캐시에서 불러왔습니다.')
        return
      }

      const worker = await getWorker()
      setStatusTone('loading')
      setStatusMessage('텍스트를 인식하는 중입니다.')

      const response = await worker.recognize(capture.dataUrl)
      const rawText = response.data.text ?? ''
      const text = videoOcr.cleanRecognizedText(rawText)
      const nextResult: VideoOcrResult = {
        id: `ocr-${Date.now()}`,
        lessonId,
        mode,
        timestampSecond,
        confidence: Number(response.data.confidence ?? 0),
        rawText,
        text,
        codeBlocks: videoOcr.extractCodeBlocks(rawText),
        selection: capture.normalizedSelection,
        createdAt: new Date().toISOString(),
      }

      cacheRef.current.set(cacheKey, nextResult)
      setResult(nextResult)
      setStatusTone('success')
      setStatusMessage('OCR이 완료되었습니다.')
      setProgressPercent(100)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'OCR 처리 중 문제가 발생했습니다.'
      setStatusTone('error')
      setStatusMessage(message)
    } finally {
      dragStartRef.current = null
      setSelecting(false)
      setSelectionRect(null)
      setBusy(false)
    }
  }

  async function runFullFrameOcr(video: HTMLVideoElement | null) {
    if (!video) {
      setStatusTone('error')
      setStatusMessage('영상 요소를 찾지 못했습니다.')
      return
    }
    await runOcr(video, 'full', null)
  }

  function handleOverlayPointerDown(event: ReactPointerEvent<HTMLDivElement>) {
    if (!selecting || busy) return
    const bounds = event.currentTarget.getBoundingClientRect()
    dragStartRef.current = {
      x: event.clientX - bounds.left,
      y: event.clientY - bounds.top,
    }
    setSelectionRect({ x: dragStartRef.current.x, y: dragStartRef.current.y, width: 0, height: 0 })
  }

  function handleOverlayPointerMove(event: ReactPointerEvent<HTMLDivElement>) {
    if (!selecting || !dragStartRef.current) return
    const bounds = event.currentTarget.getBoundingClientRect()
    const currentX = event.clientX - bounds.left
    const currentY = event.clientY - bounds.top
    const nextRect = {
      x: Math.min(dragStartRef.current.x, currentX),
      y: Math.min(dragStartRef.current.y, currentY),
      width: Math.abs(currentX - dragStartRef.current.x),
      height: Math.abs(currentY - dragStartRef.current.y),
    }
    setSelectionRect(nextRect)
  }

  async function handleOverlayPointerUp(
    event: ReactPointerEvent<HTMLDivElement>,
    video: HTMLVideoElement | null,
  ) {
    if (!selecting || !dragStartRef.current || !video) return

    const bounds = event.currentTarget.getBoundingClientRect()
    const currentX = event.clientX - bounds.left
    const currentY = event.clientY - bounds.top
    const nextRect = {
      x: Math.min(dragStartRef.current.x, currentX),
      y: Math.min(dragStartRef.current.y, currentY),
      width: Math.abs(currentX - dragStartRef.current.x),
      height: Math.abs(currentY - dragStartRef.current.y),
    }

    if (nextRect.width < MIN_SELECTION_SIZE || nextRect.height < MIN_SELECTION_SIZE) {
      cancelRegionSelection()
      setStatusTone('error')
      setStatusMessage('선택 영역이 너무 작습니다. 조금 더 크게 드래그해주세요.')
      return
    }

    await runOcr(video, 'region', nextRect)
  }

  async function copyRecognizedText() {
    if (!result?.text) return false
    try {
      await navigator.clipboard.writeText(result.text)
      setStatusTone('success')
      setStatusMessage('OCR 텍스트를 클립보드에 복사했습니다.')
      return true
    } catch {
      setStatusTone('error')
      setStatusMessage('클립보드 복사에 실패했습니다.')
      return false
    }
  }

  return {
    busy,
    selecting,
    selectionRect,
    statusTone,
    statusMessage,
    progressPercent,
    result,
    beginRegionSelection,
    cancelRegionSelection,
    runFullFrameOcr,
    handleOverlayPointerDown,
    handleOverlayPointerMove,
    handleOverlayPointerUp,
    copyRecognizedText,
  }
}
