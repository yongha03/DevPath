/**
 * Video OCR — 영상 현재 프레임(전체 또는 선택 구간)에서 코드 텍스트를 추출합니다.
 *
 * 인식 전략 (우선순위 순):
 *  1. 백엔드 API → Python OCR 서버 (가장 높은 정확도)
 *  2. Tesseract.js 로컬 폴백 (Python 서버 미실행 시)
 *
 * Python 서버 미실행 시에도 다음 최적화로 Tesseract 정확도를 최대화합니다:
 *  - 다크 테마 자동 반전, 소영역 2× 업스케일, PSM 6, Otsu 이진화
 */

import { createWorker, type Worker } from 'tesseract.js'
import { readStoredAuthSession } from './auth-session'

// ── 타입 ──────────────────────────────────────────────────────────────────

/** 구간 선택 영역 (video 엘리먼트 표시 영역 기준 픽셀 좌표) */
export type ScreenRegion = {
  x: number
  y: number
  width: number
  height: number
}

export type OcrResult = {
  text: string
  confidence: number   // 0 ~ 100
  source: string       // 'Claude Vision' | 'Python OCR' | 'Tesseract (로컬)'
}

// ── 프레임 캡처 ───────────────────────────────────────────────────────────

const MAX_SIDE = 1920  // 백엔드에는 더 높은 해상도로 전송 (정확도↑)

function captureFrame(video: HTMLVideoElement, region?: ScreenRegion): HTMLCanvasElement {
  const natW = video.videoWidth  || video.clientWidth
  const natH = video.videoHeight || video.clientHeight
  if (natW === 0 || natH === 0) throw new Error('재생 중인 프레임이 없습니다.')

  if (region) {
    // object-contain 레터박스 보정
    const dispW = video.clientWidth
    const dispH = video.clientHeight
    const natAspect = natW / natH
    const dispAspect = dispW / dispH

    let renderW = dispW, renderH = dispH
    let offsetX = 0,    offsetY = 0

    if (natAspect > dispAspect) {
      renderH = dispW / natAspect
      offsetY = (dispH - renderH) / 2
    } else {
      renderW = dispH * natAspect
      offsetX = (dispW - renderW) / 2
    }

    const scaleX = natW / renderW
    const scaleY = natH / renderH
    const srcX = Math.max(0, (region.x - offsetX) * scaleX)
    const srcY = Math.max(0, (region.y - offsetY) * scaleY)
    const srcW = Math.min(natW - srcX, region.width  * scaleX)
    const srcH = Math.min(natH - srcY, region.height * scaleY)

    if (srcW < 4 || srcH < 4) throw new Error('선택 영역이 너무 작거나 영상 범위를 벗어났습니다.')

    // 소영역 업스케일 — 백엔드에도 큰 이미지가 유리
    const scale = srcW < 600 ? 3 : srcW < 1000 ? 2 : 1
    const canvas = document.createElement('canvas')
    canvas.width  = Math.round(srcW * scale)
    canvas.height = Math.round(srcH * scale)
    const ctx = canvas.getContext('2d')!
    ctx.imageSmoothingEnabled = false
    ctx.drawImage(video, srcX, srcY, srcW, srcH, 0, 0, canvas.width, canvas.height)
    return canvas
  }

  // 전체 프레임
  let w = natW, h = natH
  if (w > MAX_SIDE || h > MAX_SIDE) {
    const ratio = Math.min(MAX_SIDE / w, MAX_SIDE / h)
    w = Math.round(w * ratio)
    h = Math.round(h * ratio)
  }
  const canvas = document.createElement('canvas')
  canvas.width = w; canvas.height = h
  canvas.getContext('2d')!.drawImage(video, 0, 0, w, h)
  return canvas
}

/** canvas → base64 (data: 프리픽스 제거) */
function toBase64(canvas: HTMLCanvasElement): string {
  const dataUrl = canvas.toDataURL('image/png')
  return dataUrl.replace(/^data:image\/\w+;base64,/, '')
}

// ── 1순위: 백엔드 API (Python OCR 서버) ──────────────────────────────────

/** 백엔드 API 호출. 사용 불가/빈 결과 시 null 반환 → 호출부에서 Tesseract 폴백 */
async function ocrViaBackend(base64: string): Promise<OcrResult | null> {
  const session = readStoredAuthSession()
  if (!session?.accessToken) return null

  try {
    const res = await fetch('/api/learning/ocr/extract', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${session.accessToken}`,
      },
      body: JSON.stringify({ imageBase64: base64 }),
      signal: AbortSignal.timeout(30_000),
    })
    if (!res.ok) return null

    const json = await res.json() as {
      data?: { text?: string; confidence?: number; engine?: string }
    }
    const data = json.data ?? {}

    // engine:"none" = 서버도 없음 → 폴백
    if (!data.text?.trim() || data.engine === 'none') return null

    const source = data.engine === 'claude' ? 'Claude Vision' : 'Python OCR'
    return {
      text:       data.text,
      confidence: data.engine === 'claude' ? 100 : (data.confidence ?? 0) * 100,
      source,
    }
  } catch {
    return null
  }
}

// ── 2순위: Tesseract.js 로컬 폴백 ────────────────────────────────────────

let workerPromise: Promise<Worker> | null = null

async function buildWorker(): Promise<Worker> {
  const w = await createWorker('eng', undefined, { logger: () => {} })
  await w.setParameters({ tessedit_pageseg_mode: '6' as never })
  return w
}

function getTesseractWorker(): Promise<Worker> {
  if (!workerPromise) {
    workerPromise = buildWorker().catch((err) => { workerPromise = null; throw err })
  }
  return workerPromise
}

export function warmupOcrWorker(): void {
  void getTesseractWorker()
}

// ── Tesseract 전처리 파이프라인 ───────────────────────────────────────────

function toGrayscale(d: Uint8ClampedArray): void {
  for (let i = 0; i < d.length; i += 4) {
    const g = d[i] * 0.299 + d[i + 1] * 0.587 + d[i + 2] * 0.114
    d[i] = d[i + 1] = d[i + 2] = g
  }
}

function autoInvert(d: Uint8ClampedArray, total: number): void {
  let sum = 0
  for (let i = 0; i < d.length; i += 4) sum += d[i]
  if (sum / total < 128) {
    for (let i = 0; i < d.length; i += 4)
      d[i] = d[i + 1] = d[i + 2] = 255 - d[i]
  }
}

function enhanceContrast(d: Uint8ClampedArray, f = 2.0): void {
  for (let i = 0; i < d.length; i += 4) {
    const v = Math.min(255, Math.max(0, (d[i] - 128) * f + 128))
    d[i] = d[i + 1] = d[i + 2] = v
  }
}

function otsuThreshold(d: Uint8ClampedArray, total: number): number {
  const h = new Int32Array(256)
  for (let i = 0; i < d.length; i += 4) h[d[i]]++
  let sum = 0
  for (let i = 0; i < 256; i++) sum += i * h[i]
  let sB = 0, wB = 0, best = 0, t = 0
  for (let i = 0; i < 256; i++) {
    wB += h[i]; if (!wB) continue
    const wF = total - wB; if (!wF) break
    sB += i * h[i]
    const mB = sB / wB, mF = (sum - sB) / wF
    const v = wB * wF * (mB - mF) * (mB - mF)
    if (v > best) { best = v; t = i }
  }
  return t
}

function binarize(d: Uint8ClampedArray, t: number): void {
  for (let i = 0; i < d.length; i += 4) {
    const v = d[i] > t ? 255 : 0; d[i] = d[i + 1] = d[i + 2] = v
  }
}

function sharpen(d: Uint8ClampedArray, w: number, h: number): Uint8ClampedArray<ArrayBuffer> {
  const src = d, out = new Uint8ClampedArray(d.length)
  const k = [0, -1, 0, -1, 5, -1, 0, -1, 0]
  for (let y = 1; y < h - 1; y++) {
    for (let x = 1; x < w - 1; x++) {
      let s = 0
      for (let ky = -1; ky <= 1; ky++)
        for (let kx = -1; kx <= 1; kx++)
          s += src[((y + ky) * w + (x + kx)) * 4] * k[(ky + 1) * 3 + (kx + 1)]
      const v = Math.min(255, Math.max(0, s)), i = (y * w + x) * 4
      out[i] = out[i + 1] = out[i + 2] = v; out[i + 3] = 255
    }
  }
  for (let i = 0; i < d.length; i += 4)
    if (!out[i + 3]) { out[i] = src[i]; out[i + 1] = src[i + 1]; out[i + 2] = src[i + 2]; out[i + 3] = 255 }
  return out
}

/** 전처리된 dataURL 반환 */
function preprocessForTesseract(canvas: HTMLCanvasElement): string {
  const ctx = canvas.getContext('2d')!
  const { width: w, height: h } = canvas
  const img = ctx.getImageData(0, 0, w, h)
  let d: Uint8ClampedArray = img.data

  toGrayscale(d)
  autoInvert(d, w * h)
  enhanceContrast(d, 2.0)
  d = sharpen(d, w, h)
  binarize(d, otsuThreshold(d, w * h))

  const out = ctx.createImageData(w, h)
  out.data.set(d)
  ctx.putImageData(out, 0, 0)
  return canvas.toDataURL('image/png')
}

function cleanCode(raw: string): string {
  return raw
    .split('\n')
    .map(l => l.replace(/^\s*\d{1,4}[\s:|]+/, '').replace(/^\s*\d{1,4}\s*$/, '').trim())
    .filter(l => l.length > 0)
    .join('\n')
    .replace(/[`'']/g, "'")
    .replace(/[""]/g, '"')
    .replace(/\s{2,}/g, ' ')
}

async function ocrViaTesseract(canvas: HTMLCanvasElement): Promise<OcrResult> {
  const dataUrl = preprocessForTesseract(canvas)
  const worker  = await getTesseractWorker()
  const { data: { text, confidence } } = await worker.recognize(dataUrl)
  return { text: cleanCode(text), confidence, source: 'Tesseract (로컬)' }
}

// ── 공개 API ──────────────────────────────────────────────────────────────

/**
 * 비디오 현재 프레임(또는 선택 구간)의 코드를 OCR로 추출합니다.
 *
 * 백엔드 Python OCR 서버 → 실패 시 Tesseract.js 로컬 폴백 순으로 시도합니다.
 */
export async function captureAndOcr(
  video: HTMLVideoElement,
  region?: ScreenRegion,
  onProgress?: (msg: string) => void,
): Promise<OcrResult> {
  onProgress?.(region ? '선택 구간 캡처 중...' : '프레임 캡처 중...')
  const canvas = captureFrame(video, region)
  const base64 = toBase64(canvas)

  // ── 1순위: Claude Vision / Python OCR (백엔드 API) ───────────────────
  onProgress?.('OCR 서버로 전송 중...')
  const backendResult = await ocrViaBackend(base64)
  if (backendResult) return backendResult

  // ── 2순위: Tesseract.js 로컬 폴백 ────────────────────────────────────
  onProgress?.('로컬 OCR 엔진으로 인식 중...')
  return ocrViaTesseract(canvas)
}
