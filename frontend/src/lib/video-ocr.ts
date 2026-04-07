export type OcrMode = 'full' | 'region'

export interface OcrSelectionRect {
  x: number
  y: number
  width: number
  height: number
}

export interface VideoOcrResult {
  id: string
  lessonId: number | null
  mode: OcrMode
  timestampSecond: number
  confidence: number
  text: string
  rawText: string
  codeBlocks: string[]
  selection: OcrSelectionRect | null
  createdAt: string
}

interface RenderedVideoRect {
  x: number
  y: number
  width: number
  height: number
}

interface CaptureOptions {
  mode: OcrMode
  selection: OcrSelectionRect | null
}

interface CaptureResult {
  dataUrl: string
  normalizedSelection: OcrSelectionRect | null
}

const FULL_FRAME_MAX_EDGE = 1280
const REGION_MAX_EDGE = 1200
const REGION_UPSCALE_EDGE = 520

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value))
}

function createCanvas(width: number, height: number) {
  const canvas = document.createElement('canvas')
  canvas.width = Math.max(1, Math.round(width))
  canvas.height = Math.max(1, Math.round(height))
  return canvas
}

function getRenderedVideoRect(video: HTMLVideoElement): RenderedVideoRect {
  const containerWidth = video.clientWidth
  const containerHeight = video.clientHeight
  const videoWidth = video.videoWidth
  const videoHeight = video.videoHeight

  if (!containerWidth || !containerHeight || !videoWidth || !videoHeight) {
    return { x: 0, y: 0, width: 0, height: 0 }
  }

  const videoAspect = videoWidth / videoHeight
  const containerAspect = containerWidth / containerHeight

  if (videoAspect > containerAspect) {
    const renderedWidth = containerWidth
    const renderedHeight = renderedWidth / videoAspect
    return {
      x: 0,
      y: (containerHeight - renderedHeight) / 2,
      width: renderedWidth,
      height: renderedHeight,
    }
  }

  const renderedHeight = containerHeight
  const renderedWidth = renderedHeight * videoAspect
  return {
    x: (containerWidth - renderedWidth) / 2,
    y: 0,
    width: renderedWidth,
    height: renderedHeight,
  }
}

function clampSelectionToVideo(selection: OcrSelectionRect, rendered: RenderedVideoRect) {
  const left = clamp(selection.x, rendered.x, rendered.x + rendered.width)
  const top = clamp(selection.y, rendered.y, rendered.y + rendered.height)
  const right = clamp(selection.x + selection.width, rendered.x, rendered.x + rendered.width)
  const bottom = clamp(selection.y + selection.height, rendered.y, rendered.y + rendered.height)

  const width = right - left
  const height = bottom - top

  if (width < 16 || height < 16) {
    return null
  }

  return { x: left, y: top, width, height }
}

function scaleCanvas(source: HTMLCanvasElement, mode: OcrMode) {
  const longEdge = Math.max(source.width, source.height)
  const maxEdge = mode === 'full' ? FULL_FRAME_MAX_EDGE : REGION_MAX_EDGE
  let scale = longEdge > maxEdge ? maxEdge / longEdge : 1

  if (mode === 'region' && longEdge < REGION_UPSCALE_EDGE) {
    scale = Math.max(scale, Math.min(2, REGION_UPSCALE_EDGE / Math.max(longEdge, 1)))
  }

  if (Math.abs(scale - 1) < 0.01) {
    return source
  }

  const canvas = createCanvas(source.width * scale, source.height * scale)
  const context = canvas.getContext('2d')
  if (!context) {
    throw new Error('Failed to prepare OCR canvas.')
  }

  context.imageSmoothingEnabled = scale < 1
  context.drawImage(source, 0, 0, canvas.width, canvas.height)
  return canvas
}

function convertToGrayscale(imageData: ImageData) {
  const data = imageData.data
  for (let index = 0; index < data.length; index += 4) {
    const gray = data[index] * 0.299 + data[index + 1] * 0.587 + data[index + 2] * 0.114
    data[index] = gray
    data[index + 1] = gray
    data[index + 2] = gray
  }
  return imageData
}

function enhanceContrast(imageData: ImageData, factor: number) {
  const data = imageData.data
  for (let index = 0; index < data.length; index += 4) {
    const next = Math.min(255, Math.max(0, (data[index] - 128) * factor + 128))
    data[index] = next
    data[index + 1] = next
    data[index + 2] = next
  }
  return imageData
}

function calculateOtsuThreshold(imageData: ImageData) {
  const histogram = new Array(256).fill(0)
  const total = imageData.width * imageData.height
  let weightedSum = 0

  for (let index = 0; index < imageData.data.length; index += 4) {
    const value = imageData.data[index]
    histogram[value] += 1
    weightedSum += value
  }

  let backgroundWeight = 0
  let backgroundSum = 0
  let bestVariance = 0
  let threshold = 140

  for (let value = 0; value < 256; value += 1) {
    backgroundWeight += histogram[value]
    if (!backgroundWeight) continue

    const foregroundWeight = total - backgroundWeight
    if (!foregroundWeight) break

    backgroundSum += value * histogram[value]
    const backgroundMean = backgroundSum / backgroundWeight
    const foregroundMean = (weightedSum - backgroundSum) / foregroundWeight
    const variance = backgroundWeight * foregroundWeight * (backgroundMean - foregroundMean) ** 2

    if (variance > bestVariance) {
      bestVariance = variance
      threshold = value
    }
  }

  return threshold
}

function binarize(imageData: ImageData, threshold: number) {
  const data = imageData.data
  for (let index = 0; index < data.length; index += 4) {
    const value = data[index] > threshold ? 255 : 0
    data[index] = value
    data[index + 1] = value
    data[index + 2] = value
  }
  return imageData
}

function preprocessCanvas(canvas: HTMLCanvasElement, mode: OcrMode) {
  const context = canvas.getContext('2d')
  if (!context) {
    throw new Error('Failed to preprocess OCR image.')
  }

  let imageData = context.getImageData(0, 0, canvas.width, canvas.height)
  imageData = convertToGrayscale(imageData)
  imageData = enhanceContrast(imageData, mode === 'region' ? 1.35 : 1.15)

  if (mode === 'region') {
    imageData = binarize(imageData, calculateOtsuThreshold(imageData))
  }

  context.putImageData(imageData, 0, 0)
}

export function captureVideoFrameForOcr(video: HTMLVideoElement, options: CaptureOptions): CaptureResult {
  if (!video.videoWidth || !video.videoHeight) {
    throw new Error('영상 메타데이터가 준비되지 않았습니다.')
  }

  const rendered = getRenderedVideoRect(video)
  if (!rendered.width || !rendered.height) {
    throw new Error('영상 표시 영역을 계산하지 못했습니다.')
  }

  const scaleX = video.videoWidth / rendered.width
  const scaleY = video.videoHeight / rendered.height

  let sourceX = 0
  let sourceY = 0
  let sourceWidth = video.videoWidth
  let sourceHeight = video.videoHeight
  let normalizedSelection: OcrSelectionRect | null = null

  if (options.mode === 'region' && options.selection) {
    normalizedSelection = clampSelectionToVideo(options.selection, rendered)
    if (!normalizedSelection) {
      throw new Error('선택 영역이 너무 작습니다.')
    }

    sourceX = Math.round((normalizedSelection.x - rendered.x) * scaleX)
    sourceY = Math.round((normalizedSelection.y - rendered.y) * scaleY)
    sourceWidth = Math.round(normalizedSelection.width * scaleX)
    sourceHeight = Math.round(normalizedSelection.height * scaleY)
  }

  const sourceCanvas = createCanvas(sourceWidth, sourceHeight)
  const sourceContext = sourceCanvas.getContext('2d')
  if (!sourceContext) {
    throw new Error('OCR용 캔버스를 만들지 못했습니다.')
  }

  sourceContext.drawImage(
    video,
    sourceX,
    sourceY,
    sourceWidth,
    sourceHeight,
    0,
    0,
    sourceWidth,
    sourceHeight,
  )

  const processedCanvas = scaleCanvas(sourceCanvas, options.mode)
  preprocessCanvas(processedCanvas, options.mode)

  try {
    return {
      dataUrl: processedCanvas.toDataURL('image/png'),
      normalizedSelection,
    }
  } catch {
    throw new Error('현재 영상은 OCR 캡처를 지원하지 않습니다. 영상 CORS 설정을 확인해주세요.')
  }
}

export function cleanRecognizedText(text: string) {
  return text
    .split('\n')
    .map((line) => line.replace(/^\s*\d{1,4}[\s:|]+/, '').replace(/\s{2,}/g, ' ').trimEnd())
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim()
}

export function extractCodeBlocks(text: string) {
  const cleaned = cleanRecognizedText(text)
  const patterns = [
    /(?:function|const|let|var|class)\s+\w+[\s\S]*?[{][\s\S]*?[}]/g,
    /(?:import|export)[\s\S]*?;/g,
    /(?:if|for|while|switch)\s*\([^)]*\)\s*[{][\s\S]*?[}]/g,
    /<[a-zA-Z][\s\S]*?>/g,
    /[.#]?[\w-]+\s*[{][\s\S]*?[}]/g,
  ]

  const results = new Set<string>()
  for (const pattern of patterns) {
    for (const match of cleaned.match(pattern) ?? []) {
      const candidate = cleanRecognizedText(match)
      if (candidate.length >= 6 && candidate.length <= 2000) {
        results.add(candidate)
      }
    }
  }

  return [...results]
}

export function buildOcrCacheKey(
  lessonId: number | null,
  mode: OcrMode,
  timestampSecond: number,
  selection: OcrSelectionRect | null,
) {
  const selectionKey = selection
    ? `${Math.round(selection.x)}:${Math.round(selection.y)}:${Math.round(selection.width)}:${Math.round(selection.height)}`
    : 'full'
  return `${lessonId ?? 'no-lesson'}:${mode}:${timestampSecond}:${selectionKey}`
}
