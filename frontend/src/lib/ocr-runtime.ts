export interface OcrProgressInfo {
  status: string
  progress: number
}

export interface OcrRecognizeResponse {
  data: {
    text: string
    confidence: number
  }
}

export interface TesseractWorkerLike {
  recognize(image: string): Promise<OcrRecognizeResponse>
  terminate(): Promise<void>
}

export interface TesseractGlobal {
  createWorker(
    langs?: string,
    oem?: number,
    options?: {
      logger?: (info: OcrProgressInfo) => void
    },
  ): Promise<TesseractWorkerLike>
}

declare global {
  interface Window {
    Tesseract?: TesseractGlobal
    __devpathTesseractLoader?: Promise<TesseractGlobal>
  }
}

const TESSERACT_SCRIPT_URL = 'https://cdn.jsdelivr.net/npm/tesseract.js@5/dist/tesseract.min.js'

export async function loadTesseractGlobal() {
  if (window.Tesseract) {
    return window.Tesseract
  }

  if (!window.__devpathTesseractLoader) {
    window.__devpathTesseractLoader = new Promise<TesseractGlobal>((resolve, reject) => {
      const existing = document.querySelector<HTMLScriptElement>(`script[data-devpath-tesseract="true"]`)
      if (existing) {
        existing.addEventListener('load', () => {
          if (window.Tesseract) resolve(window.Tesseract)
          else reject(new Error('Tesseract global was not initialized.'))
        })
        existing.addEventListener('error', () => reject(new Error('Failed to load Tesseract script.')))
        return
      }

      const script = document.createElement('script')
      script.src = TESSERACT_SCRIPT_URL
      script.async = true
      script.defer = true
      script.dataset.devpathTesseract = 'true'
      script.onload = () => {
        if (window.Tesseract) resolve(window.Tesseract)
        else reject(new Error('Tesseract global was not initialized.'))
      }
      script.onerror = () => reject(new Error('Failed to load Tesseract script.'))
      document.head.appendChild(script)
    }).catch((error) => {
      window.__devpathTesseractLoader = undefined
      throw error
    })
  }

  return window.__devpathTesseractLoader
}
