import { useEffect, useState } from 'react'
import {
  AUTH_TOAST_EVENT,
  clearQueuedAuthToast,
  consumeQueuedAuthToast,
} from '../lib/auth-toast'

const AUTH_TOAST_DURATION_MS = 2200

type AuthToastEvent = CustomEvent<{
  message: string
}>

export default function AuthToastViewport() {
  const [toastMessage, setToastMessage] = useState<string | null>(null)

  useEffect(() => {
    const queuedMessage = consumeQueuedAuthToast()

    if (queuedMessage) {
      setToastMessage(queuedMessage)
    }

    const handleAuthToast = (event: Event) => {
      const authToastEvent = event as AuthToastEvent
      const nextMessage = authToastEvent.detail?.message

      if (!nextMessage) {
        return
      }

      clearQueuedAuthToast()
      setToastMessage(nextMessage)
    }

    window.addEventListener(AUTH_TOAST_EVENT, handleAuthToast)

    return () => {
      window.removeEventListener(AUTH_TOAST_EVENT, handleAuthToast)
    }
  }, [])

  useEffect(() => {
    if (!toastMessage) {
      return
    }

    const timeoutId = window.setTimeout(() => {
      setToastMessage(null)
    }, AUTH_TOAST_DURATION_MS)

    return () => {
      window.clearTimeout(timeoutId)
    }
  }, [toastMessage])

  if (!toastMessage) {
    return null
  }

  return (
    <div className="pointer-events-none fixed top-20 left-1/2 z-[1000] -translate-x-1/2">
      <div
        role="status"
        aria-live="polite"
        className="rounded-xl border border-gray-700 bg-gray-900/90 px-5 py-3 text-sm font-bold text-white shadow-xl backdrop-blur-sm"
      >
        <i className="fas fa-info-circle mr-2 text-[#00C471]" />
        {toastMessage}
      </div>
    </div>
  )
}
