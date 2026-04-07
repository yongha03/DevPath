import { useEffect, useState } from 'react'

export function useLocalStorageState<T>(key: string, initialValue: T) {
  const [value, setValue] = useState<T>(() => {
    try {
      const raw = localStorage.getItem(key)

      if (raw !== null) {
        return JSON.parse(raw) as T
      }
    } catch {
      // Fallback to the provided initial value when parsing fails.
    }

    return initialValue
  })

  useEffect(() => {
    try {
      localStorage.setItem(key, JSON.stringify(value))
    } catch {
      // Ignore quota/storage access failures in the demo UI.
    }
  }, [key, value])

  return [value, setValue] as const
}
