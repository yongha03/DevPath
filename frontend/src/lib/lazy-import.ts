const RETRY_KEY_PREFIX = 'devpath:chunk-retry:'
const CHUNK_LOAD_ERROR_PATTERN = /Failed to fetch dynamically imported module|Importing a module script failed|error loading dynamically imported module/i

function isChunkLoadError(error: unknown) {
  if (!(error instanceof Error)) {
    return false
  }

  return CHUNK_LOAD_ERROR_PATTERN.test(error.message)
}

export async function importWithPageReload<T>(loader: () => Promise<T>, retryKey: string): Promise<T> {
  try {
    const module = await loader()
    window.sessionStorage.removeItem(`${RETRY_KEY_PREFIX}${retryKey}`)
    return module
  } catch (error) {
    if (isChunkLoadError(error)) {
      const storageKey = `${RETRY_KEY_PREFIX}${retryKey}`
      const hasRetried = window.sessionStorage.getItem(storageKey) === '1'

      if (!hasRetried) {
        window.sessionStorage.setItem(storageKey, '1')
        window.location.reload()
        return new Promise<T>(() => undefined)
      }

      window.sessionStorage.removeItem(storageKey)
    }

    throw error
  }
}
