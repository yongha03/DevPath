import { useEffect } from 'react'
import { getPostLoginRedirect, readStoredAuthSession } from './lib/auth-session'

function LoginApp() {
  useEffect(() => {
    // 로그인 전용 엔트리는 기존 세션을 역할별 기본 화면으로 돌려보낸다.
    const existingSession = readStoredAuthSession()

    if (existingSession) {
      window.location.replace(
        existingSession.role === 'ROLE_ADMIN' ? getPostLoginRedirect(existingSession.role) : '/',
      )
      return
    }

    window.location.replace('/?auth=login')
  }, [])

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-50 text-sm text-gray-500">
      로그인 화면으로 이동 중입니다.
    </div>
  )
}

export default LoginApp
