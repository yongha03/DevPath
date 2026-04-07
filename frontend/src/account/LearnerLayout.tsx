import { useEffect, useState, type ReactNode } from 'react'
import { userApi } from '../lib/api'
import { LearnerHeader } from './template'
import type { AuthSession } from '../types/auth'

export default function LearnerLayout({
  session,
  onLogout,
  children,
}: {
  session: AuthSession
  currentPageKey: string
  onLogout: () => Promise<void>
  children: ReactNode
}) {
  const [profileImage, setProfileImage] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()

    userApi
      .getMyProfile(controller.signal)
      .then((profile) => {
        setProfileImage(profile.profileImage)
      })
      .catch(() => {
        setProfileImage(null)
      })

    return () => {
      controller.abort()
    }
  }, [session.userId])

  return (
    <div className="flex min-h-screen text-gray-800">
      <div className="min-w-0 flex-1">
        <LearnerHeader session={session} profileImage={profileImage} onLogout={onLogout} />
        {children}
      </div>
    </div>
  )
}
