import type { ReactNode } from 'react'
import type { AuthSession } from '../../types/auth'
import type { InstructorPageKey } from '../navigation'
import InstructorHeader from './InstructorHeader'
import InstructorSidebar from './InstructorSidebar'

export default function InstructorLayout({
  session,
  profileImage,
  currentPageKey,
  onLogout,
  children,
}: {
  session: AuthSession
  profileImage?: string | null
  currentPageKey: InstructorPageKey
  onLogout?: () => Promise<void> | void
  children: ReactNode
}) {
  return (
    <div className="min-h-screen min-w-0 text-gray-800">
      <InstructorHeader session={session} profileImage={profileImage} onLogout={onLogout} />
      <div className="app-main flex min-h-screen min-w-0 bg-[#F3F4F6]">
        <InstructorSidebar currentPageKey={currentPageKey} />
        <main className="app-responsive-main bg-[#F3F4F6]">{children}</main>
      </div>
    </div>
  )
}
