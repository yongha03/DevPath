import type { CSSProperties } from 'react'
import type { AuthSession } from '../types/auth'
import AccountUserMenu from './AccountUserMenu'

const headerLinks = [
  { href: 'roadmap-hub.html', label: '\uB85C\uB4DC\uB9F5' },
  { href: 'lecture-list.html', label: '\uAC15\uC758' },
  { href: 'lounge-dashboard.html', label: '\uD504\uB85C\uC81D\uD2B8' },
  { href: 'community-list.html', label: '\uCEE4\uBBA4\uB2C8\uD2F0' },
  { href: 'job-matching.html', label: '\uCC44\uC6A9\uBD84\uC11D' },
]

// Edit only this object when you want pixel-level header tuning.
export const siteHeaderTuning = {
  maxWidthPx: 1600,
  horizontalPaddingPx: 32,
  containerGapPx: 32,
  sideWidthPx: 240,
  brandSlotOffsetXPx: -54,
  navBaseXPx: 17.5,
  navGapPx: 40,
  instructorGapPx: 40,
  instructorLinkGapPx: 24,
  headerGroup: { x: 0, y: 0 },
  brandGroup: { x: 15, y: 0 },
  navGroup: { x: -2.5, y: 0 },
  userGroup: { x: -12.5, y: 0 },
} as const

function getMoveStyle(offset: { x: number; y: number }): CSSProperties {
  return {
    transform: `translate(${offset.x}px, ${offset.y}px)`,
  }
}

type SiteHeaderProps = {
  session: AuthSession | null
  profileImage?: string | null
  onLogout?: () => Promise<void> | void
  onLoginClick?: () => void
}

export default function SiteHeader({ session, profileImage, onLogout, onLoginClick }: SiteHeaderProps) {
  const showInstructorDashboard = session?.role === 'ROLE_INSTRUCTOR'
  const instructorHeaderLinks = showInstructorDashboard
    ? [{ href: 'instructor-dashboard.html', label: '\uAC15\uC0AC \uB300\uC2DC\uBCF4\uB4DC' }]
    : []
  const containerStyle: CSSProperties = {
    maxWidth: `${siteHeaderTuning.maxWidthPx}px`,
    paddingLeft: `${siteHeaderTuning.horizontalPaddingPx}px`,
    paddingRight: `${siteHeaderTuning.horizontalPaddingPx}px`,
    gap: `${siteHeaderTuning.containerGapPx}px`,
    ...getMoveStyle(siteHeaderTuning.headerGroup),
  }
  const brandSlotStyle: CSSProperties = {
    width: `${siteHeaderTuning.sideWidthPx}px`,
    transform: `translateX(${siteHeaderTuning.brandSlotOffsetXPx}px)`,
  }
  const navStyle: CSSProperties = {
    gap: `${siteHeaderTuning.navGapPx}px`,
    transform: `translate(${siteHeaderTuning.navBaseXPx + siteHeaderTuning.navGroup.x}px, ${siteHeaderTuning.navGroup.y}px)`,
  }
  const instructorStyle: CSSProperties = {
    marginLeft: `${siteHeaderTuning.instructorGapPx}px`,
    gap: `${siteHeaderTuning.instructorLinkGapPx}px`,
  }
  const userStyle = getMoveStyle(siteHeaderTuning.userGroup)

  return (
    <>
      <div className="app-header-rail" />

      <nav className="app-header">
        <div className="mx-auto flex h-full w-full items-center" style={containerStyle}>
          <div className="hidden items-center px-4 lg:flex" style={brandSlotStyle}>
            <a
              href="home.html"
              className="group flex items-center gap-2 text-xl font-bold text-gray-900"
              style={getMoveStyle(siteHeaderTuning.brandGroup)}
            >
              <i className="fas fa-code-branch text-brand inline-block transition group-hover:rotate-12" />
              <span className="inline-block">DevPath</span>
            </a>
          </div>

          <div className="flex items-center lg:hidden">
            <a
              href="home.html"
              className="group flex items-center gap-2 text-xl font-bold text-gray-900"
              style={getMoveStyle(siteHeaderTuning.brandGroup)}
            >
              <i className="fas fa-code-branch text-brand inline-block transition group-hover:rotate-12" />
              <span className="inline-block">DevPath</span>
            </a>
          </div>

          <div className="hidden flex-1 items-center justify-center text-sm font-bold text-gray-500 md:flex">
            <div className="relative inline-flex items-center" style={navStyle}>
              {headerLinks.map((item) => (
                <a key={item.href} href={item.href} className="inline-block whitespace-nowrap transition hover:text-brand">
                  {item.label}
                </a>
              ))}

              {showInstructorDashboard ? (
                <div
                  className="absolute top-1/2 left-full inline-flex -translate-y-1/2 whitespace-nowrap"
                  style={instructorStyle}
                >
                  {instructorHeaderLinks.map((item) => (
                    <a key={item.href} href={item.href} className="inline-block transition hover:text-brand">
                      {item.label}
                    </a>
                  ))}
                </div>
              ) : null}
            </div>
          </div>

          <div className="flex items-center justify-end gap-2 md:w-60">
            <div className="hidden md:block" style={userStyle}>
              {session ? (
                <AccountUserMenu session={session} profileImage={profileImage} onLogout={onLogout} />
              ) : (
                <button
                  type="button"
                  onClick={onLoginClick}
                  className="rounded-full bg-gray-900 px-5 py-2 text-sm font-bold text-white shadow-lg transition hover:bg-black"
                >
                  {'\uB85C\uADF8\uC778'}
                </button>
              )}
            </div>

            <div className="md:hidden" style={userStyle}>
              {session ? (
                <AccountUserMenu session={session} profileImage={profileImage} onLogout={onLogout} />
              ) : (
                <button
                  type="button"
                  onClick={onLoginClick}
                  className="rounded-full bg-gray-900 px-5 py-2 text-sm font-bold text-white shadow-lg transition hover:bg-black"
                >
                  {'\uB85C\uADF8\uC778'}
                </button>
              )}
            </div>
          </div>
        </div>
      </nav>
    </>
  )
}
