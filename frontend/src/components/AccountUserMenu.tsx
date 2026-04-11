import { useEffect, useRef, useState } from 'react'
import { buildMyInstructorProfileHref } from '../instructor-channel-customization'
import { accountNavItems, type AccountPageKey } from '../lib/account-navigation'
import type { AuthSession } from '../types/auth'
import UserAvatar from './UserAvatar'

type AccountUserMenuProps = {
  session: AuthSession
  profileImage?: string | null
  currentPageKey?: AccountPageKey
  onLogout?: () => Promise<void> | void
}

type MenuTone = {
  iconClassName: string
}

const menuToneByKey: Record<string, MenuTone> = {
  'instructor-channel': {
    iconClassName: 'bg-violet-50 text-violet-600',
  },
  dashboard: {
    iconClassName: 'bg-sky-50 text-sky-600',
  },
  'my-learning': {
    iconClassName: 'bg-amber-50 text-amber-600',
  },
  purchase: {
    iconClassName: 'bg-indigo-50 text-indigo-600',
  },
  'learning-log-gallery': {
    iconClassName: 'bg-teal-50 text-teal-600',
  },
  'my-posts': {
    iconClassName: 'bg-orange-50 text-orange-600',
  },
  profile: {
    iconClassName: 'bg-cyan-50 text-cyan-600',
  },
  settings: {
    iconClassName: 'bg-slate-100 text-slate-600',
  },
  logout: {
    iconClassName: 'bg-rose-50 text-rose-500',
  },
}

function getMenuTone(key: string): MenuTone {
  return (
    menuToneByKey[key] ?? {
      iconClassName: 'bg-gray-100 text-gray-500',
    }
  )
}

function getMenuItemClassName(active: boolean) {
  const baseClassName =
    'group flex items-start gap-3 rounded-2xl border px-4 py-3 transition-all duration-200'

  if (active) {
    return `${baseClassName} border-emerald-100 bg-emerald-50/80 text-emerald-800 shadow-[0_12px_30px_rgba(16,185,129,0.10)]`
  }

  return `${baseClassName} border-transparent hover:-translate-y-0.5 hover:border-emerald-100 hover:bg-white hover:shadow-[0_12px_24px_rgba(16,185,129,0.10)]`
}

function getMenuIconClassName(key: string) {
  const tone = getMenuTone(key)

  return `flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl transition-all duration-200 group-hover:scale-[1.03] group-hover:ring-4 group-hover:ring-emerald-100/80 group-hover:shadow-[0_10px_24px_rgba(16,185,129,0.16)] ${tone.iconClassName}`
}

const menuDescriptionClassName =
  'mt-0.5 truncate text-xs leading-5 text-gray-500 transition-colors group-hover:text-gray-600'

export default function AccountUserMenu({
  session,
  profileImage,
  currentPageKey,
  onLogout,
}: AccountUserMenuProps) {
  const [open, setOpen] = useState(false)
  const containerRef = useRef<HTMLDivElement | null>(null)
  const currentFileName = window.location.pathname.split('/').pop() ?? ''
  const instructorChannelActive =
    currentFileName === 'instructor-profile.html' || currentFileName === 'instructor-channel.html'
  const instructorMenuItem =
    session.role === 'ROLE_INSTRUCTOR'
      ? {
          key: 'instructor-channel',
          href: buildMyInstructorProfileHref(session),
          shortLabel: '내 채널',
          description: '강사 프로필과 채널 홈으로 이동합니다.',
          icon: 'fas fa-circle-play',
        }
      : null

  useEffect(() => {
    if (!open) {
      return
    }

    function handlePointerDown(event: MouseEvent) {
      if (!containerRef.current?.contains(event.target as Node)) {
        setOpen(false)
      }
    }

    function handleEscape(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setOpen(false)
      }
    }

    document.addEventListener('mousedown', handlePointerDown)
    document.addEventListener('keydown', handleEscape)

    return () => {
      document.removeEventListener('mousedown', handlePointerDown)
      document.removeEventListener('keydown', handleEscape)
    }
  }, [open])

  return (
    <div ref={containerRef} className="relative">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        className="flex items-center gap-3 rounded-full border border-gray-200 bg-white px-3 py-2 text-left shadow-sm transition hover:border-gray-300 hover:shadow-md"
        aria-expanded={open}
        aria-haspopup="menu"
      >
        <UserAvatar
          name={session.name}
          imageUrl={profileImage}
          className="h-9 w-9 shadow-sm"
          iconClassName="text-sm"
          alt={`${session.name} profile`}
        />
        <div className="min-w-0">
          <div className="truncate text-sm font-bold text-gray-900">{session.name}</div>
        </div>
        <i className={`fas fa-chevron-${open ? 'up' : 'down'} hidden text-xs text-gray-400 sm:block`} />
      </button>

      {open ? (
        <div className="absolute right-0 z-50 mt-3 w-[calc(100vw-16px)] max-w-[344px] overflow-hidden rounded-3xl border border-gray-200 bg-white shadow-2xl shadow-gray-900/10">
          <div className="border-b border-gray-100 bg-white px-5 py-5">
            <div className="flex items-center gap-3">
              <UserAvatar
                name={session.name}
                imageUrl={profileImage}
                className="h-12 w-12 shadow-sm"
                iconClassName="text-base"
                alt={`${session.name} profile`}
              />
              <div className="min-w-0">
                <div className="truncate text-base font-extrabold text-gray-900">{session.name}</div>
              </div>
            </div>
          </div>

          <div className="grid gap-1 p-2">
            {instructorMenuItem ? (
              <a
                href={instructorMenuItem.href}
                onClick={() => setOpen(false)}
                className={getMenuItemClassName(instructorChannelActive)}
              >
                <div className={getMenuIconClassName(instructorMenuItem.key)}>
                  <i className={instructorMenuItem.icon} />
                </div>
                <div className="min-w-0">
                  <div className="text-sm font-bold text-gray-900">{instructorMenuItem.shortLabel}</div>
                  <div className={menuDescriptionClassName} title={instructorMenuItem.description}>
                    {instructorMenuItem.description}
                  </div>
                </div>
              </a>
            ) : null}
            {accountNavItems.map((item) => {
              const active = currentPageKey === item.key

              return (
                <a
                  key={item.key}
                  href={item.href}
                  onClick={() => setOpen(false)}
                  className={getMenuItemClassName(active)}
                >
                  <div className={getMenuIconClassName(item.key)}>
                    <i className={item.icon} />
                  </div>
                  <div className="min-w-0">
                    <div className="text-sm font-bold text-gray-900">{item.shortLabel}</div>
                    <div className={menuDescriptionClassName} title={item.description}>
                      {item.description}
                    </div>
                  </div>
                </a>
              )
            })}
          </div>

          <div className="border-t border-gray-100 p-2">
            <button
              type="button"
              onClick={async () => {
                setOpen(false)
                await onLogout?.()
              }}
              className={`${getMenuItemClassName(false)} w-full text-left text-sm font-bold text-gray-700`}
            >
              <div className={getMenuIconClassName('logout')}>
                <i className="fas fa-arrow-right-from-bracket" />
              </div>
              {'\uB85C\uADF8\uC544\uC6C3'}
            </button>
          </div>
        </div>
      ) : null}
    </div>
  )
}
