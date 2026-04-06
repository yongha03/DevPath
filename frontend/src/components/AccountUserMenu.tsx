import { useEffect, useRef, useState } from 'react'
import { accountNavItems, type AccountPageKey } from '../lib/account-navigation'
import type { AuthSession } from '../types/auth'
import UserAvatar from './UserAvatar'

type AccountUserMenuProps = {
  session: AuthSession
  profileImage?: string | null
  currentPageKey?: AccountPageKey
  onLogout?: () => Promise<void> | void
}

export default function AccountUserMenu({
  session,
  profileImage,
  currentPageKey,
  onLogout,
}: AccountUserMenuProps) {
  const [open, setOpen] = useState(false)
  const containerRef = useRef<HTMLDivElement | null>(null)

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
        <div className="absolute right-0 z-50 mt-3 w-[320px] overflow-hidden rounded-3xl border border-gray-200 bg-white shadow-2xl shadow-gray-900/10">
          <div className="border-b border-gray-100 bg-gradient-to-br from-emerald-50 via-white to-teal-50 px-5 py-5">
            <div className="flex items-center gap-3">
              <UserAvatar
                name={session.name}
                imageUrl={profileImage}
                className="h-12 w-12"
                iconClassName="text-base"
                alt={`${session.name} profile`}
              />
              <div className="min-w-0">
                <div className="truncate text-base font-extrabold text-gray-900">{session.name}</div>
              </div>
            </div>
          </div>

          <div className="grid gap-1 p-2">
            {accountNavItems.map((item) => {
              const active = currentPageKey === item.key

              return (
                <a
                  key={item.key}
                  href={item.href}
                  onClick={() => setOpen(false)}
                  className={`flex items-start gap-3 rounded-2xl px-4 py-3 transition ${
                    active ? 'bg-emerald-50 text-emerald-700' : 'hover:bg-gray-50'
                  }`}
                >
                  <div
                    className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl ${
                      active ? 'bg-emerald-100 text-emerald-600' : 'bg-gray-100 text-gray-500'
                    }`}
                  >
                    <i className={item.icon} />
                  </div>
                  <div className="min-w-0">
                    <div className="text-sm font-bold text-gray-900">{item.shortLabel}</div>
                    <div className="mt-0.5 text-xs leading-5 text-gray-500">{item.description}</div>
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
              className="flex w-full items-center gap-3 rounded-2xl px-4 py-3 text-left text-sm font-bold text-gray-700 transition hover:bg-gray-50"
            >
              <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-gray-100 text-gray-500">
                <i className="fas fa-arrow-right-from-bracket" />
              </div>
              로그아웃
            </button>
          </div>
        </div>
      ) : null}
    </div>
  )
}
