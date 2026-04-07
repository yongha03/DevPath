import { useEffect, useState, type FormEvent } from 'react'
import { userApi } from '../../lib/api'
import { LearnerContentRow, LearnerPageShell, MyMenuSidebar } from '../template'
import { readLocalPreferences } from '../ui'

const SETTINGS_STORAGE_KEY = 'devpath.account.preferences'

export default function SettingsPage({
}: {
  session: unknown
}) {
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [preferences, setPreferences] = useState(() => readLocalPreferences())
  const [passwordMessage, setPasswordMessage] = useState('')
  const [passwordError, setPasswordError] = useState('')

  useEffect(() => {
    localStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(preferences))
  }, [preferences])

  async function handlePasswordSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setPasswordMessage('')
    setPasswordError('')

    if (newPassword !== confirmPassword) {
      setPasswordError('새 비밀번호와 확인 값이 일치하지 않습니다.')
      return
    }

    try {
      await userApi.changePassword({
        currentPassword,
        newPassword,
      })
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
      setPasswordMessage('비밀번호가 변경되었습니다.')
    } catch (submitError) {
      setPasswordError(submitError instanceof Error ? submitError.message : '비밀번호 변경 중 문제가 발생했습니다.')
    }
  }

  return (
    <LearnerPageShell>
      <LearnerContentRow>
        <MyMenuSidebar currentPageKey="settings" wrapperClassName="w-60 shrink-0 hidden lg:block -ml-0" />

        <section className="min-w-0 max-w-3xl flex-1">
          <h2 className="mb-6 text-2xl font-bold text-gray-900">계정 설정</h2>

          <section className="mb-6 rounded-2xl border border-gray-200 bg-white p-6 shadow-sm">
            <h3 className="mb-4 text-lg font-bold text-gray-900">비밀번호 변경</h3>
            <form className="space-y-4" onSubmit={handlePasswordSubmit}>
              <div>
                <label className="mb-1 block text-sm font-bold text-gray-700">현재 비밀번호</label>
                <input
                  type="password"
                  className="input-field"
                  placeholder="현재 비밀번호를 입력하세요"
                  value={currentPassword}
                  onChange={(event) => setCurrentPassword(event.target.value)}
                />
              </div>
              <div>
                <label className="mb-1 block text-sm font-bold text-gray-700">새 비밀번호</label>
                <input
                  type="password"
                  className="input-field"
                  placeholder="새 비밀번호"
                  value={newPassword}
                  onChange={(event) => setNewPassword(event.target.value)}
                />
              </div>
              <div>
                <label className="mb-1 block text-sm font-bold text-gray-700">새 비밀번호 확인</label>
                <input
                  type="password"
                  className="input-field"
                  placeholder="새 비밀번호 확인"
                  value={confirmPassword}
                  onChange={(event) => setConfirmPassword(event.target.value)}
                />
              </div>
              {passwordMessage ? <p className="text-sm font-bold text-brand">{passwordMessage}</p> : null}
              {passwordError ? <p className="text-sm font-bold text-red-500">{passwordError}</p> : null}
              <div className="flex justify-end">
                <button
                  className="rounded-lg bg-gray-900 px-6 py-2 text-sm font-bold text-white transition hover:bg-black"
                  type="submit"
                >
                  변경하기
                </button>
              </div>
            </form>
          </section>

          <section className="mb-6 rounded-2xl border border-gray-200 bg-white p-6 shadow-sm">
            <h3 className="mb-4 text-lg font-bold text-gray-900">알림 설정</h3>

            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-bold text-gray-800">이메일 알림</p>
                  <p className="text-xs text-gray-500">주요 공지사항 및 학습 알림을 이메일로 받습니다.</p>
                </div>

                <div className="relative mr-2 inline-block w-10 align-middle select-none transition duration-200 ease-in">
                  <input
                    type="checkbox"
                    id="toggle1"
                    checked={preferences.emailAlerts}
                    onChange={(event) =>
                      setPreferences((current) => ({ ...current, emailAlerts: event.target.checked }))
                    }
                    className="toggle-checkbox checked:border-brand absolute block h-5 w-5 cursor-pointer appearance-none rounded-full border-4 bg-white"
                  />
                  <label htmlFor="toggle1" className="toggle-label block h-5 cursor-pointer overflow-hidden rounded-full bg-gray-300" />
                </div>
              </div>

              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-bold text-gray-800">마케팅 정보 수신</p>
                  <p className="text-xs text-gray-500">이벤트 및 할인 혜택 정보를 받습니다.</p>
                </div>

                <div className="relative mr-2 inline-block w-10 align-middle select-none transition duration-200 ease-in">
                  <input
                    type="checkbox"
                    id="toggle2"
                    checked={preferences.marketingAlerts}
                    onChange={(event) =>
                      setPreferences((current) => ({ ...current, marketingAlerts: event.target.checked }))
                    }
                    className="toggle-checkbox absolute block h-5 w-5 cursor-pointer appearance-none rounded-full border-4 bg-white"
                  />
                  <label htmlFor="toggle2" className="toggle-label block h-5 cursor-pointer overflow-hidden rounded-full bg-gray-300" />
                </div>
              </div>
            </div>
          </section>

          <section className="rounded-2xl border border-red-100 bg-white p-6 shadow-sm">
            <h3 className="mb-2 text-lg font-bold text-red-600">회원 탈퇴</h3>
            <p className="mb-4 text-sm text-gray-600">탈퇴 시 작성한 게시글 및 학습 기록은 복구할 수 없습니다.</p>
            <button
              className="rounded-lg border border-red-200 px-4 py-2 text-sm font-bold text-red-500 transition hover:bg-red-50"
              type="button"
              onClick={() => {
                window.alert('회원 탈퇴 API는 아직 연결되지 않았습니다.')
              }}
            >
              탈퇴하기
            </button>
          </section>
        </section>
      </LearnerContentRow>
    </LearnerPageShell>
  )
}
