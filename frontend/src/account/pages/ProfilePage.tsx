import { useEffect, useState, type FormEvent, type KeyboardEvent } from 'react'
import { userApi } from '../../lib/api'
import UserAvatar from '../../components/UserAvatar'
import { updateStoredAuthSession } from '../../lib/auth-session'
import { LearnerContentRow, LearnerPageShell, MyMenuSidebar } from '../template'
import type { TechTag, UserProfile, UserProfileUpdateRequest } from '../../types/learner'
import type { AuthSession } from '../../types/auth'

type ProfileFormState = {
  name: string
  channelName: string
  bio: string
  githubUrl: string
  blogUrl: string
  profileImage: string
  tagIds: number[]
}

const fallbackProfile: UserProfile = {
  userId: 0,
  name: '김학생',
  email: 'student@devpath.kr',
  role: 'ROLE_LEARNER',
  bio: '백엔드 개발자를 꿈꾸는 학생입니다.',
  phone: '',
  profileImage: null,
  channelName: 'CozyCoder',
  githubUrl: 'https://github.com/kim-student',
  blogUrl: '',
  tags: [
    { tagId: 1, name: 'Java', category: 'LANGUAGE' },
    { tagId: 2, name: 'Spring Boot', category: 'FRAMEWORK' },
  ],
}

function toForm(profile: UserProfile): ProfileFormState {
  return {
    name: profile.name,
    channelName: profile.channelName ?? '',
    bio: profile.bio ?? '',
    githubUrl: profile.githubUrl ?? '',
    blogUrl: profile.blogUrl ?? '',
    profileImage: profile.profileImage ?? '',
    tagIds: profile.tags.map((tag) => tag.tagId),
  }
}

export default function ProfilePage({ session }: { session: AuthSession }) {
  const [profile, setProfile] = useState<UserProfile>(fallbackProfile)
  const [officialTags, setOfficialTags] = useState<TechTag[]>(fallbackProfile.tags)
  const [form, setForm] = useState<ProfileFormState>(() => toForm(fallbackProfile))
  const [tagQuery, setTagQuery] = useState('')
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    async function load() {
      try {
        const [profileResponse, tagResponse] = await Promise.all([
          userApi.getMyProfile(),
          userApi.getOfficialTags(),
        ])

        setProfile(profileResponse)
        setForm(toForm(profileResponse))
        if (tagResponse.length) {
          setOfficialTags(tagResponse)
        }
      } catch {
        // 원본 프로필 화면을 유지하기 위해 API 실패 시 기본 데이터를 사용합니다.
      }
    }

    void load()
  }, [])

  const selectedTags = officialTags.filter((tag) => form.tagIds.includes(tag.tagId))

  function handleAddTag() {
    const keyword = tagQuery.trim().toLowerCase()

    if (!keyword) {
      return
    }

    const matchedTag = officialTags.find(
      (tag) => tag.name.toLowerCase() === keyword || tag.name.toLowerCase().includes(keyword),
    )

    if (!matchedTag) {
      setError('등록된 공식 태그에서 일치하는 항목을 찾지 못했습니다.')
      return
    }

    setError('')
    setForm((current) => ({
      ...current,
      tagIds: current.tagIds.includes(matchedTag.tagId) ? current.tagIds : [...current.tagIds, matchedTag.tagId],
    }))
    setTagQuery('')
  }

  function handleTagInputKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === 'Enter') {
      event.preventDefault()
      handleAddTag()
    }
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setMessage('')
    setError('')

    const payload: UserProfileUpdateRequest = {
      name: form.name.trim(),
      bio: form.bio.trim(),
      phone: profile.phone ?? '',
      profileImage: form.profileImage.trim(),
      channelName: form.channelName.trim(),
      githubUrl: form.githubUrl.trim(),
      blogUrl: form.blogUrl.trim(),
      tagIds: form.tagIds,
    }

    try {
      const updatedProfile = await userApi.updateMyProfile(payload)
      setProfile(updatedProfile)
      setForm(toForm(updatedProfile))
      updateStoredAuthSession({ name: updatedProfile.name })
      setMessage('프로필이 저장되었습니다.')
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : '프로필 저장 중 문제가 발생했습니다.')
    }
  }

  return (
    <LearnerPageShell>
      <LearnerContentRow>
        <MyMenuSidebar currentPageKey="profile" wrapperClassName="w-60 shrink-0 hidden lg:block -ml-0" />

        <section className="min-w-0 flex-1">
          <h2 className="mb-6 text-2xl font-bold text-gray-900">프로필 관리</h2>

          <div className="rounded-2xl border border-gray-200 bg-white p-8 shadow-sm">
            <form className="flex flex-col gap-8 md:flex-row" onSubmit={handleSubmit}>
              <div className="flex w-full shrink-0 flex-col items-center gap-4 md:w-60">
                <div className="relative">
                  <div className="h-32 w-32 overflow-hidden rounded-full border-2 border-gray-100">
                    <UserAvatar
                      name={form.name || session.name}
                      imageUrl={form.profileImage || profile.profileImage}
                      className="h-full w-full border-0"
                      iconClassName="text-4xl"
                      alt={`${session.name} profile`}
                    />
                  </div>
                  <button
                    type="button"
                    className="absolute right-0 bottom-0 flex h-8 w-8 items-center justify-center rounded-full border border-gray-200 bg-white text-gray-500 shadow-sm transition hover:border-brand hover:text-brand"
                    onClick={() => {
                      const nextUrl = window.prompt('프로필 이미지 URL을 입력해 주세요.', form.profileImage)
                      if (nextUrl !== null) {
                        setForm((current) => ({ ...current, profileImage: nextUrl.trim() }))
                      }
                    }}
                  >
                    <i className="fas fa-camera" />
                  </button>
                </div>
                <p className="text-center text-xs text-gray-400">JPG, PNG, GIF (최대 2MB)</p>
              </div>

              <div className="flex-1 space-y-6">
                <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
                  <div>
                    <label className="mb-2 block text-sm font-bold text-gray-700">이름</label>
                    <input
                      type="text"
                      className="input-field"
                      value={form.name}
                      onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))}
                    />
                  </div>
                  <div>
                    <label className="mb-2 block text-sm font-bold text-gray-700">닉네임</label>
                    <input
                      type="text"
                      className="input-field"
                      value={form.channelName}
                      onChange={(event) => setForm((current) => ({ ...current, channelName: event.target.value }))}
                    />
                  </div>
                </div>

                <div>
                  <label className="mb-2 block text-sm font-bold text-gray-700">한 줄 소개</label>
                  <input
                    type="text"
                    className="input-field"
                    value={form.bio}
                    onChange={(event) => setForm((current) => ({ ...current, bio: event.target.value }))}
                  />
                </div>

                <div>
                  <label className="mb-2 block text-sm font-bold text-gray-700">관심 기술 태그</label>
                  <div className="mb-2 flex flex-wrap gap-2">
                    {selectedTags.map((tag) => (
                      <span
                        key={tag.tagId}
                        className="bg-green-50 text-brand flex items-center gap-1 rounded-full px-3 py-1 text-xs font-bold"
                      >
                        {tag.name}
                        <button
                          type="button"
                          onClick={() =>
                            setForm((current) => ({
                              ...current,
                              tagIds: current.tagIds.filter((tagId) => tagId !== tag.tagId),
                            }))
                          }
                        >
                          <i className="fas fa-times cursor-pointer" />
                        </button>
                      </span>
                    ))}
                  </div>
                  <input
                    type="text"
                    className="input-field"
                    value={tagQuery}
                    onChange={(event) => setTagQuery(event.target.value)}
                    onKeyDown={handleTagInputKeyDown}
                    placeholder="기술 스택을 입력하고 엔터를 누르세요 (ex: React, Docker)"
                  />
                </div>

                <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
                  <div>
                    <label className="mb-2 block text-sm font-bold text-gray-700">
                      <i className="fab fa-github text-gray-800" /> GitHub
                    </label>
                    <input
                      type="text"
                      className="input-field"
                      value={form.githubUrl}
                      onChange={(event) => setForm((current) => ({ ...current, githubUrl: event.target.value }))}
                    />
                  </div>
                  <div>
                    <label className="mb-2 block text-sm font-bold text-gray-700">
                      <i className="fas fa-globe text-gray-400" /> 블로그/포트폴리오
                    </label>
                    <input
                      type="text"
                      className="input-field"
                      value={form.blogUrl}
                      onChange={(event) => setForm((current) => ({ ...current, blogUrl: event.target.value }))}
                      placeholder="URL을 입력해주세요"
                    />
                  </div>
                </div>

                {message ? <p className="text-sm font-bold text-brand">{message}</p> : null}
                {error ? <p className="text-sm font-bold text-red-500">{error}</p> : null}

                <div className="flex justify-end pt-4">
                  <button className="bg-brand rounded-xl px-8 py-3 font-bold text-white transition hover:bg-green-600" type="submit">
                    저장하기
                  </button>
                </div>
              </div>
            </form>
          </div>
        </section>
      </LearnerContentRow>
    </LearnerPageShell>
  )
}
