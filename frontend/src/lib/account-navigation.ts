export type AccountPageKey =
  | 'dashboard'
  | 'my-learning'
  | 'purchase'
  | 'my-posts'
  | 'profile'
  | 'settings'
  | 'learning-log-gallery'

export interface AccountNavItem {
  key: AccountPageKey
  href: string
  label: string
  shortLabel: string
  description: string
  icon: string
}

export const accountNavItems: AccountNavItem[] = [
  {
    key: 'dashboard',
    href: 'dashboard.html',
    label: '대시보드',
    shortLabel: '대시보드',
    description: '학습 현황과 알림을 한 번에 확인합니다.',
    icon: 'fas fa-columns',
  },
  {
    key: 'my-learning',
    href: 'my-learning.html',
    label: '내 학습',
    shortLabel: '내 학습',
    description: '수강 중이거나 완료한 강의를 모아봅니다.',
    icon: 'fas fa-book-reader',
  },
  {
    key: 'purchase',
    href: 'purchase.html',
    label: '구매 / 혜택 보관함',
    shortLabel: '구매/혜택',
    description: '구매 내역, 환불 현황, 보관한 혜택을 봅니다.',
    icon: 'fas fa-folder-open',
  },
  {
    key: 'learning-log-gallery',
    href: 'learning-log-gallery.html',
    label: '학습 기록',
    shortLabel: '학습 기록',
    description: 'Proof Card와 학습 증빙을 살펴봅니다.',
    icon: 'fas fa-clipboard-list',
  },
  {
    key: 'my-posts',
    href: 'my-posts.html',
    label: '내 게시글',
    shortLabel: '내 게시글',
    description: '작성한 커뮤니티 글을 관리합니다.',
    icon: 'fas fa-pen-nib',
  },
  {
    key: 'profile',
    href: 'profile.html',
    label: '프로필 관리',
    shortLabel: '프로필',
    description: '소개, 태그, 외부 링크를 수정합니다.',
    icon: 'fas fa-user-circle',
  },
  {
    key: 'settings',
    href: 'settings.html',
    label: '계정 설정',
    shortLabel: '설정',
    description: '비밀번호 변경과 개인 설정을 다룹니다.',
    icon: 'fas fa-cog',
  },
]

const pageKeyByFileName = new Map(
  accountNavItems.map((item) => [item.href.replace('.html', ''), item.key] as const),
)

export function getCurrentAccountPageKey(): AccountPageKey {
  const fileName = window.location.pathname.split('/').pop()?.replace('.html', '') ?? 'dashboard'

  return pageKeyByFileName.get(fileName) ?? 'dashboard'
}

export function getAccountPageMeta(key: AccountPageKey) {
  return accountNavItems.find((item) => item.key === key) ?? accountNavItems[0]
}
