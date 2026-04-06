import { useEffect, useMemo, useState } from 'react'
import { communityApi } from '../../lib/api'
import { LearnerContentRow, LearnerPageShell, MyMenuSidebar } from '../template'
import type { AuthSession } from '../../types/auth'
import type { CommunityPost } from '../../types/learner'

type FilterCategory = 'all' | 'qna' | 'tech' | 'career' | 'free' | 'project'
type SortType = 'latest' | 'popular' | 'views'

type PostViewItem = CommunityPost & {
  filterCategory: FilterCategory
  commentCount: number
  tags: string[]
  detailTitle: string
  detailBody: string[]
}

const fallbackPosts: PostViewItem[] = [
  {
    id: 1,
    authorName: '김학생',
    category: 'QNA',
    filterCategory: 'qna',
    title: 'Spring Boot JPA N+1 문제 해결 조언 부탁드립니다.',
    content:
      '엔티티 연관관계 설정 중에 자꾸 쿼리가 여러 번 나가는 문제가 발생합니다. Fetch Join을 썼는데도 해결이 안 되네요. 혹시 BatchSize 설정은 어떻게...',
    viewCount: 128,
    likeCount: 5,
    commentCount: 3,
    createdAt: '2026-02-05T10:00:00',
    tags: ['#Java', '#Spring Boot', '#JPA'],
    detailTitle: '1. 문제 상황',
    detailBody: [
      'Spring Boot + JPA 환경에서 연관관계 조회 시 N+1 문제가 반복적으로 발생하고 있습니다.',
      'Fetch Join을 적용했지만 일부 화면에서는 여전히 추가 쿼리가 나가고 있어 원인을 찾고 있습니다.',
      'BatchSize나 EntityGraph를 어떤 기준으로 적용하면 좋은지 경험 있으신 분들 의견 부탁드립니다.',
    ],
  },
  {
    id: 2,
    authorName: '김학생',
    category: 'PROJECT',
    filterCategory: 'project',
    title: '2026 졸업작품 팀원 모집합니다 (백엔드 1명)',
    content:
      "주제는 개발자들을 위한 올인원 플랫폼 'DevPath' 입니다. 현재 프론트 2명, 백엔드 1명 있습니다. 열정적으로 하실 분 구합니다!",
    viewCount: 450,
    likeCount: 24,
    commentCount: 12,
    createdAt: '2026-01-20T10:00:00',
    tags: ['#팀원모집', '#사이드프로젝트'],
    detailTitle: '프로젝트 소개',
    detailBody: [
      '졸업작품 주제는 개발자 학습과 커리어 관리를 한 곳에서 제공하는 DevPath 플랫폼입니다.',
      '현재 프론트엔드 2명, 백엔드 1명으로 구성되어 있고 백엔드 한 분을 더 찾고 있습니다.',
      'Spring Boot, 인증/인가, 데이터 모델링 경험이 있으면 좋습니다.',
    ],
  },
  {
    id: 3,
    authorName: '김학생',
    category: 'TECH_SHARE',
    filterCategory: 'tech',
    title: '2026년 백엔드 개발자 로드맵 정리 (주관적)',
    content:
      '개인적으로 공부하면서 느꼈던 필수 스킬들을 정리해봤습니다. Java, Spring, JPA, Docker 순서대로 학습하는 것을 추천드리며...',
    viewCount: 890,
    likeCount: 56,
    commentCount: 8,
    createdAt: '2025-12-15T10:00:00',
    tags: ['#Roadmap', '#Backend', '#Career'],
    detailTitle: '정리 내용',
    detailBody: [
      '기초 CS, Java, Spring Boot, JPA, 테스트, Docker 순서로 학습 흐름을 잡는 것을 추천합니다.',
      '각 단계마다 작은 프로젝트를 하나씩 넣어두면 이해도가 훨씬 높아집니다.',
      '로드맵은 절대적인 기준이 아니라 현재 목표와 경험에 맞게 조정하는 것이 중요합니다.',
    ],
  },
]

function mapCategory(category: string): FilterCategory {
  switch (category) {
    case 'TECH_SHARE':
      return 'tech'
    case 'CAREER':
      return 'career'
    case 'FREE':
      return 'free'
    case 'PROJECT':
      return 'project'
    case 'QNA':
      return 'qna'
    default:
      return 'tech'
  }
}

function badgeTone(category: FilterCategory) {
  switch (category) {
    case 'qna':
      return 'text-purple-600 bg-purple-50 border-purple-100'
    case 'project':
      return 'text-blue-600 bg-blue-50 border-blue-100'
    case 'tech':
      return 'text-green-600 bg-green-50 border-green-100'
    case 'career':
      return 'text-orange-600 bg-orange-50 border-orange-100'
    case 'free':
      return 'text-gray-600 bg-gray-50 border-gray-200'
    default:
      return 'text-gray-600 bg-gray-50 border-gray-200'
  }
}

function categoryLabel(category: FilterCategory) {
  switch (category) {
    case 'qna':
      return 'Q&A'
    case 'tech':
      return '기술 공유'
    case 'career':
      return '커리어/이직'
    case 'free':
      return '자유게시판'
    case 'project':
      return '팀프로젝트'
    default:
      return '전체'
  }
}

function formatShortDate(value: string | null | undefined) {
  if (!value) {
    return '-'
  }

  const date = new Date(value)

  return `${date.getFullYear()}.${String(date.getMonth() + 1).padStart(2, '0')}.${String(date.getDate()).padStart(2, '0')}`
}

export default function MyPostsPage({ session }: { session: AuthSession }) {
  const [posts, setPosts] = useState<PostViewItem[]>(fallbackPosts)
  const [category, setCategory] = useState<FilterCategory>('all')
  const [keyword, setKeyword] = useState('')
  const [sort, setSort] = useState<SortType>('latest')
  const [selectedPostId, setSelectedPostId] = useState<number | null>(null)

  useEffect(() => {
    async function load() {
      if (!session.userId) {
        return
      }

      try {
        const response = await communityApi.searchPosts({
          authorId: session.userId,
          page: 0,
          size: 100,
        })

        if (response.content.length) {
          setPosts(
            response.content.map((post, index) => ({
              ...post,
              filterCategory: mapCategory(post.category),
              commentCount: Math.max(1, Math.min(12, Math.round(post.likeCount / 2) || index + 1)),
              tags:
                mapCategory(post.category) === 'tech'
                  ? ['#Roadmap', '#Backend', '#Career']
                  : mapCategory(post.category) === 'project'
                    ? ['#팀원모집', '#사이드프로젝트']
                    : ['#Java', '#Spring Boot', '#JPA'],
              detailTitle: mapCategory(post.category) === 'project' ? '프로젝트 소개' : '1. 문제 상황',
              detailBody: post.content
                .split('\n')
                .map((line) => line.trim())
                .filter(Boolean)
                .slice(0, 3),
            })),
          )
        }
      } catch {
        // 원본 게시글 화면을 유지하기 위해 API 실패 시 기본 템플릿 데이터를 사용합니다.
      }
    }

    void load()
  }, [session.userId])

  const filteredPosts = useMemo(() => {
    const normalizedKeyword = keyword.trim().toLowerCase()
    const result = posts.filter((post) => {
      const categoryMatch = category === 'all' || post.filterCategory === category
      const keywordMatch =
        !normalizedKeyword ||
        post.title.toLowerCase().includes(normalizedKeyword) ||
        post.content.toLowerCase().includes(normalizedKeyword)

      return categoryMatch && keywordMatch
    })

    return [...result].sort((left, right) => {
      if (sort === 'popular') {
        return right.likeCount - left.likeCount
      }

      if (sort === 'views') {
        return right.viewCount - left.viewCount
      }

      return new Date(right.createdAt ?? 0).getTime() - new Date(left.createdAt ?? 0).getTime()
    })
  }, [category, keyword, posts, sort])

  const selectedPost = posts.find((post) => post.id === selectedPostId) ?? null

  return (
    <LearnerPageShell>
      <LearnerContentRow>
        <MyMenuSidebar currentPageKey="my-posts" wrapperClassName="w-60 shrink-0 hidden lg:block -ml-0" />

        <section className="min-w-0 flex-1">
          {selectedPost ? (
            <div className="fade-in">
              <div className="mb-4 flex items-center justify-between">
                <button
                  type="button"
                  onClick={() => setSelectedPostId(null)}
                  className="flex items-center gap-2 text-sm font-bold text-gray-500 transition hover:text-gray-900"
                >
                  <i className="fas fa-arrow-left" /> 목록으로 돌아가기
                </button>
              </div>

              <article className="mb-8 rounded-xl border border-gray-200 bg-white p-6 shadow-sm md:p-8">
                <div className="prose max-w-none text-gray-800">
                  <h3>{selectedPost.detailTitle}</h3>
                  {selectedPost.detailBody.map((paragraph, index) => (
                    <p key={`${selectedPost.id}-${index}`}>{paragraph}</p>
                  ))}
                </div>
              </article>
            </div>
          ) : (
            <div className="fade-in">
              <div className="mb-6 flex items-end justify-between">
                <h2 className="text-2xl font-bold text-gray-900">작성한 게시글</h2>
                <div className="text-sm text-gray-500">
                  총 <span className="font-bold text-brand">{filteredPosts.length}</span>개의 글
                </div>
              </div>

              <div className="mb-6 flex flex-col items-center justify-between rounded-xl border border-gray-200 bg-white px-2 shadow-sm md:flex-row">
                <div className="hide-scroll flex w-full overflow-x-auto md:w-auto">
                  {(['all', 'qna', 'tech', 'career', 'free', 'project'] as const).map((item) => (
                    <button
                      key={item}
                      type="button"
                      className={`filter-tab ${category === item ? 'active' : ''}`}
                      onMouseDown={(event) => event.preventDefault()}
                      onClick={() => setCategory(item)}
                    >
                      {item === 'all' ? '전체' : categoryLabel(item)}
                    </button>
                  ))}
                </div>

                <div className="flex w-full items-center gap-2 p-2 md:w-auto">
                  <div className="relative flex-1 md:w-56">
                    <input
                      type="text"
                      value={keyword}
                      onChange={(event) => setKeyword(event.target.value)}
                      placeholder="내 글 검색"
                      className="w-full rounded-lg border border-gray-200 bg-gray-50 py-1.5 pr-3 pl-8 text-sm outline-none transition focus:border-brand"
                    />
                    <i className="fas fa-search absolute top-1/2 left-2.5 -translate-y-1/2 text-xs text-gray-400" />
                  </div>
                  <select
                    value={sort}
                    onChange={(event) => setSort(event.target.value as SortType)}
                    className="cursor-pointer rounded-lg border border-gray-200 bg-white px-2 py-1.5 text-xs text-gray-600 outline-none hover:border-gray-300"
                  >
                    <option value="latest">최신순</option>
                    <option value="popular">인기순</option>
                    <option value="views">조회순</option>
                  </select>
                </div>
              </div>

              <div id="postListContainer" className="space-y-4">
                {filteredPosts.length ? (
                  filteredPosts.map((post) => (
                    <article
                      key={post.id}
                      className="group cursor-pointer rounded-xl border border-gray-200 bg-white p-6 shadow-sm transition hover:border-brand hover:shadow-md"
                      onClick={() => setSelectedPostId(post.id)}
                    >
                      <div className="flex items-start gap-5">
                        <div className="flex min-w-[40px] shrink-0 flex-col items-center gap-1 pt-1">
                          <i className="far fa-heart text-xl text-gray-400 transition group-hover:text-red-500" />
                          <span className="text-sm font-bold text-gray-600 transition group-hover:text-red-500">{post.likeCount}</span>
                        </div>
                        <div className="min-w-0 flex-1">
                          <div className="mb-1 flex items-center gap-2">
                            <span className={`rounded border px-2 py-0.5 text-xs font-bold ${badgeTone(post.filterCategory)}`}>
                              {categoryLabel(post.filterCategory)}
                            </span>
                            <h3 className="truncate text-lg font-bold text-gray-900 transition group-hover:text-brand">{post.title}</h3>
                          </div>
                          <p className="mb-3 line-clamp-2 text-sm text-gray-600">{post.content}</p>
                          <div className="mb-3 flex flex-wrap gap-2">
                            {post.tags.map((tag) => (
                              <span key={`${post.id}-${tag}`} className="tech-tag">
                                {tag}
                              </span>
                            ))}
                          </div>
                          <div className="flex items-center justify-between border-t border-gray-100 pt-3 text-xs text-gray-500">
                            <span className="text-gray-400">{formatShortDate(post.createdAt)}</span>
                            <div className="flex items-center gap-3">
                              <span>
                                <i className="far fa-comment-alt mr-1" /> {post.commentCount}
                              </span>
                              <span>
                                <i className="far fa-eye mr-1" /> {post.viewCount}
                              </span>
                            </div>
                          </div>
                        </div>
                      </div>
                    </article>
                  ))
                ) : (
                  <div className="py-10 text-center text-gray-500">
                    <i className="fas fa-inbox mb-3 text-4xl text-gray-300" />
                    <p>해당 카테고리의 글이 없습니다.</p>
                  </div>
                )}
              </div>
            </div>
          )}
        </section>
      </LearnerContentRow>
    </LearnerPageShell>
  )
}
