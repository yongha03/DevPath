export type CourseDifficulty = 'BEGINNER' | 'INTERMEDIATE' | 'ADVANCED' | null

export type CourseStatus = 'DRAFT' | 'PUBLISHED' | 'ARCHIVED' | string | null

export interface CourseListItem {
  courseId: number
  title: string
  thumbnailUrl: string | null
  instructorName: string
  instructorChannelName: string | null
  price: number | null
  discountPrice: number | null
  difficulty: CourseDifficulty
  tags: string[]
  isBookmarked: boolean | null
  isEnrolled: boolean | null
  status: CourseStatus
}

export interface CourseWishlistMutationResponse {
  message: string
  courseId: number
}

export interface CourseEnrollResponse {
  enrollmentId: number
  courseId: number
  courseTitle: string
  status: string
  enrolledAt: string | null
}

export interface CourseReviewOfficialReply {
  id: number
  instructorId: number
  content: string
  createdAt: string | null
  updatedAt: string | null
}

export interface CourseReview {
  id: number
  courseId: number
  learnerId: number
  rating: number
  content: string
  status: string
  isHidden: boolean | null
  issueTags: string[]
  officialReply: CourseReviewOfficialReply | null
  createdAt: string | null
  updatedAt: string | null
}
