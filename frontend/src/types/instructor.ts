export interface InstructorPublicProfile {
  instructorId: number
  nickname: string
  profileImageUrl: string | null
  headline: string | null
  isPublic: boolean | null
}

export interface InstructorChannelExternalLinks {
  githubUrl: string | null
  blogUrl: string | null
}

export interface InstructorFeaturedCourse {
  courseId: number
  title: string
  subtitle: string | null
  thumbnailUrl: string | null
}

export interface InstructorChannel {
  profile: InstructorPublicProfile
  intro: string | null
  specialties: string[]
  externalLinks: InstructorChannelExternalLinks | null
  featuredCourses: InstructorFeaturedCourse[]
}

export interface InstructorSubscriptionResponse {
  subscriptionId: number
  channelId: number
  learnerId: number
  notificationEnabled: boolean
  subscribedAt: string | null
}
