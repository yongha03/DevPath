import type { InstructorCourseListItem } from '../types/instructor'

export const DEFAULT_INSTRUCTOR_COURSE_THUMBNAIL =
  'https://images.unsplash.com/photo-1517694712202-14dd9538aa97?auto=format&fit=crop&w=1200&q=80'

const COURSE_TITLE_LABELS: Record<string, string> = {
  'Spring Boot Intro': '자바(Java) 마스터 클래스: 입문부터 실무까지',
  'JPA Practical Design': 'JPA 실전 설계',
  'React Dashboard Sprint': '리액트 대시보드 스프린트',
}

const COURSE_THUMBNAIL_FALLBACKS: Record<string, string> = {
  'Spring Boot Intro':
    'https://images.unsplash.com/photo-1517694712202-14dd9538aa97?auto=format&fit=crop&w=1200&q=80',
  'JPA Practical Design':
    'https://images.unsplash.com/photo-1555066931-4365d14bab8c?auto=format&fit=crop&w=1200&q=80',
  'React Dashboard Sprint':
    'https://images.unsplash.com/photo-1460925895917-afdab827c52f?auto=format&fit=crop&w=1200&q=80',
  '스프링 부트 3.0 완전 정복':
    'https://images.unsplash.com/photo-1516321318423-f06f85e504b3?auto=format&fit=crop&w=1200&q=80',
  '[A-CASE-A] Node Clearance Course':
    'https://images.unsplash.com/photo-1498050108023-c5249f4df085?auto=format&fit=crop&w=1200&q=80',
  '[A-CASE-B] Tag Missing Course':
    'https://images.unsplash.com/photo-1504639725590-34d0984388bd?auto=format&fit=crop&w=1200&q=80',
  '[A-CASE-C] Quiz Fail Course':
    'https://images.unsplash.com/photo-1515879218367-8466d910aaa4?auto=format&fit=crop&w=1200&q=80',
}

const BACKEND_CATEGORY_SET = new Set(['Spring Boot', 'Java', 'JPA', 'Spring Security', 'JWT'])
const FRONTEND_CATEGORY_SET = new Set(['React', 'TypeScript', 'Chart.js', 'Frontend'])

export function normalizeInstructorCourseTitle(title: string | null | undefined) {
  if (!title) {
    return ''
  }

  return COURSE_TITLE_LABELS[title] ?? title
}

export function normalizeInstructorCourseStatus(status: string | null | undefined) {
  switch (status) {
    case 'PUBLISHED':
      return 'published'
    case 'IN_REVIEW':
      return 'review'
    case 'DRAFT':
    default:
      return 'draft'
  }
}

export function normalizeInstructorLevelLabel(value: string | null | undefined) {
  switch (value) {
    case 'BEGINNER':
      return '입문'
    case 'INTERMEDIATE':
      return '중급'
    case 'ADVANCED':
      return '고급'
    case '-':
    case null:
    case undefined:
      return '미정'
    default:
      return value
  }
}

export function normalizeInstructorCategoryLabel(
  value: string | null | undefined,
  courseTitle?: string | null,
) {
  const normalizedTitle = normalizeInstructorCourseTitle(courseTitle)

  if (normalizedTitle.includes('리액트')) {
    return '프론트엔드'
  }

  if (normalizedTitle.includes('자바') || normalizedTitle.includes('JPA') || normalizedTitle.includes('스프링')) {
    return '백엔드'
  }

  if (!value || value === 'General') {
    return '일반'
  }

  if (BACKEND_CATEGORY_SET.has(value)) {
    return '백엔드'
  }

  if (FRONTEND_CATEGORY_SET.has(value)) {
    return '프론트엔드'
  }

  return value
}

export function getInstructorCategoryChipLabel(
  value: string | null | undefined,
  courseTitle?: string | null,
) {
  const normalizedCategory = normalizeInstructorCategoryLabel(value, courseTitle)

  if (normalizedCategory === '백엔드') {
    return 'BACKEND'
  }

  if (normalizedCategory === '프론트엔드') {
    return 'FRONTEND'
  }

  return normalizedCategory.toUpperCase()
}

export function resolveInstructorCourseThumbnailUrl(
  rawUrl: string | null | undefined,
  courseTitle: string | null | undefined,
) {
  const trimmed = rawUrl?.trim()

  if (trimmed && /^https?:\/\//i.test(trimmed)) {
    return trimmed
  }

  if (courseTitle && COURSE_THUMBNAIL_FALLBACKS[courseTitle]) {
    return COURSE_THUMBNAIL_FALLBACKS[courseTitle]
  }

  return DEFAULT_INSTRUCTOR_COURSE_THUMBNAIL
}

export function buildInstructorCourseOptions(
  courses: InstructorCourseListItem[],
  allowedStatuses: string[] = ['PUBLISHED'],
) {
  const statusSet = new Set(allowedStatuses)
  const options = new Map<string, string>()

  courses.forEach((course) => {
    if (
      course.courseId === null ||
      course.courseId === undefined ||
      (statusSet.size > 0 && !statusSet.has(course.status ?? ''))
    ) {
      return
    }

    options.set(String(course.courseId), normalizeInstructorCourseTitle(course.title))
  })

  return Array.from(options.entries())
}
