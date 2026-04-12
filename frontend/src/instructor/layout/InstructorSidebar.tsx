import { useEffect, useState } from 'react'
import { buildInstructorCourseOptions } from '../../instructor/course-display'
import { instructorCourseApi, instructorQnaApi } from '../../lib/api'
import { instructorNavItems, type InstructorPageKey } from '../navigation'

const sections: Array<InstructorNavItemSection> = ['개요', '소통', '관리']

type InstructorNavItemSection = '개요' | '소통' | '관리'

export default function InstructorSidebar({
  currentPageKey,
}: {
  currentPageKey: InstructorPageKey
}) {
  const [unansweredCount, setUnansweredCount] = useState<number | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    Promise.all([
      instructorQnaApi.getInbox('UNANSWERED', controller.signal),
      instructorCourseApi.getCourses(controller.signal),
    ])
      .then(([items, courses]) => {
        const publishedCourseIds = new Set(
          buildInstructorCourseOptions(courses).map(([id]) => Number(id)),
        )
        const count = items.filter(
          (item) => item.courseId !== null && publishedCourseIds.has(item.courseId),
        ).length
        setUnansweredCount(count)
      })
      .catch(() => {})
    return () => controller.abort()
  }, [])

  return (
    <aside className="hidden h-[calc(100vh-64px)] w-64 shrink-0 border-r border-gray-200 bg-white lg:flex lg:flex-col">
      <div className="pt-4" />
      <nav className="hide-scroll flex-1 space-y-1 overflow-y-auto px-4 py-6">
        {sections.map((section) => (
          <div key={section}>
            <p className="mb-2 px-2 text-[10px] font-extrabold tracking-[0.18em] text-gray-400 uppercase">
              {section}
            </p>
            <div className="space-y-1">
              {instructorNavItems
                .filter((item) => item.section === section)
                .map((item) => {
                  const active = item.key === currentPageKey
                  const badge = item.key === 'qna' && unansweredCount != null && unansweredCount > 0
                    ? String(unansweredCount)
                    : null

                  return (
                    <a
                      key={item.key}
                      href={item.href}
                      className={`instructor-nav-item ${active ? 'active' : ''} ${
                        badge ? 'justify-between' : ''
                      }`}
                    >
                      <span className="flex items-center gap-3">
                        <i className={`${item.icon} w-5 text-center`} />
                        <span>{item.label}</span>
                      </span>
                      {badge ? (
                        <span className="rounded-full bg-red-500 px-1.5 py-0.5 text-[10px] font-bold text-white">
                          {badge}
                        </span>
                      ) : null}
                    </a>
                  )
                })}
            </div>
          </div>
        ))}
      </nav>
    </aside>
  )
}
