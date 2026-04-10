import InstructorCourseDetailApp from './InstructorCourseDetailApp'
import { renderPage } from './render-page'

renderPage(<InstructorCourseDetailApp />, {
  missingRootMessage: 'instructor-course-detail root element was not found',
})
