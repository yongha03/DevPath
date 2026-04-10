import CourseDetailApp from './CourseDetailApp'
import { renderPage } from './render-page'

renderPage(<CourseDetailApp />, { missingRootMessage: 'course-detail root element was not found' })
