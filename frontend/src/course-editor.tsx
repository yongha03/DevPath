import CourseEditorApp from './CourseEditorApp'
import { renderPage } from './render-page'

renderPage(<CourseEditorApp />, { missingRootMessage: 'course-editor root element was not found' })
