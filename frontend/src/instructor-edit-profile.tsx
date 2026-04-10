import InstructorEditProfileApp from './InstructorEditProfileApp'
import { renderPage } from './render-page'

renderPage(<InstructorEditProfileApp />, {
  missingRootMessage: 'instructor-edit-profile root element was not found',
})
