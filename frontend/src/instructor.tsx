import InstructorApp from './InstructorApp'
import { renderPage } from './render-page'

renderPage(<InstructorApp />, { missingRootMessage: 'instructor root element was not found' })
