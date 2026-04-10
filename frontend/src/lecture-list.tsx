import LectureListApp from './LectureListApp'
import { renderPage } from './render-page'

renderPage(<LectureListApp />, { missingRootMessage: 'lecture-list root element was not found' })
