import ContentAssignmentEditorApp from './ContentAssignmentEditorApp'
import { renderPage } from './render-page'

renderPage(<ContentAssignmentEditorApp />, {
  missingRootMessage: 'content-assignment-editor root element was not found',
})
