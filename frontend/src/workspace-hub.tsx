import WorkspaceHubApp from './WorkspaceHubApp'
import { renderPage } from './render-page'

renderPage(<WorkspaceHubApp />, { missingRootMessage: 'workspace-hub root element was not found' })
