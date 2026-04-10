import LoginApp from './LoginApp'
import { renderPage } from './render-page'

renderPage(<LoginApp />, { missingRootMessage: 'login root element was not found' })
