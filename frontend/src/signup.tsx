import SignupApp from './SignupApp'
import { renderPage } from './render-page'

renderPage(<SignupApp />, { missingRootMessage: 'signup root element was not found' })
