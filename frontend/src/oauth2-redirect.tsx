import OAuthRedirectApp from './OAuthRedirectApp'
import { renderPage } from './render-page'

renderPage(<OAuthRedirectApp />, { missingRootMessage: 'oauth2-redirect root element was not found' })
