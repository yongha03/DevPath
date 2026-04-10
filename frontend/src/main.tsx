import App from './App.tsx'
import { renderPage } from './render-page'

renderPage(<App />, { missingRootMessage: 'home root element was not found' })
