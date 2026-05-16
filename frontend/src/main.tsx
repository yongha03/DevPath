import App from './App.tsx'
import JobMatchingApp from './JobMatchingApp'
import { renderPage } from './render-page'
import SquadDashboardApp from './SquadDashboardApp'

const pathname = window.location.pathname.replace(/\/+$/, '')

const page =
  pathname === '/job-matching'
    ? <JobMatchingApp />
    : pathname === '/squad-dashboard'
      ? <SquadDashboardApp />
      : <App />

renderPage(page, {
  missingRootMessage: 'home root element was not found',
})
