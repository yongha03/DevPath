import './roadmap.css'
import RoadmapApp from './RoadmapApp'
import { renderPage } from './render-page'

renderPage(<RoadmapApp />, { missingRootMessage: 'roadmap root element was not found' })
