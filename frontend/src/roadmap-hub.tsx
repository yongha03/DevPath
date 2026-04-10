import './roadmap-hub.css'
import RoadmapHubApp from './RoadmapHubApp'
import { renderPage } from './render-page'

renderPage(<RoadmapHubApp />, { missingRootMessage: 'roadmap-hub root element was not found' })
