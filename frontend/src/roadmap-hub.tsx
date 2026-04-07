import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import './roadmap-hub.css'
import RoadmapHubApp from './RoadmapHubApp'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <RoadmapHubApp />
  </StrictMode>,
)
