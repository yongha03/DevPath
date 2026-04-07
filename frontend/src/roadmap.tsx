import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import './roadmap.css'
import RoadmapApp from './RoadmapApp'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <RoadmapApp />
  </StrictMode>,
)
