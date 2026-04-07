import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import LearningPlayerApp from './LearningPlayerApp'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <LearningPlayerApp />
  </StrictMode>,
)
