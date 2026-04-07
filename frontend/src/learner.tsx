import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import LearnerApp from './LearnerApp'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <LearnerApp />
  </StrictMode>,
)
