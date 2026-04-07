import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import './survey.css'
import SurveyApp from './SurveyApp'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <SurveyApp />
  </StrictMode>,
)
