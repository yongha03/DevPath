import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import QuizCreatorApp from './QuizCreatorApp'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QuizCreatorApp />
  </StrictMode>,
)
