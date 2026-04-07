import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import InstructorApp from './InstructorApp'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <InstructorApp />
  </StrictMode>,
)
