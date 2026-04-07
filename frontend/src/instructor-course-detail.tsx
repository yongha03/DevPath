import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import InstructorCourseDetailApp from './InstructorCourseDetailApp'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <InstructorCourseDetailApp />
  </StrictMode>,
)
