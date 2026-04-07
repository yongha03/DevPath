import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import CourseEditorApp from './CourseEditorApp'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <CourseEditorApp />
  </StrictMode>,
)
