import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import ContentAssignmentEditorApp from './ContentAssignmentEditorApp'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ContentAssignmentEditorApp />
  </StrictMode>,
)
