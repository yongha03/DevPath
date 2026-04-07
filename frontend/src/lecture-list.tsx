import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import LectureListApp from './LectureListApp'

const rootElement = document.getElementById('root')

if (!rootElement) {
  throw new Error('lecture-list root element was not found')
}

createRoot(rootElement).render(
  <StrictMode>
    <LectureListApp />
  </StrictMode>,
)
