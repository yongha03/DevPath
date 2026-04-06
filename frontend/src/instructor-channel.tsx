import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import InstructorChannelApp from './InstructorChannelApp'

const rootElement = document.getElementById('root')

if (!rootElement) {
  throw new Error('instructor-channel root element was not found')
}

createRoot(rootElement).render(
  <StrictMode>
    <InstructorChannelApp />
  </StrictMode>,
)
