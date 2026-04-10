import './survey.css'
import SurveyApp from './SurveyApp'
import { renderPage } from './render-page'

renderPage(<SurveyApp />, { missingRootMessage: 'survey root element was not found' })
