import LearningPlayerMock from './LearningPlayerMock'
import { renderPage } from './render-page'

renderPage(<LearningPlayerMock />, { missingRootMessage: 'learning-mock root element was not found' })