import InstructorStandaloneAccess from './instructor/InstructorStandaloneAccess'
import QuizCreatorPage from './instructor/pages/QuizCreatorPage'

export default function QuizCreatorApp() {
  return (
    <InstructorStandaloneAccess title="DevPath - 퀴즈 생성기">
      <QuizCreatorPage />
    </InstructorStandaloneAccess>
  )
}
