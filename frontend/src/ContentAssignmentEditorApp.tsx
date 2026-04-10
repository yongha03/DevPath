import InstructorStandaloneAccess from './instructor/InstructorStandaloneAccess'
import ContentAssignmentEditorPage from './instructor/pages/ContentAssignmentEditorPage'

export default function ContentAssignmentEditorApp() {
  return (
    <InstructorStandaloneAccess title="DevPath - 과제 생성 및 자동 채점 설정">
      <ContentAssignmentEditorPage />
    </InstructorStandaloneAccess>
  )
}
