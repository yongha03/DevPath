package com.devpath.domain.qna.repository;

import com.devpath.domain.qna.entity.WorkspaceQuestion;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

public interface WorkspaceQuestionRepository extends JpaRepository<WorkspaceQuestion, Long> {

  // 특정 워크스페이스의 질문 목록을 최신순으로 조회한다.
  @EntityGraph(attributePaths = "writer")
  List<WorkspaceQuestion> findAllByWorkspaceIdAndIsDeletedFalseOrderByCreatedAtDesc(
      Long workspaceId);

  // 워크스페이스 질문 단건 조회에서 작성자 정보를 함께 로딩한다.
  @EntityGraph(attributePaths = "writer")
  Optional<WorkspaceQuestion> findByIdAndIsDeletedFalse(Long id);
}
