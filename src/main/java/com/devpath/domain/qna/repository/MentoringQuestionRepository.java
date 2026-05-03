package com.devpath.domain.qna.repository;

import com.devpath.domain.qna.entity.MentoringQuestion;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MentoringQuestionRepository extends JpaRepository<MentoringQuestion, Long> {

  // 특정 멘토링의 질문 목록을 최신순으로 조회한다.
  @EntityGraph(attributePaths = {"mentoring", "mentoring.mentor", "mentoring.mentee", "writer"})
  List<MentoringQuestion> findAllByMentoring_IdAndIsDeletedFalseOrderByCreatedAtDesc(
      Long mentoringId);

  // 멘토링 질문 단건 조회에서 참여자와 작성자를 함께 로딩한다.
  @EntityGraph(attributePaths = {"mentoring", "mentoring.mentor", "mentoring.mentee", "writer"})
  Optional<MentoringQuestion> findByIdAndIsDeletedFalse(Long id);

  // 멘토링 대시보드 질문 개수 집계에 사용한다.
  long countByMentoring_IdAndIsDeletedFalse(Long mentoringId);
}
