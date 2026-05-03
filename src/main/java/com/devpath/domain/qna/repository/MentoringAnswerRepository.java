package com.devpath.domain.qna.repository;

import com.devpath.domain.qna.entity.MentoringAnswer;
import java.util.List;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MentoringAnswerRepository extends JpaRepository<MentoringAnswer, Long> {

  // 특정 멘토링 질문의 답변 목록을 작성 시간순으로 조회한다.
  @EntityGraph(attributePaths = {"question", "writer"})
  List<MentoringAnswer> findAllByQuestion_IdAndIsDeletedFalseOrderByCreatedAtAsc(Long questionId);
}
