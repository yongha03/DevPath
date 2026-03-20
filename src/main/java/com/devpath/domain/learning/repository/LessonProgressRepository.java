package com.devpath.domain.learning.repository;

import com.devpath.domain.learning.entity.LessonProgress;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface LessonProgressRepository extends JpaRepository<LessonProgress, Long> {

    // 특정 학습자의 특정 레슨 진도율 조회 (이어보기 및 저장 시 활용)
    Optional<LessonProgress> findByUserIdAndLessonLessonId(Long userId, Long lessonId);

    // 특정 학습자가 해당 레슨을 완료했는지 여부 확인
    boolean existsByUserIdAndLessonLessonIdAndIsCompletedTrue(Long userId, Long lessonId);
}
