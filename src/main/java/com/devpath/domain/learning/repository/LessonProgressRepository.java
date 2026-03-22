package com.devpath.domain.learning.repository;

import com.devpath.domain.learning.entity.LessonProgress;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface LessonProgressRepository extends JpaRepository<LessonProgress, Long> {

    Optional<LessonProgress> findByUserIdAndLessonLessonId(Long userId, Long lessonId);

    List<LessonProgress> findAllByUserId(Long userId);

    boolean existsByUserIdAndLessonLessonIdAndIsCompletedTrue(Long userId, Long lessonId);
}
