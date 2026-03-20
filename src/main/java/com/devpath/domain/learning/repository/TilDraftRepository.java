package com.devpath.domain.learning.repository;

import com.devpath.domain.learning.entity.TilDraft;
import com.devpath.domain.learning.entity.TilDraftStatus;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TilDraftRepository extends JpaRepository<TilDraft, Long> {

    // 특정 학습자의 TIL 목록을 최신순으로 조회한다.
    List<TilDraft> findByUserIdAndIsDeletedFalseOrderByCreatedAtDesc(Long userId);

    // 특정 학습자의 특정 레슨 기반 TIL 목록을 조회한다.
    List<TilDraft> findByUserIdAndLessonLessonIdAndIsDeletedFalse(Long userId, Long lessonId);

    // TIL ID와 학습자 ID로 단건 조회한다. (수정/삭제 시 소유권 확인용)
    Optional<TilDraft> findByIdAndUserIdAndIsDeletedFalse(Long tilId, Long userId);

    // 특정 학습자의 특정 상태 TIL 목록을 조회한다.
    List<TilDraft> findByUserIdAndStatusAndIsDeletedFalse(Long userId, TilDraftStatus status);
}
