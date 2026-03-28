package com.devpath.domain.study.repository;

import com.devpath.domain.study.entity.StudyMatch;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface StudyMatchRepository extends JpaRepository<StudyMatch, Long> {
    // 내가 요청했거나, 요청받은 모든 매칭 내역 조회
    @Query("SELECT sm FROM StudyMatch sm WHERE sm.requesterId = :learnerId OR sm.receiverId = :learnerId")
    List<StudyMatch> findMyMatches(@Param("learnerId") Long learnerId);
}