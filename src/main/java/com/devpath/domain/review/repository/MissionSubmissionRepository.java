package com.devpath.domain.review.repository;

import com.devpath.domain.review.entity.MissionSubmission;
import java.util.Optional;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MissionSubmissionRepository extends JpaRepository<MissionSubmission, Long> {

  // 같은 멘티가 같은 미션에 중복 제출하는 것을 방지한다.
  boolean existsByMission_IdAndSubmitter_IdAndIsDeletedFalse(Long missionId, Long submitterId);

  // Pass/Reject 판정 시 미션, 멘토링, 제출자 정보를 함께 사용한다.
  @EntityGraph(
      attributePaths = {
        "mission",
        "mission.mentoring",
        "mission.mentoring.post",
        "mission.mentoring.mentor",
        "mission.mentoring.mentee",
        "submitter"
      })
  Optional<MissionSubmission> findByIdAndIsDeletedFalse(Long id);
}
