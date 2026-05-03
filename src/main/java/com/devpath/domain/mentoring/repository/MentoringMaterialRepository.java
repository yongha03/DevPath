package com.devpath.domain.mentoring.repository;

import com.devpath.domain.mentoring.entity.MentoringMaterial;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MentoringMaterialRepository extends JpaRepository<MentoringMaterial, Long> {

  // 특정 미션의 삭제되지 않은 자료를 정렬 순서대로 조회한다.
  @EntityGraph(
      attributePaths = {
        "mission",
        "mission.mentoring",
        "mission.mentoring.post",
        "mission.mentoring.mentor",
        "mission.mentoring.mentee"
      })
  List<MentoringMaterial> findAllByMission_IdAndIsDeletedFalseOrderBySortOrderAscCreatedAtAsc(
      Long missionId);

  // 자료 단건 조회에서 미션과 멘토링 정보를 함께 사용한다.
  @EntityGraph(
      attributePaths = {
        "mission",
        "mission.mentoring",
        "mission.mentoring.post",
        "mission.mentoring.mentor",
        "mission.mentoring.mentee"
      })
  Optional<MentoringMaterial> findByIdAndIsDeletedFalse(Long id);
}
