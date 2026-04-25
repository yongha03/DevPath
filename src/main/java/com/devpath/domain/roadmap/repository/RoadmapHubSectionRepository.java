package com.devpath.domain.roadmap.repository;

import com.devpath.domain.roadmap.entity.RoadmapHubSection;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoadmapHubSectionRepository extends JpaRepository<RoadmapHubSection, Long> {

  // 허브 섹션을 노출 순서대로 읽어 온다.
  List<RoadmapHubSection> findAllByOrderBySortOrderAscIdAsc();
}
