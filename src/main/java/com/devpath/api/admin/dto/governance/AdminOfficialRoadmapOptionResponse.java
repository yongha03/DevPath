package com.devpath.api.admin.dto.governance;

import com.devpath.domain.roadmap.entity.Roadmap;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
// 관리자 노드 생성 화면에서 선택할 공식 로드맵 정보다.
public class AdminOfficialRoadmapOptionResponse {

  private Long roadmapId;
  private String title;

  public static AdminOfficialRoadmapOptionResponse from(Roadmap roadmap) {
    return AdminOfficialRoadmapOptionResponse.builder()
        .roadmapId(roadmap.getRoadmapId())
        .title(roadmap.getTitle())
        .build();
  }
}
