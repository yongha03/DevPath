package com.devpath.api.admin.dto.governance;

import com.devpath.domain.roadmap.entity.RoadmapNodeResource;
import java.time.LocalDateTime;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class AdminRoadmapNodeResourceResponse {

  private Long resourceId;
  private Long nodeId;
  private String nodeTitle;
  private Long roadmapId;
  private String roadmapTitle;
  private String title;
  private String url;
  private String description;
  private String sourceType;
  private Integer sortOrder;
  private Boolean active;
  private LocalDateTime createdAt;
  private LocalDateTime updatedAt;

  public static AdminRoadmapNodeResourceResponse from(RoadmapNodeResource resource) {
    return AdminRoadmapNodeResourceResponse.builder()
        .resourceId(resource.getResourceId())
        .nodeId(resource.getNode().getNodeId())
        .nodeTitle(resource.getNode().getTitle())
        .roadmapId(resource.getNode().getRoadmap().getRoadmapId())
        .roadmapTitle(resource.getNode().getRoadmap().getTitle())
        .title(resource.getTitle())
        .url(resource.getUrl())
        .description(resource.getDescription())
        .sourceType(resource.getSourceType())
        .sortOrder(resource.getSortOrder())
        .active(resource.getActive())
        .createdAt(resource.getCreatedAt())
        .updatedAt(resource.getUpdatedAt())
        .build();
  }
}
