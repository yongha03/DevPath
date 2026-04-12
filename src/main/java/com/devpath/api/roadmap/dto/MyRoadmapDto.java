package com.devpath.api.roadmap.dto;

import com.devpath.domain.learning.entity.clearance.NodeClearance;
import com.devpath.domain.roadmap.entity.CustomRoadmap;
import com.devpath.domain.roadmap.entity.CustomRoadmapNode;
import com.devpath.domain.roadmap.entity.DisplayNodeStatus;
import com.devpath.domain.roadmap.entity.NodeStatus;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

public class MyRoadmapDto {

  @Getter
  @NoArgsConstructor(access = AccessLevel.PROTECTED)
  @Schema(name = "MyRoadmapListResponse")
  public static class ListResponse {

    @Schema(description = "내 커스텀 로드맵 목록")
    private List<Item> roadmaps;

    @Builder
    private ListResponse(List<Item> roadmaps) {
      this.roadmaps = roadmaps;
    }

    public static ListResponse from(List<CustomRoadmap> entities) {
      return ListResponse.builder().roadmaps(entities.stream().map(Item::from).toList()).build();
    }
  }

  @Getter
  @NoArgsConstructor(access = AccessLevel.PROTECTED)
  public static class Item {

    @Schema(example = "10")
    private Long customRoadmapId;

    @Schema(example = "1")
    private Long originalRoadmapId;

    @Schema(example = "Backend Master Roadmap")
    private String title;

    @Schema(description = "생성 시각")
    private LocalDateTime createdAt;

    @Builder
    private Item(
        Long customRoadmapId, Long originalRoadmapId, String title, LocalDateTime createdAt) {
      this.customRoadmapId = customRoadmapId;
      this.originalRoadmapId = originalRoadmapId;
      this.title = title;
      this.createdAt = createdAt;
    }

    public static Item from(CustomRoadmap entity) {
      return Item.builder()
          .customRoadmapId(entity.getId())
          .originalRoadmapId(entity.getOriginalRoadmap().getRoadmapId())
          .title(entity.getTitle())
          .createdAt(entity.getCreatedAt())
          .build();
    }
  }

  @Getter
  @NoArgsConstructor(access = AccessLevel.PROTECTED)
  @Schema(name = "MyRoadmapDetailResponse")
  public static class DetailResponse {

    @Schema(example = "10")
    private Long customRoadmapId;

    @Schema(example = "1")
    private Long originalRoadmapId;

    @Schema(example = "Backend Master Roadmap")
    private String title;

    @Schema(example = "0")
    private Integer progressRate;

    @Schema(description = "생성 시각")
    private LocalDateTime createdAt;

    @Schema(description = "내 로드맵 노드 목록")
    private List<NodeItem> nodes;

    @Builder
    private DetailResponse(
        Long customRoadmapId,
        Long originalRoadmapId,
        String title,
        Integer progressRate,
        LocalDateTime createdAt,
        List<NodeItem> nodes) {
      this.customRoadmapId = customRoadmapId;
      this.originalRoadmapId = originalRoadmapId;
      this.title = title;
      this.progressRate = progressRate;
      this.createdAt = createdAt;
      this.nodes = nodes;
    }

    public static DetailResponse from(
        CustomRoadmap customRoadmap,
        List<CustomRoadmapNode> nodes,
        Map<Long, List<Long>> prerequisiteIdsByNodeId,
        Map<Long, NodeStatus> statusByNodeId,
        Map<Long, NodeClearance> clearanceByNodeId) {
      return DetailResponse.builder()
          .customRoadmapId(customRoadmap.getId())
          .originalRoadmapId(customRoadmap.getOriginalRoadmap().getRoadmapId())
          .title(customRoadmap.getTitle())
          .progressRate(customRoadmap.getProgressRate())
          .createdAt(customRoadmap.getCreatedAt())
          .nodes(
              nodes.stream()
                  .map(
                      node ->
                          NodeItem.from(
                              node,
                              prerequisiteIdsByNodeId.getOrDefault(node.getId(), List.of()),
                              statusByNodeId,
                              clearanceByNodeId.get(node.getOriginalNode().getNodeId())))
                  .toList())
          .build();
    }
  }

  @Getter
  @NoArgsConstructor(access = AccessLevel.PROTECTED)
  public static class NodeItem {

    @Schema(example = "101")
    private Long customNodeId;

    @Schema(example = "11")
    private Long originalNodeId;

    @Schema(example = "Java Basics")
    private String title;

    @Schema(example = "1")
    private Integer sortOrder;

    @Schema(example = "COMPLETED", description = "PENDING / IN_PROGRESS / COMPLETED / LOCKED")
    private DisplayNodeStatus status;

    @Schema(description = "선행 커스텀 노드 ID 목록")
    private List<Long> prerequisiteCustomNodeIds;

    @Schema(description = "노드 설명")
    private String content;

    @Schema(description = "서브토픽 칩 목록")
    private List<String> subTopics;

    @Schema(description = "분기 그룹 (null=척추, 1=왼쪽, 2=오른쪽)")
    private Integer branchGroup;

    @Schema(description = "진단 퀴즈 추천 분기 노드 여부")
    @JsonProperty("isBranch")
    private boolean isBranch;

    @Schema(description = "분기 출발 원본 노드 ID (isBranch=true 일 때만 존재)")
    private Long branchFromNodeId;

    @Schema(description = "분기 종류: REVIEW(복습) | ADVANCED(심화) | null(일반)")
    private String branchType;

    @Schema(description = "레슨 진행률 (0.0~1.0), null이면 미시작")
    private Double lessonCompletionRate;

    @Schema(description = "필수 태그 충족 여부")
    private boolean requiredTagsSatisfied;

    @Builder
    private NodeItem(
        Long customNodeId,
        Long originalNodeId,
        String title,
        Integer sortOrder,
        DisplayNodeStatus status,
        List<Long> prerequisiteCustomNodeIds,
        String content,
        List<String> subTopics,
        Integer branchGroup,
        boolean isBranch,
        Long branchFromNodeId,
        String branchType,
        Double lessonCompletionRate,
        boolean requiredTagsSatisfied) {
      this.customNodeId = customNodeId;
      this.originalNodeId = originalNodeId;
      this.title = title;
      this.sortOrder = sortOrder;
      this.status = status;
      this.prerequisiteCustomNodeIds = prerequisiteCustomNodeIds;
      this.content = content;
      this.subTopics = subTopics;
      this.branchGroup = branchGroup;
      this.isBranch = isBranch;
      this.branchFromNodeId = branchFromNodeId;
      this.branchType = branchType;
      this.lessonCompletionRate = lessonCompletionRate;
      this.requiredTagsSatisfied = requiredTagsSatisfied;
    }

    public static NodeItem from(
        CustomRoadmapNode node,
        List<Long> prerequisiteCustomNodeIds,
        Map<Long, NodeStatus> statusByNodeId,
        NodeClearance clearance) {
      String raw = node.getOriginalNode().getSubTopics();
      List<String> chips = (raw != null && !raw.isBlank())
          ? Arrays.stream(raw.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList()
          : List.of();

      DisplayNodeStatus displayStatus;
      if (node.getStatus() == NodeStatus.COMPLETED) {
        displayStatus = DisplayNodeStatus.COMPLETED;
      } else if (node.getStatus() == NodeStatus.IN_PROGRESS) {
        displayStatus = DisplayNodeStatus.IN_PROGRESS;
      } else {
        boolean isLocked = !prerequisiteCustomNodeIds.isEmpty()
            && prerequisiteCustomNodeIds.stream().anyMatch(
                prereqId -> statusByNodeId.getOrDefault(prereqId, NodeStatus.NOT_STARTED)
                    != NodeStatus.COMPLETED);
        displayStatus = isLocked ? DisplayNodeStatus.LOCKED : DisplayNodeStatus.PENDING;
      }

      double lessonRate = clearance != null && clearance.getLessonCompletionRate() != null
          ? clearance.getLessonCompletionRate().doubleValue() : 0.0;
      boolean tagsSatisfied = clearance != null && Boolean.TRUE.equals(clearance.getRequiredTagsSatisfied());

      return NodeItem.builder()
          .customNodeId(node.getId())
          .originalNodeId(node.getOriginalNode().getNodeId())
          .title(node.getOriginalNode().getTitle())
          .sortOrder(node.getCustomSortOrder())
          .status(displayStatus)
          .prerequisiteCustomNodeIds(prerequisiteCustomNodeIds)
          .content(node.getOriginalNode().getContent())
          .subTopics(chips)
          .branchGroup(node.getOriginalNode().getBranchGroup())
          .isBranch(node.isBranch())
          .branchFromNodeId(node.getBranchFromNodeId())
          .branchType(node.getBranchType())
          .lessonCompletionRate(lessonRate)
          .requiredTagsSatisfied(tagsSatisfied)
          .build();
    }
  }
}
