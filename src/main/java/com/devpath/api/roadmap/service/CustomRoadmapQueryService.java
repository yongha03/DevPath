package com.devpath.api.roadmap.service;

import com.devpath.api.roadmap.dto.MyRoadmapDto;
import com.devpath.common.exception.CustomException;
import com.devpath.common.exception.ErrorCode;
import com.devpath.domain.learning.entity.clearance.NodeClearance;
import com.devpath.domain.learning.repository.clearance.NodeClearanceRepository;
import com.devpath.domain.roadmap.entity.CustomRoadmap;
import com.devpath.domain.roadmap.entity.CustomRoadmapNode;
import com.devpath.domain.roadmap.entity.NodeStatus;
import com.devpath.domain.roadmap.entity.RoadmapNodeResource;
import com.devpath.domain.roadmap.repository.CustomNodePrerequisiteRepository;
import com.devpath.domain.roadmap.repository.CustomRoadmapNodeRepository;
import com.devpath.domain.roadmap.repository.CustomRoadmapRepository;
import com.devpath.domain.roadmap.repository.NodeRequiredTagRepository;
import com.devpath.domain.roadmap.repository.RoadmapNodeResourceRepository;
import com.devpath.domain.user.entity.User;
import com.devpath.domain.user.repository.UserRepository;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class CustomRoadmapQueryService {

  private final UserRepository userRepository;
  private final CustomRoadmapRepository customRoadmapRepository;
  private final CustomRoadmapNodeRepository customRoadmapNodeRepository;
  private final CustomNodePrerequisiteRepository customNodePrerequisiteRepository;
  private final NodeClearanceRepository nodeClearanceRepository;
  private final RoadmapNodeResourceRepository roadmapNodeResourceRepository;
  private final NodeRequiredTagRepository nodeRequiredTagRepository;
  private final RoadmapProgressService roadmapProgressService;

  @Transactional(readOnly = true)
  public List<CustomRoadmap> getMyRoadmaps(Long userId) {
    User user =
        userRepository
            .findById(userId)
            .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));
    return customRoadmapRepository.findAllByUserOrderByCreatedAtDesc(user);
  }

  @Transactional(readOnly = true)
  public MyRoadmapDto.DetailResponse getMyRoadmap(Long userId, Long customRoadmapId) {
    CustomRoadmap customRoadmap = getOwnedRoadmap(userId, customRoadmapId);
    List<CustomRoadmapNode> customNodes =
        customRoadmapNodeRepository.findAllByCustomRoadmapOrderByCustomSortOrderAsc(
            customRoadmap);
    Map<Long, List<Long>> prerequisiteIdsByNodeId =
        customNodePrerequisiteRepository.findAllByCustomRoadmap(customRoadmap).stream()
            .collect(
                Collectors.groupingBy(
                    prerequisite -> prerequisite.getCustomNode().getId(),
                    Collectors.mapping(
                        prerequisite -> prerequisite.getPrerequisiteCustomNode().getId(),
                        Collectors.toList())));

    Map<Long, NodeStatus> statusByNodeId = customNodes.stream()
        .collect(Collectors.toMap(CustomRoadmapNode::getId, CustomRoadmapNode::getStatus));

    Map<Long, NodeClearance> clearanceByNodeId =
        customRoadmap.getOriginalRoadmap() != null
            ? nodeClearanceRepository.findAllByUserIdAndNodeRoadmapRoadmapIdOrderByNodeSortOrderAscNodeNodeIdAsc(
                    userId, customRoadmap.getOriginalRoadmap().getRoadmapId())
                .stream()
                .collect(Collectors.toMap(c -> c.getNode().getNodeId(), c -> c))
            : Map.of();

    List<Long> originalNodeIds =
        customNodes.stream()
            .filter(node -> node.getOriginalNode() != null)
            .map(node -> node.getOriginalNode().getNodeId())
            .toList();
    Map<Long, List<RoadmapNodeResource>> resourcesByNodeId =
        originalNodeIds.isEmpty()
            ? Map.of()
            : roadmapNodeResourceRepository.findActiveByNodeIds(originalNodeIds).stream()
                .collect(Collectors.groupingBy(resource -> resource.getNode().getNodeId()));

    Map<Long, List<String>> requiredTagsByNodeId =
        originalNodeIds.isEmpty()
            ? Map.of()
            : nodeRequiredTagRepository.findTagNamesByNodeIds(originalNodeIds).stream()
                .collect(Collectors.groupingBy(
                    p -> p.getNodeId(),
                    Collectors.mapping(p -> p.getTagName(), Collectors.toList())));

    return MyRoadmapDto.DetailResponse.from(
        customRoadmap,
        roadmapProgressService.calculateProgressRate(customNodes),
        customNodes,
        prerequisiteIdsByNodeId,
        statusByNodeId,
        clearanceByNodeId,
        resourcesByNodeId,
        requiredTagsByNodeId);
  }

  @Transactional
  public void deleteMyRoadmap(Long userId, Long customRoadmapId) {
    CustomRoadmap roadmap = getOwnedRoadmap(userId, customRoadmapId);
    customNodePrerequisiteRepository.deleteAllByCustomRoadmap(roadmap);
    customRoadmapNodeRepository.deleteAllByCustomRoadmap(roadmap);
    customRoadmapRepository.delete(roadmap);
  }

  private CustomRoadmap getOwnedRoadmap(Long userId, Long customRoadmapId) {
    User user =
        userRepository
            .findById(userId)
            .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

    CustomRoadmap roadmap =
        customRoadmapRepository
            .findById(customRoadmapId)
            .orElseThrow(() -> new CustomException(ErrorCode.CUSTOM_ROADMAP_NOT_FOUND));

    if (!roadmap.getUser().getId().equals(user.getId())) {
      throw new CustomException(ErrorCode.FORBIDDEN);
    }

    return roadmap;
  }
}
