package com.devpath.api.roadmap.service;

import com.devpath.domain.roadmap.entity.CustomRoadmap;
import com.devpath.domain.roadmap.entity.CustomRoadmapNode;
import com.devpath.domain.roadmap.entity.NodeStatus;
import java.util.Collection;
import org.springframework.stereotype.Component;

@Component
public class RoadmapProgressService {

  public int calculateProgressRate(Collection<CustomRoadmapNode> nodes) {
    if (nodes == null || nodes.isEmpty()) {
      return 0;
    }

    long completedCount =
        nodes.stream().filter(node -> node.getStatus() == NodeStatus.COMPLETED).count();
    return (int) (completedCount * 100 / nodes.size());
  }

  public int updateProgressRate(CustomRoadmap customRoadmap, Collection<CustomRoadmapNode> nodes) {
    int progressRate = calculateProgressRate(nodes);
    customRoadmap.updateProgressRate(progressRate);
    return progressRate;
  }

  public int updateProgressRate(CustomRoadmap customRoadmap, long total, long completed) {
    int progressRate = total == 0 ? 0 : (int) (completed * 100 / total);
    customRoadmap.updateProgressRate(progressRate);
    return progressRate;
  }
}
