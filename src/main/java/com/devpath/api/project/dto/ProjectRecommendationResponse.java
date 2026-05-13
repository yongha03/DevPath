package com.devpath.api.project.dto;

import com.devpath.domain.project.entity.Project;
import java.util.List;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class ProjectRecommendationResponse {

  private Long projectId;
  private String name;
  private String description;
  private String projectType;
  private String recruitingStatus;
  private int recommendationScore;
  private List<String> matchedSkillTags;
  private String reason;

  public static ProjectRecommendationResponse from(
      Project project, int recommendationScore, List<String> matchedSkillTags) {
    return ProjectRecommendationResponse.builder()
        .projectId(project.getId())
        .name(project.getName())
        .description(project.getDescription())
        .projectType(project.getProjectType().name())
        .recruitingStatus(project.getRecruitingStatus().name())
        .recommendationScore(recommendationScore)
        .matchedSkillTags(matchedSkillTags)
        .reason(buildReason(matchedSkillTags))
        .build();
  }

  private static String buildReason(List<String> matchedSkillTags) {
    if (matchedSkillTags.isEmpty()) {
      return "학습 기술 스택과 직접 일치하는 항목이 없습니다.";
    }

    return String.join(", ", matchedSkillTags) + " 기술 스택과 일치합니다.";
  }
}
