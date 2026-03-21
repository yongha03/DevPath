package com.devpath.api.evaluation.dto.response;

import com.devpath.domain.learning.entity.Rubric;
import io.swagger.v3.oas.annotations.media.Schema;
import java.time.LocalDateTime;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Schema(description = "강사용 루브릭 응답 DTO")
public class RubricResponse {

  // Evaluation Swagger 문서화 기준에 맞춘 루브릭 응답 DTO다.
  @Schema(description = "루브릭 ID", example = "301")
  private Long rubricId;

  @Schema(description = "연결된 과제 ID", example = "20")
  private Long assignmentId;

  @Schema(description = "루브릭 기준명", example = "JWT 필터 구현")
  private String criteriaName;

  @Schema(
      description = "루브릭 기준 설명",
      example = "OncePerRequestFilter를 사용해 Access Token을 검증했는지 평가합니다.")
  private String criteriaDescription;

  @Schema(description = "최대 점수", example = "30")
  private Integer maxPoints;

  @Schema(description = "루브릭 노출 순서", example = "1")
  private Integer displayOrder;

  @Schema(description = "루브릭 생성 시각", example = "2026-03-20T12:10:00")
  private LocalDateTime createdAt;

  @Builder
  public RubricResponse(
      Long rubricId,
      Long assignmentId,
      String criteriaName,
      String criteriaDescription,
      Integer maxPoints,
      Integer displayOrder,
      LocalDateTime createdAt) {
    this.rubricId = rubricId;
    this.assignmentId = assignmentId;
    this.criteriaName = criteriaName;
    this.criteriaDescription = criteriaDescription;
    this.maxPoints = maxPoints;
    this.displayOrder = displayOrder;
    this.createdAt = createdAt;
  }

  public static RubricResponse from(Rubric rubric) {
    return RubricResponse.builder()
        .rubricId(rubric.getId())
        .assignmentId(rubric.getAssignment().getId())
        .criteriaName(rubric.getCriteriaName())
        .criteriaDescription(rubric.getCriteriaDescription())
        .maxPoints(rubric.getMaxPoints())
        .displayOrder(rubric.getDisplayOrder())
        .createdAt(rubric.getCreatedAt())
        .build();
  }
}
