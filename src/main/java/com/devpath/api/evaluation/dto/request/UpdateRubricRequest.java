package com.devpath.api.evaluation.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Schema(description = "강사용 루브릭 수정 요청 DTO")
public class UpdateRubricRequest {

  // Evaluation Swagger 문서화 기준에 맞춘 루브릭 수정 요청 DTO다.
  @NotBlank
  @Schema(description = "수정할 루브릭 기준명", example = "JWT 필터 구현")
  private String criteriaName;

  @Schema(
      description = "수정할 루브릭 기준 설명",
      example = "OncePerRequestFilter를 이용해 JWT 검증을 올바르게 수행했는지 평가합니다.")
  private String criteriaDescription;

  @NotNull
  @Min(0)
  @Schema(description = "수정할 최대 점수", example = "40")
  private Integer maxPoints;

  @NotNull
  @Min(0)
  @Schema(description = "수정할 루브릭 노출 순서", example = "1")
  private Integer displayOrder;

  @Builder
  public UpdateRubricRequest(
      String criteriaName, String criteriaDescription, Integer maxPoints, Integer displayOrder) {
    this.criteriaName = criteriaName;
    this.criteriaDescription = criteriaDescription;
    this.maxPoints = maxPoints;
    this.displayOrder = displayOrder;
  }
}
