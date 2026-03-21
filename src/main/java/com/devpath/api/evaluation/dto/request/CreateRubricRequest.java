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
@Schema(description = "강사용 루브릭 생성 요청 DTO")
public class CreateRubricRequest {

  // Evaluation Swagger 문서화 기준에 맞춘 루브릭 생성 요청 DTO다.
  @NotBlank
  @Schema(description = "루브릭 기준명", example = "JWT 필터 구현")
  private String criteriaName;

  @Schema(
      description = "루브릭 기준 설명",
      example = "OncePerRequestFilter를 사용해 Access Token을 검증했는지 평가합니다.")
  private String criteriaDescription;

  @NotNull
  @Min(0)
  @Schema(description = "해당 기준의 최대 점수", example = "30")
  private Integer maxPoints;

  @NotNull
  @Min(0)
  @Schema(description = "루브릭 노출 순서", example = "1")
  private Integer displayOrder;

  @Builder
  public CreateRubricRequest(
      String criteriaName, String criteriaDescription, Integer maxPoints, Integer displayOrder) {
    this.criteriaName = criteriaName;
    this.criteriaDescription = criteriaDescription;
    this.maxPoints = maxPoints;
    this.displayOrder = displayOrder;
  }
}
