package com.devpath.api.evaluation.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Schema(description = "과제 precheck 결과 응답 DTO")
public class AssignmentPrecheckResponse {

  // Evaluation Swagger 문서화 기준에 맞춘 precheck 결과 응답 DTO다.
  @Schema(description = "전체 precheck 통과 여부", example = "true")
  private Boolean passed;

  @Schema(description = "README 요구사항 통과 여부", example = "true")
  private Boolean readmePassed;

  @Schema(description = "테스트 요구사항 통과 여부", example = "true")
  private Boolean testPassed;

  @Schema(description = "린트 요구사항 통과 여부", example = "true")
  private Boolean lintPassed;

  @Schema(description = "파일 형식 검증 통과 여부", example = "true")
  private Boolean fileFormatPassed;

  @Schema(description = "자동 검증 품질 점수", example = "100")
  private Integer qualityScore;

  @Schema(description = "precheck 결과 메시지", example = "precheck를 통과했습니다.")
  private String message;

  @Builder
  public AssignmentPrecheckResponse(
      Boolean passed,
      Boolean readmePassed,
      Boolean testPassed,
      Boolean lintPassed,
      Boolean fileFormatPassed,
      Integer qualityScore,
      String message) {
    this.passed = passed;
    this.readmePassed = readmePassed;
    this.testPassed = testPassed;
    this.lintPassed = lintPassed;
    this.fileFormatPassed = fileFormatPassed;
    this.qualityScore = qualityScore;
    this.message = message;
  }
}
