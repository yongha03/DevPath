package com.devpath.api.evaluation.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Schema(description = "강사용 제출물 피드백 생성 요청 DTO")
public class CreateFeedbackRequest {

  // Evaluation Swagger 문서화 기준에 맞춘 피드백 생성 요청 DTO다.
  @NotBlank
  @Schema(description = "피드백 유형", example = "INDIVIDUAL")
  private String feedbackType;

  @NotBlank
  @Schema(description = "저장할 피드백 내용", example = "테스트 코드 커버리지를 조금 더 보강하면 좋겠습니다.")
  private String content;

  @Builder
  public CreateFeedbackRequest(String feedbackType, String content) {
    this.feedbackType = feedbackType;
    this.content = content;
  }
}
