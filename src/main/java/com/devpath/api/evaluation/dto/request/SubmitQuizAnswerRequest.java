package com.devpath.api.evaluation.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Schema(description = "학습자용 퀴즈 문항별 답안 요청 DTO")
public class SubmitQuizAnswerRequest {

  // Evaluation Swagger 문서화 기준에 맞춘 문항별 답안 요청 DTO다.
  @NotNull
  @Schema(description = "답안을 제출할 문항 ID", example = "10")
  private Long questionId;

  @Schema(description = "객관식 또는 OX 문항에서 선택한 선택지 ID", example = "100")
  private Long selectedOptionId;

  @Schema(description = "주관식 문항에 직접 입력한 답안", example = "Spring Security")
  private String textAnswer;

  @Builder
  public SubmitQuizAnswerRequest(Long questionId, Long selectedOptionId, String textAnswer) {
    this.questionId = questionId;
    this.selectedOptionId = selectedOptionId;
    this.textAnswer = textAnswer;
  }
}
