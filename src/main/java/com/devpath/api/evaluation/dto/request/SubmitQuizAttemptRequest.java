package com.devpath.api.evaluation.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import java.util.ArrayList;
import java.util.List;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Schema(description = "학습자용 퀴즈 응시 제출 요청 DTO")
public class SubmitQuizAttemptRequest {

  // Evaluation Swagger 문서화 기준에 맞춘 퀴즈 응시 제출 요청 DTO다.
  @Valid
  @NotEmpty
  @Schema(description = "문항별 답안 목록")
  private List<SubmitQuizAnswerRequest> answers = new ArrayList<>();

  @Min(0)
  @Schema(description = "퀴즈 풀이 소요 시간(초)", example = "180")
  private Integer timeSpentSeconds;

  @Builder
  public SubmitQuizAttemptRequest(List<SubmitQuizAnswerRequest> answers, Integer timeSpentSeconds) {
    this.answers = answers == null ? new ArrayList<>() : answers;
    this.timeSpentSeconds = timeSpentSeconds;
  }
}
