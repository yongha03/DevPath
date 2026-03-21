package com.devpath.api.evaluation.dto.response;

import com.devpath.domain.learning.entity.SubmissionStatus;
import io.swagger.v3.oas.annotations.media.Schema;
import java.time.LocalDateTime;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Schema(description = "제출물 피드백 저장 결과 응답 DTO")
public class FeedbackResponse {

  // Evaluation Swagger 문서화 기준에 맞춘 피드백 저장 결과 응답 DTO다.
  @Schema(description = "제출 ID", example = "1")
  private Long submissionId;

  @Schema(description = "피드백 유형", example = "INDIVIDUAL")
  private String feedbackType;

  @Schema(description = "저장된 피드백 내용", example = "테스트 코드 커버리지를 조금 더 보강하면 좋겠습니다.")
  private String content;

  @Schema(description = "피드백 저장 이후 제출 상태", example = "GRADED")
  private SubmissionStatus submissionStatus;

  @Schema(description = "현재 총점", example = "24")
  private Integer totalScore;

  @Schema(description = "피드백 반영 시각", example = "2026-03-20T14:00:00")
  private LocalDateTime updatedAt;

  @Builder
  public FeedbackResponse(
      Long submissionId,
      String feedbackType,
      String content,
      SubmissionStatus submissionStatus,
      Integer totalScore,
      LocalDateTime updatedAt) {
    this.submissionId = submissionId;
    this.feedbackType = feedbackType;
    this.content = content;
    this.submissionStatus = submissionStatus;
    this.totalScore = totalScore;
    this.updatedAt = updatedAt;
  }
}
