package com.devpath.api.evaluation.dto.request;

import com.devpath.domain.learning.entity.QuizType;
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
@Schema(description = "강사용 퀴즈 생성 요청 DTO")
public class CreateQuizRequest {

  // Evaluation Swagger 문서화 기준에 맞춘 퀴즈 생성 요청 DTO다.
  @NotNull
  @Schema(description = "퀴즈를 연결할 로드맵 노드 ID", example = "1")
  private Long roadmapNodeId;

  @NotBlank
  @Schema(description = "퀴즈 제목", example = "Spring Security 기초 퀴즈")
  private String title;

  @Schema(description = "퀴즈 설명", example = "인증과 인가 핵심 개념을 확인하는 퀴즈입니다.")
  private String description;

  @NotNull
  @Schema(description = "퀴즈 생성 방식", example = "MANUAL")
  private QuizType quizType;

  @NotNull
  @Min(0)
  @Schema(description = "퀴즈 총점", example = "100")
  private Integer totalScore;

  @Schema(description = "생성 직후 퀴즈를 공개할지 여부", example = "false")
  private Boolean isPublished;

  @Schema(description = "생성 직후 퀴즈를 활성 상태로 둘지 여부", example = "true")
  private Boolean isActive;

  @Schema(description = "응시 직후 정답을 공개할지 여부", example = "true")
  private Boolean exposeAnswer;

  @Schema(description = "응시 직후 해설을 공개할지 여부", example = "true")
  private Boolean exposeExplanation;

  @Builder
  public CreateQuizRequest(
      Long roadmapNodeId,
      String title,
      String description,
      QuizType quizType,
      Integer totalScore,
      Boolean isPublished,
      Boolean isActive,
      Boolean exposeAnswer,
      Boolean exposeExplanation) {
    this.roadmapNodeId = roadmapNodeId;
    this.title = title;
    this.description = description;
    this.quizType = quizType;
    this.totalScore = totalScore;
    this.isPublished = isPublished;
    this.isActive = isActive;
    this.exposeAnswer = exposeAnswer;
    this.exposeExplanation = exposeExplanation;
  }
}
