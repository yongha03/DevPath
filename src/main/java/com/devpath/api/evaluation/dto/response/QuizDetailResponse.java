package com.devpath.api.evaluation.dto.response;

import com.devpath.domain.learning.entity.Quiz;
import com.devpath.domain.learning.entity.QuizQuestion;
import com.devpath.domain.learning.entity.QuizQuestionOption;
import com.devpath.domain.learning.entity.QuizType;
import io.swagger.v3.oas.annotations.media.Schema;
import java.time.LocalDateTime;
import java.util.Comparator;
import java.util.List;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Schema(description = "강사용 퀴즈 상세 응답 DTO")
public class QuizDetailResponse {

  // Evaluation Swagger 문서화 기준에 맞춘 퀴즈 상세 응답 DTO다.
  @Schema(description = "퀴즈 ID", example = "10")
  private Long quizId;

  @Schema(description = "연결된 로드맵 노드 ID", example = "1")
  private Long roadmapNodeId;

  @Schema(description = "퀴즈 제목", example = "Spring Security 기초 퀴즈")
  private String title;

  @Schema(description = "퀴즈 설명", example = "인증과 인가 핵심 개념을 확인하는 퀴즈입니다.")
  private String description;

  @Schema(description = "퀴즈 생성 방식", example = "MANUAL")
  private QuizType quizType;

  @Schema(description = "퀴즈 총점", example = "100")
  private Integer totalScore;

  @Schema(description = "퀴즈 공개 여부", example = "false")
  private Boolean isPublished;

  @Schema(description = "퀴즈 활성 여부", example = "true")
  private Boolean isActive;

  @Schema(description = "응시 후 정답 공개 여부", example = "true")
  private Boolean exposeAnswer;

  @Schema(description = "응시 후 해설 공개 여부", example = "true")
  private Boolean exposeExplanation;

  @Schema(description = "퀴즈 생성 시각", example = "2026-03-20T11:00:00")
  private LocalDateTime createdAt;

  @Schema(description = "퀴즈에 포함된 문항 목록")
  private List<QuestionInfo> questions;

  @Builder
  public QuizDetailResponse(
      Long quizId,
      Long roadmapNodeId,
      String title,
      String description,
      QuizType quizType,
      Integer totalScore,
      Boolean isPublished,
      Boolean isActive,
      Boolean exposeAnswer,
      Boolean exposeExplanation,
      LocalDateTime createdAt,
      List<QuestionInfo> questions) {
    this.quizId = quizId;
    this.roadmapNodeId = roadmapNodeId;
    this.title = title;
    this.description = description;
    this.quizType = quizType;
    this.totalScore = totalScore;
    this.isPublished = isPublished;
    this.isActive = isActive;
    this.exposeAnswer = exposeAnswer;
    this.exposeExplanation = exposeExplanation;
    this.createdAt = createdAt;
    this.questions = questions;
  }

  public static QuizDetailResponse from(Quiz quiz) {
    return QuizDetailResponse.builder()
        .quizId(quiz.getId())
        .roadmapNodeId(quiz.getRoadmapNode().getNodeId())
        .title(quiz.getTitle())
        .description(quiz.getDescription())
        .quizType(quiz.getQuizType())
        .totalScore(quiz.getTotalScore())
        .isPublished(quiz.getIsPublished())
        .isActive(quiz.getIsActive())
        .exposeAnswer(quiz.getExposeAnswer())
        .exposeExplanation(quiz.getExposeExplanation())
        .createdAt(quiz.getCreatedAt())
        .questions(
            quiz.getQuestions().stream()
                .filter(question -> !Boolean.TRUE.equals(question.getIsDeleted()))
                .sorted(Comparator.comparing(QuizQuestion::getDisplayOrder))
                .map(QuestionInfo::from)
                .toList())
        .build();
  }

  @Getter
  @NoArgsConstructor(access = AccessLevel.PROTECTED)
  @Schema(description = "퀴즈 문항 응답 DTO")
  public static class QuestionInfo {

    @Schema(description = "문항 ID", example = "101")
    private Long questionId;

    @Schema(description = "문항 유형", example = "MULTIPLE_CHOICE")
    private String questionType;

    @Schema(description = "문항 본문", example = "JWT의 장점으로 가장 적절한 것은 무엇인가?")
    private String questionText;

    @Schema(description = "문항 해설", example = "JWT는 서버 세션 없이 인증 상태를 표현할 수 있습니다.")
    private String explanation;

    @Schema(description = "문항 배점", example = "20")
    private Integer points;

    @Schema(description = "문항 노출 순서", example = "1")
    private Integer displayOrder;

    @Schema(description = "AI 생성 문항일 경우 근거 타임스탬프", example = "00:10:15-00:11:03")
    private String sourceTimestamp;

    @Schema(description = "문항 선택지 목록")
    private List<OptionInfo> options;

    @Builder
    public QuestionInfo(
        Long questionId,
        String questionType,
        String questionText,
        String explanation,
        Integer points,
        Integer displayOrder,
        String sourceTimestamp,
        List<OptionInfo> options) {
      this.questionId = questionId;
      this.questionType = questionType;
      this.questionText = questionText;
      this.explanation = explanation;
      this.points = points;
      this.displayOrder = displayOrder;
      this.sourceTimestamp = sourceTimestamp;
      this.options = options;
    }

    public static QuestionInfo from(QuizQuestion question) {
      return QuestionInfo.builder()
          .questionId(question.getId())
          .questionType(question.getQuestionType().name())
          .questionText(question.getQuestionText())
          .explanation(question.getExplanation())
          .points(question.getPoints())
          .displayOrder(question.getDisplayOrder())
          .sourceTimestamp(question.getSourceTimestamp())
          .options(
              question.getOptions().stream()
                  .filter(option -> !Boolean.TRUE.equals(option.getIsDeleted()))
                  .sorted(Comparator.comparing(QuizQuestionOption::getDisplayOrder))
                  .map(OptionInfo::from)
                  .toList())
          .build();
    }
  }

  @Getter
  @NoArgsConstructor(access = AccessLevel.PROTECTED)
  @Schema(description = "퀴즈 선택지 응답 DTO")
  public static class OptionInfo {

    @Schema(description = "선택지 ID", example = "1001")
    private Long optionId;

    @Schema(description = "선택지 내용", example = "서버 세션 없이 인증 상태를 유지할 수 있다.")
    private String optionText;

    @Schema(description = "정답 여부", example = "true")
    private Boolean isCorrect;

    @Schema(description = "선택지 노출 순서", example = "1")
    private Integer displayOrder;

    @Builder
    public OptionInfo(Long optionId, String optionText, Boolean isCorrect, Integer displayOrder) {
      this.optionId = optionId;
      this.optionText = optionText;
      this.isCorrect = isCorrect;
      this.displayOrder = displayOrder;
    }

    public static OptionInfo from(QuizQuestionOption option) {
      return OptionInfo.builder()
          .optionId(option.getId())
          .optionText(option.getOptionText())
          .isCorrect(option.getIsCorrect())
          .displayOrder(option.getDisplayOrder())
          .build();
    }
  }
}
