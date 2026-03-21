package com.devpath.api.evaluation.dto.request;

import com.devpath.domain.learning.entity.QuestionType;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import java.util.ArrayList;
import java.util.List;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Schema(description = "AI 퀴즈 초안 수정 요청 DTO")
public class UpdateAiQuizDraftRequest {

  // Evaluation Swagger 문서화 기준에 맞춘 AI 퀴즈 초안 수정 요청 DTO다.
  @Schema(description = "수정할 초안 제목", example = "Spring Security 수정된 초안 퀴즈")
  private String title;

  @Schema(description = "수정할 초안 설명", example = "강사 검토 후 초안을 일부 수정했습니다.")
  private String description;

  @Valid
  @Schema(description = "초안 문항 전체 교체에 사용할 문항 목록")
  private List<DraftQuestionUpdateRequest> questions = new ArrayList<>();

  @Builder
  public UpdateAiQuizDraftRequest(
      String title, String description, List<DraftQuestionUpdateRequest> questions) {
    this.title = title;
    this.description = description;
    this.questions = questions == null ? new ArrayList<>() : questions;
  }

  @Getter
  @NoArgsConstructor(access = AccessLevel.PROTECTED)
  @Schema(description = "AI 초안 문항 수정 요청 DTO")
  public static class DraftQuestionUpdateRequest {

    @Schema(description = "초안 문항 ID", example = "1")
    private Long draftQuestionId;

    @Schema(description = "문항 유형", example = "MULTIPLE_CHOICE")
    private QuestionType questionType;

    @Schema(description = "문항 본문", example = "Spring Security의 핵심 역할은 무엇인가?")
    private String questionText;

    @Schema(description = "문항 해설", example = "인증과 인가를 지원하는 것이 핵심 역할입니다.")
    private String explanation;

    @Schema(description = "문항 배점", example = "5")
    private Integer points;

    @Schema(description = "문항 노출 순서", example = "1")
    private Integer displayOrder;

    @Schema(description = "문항별 근거 타임스탬프", example = "12:10-13:20")
    private String sourceTimestamp;

    @Valid
    @Schema(description = "문항에 포함할 선택지 목록")
    private List<DraftOptionUpdateRequest> options = new ArrayList<>();

    @Builder
    public DraftQuestionUpdateRequest(
        Long draftQuestionId,
        QuestionType questionType,
        String questionText,
        String explanation,
        Integer points,
        Integer displayOrder,
        String sourceTimestamp,
        List<DraftOptionUpdateRequest> options) {
      this.draftQuestionId = draftQuestionId;
      this.questionType = questionType;
      this.questionText = questionText;
      this.explanation = explanation;
      this.points = points;
      this.displayOrder = displayOrder;
      this.sourceTimestamp = sourceTimestamp;
      this.options = options == null ? new ArrayList<>() : options;
    }
  }

  @Getter
  @NoArgsConstructor(access = AccessLevel.PROTECTED)
  @Schema(description = "AI 초안 선택지 수정 요청 DTO")
  public static class DraftOptionUpdateRequest {

    @Schema(description = "초안 선택지 ID", example = "1")
    private Long draftOptionId;

    @Schema(description = "선택지 내용", example = "인증과 인가")
    private String optionText;

    @Schema(description = "정답 여부", example = "true")
    private Boolean correct;

    @Schema(description = "선택지 노출 순서", example = "1")
    private Integer displayOrder;

    @Builder
    public DraftOptionUpdateRequest(
        Long draftOptionId, String optionText, Boolean correct, Integer displayOrder) {
      this.draftOptionId = draftOptionId;
      this.optionText = optionText;
      this.correct = correct;
      this.displayOrder = displayOrder;
    }
  }
}
