package com.devpath.api.evaluation.dto.request;

import com.devpath.domain.learning.entity.QuestionType;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.util.ArrayList;
import java.util.List;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Schema(description = "강사용 퀴즈 문항 생성 요청 DTO")
public class CreateQuizQuestionRequest {

  // Evaluation Swagger 문서화 기준에 맞춘 퀴즈 문항 생성 요청 DTO다.
  @NotNull
  @Schema(description = "문항 유형", example = "MULTIPLE_CHOICE")
  private QuestionType questionType;

  @NotBlank
  @Schema(description = "문항 본문", example = "JWT의 장점으로 가장 적절한 것은 무엇인가?")
  private String questionText;

  @Schema(description = "문항 해설", example = "JWT는 서버 세션 없이 인증 상태를 표현할 수 있습니다.")
  private String explanation;

  @NotNull
  @Min(0)
  @Schema(description = "문항 배점", example = "20")
  private Integer points;

  @NotNull
  @Min(0)
  @Schema(description = "문항 노출 순서", example = "1")
  private Integer displayOrder;

  @Schema(description = "AI 생성 문항일 경우 근거 타임스탬프", example = "00:10:15-00:11:03")
  private String sourceTimestamp;

  @Valid
  @NotEmpty
  @Schema(description = "문항에 포함할 선택지 목록")
  private List<CreateQuizQuestionOptionRequest> options = new ArrayList<>();

  @Builder
  public CreateQuizQuestionRequest(
      QuestionType questionType,
      String questionText,
      String explanation,
      Integer points,
      Integer displayOrder,
      String sourceTimestamp,
      List<CreateQuizQuestionOptionRequest> options) {
    this.questionType = questionType;
    this.questionText = questionText;
    this.explanation = explanation;
    this.points = points;
    this.displayOrder = displayOrder;
    this.sourceTimestamp = sourceTimestamp;
    this.options = options == null ? new ArrayList<>() : options;
  }
}
