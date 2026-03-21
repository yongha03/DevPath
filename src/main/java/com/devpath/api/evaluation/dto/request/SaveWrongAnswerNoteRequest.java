package com.devpath.api.evaluation.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Schema(description = "학습자용 오답 노트 저장 요청 DTO")
public class SaveWrongAnswerNoteRequest {

  // Evaluation Swagger 문서화 기준에 맞춘 오답 노트 저장 요청 DTO다.
  @NotNull
  @Schema(description = "오답 노트를 저장할 문항 ID", example = "10")
  private Long questionId;

  @NotBlank
  @Schema(description = "학습자가 남기는 오답 복습 메모", example = "정답 공개 후 핵심 개념을 다시 정리해야 한다.")
  private String noteContent;

  @Builder
  public SaveWrongAnswerNoteRequest(Long questionId, String noteContent) {
    this.questionId = questionId;
    this.noteContent = noteContent;
  }
}
