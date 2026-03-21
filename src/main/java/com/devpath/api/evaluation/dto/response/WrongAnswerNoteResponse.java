package com.devpath.api.evaluation.dto.response;

import com.devpath.domain.learning.entity.WrongAnswerNote;
import io.swagger.v3.oas.annotations.media.Schema;
import java.time.LocalDateTime;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Schema(description = "오답 노트 응답 DTO")
public class WrongAnswerNoteResponse {

  // Evaluation Swagger 문서화 기준에 맞춘 오답 노트 응답 DTO다.
  @Schema(description = "오답 노트 ID", example = "1")
  private Long noteId;

  @Schema(description = "연결된 퀴즈 응시 ID", example = "100")
  private Long attemptId;

  @Schema(description = "연결된 문항 ID", example = "10")
  private Long questionId;

  @Schema(description = "오답 노트를 작성한 학습자 ID", example = "1")
  private Long learnerId;

  @Schema(description = "오답 노트 내용", example = "정답 공개 후 핵심 개념을 다시 정리해야 한다.")
  private String noteContent;

  @Schema(description = "복습 완료 여부", example = "false")
  private Boolean reviewed;

  @Schema(description = "오답 노트 생성 시각", example = "2026-03-20T10:15:30")
  private LocalDateTime createdAt;

  @Builder
  public WrongAnswerNoteResponse(
      Long noteId,
      Long attemptId,
      Long questionId,
      Long learnerId,
      String noteContent,
      Boolean reviewed,
      LocalDateTime createdAt) {
    this.noteId = noteId;
    this.attemptId = attemptId;
    this.questionId = questionId;
    this.learnerId = learnerId;
    this.noteContent = noteContent;
    this.reviewed = reviewed;
    this.createdAt = createdAt;
  }

  public static WrongAnswerNoteResponse from(WrongAnswerNote wrongAnswerNote) {
    return WrongAnswerNoteResponse.builder()
        .noteId(wrongAnswerNote.getId())
        .attemptId(wrongAnswerNote.getAttempt().getId())
        .questionId(wrongAnswerNote.getQuestion().getId())
        .learnerId(wrongAnswerNote.getLearner().getId())
        .noteContent(wrongAnswerNote.getNoteContent())
        .reviewed(wrongAnswerNote.getIsReviewed())
        .createdAt(wrongAnswerNote.getCreatedAt())
        .build();
  }
}
