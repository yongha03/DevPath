package com.devpath.api.evaluation.dto.response;

import com.devpath.domain.learning.entity.Assignment;
import com.devpath.domain.learning.entity.SubmissionType;
import io.swagger.v3.oas.annotations.media.Schema;
import java.time.LocalDateTime;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Schema(description = "강사용 과제 상세 응답 DTO")
public class AssignmentDetailResponse {

  // Evaluation Swagger 문서화 기준에 맞춘 과제 상세 응답 DTO다.
  @Schema(description = "과제 ID", example = "20")
  private Long assignmentId;

  @Schema(description = "연결된 로드맵 노드 ID", example = "1")
  private Long roadmapNodeId;

  @Schema(description = "과제 제목", example = "JWT 로그인 API 구현")
  private String title;

  @Schema(description = "과제 설명", example = "Spring Security와 JWT를 사용한 로그인 API를 구현하세요.")
  private String description;

  @Schema(description = "허용 제출 유형", example = "MULTIPLE")
  private SubmissionType submissionType;

  @Schema(description = "과제 마감 일시", example = "2026-03-27T23:59:59")
  private LocalDateTime dueAt;

  @Schema(description = "허용 파일 형식 목록", example = "zip,pdf,md")
  private String allowedFileFormats;

  @Schema(description = "README 필수 여부", example = "true")
  private Boolean readmeRequired;

  @Schema(description = "테스트 필수 여부", example = "true")
  private Boolean testRequired;

  @Schema(description = "린트 필수 여부", example = "true")
  private Boolean lintRequired;

  @Schema(description = "제출 규칙 설명", example = "README에 실행 방법과 검증 결과를 반드시 포함하세요.")
  private String submissionRuleDescription;

  @Schema(description = "과제 총점", example = "100")
  private Integer totalScore;

  @Schema(description = "과제 공개 여부", example = "false")
  private Boolean isPublished;

  @Schema(description = "과제 활성 여부", example = "true")
  private Boolean isActive;

  @Schema(description = "지각 제출 허용 여부", example = "false")
  private Boolean allowLateSubmission;

  @Schema(description = "과제 생성 시각", example = "2026-03-20T11:30:00")
  private LocalDateTime createdAt;

  @Builder
  public AssignmentDetailResponse(
      Long assignmentId,
      Long roadmapNodeId,
      String title,
      String description,
      SubmissionType submissionType,
      LocalDateTime dueAt,
      String allowedFileFormats,
      Boolean readmeRequired,
      Boolean testRequired,
      Boolean lintRequired,
      String submissionRuleDescription,
      Integer totalScore,
      Boolean isPublished,
      Boolean isActive,
      Boolean allowLateSubmission,
      LocalDateTime createdAt) {
    this.assignmentId = assignmentId;
    this.roadmapNodeId = roadmapNodeId;
    this.title = title;
    this.description = description;
    this.submissionType = submissionType;
    this.dueAt = dueAt;
    this.allowedFileFormats = allowedFileFormats;
    this.readmeRequired = readmeRequired;
    this.testRequired = testRequired;
    this.lintRequired = lintRequired;
    this.submissionRuleDescription = submissionRuleDescription;
    this.totalScore = totalScore;
    this.isPublished = isPublished;
    this.isActive = isActive;
    this.allowLateSubmission = allowLateSubmission;
    this.createdAt = createdAt;
  }

  public static AssignmentDetailResponse from(Assignment assignment) {
    return AssignmentDetailResponse.builder()
        .assignmentId(assignment.getId())
        .roadmapNodeId(assignment.getRoadmapNode().getNodeId())
        .title(assignment.getTitle())
        .description(assignment.getDescription())
        .submissionType(assignment.getSubmissionType())
        .dueAt(assignment.getDueAt())
        .allowedFileFormats(assignment.getAllowedFileFormats())
        .readmeRequired(assignment.getReadmeRequired())
        .testRequired(assignment.getTestRequired())
        .lintRequired(assignment.getLintRequired())
        .submissionRuleDescription(assignment.getSubmissionRuleDescription())
        .totalScore(assignment.getTotalScore())
        .isPublished(assignment.getIsPublished())
        .isActive(assignment.getIsActive())
        .allowLateSubmission(assignment.getAllowLateSubmission())
        .createdAt(assignment.getCreatedAt())
        .build();
  }
}
