package com.devpath.api.evaluation.dto.response;

import com.devpath.domain.learning.entity.Rubric;
import com.devpath.domain.learning.entity.Submission;
import com.devpath.domain.learning.entity.SubmissionFile;
import com.devpath.domain.learning.entity.SubmissionStatus;
import io.swagger.v3.oas.annotations.media.Schema;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Schema(description = "제출물 상세 조회 응답 DTO")
public class SubmissionDetailResponse {

  // Evaluation Swagger 문서화 기준에 맞춘 제출 상세 응답 DTO다.
  @Schema(description = "제출 ID", example = "1")
  private Long submissionId;

  @Schema(description = "과제 ID", example = "10")
  private Long assignmentId;

  @Schema(description = "과제 제목", example = "Spring Security 실습 과제")
  private String assignmentTitle;

  @Schema(description = "학습자 ID", example = "2")
  private Long learnerId;

  @Schema(description = "학습자 이름", example = "김수형")
  private String learnerName;

  @Schema(description = "현재 제출 상태", example = "SUBMITTED")
  private SubmissionStatus submissionStatus;

  @Schema(description = "제출 본문", example = "구현 요약과 실행 결과를 정리했습니다.")
  private String submissionText;

  @Schema(description = "제출 URL", example = "https://github.com/example/devpath-assignment")
  private String submissionUrl;

  @Schema(description = "지각 제출 여부", example = "false")
  private Boolean isLate;

  @Schema(description = "제출 시각", example = "2026-03-20T12:00:00")
  private LocalDateTime submittedAt;

  @Schema(description = "채점 시각", example = "2026-03-20T13:00:00")
  private LocalDateTime gradedAt;

  @Schema(description = "README 검증 통과 여부", example = "true")
  private Boolean readmePassed;

  @Schema(description = "테스트 검증 통과 여부", example = "true")
  private Boolean testPassed;

  @Schema(description = "린트 검증 통과 여부", example = "true")
  private Boolean lintPassed;

  @Schema(description = "파일 형식 검증 통과 여부", example = "true")
  private Boolean fileFormatPassed;

  @Schema(description = "자동 검증 품질 점수", example = "100")
  private Integer qualityScore;

  @Schema(description = "최종 채점 점수", example = "85")
  private Integer totalScore;

  @Schema(description = "개별 피드백 내용", example = "전반적으로 구현이 안정적입니다.")
  private String individualFeedback;

  @Schema(description = "공통 피드백 내용", example = "README에 실행 방법을 조금 더 구체적으로 적어주세요.")
  private String commonFeedback;

  @Schema(description = "제출 파일 목록")
  private List<FileItem> files = new ArrayList<>();

  @Schema(description = "연결된 루브릭 목록")
  private List<RubricItem> rubrics = new ArrayList<>();

  @Builder
  public SubmissionDetailResponse(
      Long submissionId,
      Long assignmentId,
      String assignmentTitle,
      Long learnerId,
      String learnerName,
      SubmissionStatus submissionStatus,
      String submissionText,
      String submissionUrl,
      Boolean isLate,
      LocalDateTime submittedAt,
      LocalDateTime gradedAt,
      Boolean readmePassed,
      Boolean testPassed,
      Boolean lintPassed,
      Boolean fileFormatPassed,
      Integer qualityScore,
      Integer totalScore,
      String individualFeedback,
      String commonFeedback,
      List<FileItem> files,
      List<RubricItem> rubrics) {
    this.submissionId = submissionId;
    this.assignmentId = assignmentId;
    this.assignmentTitle = assignmentTitle;
    this.learnerId = learnerId;
    this.learnerName = learnerName;
    this.submissionStatus = submissionStatus;
    this.submissionText = submissionText;
    this.submissionUrl = submissionUrl;
    this.isLate = isLate;
    this.submittedAt = submittedAt;
    this.gradedAt = gradedAt;
    this.readmePassed = readmePassed;
    this.testPassed = testPassed;
    this.lintPassed = lintPassed;
    this.fileFormatPassed = fileFormatPassed;
    this.qualityScore = qualityScore;
    this.totalScore = totalScore;
    this.individualFeedback = individualFeedback;
    this.commonFeedback = commonFeedback;
    this.files = files == null ? new ArrayList<>() : files;
    this.rubrics = rubrics == null ? new ArrayList<>() : rubrics;
  }

  public static SubmissionDetailResponse of(Submission submission, List<Rubric> rubricList) {
    List<FileItem> fileItems =
        submission.getFiles() == null
            ? new ArrayList<>()
            : submission.getFiles().stream().map(FileItem::from).toList();

    List<RubricItem> rubricItems =
        rubricList == null ? new ArrayList<>() : rubricList.stream().map(RubricItem::from).toList();

    return SubmissionDetailResponse.builder()
        .submissionId(submission.getId())
        .assignmentId(submission.getAssignment().getId())
        .assignmentTitle(submission.getAssignment().getTitle())
        .learnerId(submission.getLearner().getId())
        .learnerName(submission.getLearner().getName())
        .submissionStatus(submission.getSubmissionStatus())
        .submissionText(submission.getSubmissionText())
        .submissionUrl(submission.getSubmissionUrl())
        .isLate(submission.getIsLate())
        .submittedAt(submission.getSubmittedAt())
        .gradedAt(submission.getGradedAt())
        .readmePassed(submission.getReadmePassed())
        .testPassed(submission.getTestPassed())
        .lintPassed(submission.getLintPassed())
        .fileFormatPassed(submission.getFileFormatPassed())
        .qualityScore(submission.getQualityScore())
        .totalScore(submission.getTotalScore())
        .individualFeedback(submission.getIndividualFeedback())
        .commonFeedback(submission.getCommonFeedback())
        .files(fileItems)
        .rubrics(rubricItems)
        .build();
  }

  @Getter
  @NoArgsConstructor(access = AccessLevel.PROTECTED)
  @Schema(description = "제출 파일 항목 DTO")
  public static class FileItem {

    @Schema(description = "파일 ID", example = "1")
    private Long fileId;

    @Schema(description = "파일명", example = "README.md")
    private String fileName;

    @Schema(description = "파일 URL", example = "https://s3.example.com/devpath/README.md")
    private String fileUrl;

    @Schema(description = "파일 크기(byte)", example = "2048")
    private Long fileSize;

    @Schema(description = "파일 타입", example = "md")
    private String fileType;

    @Builder
    public FileItem(Long fileId, String fileName, String fileUrl, Long fileSize, String fileType) {
      this.fileId = fileId;
      this.fileName = fileName;
      this.fileUrl = fileUrl;
      this.fileSize = fileSize;
      this.fileType = fileType;
    }

    public static FileItem from(SubmissionFile file) {
      return FileItem.builder()
          .fileId(file.getId())
          .fileName(file.getFileName())
          .fileUrl(file.getFileUrl())
          .fileSize(file.getFileSize())
          .fileType(file.getFileType())
          .build();
    }
  }

  @Getter
  @NoArgsConstructor(access = AccessLevel.PROTECTED)
  @Schema(description = "루브릭 항목 DTO")
  public static class RubricItem {

    @Schema(description = "루브릭 ID", example = "1")
    private Long rubricId;

    @Schema(description = "루브릭 기준명", example = "기능 구현 완성도")
    private String criteriaName;

    @Schema(description = "루브릭 기준 설명", example = "필수 기능을 정확하게 구현했는지 평가합니다.")
    private String criteriaDescription;

    @Schema(description = "최대 점수", example = "10")
    private Integer maxPoints;

    @Schema(description = "노출 순서", example = "1")
    private Integer displayOrder;

    @Builder
    public RubricItem(
        Long rubricId,
        String criteriaName,
        String criteriaDescription,
        Integer maxPoints,
        Integer displayOrder) {
      this.rubricId = rubricId;
      this.criteriaName = criteriaName;
      this.criteriaDescription = criteriaDescription;
      this.maxPoints = maxPoints;
      this.displayOrder = displayOrder;
    }

    public static RubricItem from(Rubric rubric) {
      return RubricItem.builder()
          .rubricId(rubric.getId())
          .criteriaName(rubric.getCriteriaName())
          .criteriaDescription(rubric.getCriteriaDescription())
          .maxPoints(rubric.getMaxPoints())
          .displayOrder(rubric.getDisplayOrder())
          .build();
    }
  }
}
