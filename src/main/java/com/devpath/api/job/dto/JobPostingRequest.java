package com.devpath.api.job.dto;

import com.devpath.domain.job.entity.JobPostingStatus;
import com.devpath.domain.job.entity.JobSource;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.time.LocalDate;

public class JobPostingRequest {

  private JobPostingRequest() {}

  @Schema(name = "JobPostingCreateRequest", description = "채용 공고 등록 요청")
  public record Create(
      @Schema(description = "기업 ID", example = "1") @NotNull(message = "기업 ID는 필수입니다.")
          Long companyId,
      @Schema(description = "공고 제목", example = "백엔드 주니어 개발자 채용")
          @NotBlank(message = "공고 제목은 필수입니다.")
          @Size(max = 200, message = "공고 제목은 200자 이하여야 합니다.")
          String title,
      @Schema(description = "직무명", example = "Backend Developer")
          @NotBlank(message = "직무명은 필수입니다.")
          @Size(max = 100, message = "직무명은 100자 이하여야 합니다.")
          String jobRole,
      @Schema(description = "공고 설명", example = "Spring Boot 기반 백엔드 API 개발자를 채용합니다.")
          @NotBlank(message = "공고 설명은 필수입니다.")
          @Size(max = 10000, message = "공고 설명은 10000자 이하여야 합니다.")
          String description,
      @Schema(description = "요구 기술 스택", example = "Java, Spring Boot, JPA, PostgreSQL")
          @Size(max = 3000, message = "요구 기술 스택은 3000자 이하여야 합니다.")
          String requiredSkills,
      @Schema(description = "근무 지역", example = "SEOUL")
          @Size(max = 150, message = "근무 지역은 150자 이하여야 합니다.")
          String region,
      @Schema(description = "경력 조건", example = "JUNIOR")
          @Size(max = 50, message = "경력 조건은 50자 이하여야 합니다.")
          String careerLevel,
      @Schema(description = "원문 공고 URL", example = "https://jobs.example.com/postings/1")
          @Size(max = 1000, message = "원문 공고 URL은 1000자 이하여야 합니다.")
          String sourceUrl,
      @Schema(description = "공고 출처", example = "INTERNAL") @NotNull(message = "공고 출처는 필수입니다.")
          JobSource source,
      @Schema(description = "공고 상태", example = "OPEN") @NotNull(message = "공고 상태는 필수입니다.")
          JobPostingStatus status,
      @Schema(description = "공고 마감일", example = "2026-06-30") LocalDate deadline,
      @Schema(description = "외부 플랫폼 공고 ID", example = "wanted-12345")
          @Size(max = 150, message = "외부 공고 ID는 150자 이하여야 합니다.")
          String externalJobId) {}

  @Schema(name = "JobPostingUpdateRequest", description = "채용 공고 수정 요청")
  public record Update(
      @Schema(description = "공고 제목", example = "백엔드 주니어 개발자 채용 수정")
          @NotBlank(message = "공고 제목은 필수입니다.")
          @Size(max = 200, message = "공고 제목은 200자 이하여야 합니다.")
          String title,
      @Schema(description = "직무명", example = "Backend Engineer")
          @NotBlank(message = "직무명은 필수입니다.")
          @Size(max = 100, message = "직무명은 100자 이하여야 합니다.")
          String jobRole,
      @Schema(description = "공고 설명", example = "Java 21과 Spring Boot 기반 API 개발자를 채용합니다.")
          @NotBlank(message = "공고 설명은 필수입니다.")
          @Size(max = 10000, message = "공고 설명은 10000자 이하여야 합니다.")
          String description,
      @Schema(description = "요구 기술 스택", example = "Java, Spring Boot, JPA, Redis, PostgreSQL")
          @Size(max = 3000, message = "요구 기술 스택은 3000자 이하여야 합니다.")
          String requiredSkills,
      @Schema(description = "근무 지역", example = "GYEONGGI")
          @Size(max = 150, message = "근무 지역은 150자 이하여야 합니다.")
          String region,
      @Schema(description = "경력 조건", example = "JUNIOR")
          @Size(max = 50, message = "경력 조건은 50자 이하여야 합니다.")
          String careerLevel,
      @Schema(description = "원문 공고 URL", example = "https://jobs.example.com/postings/1")
          @Size(max = 1000, message = "원문 공고 URL은 1000자 이하여야 합니다.")
          String sourceUrl,
      @Schema(description = "공고 출처", example = "INTERNAL") @NotNull(message = "공고 출처는 필수입니다.")
          JobSource source,
      @Schema(description = "공고 상태", example = "OPEN") @NotNull(message = "공고 상태는 필수입니다.")
          JobPostingStatus status,
      @Schema(description = "공고 마감일", example = "2026-07-31") LocalDate deadline,
      @Schema(description = "외부 플랫폼 공고 ID", example = "wanted-12345")
          @Size(max = 150, message = "외부 공고 ID는 150자 이하여야 합니다.")
          String externalJobId) {}

  @Schema(name = "JobCollectRequest", description = "외부 채용 데이터 수집 요청")
  public record Collect(
      @Schema(description = "수집 소스", example = "WANTED") @NotNull(message = "수집 소스는 필수입니다.")
          JobSource source,
      @Schema(description = "수집 키워드", example = "Spring Boot")
          @Size(max = 100, message = "수집 키워드는 100자 이하여야 합니다.")
          String keyword,
      @Schema(description = "수집 요청 개수", example = "20")
          @NotNull(message = "수집 요청 개수는 필수입니다.")
          @Min(value = 1, message = "수집 요청 개수는 1 이상이어야 합니다.")
          Integer limit) {}
}
