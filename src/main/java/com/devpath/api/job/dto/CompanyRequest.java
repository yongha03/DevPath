package com.devpath.api.job.dto;

import com.devpath.domain.job.entity.CompanyVerificationStatus;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public class CompanyRequest {

  private CompanyRequest() {}

  @Schema(name = "CompanyCreateRequest", description = "기업 프로필 생성 요청")
  public record Create(
      @Schema(description = "기업명", example = "DevPath Labs")
          @NotBlank(message = "기업명은 필수입니다.")
          @Size(max = 150, message = "기업명은 150자 이하여야 합니다.")
          String name,
      @Schema(description = "기업 소개", example = "개발자 성장 플랫폼을 만드는 스타트업입니다.")
          @Size(max = 5000, message = "기업 소개는 5000자 이하여야 합니다.")
          String description,
      @Schema(description = "기업 홈페이지 URL", example = "https://devpath.example.com")
          @Size(max = 1000, message = "홈페이지 URL은 1000자 이하여야 합니다.")
          String websiteUrl,
      @Schema(description = "기업 로고 URL", example = "https://cdn.example.com/logo.png")
          @Size(max = 1000, message = "로고 URL은 1000자 이하여야 합니다.")
          String logoUrl,
      @Schema(description = "산업군", example = "EdTech")
          @Size(max = 100, message = "산업군은 100자 이하여야 합니다.")
          String industry,
      @Schema(description = "기업 위치", example = "서울")
          @Size(max = 150, message = "기업 위치는 150자 이하여야 합니다.")
          String location) {}

  @Schema(name = "CompanyUpdateRequest", description = "기업 프로필 수정 요청")
  public record Update(
      @Schema(description = "기업명", example = "DevPath Labs Korea")
          @NotBlank(message = "기업명은 필수입니다.")
          @Size(max = 150, message = "기업명은 150자 이하여야 합니다.")
          String name,
      @Schema(description = "기업 소개", example = "개발자 교육과 커리어 분석을 제공하는 플랫폼 기업입니다.")
          @Size(max = 5000, message = "기업 소개는 5000자 이하여야 합니다.")
          String description,
      @Schema(description = "기업 홈페이지 URL", example = "https://devpath.example.com")
          @Size(max = 1000, message = "홈페이지 URL은 1000자 이하여야 합니다.")
          String websiteUrl,
      @Schema(description = "기업 로고 URL", example = "https://cdn.example.com/logo-new.png")
          @Size(max = 1000, message = "로고 URL은 1000자 이하여야 합니다.")
          String logoUrl,
      @Schema(description = "산업군", example = "HR Tech")
          @Size(max = 100, message = "산업군은 100자 이하여야 합니다.")
          String industry,
      @Schema(description = "기업 위치", example = "경기 부천")
          @Size(max = 150, message = "기업 위치는 150자 이하여야 합니다.")
          String location) {}

  @Schema(name = "CompanyVerifyRequest", description = "기업 인증 처리 요청")
  public record Verify(
      @Schema(description = "기업 인증 상태", example = "VERIFIED") @NotNull(message = "기업 인증 상태는 필수입니다.")
          CompanyVerificationStatus status,
      @Schema(description = "인증 처리 메모", example = "사업자 정보 확인 완료")
          @Size(max = 500, message = "인증 메모는 500자 이하여야 합니다.")
          String memo) {}
}
