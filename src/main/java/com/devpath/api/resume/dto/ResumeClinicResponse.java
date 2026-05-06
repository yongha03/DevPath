package com.devpath.api.resume.dto;

import com.devpath.domain.resume.model.ResumeClinicGeneratedContent;
import com.devpath.domain.resume.model.ResumeClinicSourceType;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

public class ResumeClinicResponse {

  private ResumeClinicResponse() {}

  @Schema(name = "ResumeStrengthSummaryResponse", description = "강점 요약 응답")
  public record StrengthSummary(
      @Schema(description = "목표 직무", example = "Backend Developer") String targetRole,
      @Schema(description = "핵심 기술 스택", example = "[\"Java\", \"Spring Boot\", \"JPA\"]")
          List<String> skills,
      @Schema(description = "학습 이력 기반 강점 요약") String learningStrengthSummary,
      @Schema(description = "프로젝트 이력 기반 강점 요약") String projectStrengthSummary,
      @Schema(description = "Proof Card 기반 강점 요약") String proofCardStrengthSummary,
      @Schema(description = "종합 강점 요약") String overallSummary,
      @Schema(description = "추천 키워드", example = "[\"Java\", \"Spring Boot\", \"JPA\"]")
          List<String> recommendedKeywords) {}

  @Schema(name = "ResumeHighlightPointsResponse", description = "이력서 강조 포인트 응답")
  public record HighlightPoints(
      @Schema(description = "목표 직무", example = "Backend Developer") String targetRole,
      @Schema(description = "강조 포인트 목록") List<String> highlightPoints,
      @Schema(description = "이력서 bullet 문구 목록") List<String> bulletPoints,
      @Schema(description = "매칭 키워드", example = "[\"REST API\", \"Spring Security\"]")
          List<String> matchedKeywords) {}

  @Schema(name = "PortfolioPhrasesResponse", description = "포트폴리오 추천 문구 응답")
  public record PortfolioPhrases(
      @Schema(description = "포트폴리오 헤드라인") String headline,
      @Schema(description = "포트폴리오 소개 문구") String introduction,
      @Schema(description = "프로젝트 설명 문구") List<String> projectPhrases,
      @Schema(description = "Proof Card 설명 문구") List<String> proofCardPhrases,
      @Schema(description = "마무리 문구") List<String> closingPhrases) {}

  @Schema(name = "ResumeGeneratedContentResponse", description = "생성 문구 공통 응답")
  public record GeneratedContent(
      @Schema(description = "문구 출처 타입", example = "PROJECT")
          ResumeClinicSourceType sourceType,
      @Schema(description = "문구 제목", example = "프로젝트 기반 강점") String title,
      @Schema(description = "생성 문구") String content,
      @Schema(description = "관련 키워드") List<String> keywords) {

    public static GeneratedContent from(ResumeClinicGeneratedContent content) {
      return new GeneratedContent(
          content.sourceType(), content.title(), content.content(), content.keywords());
    }
  }
}
