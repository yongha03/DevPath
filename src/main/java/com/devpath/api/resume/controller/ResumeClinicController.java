package com.devpath.api.resume.controller;

import com.devpath.api.resume.dto.ResumeClinicRequest;
import com.devpath.api.resume.dto.ResumeClinicResponse;
import com.devpath.api.resume.service.ResumeClinicService;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "Resume Clinic", description = "학습/프로젝트/Proof Card 기반 이력서 문구 추천 API")
@RestController
@RequiredArgsConstructor
public class ResumeClinicController {

  private final ResumeClinicService resumeClinicService;

  @PostMapping("/api/resume-clinic/strength-summary")
  @Operation(summary = "강점 요약 생성", description = "학습 이력, 프로젝트 이력, Proof Card 기반 강점 요약을 생성합니다.")
  public ResponseEntity<ApiResponse<ResumeClinicResponse.StrengthSummary>> createStrengthSummary(
      @Valid @RequestBody ResumeClinicRequest.StrengthSummary request) {
    return ResponseEntity.ok(ApiResponse.ok(resumeClinicService.createStrengthSummary(request)));
  }

  @PostMapping("/api/resume-clinic/highlight-points")
  @Operation(summary = "이력서 강조 포인트 추천", description = "기술 스택과 프로젝트 경험 기반으로 이력서 강조 포인트를 추천합니다.")
  public ResponseEntity<ApiResponse<ResumeClinicResponse.HighlightPoints>> createHighlightPoints(
      @Valid @RequestBody ResumeClinicRequest.HighlightPoints request) {
    return ResponseEntity.ok(ApiResponse.ok(resumeClinicService.createHighlightPoints(request)));
  }

  @PostMapping("/api/resume-clinic/portfolio-phrases")
  @Operation(summary = "포트폴리오 문구 생성", description = "프로젝트와 Proof Card 기반 포트폴리오 소개 문구를 생성합니다.")
  public ResponseEntity<ApiResponse<ResumeClinicResponse.PortfolioPhrases>> createPortfolioPhrases(
      @Valid @RequestBody ResumeClinicRequest.PortfolioPhrases request) {
    return ResponseEntity.ok(ApiResponse.ok(resumeClinicService.createPortfolioPhrases(request)));
  }
}
