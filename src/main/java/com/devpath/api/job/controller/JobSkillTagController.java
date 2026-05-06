package com.devpath.api.job.controller;

import com.devpath.api.job.dto.JobSkillTagResponse;
import com.devpath.api.job.service.JobSkillTagService;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "JD Analysis", description = "JD 분석 및 채용 기술 태그 API")
@RestController
@RequiredArgsConstructor
public class JobSkillTagController {

  private final JobSkillTagService jobSkillTagService;

  @PostMapping("/api/admin/jobs/{jobId}/analyze-jd")
  @Operation(summary = "JD 분석", description = "채용 공고 설명에서 기술 스택 키워드를 추출해 저장합니다.")
  public ResponseEntity<ApiResponse<JobSkillTagResponse.AnalysisResult>> analyzeJd(
      @PathVariable Long jobId) {
    return ResponseEntity.ok(ApiResponse.ok(jobSkillTagService.analyzeJd(jobId)));
  }

  @GetMapping("/api/admin/jobs/{jobId}/skill-tags")
  @Operation(summary = "공고별 기술 태그 조회", description = "채용 공고 ID 기준으로 추출된 기술 스택 태그를 조회합니다.")
  public ResponseEntity<ApiResponse<List<JobSkillTagResponse.Detail>>> getSkillTags(
      @PathVariable Long jobId) {
    return ResponseEntity.ok(ApiResponse.ok(jobSkillTagService.getSkillTags(jobId)));
  }

  @GetMapping("/api/market/job-skill-tags/popular")
  @Operation(summary = "인기 기술 태그 조회", description = "전체 채용 공고 기준 기술 태그 등장 횟수를 조회합니다.")
  public ResponseEntity<ApiResponse<List<JobSkillTagResponse.Popular>>> getPopularSkillTags() {
    return ResponseEntity.ok(ApiResponse.ok(jobSkillTagService.getPopularSkillTags()));
  }
}
