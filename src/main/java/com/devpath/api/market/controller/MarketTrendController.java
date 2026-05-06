package com.devpath.api.market.controller;

import com.devpath.api.market.dto.MarketTrendResponse;
import com.devpath.api.market.service.MarketTrendService;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "Market Trend", description = "채용 시장 트렌드 및 관리자 리포트 API")
@RestController
@RequiredArgsConstructor
public class MarketTrendController {

  private final MarketTrendService marketTrendService;

  @GetMapping("/api/market/trends/stacks")
  @Operation(summary = "직무 시장 인기 기술 스택 조회", description = "JD 분석 결과 기반 인기 기술 스택 통계를 조회합니다.")
  public ResponseEntity<ApiResponse<List<MarketTrendResponse.SkillStackTrend>>> getStackTrends() {
    return ResponseEntity.ok(ApiResponse.ok(marketTrendService.getStackTrends()));
  }

  @GetMapping("/api/market/trends/jobs")
  @Operation(summary = "직무별 채용 트렌드 조회", description = "직무별 채용 공고 수를 조회합니다.")
  public ResponseEntity<ApiResponse<List<MarketTrendResponse.JobTrend>>> getJobTrends() {
    return ResponseEntity.ok(ApiResponse.ok(marketTrendService.getJobTrends()));
  }

  @GetMapping("/api/market/trends/indicators")
  @Operation(summary = "시장 트렌드 지표 조회", description = "지역별/경력별 채용 공고 지표를 조회합니다.")
  public ResponseEntity<ApiResponse<List<MarketTrendResponse.Indicator>>> getIndicators() {
    return ResponseEntity.ok(ApiResponse.ok(marketTrendService.getIndicators()));
  }

  @GetMapping("/api/admin/market/reports")
  @Operation(summary = "관리자 채용 분석 리포트 조회", description = "관리자용 채용 시장 요약 리포트를 조회합니다.")
  public ResponseEntity<ApiResponse<MarketTrendResponse.AdminReport>> getAdminReport() {
    return ResponseEntity.ok(ApiResponse.ok(marketTrendService.getAdminReport()));
  }
}
