package com.devpath.api.dashboard.controller;

import com.devpath.api.dashboard.dto.DashboardSummaryResponse;
import com.devpath.api.dashboard.dto.HeatmapResponse;
import com.devpath.api.dashboard.service.LearnerDashboardService;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/me/dashboard")
@RequiredArgsConstructor
@Tag(name = "Learner - Dashboard", description = "학습자 대시보드 통계 API")
public class LearnerDashboardController {

    private final LearnerDashboardService dashboardService;

    @GetMapping("/summary")
    @Operation(summary = "대시보드 요약 통계", description = "총 학습 시간, 클리어 노드 수 등을 반환합니다.")
    public ApiResponse<DashboardSummaryResponse> getSummary(
            @RequestParam(defaultValue = "1") Long learnerId) {
        return ApiResponse.ok(dashboardService.getSummary(learnerId));
    }

    @GetMapping("/heatmap")
    @Operation(summary = "학습 활동 히트맵", description = "일자별 학습 활동 레벨(잔디)을 반환합니다.")
    public ApiResponse<List<HeatmapResponse>> getHeatmap(
            @RequestParam(defaultValue = "1") Long learnerId) {
        return ApiResponse.ok(dashboardService.getHeatmap(learnerId));
    }
}