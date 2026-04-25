package com.devpath.api.dashboard.controller;

import static com.devpath.common.security.AuthenticationUtils.requireUserId;

import com.devpath.api.dashboard.dto.DashboardGrowthRecommendationResponse;
import com.devpath.api.dashboard.dto.DashboardMentoringResponse;
import com.devpath.api.dashboard.dto.DashboardStudyGroupResponse;
import com.devpath.api.dashboard.dto.DashboardSummaryResponse;
import com.devpath.api.dashboard.dto.HeatmapResponse;
import com.devpath.api.dashboard.service.LearnerDashboardService;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/me/dashboard")
@RequiredArgsConstructor
@Tag(name = "Learner - Dashboard", description = "Learner dashboard API")
public class LearnerDashboardController {

    private final LearnerDashboardService dashboardService;

    @GetMapping("/summary")
    @Operation(summary = "Get dashboard summary", description = "Get dashboard summary for the authenticated user.")
    public ApiResponse<DashboardSummaryResponse> getSummary(
            @Parameter(hidden = true) @AuthenticationPrincipal Long learnerId
    ) {
        return ApiResponse.ok(dashboardService.getSummary(requireUserId(learnerId)));
    }

    @GetMapping("/heatmap")
    @Operation(summary = "Get heatmap", description = "Get learning heatmap data for the authenticated user.")
    public ApiResponse<List<HeatmapResponse>> getHeatmap(
            @Parameter(hidden = true) @AuthenticationPrincipal Long learnerId
    ) {
        return ApiResponse.ok(dashboardService.getHeatmap(requireUserId(learnerId)));
    }

    @GetMapping("/study-group")
    @Operation(summary = "Get dashboard study group", description = "Get study group summary for the authenticated user.")
    public ApiResponse<DashboardStudyGroupResponse> getDashboardStudyGroup(
            @Parameter(hidden = true) @AuthenticationPrincipal Long learnerId
    ) {
        return ApiResponse.ok(dashboardService.getDashboardStudyGroup(requireUserId(learnerId)));
    }

    @GetMapping("/mentoring")
    @Operation(summary = "Get dashboard mentoring summary", description = "Get mentoring summary for projects joined by the authenticated user.")
    public ApiResponse<DashboardMentoringResponse> getDashboardMentoring(
            @Parameter(hidden = true) @AuthenticationPrincipal Long learnerId
    ) {
        return ApiResponse.ok(dashboardService.getDashboardMentoring(requireUserId(learnerId)));
    }

    @GetMapping("/growth-recommendation")
    @Operation(summary = "Get AI growth recommendation", description = "Get AI-powered growth recommendation based on the learner's proof card tags.")
    public ApiResponse<DashboardGrowthRecommendationResponse> getGrowthRecommendation(
            @Parameter(hidden = true) @AuthenticationPrincipal Long learnerId
    ) {
        return ApiResponse.ok(dashboardService.getGrowthRecommendation(requireUserId(learnerId)));
    }
}
