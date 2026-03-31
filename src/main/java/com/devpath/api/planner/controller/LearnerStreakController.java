package com.devpath.api.planner.controller;

import static com.devpath.common.security.AuthenticationUtils.requireUserId;

import com.devpath.api.planner.dto.RecoveryPlanRequest;
import com.devpath.api.planner.dto.RecoveryPlanResponse;
import com.devpath.api.planner.dto.StreakResponse;
import com.devpath.api.planner.service.LearnerStreakService;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/me/streaks")
@RequiredArgsConstructor
@Tag(name = "Learner - Streak", description = "Learner streak management API")
public class LearnerStreakController {

    private final LearnerStreakService learnerStreakService;

    @GetMapping
    @Operation(summary = "Get streak", description = "Get streak data for the authenticated user.")
    public ApiResponse<StreakResponse> getStreak(
            @Parameter(hidden = true) @AuthenticationPrincipal Long learnerId
    ) {
        return ApiResponse.ok(learnerStreakService.getStreak(requireUserId(learnerId)));
    }

    @PostMapping("/refresh")
    @Operation(summary = "Refresh streak", description = "Refresh streak data for the authenticated user.")
    public ApiResponse<StreakResponse> refreshStreak(
            @Parameter(hidden = true) @AuthenticationPrincipal Long learnerId
    ) {
        return ApiResponse.ok(learnerStreakService.refreshStreak(requireUserId(learnerId)));
    }

    @PostMapping("/recovery-plans")
    @Operation(summary = "Create recovery plan", description = "Create a recovery plan for the authenticated user.")
    public ApiResponse<RecoveryPlanResponse> createRecoveryPlan(
            @Parameter(hidden = true) @AuthenticationPrincipal Long learnerId,
            @Valid @RequestBody RecoveryPlanRequest request
    ) {
        return ApiResponse.ok(learnerStreakService.createRecoveryPlan(requireUserId(learnerId), request));
    }
}
