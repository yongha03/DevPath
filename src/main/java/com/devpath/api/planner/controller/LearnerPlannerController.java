package com.devpath.api.planner.controller;

import static com.devpath.common.security.AuthenticationUtils.requireUserId;

import com.devpath.api.planner.dto.PlannerGoalRequest;
import com.devpath.api.planner.dto.PlannerGoalResponse;
import com.devpath.api.planner.dto.WeeklyPlanRequest;
import com.devpath.api.planner.dto.WeeklyPlanResponse;
import com.devpath.api.planner.service.LearnerPlannerService;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/me/planner")
@RequiredArgsConstructor
@Tag(name = "Learner - Planner", description = "Learner planner and goal management API")
public class LearnerPlannerController {

    private final LearnerPlannerService learnerPlannerService;

    @PostMapping("/goals")
    @Operation(summary = "Create goal", description = "Create a learner goal for the authenticated user.")
    public ApiResponse<PlannerGoalResponse> createGoal(
            @Parameter(hidden = true) @AuthenticationPrincipal Long learnerId,
            @Valid @RequestBody PlannerGoalRequest request
    ) {
        return ApiResponse.ok(learnerPlannerService.createGoal(requireUserId(learnerId), request));
    }

    @GetMapping("/goals")
    @Operation(summary = "Get my goals", description = "Get learner goals for the authenticated user.")
    public ApiResponse<List<PlannerGoalResponse>> getMyGoals(
            @Parameter(hidden = true) @AuthenticationPrincipal Long learnerId
    ) {
        return ApiResponse.ok(learnerPlannerService.getMyGoals(requireUserId(learnerId)));
    }

    @PostMapping("/weekly-plans")
    @Operation(summary = "Create weekly plan", description = "Create a weekly plan for the authenticated user.")
    public ApiResponse<WeeklyPlanResponse> createWeeklyPlan(
            @Parameter(hidden = true) @AuthenticationPrincipal Long learnerId,
            @Valid @RequestBody WeeklyPlanRequest request
    ) {
        return ApiResponse.ok(learnerPlannerService.createWeeklyPlan(requireUserId(learnerId), request));
    }

    @GetMapping("/weekly-plans")
    @Operation(summary = "Get my weekly plans", description = "Get weekly plans for the authenticated user.")
    public ApiResponse<List<WeeklyPlanResponse>> getMyWeeklyPlans(
            @Parameter(hidden = true) @AuthenticationPrincipal Long learnerId
    ) {
        return ApiResponse.ok(learnerPlannerService.getMyWeeklyPlans(requireUserId(learnerId)));
    }

    @PutMapping("/weekly-plans/{planId}")
    @Operation(summary = "Update weekly plan", description = "Update a weekly plan owned by the authenticated user.")
    public ApiResponse<WeeklyPlanResponse> updateWeeklyPlan(
            @PathVariable Long planId,
            @Parameter(hidden = true) @AuthenticationPrincipal Long learnerId,
            @Valid @RequestBody WeeklyPlanRequest request
    ) {
        return ApiResponse.ok(learnerPlannerService.updateWeeklyPlan(requireUserId(learnerId), planId, request));
    }

    @PostMapping("/weekly-plans/{planId}/adjust")
    @Operation(summary = "Adjust weekly plan", description = "Adjust a weekly plan for the authenticated user.")
    public ApiResponse<WeeklyPlanResponse> adjustWeeklyPlan(
            @PathVariable Long planId,
            @Parameter(hidden = true) @AuthenticationPrincipal Long learnerId,
            @Valid @RequestBody WeeklyPlanRequest request
    ) {
        return ApiResponse.ok(learnerPlannerService.adjustWeeklyPlan(requireUserId(learnerId), planId, request));
    }
}
