package com.devpath.api.planner.controller;

import com.devpath.api.planner.dto.StreakResponse;
import com.devpath.api.planner.service.LearnerStreakService;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;

@RestController
@RequestMapping("/api/me/streaks")
@RequiredArgsConstructor
@Tag(name = "Learner - Streak", description = "학습자 스트릭(잔디) 관리 API")
public class LearnerStreakController {

    private final LearnerStreakService learnerStreakService;

    // TODO: 추후 Spring Security 도입 시 @AuthenticationPrincipal을 통해 learnerId를 추출하도록 변경
    @GetMapping
    @Operation(summary = "내 스트릭 조회", description = "현재 로그인한 사용자의 스트릭 현황을 조회합니다.")
    public ApiResponse<StreakResponse> getMyStreak(@RequestParam(defaultValue = "1") Long learnerId) {
        StreakResponse response = learnerStreakService.getStreak(learnerId);
        return ApiResponse.ok(response);
    }

    @PostMapping("/refresh")
    @Operation(summary = "스트릭 갱신", description = "오늘 자 학습을 완료하여 스트릭을 갱신합니다.")
    public ApiResponse<StreakResponse> refreshStreak(@RequestParam(defaultValue = "1") Long learnerId) {
        // 실제 운영에서는 클라이언트 시간이 아닌 서버 시간(LocalDate.now())을 사용합니다.
        StreakResponse response = learnerStreakService.refreshStreak(learnerId, LocalDate.now());
        return ApiResponse.ok(response);
    }
}