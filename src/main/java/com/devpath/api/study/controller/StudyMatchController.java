package com.devpath.api.study.controller;

import static com.devpath.common.security.AuthenticationUtils.requireUserId;

import com.devpath.api.study.dto.StudyMatchRecommendationResponse;
import com.devpath.api.study.dto.StudyMatchResponse;
import com.devpath.api.study.service.StudyMatchService;
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
@RequestMapping("/api/study-matches")
@RequiredArgsConstructor
@Tag(name = "Learner - Study Match", description = "Learner study match and recommendation API")
public class StudyMatchController {

    private final StudyMatchService studyMatchService;

    @GetMapping
    @Operation(summary = "Get my matches")
    public ApiResponse<List<StudyMatchResponse>> getMyMatches(
            @Parameter(hidden = true) @AuthenticationPrincipal Long learnerId
    ) {
        return ApiResponse.ok(studyMatchService.getMyMatches(requireUserId(learnerId)));
    }

    @GetMapping("/recommendations")
    @Operation(summary = "Get study match recommendations")
    public ApiResponse<List<StudyMatchRecommendationResponse>> getRecommendations(
            @Parameter(hidden = true) @AuthenticationPrincipal Long learnerId
    ) {
        return ApiResponse.ok(studyMatchService.getRecommendations(requireUserId(learnerId)));
    }
}
