package com.devpath.api.study.controller;

import com.devpath.api.study.dto.StudyMatchRecommendationResponse;
import com.devpath.api.study.dto.StudyMatchResponse;
import com.devpath.api.study.service.StudyMatchService;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/study-matches")
@RequiredArgsConstructor
@Tag(name = "Learner - Study Match", description = "학습자 자동 매칭 및 추천 API")
public class StudyMatchController {

    private final StudyMatchService studyMatchService;

    @GetMapping
    @Operation(summary = "내 매칭 내역 조회", description = "내가 요청했거나 받은 스터디 매칭 내역을 조회합니다.")
    public ApiResponse<List<StudyMatchResponse>> getMyMatches(
            @RequestParam(defaultValue = "1") Long learnerId) { // TODO: Spring Security 연동 시 Authentication 적용
        return ApiResponse.ok(studyMatchService.getMyMatches(learnerId));
    }

    @GetMapping("/recommendations")
    @Operation(summary = "자동 매칭 추천 조회", description = "나와 같은 노드를 진행 중인 학습자 목록을 매칭 점수순으로 추천받습니다.")
    public ApiResponse<List<StudyMatchRecommendationResponse>> getRecommendations(
            @RequestParam(defaultValue = "1") Long learnerId) {
        return ApiResponse.ok(studyMatchService.getRecommendations(learnerId));
    }
}