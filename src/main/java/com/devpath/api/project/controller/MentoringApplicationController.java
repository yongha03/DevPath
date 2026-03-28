package com.devpath.api.project.controller;

import com.devpath.api.project.dto.ProjectAdvancedRequests.MentoringRequest;
import com.devpath.api.project.dto.ProjectAdvancedResponses.MentoringResponse;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.List;

@RestController
@RequestMapping("/api/projects/mentoring-applications")
@RequiredArgsConstructor
@Tag(name = "Project - Mentoring", description = "프로젝트 멘토링 지원 API")
public class MentoringApplicationController {

    @PostMapping
    @Operation(summary = "멘토링 지원 신청", description = "팀 프로젝트를 위한 멘토링을 신청합니다.")
    public ApiResponse<MentoringResponse> applyForMentoring(@Valid @RequestBody MentoringRequest request) {
        // TODO: Service 구현 연동
        return ApiResponse.ok(null);
    }

    @GetMapping
    @Operation(summary = "멘토링 지원 목록 조회", description = "현재 프로젝트가 지원한 멘토링 목록을 조회합니다.")
    public ApiResponse<List<MentoringResponse>> getMentoringApplications(@RequestParam Long projectId) {
        // TODO: Service 구현 연동
        return ApiResponse.ok(Collections.emptyList());
    }
}