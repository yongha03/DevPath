package com.devpath.api.project.controller;

import com.devpath.api.project.dto.ProjectAdvancedRequests.ProofSubmissionRequest;
import com.devpath.api.project.dto.ProjectAdvancedResponses.ProofSubmissionResponse;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.List;

@RestController
@RequestMapping("/api/projects/proof-submissions")
@RequiredArgsConstructor
@Tag(name = "Project - Proof Submission", description = "Proof Card 기반 이력 제출 API")
public class ProjectProofSubmissionController {

    @PostMapping
    @Operation(summary = "증명서 제출", description = "발급받은 Proof Card를 프로젝트 이력으로 제출합니다.")
    public ApiResponse<ProofSubmissionResponse> submitProof(@Valid @RequestBody ProofSubmissionRequest request) {
        // TODO: Service 연동
        return ApiResponse.ok(null);
    }

    @GetMapping
    @Operation(summary = "제출 내역 목록 조회", description = "특정 프로젝트에 제출된 Proof Card 이력을 조회합니다.")
    public ApiResponse<List<ProofSubmissionResponse>> getSubmissions(@RequestParam Long projectId) {
        // TODO: Service 연동
        return ApiResponse.ok(Collections.emptyList());
    }

    @GetMapping("/{submissionId}")
    @Operation(summary = "제출 내역 상세 조회", description = "특정 제출 건의 상세 정보를 조회합니다.")
    public ApiResponse<ProofSubmissionResponse> getSubmissionDetail(@PathVariable Long submissionId) {
        // TODO: Service 연동
        return ApiResponse.ok(null);
    }
}