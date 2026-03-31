package com.devpath.api.project.controller;

import static com.devpath.common.security.AuthenticationUtils.requireUserId;

import com.devpath.api.project.dto.ProjectAdvancedRequests.ProofSubmissionRequest;
import com.devpath.api.project.dto.ProjectAdvancedResponses.ProofSubmissionResponse;
import com.devpath.api.project.service.ProjectProofSubmissionService;
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
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/projects/proof-submissions")
@RequiredArgsConstructor
@Tag(name = "Project - Proof Submission", description = "Project proof submission API")
public class ProjectProofSubmissionController {

    private final ProjectProofSubmissionService projectProofSubmissionService;

    @PostMapping
    @Operation(summary = "Submit proof", description = "Submit a proof card for the authenticated user.")
    public ApiResponse<ProofSubmissionResponse> submitProof(
            @Valid @RequestBody ProofSubmissionRequest request,
            @Parameter(hidden = true) @AuthenticationPrincipal Long submitterId
    ) {
        return ApiResponse.ok(projectProofSubmissionService.submitProof(request, requireUserId(submitterId)));
    }

    @GetMapping
    @Operation(summary = "Get submissions", description = "Get proof submissions for one project.")
    public ApiResponse<List<ProofSubmissionResponse>> getSubmissions(@RequestParam Long projectId) {
        return ApiResponse.ok(projectProofSubmissionService.getSubmissions(projectId));
    }

    @GetMapping("/{submissionId}")
    @Operation(summary = "Get submission", description = "Get one proof submission by id.")
    public ApiResponse<ProofSubmissionResponse> getSubmissionDetail(@PathVariable Long submissionId) {
        return ApiResponse.ok(projectProofSubmissionService.getSubmissionDetail(submissionId));
    }
}
