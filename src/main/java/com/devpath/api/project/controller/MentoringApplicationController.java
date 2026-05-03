package com.devpath.api.project.controller;

import static com.devpath.common.security.AuthenticationUtils.requireUserId;

import com.devpath.api.project.dto.ProjectAdvancedRequests.MentoringRequest;
import com.devpath.api.project.dto.ProjectAdvancedResponses.MentoringResponse;
import com.devpath.api.project.service.MentoringApplicationService;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController("projectMentoringApplicationController")
@RequestMapping("/api/projects/mentoring-applications")
@RequiredArgsConstructor
@Tag(name = "Project - Mentoring", description = "Project mentoring application API")
public class MentoringApplicationController {

    private final MentoringApplicationService mentoringApplicationService;

    @PostMapping
    @Operation(summary = "Apply for mentoring", description = "Apply for mentoring for a project.")
    public ApiResponse<MentoringResponse> applyForMentoring(
            @Valid @RequestBody MentoringRequest request,
            @Parameter(hidden = true) @AuthenticationPrincipal Long requesterId
    ) {
        return ApiResponse.ok(mentoringApplicationService.applyForMentoring(request, requireUserId(requesterId)));
    }

    @GetMapping
    @Operation(summary = "Get mentoring applications", description = "Get mentoring applications for a project.")
    public ApiResponse<List<MentoringResponse>> getMentoringApplications(
            @RequestParam Long projectId,
            @Parameter(hidden = true) @AuthenticationPrincipal Long requesterId
    ) {
        return ApiResponse.ok(mentoringApplicationService.getMentoringApplications(projectId, requireUserId(requesterId)));
    }
}
