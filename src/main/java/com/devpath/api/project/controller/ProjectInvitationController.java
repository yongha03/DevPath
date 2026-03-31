package com.devpath.api.project.controller;

import static com.devpath.common.security.AuthenticationUtils.requireUserId;

import com.devpath.api.project.dto.ProjectAdvancedRequests.InvitationRequest;
import com.devpath.api.project.dto.ProjectAdvancedResponses.InvitationResponse;
import com.devpath.api.project.service.ProjectInvitationService;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/projects/invitations")
@RequiredArgsConstructor
@Tag(name = "Project - Invitation", description = "Project invitation API")
public class ProjectInvitationController {

    private final ProjectInvitationService projectInvitationService;

    @PostMapping
    @Operation(summary = "Invite member", description = "Invite one user to the project.")
    public ApiResponse<InvitationResponse> inviteMember(
            @Valid @RequestBody InvitationRequest request,
            @Parameter(hidden = true) @AuthenticationPrincipal Long inviterId
    ) {
        return ApiResponse.ok(projectInvitationService.inviteMember(request, requireUserId(inviterId)));
    }

    @PostMapping("/{invitationId}/accept")
    @Operation(summary = "Accept invitation", description = "Accept an invitation addressed to the authenticated user.")
    public ApiResponse<InvitationResponse> acceptInvitation(
            @PathVariable Long invitationId,
            @Parameter(hidden = true) @AuthenticationPrincipal Long learnerId
    ) {
        return ApiResponse.ok(projectInvitationService.acceptInvitation(invitationId, requireUserId(learnerId)));
    }

    @PostMapping("/{invitationId}/reject")
    @Operation(summary = "Reject invitation", description = "Reject an invitation addressed to the authenticated user.")
    public ApiResponse<InvitationResponse> rejectInvitation(
            @PathVariable Long invitationId,
            @Parameter(hidden = true) @AuthenticationPrincipal Long learnerId
    ) {
        return ApiResponse.ok(projectInvitationService.rejectInvitation(invitationId, requireUserId(learnerId)));
    }
}
