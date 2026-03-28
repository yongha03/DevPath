package com.devpath.api.project.controller;

import com.devpath.api.project.dto.ProjectAdvancedRequests.InvitationRequest;
import com.devpath.api.project.dto.ProjectAdvancedResponses.InvitationResponse;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/projects/invitations")
@RequiredArgsConstructor
@Tag(name = "Project - Invitation", description = "프로젝트 팀원 초대 API")
public class ProjectInvitationController {

    @PostMapping
    @Operation(summary = "팀원 초대", description = "특정 유저를 프로젝트 팀원으로 초대합니다.")
    public ApiResponse<InvitationResponse> inviteMember(@Valid @RequestBody InvitationRequest request) {
        // TODO: Service 구현 연동
        return ApiResponse.ok(null);
    }

    @PostMapping("/{invitationId}/accept")
    @Operation(summary = "초대 수락", description = "받은 프로젝트 초대를 수락합니다.")
    public ApiResponse<Void> acceptInvitation(@PathVariable Long invitationId) {
        // TODO: Service 구현 연동
        return ApiResponse.ok(null);
    }

    @PostMapping("/{invitationId}/reject")
    @Operation(summary = "초대 거절", description = "받은 프로젝트 초대를 거절합니다.")
    public ApiResponse<Void> rejectInvitation(@PathVariable Long invitationId) {
        // TODO: Service 구현 연동
        return ApiResponse.ok(null);
    }
}