package com.devpath.api.project.controller;

import static com.devpath.common.security.AuthenticationUtils.requireUserId;

import com.devpath.api.project.dto.ProjectAdvancedRequests.RoleRequest;
import com.devpath.api.project.dto.ProjectAdvancedResponses.RoleResponse;
import com.devpath.api.project.service.ProjectRoleService;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/projects/roles")
@RequiredArgsConstructor
@Tag(name = "Project - Role", description = "Project role management API")
public class ProjectRoleController {

    private final ProjectRoleService projectRoleService;

    @PostMapping
    @Operation(summary = "Add role", description = "Add a role to a project.")
    public ApiResponse<RoleResponse> addRole(
            @Valid @RequestBody RoleRequest request,
            @Parameter(hidden = true) @AuthenticationPrincipal Long requesterId
    ) {
        return ApiResponse.ok(projectRoleService.addRole(request, requireUserId(requesterId)));
    }

    @PutMapping("/{roleId}")
    @Operation(summary = "Update role", description = "Update a role for a project.")
    public ApiResponse<RoleResponse> updateRole(
            @PathVariable Long roleId,
            @Valid @RequestBody RoleRequest request,
            @Parameter(hidden = true) @AuthenticationPrincipal Long requesterId
    ) {
        return ApiResponse.ok(projectRoleService.updateRole(roleId, request, requireUserId(requesterId)));
    }
}
