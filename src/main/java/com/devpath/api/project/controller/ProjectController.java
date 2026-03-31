package com.devpath.api.project.controller;

import static com.devpath.common.security.AuthenticationUtils.requireUserId;

import com.devpath.api.project.dto.ProjectRequest;
import com.devpath.api.project.dto.ProjectResponse;
import com.devpath.api.project.service.ProjectService;
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
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/projects")
@RequiredArgsConstructor
@Tag(name = "Project - Core", description = "Project creation and management API")
public class ProjectController {

    private final ProjectService projectService;

    @PostMapping
    @Operation(summary = "Create project", description = "Create a new team project.")
    public ApiResponse<ProjectResponse> createProject(
            @Valid @RequestBody ProjectRequest request,
            @Parameter(hidden = true) @AuthenticationPrincipal Long creatorId
    ) {
        return ApiResponse.ok(projectService.createProject(request, requireUserId(creatorId)));
    }

    @GetMapping
    @Operation(summary = "Get projects", description = "Get all projects.")
    public ApiResponse<List<ProjectResponse>> getAllProjects() {
        return ApiResponse.ok(projectService.getAllProjects());
    }

    @GetMapping("/{projectId}")
    @Operation(summary = "Get project", description = "Get project detail.")
    public ApiResponse<ProjectResponse> getProject(@PathVariable Long projectId) {
        return ApiResponse.ok(projectService.getProject(projectId));
    }

    @PutMapping("/{projectId}")
    @Operation(summary = "Update project", description = "Update a project as an authenticated member.")
    public ApiResponse<ProjectResponse> updateProject(
            @PathVariable Long projectId,
            @Valid @RequestBody ProjectRequest request,
            @Parameter(hidden = true) @AuthenticationPrincipal Long requesterId
    ) {
        return ApiResponse.ok(projectService.updateProject(projectId, requireUserId(requesterId), request));
    }
}
