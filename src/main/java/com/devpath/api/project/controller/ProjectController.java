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
@Tag(name = "프로젝트 - 기본", description = "프로젝트 생성 및 관리 API")
public class ProjectController {

    private final ProjectService projectService;

    @PostMapping
    @Operation(summary = "프로젝트 생성", description = "새 팀 프로젝트를 생성합니다.")
    public ApiResponse<ProjectResponse> createProject(
            @Valid @RequestBody ProjectRequest request,
            @Parameter(hidden = true) @AuthenticationPrincipal Long creatorId
    ) {
        return ApiResponse.ok(projectService.createProject(request, requireUserId(creatorId)));
    }

    @GetMapping
    @Operation(summary = "프로젝트 목록 조회", description = "전체 프로젝트 목록을 조회합니다.")
    public ApiResponse<List<ProjectResponse>> getAllProjects() {
        return ApiResponse.ok(projectService.getAllProjects());
    }

    @GetMapping("/{projectId}")
    @Operation(summary = "프로젝트 상세 조회", description = "프로젝트 상세 정보를 조회합니다.")
    public ApiResponse<ProjectResponse> getProject(@PathVariable Long projectId) {
        return ApiResponse.ok(projectService.getProject(projectId));
    }

    @PutMapping("/{projectId}")
    @Operation(summary = "프로젝트 수정", description = "로그인한 프로젝트 멤버가 프로젝트를 수정합니다.")
    public ApiResponse<ProjectResponse> updateProject(
            @PathVariable Long projectId,
            @Valid @RequestBody ProjectRequest request,
            @Parameter(hidden = true) @AuthenticationPrincipal Long requesterId
    ) {
        return ApiResponse.ok(projectService.updateProject(projectId, requireUserId(requesterId), request));
    }
}
