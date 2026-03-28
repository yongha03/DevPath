package com.devpath.api.project.controller;

import com.devpath.api.project.dto.ProjectAdvancedRequests.RoleRequest;
import com.devpath.api.project.dto.ProjectAdvancedResponses.RoleResponse;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/projects/roles")
@RequiredArgsConstructor
@Tag(name = "Project - Role", description = "프로젝트 모집 역할 관리 API")
public class ProjectRoleController {

    @PostMapping
    @Operation(summary = "역할 추가", description = "프로젝트에 필요한 모집 역할을 추가합니다.")
    public ApiResponse<RoleResponse> addRole(@Valid @RequestBody RoleRequest request) {
        // TODO: Service 구현 연동
        return ApiResponse.ok(null);
    }

    @PutMapping("/{roleId}")
    @Operation(summary = "역할 수정", description = "모집 역할의 필요 인원 등을 수정합니다.")
    public ApiResponse<RoleResponse> updateRole(@PathVariable Long roleId, @Valid @RequestBody RoleRequest request) {
        // TODO: Service 구현 연동
        return ApiResponse.ok(null);
    }
}