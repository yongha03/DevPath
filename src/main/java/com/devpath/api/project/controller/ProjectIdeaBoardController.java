package com.devpath.api.project.controller;

import static com.devpath.common.security.AuthenticationUtils.requireUserId;

import com.devpath.api.project.dto.ProjectAdvancedRequests.IdeaPostRequest;
import com.devpath.api.project.dto.ProjectAdvancedResponses.IdeaPostResponse;
import com.devpath.api.project.service.ProjectIdeaBoardService;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/project-ideas")
@RequiredArgsConstructor
@Tag(name = "Project - Idea Board", description = "Project idea board API")
public class ProjectIdeaBoardController {

    private final ProjectIdeaBoardService projectIdeaBoardService;

    @PostMapping
    @Operation(summary = "Create idea post", description = "Create an idea post for the authenticated user.")
    public ApiResponse<IdeaPostResponse> createIdeaPost(
            @Valid @RequestBody IdeaPostRequest request,
            @Parameter(hidden = true) @AuthenticationPrincipal Long authorId
    ) {
        return ApiResponse.ok(projectIdeaBoardService.createIdeaPost(request, requireUserId(authorId)));
    }

    @GetMapping
    @Operation(summary = "Get idea posts", description = "Get all idea posts.")
    public ApiResponse<List<IdeaPostResponse>> getIdeaPostList() {
        return ApiResponse.ok(projectIdeaBoardService.getIdeaPostList());
    }

    @GetMapping("/{ideaId}")
    @Operation(summary = "Get idea post", description = "Get one idea post by id.")
    public ApiResponse<IdeaPostResponse> getIdeaPostDetail(@PathVariable Long ideaId) {
        return ApiResponse.ok(projectIdeaBoardService.getIdeaPostDetail(ideaId));
    }

    @PutMapping("/{ideaId}")
    @Operation(summary = "Update idea post", description = "Update an idea post owned by the authenticated user.")
    public ApiResponse<IdeaPostResponse> updateIdeaPost(
            @PathVariable Long ideaId,
            @Valid @RequestBody IdeaPostRequest request,
            @Parameter(hidden = true) @AuthenticationPrincipal Long requesterId
    ) {
        return ApiResponse.ok(projectIdeaBoardService.updateIdeaPost(ideaId, request, requireUserId(requesterId)));
    }

    @DeleteMapping("/{ideaId}")
    @Operation(summary = "Delete idea post", description = "Delete an idea post owned by the authenticated user.")
    public ApiResponse<Void> deleteIdeaPost(
            @PathVariable Long ideaId,
            @Parameter(hidden = true) @AuthenticationPrincipal Long requesterId
    ) {
        projectIdeaBoardService.deleteIdeaPost(ideaId, requireUserId(requesterId));
        return ApiResponse.ok();
    }
}
