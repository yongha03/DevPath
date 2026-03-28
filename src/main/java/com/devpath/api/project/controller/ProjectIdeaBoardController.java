package com.devpath.api.project.controller;

import com.devpath.api.project.dto.ProjectAdvancedRequests.IdeaPostRequest;
import com.devpath.api.project.dto.ProjectAdvancedResponses.IdeaPostResponse;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.List;

@RestController
@RequestMapping("/api/project-ideas")
@RequiredArgsConstructor
@Tag(name = "Project - Idea Board", description = "프로젝트 아이디어 모집 게시판 API")
public class ProjectIdeaBoardController {

    @PostMapping
    @Operation(summary = "아이디어 게시글 작성", description = "새로운 프로젝트 아이디어와 팀원 모집 글을 작성합니다.")
    public ApiResponse<IdeaPostResponse> createIdeaPost(@Valid @RequestBody IdeaPostRequest request) {
        // TODO: Service 연동
        return ApiResponse.ok(null);
    }

    @GetMapping
    @Operation(summary = "게시글 목록 조회", description = "프로젝트 아이디어 게시글 목록을 조회합니다.")
    public ApiResponse<List<IdeaPostResponse>> getIdeaPostList() {
        // TODO: Service 연동 (페이징 추가 필요)
        return ApiResponse.ok(Collections.emptyList());
    }

    @GetMapping("/{ideaId}")
    @Operation(summary = "게시글 상세 조회", description = "특정 아이디어 게시글의 상세 내용을 조회합니다.")
    public ApiResponse<IdeaPostResponse> getIdeaPostDetail(@PathVariable Long ideaId) {
        // TODO: Service 연동
        return ApiResponse.ok(null);
    }

    @PutMapping("/{ideaId}")
    @Operation(summary = "게시글 수정", description = "작성한 아이디어 게시글을 수정합니다.")
    public ApiResponse<IdeaPostResponse> updateIdeaPost(@PathVariable Long ideaId, @Valid @RequestBody IdeaPostRequest request) {
        // TODO: Service 연동
        return ApiResponse.ok(null);
    }

    @DeleteMapping("/{ideaId}")
    @Operation(summary = "게시글 삭제", description = "작성한 아이디어 게시글을 삭제(Soft Delete)합니다.")
    public ApiResponse<Void> deleteIdeaPost(@PathVariable Long ideaId) {
        // TODO: Service 연동
        return ApiResponse.ok(null);
    }
}