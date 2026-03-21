package com.devpath.api.community.controller;

import com.devpath.api.community.dto.PostRequest;
import com.devpath.api.community.dto.PostResponse;
import com.devpath.api.community.service.CommunityService;
import com.devpath.common.response.ApiResponse;
import com.devpath.domain.community.entity.CommunityCategory;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/posts")
@RequiredArgsConstructor
@Tag(name = "Community API", description = "일반 커뮤니티 게시판 CRUD API")
public class CommunityController {

    private final CommunityService communityService;

    @PostMapping
    @Operation(summary = "게시글 작성", description = "커뮤니티에 새로운 글을 작성합니다.")
    public ApiResponse<PostResponse> createPost(
            // TODO: 추후 Spring Security의 @AuthenticationPrincipal 로 대체
            @RequestParam Long userId,
            @Valid @RequestBody PostRequest request) {

        PostResponse response = communityService.createPost(userId, request);
        return ApiResponse.ok(response); // 수정: success -> ok
    }

    @GetMapping
    @Operation(summary = "카테고리별 게시글 목록 조회", description = "특정 카테고리의 게시글을 최신순으로 조회합니다.")
    public ApiResponse<List<PostResponse>> getPosts(
            @RequestParam CommunityCategory category) {

        List<PostResponse> responses = communityService.getPostsByCategory(category);
        return ApiResponse.ok(responses); // 수정: success -> ok
    }

    @GetMapping("/{postId}")
    @Operation(summary = "게시글 상세 조회", description = "게시글 상세 정보를 조회하고 조회수를 증가시킵니다.")
    public ApiResponse<PostResponse> getPostDetail(@PathVariable Long postId) {

        PostResponse response = communityService.getPostDetail(postId);
        return ApiResponse.ok(response); // 수정: success -> ok
    }
}