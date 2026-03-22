package com.devpath.api.learning.controller;

import com.devpath.api.learning.dto.LessonProgressRequest;
import com.devpath.api.learning.dto.LessonProgressResponse;
import com.devpath.api.learning.service.LessonProgressService;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "강의 학습 - 진도율", description = "강의 세션 시작 및 진도율 저장/조회 API")
@RestController
@RequestMapping("/api/learning/sessions")
@RequiredArgsConstructor
public class LessonProgressController {

    private final LessonProgressService lessonProgressService;

    @Operation(
            summary = "강의 세션 시작",
            description = "강의 시청을 시작합니다. 최초 진입 시 진도 이력을 생성하고 이어보기 위치를 반환합니다."
    )
    @PostMapping("/{lessonId}/start")
    public ResponseEntity<ApiResponse<LessonProgressResponse>> startSession(
            @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
            @Parameter(description = "레슨 ID", example = "10") @PathVariable Long lessonId
    ) {
        return ResponseEntity.status(HttpStatus.OK)
                .body(ApiResponse.ok(lessonProgressService.startSession(userId, lessonId)));
    }

    @Operation(
            summary = "진도율 저장",
            description = "현재 재생 위치(초)와 진도율(%)을 저장합니다. progressSeconds는 플레이어 이어보기 기준값으로 사용됩니다."
    )
    @PutMapping("/{lessonId}/progress")
    public ResponseEntity<ApiResponse<LessonProgressResponse>> saveProgress(
            @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
            @Parameter(description = "레슨 ID", example = "10") @PathVariable Long lessonId,
            @Valid @RequestBody LessonProgressRequest.SaveProgress request
    ) {
        return ResponseEntity.ok(ApiResponse.ok(lessonProgressService.saveProgress(userId, lessonId, request)));
    }

    @Operation(
            summary = "진도율 조회",
            description = "현재 저장된 진도율과 재생 위치를 조회합니다. progressSeconds는 항상 함께 반환됩니다."
    )
    @GetMapping("/{lessonId}/progress")
    public ResponseEntity<ApiResponse<LessonProgressResponse>> getProgress(
            @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
            @Parameter(description = "레슨 ID", example = "10") @PathVariable Long lessonId
    ) {
        return ResponseEntity.ok(ApiResponse.ok(lessonProgressService.getProgress(userId, lessonId)));
    }
}
