package com.devpath.api.learner.controller;

import com.devpath.api.common.dto.ApiResponse;
import com.devpath.api.learner.dto.NodeRecommendationDto;
import com.devpath.api.learner.service.NodeRecommendationService;
import com.devpath.common.exception.CustomException;
import com.devpath.common.exception.ErrorCode;
import com.devpath.domain.roadmap.entity.NodeRecommendation;
import com.devpath.domain.roadmap.entity.Roadmap;
import com.devpath.domain.roadmap.entity.RecommendationStatus;
import com.devpath.domain.roadmap.repository.RoadmapRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/me")
@RequiredArgsConstructor
@Tag(name = "학습자 - 노드 추천", description = "AI 기반 로드맵 노드 추천 관리 API")
public class NodeRecommendationController {

    private final NodeRecommendationService nodeRecommendationService;
    private final RoadmapRepository roadmapRepository;

    @PostMapping("/roadmaps/{roadmapId}/recommendations/init")
    @Operation(
            summary = "AI 추천 노드 생성",
            description = "진단 퀴즈 결과를 바탕으로 AI가 추천하는 보강/심화 노드를 생성합니다. 기존 PENDING 상태 추천은 만료 처리됩니다."
    )
    public ResponseEntity<ApiResponse<NodeRecommendationDto.GenerateRecommendationsResponse>> generateRecommendations(
            @Parameter(description = "로드맵 ID") @PathVariable Long roadmapId
    ) {
        // TODO: SecurityContext에서 userId 추출
        Long userId = 1L;

        // 추천 생성
        List<NodeRecommendation> recommendations = nodeRecommendationService.generateRecommendations(userId, roadmapId);

        NodeRecommendationDto.GenerateRecommendationsResponse response =
                NodeRecommendationDto.GenerateRecommendationsResponse.from(roadmapId, recommendations);

        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @GetMapping("/roadmaps/{roadmapId}/recommendations")
    @Operation(
            summary = "로드맵 추천 목록 조회",
            description = "특정 로드맵의 모든 추천 노드를 조회합니다. PENDING 상태인 추천만 필터링하거나 전체 추천을 조회할 수 있습니다."
    )
    public ResponseEntity<ApiResponse<NodeRecommendationDto.RoadmapRecommendationsResponse>> getRecommendations(
            @Parameter(description = "로드맵 ID") @PathVariable Long roadmapId,
            @Parameter(description = "PENDING 상태만 조회 여부") @RequestParam(defaultValue = "true") Boolean pendingOnly
    ) {
        // TODO: SecurityContext에서 userId 추출
        Long userId = 1L;

        // 로드맵 조회
        Roadmap roadmap = roadmapRepository.findById(roadmapId)
                .orElseThrow(() -> new CustomException(ErrorCode.ROADMAP_NOT_FOUND));

        // 추천 목록 조회
        List<NodeRecommendation> recommendations = pendingOnly
                ? nodeRecommendationService.getPendingRecommendations(userId, roadmapId)
                : nodeRecommendationService.getRecommendations(userId, roadmapId);

        // 상태별 카운트
        long pendingCount = recommendations.stream()
                .filter(r -> r.getStatus() == RecommendationStatus.PENDING)
                .count();

        long acceptedCount = recommendations.stream()
                .filter(r -> r.getStatus() == RecommendationStatus.ACCEPTED)
                .count();

        long rejectedCount = recommendations.stream()
                .filter(r -> r.getStatus() == RecommendationStatus.REJECTED)
                .count();

        NodeRecommendationDto.RoadmapRecommendationsResponse response =
                NodeRecommendationDto.RoadmapRecommendationsResponse.builder()
                        .roadmapId(roadmapId)
                        .roadmapTitle(roadmap.getTitle())
                        .totalRecommendations(recommendations.size())
                        .pendingCount((int) pendingCount)
                        .acceptedCount((int) acceptedCount)
                        .rejectedCount((int) rejectedCount)
                        .recommendations(
                                recommendations.stream()
                                        .map(NodeRecommendationDto.RecommendationResponse::from)
                                        .collect(Collectors.toList())
                        )
                        .build();

        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @PatchMapping("/recommendations/{recommendationId}/accept")
    @Operation(
            summary = "추천 수락",
            description = "AI가 추천한 노드를 수락합니다. 수락 시 해당 노드가 사용자의 커스텀 로드맵에 추가됩니다."
    )
    public ResponseEntity<ApiResponse<NodeRecommendationDto.ProcessRecommendationResponse>> acceptRecommendation(
            @Parameter(description = "추천 ID") @PathVariable Long recommendationId
    ) {
        NodeRecommendation recommendation = nodeRecommendationService.acceptRecommendation(recommendationId);

        NodeRecommendationDto.ProcessRecommendationResponse response =
                NodeRecommendationDto.ProcessRecommendationResponse.from(
                        recommendation,
                        "추천 노드가 로드맵에 추가되었습니다."
                );

        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @PatchMapping("/recommendations/{recommendationId}/reject")
    @Operation(
            summary = "추천 거절",
            description = "AI가 추천한 노드를 거절합니다. 거절된 추천은 로드맵에 추가되지 않습니다."
    )
    public ResponseEntity<ApiResponse<NodeRecommendationDto.ProcessRecommendationResponse>> rejectRecommendation(
            @Parameter(description = "추천 ID") @PathVariable Long recommendationId
    ) {
        NodeRecommendation recommendation = nodeRecommendationService.rejectRecommendation(recommendationId);

        NodeRecommendationDto.ProcessRecommendationResponse response =
                NodeRecommendationDto.ProcessRecommendationResponse.from(
                        recommendation,
                        "추천을 거절했습니다."
                );

        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @PatchMapping("/recommendations/{recommendationId}/expire")
    @Operation(
            summary = "추천 만료 처리",
            description = "추천을 수동으로 만료 처리합니다."
    )
    public ResponseEntity<ApiResponse<NodeRecommendationDto.ProcessRecommendationResponse>> expireRecommendation(
            @Parameter(description = "추천 ID") @PathVariable Long recommendationId
    ) {
        NodeRecommendation recommendation = nodeRecommendationService.expireRecommendation(recommendationId);

        NodeRecommendationDto.ProcessRecommendationResponse response =
                NodeRecommendationDto.ProcessRecommendationResponse.from(
                        recommendation,
                        "추천이 만료되었습니다."
                );

        return ResponseEntity.ok(ApiResponse.success(response));
    }
}
