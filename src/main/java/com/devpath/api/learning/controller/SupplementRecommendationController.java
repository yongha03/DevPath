package com.devpath.api.learning.controller;

import com.devpath.api.learning.dto.RecommendationHistoryResponse;
import com.devpath.api.learning.dto.RiskWarningResponse;
import com.devpath.api.learning.dto.SupplementRecommendationResponse;
import com.devpath.api.learning.service.SupplementRecommendationService;
import com.devpath.common.response.ApiResponse;
import com.devpath.domain.learning.entity.recommendation.RecommendationStatus;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "보강 노드 추천", description = "학습 진행 기반 자동 후보 생성과 수동 확인/거절 API")
@RestController
@RequestMapping("/api/learning/supplement-recommendations")
@RequiredArgsConstructor
public class SupplementRecommendationController {

    private final SupplementRecommendationService supplementRecommendationService;

    @Operation(
            summary = "보강 노드 후보 생성",
            description = "nodeId가 없으면 학습 진행 데이터로 자동 후보를 만들고 있으면 해당 노드를 수동 추천으로 저장합니다."
    )
    @PostMapping
    public ResponseEntity<ApiResponse<SupplementRecommendationResponse>> createRecommendation(
            @AuthenticationPrincipal Long userId,
            @RequestParam(required = false) Long nodeId,
            @RequestParam(required = false) String reason
    ) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.ok(supplementRecommendationService.createRecommendation(userId, nodeId, reason)));
    }

    @Operation(summary = "보강 노드 추천 목록 조회", description = "status 파라미터로 PENDING/APPROVED/REJECTED 필터링이 가능합니다.")
    @GetMapping
    public ResponseEntity<ApiResponse<List<SupplementRecommendationResponse>>> getRecommendations(
            @AuthenticationPrincipal Long userId,
            @RequestParam(required = false) RecommendationStatus status
    ) {
        return ResponseEntity.ok(ApiResponse.ok(supplementRecommendationService.getRecommendations(userId, status)));
    }

    @Operation(summary = "보강 노드 추천 승인", description = "학습자가 보강 노드 추천을 승인합니다.")
    @PatchMapping("/{recommendationId}/approve")
    public ResponseEntity<ApiResponse<SupplementRecommendationResponse>> approveRecommendation(
            @AuthenticationPrincipal Long userId,
            @PathVariable Long recommendationId
    ) {
        return ResponseEntity.ok(ApiResponse.ok(supplementRecommendationService.approveRecommendation(userId, recommendationId)));
    }

    @Operation(summary = "보강 노드 추천 거절", description = "학습자가 보강 노드 추천을 거절합니다.")
    @PatchMapping("/{recommendationId}/reject")
    public ResponseEntity<ApiResponse<SupplementRecommendationResponse>> rejectRecommendation(
            @AuthenticationPrincipal Long userId,
            @PathVariable Long recommendationId
    ) {
        return ResponseEntity.ok(ApiResponse.ok(supplementRecommendationService.rejectRecommendation(userId, recommendationId)));
    }

    @Operation(
            summary = "추천 변경 이력 조회",
            description = "recommendationId 또는 nodeId로 필터링할 수 있으며, 둘 다 없으면 전체 추천 변경 이력을 조회합니다."
    )
    @GetMapping("/histories")
    public ResponseEntity<ApiResponse<List<RecommendationHistoryResponse>>> getRecommendationHistories(
            @AuthenticationPrincipal Long userId,
            @RequestParam(required = false) Long recommendationId,
            @RequestParam(required = false) Long nodeId
    ) {
        return ResponseEntity.ok(
                ApiResponse.ok(
                        supplementRecommendationService.getRecommendationHistories(userId, recommendationId, nodeId)
                )
        );
    }

    @Operation(
            summary = "추천 리스크 경고 조회",
            description = "unacknowledgedOnly=true면 미확인 경고만 조회하고, nodeId로 특정 노드 경고만 필터링할 수 있습니다."
    )
    @GetMapping("/risk-warnings")
    public ResponseEntity<ApiResponse<List<RiskWarningResponse>>> getRiskWarnings(
            @AuthenticationPrincipal Long userId,
            @RequestParam(required = false) Boolean unacknowledgedOnly,
            @RequestParam(required = false) Long nodeId
    ) {
        return ResponseEntity.ok(
                ApiResponse.ok(
                        supplementRecommendationService.getRiskWarnings(userId, unacknowledgedOnly, nodeId)
                )
        );
    }
}
