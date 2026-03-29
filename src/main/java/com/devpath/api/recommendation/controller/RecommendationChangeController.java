package com.devpath.api.recommendation.controller;

import com.devpath.api.recommendation.dto.RecommendationChangeRequest;
import com.devpath.api.recommendation.dto.RecommendationChangeResponse;
import com.devpath.api.recommendation.service.RecommendationChangeService;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "Learner - Recommendation Change", description = "Learner recommendation change API")
@RestController
@RequestMapping("/api/me/recommendation-changes")
@RequiredArgsConstructor
public class RecommendationChangeController {

    private final RecommendationChangeService recommendationChangeService;

    @Operation(
        summary = "Create recommendation change suggestions",
        description = "Creates recommendation change suggestions from supplement recommendations and learning signals."
    )
    @PostMapping("/suggestions")
    public ResponseEntity<ApiResponse<List<RecommendationChangeResponse.Detail>>> createSuggestions(
        @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
        @Valid @RequestBody RecommendationChangeRequest.Suggestion request
    ) {
        return ResponseEntity.ok(ApiResponse.ok(recommendationChangeService.createSuggestions(userId, request)));
    }

    @Operation(summary = "Get recommendation changes", description = "Returns current recommendation change suggestions.")
    @GetMapping
    public ResponseEntity<ApiResponse<List<RecommendationChangeResponse.Detail>>> getRecommendationChanges(
        @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        return ResponseEntity.ok(ApiResponse.ok(recommendationChangeService.getRecommendationChanges(userId)));
    }

    @Operation(summary = "Apply recommendation change", description = "Applies a recommendation change suggestion.")
    @PostMapping("/{changeId}/apply")
    public ResponseEntity<ApiResponse<RecommendationChangeResponse.Detail>> apply(
        @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
        @Parameter(description = "Recommendation change id", example = "1") @PathVariable Long changeId
    ) {
        return ResponseEntity.ok(ApiResponse.ok(recommendationChangeService.apply(userId, changeId)));
    }

    @Operation(summary = "Ignore recommendation change", description = "Ignores a recommendation change suggestion.")
    @PostMapping("/{changeId}/ignore")
    public ResponseEntity<ApiResponse<RecommendationChangeResponse.Detail>> ignore(
        @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
        @Parameter(description = "Recommendation change id", example = "1") @PathVariable Long changeId
    ) {
        return ResponseEntity.ok(ApiResponse.ok(recommendationChangeService.ignore(userId, changeId)));
    }

    @Operation(
        summary = "Get recommendation change histories",
        description = "Returns applied, ignored, and recalculated recommendation changes."
    )
    @GetMapping("/histories")
    public ResponseEntity<ApiResponse<List<RecommendationChangeResponse.HistoryItem>>> getHistories(
        @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        return ResponseEntity.ok(ApiResponse.ok(recommendationChangeService.getHistories(userId)));
    }

    @Operation(
        summary = "Recalculate next recommendation changes",
        description = "Marks current suggestions as recalculated and regenerates recommendation change suggestions."
    )
    @PostMapping("/recalculate-next-nodes")
    public ResponseEntity<ApiResponse<RecommendationChangeResponse.RecalculateResult>> recalculateNextNodes(
        @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
        @Valid @RequestBody RecommendationChangeRequest.RecalculateNextNodes request
    ) {
        return ResponseEntity.ok(ApiResponse.ok(recommendationChangeService.recalculateNextNodes(userId, request)));
    }
}
