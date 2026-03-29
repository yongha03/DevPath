package com.devpath.api.learning.controller;

import com.devpath.api.learning.dto.LearningHistoryRequest;
import com.devpath.api.learning.dto.LearningHistoryResponse;
import com.devpath.api.learning.dto.TilResponse;
import com.devpath.api.learning.service.LearningHistoryService;
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

@Tag(name = "Learner - Learning History", description = "Learner learning history API")
@RestController
@RequestMapping("/api/me/learning-histories")
@RequiredArgsConstructor
public class LearningHistoryController {

    private final LearningHistoryService learningHistoryService;

    @Operation(summary = "Get learning history", description = "Returns the full learning history read model.")
    @GetMapping
    public ResponseEntity<ApiResponse<LearningHistoryResponse.Detail>> getLearningHistory(
        @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        return ResponseEntity.ok(ApiResponse.ok(learningHistoryService.getLearningHistory(userId)));
    }

    @Operation(summary = "Get learning history summary", description = "Returns the summary of learning history.")
    @GetMapping("/summary")
    public ResponseEntity<ApiResponse<LearningHistoryResponse.Summary>> getSummary(
        @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        return ResponseEntity.ok(ApiResponse.ok(learningHistoryService.getSummary(userId)));
    }

    @Operation(summary = "Get completed nodes", description = "Returns cleared roadmap nodes.")
    @GetMapping("/completed-nodes")
    public ResponseEntity<ApiResponse<List<LearningHistoryResponse.CompletedNodeDetail>>> getCompletedNodes(
        @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        return ResponseEntity.ok(ApiResponse.ok(learningHistoryService.getCompletedNodes(userId)));
    }

    @Operation(summary = "Get assignments", description = "Returns assignment submissions and grading results.")
    @GetMapping("/assignments")
    public ResponseEntity<ApiResponse<List<LearningHistoryResponse.AssignmentDetail>>> getAssignments(
        @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        return ResponseEntity.ok(ApiResponse.ok(learningHistoryService.getAssignments(userId)));
    }

    @Operation(summary = "Get TIL history", description = "Returns the TIL list for learning history.")
    @GetMapping("/til")
    public ResponseEntity<ApiResponse<List<TilResponse>>> getTilHistory(
        @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        return ResponseEntity.ok(ApiResponse.ok(learningHistoryService.getTilHistory(userId)));
    }

    @Operation(summary = "Create share link", description = "Creates a share link for learning history.")
    @PostMapping("/share-links")
    public ResponseEntity<ApiResponse<LearningHistoryResponse.ShareLinkDetail>> createShareLink(
        @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
        @Valid @RequestBody LearningHistoryRequest.CreateShareLink request
    ) {
        return ResponseEntity.ok(ApiResponse.ok(learningHistoryService.createShareLink(userId, request)));
    }

    @Operation(summary = "Get shared learning history", description = "Returns shared learning history by token.")
    @GetMapping("/share-links/{shareToken}")
    public ResponseEntity<ApiResponse<LearningHistoryResponse.SharedDetail>> getSharedLearningHistory(
        @Parameter(description = "Share token", example = "history-share-token-123") @PathVariable String shareToken
    ) {
        return ResponseEntity.ok(ApiResponse.ok(learningHistoryService.getSharedLearningHistory(shareToken)));
    }

    @Operation(summary = "Organize learning history", description = "Reassembles the learning history summary.")
    @PostMapping("/organize")
    public ResponseEntity<ApiResponse<LearningHistoryResponse.OrganizeResult>> organize(
        @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
        @Valid @RequestBody LearningHistoryRequest.Organize request
    ) {
        return ResponseEntity.ok(ApiResponse.ok(learningHistoryService.organize(userId, request)));
    }
}
