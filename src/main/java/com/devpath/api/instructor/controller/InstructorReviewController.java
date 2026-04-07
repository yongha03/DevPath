package com.devpath.api.instructor.controller;

import com.devpath.api.instructor.dto.review.InstructorReviewListResponse;
import com.devpath.api.instructor.dto.review.ReviewHelpfulResponse;
import com.devpath.api.instructor.dto.review.ReviewIssueTagRequest;
import com.devpath.api.instructor.dto.review.ReviewReplyRequest;
import com.devpath.api.instructor.dto.review.ReviewReplyResponse;
import com.devpath.api.instructor.dto.review.ReviewStatusUpdateRequest;
import com.devpath.api.instructor.dto.review.ReviewSummaryResponse;
import com.devpath.api.instructor.dto.review.ReviewTemplateRequest;
import com.devpath.api.instructor.dto.review.ReviewTemplateResponse;
import com.devpath.api.instructor.service.InstructorReviewService;
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
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "Instructor - Review Operations", description = "Instructor review API")
@RestController
@RequestMapping("/api/instructor/reviews")
@RequiredArgsConstructor
public class InstructorReviewController {

    private final InstructorReviewService instructorReviewService;

    @Operation(summary = "List reviews")
    @GetMapping
    public ApiResponse<List<InstructorReviewListResponse>> getReviews(
            @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        return ApiResponse.success("Review list loaded.", instructorReviewService.getReviews(userId));
    }

    @Operation(summary = "Create review reply")
    @PostMapping("/{reviewId}/replies")
    public ApiResponse<ReviewReplyResponse> createReply(
            @PathVariable Long reviewId,
            @RequestBody @Valid ReviewReplyRequest request,
            @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        return ApiResponse.success("Reply created.", instructorReviewService.createReply(reviewId, userId, request));
    }

    @Operation(summary = "Update review reply")
    @PutMapping("/{reviewId}/replies/{replyId}")
    public ApiResponse<ReviewReplyResponse> updateReply(
            @PathVariable Long reviewId,
            @PathVariable Long replyId,
            @RequestBody @Valid ReviewReplyRequest request,
            @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        return ApiResponse.success("Reply updated.", instructorReviewService.updateReply(reviewId, replyId, userId, request));
    }

    @Operation(summary = "Delete review reply")
    @DeleteMapping("/{reviewId}/replies/{replyId}")
    public ApiResponse<Void> deleteReply(
            @PathVariable Long reviewId,
            @PathVariable Long replyId,
            @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        instructorReviewService.deleteReply(reviewId, replyId, userId);
        return ApiResponse.success("Reply deleted.", null);
    }

    @Operation(summary = "Update review status")
    @PatchMapping("/{reviewId}/status")
    public ApiResponse<Void> updateStatus(
            @PathVariable Long reviewId,
            @RequestBody @Valid ReviewStatusUpdateRequest request,
            @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        instructorReviewService.updateStatus(reviewId, userId, request);
        return ApiResponse.success("Review status updated.", null);
    }

    @Operation(summary = "Add review issue tags")
    @PostMapping("/{reviewId}/issue-tags")
    public ApiResponse<Void> addIssueTags(
            @PathVariable Long reviewId,
            @RequestBody @Valid ReviewIssueTagRequest request,
            @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        instructorReviewService.addIssueTags(reviewId, userId, request);
        return ApiResponse.success("Issue tags added.", null);
    }

    @Operation(summary = "Get review summary")
    @GetMapping("/summary")
    public ApiResponse<ReviewSummaryResponse> getReviewSummary(
            @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        return ApiResponse.success("Review summary loaded.", instructorReviewService.getReviewSummary(userId));
    }

    @Operation(summary = "Get review helpful stats")
    @GetMapping("/helpful")
    public ApiResponse<ReviewHelpfulResponse> getHelpfulStats(
            @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        return ApiResponse.success("Review helpful stats loaded.", instructorReviewService.getHelpfulStats(userId));
    }

    @Operation(summary = "Create review template")
    @PostMapping("/templates")
    public ApiResponse<ReviewTemplateResponse> createTemplate(
            @RequestBody @Valid ReviewTemplateRequest request,
            @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        return ApiResponse.success("Template created.", instructorReviewService.createTemplate(userId, request));
    }

    @Operation(summary = "List review templates")
    @GetMapping("/templates")
    public ApiResponse<List<ReviewTemplateResponse>> getTemplates(
            @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        return ApiResponse.success("Templates loaded.", instructorReviewService.getTemplates(userId));
    }

    @Operation(summary = "Update review template")
    @PutMapping("/templates/{templateId}")
    public ApiResponse<ReviewTemplateResponse> updateTemplate(
            @PathVariable Long templateId,
            @RequestBody @Valid ReviewTemplateRequest request,
            @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        return ApiResponse.success("Template updated.", instructorReviewService.updateTemplate(templateId, userId, request));
    }

    @Operation(summary = "Delete review template")
    @DeleteMapping("/templates/{templateId}")
    public ApiResponse<Void> deleteTemplate(
            @PathVariable Long templateId,
            @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        instructorReviewService.deleteTemplate(templateId, userId);
        return ApiResponse.success("Template deleted.", null);
    }

    @Operation(summary = "Hide review")
    @PostMapping("/{reviewId}/hide")
    public ApiResponse<Void> hideReview(
            @PathVariable Long reviewId,
            @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        instructorReviewService.hideReview(reviewId, userId);
        return ApiResponse.success("Review hidden.", null);
    }

    @Operation(summary = "Resolve review report")
    @PostMapping("/{reviewId}/reports/resolve")
    public ApiResponse<Void> resolveReport(
            @PathVariable Long reviewId,
            @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        instructorReviewService.resolveReport(reviewId, userId);
        return ApiResponse.success("Review report resolved.", null);
    }
}
