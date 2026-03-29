package com.devpath.api.analytics.controller;

import com.devpath.api.analytics.dto.InstructorAnalyticsAssignmentResponse;
import com.devpath.api.analytics.dto.InstructorAnalyticsDifficultyResponse;
import com.devpath.api.analytics.dto.InstructorAnalyticsDropOffResponse;
import com.devpath.api.analytics.dto.InstructorAnalyticsFunnelResponse;
import com.devpath.api.analytics.dto.InstructorAnalyticsOverviewResponse;
import com.devpath.api.analytics.dto.InstructorAnalyticsProgressResponse;
import com.devpath.api.analytics.dto.InstructorAnalyticsQuizResponse;
import com.devpath.api.analytics.dto.InstructorAnalyticsStudentResponse;
import com.devpath.api.analytics.dto.InstructorAnalyticsWeakPointResponse;
import com.devpath.api.analytics.service.InstructorLearningAnalyticsService;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "Instructor - Learning Analytics", description = "Instructor learning analytics API")
@RestController
@RequestMapping("/api/instructor/analytics")
@RequiredArgsConstructor
public class InstructorLearningAnalyticsController {

    private final InstructorLearningAnalyticsService instructorLearningAnalyticsService;

    @Operation(summary = "Get analytics overview", description = "Returns the instructor-wide analytics overview.")
    @GetMapping("/overview")
    public ResponseEntity<ApiResponse<InstructorAnalyticsOverviewResponse.Detail>> getOverview(
        @Parameter(hidden = true) @AuthenticationPrincipal Long instructorId
    ) {
        return ResponseEntity.ok(ApiResponse.ok(instructorLearningAnalyticsService.getOverview(instructorId)));
    }

    @Operation(summary = "Get students", description = "Returns student analytics across the instructor's courses.")
    @GetMapping("/students")
    public ResponseEntity<ApiResponse<List<InstructorAnalyticsStudentResponse.StudentItem>>> getStudents(
        @Parameter(hidden = true) @AuthenticationPrincipal Long instructorId
    ) {
        return ResponseEntity.ok(ApiResponse.ok(instructorLearningAnalyticsService.getStudents(instructorId)));
    }

    @Operation(summary = "Get progress", description = "Returns course-level progress analytics.")
    @GetMapping("/progress")
    public ResponseEntity<ApiResponse<List<InstructorAnalyticsProgressResponse.CourseProgressItem>>> getProgress(
        @Parameter(hidden = true) @AuthenticationPrincipal Long instructorId
    ) {
        return ResponseEntity.ok(ApiResponse.ok(instructorLearningAnalyticsService.getProgress(instructorId)));
    }

    @Operation(summary = "Get completion rate", description = "Returns course-level completion rates.")
    @GetMapping("/completion-rate")
    public ResponseEntity<ApiResponse<List<InstructorAnalyticsProgressResponse.CompletionRateItem>>> getCompletionRate(
        @Parameter(hidden = true) @AuthenticationPrincipal Long instructorId
    ) {
        return ResponseEntity.ok(ApiResponse.ok(instructorLearningAnalyticsService.getCompletionRate(instructorId)));
    }

    @Operation(summary = "Get average watch time", description = "Returns course-level average watch time.")
    @GetMapping("/average-watch-time")
    public ResponseEntity<ApiResponse<List<InstructorAnalyticsProgressResponse.AverageWatchTimeItem>>> getAverageWatchTime(
        @Parameter(hidden = true) @AuthenticationPrincipal Long instructorId
    ) {
        return ResponseEntity.ok(ApiResponse.ok(instructorLearningAnalyticsService.getAverageWatchTime(instructorId)));
    }

    @Operation(summary = "Get assignment stats", description = "Returns assignment submission and grading analytics.")
    @GetMapping("/assignment-stats")
    public ResponseEntity<ApiResponse<InstructorAnalyticsAssignmentResponse.Detail>> getAssignmentStats(
        @Parameter(hidden = true) @AuthenticationPrincipal Long instructorId
    ) {
        return ResponseEntity.ok(ApiResponse.ok(instructorLearningAnalyticsService.getAssignmentStats(instructorId)));
    }

    @Operation(summary = "Get quiz stats", description = "Returns quiz attempt analytics.")
    @GetMapping("/quiz-stats")
    public ResponseEntity<ApiResponse<InstructorAnalyticsQuizResponse.Detail>> getQuizStats(
        @Parameter(hidden = true) @AuthenticationPrincipal Long instructorId
    ) {
        return ResponseEntity.ok(ApiResponse.ok(instructorLearningAnalyticsService.getQuizStats(instructorId)));
    }

    @Operation(summary = "Get drop-off", description = "Returns lesson-level drop-off analytics.")
    @GetMapping("/drop-off")
    public ResponseEntity<ApiResponse<List<InstructorAnalyticsDropOffResponse.LessonItem>>> getDropOff(
        @Parameter(hidden = true) @AuthenticationPrincipal Long instructorId
    ) {
        return ResponseEntity.ok(ApiResponse.ok(instructorLearningAnalyticsService.getDropOff(instructorId)));
    }

    @Operation(summary = "Get difficulty", description = "Returns node-level difficulty analytics.")
    @GetMapping("/difficulty")
    public ResponseEntity<ApiResponse<List<InstructorAnalyticsDifficultyResponse.NodeItem>>> getDifficulty(
        @Parameter(hidden = true) @AuthenticationPrincipal Long instructorId
    ) {
        return ResponseEntity.ok(ApiResponse.ok(instructorLearningAnalyticsService.getDifficulty(instructorId)));
    }

    @Operation(summary = "Get student progress", description = "Returns students sorted by progress.")
    @GetMapping("/student-progress")
    public ResponseEntity<ApiResponse<List<InstructorAnalyticsStudentResponse.StudentItem>>> getStudentProgress(
        @Parameter(hidden = true) @AuthenticationPrincipal Long instructorId
    ) {
        return ResponseEntity.ok(ApiResponse.ok(instructorLearningAnalyticsService.getStudentProgress(instructorId)));
    }

    @Operation(summary = "Get question performance", description = "Returns quiz-level performance analytics.")
    @GetMapping("/question-performance")
    public ResponseEntity<ApiResponse<List<InstructorAnalyticsQuizResponse.QuestionPerformanceItem>>> getQuestionPerformance(
        @Parameter(hidden = true) @AuthenticationPrincipal Long instructorId
    ) {
        return ResponseEntity.ok(ApiResponse.ok(instructorLearningAnalyticsService.getQuestionPerformance(instructorId)));
    }

    @Operation(summary = "Get funnel", description = "Returns enrollment-to-completion funnel analytics.")
    @GetMapping("/funnel")
    public ResponseEntity<ApiResponse<InstructorAnalyticsFunnelResponse.Detail>> getFunnel(
        @Parameter(hidden = true) @AuthenticationPrincipal Long instructorId
    ) {
        return ResponseEntity.ok(ApiResponse.ok(instructorLearningAnalyticsService.getFunnel(instructorId)));
    }

    @Operation(summary = "Get weak points", description = "Returns weak point analytics ordered by weakness score.")
    @GetMapping("/weak-points")
    public ResponseEntity<ApiResponse<List<InstructorAnalyticsWeakPointResponse.NodeItem>>> getWeakPoints(
        @Parameter(hidden = true) @AuthenticationPrincipal Long instructorId
    ) {
        return ResponseEntity.ok(ApiResponse.ok(instructorLearningAnalyticsService.getWeakPoints(instructorId)));
    }
}
