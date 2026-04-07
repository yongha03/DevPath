package com.devpath.api.instructor.controller;

import com.devpath.api.common.dto.CourseDetailResponse;
import com.devpath.api.instructor.dto.InstructorCourseDto;
import com.devpath.api.instructor.dto.course.InstructorCourseListResponse;
import com.devpath.api.instructor.service.InstructorCourseQueryService;
import com.devpath.api.instructor.service.InstructorCourseService;
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

@Tag(name = "Instructor - Course Management", description = "Instructor course management API")
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/instructor")
public class InstructorCourseManagementController {

  private final InstructorCourseService instructorCourseService;
  private final InstructorCourseQueryService instructorCourseQueryService;

  @Operation(summary = "Create course")
  @PostMapping("/courses")
  public ApiResponse<Long> createCourse(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @Valid @RequestBody InstructorCourseDto.CreateCourseRequest request) {
    Long courseId = instructorCourseService.createCourse(userId, request);
    return ApiResponse.success("Course created.", courseId);
  }

  @Operation(summary = "List instructor courses")
  @GetMapping("/courses")
  public ApiResponse<List<InstructorCourseListResponse>> getCourses(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId) {
    return ApiResponse.success("Instructor courses loaded.", instructorCourseQueryService.getCourseList(userId));
  }

  @Operation(summary = "Get course detail")
  @GetMapping("/courses/{courseId}")
  public ApiResponse<CourseDetailResponse> getCourseDetail(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long courseId) {
    CourseDetailResponse response = instructorCourseQueryService.getCourseDetail(userId, courseId);
    return ApiResponse.success("Course detail loaded.", response);
  }

  @Operation(summary = "Update course")
  @PutMapping("/courses/{courseId}")
  public ApiResponse<Void> updateCourse(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long courseId,
      @Valid @RequestBody InstructorCourseDto.UpdateCourseRequest request) {
    instructorCourseService.updateCourse(userId, courseId, request);
    return ApiResponse.success("Course updated.", null);
  }

  @Operation(summary = "Delete course")
  @DeleteMapping("/courses/{courseId}")
  public ApiResponse<Void> deleteCourse(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long courseId) {
    instructorCourseService.deleteCourse(userId, courseId);
    return ApiResponse.success("Course deleted.", null);
  }

  @Operation(summary = "Update course status")
  @PatchMapping("/courses/{courseId}/status")
  public ApiResponse<Void> updateCourseStatus(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long courseId,
      @Valid @RequestBody InstructorCourseDto.UpdateStatusRequest request) {
    instructorCourseService.updateCourseStatus(userId, courseId, request);
    return ApiResponse.success("Course status updated.", null);
  }
}
