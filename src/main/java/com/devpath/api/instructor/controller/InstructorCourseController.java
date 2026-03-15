package com.devpath.api.instructor.controller;

import com.devpath.api.common.dto.CourseDetailResponse;
import com.devpath.api.instructor.dto.InstructorAnnouncementDto;
import com.devpath.api.instructor.dto.InstructorCourseDto;
import com.devpath.api.instructor.dto.InstructorLessonDto;
import com.devpath.api.instructor.dto.InstructorMaterialDto;
import com.devpath.api.instructor.dto.InstructorNodeClassificationDto;
import com.devpath.api.instructor.dto.InstructorNodeCoverageDto;
import com.devpath.api.instructor.dto.InstructorSectionDto;
import com.devpath.api.instructor.service.InstructorAnnouncementQueryService;
import com.devpath.api.instructor.service.InstructorAnnouncementService;
import com.devpath.api.instructor.service.InstructorCourseQueryService;
import com.devpath.api.instructor.service.InstructorCourseService;
import com.devpath.api.instructor.service.InstructorNodeClassificationQueryService;
import com.devpath.api.instructor.service.InstructorNodeCoverageQueryService;
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

// 강사가 자신의 강의와 하위 데이터를 관리하는 API를 제공한다.
@Tag(name = "강사 강의 API", description = "강사가 자신의 강의와 부가 데이터를 관리하는 API")
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/instructor")
public class InstructorCourseController {

  private final InstructorAnnouncementService instructorAnnouncementService;
  private final InstructorAnnouncementQueryService instructorAnnouncementQueryService;
  private final InstructorCourseService instructorCourseService;
  private final InstructorCourseQueryService instructorCourseQueryService;
  private final InstructorNodeClassificationQueryService instructorNodeClassificationQueryService;
  private final InstructorNodeCoverageQueryService instructorNodeCoverageQueryService;

  // 강의 생성 API다.
  @Operation(summary = "강의 생성")
  @PostMapping("/courses")
  public ApiResponse<Long> createCourse(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @Valid @RequestBody InstructorCourseDto.CreateCourseRequest request) {
    Long courseId = instructorCourseService.createCourse(userId, request);
    return ApiResponse.success("강의가 생성되었습니다.", courseId);
  }

  // 강의 상세 조회 API다.
  @Operation(summary = "강의 상세 조회")
  @GetMapping("/courses/{courseId}")
  public ApiResponse<CourseDetailResponse> getCourseDetail(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long courseId) {
    CourseDetailResponse response = instructorCourseQueryService.getCourseDetail(userId, courseId);
    return ApiResponse.success("강의 상세 정보를 조회했습니다.", response);
  }

  // 강의 수정 API다.
  @Operation(summary = "강의 수정")
  @PutMapping("/courses/{courseId}")
  public ApiResponse<Void> updateCourse(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long courseId,
      @Valid @RequestBody InstructorCourseDto.UpdateCourseRequest request) {
    instructorCourseService.updateCourse(userId, courseId, request);
    return ApiResponse.success("강의가 수정되었습니다.", null);
  }

  // 강의 삭제 API다.
  @Operation(summary = "강의 삭제")
  @DeleteMapping("/courses/{courseId}")
  public ApiResponse<Void> deleteCourse(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long courseId) {
    instructorCourseService.deleteCourse(userId, courseId);
    return ApiResponse.success("강의가 삭제되었습니다.", null);
  }

  // 강사가 특정 강의에 공지를 등록한다.
  @Operation(summary = "강의 공지 등록")
  @PostMapping("/courses/{courseId}/announcements")
  public ApiResponse<Long> createAnnouncement(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long courseId,
      @Valid @RequestBody InstructorAnnouncementDto.CreateAnnouncementRequest request) {
    Long announcementId =
        instructorAnnouncementService.createAnnouncement(userId, courseId, request);
    return ApiResponse.success("강의 공지가 등록되었습니다.", announcementId);
  }

  // 강사가 특정 강의의 공지 목록을 조회한다.
  @Operation(summary = "강의 공지 목록 조회")
  @GetMapping("/courses/{courseId}/announcements")
  public ApiResponse<List<InstructorAnnouncementDto.AnnouncementSummaryResponse>> getAnnouncements(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long courseId) {
    List<InstructorAnnouncementDto.AnnouncementSummaryResponse> response =
        instructorAnnouncementQueryService.getAnnouncements(userId, courseId);
    return ApiResponse.success("강의 공지 목록을 조회했습니다.", response);
  }

  // 강사가 특정 공지의 고정 여부를 변경한다.
  @Operation(summary = "강의 공지 고정 여부 변경")
  @PatchMapping("/courses/{courseId}/announcements/{announcementId}/pin")
  public ApiResponse<Void> updateAnnouncementPin(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long courseId,
      @PathVariable Long announcementId,
      @Valid @RequestBody InstructorAnnouncementDto.UpdateAnnouncementPinRequest request) {
    instructorAnnouncementService.updateAnnouncementPin(userId, courseId, announcementId, request);
    return ApiResponse.success("강의 공지 고정 여부가 변경되었습니다.", null);
  }

  // 강사가 특정 강의의 공지 노출 순서를 일괄 변경한다.
  @Operation(summary = "강의 공지 노출 순서 변경")
  @PatchMapping("/courses/{courseId}/announcements/order")
  public ApiResponse<Void> updateAnnouncementOrder(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long courseId,
      @Valid @RequestBody InstructorAnnouncementDto.UpdateAnnouncementOrderRequest request) {
    instructorAnnouncementService.updateAnnouncementDisplayOrder(userId, courseId, request);
    return ApiResponse.success("강의 공지 노출 순서가 변경되었습니다.", null);
  }

  // 강사가 특정 공지의 상세 정보를 조회한다.
  @Operation(summary = "강의 공지 상세 조회")
  @GetMapping("/announcements/{announcementId}")
  public ApiResponse<InstructorAnnouncementDto.AnnouncementDetailResponse> getAnnouncementDetail(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long announcementId) {
    InstructorAnnouncementDto.AnnouncementDetailResponse response =
        instructorAnnouncementQueryService.getAnnouncementDetail(userId, announcementId);
    return ApiResponse.success("강의 공지 상세 정보를 조회했습니다.", response);
  }

  // 강사가 특정 공지를 수정한다.
  @Operation(summary = "강의 공지 수정")
  @PutMapping("/announcements/{announcementId}")
  public ApiResponse<Void> updateAnnouncement(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long announcementId,
      @Valid @RequestBody InstructorAnnouncementDto.UpdateAnnouncementRequest request) {
    instructorAnnouncementService.updateAnnouncement(userId, announcementId, request);
    return ApiResponse.success("강의 공지가 수정되었습니다.", null);
  }

  // 강사가 특정 공지를 삭제한다.
  @Operation(summary = "강의 공지 삭제")
  @DeleteMapping("/announcements/{announcementId}")
  public ApiResponse<Void> deleteAnnouncement(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long announcementId) {
    instructorAnnouncementService.deleteAnnouncement(userId, announcementId);
    return ApiResponse.success("강의 공지가 삭제되었습니다.", null);
  }

  // 강의 상태 변경 API다.
  @Operation(summary = "강의 상태 변경")
  @PatchMapping("/courses/{courseId}/status")
  public ApiResponse<Void> updateCourseStatus(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long courseId,
      @Valid @RequestBody InstructorCourseDto.UpdateStatusRequest request) {
    instructorCourseService.updateCourseStatus(userId, courseId, request);
    return ApiResponse.success("강의 상태가 변경되었습니다.", null);
  }

  // 섹션 생성 API다.
  @Operation(summary = "섹션 생성")
  @PostMapping("/courses/{courseId}/sections")
  public ApiResponse<Long> createSection(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long courseId,
      @Valid @RequestBody InstructorSectionDto.CreateSectionRequest request) {
    Long sectionId = instructorCourseService.createSection(userId, courseId, request);
    return ApiResponse.success("섹션이 생성되었습니다.", sectionId);
  }

  // 섹션 수정 API다.
  @Operation(summary = "섹션 수정")
  @PutMapping("/sections/{sectionId}")
  public ApiResponse<Void> updateSection(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long sectionId,
      @Valid @RequestBody InstructorSectionDto.UpdateSectionRequest request) {
    instructorCourseService.updateSection(userId, sectionId, request);
    return ApiResponse.success("섹션이 수정되었습니다.", null);
  }

  // 섹션 삭제 API다.
  @Operation(summary = "섹션 삭제")
  @DeleteMapping("/sections/{sectionId}")
  public ApiResponse<Void> deleteSection(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long sectionId) {
    instructorCourseService.deleteSection(userId, sectionId);
    return ApiResponse.success("섹션이 삭제되었습니다.", null);
  }

  // 레슨 생성 API다.
  @Operation(summary = "레슨 생성")
  @PostMapping("/sections/{sectionId}/lessons")
  public ApiResponse<Long> createLesson(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long sectionId,
      @Valid @RequestBody InstructorLessonDto.CreateLessonRequest request) {
    Long lessonId = instructorCourseService.createLesson(userId, sectionId, request);
    return ApiResponse.success("레슨이 생성되었습니다.", lessonId);
  }

  // 레슨 수정 API다.
  @Operation(summary = "레슨 수정")
  @PutMapping("/lessons/{lessonId}")
  public ApiResponse<Void> updateLesson(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long lessonId,
      @Valid @RequestBody InstructorLessonDto.UpdateLessonRequest request) {
    instructorCourseService.updateLesson(userId, lessonId, request);
    return ApiResponse.success("레슨이 수정되었습니다.", null);
  }

  // 레슨 선행 조건 목록을 전체 교체한다.
  @Operation(summary = "레슨 선행 조건 전체 교체")
  @PutMapping("/lessons/{lessonId}/prerequisites")
  public ApiResponse<InstructorLessonDto.UpdateLessonPrerequisitesResponse>
      updateLessonPrerequisites(
          @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
          @PathVariable Long lessonId,
          @Valid @RequestBody InstructorLessonDto.UpdateLessonPrerequisitesRequest request) {
    InstructorLessonDto.UpdateLessonPrerequisitesResponse response =
        instructorCourseService.updateLessonPrerequisites(userId, lessonId, request);
    return ApiResponse.success("레슨 선행 조건이 저장되었습니다.", response);
  }

  // 레슨 삭제 API다.
  @Operation(summary = "레슨 삭제")
  @DeleteMapping("/lessons/{lessonId}")
  public ApiResponse<Void> deleteLesson(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long lessonId) {
    instructorCourseService.deleteLesson(userId, lessonId);
    return ApiResponse.success("레슨이 삭제되었습니다.", null);
  }

  // 레슨 순서를 일괄 변경한다.
  @Operation(summary = "레슨 순서 변경")
  @PatchMapping("/lessons/order")
  public ApiResponse<Void> updateLessonOrder(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @Valid @RequestBody InstructorLessonDto.UpdateLessonOrderRequest request) {
    instructorCourseService.updateLessonOrder(userId, request);
    return ApiResponse.success("레슨 순서가 변경되었습니다.", null);
  }

  // 강의 메타데이터를 수정한다.
  @Operation(summary = "강의 메타데이터 수정")
  @PatchMapping("/courses/{courseId}/metadata")
  public ApiResponse<Void> updateCourseMetadata(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long courseId,
      @Valid @RequestBody InstructorCourseDto.UpdateMetadataRequest request) {
    instructorCourseService.updateCourseMetadata(userId, courseId, request);
    return ApiResponse.success("강의 메타데이터가 수정되었습니다.", null);
  }

  // 강의 목표를 전체 교체한다.
  @Operation(summary = "강의 목표 전체 교체")
  @PostMapping("/courses/{courseId}/objectives")
  public ApiResponse<Void> replaceObjectives(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long courseId,
      @Valid @RequestBody InstructorCourseDto.ReplaceObjectivesRequest request) {
    instructorCourseService.replaceObjectives(userId, courseId, request);
    return ApiResponse.success("강의 목표가 저장되었습니다.", null);
  }

  // 수강 대상을 전체 교체한다.
  @Operation(summary = "강의 수강 대상 전체 교체")
  @PostMapping("/courses/{courseId}/target-audiences")
  public ApiResponse<Void> replaceTargetAudiences(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long courseId,
      @Valid @RequestBody InstructorCourseDto.ReplaceTargetAudiencesRequest request) {
    instructorCourseService.replaceTargetAudiences(userId, courseId, request);
    return ApiResponse.success("강의 수강 대상이 저장되었습니다.", null);
  }

  // 레슨 첨부 자료를 생성한다.
  @Operation(summary = "레슨 자료 등록")
  @PostMapping("/lessons/{lessonId}/materials")
  public ApiResponse<Long> createMaterial(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long lessonId,
      @Valid @RequestBody InstructorMaterialDto.CreateMaterialRequest request) {
    Long materialId = instructorCourseService.createMaterial(userId, lessonId, request);
    return ApiResponse.success("레슨 자료가 등록되었습니다.", materialId);
  }

  // 강의 썸네일을 등록한다.
  @Operation(summary = "강의 썸네일 등록")
  @PostMapping("/courses/{courseId}/thumbnail")
  public ApiResponse<Void> uploadThumbnail(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long courseId,
      @Valid @RequestBody InstructorCourseDto.UploadThumbnailRequest request) {
    instructorCourseService.uploadThumbnail(userId, courseId, request);
    return ApiResponse.success("강의 썸네일이 등록되었습니다.", null);
  }

  // 강의 트레일러를 등록한다.
  @Operation(summary = "강의 트레일러 등록")
  @PostMapping("/courses/{courseId}/trailer")
  public ApiResponse<Void> uploadTrailer(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long courseId,
      @Valid @RequestBody InstructorCourseDto.UploadTrailerRequest request) {
    instructorCourseService.uploadTrailer(userId, courseId, request);
    return ApiResponse.success("강의 트레일러가 등록되었습니다.", null);
  }

  // 강의 태그 기반 자동 노드 분류 결과를 조회한다.
  @Operation(summary = "강의 자동 노드 분류 결과 조회")
  @GetMapping("/courses/{courseId}/node-classifications")
  public ApiResponse<InstructorNodeClassificationDto.AutoClassificationResponse>
      getCourseNodeClassifications(
          @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
          @PathVariable Long courseId) {
    InstructorNodeClassificationDto.AutoClassificationResponse response =
        instructorNodeClassificationQueryService.getAutoClassifications(userId, courseId);

    return ApiResponse.success("강의 자동 노드 분류 결과를 조회했습니다.", response);
  }

  // 강의 태그 기반 노드 커버리지 결과를 조회한다.
  @Operation(summary = "강의 노드 태그 커버리지 조회")
  @GetMapping("/courses/{courseId}/node-coverages")
  public ApiResponse<InstructorNodeCoverageDto.NodeCoverageResponse> getCourseNodeCoverages(
      @Parameter(hidden = true) @AuthenticationPrincipal Long userId,
      @PathVariable Long courseId) {
    InstructorNodeCoverageDto.NodeCoverageResponse response =
        instructorNodeCoverageQueryService.getNodeCoverages(userId, courseId);

    return ApiResponse.success("강의 노드 태그 커버리지를 조회했습니다.", response);
  }
}
