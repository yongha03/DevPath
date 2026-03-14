package com.devpath.api.instructor.service;

import com.devpath.api.instructor.dto.InstructorCourseDto;
import com.devpath.api.instructor.dto.InstructorLessonDto;
import com.devpath.api.instructor.dto.InstructorMaterialDto;
import com.devpath.api.instructor.dto.InstructorSectionDto;
import com.devpath.common.exception.CustomException;
import com.devpath.common.exception.ErrorCode;
import com.devpath.domain.course.entity.Course;
import com.devpath.domain.course.entity.CourseDifficultyLevel;
import com.devpath.domain.course.entity.CourseMaterial;
import com.devpath.domain.course.entity.CourseObjective;
import com.devpath.domain.course.entity.CourseSection;
import com.devpath.domain.course.entity.CourseStatus;
import com.devpath.domain.course.entity.CourseTagMap;
import com.devpath.domain.course.entity.CourseTargetAudience;
import com.devpath.domain.course.entity.Lesson;
import com.devpath.domain.course.entity.LessonType;
import com.devpath.domain.course.repository.CourseMaterialRepository;
import com.devpath.domain.course.repository.CourseObjectiveRepository;
import com.devpath.domain.course.repository.CourseRepository;
import com.devpath.domain.course.repository.CourseSectionRepository;
import com.devpath.domain.course.repository.CourseTagMapRepository;
import com.devpath.domain.course.repository.CourseTargetAudienceRepository;
import com.devpath.domain.course.repository.LessonRepository;
import com.devpath.domain.user.entity.Tag;
import com.devpath.domain.user.repository.TagRepository;
import com.devpath.domain.user.repository.UserRepository;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

// 강사용 강의/커리큘럼 관리 비즈니스 로직을 처리한다.
@Service
@RequiredArgsConstructor
public class InstructorCourseService {

  private final UserRepository userRepository;
  private final TagRepository tagRepository;

  private final CourseRepository courseRepository;
  private final CourseSectionRepository courseSectionRepository;
  private final LessonRepository lessonRepository;
  private final CourseMaterialRepository courseMaterialRepository;
  private final CourseObjectiveRepository courseObjectiveRepository;
  private final CourseTargetAudienceRepository courseTargetAudienceRepository;
  private final CourseTagMapRepository courseTagMapRepository;

  // 강사가 새 강의를 생성한다.
  @Transactional
  public Long createCourse(Long instructorId, InstructorCourseDto.CreateCourseRequest request) {
    validateAuthenticatedUser(instructorId);

    Course course =
        Course.builder()
            .instructorId(instructorId)
            .title(request.getTitle())
            .subtitle(request.getSubtitle())
            .description(request.getDescription())
            .price(request.getPrice())
            .originalPrice(request.getOriginalPrice())
            .currency(request.getCurrency())
            .difficultyLevel(toDifficultyLevel(request.getDifficultyLevel()))
            .status(CourseStatus.DRAFT)
            .language(request.getLanguage())
            .hasCertificate(request.getHasCertificate())
            .build();

    Course savedCourse = courseRepository.save(course);
    replaceCourseTags(savedCourse, request.getTagIds());
    return savedCourse.getCourseId();
  }

  // 강사가 자신의 강의 기본 정보를 수정한다.
  @Transactional
  public void updateCourse(
      Long instructorId, Long courseId, InstructorCourseDto.UpdateCourseRequest request) {
    validateAuthenticatedUser(instructorId);

    Course course = getOwnedCourse(instructorId, courseId);
    course.updateBasicInfo(
        request.getTitle(),
        request.getSubtitle(),
        request.getDescription(),
        request.getPrice(),
        request.getOriginalPrice(),
        request.getCurrency(),
        toDifficultyLevel(request.getDifficultyLevel()),
        request.getLanguage(),
        request.getHasCertificate());
  }

  // 강사가 자신의 강의 상태를 변경한다.
  @Transactional
  public void updateCourseStatus(
      Long instructorId, Long courseId, InstructorCourseDto.UpdateStatusRequest request) {
    validateAuthenticatedUser(instructorId);

    Course course = getOwnedCourse(instructorId, courseId);
    course.changeStatus(toCourseStatus(request.getStatus()));
  }

  // 강사가 자신의 강의를 삭제한다.
  @Transactional
  public void deleteCourse(Long instructorId, Long courseId) {
    validateAuthenticatedUser(instructorId);

    Course course = getOwnedCourse(instructorId, courseId);
    deleteCourseChildren(courseId);
    courseRepository.delete(course);
  }

  // 특정 강의에 섹션을 추가한다.
  @Transactional
  public Long createSection(
      Long instructorId, Long courseId, InstructorSectionDto.CreateSectionRequest request) {
    validateAuthenticatedUser(instructorId);

    Course course = getOwnedCourse(instructorId, courseId);

    CourseSection section =
        CourseSection.builder()
            .course(course)
            .title(request.getTitle())
            .description(request.getDescription())
            .orderIndex(request.getOrderIndex())
            .isPublished(request.getIsPublished())
            .build();

    CourseSection savedSection = courseSectionRepository.save(section);
    return savedSection.getSectionId();
  }

  // 강사가 자신의 섹션을 수정한다.
  @Transactional
  public void updateSection(
      Long instructorId, Long sectionId, InstructorSectionDto.UpdateSectionRequest request) {
    validateAuthenticatedUser(instructorId);

    CourseSection section = getOwnedSection(instructorId, sectionId);
    section.updateInfo(request.getTitle(), request.getDescription());
    section.changeOrderIndex(request.getOrderIndex());
    section.changePublished(request.getIsPublished());
  }

  // 강사가 자신의 섹션을 삭제한다.
  @Transactional
  public void deleteSection(Long instructorId, Long sectionId) {
    validateAuthenticatedUser(instructorId);

    CourseSection section = getOwnedSection(instructorId, sectionId);

    // 섹션 삭제 전 하위 레슨과 자료를 먼저 정리한다.
    List<Lesson> lessons =
        lessonRepository.findAllBySectionSectionIdOrderByOrderIndexAsc(section.getSectionId());

    for (Lesson lesson : lessons) {
      List<CourseMaterial> materials =
          courseMaterialRepository.findAllByLessonLessonIdOrderByDisplayOrderAsc(
              lesson.getLessonId());

      if (!materials.isEmpty()) {
        courseMaterialRepository.deleteAllInBatch(materials);
      }
    }

    if (!lessons.isEmpty()) {
      lessonRepository.deleteAllInBatch(lessons);
    }

    courseSectionRepository.delete(section);
  }

  // 특정 섹션에 레슨을 추가한다.
  @Transactional
  public Long createLesson(
      Long instructorId, Long sectionId, InstructorLessonDto.CreateLessonRequest request) {
    validateAuthenticatedUser(instructorId);

    CourseSection section = getOwnedSection(instructorId, sectionId);

    Lesson lesson =
        Lesson.builder()
            .section(section)
            .title(request.getTitle())
            .description(request.getDescription())
            .lessonType(toLessonType(request.getLessonType()))
            .videoId(request.getVideoId())
            .videoUrl(request.getVideoUrl())
            .videoProvider(request.getVideoProvider())
            .thumbnailUrl(request.getThumbnailUrl())
            .durationSeconds(request.getDurationSeconds())
            .orderIndex(request.getOrderIndex())
            .isPreview(request.getIsPreview())
            .isPublished(request.getIsPublished())
            .build();

    Lesson savedLesson = lessonRepository.save(lesson);
    return savedLesson.getLessonId();
  }

  // 강사가 자신의 레슨을 수정한다.
  @Transactional
  public void updateLesson(
      Long instructorId, Long lessonId, InstructorLessonDto.UpdateLessonRequest request) {
    validateAuthenticatedUser(instructorId);

    Lesson lesson = getOwnedLesson(instructorId, lessonId);
    lesson.updateInfo(
        request.getTitle(),
        request.getDescription(),
        toLessonType(request.getLessonType()),
        request.getVideoId(),
        request.getVideoUrl(),
        request.getVideoProvider(),
        request.getThumbnailUrl(),
        request.getDurationSeconds(),
        request.getIsPreview(),
        request.getIsPublished());
  }

  // 강사가 자신의 레슨을 삭제한다.
  @Transactional
  public void deleteLesson(Long instructorId, Long lessonId) {
    validateAuthenticatedUser(instructorId);

    Lesson lesson = getOwnedLesson(instructorId, lessonId);

    // 레슨 삭제 전 첨부 자료를 먼저 정리한다.
    List<CourseMaterial> materials =
        courseMaterialRepository.findAllByLessonLessonIdOrderByDisplayOrderAsc(lessonId);

    if (!materials.isEmpty()) {
      courseMaterialRepository.deleteAllInBatch(materials);
    }

    lessonRepository.delete(lesson);
  }

  // 동일 섹션 내 레슨 순서를 일괄 변경한다.
  @Transactional
  public void updateLessonOrder(
      Long instructorId, InstructorLessonDto.UpdateLessonOrderRequest request) {
    validateAuthenticatedUser(instructorId);

    CourseSection section = getOwnedSection(instructorId, request.getSectionId());

    List<Lesson> lessons =
        lessonRepository.findAllBySectionSectionIdOrderByOrderIndexAsc(section.getSectionId());

    validateLessonOrders(lessons, request);

    Map<Long, Lesson> lessonMap =
        lessons.stream().collect(Collectors.toMap(Lesson::getLessonId, Function.identity()));

    // 요청으로 들어온 순서 값으로 레슨의 orderIndex를 일괄 변경한다.
    for (InstructorLessonDto.LessonOrderItem item : request.getLessonOrders()) {
      Lesson lesson = lessonMap.get(item.getLessonId());
      lesson.changeOrderIndex(item.getOrderIndex());
    }
  }

  // 강의의 선수지식, 직무 연관성, 태그를 전체 교체한다.
  @Transactional
  public void updateCourseMetadata(
      Long instructorId, Long courseId, InstructorCourseDto.UpdateMetadataRequest request) {
    validateAuthenticatedUser(instructorId);

    Course course = getOwnedCourse(instructorId, courseId);
    course.replacePrerequisites(request.getPrerequisites());
    course.replaceJobRelevance(request.getJobRelevance());
    replaceCourseTags(course, request.getTagIds());
  }

  // 강의 목표를 bulk replace 방식으로 저장한다.
  @Transactional
  public void replaceObjectives(
      Long instructorId, Long courseId, InstructorCourseDto.ReplaceObjectivesRequest request) {
    validateAuthenticatedUser(instructorId);

    Course course = getOwnedCourse(instructorId, courseId);
    courseObjectiveRepository.deleteAllByCourseCourseId(courseId);

    List<CourseObjective> objectives = new ArrayList<>();
    for (int i = 0; i < request.getObjectives().size(); i++) {
      objectives.add(
          CourseObjective.builder()
              .course(course)
              .objectiveText(request.getObjectives().get(i))
              .displayOrder(i)
              .build());
    }

    courseObjectiveRepository.saveAll(objectives);
  }

  // 강의 수강 대상을 bulk replace 방식으로 저장한다.
  @Transactional
  public void replaceTargetAudiences(
      Long instructorId,
      Long courseId,
      InstructorCourseDto.ReplaceTargetAudiencesRequest request) {
    validateAuthenticatedUser(instructorId);

    Course course = getOwnedCourse(instructorId, courseId);
    courseTargetAudienceRepository.deleteAllByCourseCourseId(courseId);

    List<CourseTargetAudience> targetAudiences = new ArrayList<>();
    for (int i = 0; i < request.getTargetAudiences().size(); i++) {
      targetAudiences.add(
          CourseTargetAudience.builder()
              .course(course)
              .audienceDescription(request.getTargetAudiences().get(i))
              .displayOrder(i)
              .build());
    }

    courseTargetAudienceRepository.saveAll(targetAudiences);
  }

  // 레슨 첨부 자료 메타데이터를 저장한다.
  @Transactional
  public Long createMaterial(
      Long instructorId, Long lessonId, InstructorMaterialDto.CreateMaterialRequest request) {
    validateAuthenticatedUser(instructorId);

    Lesson lesson = getOwnedLesson(instructorId, lessonId);

    // 현재 엔티티에는 fileSize 컬럼이 없어 저장하지 않는다.
    CourseMaterial material =
        CourseMaterial.builder()
            .lesson(lesson)
            .materialType(request.getMaterialType())
            .materialUrl(request.getMaterialUrl())
            .assetKey(request.getAssetKey())
            .originalFileName(request.getOriginalFileName())
            .displayOrder(request.getDisplayOrder())
            .build();

    CourseMaterial savedMaterial = courseMaterialRepository.save(material);
    return savedMaterial.getMaterialId();
  }

  // 강의 썸네일 메타데이터를 저장한다.
  @Transactional
  public void uploadThumbnail(
      Long instructorId, Long courseId, InstructorCourseDto.UploadThumbnailRequest request) {
    validateAuthenticatedUser(instructorId);

    Course course = getOwnedCourse(instructorId, courseId);
    course.updateThumbnail(request.getThumbnailUrl());
  }

  // 강의 트레일러 메타데이터를 저장한다.
  @Transactional
  public void uploadTrailer(
      Long instructorId, Long courseId, InstructorCourseDto.UploadTrailerRequest request) {
    validateAuthenticatedUser(instructorId);

    Course course = getOwnedCourse(instructorId, courseId);
    course.updateTrailer(
        request.getTrailerUrl(), request.getVideoAssetKey(), request.getDurationSeconds());
  }

  // 현재 로그인한 사용자 존재 여부를 검증한다.
  private void validateAuthenticatedUser(Long instructorId) {
    if (instructorId == null) {
      throw new CustomException(ErrorCode.UNAUTHORIZED);
    }

    if (!userRepository.existsById(instructorId)) {
      throw new CustomException(ErrorCode.USER_NOT_FOUND);
    }
  }

  // 현재 로그인한 강사가 자신의 강의만 수정할 수 있도록 검증한다.
  private Course getOwnedCourse(Long instructorId, Long courseId) {
    return courseRepository
        .findByCourseIdAndInstructorId(courseId, instructorId)
        .orElseGet(
            () -> {
              if (courseRepository.existsById(courseId)) {
                throw new CustomException(ErrorCode.FORBIDDEN);
              }
              throw new CustomException(ErrorCode.RESOURCE_NOT_FOUND);
            });
  }

  // 현재 로그인한 강사가 자신의 섹션만 수정할 수 있도록 검증한다.
  private CourseSection getOwnedSection(Long instructorId, Long sectionId) {
    return courseSectionRepository
        .findBySectionIdAndCourseInstructorId(sectionId, instructorId)
        .orElseGet(
            () -> {
              if (courseSectionRepository.existsById(sectionId)) {
                throw new CustomException(ErrorCode.FORBIDDEN);
              }
              throw new CustomException(ErrorCode.RESOURCE_NOT_FOUND);
            });
  }

  // 현재 로그인한 강사가 자신의 레슨만 수정할 수 있도록 검증한다.
  private Lesson getOwnedLesson(Long instructorId, Long lessonId) {
    return lessonRepository
        .findByLessonIdAndSectionCourseInstructorId(lessonId, instructorId)
        .orElseGet(
            () -> {
              if (lessonRepository.existsById(lessonId)) {
                throw new CustomException(ErrorCode.FORBIDDEN);
              }
              throw new CustomException(ErrorCode.RESOURCE_NOT_FOUND);
            });
  }

  // 동일 섹션의 레슨만 순서 변경 대상으로 들어왔는지 검증한다.
  private void validateLessonOrders(
      List<Lesson> lessons, InstructorLessonDto.UpdateLessonOrderRequest request) {
    if (lessons.isEmpty()) {
      throw new CustomException(ErrorCode.RESOURCE_NOT_FOUND);
    }

    Set<Long> actualLessonIds =
        lessons.stream().map(Lesson::getLessonId).collect(Collectors.toSet());

    Set<Long> requestedLessonIds =
        request.getLessonOrders().stream()
            .map(InstructorLessonDto.LessonOrderItem::getLessonId)
            .collect(Collectors.toSet());

    if (actualLessonIds.size() != request.getLessonOrders().size()
        || !actualLessonIds.equals(requestedLessonIds)) {
      throw new CustomException(ErrorCode.INVALID_INPUT);
    }

    // 중복 순서 번호를 방지한다.
    Set<Integer> requestedOrderIndexes = new HashSet<>();
    for (InstructorLessonDto.LessonOrderItem item : request.getLessonOrders()) {
      if (!requestedOrderIndexes.add(item.getOrderIndex())) {
        throw new CustomException(ErrorCode.INVALID_INPUT);
      }
    }
  }

  // 강의 생성 시 선택한 태그를 강의-태그 매핑으로 대체한다.
  private void replaceCourseTags(Course course, List<Long> tagIds) {
    List<Tag> tags = tagRepository.findAllById(tagIds);

    if (tags.size() != tagIds.size()) {
      throw new CustomException(ErrorCode.TAG_NOT_FOUND);
    }

    courseTagMapRepository.deleteAllByCourseCourseId(course.getCourseId());

    List<CourseTagMap> mappings =
        tags.stream()
            .map(
                tag ->
                    CourseTagMap.builder().course(course).tag(tag).proficiencyLevel(3).build())
            .toList();

    courseTagMapRepository.saveAll(mappings);
  }

  // 강의 삭제 시 하위 엔티티를 순서대로 정리한다.
  private void deleteCourseChildren(Long courseId) {
    courseMaterialRepository.deleteAllByLessonSectionCourseCourseId(courseId);
    lessonRepository.deleteAllBySectionCourseCourseId(courseId);
    courseSectionRepository.deleteAllByCourseCourseId(courseId);
    courseObjectiveRepository.deleteAllByCourseCourseId(courseId);
    courseTargetAudienceRepository.deleteAllByCourseCourseId(courseId);
    courseTagMapRepository.deleteAllByCourseCourseId(courseId);
  }

  // 문자열 상태값을 강의 상태 enum으로 변환한다.
  private CourseStatus toCourseStatus(String status) {
    try {
      return CourseStatus.valueOf(status.toUpperCase(Locale.ROOT));
    } catch (IllegalArgumentException e) {
      throw new CustomException(ErrorCode.INVALID_COURSE_STATUS);
    }
  }

  // 문자열 난이도값을 강의 난이도 enum으로 변환한다.
  private CourseDifficultyLevel toDifficultyLevel(String difficultyLevel) {
    if (difficultyLevel == null || difficultyLevel.isBlank()) {
      return null;
    }

    try {
      return CourseDifficultyLevel.valueOf(difficultyLevel.toUpperCase(Locale.ROOT));
    } catch (IllegalArgumentException e) {
      throw new CustomException(ErrorCode.INVALID_COURSE_DIFFICULTY_LEVEL);
    }
  }

  // 문자열 레슨 유형값을 enum으로 변환한다.
  private LessonType toLessonType(String lessonType) {
    try {
      return LessonType.valueOf(lessonType.toUpperCase(Locale.ROOT));
    } catch (IllegalArgumentException | NullPointerException e) {
      throw new CustomException(ErrorCode.INVALID_INPUT);
    }
  }
}
