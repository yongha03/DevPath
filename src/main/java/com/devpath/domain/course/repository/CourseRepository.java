package com.devpath.domain.course.repository;

import com.devpath.domain.course.entity.Course;
import java.util.Optional;
import com.devpath.domain.course.entity.CourseStatus; // 추가된 import
import java.util.List; // 추가된 import
import org.springframework.data.jpa.repository.JpaRepository;

public interface CourseRepository extends JpaRepository<Course, Long> {
  Optional<Course> findByCourseIdAndInstructorId(Long courseId, Long instructorId);

  boolean existsByCourseIdAndInstructorId(Long courseId, Long instructorId);
  List<Course> findByStatus(CourseStatus status);
}
