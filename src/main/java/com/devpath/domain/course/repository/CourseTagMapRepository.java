package com.devpath.domain.course.repository;

import com.devpath.domain.course.entity.CourseTagMap;
import java.util.Collection;
import java.util.List;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface CourseTagMapRepository extends JpaRepository<CourseTagMap, Long> {
  @EntityGraph(attributePaths = "tag")
  List<CourseTagMap> findAllByCourseCourseId(Long courseId);

  @Query(
      """
            select t.name
            from CourseTagMap ctm
            join ctm.tag t
            where ctm.course.courseId = :courseId
            order by t.name asc
            """)
  List<String> findTagNamesByCourseId(@Param("courseId") Long courseId);

  @EntityGraph(attributePaths = "tag")
  @Query(
      """
            select ctm
            from CourseTagMap ctm
            where ctm.course.courseId in :courseIds
            order by ctm.course.courseId asc, ctm.tag.name asc
            """)
  List<CourseTagMap> findAllByCourseCourseIdInOrderByCourseAndTagName(@Param("courseIds") Collection<Long> courseIds);

  List<CourseTagMap> findAllByTagTagId(Long tagId);

  boolean existsByCourseCourseIdAndTagTagId(Long courseId, Long tagId);

  void deleteAllByCourseCourseId(Long courseId);
}
