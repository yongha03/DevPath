package com.devpath.api.learner.service;

import com.devpath.common.exception.CustomException;
import com.devpath.common.exception.ErrorCode;
import com.devpath.domain.course.entity.Course;
import com.devpath.domain.course.repository.CourseRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class LearnerCourseService {

    private final CourseRepository courseRepository;

    /**
     * 강의 목록 조회
     */
    public List<Course> getCourseList() {
        return courseRepository.findAll();
    }

    /**
     * 강의 상세 조회
     */
    public Course getCourseDetail(Long courseId) {
        return courseRepository.findById(courseId)
                .orElseThrow(() -> new CustomException(ErrorCode.COURSE_NOT_FOUND));
    }
}
