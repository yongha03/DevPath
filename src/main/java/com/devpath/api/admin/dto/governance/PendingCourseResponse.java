package com.devpath.api.admin.dto.governance;

import com.devpath.domain.course.entity.Course;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
@Builder
// 강의 검수 대기열 표에 필요한 최소 필드만 담는다.
public class PendingCourseResponse {

    private Long courseId;
    private Long instructorId;
    private String instructorName;
    private String title;
    private LocalDateTime submittedAt;

    // 강의 엔티티를 관리자 검수 화면용 응답으로 변환한다.
    public static PendingCourseResponse from(Course course) {
        return PendingCourseResponse.builder()
                .courseId(course.getCourseId())
                .instructorId(course.getInstructorId())
                .instructorName(course.getInstructor() == null ? null : course.getInstructor().getName())
                .title(course.getTitle())
                .submittedAt(course.getPublishedAt())
                .build();
    }
}
