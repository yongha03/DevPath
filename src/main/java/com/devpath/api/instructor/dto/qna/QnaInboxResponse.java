package com.devpath.api.instructor.dto.qna;

import com.devpath.domain.qna.entity.QnaStatus;
import com.devpath.domain.qna.entity.Question;
import java.time.LocalDateTime;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class QnaInboxResponse {

    private Long questionId;
    private Long courseId;
    private Long learnerId;
    private String title;
    private String content;
    private QnaStatus status;
    private String lectureTimestamp;
    private LocalDateTime createdAt;

    public static QnaInboxResponse from(Question question) {
        return QnaInboxResponse.builder()
                .questionId(question.getId())
                .courseId(question.getCourseId())
                .learnerId(question.getUser().getId())
                .title(question.getTitle())
                .content(question.getContent())
                .status(question.getQnaStatus())
                .lectureTimestamp(question.getLectureTimestamp())
                .createdAt(question.getCreatedAt())
                .build();
    }
}
