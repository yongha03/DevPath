package com.devpath.api.instructor.dto.qna;

import com.devpath.domain.qna.entity.QnaStatus;
import com.devpath.domain.qna.entity.Question;
import java.time.LocalDateTime;

public record QnaInboxResponse(
        Long questionId,
        Long courseId,
        Long learnerId,
        String courseTitle,
        String learnerName,
        String learnerAvatarSeed,
        String title,
        String content,
        QnaStatus status,
        String lectureTimestamp,
        LocalDateTime createdAt
) {

    public static QnaInboxResponse from(Question question) {
        return from(question, null);
    }

    public static QnaInboxResponse from(Question question, String courseTitle) {
        Long learnerId = question.getUser() == null ? null : question.getUser().getId();
        String learnerName = question.getUser() == null ? null : question.getUser().getName();
        return new QnaInboxResponse(
                question.getId(),
                question.getCourseId(),
                learnerId,
                courseTitle,
                learnerName,
                learnerName,
                question.getTitle(),
                question.getContent(),
                question.getQnaStatus(),
                question.getLectureTimestamp(),
                question.getCreatedAt()
        );
    }
}
