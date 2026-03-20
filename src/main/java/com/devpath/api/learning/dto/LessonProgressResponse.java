package com.devpath.api.learning.dto;

import com.devpath.domain.learning.entity.LessonProgress;
import java.time.LocalDateTime;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class LessonProgressResponse {

    private Long lessonId;
    private Integer progressPercent;
    private Integer progressSeconds;
    private Double defaultPlaybackRate;
    private Boolean isCompleted;
    private LocalDateTime lastWatchedAt;

    public static LessonProgressResponse from(LessonProgress progress) {
        return LessonProgressResponse.builder()
                .lessonId(progress.getLesson().getLessonId())
                .progressPercent(progress.getProgressPercent())
                .progressSeconds(progress.getProgressSeconds())
                .defaultPlaybackRate(progress.getDefaultPlaybackRate())
                .isCompleted(progress.getIsCompleted())
                .lastWatchedAt(progress.getLastWatchedAt())
                .build();
    }
}
