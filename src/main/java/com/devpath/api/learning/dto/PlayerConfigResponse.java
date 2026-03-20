package com.devpath.api.learning.dto;

import com.devpath.domain.learning.entity.LessonProgress;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class PlayerConfigResponse {

    private Long lessonId;
    private Double defaultPlaybackRate;

    public static PlayerConfigResponse from(LessonProgress progress) {
        return PlayerConfigResponse.builder()
                .lessonId(progress.getLesson().getLessonId())
                .defaultPlaybackRate(progress.getDefaultPlaybackRate())
                .build();
    }
}
