package com.devpath.api.learning.dto;

import com.devpath.domain.learning.entity.LessonProgress;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@Schema(description = "플레이어 설정 응답 DTO")
public class PlayerConfigResponse {

    @Schema(description = "레슨 ID", example = "10")
    private Long lessonId;

    @Schema(description = "기본 재생 속도", example = "1.25")
    private Double defaultPlaybackRate;

    public static PlayerConfigResponse from(LessonProgress progress) {
        return PlayerConfigResponse.builder()
                .lessonId(progress.getLesson().getLessonId())
                .defaultPlaybackRate(progress.getDefaultPlaybackRate())
                .build();
    }
}
