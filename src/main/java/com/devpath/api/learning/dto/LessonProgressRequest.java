package com.devpath.api.learning.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.NoArgsConstructor;

public class LessonProgressRequest {

    @Getter
    @NoArgsConstructor
    public static class SaveProgress {

        @NotNull(message = "진도율은 필수입니다.")
        @Min(value = 0, message = "진도율은 0 이상이어야 합니다.")
        @Max(value = 100, message = "진도율은 100 이하이어야 합니다.")
        private Integer progressPercent;

        @NotNull(message = "재생 위치(초)는 필수입니다.")
        @Min(value = 0, message = "재생 위치는 0 이상이어야 합니다.")
        private Integer progressSeconds;
    }
}
