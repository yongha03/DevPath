package com.devpath.api.learning.dto;

import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.NoArgsConstructor;

public class PlayerConfigRequest {

    @Getter
    @NoArgsConstructor
    public static class UpdatePlaybackRate {

        @NotNull(message = "재생 속도는 필수입니다.")
        @DecimalMin(value = "0.5", message = "재생 속도는 0.5 이상이어야 합니다.")
        @DecimalMax(value = "2.0", message = "재생 속도는 2.0 이하이어야 합니다.")
        private Double defaultPlaybackRate;
    }
}
