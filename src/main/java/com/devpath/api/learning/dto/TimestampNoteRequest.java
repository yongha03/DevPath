package com.devpath.api.learning.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.NoArgsConstructor;

public class TimestampNoteRequest {

    @Getter
    @NoArgsConstructor
    @Schema(description = "타임스탬프 노트 생성 요청 DTO")
    public static class Create {

        @NotNull(message = "타임스탬프(초)는 필수입니다.")
        @Min(value = 0, message = "타임스탬프는 0 이상이어야 합니다.")
        @Schema(description = "타임스탬프(초)", example = "125")
        private Integer timestampSecond;

        @NotBlank(message = "노트 내용은 필수입니다.")
        @Schema(description = "노트 내용", example = "Spring Security 인증 흐름 다시 보기")
        private String content;
    }

    @Getter
    @NoArgsConstructor
    @Schema(description = "타임스탬프 노트 수정 요청 DTO")
    public static class Update {

        @NotNull(message = "타임스탬프(초)는 필수입니다.")
        @Min(value = 0, message = "타임스탬프는 0 이상이어야 합니다.")
        @Schema(description = "타임스탬프(초)", example = "140")
        private Integer timestampSecond;

        @NotBlank(message = "노트 내용은 필수입니다.")
        @Schema(description = "노트 내용", example = "여기서 필터 체인 동작 확인")
        private String content;
    }
}
