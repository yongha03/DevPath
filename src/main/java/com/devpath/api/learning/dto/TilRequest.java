package com.devpath.api.learning.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;
import lombok.Getter;
import lombok.NoArgsConstructor;

public class TilRequest {

    @Getter
    @NoArgsConstructor
    public static class Create {

        @NotBlank(message = "TIL 제목은 필수입니다.")
        private String title;

        @NotBlank(message = "TIL 본문은 필수입니다.")
        private String content;

        // 특정 레슨 기반 TIL 작성 시 lessonId를 포함한다. (선택)
        private Long lessonId;
    }

    @Getter
    @NoArgsConstructor
    public static class Update {

        @NotBlank(message = "TIL 제목은 필수입니다.")
        private String title;

        @NotBlank(message = "TIL 본문은 필수입니다.")
        private String content;
    }

    // 노트 목록을 TIL로 변환하는 요청
    @Getter
    @NoArgsConstructor
    public static class ConvertFromNotes {

        @NotEmpty(message = "변환할 노트 ID 목록은 필수입니다.")
        private List<Long> noteIds;

        @NotBlank(message = "TIL 제목은 필수입니다.")
        private String title;

        // 변환 기반 레슨 ID (선택)
        private Long lessonId;
    }
}
