package com.devpath.api.admin.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

public class TagGovernanceRequests {

    @Getter
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    @Schema(description = "표준 태그 생성 요청 DTO")
    public static class CreateTag {
        @Schema(description = "태그명 (예: spring-boot)", example = "spring-boot")
        private String name;

        @Schema(description = "카테고리 (예: backend)", example = "backend")
        private String category;
    }

    @Getter
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    @Schema(description = "표준 태그 수정 요청 DTO")
    public static class UpdateTag {
        @Schema(description = "변경할 태그명")
        private String name;

        @Schema(description = "변경할 카테고리")
        private String category;
    }

    @Getter
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    @Schema(description = "태그 병합 요청 DTO (중복 태그 통합)")
    public static class MergeTags {
        @Schema(description = "없어질(흡수될) 태그 ID")
        private Long sourceTagId;

        @Schema(description = "살아남을 표준 태그 ID")
        private Long targetTagId;
    }
}