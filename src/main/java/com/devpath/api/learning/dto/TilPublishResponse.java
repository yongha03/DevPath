package com.devpath.api.learning.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.time.LocalDateTime;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@Schema(description = "외부 블로그 발행 응답 DTO")
public class TilPublishResponse {

    // 발행 대상 TIL ID다.
    @Schema(description = "TIL ID", example = "1")
    private Long tilId;

    // 외부 블로그 발행 성공 여부다.
    @Schema(description = "발행 성공 여부", example = "true")
    private Boolean published;

    // 외부 블로그 플랫폼 식별자다.
    @Schema(description = "발행 플랫폼", example = "VELLOG")
    private String platform;

    // 외부 게시글 ID다. 현재는 mock/stub 값으로 생성한다.
    @Schema(description = "외부 게시글 ID", example = "mock-post-1")
    private String externalPostId;

    // 외부 블로그 게시글 URL이다.
    @Schema(description = "외부 게시글 URL", example = "https://mock.blog.devpath/posts/mock-post-1")
    private String publishedUrl;

    // 외부 플랫폼에 draft 상태로 발행했는지 여부다.
    @Schema(description = "외부 플랫폼 draft 발행 여부", example = "false")
    private Boolean draft;

    // 발행 완료 시각이다.
    @Schema(description = "발행 완료 시각", example = "2026-03-23T11:30:00")
    private LocalDateTime publishedAt;
}
