package com.devpath.api.learning.dto;

import com.devpath.domain.learning.entity.TilDraft;
import com.devpath.domain.learning.entity.TilDraftStatus;
import java.time.LocalDateTime;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class TilResponse {

    private Long tilId;
    private Long lessonId;
    private String title;
    private String content;
    private String tableOfContents;
    private TilDraftStatus status;
    private String publishedUrl;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    public static TilResponse from(TilDraft til) {
        return TilResponse.builder()
                .tilId(til.getId())
                .lessonId(til.getLesson() != null ? til.getLesson().getLessonId() : null)
                .title(til.getTitle())
                .content(til.getContent())
                .tableOfContents(til.getTableOfContents())
                .status(til.getStatus())
                .publishedUrl(til.getPublishedUrl())
                .createdAt(til.getCreatedAt())
                .updatedAt(til.getUpdatedAt())
                .build();
    }
}
