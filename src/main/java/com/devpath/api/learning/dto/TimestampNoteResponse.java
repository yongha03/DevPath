package com.devpath.api.learning.dto;

import com.devpath.domain.learning.entity.TimestampNote;
import io.swagger.v3.oas.annotations.media.Schema;
import java.time.LocalDateTime;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@Schema(description = "타임스탬프 노트 응답 DTO")
public class TimestampNoteResponse {

    @Schema(description = "노트 ID", example = "1")
    private Long noteId;

    @Schema(description = "레슨 ID", example = "10")
    private Long lessonId;

    @Schema(description = "정규화된 타임스탬프 초", example = "125")
    private Integer timestampSecond;

    // 노트 클릭 시 플레이어가 바로 이동할 수 있도록 동일한 초 값을 함께 내려준다.
    @Schema(description = "플레이어 이동용 초 값", example = "125")
    private Integer seekSecond;

    // 화면 표시에 바로 쓸 수 있도록 mm:ss 형식 라벨을 함께 내려준다.
    @Schema(description = "표시용 타임스탬프 라벨", example = "02:05")
    private String timestampLabel;

    @Schema(description = "노트 내용", example = "Spring Security 인증 흐름 다시 보기")
    private String content;

    @Schema(description = "생성 시각", example = "2026-03-23T10:30:00")
    private LocalDateTime createdAt;

    @Schema(description = "수정 시각", example = "2026-03-23T10:40:00")
    private LocalDateTime updatedAt;

    public static TimestampNoteResponse from(TimestampNote note) {
        return TimestampNoteResponse.builder()
                .noteId(note.getId())
                .lessonId(note.getLesson().getLessonId())
                .timestampSecond(note.getTimestampSecond())
                .seekSecond(note.getTimestampSecond())
                .timestampLabel(toTimestampLabel(note.getTimestampSecond()))
                .content(note.getContent())
                .createdAt(note.getCreatedAt())
                .updatedAt(note.getUpdatedAt())
                .build();
    }

    private static String toTimestampLabel(Integer second) {
        int value = second == null ? 0 : Math.max(0, second);
        return String.format("%02d:%02d", value / 60, value % 60);
    }
}
