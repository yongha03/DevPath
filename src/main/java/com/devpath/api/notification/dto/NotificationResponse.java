package com.devpath.api.notification.dto;

import com.devpath.domain.notification.entity.LearnerNotificationType;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
@Builder
@Schema(description = "학습자 알림 응답 DTO")
public class NotificationResponse {

    @Schema(description = "알림 ID", example = "1")
    private Long id;

    @Schema(description = "알림 타입", example = "STUDY_GROUP")
    private LearnerNotificationType type;

    @Schema(description = "알림 메시지 내용", example = "새로운 스터디 그룹 매칭이 있습니다.")
    private String message;

    @Schema(description = "읽음 여부", example = "false")
    private Boolean isRead;

    @Schema(description = "알림 생성 일시")
    private LocalDateTime createdAt;
}