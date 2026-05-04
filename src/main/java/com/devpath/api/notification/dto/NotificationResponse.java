package com.devpath.api.notification.dto;

import com.devpath.domain.notification.entity.LearnerNotification;
import com.devpath.domain.notification.entity.LearnerNotificationType;
import io.swagger.v3.oas.annotations.media.Schema;
import java.time.LocalDateTime;

@Schema(name = "NotificationResponse", description = "알림 응답")
public record NotificationResponse(

        @Schema(description = "알림 ID", example = "1")
        Long id,

        @Schema(description = "알림 수신자 ID", example = "2")
        Long learnerId,

        @Schema(description = "알림 타입", example = "SYSTEM")
        LearnerNotificationType type,

        @Schema(description = "알림 메시지 내용", example = "멘토링 질문에 새 답변이 등록되었습니다.")
        String message,

        @Schema(description = "읽음 여부", example = "false")
        Boolean isRead,

        @Schema(description = "알림 생성 일시", example = "2026-05-03T18:30:00")
        LocalDateTime createdAt
) {

    // 알림 Entity를 API 응답 DTO로 변환한다.
    public static NotificationResponse from(LearnerNotification notification) {
        return new NotificationResponse(
                notification.getId(),
                notification.getLearnerId(),
                notification.getType(),
                notification.getMessage(),
                notification.getIsRead(),
                notification.getCreatedAt()
        );
    }
}
