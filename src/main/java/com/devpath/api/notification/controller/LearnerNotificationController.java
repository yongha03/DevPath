package com.devpath.api.notification.controller;

import com.devpath.api.notification.dto.NotificationResponse;
import com.devpath.api.notification.service.LearnerNotificationService;
import com.devpath.api.notification.service.NotificationSseService;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

@Tag(name = "Notification SSE", description = "알림 목록, 읽음 처리, SSE 구독 API")
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/notifications")
public class LearnerNotificationController {

    private final LearnerNotificationService learnerNotificationService;
    private final NotificationSseService notificationSseService;

    @GetMapping(value = "/subscribe", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    @Operation(summary = "SSE 알림 구독", description = "사용자의 실시간 알림 SSE 연결을 생성합니다.")
    public SseEmitter subscribe(
            @Parameter(description = "알림 수신자 사용자 ID", example = "2")
            @RequestParam Long learnerId
    ) {
        // SSE 연결은 ApiResponse로 감싸지 않고 text/event-stream으로 유지한다.
        return notificationSseService.subscribe(learnerId);
    }

    @GetMapping
    @Operation(summary = "알림 목록 조회", description = "내 알림 목록을 최신순으로 조회합니다.")
    public ResponseEntity<ApiResponse<List<NotificationResponse>>> getMyNotifications(
            @Parameter(description = "알림 수신자 사용자 ID", example = "2")
            @RequestParam Long learnerId
    ) {
        // REST 응답은 공통 ApiResponse 포맷으로 반환한다.
        return ResponseEntity.ok(ApiResponse.ok(learnerNotificationService.getMyNotifications(learnerId)));
    }

    @PatchMapping("/{notificationId}/read")
    @Operation(summary = "알림 읽음 처리", description = "특정 알림을 읽음 상태로 변경합니다.")
    public ResponseEntity<ApiResponse<NotificationResponse>> markAsRead(
            @PathVariable Long notificationId,

            @Parameter(description = "알림 수신자 사용자 ID", example = "2")
            @RequestParam Long learnerId
    ) {
        // 본인의 알림인지 검증한 뒤 읽음 처리한다.
        return ResponseEntity.ok(ApiResponse.ok(learnerNotificationService.markAsRead(learnerId, notificationId)));
    }
}
