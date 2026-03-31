package com.devpath.api.instructor.controller;

import com.devpath.api.instructor.dto.notification.NotificationResponse;
import com.devpath.api.instructor.service.InstructorNotificationService;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "Instructor - Notification", description = "강사 알림 API")
@RestController
@RequestMapping("/api/instructor/notifications")
@RequiredArgsConstructor
public class InstructorNotificationController {

    private final InstructorNotificationService instructorNotificationService;

    // 강사 전용 알림 목록을 최신순으로 조회한다.
    @Operation(summary = "통합 알림 조회")
    @GetMapping
    public ApiResponse<List<NotificationResponse>> getNotifications(
            @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        return ApiResponse.success(
                "알림 목록을 조회했습니다.",
                instructorNotificationService.getNotifications(userId)
        );
    }
}
