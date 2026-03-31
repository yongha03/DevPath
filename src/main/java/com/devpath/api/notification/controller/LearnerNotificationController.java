package com.devpath.api.notification.controller;

import static com.devpath.common.security.AuthenticationUtils.requireUserId;

import com.devpath.api.notification.dto.NotificationResponse;
import com.devpath.api.notification.service.LearnerNotificationService;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/notifications")
@RequiredArgsConstructor
@Tag(name = "Learner - Notification", description = "Learner notification API")
public class LearnerNotificationController {

    private final LearnerNotificationService notificationService;

    @GetMapping
    @Operation(summary = "Get notifications", description = "Get notifications for the authenticated user.")
    public ApiResponse<List<NotificationResponse>> getMyNotifications(
            @Parameter(hidden = true) @AuthenticationPrincipal Long learnerId
    ) {
        return ApiResponse.ok(notificationService.getMyNotifications(requireUserId(learnerId)));
    }

    @PatchMapping("/{notificationId}/read")
    @Operation(summary = "Mark notification as read", description = "Mark one notification as read for the authenticated user.")
    public ApiResponse<Void> markAsRead(
            @PathVariable Long notificationId,
            @Parameter(hidden = true) @AuthenticationPrincipal Long learnerId
    ) {
        notificationService.markAsRead(requireUserId(learnerId), notificationId);
        return ApiResponse.ok();
    }
}
