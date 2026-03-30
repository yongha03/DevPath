package com.devpath.api.instructor.service;

import com.devpath.api.instructor.dto.notification.NotificationResponse;
import com.devpath.domain.notification.entity.InstructorNotification;
import com.devpath.domain.notification.repository.InstructorNotificationRepository;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class InstructorNotificationService {

    private final InstructorNotificationRepository instructorNotificationRepository;

    public List<NotificationResponse> getNotifications(Long instructorId) {
        return instructorNotificationRepository.findAllByInstructorIdOrderByCreatedAtDesc(instructorId)
                .stream()
                .map(this::toResponse)
                .toList();
    }

    // 강사 전용 알림 엔티티를 응답 DTO로 변환한다.
    private NotificationResponse toResponse(InstructorNotification notification) {
        return NotificationResponse.builder()
                .notificationId(notification.getId())
                .type(notification.getType().name())
                .message(notification.getMessage())
                .isRead(notification.getIsRead())
                .createdAt(notification.getCreatedAt())
                .build();
    }
}
