package com.devpath.api.notification.service;

import com.devpath.api.notification.dto.NotificationResponse;
import com.devpath.domain.notification.entity.LearnerNotification;
import com.devpath.domain.notification.repository.LearnerNotificationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class LearnerNotificationService {

    private final LearnerNotificationRepository notificationRepository;

    public List<NotificationResponse> getMyNotifications(Long learnerId) {
        return notificationRepository.findAllByLearnerIdOrderByCreatedAtDesc(learnerId).stream()
                .map(this::convertToDto)
                .collect(Collectors.toList());
    }

    @Transactional
    public void markAsRead(Long notificationId) {
        LearnerNotification notification = notificationRepository.findById(notificationId)
                .orElseThrow(() -> new IllegalArgumentException("알림을 찾을 수 없습니다."));
        notification.markAsRead();
    }

    private NotificationResponse convertToDto(LearnerNotification notification) {
        return NotificationResponse.builder()
                .id(notification.getId())
                .type(notification.getType())
                .message(notification.getMessage())
                .isRead(notification.getIsRead())
                .createdAt(notification.getCreatedAt())
                .build();
    }
}