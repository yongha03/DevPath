package com.devpath.api.notification.service;

import com.devpath.api.notification.dto.NotificationResponse;
import com.devpath.domain.notification.entity.LearnerNotification;
import com.devpath.domain.notification.entity.LearnerNotificationType;
import com.devpath.domain.notification.repository.LearnerNotificationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class NotificationEventService {

    private final LearnerNotificationRepository learnerNotificationRepository;
    private final NotificationSseService notificationSseService;

    @Transactional
    public NotificationResponse notifySystem(Long receiverId, String message) {
        // 도메인 이벤트 발생 시 DB에 알림을 저장한다.
        LearnerNotification notification = LearnerNotification.builder()
                .learnerId(receiverId)
                .type(LearnerNotificationType.SYSTEM)
                .message(message)
                .build();

        LearnerNotification savedNotification = learnerNotificationRepository.save(notification);
        NotificationResponse response = NotificationResponse.from(savedNotification);

        // 사용자가 SSE에 연결되어 있으면 실시간으로 알림을 전송한다.
        notificationSseService.send(receiverId, response);

        return response;
    }
}
