package com.devpath.domain.notification.repository;

import com.devpath.domain.notification.entity.LearnerNotification;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface LearnerNotificationRepository extends JpaRepository<LearnerNotification, Long> {
    List<LearnerNotification> findAllByLearnerIdOrderByCreatedAtDesc(Long learnerId);
}