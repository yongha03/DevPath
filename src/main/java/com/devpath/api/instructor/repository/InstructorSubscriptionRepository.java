package com.devpath.api.instructor.repository;

import com.devpath.api.instructor.entity.InstructorSubscription;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface InstructorSubscriptionRepository extends JpaRepository<InstructorSubscription, Long> {

    Optional<InstructorSubscription> findByChannelIdAndLearnerIdAndIsDeletedFalse(Long channelId, Long learnerId);
}