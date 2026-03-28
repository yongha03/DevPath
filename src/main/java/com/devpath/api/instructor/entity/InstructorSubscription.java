package com.devpath.api.instructor.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@Table(name = "instructor_subscription")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
@EntityListeners(AuditingEntityListener.class)
public class InstructorSubscription {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Long channelId;

    @Column(nullable = false)
    private Long learnerId;

    @Builder.Default
    private boolean notificationEnabled = true;

    @Builder.Default
    private Boolean isDeleted = false;

    @CreatedDate
    private LocalDateTime subscribedAt;

    public void updateNotification(boolean notificationEnabled) {
        this.notificationEnabled = notificationEnabled;
    }

    public void unsubscribe() {
        this.isDeleted = true;
    }
}