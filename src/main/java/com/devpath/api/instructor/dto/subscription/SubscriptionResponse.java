package com.devpath.api.instructor.dto.subscription;

import com.devpath.api.instructor.entity.InstructorSubscription;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
@Builder
public class SubscriptionResponse {

    private Long channelId;
    private Long instructorId;
    private boolean notificationEnabled;
    private LocalDateTime subscribedAt;

    public static SubscriptionResponse from(InstructorSubscription subscription) {
        return SubscriptionResponse.builder()
                .channelId(subscription.getChannelId())
                .instructorId(subscription.getChannelId())
                .notificationEnabled(subscription.isNotificationEnabled())
                .subscribedAt(subscription.getSubscribedAt())
                .build();
    }
}