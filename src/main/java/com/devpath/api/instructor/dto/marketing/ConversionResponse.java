package com.devpath.api.instructor.dto.marketing;

import java.time.LocalDateTime;
import java.util.List;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class ConversionResponse {

    private long totalVisitors;
    private long totalSignups;
    private long totalPurchases;
    private double signupRate;
    private double purchaseRate;
    private long dailySnapshotCount;
    private long weeklySnapshotCount;
    private List<CourseConversionItem> courseConversions;

    @Getter
    @Builder
    public static class CourseConversionItem {
        private Long courseId;
        private long totalVisitors;
        private long totalSignups;
        private long totalPurchases;
        private double signupRate;
        private double purchaseRate;
        private LocalDateTime calculatedAt;
    }
}
