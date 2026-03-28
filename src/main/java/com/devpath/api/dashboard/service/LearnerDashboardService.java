package com.devpath.api.dashboard.service;

import com.devpath.api.dashboard.dto.DashboardSummaryResponse;
import com.devpath.api.dashboard.dto.HeatmapResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class LearnerDashboardService {

    // 실제로는 여러 Repository(Streak, Course, Node 등)를 주입받아 통계를 냅니다.
    // 현재는 구조 완성을 위해 더미(Mock) 데이터를 반환하도록 세팅합니다.

    public DashboardSummaryResponse getSummary(Long learnerId) {
        return DashboardSummaryResponse.builder()
                .totalStudyHours(125)
                .completedNodes(42)
                .currentStreak(5)
                .build();
    }

    public List<HeatmapResponse> getHeatmap(Long learnerId) {
        return List.of(
                HeatmapResponse.builder().date(LocalDate.now().minusDays(2)).activityLevel(1).build(),
                HeatmapResponse.builder().date(LocalDate.now().minusDays(1)).activityLevel(3).build(),
                HeatmapResponse.builder().date(LocalDate.now()).activityLevel(4).build()
        );
    }
}