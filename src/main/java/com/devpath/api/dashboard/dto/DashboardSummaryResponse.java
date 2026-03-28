package com.devpath.api.dashboard.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@Schema(description = "학습자 대시보드 요약 응답 DTO")
public class DashboardSummaryResponse {

    @Schema(description = "총 학습 시간 (시간 단위)", example = "120")
    private Integer totalStudyHours;

    @Schema(description = "클리어한 총 노드 수", example = "15")
    private Integer completedNodes;

    @Schema(description = "현재 유지 중인 스트릭(연속 학습) 일수", example = "7")
    private Integer currentStreak;
}