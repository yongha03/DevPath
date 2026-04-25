package com.devpath.api.admin.dto.dashboard;

import java.util.List;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
// 관리자 대시보드 상단 카드와 차트 응답 전체다.
public class AdminDashboardOverviewResponse {

  private SummaryMetric weeklyActiveUsers;
  private SummaryMetric pendingCourseReviews;
  private SummaryMetric issuedCertificates;
  private SummaryMetric pendingReports;
  private List<TrafficPoint> trafficTrend;
  private List<CategoryDistribution> courseCategoryDistribution;

  @Getter
  @Builder
  // KPI 카드 한 개를 표현한다.
  public static class SummaryMetric {

    private long value;
    private String suffix;
    private int progressPercent;
    private String changeLabel;
    private String changeTone;
  }

  @Getter
  @Builder
  // 최근 유입 추이 차트의 한 점이다.
  public static class TrafficPoint {

    private String label;
    private long learners;
    private long instructors;
  }

  @Getter
  @Builder
  // 카테고리 분포 도넛 차트 항목이다.
  public static class CategoryDistribution {

    private String label;
    private long count;
    private int percentage;
  }
}
