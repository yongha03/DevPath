package com.devpath.domain.review.entity;

public enum MissionSubmissionStatus {

  // 학습자가 미션 결과물을 제출했고 아직 최종 판정을 받지 않은 상태
  SUBMITTED,

  // 멘토가 미션 제출물을 통과 처리한 상태
  PASSED,

  // 멘토가 미션 제출물을 반려 처리한 상태
  REJECTED
}
