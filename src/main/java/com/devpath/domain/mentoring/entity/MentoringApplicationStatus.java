package com.devpath.domain.mentoring.entity;

public enum MentoringApplicationStatus {

  // 멘토가 아직 승인 또는 거절하지 않은 신청 상태
  PENDING,

  // 멘토가 승인한 신청 상태
  APPROVED,

  // 멘토가 거절한 신청 상태
  REJECTED
}
