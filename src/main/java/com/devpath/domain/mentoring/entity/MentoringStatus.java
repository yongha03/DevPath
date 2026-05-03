package com.devpath.domain.mentoring.entity;

public enum MentoringStatus {

  // 승인 이후 진행 중인 멘토링 상태
  ONGOING,

  // 정상 종료된 멘토링 상태
  COMPLETED,

  // 중도 취소된 멘토링 상태
  CANCELLED
}
