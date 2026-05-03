package com.devpath.domain.application.entity;

public enum LoungeApplicationStatus {

  // 아직 승인 또는 거절되지 않은 대기 상태
  PENDING,

  // 받은 사용자가 승인한 상태
  APPROVED,

  // 받은 사용자가 거절한 상태
  REJECTED
}
