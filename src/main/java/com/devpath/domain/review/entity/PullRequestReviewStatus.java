package com.devpath.domain.review.entity;

public enum PullRequestReviewStatus {

  // 리뷰 코멘트만 작성된 기본 상태
  COMMENTED,

  // 리뷰 코멘트가 승인 처리된 상태
  APPROVED,

  // 리뷰 코멘트가 반려 처리된 상태
  REJECTED
}
