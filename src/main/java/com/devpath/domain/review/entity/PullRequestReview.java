package com.devpath.domain.review.entity;

import com.devpath.domain.user.entity.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

@Entity
@Table(name = "pull_request_reviews")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class PullRequestReview {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "pull_request_review_id")
  private Long id;

  // 어떤 PR 제출물에 대한 리뷰인지 연결한다.
  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "pull_request_submission_id", nullable = false)
  private PullRequestSubmission pullRequestSubmission;

  // 리뷰를 작성한 멘토 또는 강사 사용자다.
  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "reviewer_id", nullable = false)
  private User reviewer;

  // 코드 리뷰 코멘트 본문이다.
  @Column(nullable = false, columnDefinition = "TEXT")
  private String comment;

  // 리뷰 코멘트의 승인/반려 상태다.
  @Enumerated(EnumType.STRING)
  @Column(nullable = false, length = 20)
  private PullRequestReviewStatus status;

  // 리뷰 승인 또는 반려가 처리된 시각이다.
  @Column(name = "decided_at")
  private LocalDateTime decidedAt;

  // 리뷰 이력 보존을 위해 물리 삭제 대신 논리 삭제를 사용한다.
  @Column(name = "is_deleted", nullable = false)
  private Boolean isDeleted;

  // 최초 리뷰 작성 시간을 자동 기록한다.
  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private LocalDateTime createdAt;

  // 마지막 수정 시간을 자동 기록한다.
  @UpdateTimestamp
  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;

  @Builder
  private PullRequestReview(
      PullRequestSubmission pullRequestSubmission, User reviewer, String comment) {
    this.pullRequestSubmission = pullRequestSubmission;
    this.reviewer = reviewer;
    this.comment = comment;
    this.status = PullRequestReviewStatus.COMMENTED;
    this.isDeleted = false;
  }

  // 리뷰 코멘트를 승인 처리한다.
  public void approve() {
    this.status = PullRequestReviewStatus.APPROVED;
    this.decidedAt = LocalDateTime.now();
  }

  // 리뷰 코멘트를 반려 처리한다.
  public void reject() {
    this.status = PullRequestReviewStatus.REJECTED;
    this.decidedAt = LocalDateTime.now();
  }

  // 리뷰를 논리 삭제한다.
  public void delete() {
    this.isDeleted = true;
  }
}
