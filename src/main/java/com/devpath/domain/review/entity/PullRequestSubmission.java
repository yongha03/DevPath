package com.devpath.domain.review.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

@Entity
@Table(name = "pull_request_submissions")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class PullRequestSubmission {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "pull_request_submission_id")
  private Long id;

  // PR 제출은 하나의 미션 제출 상태와 1:1로 연결한다.
  @OneToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "mission_submission_id", nullable = false, unique = true)
  private MissionSubmission missionSubmission;

  // GitHub Pull Request URL을 저장한다.
  @Column(name = "pr_url", nullable = false, length = 1000)
  private String prUrl;

  // PR 제출 목록에 노출할 제목이다.
  @Column(nullable = false, length = 150)
  private String title;

  // PR 설명, 구현 내용, 리뷰 요청 사항을 저장한다.
  @Column(columnDefinition = "TEXT")
  private String description;

  // 제출 이력 보존을 위해 물리 삭제 대신 논리 삭제를 사용한다.
  @Column(name = "is_deleted", nullable = false)
  private Boolean isDeleted;

  // 최초 제출 시간을 자동 기록한다.
  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private LocalDateTime createdAt;

  // 마지막 수정 시간을 자동 기록한다.
  @UpdateTimestamp
  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;

  @Builder
  private PullRequestSubmission(
      MissionSubmission missionSubmission, String prUrl, String title, String description) {
    this.missionSubmission = missionSubmission;
    this.prUrl = prUrl;
    this.title = title;
    this.description = description;
    this.isDeleted = false;
  }

  // PR 제출물을 논리 삭제한다.
  public void delete() {
    this.isDeleted = true;
  }
}
