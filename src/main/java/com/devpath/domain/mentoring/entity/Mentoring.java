package com.devpath.domain.mentoring.entity;

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
@Table(name = "mentorings")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Mentoring {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "mentoring_id")
  private Long id;

  // 어떤 공고에서 생성된 멘토링인지 추적한다.
  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "mentoring_post_id", nullable = false)
  private MentoringPost post;

  // 멘토링을 진행하는 멘토 사용자다.
  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "mentor_id", nullable = false)
  private User mentor;

  // 멘토링을 받는 신청자 사용자다.
  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "mentee_id", nullable = false)
  private User mentee;

  // 멘토링 진행 상태를 enum으로 관리한다.
  @Enumerated(EnumType.STRING)
  @Column(nullable = false, length = 20)
  private MentoringStatus status;

  // 멘토링 시작 시각이다.
  @Column(name = "started_at", nullable = false)
  private LocalDateTime startedAt;

  // 멘토링 종료 시각이다.
  @Column(name = "ended_at")
  private LocalDateTime endedAt;

  // 멘토링도 운영 이력 보존을 위해 Soft Delete 방식으로 관리한다.
  @Column(name = "is_deleted", nullable = false)
  private Boolean isDeleted;

  // 최초 생성 시간을 자동 기록한다.
  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private LocalDateTime createdAt;

  // 마지막 수정 시간을 자동 기록한다.
  @UpdateTimestamp
  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;

  @Builder
  private Mentoring(MentoringPost post, User mentor, User mentee) {
    this.post = post;
    this.mentor = mentor;
    this.mentee = mentee;
    this.status = MentoringStatus.ONGOING;
    this.startedAt = LocalDateTime.now();
    this.isDeleted = false;
  }

  // 멘토링을 완료 상태로 변경한다.
  public void complete() {
    this.status = MentoringStatus.COMPLETED;
    this.endedAt = LocalDateTime.now();
  }

  // 멘토링을 취소 상태로 변경한다.
  public void cancel() {
    this.status = MentoringStatus.CANCELLED;
    this.endedAt = LocalDateTime.now();
  }

  // 멘토링을 논리 삭제한다.
  public void delete() {
    this.isDeleted = true;
  }
}
