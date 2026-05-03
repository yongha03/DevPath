package com.devpath.domain.review.entity;

import com.devpath.domain.mentoring.entity.MentoringMission;
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
@Table(name = "mission_submissions")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class MissionSubmission {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "mission_submission_id")
  private Long id;

  // 어떤 멘토링 미션에 대한 제출물인지 연결한다.
  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "mentoring_mission_id", nullable = false)
  private MentoringMission mission;

  // 미션을 제출한 멘티 사용자다.
  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "submitter_id", nullable = false)
  private User submitter;

  // 미션 제출물의 최종 판정 상태다.
  @Enumerated(EnumType.STRING)
  @Column(nullable = false, length = 20)
  private MissionSubmissionStatus status;

  // Pass 또는 Reject 시 멘토가 남긴 최종 피드백이다.
  @Column(columnDefinition = "TEXT")
  private String feedback;

  // 최종 판정이 내려진 시각이다.
  @Column(name = "graded_at")
  private LocalDateTime gradedAt;

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
  private MissionSubmission(MentoringMission mission, User submitter) {
    this.mission = mission;
    this.submitter = submitter;
    this.status = MissionSubmissionStatus.SUBMITTED;
    this.isDeleted = false;
  }

  // 아직 최종 판정을 받지 않은 제출물인지 확인한다.
  public boolean isSubmitted() {
    return this.status == MissionSubmissionStatus.SUBMITTED;
  }

  // 미션 제출물을 통과 처리한다.
  public void pass(String feedback) {
    this.status = MissionSubmissionStatus.PASSED;
    this.feedback = feedback;
    this.gradedAt = LocalDateTime.now();
  }

  // 미션 제출물을 반려 처리한다.
  public void reject(String feedback) {
    this.status = MissionSubmissionStatus.REJECTED;
    this.feedback = feedback;
    this.gradedAt = LocalDateTime.now();
  }

  // 미션 제출물을 논리 삭제한다.
  public void delete() {
    this.isDeleted = true;
  }
}
