package com.devpath.domain.mentoring.entity;

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
@Table(name = "mentoring_missions")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class MentoringMission {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "mentoring_mission_id")
  private Long id;

  // 어떤 멘토링 워크스페이스에 속한 미션인지 연결한다.
  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "mentoring_id", nullable = false)
  private Mentoring mentoring;

  // 멘토링 내부에서 몇 주차 미션인지 나타낸다.
  @Column(name = "week_number", nullable = false)
  private Integer weekNumber;

  // 미션 목록과 상세 화면에 노출되는 제목이다.
  @Column(nullable = false, length = 150)
  private String title;

  // 미션 상세 요구사항과 제출 기준을 저장한다.
  @Column(nullable = false, columnDefinition = "TEXT")
  private String description;

  // PR 제출 또는 과제 제출 권장 마감일이다.
  @Column(name = "due_at")
  private LocalDateTime dueAt;

  // 미션 공개 상태를 enum으로 고정한다.
  @Enumerated(EnumType.STRING)
  @Column(nullable = false, length = 20)
  private MentoringMissionStatus status;

  // 물리 삭제 대신 논리 삭제 여부를 저장한다.
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
  private MentoringMission(
      Mentoring mentoring,
      Integer weekNumber,
      String title,
      String description,
      LocalDateTime dueAt) {
    this.mentoring = mentoring;
    this.weekNumber = weekNumber;
    this.title = title;
    this.description = description;
    this.dueAt = dueAt;
    this.status = MentoringMissionStatus.OPEN;
    this.isDeleted = false;
  }

  // 미션의 수정 가능한 필드만 변경한다.
  public void update(Integer weekNumber, String title, String description, LocalDateTime dueAt) {
    this.weekNumber = weekNumber;
    this.title = title;
    this.description = description;
    this.dueAt = dueAt;
  }

  // 미션 제출을 더 이상 받지 않도록 마감한다.
  public void close() {
    this.status = MentoringMissionStatus.CLOSED;
  }

  // 마감된 미션을 다시 공개 상태로 되돌린다.
  public void reopen() {
    this.status = MentoringMissionStatus.OPEN;
  }

  // 미션을 논리 삭제하고 상태도 마감 처리한다.
  public void delete() {
    this.isDeleted = true;
    this.status = MentoringMissionStatus.CLOSED;
  }
}
