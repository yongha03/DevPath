package com.devpath.domain.application.entity;

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
@Table(name = "lounge_applications")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class LoungeApplication {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "lounge_application_id")
  private Long id;

  // 신청서 또는 제안서를 보낸 사용자다.
  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "sender_id", nullable = false)
  private User sender;

  // 신청서 또는 제안서를 받은 사용자다.
  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "receiver_id", nullable = false)
  private User receiver;

  // 스쿼드 지원서인지 제안서인지 구분한다.
  @Enumerated(EnumType.STRING)
  @Column(nullable = false, length = 30)
  private LoungeApplicationType type;

  // A 담당 스쿼드/워크스페이스 Entity와 직접 FK를 걸지 않기 위한 대상 ID다.
  @Column(name = "target_id", nullable = false)
  private Long targetId;

  // 목록 화면에서 대상 이름을 보여주기 위한 표시용 제목이다.
  @Column(name = "target_title", nullable = false, length = 150)
  private String targetTitle;

  // 신청서 또는 제안서 제목이다.
  @Column(nullable = false, length = 150)
  private String title;

  // 신청 동기, 제안 내용, 자기소개 등을 저장한다.
  @Column(nullable = false, columnDefinition = "TEXT")
  private String content;

  // 신청 처리 상태를 enum으로 관리한다.
  @Enumerated(EnumType.STRING)
  @Column(nullable = false, length = 20)
  private LoungeApplicationStatus status;

  // 거절 시 받은 사용자가 작성한 사유다.
  @Column(name = "reject_reason", length = 500)
  private String rejectReason;

  // 승인 또는 거절 처리된 시각이다.
  @Column(name = "processed_at")
  private LocalDateTime processedAt;

  // 운영 이력 보존을 위해 물리 삭제 대신 논리 삭제를 사용한다.
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
  private LoungeApplication(
      User sender,
      User receiver,
      LoungeApplicationType type,
      Long targetId,
      String targetTitle,
      String title,
      String content) {
    this.sender = sender;
    this.receiver = receiver;
    this.type = type;
    this.targetId = targetId;
    this.targetTitle = targetTitle;
    this.title = title;
    this.content = content;
    this.status = LoungeApplicationStatus.PENDING;
    this.isDeleted = false;
  }

  // 아직 처리되지 않은 신청인지 확인한다.
  public boolean isPending() {
    return this.status == LoungeApplicationStatus.PENDING;
  }

  // 신청서 또는 제안서를 승인 상태로 변경한다.
  public void approve() {
    this.status = LoungeApplicationStatus.APPROVED;
    this.rejectReason = null;
    this.processedAt = LocalDateTime.now();
  }

  // 신청서 또는 제안서를 거절 상태로 변경한다.
  public void reject(String rejectReason) {
    this.status = LoungeApplicationStatus.REJECTED;
    this.rejectReason = rejectReason;
    this.processedAt = LocalDateTime.now();
  }

  // 신청서 또는 제안서를 논리 삭제한다.
  public void delete() {
    this.isDeleted = true;
  }
}
