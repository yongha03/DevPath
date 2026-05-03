package com.devpath.domain.qna.entity;

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
@Table(name = "workspace_questions")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class WorkspaceQuestion {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "workspace_question_id")
  private Long id;

  // A 담당 워크스페이스 Entity와 충돌을 줄이기 위해 ID만 느슨하게 참조한다.
  @Column(name = "workspace_id", nullable = false)
  private Long workspaceId;

  // 질문 작성자다.
  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "writer_id", nullable = false)
  private User writer;

  // 질문 제목이다.
  @Column(nullable = false, length = 150)
  private String title;

  // 질문 본문이다.
  @Column(nullable = false, columnDefinition = "TEXT")
  private String content;

  // 질문 상태를 enum으로 관리한다.
  @Enumerated(EnumType.STRING)
  @Column(nullable = false, length = 20)
  private QuestionStatus status;

  // 질문 이력 보존을 위해 물리 삭제 대신 논리 삭제를 사용한다.
  @Column(name = "is_deleted", nullable = false)
  private Boolean isDeleted;

  // 최초 작성 시간을 자동 기록한다.
  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private LocalDateTime createdAt;

  // 마지막 수정 시간을 자동 기록한다.
  @UpdateTimestamp
  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;

  @Builder
  private WorkspaceQuestion(Long workspaceId, User writer, String title, String content) {
    this.workspaceId = workspaceId;
    this.writer = writer;
    this.title = title;
    this.content = content;
    this.status = QuestionStatus.WAITING;
    this.isDeleted = false;
  }

  // 답변 등록 시 질문 상태를 답변 완료로 변경한다.
  public void markAsAnswered() {
    if (this.status != QuestionStatus.CLOSED) {
      this.status = QuestionStatus.ANSWERED;
    }
  }

  // 질문 상태를 명시적으로 변경한다.
  public void changeStatus(QuestionStatus status) {
    this.status = status;
  }

  // 질문을 논리 삭제한다.
  public void delete() {
    this.isDeleted = true;
  }
}
