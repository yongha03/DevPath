package com.devpath.domain.qna.entity;

import com.devpath.domain.user.entity.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
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
@Table(name = "mentoring_answers")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class MentoringAnswer {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "mentoring_answer_id")
  private Long id;

  // 답변이 달린 멘토링 질문이다.
  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "mentoring_question_id", nullable = false)
  private MentoringQuestion question;

  // 답변 작성자다.
  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "writer_id", nullable = false)
  private User writer;

  // 답변 본문이다.
  @Column(nullable = false, columnDefinition = "TEXT")
  private String content;

  // 답변 이력 보존을 위해 물리 삭제 대신 논리 삭제를 사용한다.
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
  private MentoringAnswer(MentoringQuestion question, User writer, String content) {
    this.question = question;
    this.writer = writer;
    this.content = content;
    this.isDeleted = false;
  }

  // 답변을 논리 삭제한다.
  public void delete() {
    this.isDeleted = true;
  }
}
