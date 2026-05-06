package com.devpath.domain.job.entity;

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
@Table(name = "job_skill_tags")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class JobSkillTag {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "job_skill_tag_id")
  private Long id;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "job_posting_id", nullable = false)
  private JobPosting jobPosting;

  @Column(nullable = false, length = 100)
  private String name;

  @Enumerated(EnumType.STRING)
  @Column(nullable = false, length = 30)
  private JobSkillTagSource source;

  @Column(name = "confidence_score", nullable = false)
  private Double confidenceScore;

  @Column(name = "matched_keyword", nullable = false, length = 100)
  private String matchedKeyword;

  @Column(name = "is_deleted", nullable = false)
  private Boolean isDeleted;

  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private LocalDateTime createdAt;

  @UpdateTimestamp
  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;

  @Builder
  private JobSkillTag(
      JobPosting jobPosting,
      String name,
      JobSkillTagSource source,
      Double confidenceScore,
      String matchedKeyword) {
    this.jobPosting = jobPosting;
    this.name = name;
    this.source = source;
    this.confidenceScore = confidenceScore;
    this.matchedKeyword = matchedKeyword;
    this.isDeleted = false;
  }

  public void delete() {
    this.isDeleted = true;
  }
}
