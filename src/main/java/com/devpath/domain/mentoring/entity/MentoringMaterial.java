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
@Table(name = "mentoring_materials")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class MentoringMaterial {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "mentoring_material_id")
  private Long id;

  // 자료가 어느 주차별 미션에 속하는지 연결한다.
  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "mentoring_mission_id", nullable = false)
  private MentoringMission mission;

  // URL 자료인지 TEXT 가이드라인인지 enum으로 고정한다.
  @Enumerated(EnumType.STRING)
  @Column(nullable = false, length = 20)
  private MentoringMaterialType type;

  // 자료 목록에서 노출되는 제목이다.
  @Column(nullable = false, length = 150)
  private String title;

  // TEXT 타입일 때 가이드라인 본문을 저장한다.
  @Column(columnDefinition = "TEXT")
  private String content;

  // URL 타입일 때 외부 자료 링크를 저장한다.
  @Column(length = 1000)
  private String url;

  // 프론트에서 자료 정렬 순서를 제어하기 위한 값이다.
  @Column(name = "sort_order", nullable = false)
  private Integer sortOrder;

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
  private MentoringMaterial(
      MentoringMission mission,
      MentoringMaterialType type,
      String title,
      String content,
      String url,
      Integer sortOrder) {
    this.mission = mission;
    this.type = type;
    this.title = title;
    this.content = content;
    this.url = url;
    this.sortOrder = sortOrder;
    this.isDeleted = false;
  }

  // 자료의 수정 가능한 필드만 변경한다.
  public void update(
      MentoringMaterialType type, String title, String content, String url, Integer sortOrder) {
    this.type = type;
    this.title = title;
    this.content = content;
    this.url = url;
    this.sortOrder = sortOrder;
  }

  // 자료를 논리 삭제한다.
  public void delete() {
    this.isDeleted = true;
  }
}
