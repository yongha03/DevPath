package com.devpath.domain.roadmap.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

// 로드맵 허브의 섹션 메타데이터를 저장한다.
@Entity
@Table(name = "roadmap_hub_sections")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class RoadmapHubSection {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "section_key", nullable = false, unique = true, length = 80)
  private String sectionKey;

  @Column(nullable = false, length = 120)
  private String title;

  @Column(columnDefinition = "TEXT")
  private String description;

  @Column(name = "layout_type", nullable = false, length = 40)
  private String layoutType;

  @Column(name = "sort_order", nullable = false)
  private Integer sortOrder;

  @Builder.Default
  @Column(name = "is_active", nullable = false)
  private Boolean active = true;
}
