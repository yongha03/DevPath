package com.devpath.domain.roadmap.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

// 로드맵 허브 섹션 안에 노출되는 개별 항목을 저장한다.
@Entity
@Table(name = "roadmap_hub_items")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class RoadmapHubItem {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @ManyToOne(fetch = FetchType.LAZY, optional = false)
  @JoinColumn(name = "section_id", nullable = false)
  private RoadmapHubSection section;

  @Column(nullable = false, length = 160)
  private String title;

  @Column(length = 160)
  private String subtitle;

  @Column(name = "icon_class", length = 120)
  private String iconClass;

  @Column(name = "icon_color", length = 32)
  private String iconColor;

  @Column(name = "sort_order", nullable = false)
  private Integer sortOrder;

  @Builder.Default
  @Column(name = "is_active", nullable = false)
  private Boolean active = true;

  @Builder.Default
  @Column(name = "is_featured", nullable = false)
  private Boolean featured = false;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "linked_roadmap_id")
  private Roadmap linkedRoadmap;
}
