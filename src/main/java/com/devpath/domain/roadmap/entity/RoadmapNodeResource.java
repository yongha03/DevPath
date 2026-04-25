package com.devpath.domain.roadmap.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

@Entity
@Table(
    name = "roadmap_node_resources",
    indexes = {
      @Index(name = "idx_roadmap_node_resources_node_id", columnList = "node_id"),
      @Index(name = "idx_roadmap_node_resources_active", columnList = "active")
    })
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class RoadmapNodeResource {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "resource_id")
  private Long resourceId;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "node_id", nullable = false)
  private RoadmapNode node;

  @Column(nullable = false)
  private String title;

  @Column(nullable = false, length = 1000)
  private String url;

  @Column(columnDefinition = "TEXT")
  private String description;

  @Column(name = "source_type", length = 30)
  private String sourceType;

  @Column(name = "sort_order", nullable = false)
  private Integer sortOrder;

  @Builder.Default
  @Column(nullable = false)
  private Boolean active = true;

  @CreationTimestamp
  @Column(name = "created_at", updatable = false)
  private LocalDateTime createdAt;

  @UpdateTimestamp
  @Column(name = "updated_at")
  private LocalDateTime updatedAt;

  public void update(
      RoadmapNode node,
      String title,
      String url,
      String description,
      String sourceType,
      Integer sortOrder,
      Boolean active) {
    this.node = node;
    this.title = title;
    this.url = url;
    this.description = description;
    this.sourceType = sourceType;
    this.sortOrder = sortOrder;
    this.active = active;
  }
}
