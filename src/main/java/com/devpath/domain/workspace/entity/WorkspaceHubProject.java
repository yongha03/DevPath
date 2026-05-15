package com.devpath.domain.workspace.entity;

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

@Entity
@Table(name = "workspace_hub_project")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class WorkspaceHubProject {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "dom_id", nullable = false, length = 80, unique = true)
  private String domId;

  @Column(name = "menu_id", nullable = false, length = 80, unique = true)
  private String menuId;

  @Column(name = "card_type", nullable = false, length = 20)
  private String type;

  @Column(name = "card_status", nullable = false, length = 20)
  private String status;

  @Column(name = "dashboard_url", nullable = false, length = 120)
  private String dashboardUrl;

  @Column(nullable = false, length = 150)
  private String title;

  @Column(nullable = false, columnDefinition = "TEXT")
  private String description;

  @Column(name = "progress_percent", nullable = false)
  private int progressPercent;

  @Column(name = "mentoring_mode_label", length = 40)
  private String mentoringModeLabel;

  @Column(name = "mentoring_mode_icon", length = 40)
  private String mentoringModeIcon;

  @Column(name = "category_label", length = 40)
  private String categoryLabel;

  @Column(name = "role_label", length = 80)
  private String roleLabel;

  @Column(name = "footer_kind", nullable = false, length = 20)
  private String footerKind;

  @Column(name = "footer_date_label", length = 40)
  private String footerDateLabel;

  @Column(name = "member_avatar_seeds", length = 200)
  private String memberAvatarSeeds;

  @Column(name = "extra_member_count")
  private Integer extraMemberCount;

  @Column(name = "footer_avatar_seed", length = 80)
  private String footerAvatarSeed;

  @Column(name = "footer_text", length = 120)
  private String footerText;

  @Column(name = "footer_meta_text", length = 80)
  private String footerMetaText;

  @Column(name = "footer_meta_icon", length = 60)
  private String footerMetaIcon;

  @Column(name = "sort_order", nullable = false)
  private int sortOrder;

  @Column(name = "is_deleted", nullable = false)
  @Builder.Default
  private boolean isDeleted = false;
}
