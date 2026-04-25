package com.devpath.api.admin.dto.governance;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RoadmapNodeResourceUpsertRequest {

  @NotNull(message = "노드 ID는 필수입니다.")
  private Long nodeId;

  @NotBlank(message = "자료 제목은 필수입니다.")
  private String title;

  @NotBlank(message = "자료 링크는 필수입니다.")
  private String url;

  private String description;

  private String sourceType;

  private Integer sortOrder;

  private Boolean active;
}
