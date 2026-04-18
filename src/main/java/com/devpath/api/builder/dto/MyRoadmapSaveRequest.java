package com.devpath.api.builder.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class MyRoadmapSaveRequest {

  @NotBlank
  private String title;

  @NotEmpty
  @Valid
  private List<ModuleItem> modules;

  @Getter
  @NoArgsConstructor
  public static class ModuleItem {

    @jakarta.validation.constraints.NotNull
    private Long builderModuleId;

    private int sortOrder;

    private Integer branchGroup;
  }
}