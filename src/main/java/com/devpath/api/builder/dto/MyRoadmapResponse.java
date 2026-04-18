package com.devpath.api.builder.dto;

import com.devpath.domain.builder.entity.MyRoadmap;
import com.devpath.domain.builder.entity.MyRoadmapModule;
import java.time.LocalDateTime;
import java.util.List;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class MyRoadmapResponse {

  private Long myRoadmapId;
  private String title;
  private LocalDateTime createdAt;
  private List<MyRoadmapModuleDto> modules;

  public static MyRoadmapResponse from(MyRoadmap myRoadmap) {
    return MyRoadmapResponse.builder()
        .myRoadmapId(myRoadmap.getMyRoadmapId())
        .title(myRoadmap.getTitle())
        .createdAt(myRoadmap.getCreatedAt())
        .modules(myRoadmap.getModules().stream()
            .map(MyRoadmapModuleDto::from)
            .toList())
        .build();
  }

  @Getter
  @Builder
  @AllArgsConstructor(access = AccessLevel.PRIVATE)
  public static class MyRoadmapModuleDto {

    private Long builderModuleId;
    private String moduleId;
    private String title;
    private String icon;
    private String color;
    private String bgColor;
    private List<String> topics;
    private int sortOrder;
    private Integer branchGroup;

    public static MyRoadmapModuleDto from(MyRoadmapModule m) {
      return MyRoadmapModuleDto.builder()
          .builderModuleId(m.getBuilderModule().getId())
          .moduleId(m.getBuilderModule().getModuleId())
          .title(m.getBuilderModule().getTitle())
          .icon(m.getBuilderModule().getIcon())
          .color(m.getBuilderModule().getColor())
          .bgColor(m.getBuilderModule().getBgColor())
          .topics(m.getBuilderModule().getTopics())
          .sortOrder(m.getSortOrder())
          .branchGroup(m.getBranchGroup())
          .build();
    }
  }
}