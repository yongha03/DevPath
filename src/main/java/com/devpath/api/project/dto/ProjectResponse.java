package com.devpath.api.project.dto;

import com.devpath.domain.project.entity.Project;
import com.devpath.domain.project.entity.ProjectStatus;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
@Builder
@Schema(description = "프로젝트 응답 DTO")
public class ProjectResponse {

    @Schema(description = "프로젝트 ID", example = "1")
    private Long id;

    @Schema(description = "프로젝트 이름", example = "DevPath 클론 코딩")
    private String name;

    @Schema(description = "프로젝트 설명", example = "React와 Spring Boot를 활용한 플랫폼 개발")
    private String description;

    @Schema(description = "프로젝트 진행 상태", example = "PREPARING")
    private ProjectStatus status;

    @Schema(description = "생성 일시")
    private LocalDateTime createdAt;

    public static ProjectResponse from(Project project) {
        return ProjectResponse.builder()
                .id(project.getId())
                .name(project.getName())
                .description(project.getDescription())
                .status(project.getStatus())
                .createdAt(project.getCreatedAt())
                .build();
    }
}