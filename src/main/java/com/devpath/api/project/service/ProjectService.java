package com.devpath.api.project.service;

import com.devpath.api.project.dto.ProjectRequest;
import com.devpath.api.project.dto.ProjectResponse;
import com.devpath.common.exception.CustomException;
import com.devpath.common.exception.ErrorCode;
import com.devpath.domain.project.entity.Project;
import com.devpath.domain.project.entity.ProjectMember;
import com.devpath.domain.project.entity.ProjectRoleType;
import com.devpath.domain.project.entity.ProjectStatus;
import com.devpath.domain.project.repository.ProjectMemberRepository;
import com.devpath.domain.project.repository.ProjectRepository;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class ProjectService {

    private final ProjectRepository projectRepository;
    private final ProjectMemberRepository projectMemberRepository;

    @Transactional
    public ProjectResponse createProject(ProjectRequest request, Long creatorId) {
        Project project = Project.builder()
                .name(request.getName().trim())
                .description(request.getDescription())
                .status(ProjectStatus.PREPARING)
                .build();

        Project savedProject = projectRepository.save(project);

        ProjectMember leaderMember = ProjectMember.builder()
                .projectId(savedProject.getId())
                .learnerId(creatorId)
                .roleType(ProjectRoleType.LEADER)
                .build();
        projectMemberRepository.save(leaderMember);

        return ProjectResponse.from(savedProject);
    }

    public List<ProjectResponse> getAllProjects() {
        return projectRepository.findAllByIsDeletedFalseOrderByCreatedAtDesc().stream()
                .map(ProjectResponse::from)
                .toList();
    }

    public ProjectResponse getProject(Long projectId) {
        return ProjectResponse.from(getProjectEntity(projectId));
    }

    @Transactional
    public ProjectResponse updateProject(Long projectId, Long requesterId, ProjectRequest request) {
        Project project = getProjectEntity(projectId);
        validateProjectMember(project.getId(), requesterId);

        project.updateProject(request.getName().trim(), request.getDescription());
        return ProjectResponse.from(project);
    }

    private void validateProjectMember(Long projectId, Long requesterId) {
        if (!projectMemberRepository.existsByProjectIdAndLearnerId(projectId, requesterId)) {
            throw new CustomException(ErrorCode.UNAUTHORIZED_ACTION, "Only project members can update the project.");
        }
    }

    private Project getProjectEntity(Long projectId) {
        return projectRepository.findByIdAndIsDeletedFalse(projectId)
                .orElseThrow(() -> new CustomException(ErrorCode.RESOURCE_NOT_FOUND, "Project not found."));
    }
}
