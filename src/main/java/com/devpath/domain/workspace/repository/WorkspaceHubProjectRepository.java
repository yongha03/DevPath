package com.devpath.domain.workspace.repository;

import com.devpath.domain.workspace.entity.WorkspaceHubProject;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface WorkspaceHubProjectRepository extends JpaRepository<WorkspaceHubProject, Long> {

  List<WorkspaceHubProject> findAllByIsDeletedFalseOrderBySortOrderAscIdAsc();

  Optional<WorkspaceHubProject> findByDomIdAndIsDeletedFalse(String domId);
}
