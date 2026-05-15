package com.devpath.api.workspace;

import com.devpath.api.workspace.dto.WorkspaceHubProjectResponse;
import com.devpath.api.workspace.service.WorkspaceHubProjectService;
import com.devpath.common.response.ApiResponse;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/workspaces/hub")
@RequiredArgsConstructor
public class WorkspaceHubProjectController {

  private final WorkspaceHubProjectService workspaceHubProjectService;

  @GetMapping("/projects")
  public ApiResponse<List<WorkspaceHubProjectResponse>> getProjects(
      @AuthenticationPrincipal Long userId) {
    return ApiResponse.ok(workspaceHubProjectService.getProjects(userId));
  }
}
