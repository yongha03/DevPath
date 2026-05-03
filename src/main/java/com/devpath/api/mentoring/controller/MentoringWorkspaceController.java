package com.devpath.api.mentoring.controller;

import com.devpath.api.mentoring.dto.MentoringWorkspaceResponse;
import com.devpath.api.mentoring.service.MentoringWorkspaceService;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "Mentoring Workspace", description = "멘토링 워크스페이스 및 대시보드 API")
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/mentorings")
public class MentoringWorkspaceController {

  private final MentoringWorkspaceService mentoringWorkspaceService;

  @GetMapping("/{mentoringId}/workspace")
  @Operation(summary = "멘토링 워크스페이스 조회", description = "승인된 멘토링의 기본 정보, 참여자, 집계, 최근 활동을 조회합니다.")
  public ResponseEntity<ApiResponse<MentoringWorkspaceResponse.Workspace>> getWorkspace(
      @PathVariable Long mentoringId) {
    // Controller는 Service 호출과 공통 응답 반환만 담당한다.
    return ResponseEntity.ok(ApiResponse.ok(mentoringWorkspaceService.getWorkspace(mentoringId)));
  }

  @GetMapping("/{mentoringId}/dashboard")
  @Operation(summary = "멘토링 대시보드 조회", description = "멘토링 워크스페이스의 요약 대시보드 정보를 조회합니다.")
  public ResponseEntity<ApiResponse<MentoringWorkspaceResponse.Dashboard>> getDashboard(
      @PathVariable Long mentoringId) {
    // 대시보드는 count 중심의 요약 정보를 반환한다.
    return ResponseEntity.ok(ApiResponse.ok(mentoringWorkspaceService.getDashboard(mentoringId)));
  }
}
