package com.devpath.api.admin.controller;

import com.devpath.api.admin.dto.governance.AdminRoadmapNodeSummaryResponse;
import com.devpath.api.admin.dto.governance.NodeCompletionRuleRequest;
import com.devpath.api.admin.dto.governance.NodePrerequisitesRequest;
import com.devpath.api.admin.dto.governance.NodeRequiredTagsRequest;
import com.devpath.api.admin.dto.governance.NodeTypeRequest;
import com.devpath.api.admin.service.AdminNodeGovernanceService;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "Admin - Node Governance", description = "관리자 노드 거버넌스 API")
@RestController
@RequestMapping("/api/admin/nodes")
@RequiredArgsConstructor
// 공식 로드맵 노드의 필수 조건을 관리하는 관리자 API다.
public class AdminNodeGovernanceController {

  private final AdminNodeGovernanceService adminNodeGovernanceService;

  @Operation(summary = "노드 목록 조회")
  @GetMapping
  // 관리자 표에서 사용하는 노드 요약 목록을 내려준다.
  public ApiResponse<List<AdminRoadmapNodeSummaryResponse>> getNodes() {
    return ApiResponse.success(
        "노드 목록을 조회했습니다.",
        adminNodeGovernanceService.getNodes());
  }

  @Operation(summary = "노드 필수 태그 수정")
  @PutMapping("/{nodeId}/required-tags")
  public ApiResponse<Void> updateRequiredTags(
      @PathVariable Long nodeId,
      @RequestBody @Valid NodeRequiredTagsRequest request) {
    adminNodeGovernanceService.updateRequiredTags(nodeId, request);
    return ApiResponse.success("노드 필수 태그를 수정했습니다.", null);
  }

  @Operation(summary = "노드 유형 수정", description = "CONCEPT / PRACTICE / PROJECT / REVIEW / EXAM")
  @PutMapping("/{nodeId}/type")
  public ApiResponse<Void> updateNodeType(
      @PathVariable Long nodeId,
      @RequestBody @Valid NodeTypeRequest request) {
    adminNodeGovernanceService.updateNodeType(nodeId, request);
    return ApiResponse.success("노드 유형을 수정했습니다.", null);
  }

  @Operation(summary = "노드 선수조건 수정")
  @PutMapping("/{nodeId}/prerequisites")
  public ApiResponse<Void> updatePrerequisites(
      @PathVariable Long nodeId,
      @RequestBody @Valid NodePrerequisitesRequest request) {
    adminNodeGovernanceService.updatePrerequisites(nodeId, request);
    return ApiResponse.success("노드 선수조건을 수정했습니다.", null);
  }

  @Operation(summary = "노드 완료기준 수정")
  @PutMapping("/{nodeId}/completion-rule")
  public ApiResponse<Void> updateCompletionRule(
      @PathVariable Long nodeId,
      @RequestBody @Valid NodeCompletionRuleRequest request) {
    adminNodeGovernanceService.updateCompletionRule(nodeId, request);
    return ApiResponse.success("노드 완료기준을 수정했습니다.", null);
  }
}
