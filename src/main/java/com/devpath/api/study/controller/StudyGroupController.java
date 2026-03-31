package com.devpath.api.study.controller;

import static com.devpath.common.security.AuthenticationUtils.requireUserId;

import com.devpath.api.study.dto.StudyApplicationResponse;
import com.devpath.api.study.dto.StudyGroupRequest;
import com.devpath.api.study.dto.StudyGroupResponse;
import com.devpath.api.study.dto.StudyGroupStatusRequest;
import com.devpath.api.study.service.StudyGroupService;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/study-groups")
@RequiredArgsConstructor
@Tag(name = "Learner - Study Group", description = "Study group recruitment and management API")
public class StudyGroupController {

    private final StudyGroupService studyGroupService;

    @PostMapping
    @Operation(summary = "Create study group")
    public ApiResponse<StudyGroupResponse> createStudyGroup(
            @Parameter(hidden = true) @AuthenticationPrincipal Long learnerId,
            @Valid @RequestBody StudyGroupRequest request
    ) {
        return ApiResponse.ok(studyGroupService.createStudyGroup(requireUserId(learnerId), request));
    }

    @GetMapping
    @Operation(summary = "List study groups")
    public ApiResponse<List<StudyGroupResponse>> getAllStudyGroups() {
        return ApiResponse.ok(studyGroupService.getAllStudyGroups());
    }

    @GetMapping("/{groupId}")
    @Operation(summary = "Get study group")
    public ApiResponse<StudyGroupResponse> getStudyGroup(@PathVariable Long groupId) {
        return ApiResponse.ok(studyGroupService.getStudyGroup(groupId));
    }

    @PutMapping("/{groupId}")
    @Operation(summary = "Update study group")
    public ApiResponse<StudyGroupResponse> updateStudyGroup(
            @PathVariable Long groupId,
            @Parameter(hidden = true) @AuthenticationPrincipal Long learnerId,
            @Valid @RequestBody StudyGroupRequest request
    ) {
        return ApiResponse.ok(studyGroupService.updateStudyGroup(groupId, requireUserId(learnerId), request));
    }

    @DeleteMapping("/{groupId}")
    @Operation(summary = "Delete study group")
    public ApiResponse<Void> deleteStudyGroup(
            @PathVariable Long groupId,
            @Parameter(hidden = true) @AuthenticationPrincipal Long learnerId
    ) {
        studyGroupService.deleteStudyGroup(groupId, requireUserId(learnerId));
        return ApiResponse.ok();
    }

    @PatchMapping("/{groupId}/recruitment-status")
    @Operation(summary = "Change recruitment status")
    public ApiResponse<StudyGroupResponse> changeRecruitmentStatus(
            @PathVariable Long groupId,
            @Parameter(hidden = true) @AuthenticationPrincipal Long learnerId,
            @Valid @RequestBody StudyGroupStatusRequest request
    ) {
        return ApiResponse.ok(
                studyGroupService.changeRecruitmentStatus(groupId, requireUserId(learnerId), request.getStatus())
        );
    }

    @PostMapping("/{groupId}/applications")
    @Operation(summary = "Apply for study group")
    public ApiResponse<StudyApplicationResponse> applyForStudyGroup(
            @PathVariable Long groupId,
            @Parameter(hidden = true) @AuthenticationPrincipal Long learnerId
    ) {
        return ApiResponse.ok(studyGroupService.applyForStudyGroup(groupId, requireUserId(learnerId)));
    }

    @PostMapping("/{groupId}/applications/{applicationId}/approve")
    @Operation(summary = "Approve study application")
    public ApiResponse<StudyApplicationResponse> approveApplication(
            @PathVariable Long groupId,
            @PathVariable Long applicationId,
            @Parameter(hidden = true) @AuthenticationPrincipal Long learnerId
    ) {
        return ApiResponse.ok(
                studyGroupService.approveApplication(groupId, applicationId, requireUserId(learnerId))
        );
    }

    @PostMapping("/{groupId}/applications/{applicationId}/reject")
    @Operation(summary = "Reject study application")
    public ApiResponse<StudyApplicationResponse> rejectApplication(
            @PathVariable Long groupId,
            @PathVariable Long applicationId,
            @Parameter(hidden = true) @AuthenticationPrincipal Long learnerId
    ) {
        return ApiResponse.ok(
                studyGroupService.rejectApplication(groupId, applicationId, requireUserId(learnerId))
        );
    }
}
