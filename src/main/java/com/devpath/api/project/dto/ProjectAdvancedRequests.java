package com.devpath.api.project.dto;

import com.devpath.domain.project.entity.ProjectRoleType;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

public class ProjectAdvancedRequests {

    @Getter
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    @Schema(description = "프로젝트 초대 요청 DTO")
    public static class InvitationRequest {
        @NotNull(message = "프로젝트 ID는 필수입니다.")
        @Schema(description = "프로젝트 ID", example = "1")
        private Long projectId;

        @NotNull(message = "초대할 유저 ID는 필수입니다.")
        @Schema(description = "초대받는 유저 ID", example = "2")
        private Long inviteeId;
    }

    @Getter
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    @Schema(description = "프로젝트 역할 생성/수정 요청 DTO")
    public static class RoleRequest {
        @NotNull(message = "프로젝트 ID는 필수입니다.")
        @Schema(description = "프로젝트 ID", example = "1")
        private Long projectId;

        @NotNull(message = "역할 타입은 필수입니다.")
        @Schema(description = "역할 (예: BACKEND, FRONTEND)", example = "BACKEND")
        private ProjectRoleType roleType;

        @NotNull(message = "필요 인원 수는 필수입니다.")
        @Schema(description = "해당 역할의 모집 필요 인원", example = "2")
        private Integer requiredCount;
    }

    @Getter
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    @Schema(description = "멘토링 지원 요청 DTO")
    public static class MentoringRequest {
        @NotNull(message = "프로젝트 ID는 필수입니다.")
        @Schema(description = "프로젝트 ID", example = "1")
        private Long projectId;

        @NotNull(message = "멘토 ID는 필수입니다.")
        @Schema(description = "지원할 멘토의 ID", example = "5")
        private Long mentorId;

        @NotBlank(message = "지원 메시지는 필수입니다.")
        @Schema(description = "멘토에게 남기는 지원 메시지", example = "열심히 하겠습니다!")
        private String message;
    }

    @Getter
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    @Schema(description = "프로젝트 아이디어 게시글 요청 DTO")
    public static class IdeaPostRequest {
        @NotBlank(message = "제목은 필수입니다.")
        @Schema(description = "게시글 제목", example = "O2O 펫 시터 플랫폼 팀원 구합니다.")
        private String title;

        @NotBlank(message = "내용은 필수입니다.")
        @Schema(description = "게시글 내용", example = "프로젝트 상세 내용...")
        private String content;
    }

    @Getter
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    @Schema(description = "프로젝트 인증(Proof) 제출 요청 DTO")
    public static class ProofSubmissionRequest {
        @NotNull(message = "프로젝트 ID는 필수입니다.")
        @Schema(description = "프로젝트 ID", example = "1")
        private Long projectId;

        @NotBlank(message = "Proof Card ID는 필수입니다.")
        @Schema(description = "발급된 Proof Card의 참조 ID", example = "PROOF-2026-ABC")
        private String proofCardRefId;
    }
}