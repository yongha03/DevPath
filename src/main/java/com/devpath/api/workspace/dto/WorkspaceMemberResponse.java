package com.devpath.api.workspace.dto;

import com.devpath.domain.user.entity.User;
import com.devpath.domain.user.entity.UserProfile;
import com.devpath.domain.workspace.entity.WorkspaceMember;
import io.swagger.v3.oas.annotations.media.Schema;
import java.time.LocalDateTime;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@Schema(description = "워크스페이스 멤버 응답 DTO")
public class WorkspaceMemberResponse {

  @Schema(description = "멤버 ID", example = "1")
  private Long memberId;

  @Schema(description = "학습자 ID", example = "1")
  private Long learnerId;

  @Schema(description = "Learner display name", example = "김하늘")
  private String learnerName;

  @Schema(description = "Learner profile image URL")
  private String profileImage;

  @Schema(description = "참여 일시")
  private LocalDateTime joinedAt;

  @Schema(description = "마지막 워크스페이스 접속 일시")
  private LocalDateTime lastActiveAt;

  @Schema(description = "현재 온라인 여부")
  private boolean online;

  public static WorkspaceMemberResponse from(WorkspaceMember member) {
    return from(member, false);
  }

  public static WorkspaceMemberResponse from(WorkspaceMember member, boolean online) {
    return builder()
        .memberId(member.getId())
        .learnerId(member.getLearnerId())
        .joinedAt(member.getJoinedAt())
        .lastActiveAt(member.getLastActiveAt())
        .online(online)
        .build();
  }

  public static WorkspaceMemberResponse from(
      WorkspaceMember member, User user, UserProfile profile) {
    return from(member, user, profile, false);
  }

  public static WorkspaceMemberResponse from(
      WorkspaceMember member, User user, UserProfile profile, boolean online) {
    return builder()
        .memberId(member.getId())
        .learnerId(member.getLearnerId())
        .learnerName(user == null ? null : user.getName())
        .profileImage(profile == null ? null : profile.getDisplayProfileImage())
        .joinedAt(member.getJoinedAt())
        .lastActiveAt(member.getLastActiveAt())
        .online(online)
        .build();
  }
}
