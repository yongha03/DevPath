package com.devpath.api.user.dto;

import com.devpath.domain.user.entity.User;
import com.devpath.domain.user.entity.UserProfile;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

@Schema(description = "User profile response DTO")
public record UserProfileResponse(
    @Schema(description = "User id", example = "1") Long userId,
    @Schema(description = "Display name", example = "Kim Dev") String name,
    @Schema(description = "Email address", example = "learner@devpath.com") String email,
    @Schema(description = "Role", example = "ROLE_LEARNER") String role,
    @Schema(description = "Bio", example = "Backend learner focused on Spring.") String bio,
    @Schema(description = "Phone number", example = "010-1234-5678") String phone,
    @Schema(description = "Profile image URL") String profileImage,
    @Schema(description = "Channel or nickname", example = "CozyCoder") String channelName,
    @Schema(description = "GitHub URL") String githubUrl,
    @Schema(description = "Blog URL") String blogUrl,
    @Schema(description = "Tech tags") List<TagItem> tags) {

  public static UserProfileResponse of(User user, UserProfile profile, List<TagItem> tags) {
    return new UserProfileResponse(
        user.getId(),
        user.getName(),
        user.getEmail(),
        user.getRole().name(),
        profile == null ? null : profile.getBio(),
        profile == null ? null : profile.getPhone(),
        profile == null ? null : profile.getDisplayProfileImage(),
        profile == null ? null : profile.getChannelName(),
        profile == null ? null : profile.getGithubUrl(),
        profile == null ? null : profile.getBlogUrl(),
        tags);
  }

  @Schema(description = "Tech tag summary")
  public record TagItem(
      @Schema(description = "Tag id", example = "3") Long tagId,
      @Schema(description = "Tag name", example = "Spring Boot") String name,
      @Schema(description = "Category", example = "BACKEND") String category) {}
}
