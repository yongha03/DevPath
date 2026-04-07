package com.devpath.api.user.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Schema(description = "User password change request DTO")
public record UserPasswordChangeRequest(
    @Schema(description = "Current password", example = "currentPassword123!")
        @NotBlank(message = "Current password is required.")
        String currentPassword,
    @Schema(description = "New password", example = "newPassword123!")
        @NotBlank(message = "New password is required.")
        @Size(min = 8, max = 100, message = "Password must be between 8 and 100 characters.")
        String newPassword) {}
