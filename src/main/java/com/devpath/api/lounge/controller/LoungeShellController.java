package com.devpath.api.lounge.controller;

import com.devpath.api.lounge.dto.LoungeShellResponse;
import com.devpath.api.lounge.service.LoungeShellService;
import com.devpath.common.response.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/lounge/shell")
@RequiredArgsConstructor
public class LoungeShellController {

  private final LoungeShellService loungeShellService;

  @GetMapping
  public ApiResponse<LoungeShellResponse.Shell> getShell(@AuthenticationPrincipal Long userId) {
    return ApiResponse.ok(loungeShellService.getShell(userId));
  }
}
