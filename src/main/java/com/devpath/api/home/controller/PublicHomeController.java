package com.devpath.api.home.controller;

import com.devpath.api.home.dto.PublicHomeDto;
import com.devpath.api.home.service.PublicHomeService;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "공개 홈", description = "랜딩 페이지 개요 조회 API")
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/home")
public class PublicHomeController {

  private final PublicHomeService publicHomeService;

  @Operation(summary = "랜딩 페이지 개요 조회", description = "랜딩 페이지에 노출할 공개 개요 데이터를 조회합니다.")
  @GetMapping("/overview")
  public ApiResponse<PublicHomeDto.OverviewResponse> getOverview() {
    return ApiResponse.ok(publicHomeService.getOverview());
  }
}
