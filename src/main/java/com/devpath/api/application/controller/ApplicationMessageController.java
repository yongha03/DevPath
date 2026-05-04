package com.devpath.api.application.controller;

import com.devpath.api.application.dto.ApplicationMessageRequest;
import com.devpath.api.application.dto.ApplicationMessageResponse;
import com.devpath.api.application.service.ApplicationMessageService;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "라운지 신청 메시지", description = "라운지 신청서/제안서 메시지 API")
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/lounge/applications/{applicationId}/messages")
public class ApplicationMessageController {

  private final ApplicationMessageService applicationMessageService;

  @PostMapping
  @Operation(summary = "라운지 신청 메시지 작성", description = "신청서/제안서에 메시지 또는 답장을 작성합니다.")
  public ResponseEntity<ApiResponse<ApplicationMessageResponse.Detail>> create(
      @PathVariable Long applicationId,
      @Valid @RequestBody ApplicationMessageRequest.Create request) {
    // Controller는 요청 검증, Service 호출, 공통 응답 반환만 담당한다.
    return ResponseEntity.ok(ApiResponse.ok(applicationMessageService.create(applicationId, request)));
  }

  @GetMapping
  @Operation(summary = "라운지 신청 메시지 목록 조회", description = "신청서/제안서의 메시지 목록을 작성 시간순으로 조회합니다.")
  public ResponseEntity<ApiResponse<List<ApplicationMessageResponse.Detail>>> getMessages(
      @PathVariable Long applicationId,
      @Parameter(description = "현재 조회자 사용자 ID", example = "2") @RequestParam Long viewerId) {
    // viewerId 기준으로 각 메시지가 내가 보낸 메시지인지 계산한다.
    return ResponseEntity.ok(
        ApiResponse.ok(applicationMessageService.getMessages(applicationId, viewerId)));
  }
}
