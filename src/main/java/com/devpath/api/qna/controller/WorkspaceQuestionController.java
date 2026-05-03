package com.devpath.api.qna.controller;

import com.devpath.api.qna.dto.QnaRequest;
import com.devpath.api.qna.dto.QnaResponse;
import com.devpath.api.qna.service.WorkspaceQuestionService;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "Workspace Q&A", description = "팀 워크스페이스 전용 Q&A API")
@RestController
@RequiredArgsConstructor
public class WorkspaceQuestionController {

  private final WorkspaceQuestionService workspaceQuestionService;

  @PostMapping("/api/workspaces/{workspaceId}/questions")
  @Operation(summary = "워크스페이스 질문 작성", description = "팀 워크스페이스에 질문을 작성합니다.")
  public ResponseEntity<ApiResponse<QnaResponse.WorkspaceQuestionDetail>> createQuestion(
      @PathVariable Long workspaceId, @Valid @RequestBody QnaRequest.QuestionCreate request) {
    // Controller는 요청 검증, Service 호출, 공통 응답 반환만 담당한다.
    return ResponseEntity.ok(
        ApiResponse.ok(workspaceQuestionService.createQuestion(workspaceId, request)));
  }

  @GetMapping("/api/workspaces/{workspaceId}/questions")
  @Operation(summary = "워크스페이스 질문 목록 조회", description = "팀 워크스페이스의 질문 목록을 조회합니다.")
  public ResponseEntity<ApiResponse<List<QnaResponse.WorkspaceQuestionSummary>>> getQuestions(
      @PathVariable Long workspaceId) {
    // 질문 목록은 최신순으로 반환한다.
    return ResponseEntity.ok(ApiResponse.ok(workspaceQuestionService.getQuestions(workspaceId)));
  }

  @GetMapping("/api/workspace-questions/{questionId}")
  @Operation(summary = "워크스페이스 질문 단건 조회", description = "워크스페이스 질문 상세와 답변 목록을 조회합니다.")
  public ResponseEntity<ApiResponse<QnaResponse.WorkspaceQuestionDetail>> getQuestion(
      @PathVariable Long questionId) {
    // 질문 상세와 답변 목록을 함께 반환한다.
    return ResponseEntity.ok(ApiResponse.ok(workspaceQuestionService.getQuestion(questionId)));
  }

  @PostMapping("/api/workspace-questions/{questionId}/answers")
  @Operation(summary = "워크스페이스 답변 작성", description = "워크스페이스 질문에 답변을 작성하고 질문 상태를 ANSWERED로 변경합니다.")
  public ResponseEntity<ApiResponse<QnaResponse.AnswerDetail>> createAnswer(
      @PathVariable Long questionId, @Valid @RequestBody QnaRequest.AnswerCreate request) {
    // 답변 작성 시 질문 상태를 ANSWERED로 변경한다.
    return ResponseEntity.ok(
        ApiResponse.ok(workspaceQuestionService.createAnswer(questionId, request)));
  }

  @PatchMapping("/api/workspace-questions/{questionId}/status")
  @Operation(summary = "워크스페이스 질문 상태 변경", description = "워크스페이스 질문 상태를 WAITING, ANSWERED, CLOSED 중 하나로 변경합니다.")
  public ResponseEntity<ApiResponse<QnaResponse.Status>> updateStatus(
      @PathVariable Long questionId, @Valid @RequestBody QnaRequest.StatusUpdate request) {
    // 상태 변경 검증은 Service에서 처리한다.
    return ResponseEntity.ok(
        ApiResponse.ok(workspaceQuestionService.updateStatus(questionId, request)));
  }
}
