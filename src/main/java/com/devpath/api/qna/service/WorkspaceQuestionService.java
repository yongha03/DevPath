package com.devpath.api.qna.service;

import com.devpath.api.qna.dto.QnaRequest;
import com.devpath.api.qna.dto.QnaResponse;
import com.devpath.common.exception.CustomException;
import com.devpath.common.exception.ErrorCode;
import com.devpath.domain.qna.entity.QuestionStatus;
import com.devpath.domain.qna.entity.WorkspaceAnswer;
import com.devpath.domain.qna.entity.WorkspaceQuestion;
import com.devpath.domain.qna.repository.WorkspaceAnswerRepository;
import com.devpath.domain.qna.repository.WorkspaceQuestionRepository;
import com.devpath.domain.user.entity.User;
import com.devpath.domain.user.repository.UserRepository;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class WorkspaceQuestionService {

  private final WorkspaceQuestionRepository workspaceQuestionRepository;
  private final WorkspaceAnswerRepository workspaceAnswerRepository;
  private final UserRepository userRepository;

  @Transactional
  public QnaResponse.WorkspaceQuestionDetail createQuestion(
      Long workspaceId, QnaRequest.QuestionCreate request) {
    User writer = getUser(request.writerId());

    WorkspaceQuestion question =
        WorkspaceQuestion.builder()
            .workspaceId(workspaceId)
            .writer(writer)
            .title(request.title())
            .content(request.content())
            .build();

    return QnaResponse.WorkspaceQuestionDetail.from(
        workspaceQuestionRepository.save(question), List.of());
  }

  public List<QnaResponse.WorkspaceQuestionSummary> getQuestions(Long workspaceId) {
    return workspaceQuestionRepository
        .findAllByWorkspaceIdAndIsDeletedFalseOrderByCreatedAtDesc(workspaceId)
        .stream()
        .map(QnaResponse.WorkspaceQuestionSummary::from)
        .toList();
  }

  public QnaResponse.WorkspaceQuestionDetail getQuestion(Long questionId) {
    WorkspaceQuestion question = getActiveQuestion(questionId);
    List<WorkspaceAnswer> answers =
        workspaceAnswerRepository.findAllByQuestion_IdAndIsDeletedFalseOrderByCreatedAtAsc(
            questionId);

    return QnaResponse.WorkspaceQuestionDetail.from(question, answers);
  }

  @Transactional
  public QnaResponse.AnswerDetail createAnswer(Long questionId, QnaRequest.AnswerCreate request) {
    WorkspaceQuestion question = getActiveQuestion(questionId);
    User writer = getUser(request.writerId());

    // 닫힌 질문에는 답변을 작성할 수 없다.
    validateQuestionNotClosed(question.getStatus());

    WorkspaceAnswer answer =
        WorkspaceAnswer.builder()
            .question(question)
            .writer(writer)
            .content(request.content())
            .build();

    WorkspaceAnswer savedAnswer = workspaceAnswerRepository.save(answer);

    question.markAsAnswered();

    return QnaResponse.AnswerDetail.from(savedAnswer);
  }

  @Transactional
  public QnaResponse.Status updateStatus(Long questionId, QnaRequest.StatusUpdate request) {
    WorkspaceQuestion question = getActiveQuestion(questionId);

    // 현재는 워크스페이스 멤버십 도메인과 강하게 연결하지 않고 사용자 존재 여부만 검증한다.
    validateUserExists(request.requesterId());

    question.changeStatus(request.status());

    return QnaResponse.Status.from(question);
  }

  private WorkspaceQuestion getActiveQuestion(Long questionId) {
    return workspaceQuestionRepository
        .findByIdAndIsDeletedFalse(questionId)
        .orElseThrow(() -> new CustomException(ErrorCode.QNA_WORKSPACE_QUESTION_NOT_FOUND));
  }

  private User getUser(Long userId) {
    return userRepository
        .findById(userId)
        .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));
  }

  private void validateUserExists(Long userId) {
    if (!userRepository.existsById(userId)) {
      throw new CustomException(ErrorCode.USER_NOT_FOUND);
    }
  }

  private void validateQuestionNotClosed(QuestionStatus status) {
    if (status == QuestionStatus.CLOSED) {
      throw new CustomException(ErrorCode.QNA_QUESTION_CLOSED);
    }
  }
}
