package com.devpath.api.qna.service;

import com.devpath.api.notification.service.NotificationEventService;
import com.devpath.api.qna.dto.QnaRequest;
import com.devpath.api.qna.dto.QnaResponse;
import com.devpath.common.exception.CustomException;
import com.devpath.common.exception.ErrorCode;
import com.devpath.domain.mentoring.entity.Mentoring;
import com.devpath.domain.mentoring.repository.MentoringRepository;
import com.devpath.domain.qna.entity.MentoringAnswer;
import com.devpath.domain.qna.entity.MentoringQuestion;
import com.devpath.domain.qna.entity.QuestionStatus;
import com.devpath.domain.qna.repository.MentoringAnswerRepository;
import com.devpath.domain.qna.repository.MentoringQuestionRepository;
import com.devpath.domain.user.entity.User;
import com.devpath.domain.user.repository.UserRepository;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class MentoringQuestionService {

    private final MentoringRepository mentoringRepository;
    private final MentoringQuestionRepository mentoringQuestionRepository;
    private final MentoringAnswerRepository mentoringAnswerRepository;
    private final NotificationEventService notificationEventService;
    private final UserRepository userRepository;

    @Transactional
    public QnaResponse.MentoringQuestionDetail createQuestion(
            Long mentoringId,
            QnaRequest.QuestionCreate request
    ) {
        Mentoring mentoring = getActiveMentoring(mentoringId);
        User writer = getUser(request.writerId());

        // 멘토링 참여자만 멘토링 질문을 작성할 수 있다.
        validateMentoringParticipant(mentoring, writer.getId());

        MentoringQuestion question = MentoringQuestion.builder()
                .mentoring(mentoring)
                .writer(writer)
                .title(request.title())
                .content(request.content())
                .build();

        return QnaResponse.MentoringQuestionDetail.from(
                mentoringQuestionRepository.save(question),
                List.of()
        );
    }

    public List<QnaResponse.MentoringQuestionSummary> getQuestions(Long mentoringId) {
        // 존재하지 않거나 삭제된 멘토링 기준으로 질문 목록을 조회하지 않도록 막는다.
        getActiveMentoring(mentoringId);

        return mentoringQuestionRepository
                .findAllByMentoring_IdAndIsDeletedFalseOrderByCreatedAtDesc(mentoringId)
                .stream()
                .map(QnaResponse.MentoringQuestionSummary::from)
                .toList();
    }

    public QnaResponse.MentoringQuestionDetail getQuestion(Long questionId) {
        MentoringQuestion question = getActiveQuestion(questionId);
        List<MentoringAnswer> answers = mentoringAnswerRepository
                .findAllByQuestion_IdAndIsDeletedFalseOrderByCreatedAtAsc(questionId);

        return QnaResponse.MentoringQuestionDetail.from(question, answers);
    }

    @Transactional
    public QnaResponse.AnswerDetail createAnswer(
            Long questionId,
            QnaRequest.AnswerCreate request
    ) {
        MentoringQuestion question = getActiveQuestion(questionId);
        User writer = getUser(request.writerId());

        // 멘토링 참여자만 답변을 작성할 수 있다.
        validateMentoringParticipant(question.getMentoring(), writer.getId());

        // 닫힌 질문에는 답변을 작성할 수 없다.
        validateQuestionNotClosed(question.getStatus());

        MentoringAnswer answer = MentoringAnswer.builder()
                .question(question)
                .writer(writer)
                .content(request.content())
                .build();

        MentoringAnswer savedAnswer = mentoringAnswerRepository.save(answer);

        question.markAsAnswered();

        // 질문 작성자가 아닌 사람이 답변하면 질문 작성자에게 알림을 저장하고 SSE로 전송한다.
        createAnswerNotificationIfNeeded(question, writer);

        return QnaResponse.AnswerDetail.from(savedAnswer);
    }

    @Transactional
    public QnaResponse.Status updateStatus(
            Long questionId,
            QnaRequest.StatusUpdate request
    ) {
        MentoringQuestion question = getActiveQuestion(questionId);

        // 멘토링 참여자만 질문 상태를 변경할 수 있다.
        validateMentoringParticipant(question.getMentoring(), request.requesterId());

        question.changeStatus(request.status());

        return QnaResponse.Status.from(question);
    }

    private Mentoring getActiveMentoring(Long mentoringId) {
        return mentoringRepository.findByIdAndIsDeletedFalse(mentoringId)
                .orElseThrow(() -> new CustomException(ErrorCode.MENTORING_NOT_FOUND));
    }

    private MentoringQuestion getActiveQuestion(Long questionId) {
        return mentoringQuestionRepository.findByIdAndIsDeletedFalse(questionId)
                .orElseThrow(() -> new CustomException(ErrorCode.QNA_MENTORING_QUESTION_NOT_FOUND));
    }

    private User getUser(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));
    }

    private void validateMentoringParticipant(Mentoring mentoring, Long userId) {
        boolean mentor = mentoring.getMentor().getId().equals(userId);
        boolean mentee = mentoring.getMentee().getId().equals(userId);

        if (!mentor && !mentee) {
            throw new CustomException(ErrorCode.QNA_FORBIDDEN);
        }
    }

    private void validateQuestionNotClosed(QuestionStatus status) {
        if (status == QuestionStatus.CLOSED) {
            throw new CustomException(ErrorCode.QNA_QUESTION_CLOSED);
        }
    }

    private void createAnswerNotificationIfNeeded(MentoringQuestion question, User answerWriter) {
        if (question.getWriter().getId().equals(answerWriter.getId())) {
            return;
        }

        notificationEventService.notifySystem(
                question.getWriter().getId(),
                "멘토링 질문에 새 답변이 등록되었습니다: " + question.getTitle()
        );
    }
}
