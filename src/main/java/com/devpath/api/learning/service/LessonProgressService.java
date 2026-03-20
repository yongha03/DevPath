package com.devpath.api.learning.service;

import com.devpath.api.learning.dto.LessonProgressRequest;
import com.devpath.api.learning.dto.LessonProgressResponse;
import com.devpath.common.exception.CustomException;
import com.devpath.common.exception.ErrorCode;
import com.devpath.domain.course.entity.Lesson;
import com.devpath.domain.course.repository.LessonRepository;
import com.devpath.domain.learning.entity.LessonProgress;
import com.devpath.domain.learning.repository.LessonProgressRepository;
import com.devpath.domain.user.entity.User;
import com.devpath.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class LessonProgressService {

    private final LessonProgressRepository lessonProgressRepository;
    private final LessonRepository lessonRepository;
    private final UserRepository userRepository;

    // 강의 세션 시작: 진도 이력이 없으면 새로 생성하고, 있으면 기존 진도 정보를 반환한다.
    @Transactional
    public LessonProgressResponse startSession(Long userId, Long lessonId) {
        Lesson lesson = lessonRepository.findById(lessonId)
                .orElseThrow(() -> new CustomException(ErrorCode.LESSON_NOT_FOUND));
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

        LessonProgress progress = lessonProgressRepository
                .findByUserIdAndLessonLessonId(userId, lessonId)
                .orElseGet(() -> lessonProgressRepository.save(
                        LessonProgress.builder()
                                .user(user)
                                .lesson(lesson)
                                .build()
                ));

        return LessonProgressResponse.from(progress);
    }

    // 진도율 및 재생 위치 저장
    @Transactional
    public LessonProgressResponse saveProgress(Long userId, Long lessonId,
            LessonProgressRequest.SaveProgress request) {
        LessonProgress progress = lessonProgressRepository
                .findByUserIdAndLessonLessonId(userId, lessonId)
                .orElseThrow(() -> new CustomException(ErrorCode.LESSON_PROGRESS_NOT_FOUND));

        progress.updateProgress(request.getProgressPercent(), request.getProgressSeconds());

        return LessonProgressResponse.from(progress);
    }

    // 현재 진도율 조회
    @Transactional(readOnly = true)
    public LessonProgressResponse getProgress(Long userId, Long lessonId) {
        LessonProgress progress = lessonProgressRepository
                .findByUserIdAndLessonLessonId(userId, lessonId)
                .orElseThrow(() -> new CustomException(ErrorCode.LESSON_PROGRESS_NOT_FOUND));

        return LessonProgressResponse.from(progress);
    }
}
