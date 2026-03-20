package com.devpath.api.learning.service;

import com.devpath.api.learning.dto.PlayerConfigRequest;
import com.devpath.api.learning.dto.PlayerConfigResponse;
import com.devpath.common.exception.CustomException;
import com.devpath.common.exception.ErrorCode;
import com.devpath.domain.learning.entity.LessonProgress;
import com.devpath.domain.learning.repository.LessonProgressRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class PlayerConfigService {

    private final LessonProgressRepository lessonProgressRepository;

    // 특정 레슨의 플레이어 설정(재생 속도 등) 조회
    @Transactional(readOnly = true)
    public PlayerConfigResponse getPlayerConfig(Long userId, Long lessonId) {
        LessonProgress progress = lessonProgressRepository
                .findByUserIdAndLessonLessonId(userId, lessonId)
                .orElseThrow(() -> new CustomException(ErrorCode.LESSON_PROGRESS_NOT_FOUND));

        return PlayerConfigResponse.from(progress);
    }

    // 재생 속도 저장
    @Transactional
    public PlayerConfigResponse updatePlaybackRate(Long userId, Long lessonId,
            PlayerConfigRequest.UpdatePlaybackRate request) {
        LessonProgress progress = lessonProgressRepository
                .findByUserIdAndLessonLessonId(userId, lessonId)
                .orElseThrow(() -> new CustomException(ErrorCode.LESSON_PROGRESS_NOT_FOUND));

        progress.updatePlaybackRate(request.getDefaultPlaybackRate());

        return PlayerConfigResponse.from(progress);
    }
}
