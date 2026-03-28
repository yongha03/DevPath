package com.devpath.api.planner.service;

import com.devpath.api.planner.dto.StreakResponse;
import com.devpath.domain.planner.entity.Streak;
import com.devpath.domain.planner.repository.StreakRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class LearnerStreakService {

    private final StreakRepository streakRepository;

    public StreakResponse getStreak(Long learnerId) {
        Streak streak = streakRepository.findByLearnerId(learnerId)
                .orElse(null);

        // 스트릭 정보가 없으면 기본값 0으로 반환
        if (streak == null) {
            return StreakResponse.builder()
                    .currentStreak(0)
                    .longestStreak(0)
                    .build();
        }
        return StreakResponse.from(streak);
    }

    @Transactional
    public StreakResponse refreshStreak(Long learnerId, LocalDate today) {
        // 기존 스트릭이 없으면 새로 생성해서 가져옴
        Streak streak = streakRepository.findByLearnerId(learnerId)
                .orElseGet(() -> streakRepository.save(Streak.builder()
                        .learnerId(learnerId)
                        .build()));

        // Entity 내부에 만들어둔 비즈니스 로직 호출
        streak.incrementStreak(today);

        return StreakResponse.from(streak);
    }
}