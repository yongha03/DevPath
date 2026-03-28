package com.devpath.domain.planner.repository;

import com.devpath.domain.planner.entity.Streak;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface StreakRepository extends JpaRepository<Streak, Long> {
    Optional<Streak> findByLearnerId(Long learnerId);
}