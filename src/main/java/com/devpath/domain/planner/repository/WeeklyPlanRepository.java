package com.devpath.domain.planner.repository;

import com.devpath.domain.planner.entity.WeeklyPlan;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface WeeklyPlanRepository extends JpaRepository<WeeklyPlan, Long> {
    List<WeeklyPlan> findAllByLearnerIdOrderByCreatedAtDesc(Long learnerId);
}