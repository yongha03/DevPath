package com.devpath.domain.planner.repository;

import com.devpath.domain.planner.entity.LearnerGoal;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface LearnerGoalRepository extends JpaRepository<LearnerGoal, Long> {
    List<LearnerGoal> findAllByLearnerIdAndIsActiveTrue(Long learnerId);
}