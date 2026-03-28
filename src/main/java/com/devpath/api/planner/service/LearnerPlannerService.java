package com.devpath.api.planner.service;

import com.devpath.api.planner.dto.PlannerGoalRequest;
import com.devpath.api.planner.dto.PlannerGoalResponse;
import com.devpath.api.planner.dto.WeeklyPlanRequest;
import com.devpath.api.planner.dto.WeeklyPlanResponse;
import com.devpath.domain.planner.entity.LearnerGoal;
import com.devpath.domain.planner.entity.WeeklyPlan;
import com.devpath.domain.planner.entity.WeeklyPlanStatus;
import com.devpath.domain.planner.repository.LearnerGoalRepository;
import com.devpath.domain.planner.repository.WeeklyPlanRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class LearnerPlannerService {

    private final LearnerGoalRepository learnerGoalRepository;
    private final WeeklyPlanRepository weeklyPlanRepository;

    // --- 1. 목표(Goal) 관리 ---
    @Transactional
    public PlannerGoalResponse createGoal(Long learnerId, PlannerGoalRequest request) {
        LearnerGoal goal = LearnerGoal.builder()
                .learnerId(learnerId)
                .goalType(request.getGoalType())
                .targetValue(request.getTargetValue())
                .build();
        return PlannerGoalResponse.from(learnerGoalRepository.save(goal));
    }

    public List<PlannerGoalResponse> getMyGoals(Long learnerId) {
        return learnerGoalRepository.findAllByLearnerIdAndIsActiveTrue(learnerId).stream()
                .map(PlannerGoalResponse::from)
                .collect(Collectors.toList());
    }

    // --- 2. 주간 플랜(Weekly Plan) 관리 ---
    @Transactional
    public WeeklyPlanResponse createWeeklyPlan(Long learnerId, WeeklyPlanRequest request) {
        WeeklyPlan plan = WeeklyPlan.builder()
                .learnerId(learnerId)
                .planContent(request.getPlanContent())
                .status(WeeklyPlanStatus.PLANNED)
                .build();
        return WeeklyPlanResponse.from(weeklyPlanRepository.save(plan));
    }

    public List<WeeklyPlanResponse> getMyWeeklyPlans(Long learnerId) {
        return weeklyPlanRepository.findAllByLearnerIdOrderByCreatedAtDesc(learnerId).stream()
                .map(WeeklyPlanResponse::from)
                .collect(Collectors.toList());
    }

    @Transactional
    public WeeklyPlanResponse updateWeeklyPlan(Long planId, WeeklyPlanRequest request) {
        WeeklyPlan plan = weeklyPlanRepository.findById(planId)
                .orElseThrow(() -> new IllegalArgumentException("플랜을 찾을 수 없습니다."));
        plan.updateContent(request.getPlanContent());
        return WeeklyPlanResponse.from(plan);
    }

    @Transactional
    public WeeklyPlanResponse adjustWeeklyPlan(Long planId, WeeklyPlanRequest request) {
        WeeklyPlan plan = weeklyPlanRepository.findById(planId)
                .orElseThrow(() -> new IllegalArgumentException("플랜을 찾을 수 없습니다."));
        // AI 추천 등에 의해 기존 플랜을 조정하는 로직
        plan.adjustPlan(request.getPlanContent());
        return WeeklyPlanResponse.from(plan);
    }
}