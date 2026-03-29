package com.devpath.api.recommendation.service;

import com.devpath.api.learning.service.SupplementRecommendationService;
import com.devpath.api.learning.service.TilService;
import com.devpath.api.learning.service.WeaknessAnalysisService;
import com.devpath.api.recommendation.dto.RecommendationChangeRequest;
import com.devpath.api.recommendation.dto.RecommendationChangeResponse;
import com.devpath.common.exception.CustomException;
import com.devpath.common.exception.ErrorCode;
import com.devpath.domain.learning.entity.recommendation.RecommendationChange;
import com.devpath.domain.learning.entity.recommendation.RecommendationChangeStatus;
import com.devpath.domain.learning.entity.recommendation.RecommendationHistory;
import com.devpath.domain.learning.entity.recommendation.SupplementRecommendation;
import com.devpath.domain.learning.repository.recommendation.RecommendationChangeRepository;
import com.devpath.domain.learning.repository.recommendation.RecommendationHistoryRepository;
import com.devpath.domain.roadmap.repository.RoadmapRepository;
import com.devpath.domain.user.entity.User;
import com.devpath.domain.user.repository.UserRepository;
import java.util.List;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class RecommendationChangeService {

    private final RecommendationChangeRepository recommendationChangeRepository;
    private final RecommendationHistoryRepository recommendationHistoryRepository;
    private final UserRepository userRepository;
    private final RoadmapRepository roadmapRepository;
    private final SupplementRecommendationService supplementRecommendationService;
    private final RecommendationHistoryService recommendationHistoryService;
    private final RiskWarningService riskWarningService;
    private final WeaknessAnalysisService weaknessAnalysisService;
    private final TilService tilService;

    @Transactional
    public List<RecommendationChangeResponse.Detail> createSuggestions(
        Long userId,
        RecommendationChangeRequest.Suggestion request
    ) {
        User user = validateUser(userId);

        if (request.getRoadmapId() != null) {
            roadmapRepository.findByRoadmapIdAndIsDeletedFalse(request.getRoadmapId())
                .orElseThrow(() -> new CustomException(ErrorCode.ROADMAP_NOT_FOUND));
        }

        int limit = request.getLimit() == null || request.getLimit() <= 0 ? 5 : request.getLimit();
        long tilSignalCount = tilService.getTilSignalCountForRecommendationChange(userId);
        boolean weaknessSignal = weaknessAnalysisService.hasLatestAnalysisSignalForRecommendationChange(userId);
        long riskWarningCount = riskWarningService.getUnacknowledgedWarningCountForRecommendationChange(userId);
        long recommendationHistoryCount =
            recommendationHistoryService.getRecentHistoryCountForRecommendationChange(userId);

        List<SupplementRecommendation> supplementRecommendations =
            supplementRecommendationService.getPendingRecommendationsForRecommendationChange(userId, request.getRoadmapId());

        return supplementRecommendations.stream()
            .limit(limit)
            .map(supplementRecommendation -> upsertChange(
                user,
                supplementRecommendation,
                buildReason(supplementRecommendation),
                buildContextSummary(tilSignalCount, weaknessSignal, riskWarningCount, recommendationHistoryCount)
            ))
            .map(this::toDetail)
            .toList();
    }

    @Transactional(readOnly = true)
    public List<RecommendationChangeResponse.Detail> getRecommendationChanges(Long userId) {
        validateUser(userId);

        return recommendationChangeRepository.findAllByUserIdAndChangeStatusOrderByCreatedAtDesc(
                userId,
                RecommendationChangeStatus.SUGGESTED
            )
            .stream()
            .map(this::toDetail)
            .toList();
    }

    @Transactional
    public RecommendationChangeResponse.Detail apply(Long userId, Long changeId) {
        RecommendationChange recommendationChange = recommendationChangeRepository.findByIdAndUserId(changeId, userId)
            .orElseThrow(() -> new CustomException(ErrorCode.RECOMMENDATION_CHANGE_NOT_FOUND));

        if (recommendationChange.getChangeStatus() != RecommendationChangeStatus.SUGGESTED) {
            throw new CustomException(ErrorCode.RECOMMENDATION_ALREADY_PROCESSED);
        }

        recommendationChange.apply();

        if (recommendationChange.getSourceRecommendationId() != null) {
            supplementRecommendationService.approveRecommendation(userId, recommendationChange.getSourceRecommendationId());
        }

        saveHistory(
            recommendationChange,
            "CHANGE_APPLY",
            RecommendationChangeStatus.SUGGESTED.name(),
            RecommendationChangeStatus.APPLIED.name()
        );

        return toDetail(recommendationChange);
    }

    @Transactional
    public RecommendationChangeResponse.Detail ignore(Long userId, Long changeId) {
        RecommendationChange recommendationChange = recommendationChangeRepository.findByIdAndUserId(changeId, userId)
            .orElseThrow(() -> new CustomException(ErrorCode.RECOMMENDATION_CHANGE_NOT_FOUND));

        if (recommendationChange.getChangeStatus() != RecommendationChangeStatus.SUGGESTED) {
            throw new CustomException(ErrorCode.RECOMMENDATION_ALREADY_PROCESSED);
        }

        recommendationChange.ignore();

        if (recommendationChange.getSourceRecommendationId() != null) {
            supplementRecommendationService.rejectRecommendation(userId, recommendationChange.getSourceRecommendationId());
        }

        saveHistory(
            recommendationChange,
            "CHANGE_IGNORE",
            RecommendationChangeStatus.SUGGESTED.name(),
            RecommendationChangeStatus.IGNORED.name()
        );

        return toDetail(recommendationChange);
    }

    @Transactional(readOnly = true)
    public List<RecommendationChangeResponse.HistoryItem> getHistories(Long userId) {
        validateUser(userId);

        return recommendationChangeRepository.findAllByUserIdAndChangeStatusInOrderByUpdatedAtDesc(
                userId,
                Set.of(
                    RecommendationChangeStatus.APPLIED,
                    RecommendationChangeStatus.IGNORED,
                    RecommendationChangeStatus.RECALCULATED
                )
            )
            .stream()
            .map(recommendationChange -> RecommendationChangeResponse.HistoryItem.builder()
                .changeId(recommendationChange.getId())
                .nodeId(recommendationChange.getRoadmapNode().getNodeId())
                .nodeTitle(recommendationChange.getRoadmapNode().getTitle())
                .changeStatus(recommendationChange.getChangeStatus().name())
                .decisionStatus(recommendationChange.getDecisionStatus().name())
                .updatedAt(recommendationChange.getUpdatedAt())
                .build())
            .toList();
    }

    @Transactional
    public RecommendationChangeResponse.RecalculateResult recalculateNextNodes(
        Long userId,
        RecommendationChangeRequest.RecalculateNextNodes request
    ) {
        validateUser(userId);

        List<RecommendationChange> currentPendingChanges =
            request.getRoadmapId() == null
                ? recommendationChangeRepository.findAllByUserIdAndChangeStatusOrderByCreatedAtDesc(
                    userId,
                    RecommendationChangeStatus.SUGGESTED
                )
                : recommendationChangeRepository.findAllByUserIdAndRoadmapNodeRoadmapRoadmapIdAndChangeStatusOrderByCreatedAtDesc(
                    userId,
                    request.getRoadmapId(),
                    RecommendationChangeStatus.SUGGESTED
                );

        for (RecommendationChange currentPendingChange : currentPendingChanges) {
            currentPendingChange.markRecalculated();
        }

        List<RecommendationChangeResponse.Detail> regenerated = createSuggestions(
            userId,
            RecommendationChangeRequest.SuggestionHolder.from(request)
        );

        return RecommendationChangeResponse.RecalculateResult.builder()
            .recalculatedCount(currentPendingChanges.size())
            .items(regenerated)
            .build();
    }

    private RecommendationChange upsertChange(
        User user,
        SupplementRecommendation supplementRecommendation,
        String reason,
        String contextSummary
    ) {
        return recommendationChangeRepository
            .findTopByUserIdAndRoadmapNodeNodeIdAndChangeStatusOrderByCreatedAtDesc(
                user.getId(),
                supplementRecommendation.getRoadmapNode().getNodeId(),
                RecommendationChangeStatus.SUGGESTED
            )
            .orElseGet(() -> recommendationChangeRepository.save(
                RecommendationChange.builder()
                    .user(user)
                    .roadmapNode(supplementRecommendation.getRoadmapNode())
                    .sourceRecommendationId(supplementRecommendation.getId())
                    .reason(reason)
                    .contextSummary(contextSummary)
                    .build()
            ));
    }

    private String buildReason(SupplementRecommendation supplementRecommendation) {
        if (supplementRecommendation.getReason() != null && !supplementRecommendation.getReason().isBlank()) {
            return supplementRecommendation.getReason();
        }

        return "Generated a recommendation change from the existing supplement recommendation flow.";
    }

    private String buildContextSummary(
        long tilSignalCount,
        boolean weaknessSignal,
        long riskWarningCount,
        long recommendationHistoryCount
    ) {
        return "tilCount=" + tilSignalCount
            + ", weaknessSignal=" + weaknessSignal
            + ", warningCount=" + riskWarningCount
            + ", historyCount=" + recommendationHistoryCount;
    }

    private void saveHistory(
        RecommendationChange recommendationChange,
        String actionType,
        String beforeStatus,
        String afterStatus
    ) {
        recommendationHistoryRepository.save(
            RecommendationHistory.builder()
                .user(recommendationChange.getUser())
                .recommendationId(recommendationChange.getId())
                .roadmapNode(recommendationChange.getRoadmapNode())
                .beforeStatus(beforeStatus)
                .afterStatus(afterStatus)
                .actionType(actionType)
                .context(recommendationChange.getContextSummary())
                .build()
        );
    }

    private User validateUser(Long userId) {
        if (userId == null) {
            throw new CustomException(ErrorCode.UNAUTHORIZED);
        }

        return userRepository.findById(userId)
            .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));
    }

    private RecommendationChangeResponse.Detail toDetail(RecommendationChange recommendationChange) {
        return RecommendationChangeResponse.Detail.builder()
            .changeId(recommendationChange.getId())
            .sourceRecommendationId(recommendationChange.getSourceRecommendationId())
            .nodeId(recommendationChange.getRoadmapNode().getNodeId())
            .nodeTitle(recommendationChange.getRoadmapNode().getTitle())
            .reason(recommendationChange.getReason())
            .contextSummary(recommendationChange.getContextSummary())
            .changeStatus(recommendationChange.getChangeStatus().name())
            .decisionStatus(recommendationChange.getDecisionStatus().name())
            .suggestedAt(recommendationChange.getSuggestedAt())
            .appliedAt(recommendationChange.getAppliedAt())
            .ignoredAt(recommendationChange.getIgnoredAt())
            .build();
    }
}
