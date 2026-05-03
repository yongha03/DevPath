package com.devpath.api.mentoring.service;

import com.devpath.api.mentoring.dto.MentoringWorkspaceResponse;
import com.devpath.common.exception.CustomException;
import com.devpath.common.exception.ErrorCode;
import com.devpath.domain.mentoring.entity.Mentoring;
import com.devpath.domain.mentoring.repository.MentoringRepository;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class MentoringWorkspaceService {

  private final MentoringRepository mentoringRepository;

  public MentoringWorkspaceResponse.Workspace getWorkspace(Long mentoringId) {
    Mentoring mentoring = getActiveMentoring(mentoringId);

    // 워크스페이스는 기본 정보, 참여자, count, 최근 활동을 한 번에 반환한다.
    return MentoringWorkspaceResponse.Workspace.from(
        mentoring, buildStats(mentoring.getId()), buildRecentActivities(mentoring));
  }

  public MentoringWorkspaceResponse.Dashboard getDashboard(Long mentoringId) {
    Mentoring mentoring = getActiveMentoring(mentoringId);

    // 대시보드는 프론트 카드 UI에 맞춰 요약 중심 응답을 반환한다.
    return MentoringWorkspaceResponse.Dashboard.from(
        mentoring, buildStats(mentoring.getId()), buildRecentActivities(mentoring));
  }

  private Mentoring getActiveMentoring(Long mentoringId) {
    // Soft Delete 된 멘토링은 워크스페이스 조회 대상에서 제외한다.
    return mentoringRepository
        .findByIdAndIsDeletedFalse(mentoringId)
        .orElseThrow(() -> new CustomException(ErrorCode.MENTORING_NOT_FOUND));
  }

  private MentoringWorkspaceResponse.Stats buildStats(Long mentoringId) {
    // 5단계 이후 MentoringMissionRepository가 생기면 실제 미션 개수로 교체한다.
    long missionCount = countMissions(mentoringId);

    // 7단계 이후 PullRequestSubmissionRepository가 생기면 실제 PR 제출 개수로 교체한다.
    long pullRequestCount = countPullRequests(mentoringId);

    // 10단계 이후 MentoringQuestionRepository가 생기면 실제 질문 개수로 교체한다.
    long questionCount = countQuestions(mentoringId);

    // 13단계 이후 MeetingRoomRepository가 생기면 실제 회의 개수로 교체한다.
    long meetingCount = countMeetings(mentoringId);

    return MentoringWorkspaceResponse.Stats.of(
        missionCount, pullRequestCount, questionCount, meetingCount);
  }

  private List<MentoringWorkspaceResponse.RecentActivity> buildRecentActivities(
      Mentoring mentoring) {
    // 아직 활동 도메인이 없으므로 멘토링 시작 이벤트를 기본 최근 활동으로 제공한다.
    return List.of(
        MentoringWorkspaceResponse.RecentActivity.of(
            "MENTORING_STARTED", "멘토링이 시작되었습니다.", mentoring.getStartedAt()));
  }

  private long countMissions(Long mentoringId) {
    // 후속 단계에서 실제 Repository count 쿼리로 교체한다.
    return 0L;
  }

  private long countPullRequests(Long mentoringId) {
    // 후속 단계에서 실제 Repository count 쿼리로 교체한다.
    return 0L;
  }

  private long countQuestions(Long mentoringId) {
    // 후속 단계에서 실제 Repository count 쿼리로 교체한다.
    return 0L;
  }

  private long countMeetings(Long mentoringId) {
    // 후속 단계에서 실제 Repository count 쿼리로 교체한다.
    return 0L;
  }
}
