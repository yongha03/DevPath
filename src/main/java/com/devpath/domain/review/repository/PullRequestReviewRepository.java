package com.devpath.domain.review.repository;

import com.devpath.domain.review.entity.PullRequestReview;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PullRequestReviewRepository extends JpaRepository<PullRequestReview, Long> {

  // PR 상세 조회에서 리뷰 목록을 최신순으로 조회한다.
  @EntityGraph(attributePaths = {"pullRequestSubmission", "reviewer"})
  List<PullRequestReview> findAllByPullRequestSubmission_IdAndIsDeletedFalseOrderByCreatedAtDesc(
      Long pullRequestId);

  // 리뷰 승인/반려 시 리뷰 작성자와 PR 정보를 함께 로딩한다.
  @EntityGraph(
      attributePaths = {
        "pullRequestSubmission",
        "pullRequestSubmission.missionSubmission",
        "pullRequestSubmission.missionSubmission.mission",
        "pullRequestSubmission.missionSubmission.mission.mentoring",
        "pullRequestSubmission.missionSubmission.mission.mentoring.mentor",
        "reviewer"
      })
  Optional<PullRequestReview> findByIdAndIsDeletedFalse(Long id);
}
