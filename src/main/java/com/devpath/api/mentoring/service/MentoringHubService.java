package com.devpath.api.mentoring.service;

import com.devpath.api.mentoring.dto.MentoringHubResponse;
import com.devpath.common.exception.CustomException;
import com.devpath.common.exception.ErrorCode;
import com.devpath.domain.mentoring.entity.Mentoring;
import com.devpath.domain.mentoring.entity.MentoringPostStatus;
import com.devpath.domain.mentoring.entity.MentoringStatus;
import com.devpath.domain.mentoring.repository.MentoringPostRepository;
import com.devpath.domain.mentoring.repository.MentoringRepository;
import com.devpath.domain.user.repository.UserRepository;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class MentoringHubService {

  private final MentoringPostRepository mentoringPostRepository;
  private final MentoringRepository mentoringRepository;
  private final UserRepository userRepository;

  public MentoringHubResponse.Hub getHub() {
    // 허브에서는 신청 가능한 OPEN 공고만 노출한다.
    List<MentoringHubResponse.OpenPost> openPosts =
        mentoringPostRepository
            .findAllByStatusAndIsDeletedFalseOrderByCreatedAtDesc(MentoringPostStatus.OPEN)
            .stream()
            .map(MentoringHubResponse.OpenPost::from)
            .toList();

    return MentoringHubResponse.Hub.of(openPosts);
  }

  public List<MentoringHubResponse.Ongoing> getOngoingMentorings() {
    // 승인 이후 실제 생성된 ONGOING 멘토링만 조회한다.
    List<Mentoring> mentorings =
        mentoringRepository.findAllByStatusAndIsDeletedFalseOrderByCreatedAtDesc(
            MentoringStatus.ONGOING);

    return mentorings.stream().map(MentoringHubResponse.Ongoing::from).toList();
  }

  public List<MentoringHubResponse.MyMentoring> getMyMentorings(Long userId) {
    // 존재하지 않는 사용자 기준으로 워크스페이스 목록을 조회하지 않도록 막는다.
    validateUserExists(userId);

    List<Mentoring> asMentor =
        mentoringRepository.findAllByMentor_IdAndIsDeletedFalseOrderByCreatedAtDesc(userId);

    List<Mentoring> asMentee =
        mentoringRepository.findAllByMentee_IdAndIsDeletedFalseOrderByCreatedAtDesc(userId);

    // 같은 사용자가 멘토와 멘티 양쪽에 걸리는 특수 상황에서도 중복 응답을 방지한다.
    Map<Long, Mentoring> uniqueMentorings = new LinkedHashMap<>();
    asMentor.forEach(mentoring -> uniqueMentorings.put(mentoring.getId(), mentoring));
    asMentee.forEach(mentoring -> uniqueMentorings.put(mentoring.getId(), mentoring));

    return uniqueMentorings.values().stream()
        .map(mentoring -> MentoringHubResponse.MyMentoring.from(mentoring, userId))
        .toList();
  }

  private void validateUserExists(Long userId) {
    // userId query parameter 누락은 Controller 레벨에서 막고, 존재 여부는 Service에서 검증한다.
    if (!userRepository.existsById(userId)) {
      throw new CustomException(ErrorCode.USER_NOT_FOUND);
    }
  }
}
