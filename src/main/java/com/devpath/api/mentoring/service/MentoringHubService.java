package com.devpath.api.mentoring.service;

import com.devpath.api.mentoring.dto.MentoringHubResponse;
import com.devpath.common.exception.CustomException;
import com.devpath.common.exception.ErrorCode;
import com.devpath.domain.mentoring.entity.Mentoring;
import com.devpath.domain.mentoring.entity.MentoringStatus;
import com.devpath.domain.mentoring.repository.MentoringPostRepository;
import com.devpath.domain.mentoring.repository.MentoringRepository;
import com.devpath.domain.user.entity.UserProfile;
import com.devpath.domain.user.repository.UserProfileRepository;
import com.devpath.domain.user.repository.UserRepository;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
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
  private final UserProfileRepository userProfileRepository;

  public MentoringHubResponse.Hub getHub() {
    var posts = mentoringPostRepository.findAllByIsDeletedFalseOrderByCreatedAtDesc();
    Map<Long, UserProfile> mentorProfiles =
        userProfileRepository
            .findAllByUserIdIn(
                posts.stream().map(post -> post.getMentor().getId()).collect(Collectors.toSet()))
            .stream()
            .collect(Collectors.toMap(profile -> profile.getUser().getId(), Function.identity()));

    List<MentoringHubResponse.OpenPost> openPosts =
        posts.stream()
            .map(
                post ->
                    MentoringHubResponse.OpenPost.from(
                        post, mentorProfiles.get(post.getMentor().getId())))
            .toList();

    return MentoringHubResponse.Hub.of(openPosts);
  }

  public List<MentoringHubResponse.Ongoing> getOngoingMentorings() {
    List<Mentoring> mentorings =
        mentoringRepository.findAllByStatusAndIsDeletedFalseOrderByCreatedAtDesc(
            MentoringStatus.ONGOING);

    return mentorings.stream().map(MentoringHubResponse.Ongoing::from).toList();
  }

  public List<MentoringHubResponse.MyMentoring> getMyMentorings(Long userId) {
    validateUserExists(userId);

    List<Mentoring> asMentor =
        mentoringRepository.findAllByMentor_IdAndIsDeletedFalseOrderByCreatedAtDesc(userId);

    List<Mentoring> asMentee =
        mentoringRepository.findAllByMentee_IdAndIsDeletedFalseOrderByCreatedAtDesc(userId);

    Map<Long, Mentoring> uniqueMentorings = new LinkedHashMap<>();
    asMentor.forEach(mentoring -> uniqueMentorings.put(mentoring.getId(), mentoring));
    asMentee.forEach(mentoring -> uniqueMentorings.put(mentoring.getId(), mentoring));

    return uniqueMentorings.values().stream()
        .map(mentoring -> MentoringHubResponse.MyMentoring.from(mentoring, userId))
        .toList();
  }

  private void validateUserExists(Long userId) {
    if (!userRepository.existsById(userId)) {
      throw new CustomException(ErrorCode.USER_NOT_FOUND);
    }
  }
}
