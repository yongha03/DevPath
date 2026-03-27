package com.devpath.api.instructor.service;

import com.devpath.api.instructor.dto.channel.ChannelInfoUpdateRequest;
import com.devpath.api.instructor.dto.channel.ChannelProfileUpdateRequest;
import com.devpath.common.exception.CustomException;
import com.devpath.common.exception.ErrorCode;
import com.devpath.domain.user.entity.UserProfile;
import com.devpath.domain.user.repository.UserProfileRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
public class InstructorChannelService {

    private final UserProfileRepository userProfileRepository;

    public void updateProfile(Long instructorId, ChannelProfileUpdateRequest request) {
        UserProfile userProfile = userProfileRepository.findByUserId(instructorId)
                .orElseThrow(() -> new CustomException(ErrorCode.RESOURCE_NOT_FOUND));

        List<String> links = request.getExternalLinks();
        String githubUrl = (links != null && links.size() > 0) ? links.get(0) : userProfile.getGithubUrl();
        String blogUrl = (links != null && links.size() > 1) ? links.get(1) : userProfile.getBlogUrl();

        userProfile.updateProfile(
                request.getIntroduction(),
                request.getProfileImageUrl(),
                userProfile.getChannelName(),
                githubUrl,
                blogUrl
        );
    }

    public void updateChannelInfo(Long instructorId, ChannelInfoUpdateRequest request) {
        UserProfile userProfile = userProfileRepository.findByUserId(instructorId)
                .orElseThrow(() -> new CustomException(ErrorCode.RESOURCE_NOT_FOUND));

        userProfile.updateProfile(
                request.getChannelDescription(),
                userProfile.getProfileImage(),
                request.getChannelName(),
                userProfile.getGithubUrl(),
                userProfile.getBlogUrl()
        );
    }
}