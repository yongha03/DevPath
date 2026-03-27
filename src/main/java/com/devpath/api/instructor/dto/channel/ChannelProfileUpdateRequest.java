package com.devpath.api.instructor.dto.channel;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class ChannelProfileUpdateRequest {

    private String introduction;
    private String profileImageUrl;
    private List<String> expertiseList;
    private List<String> externalLinks;
}