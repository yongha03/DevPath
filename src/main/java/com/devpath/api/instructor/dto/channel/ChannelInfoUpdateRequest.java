package com.devpath.api.instructor.dto.channel;

import jakarta.validation.constraints.NotBlank;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class ChannelInfoUpdateRequest {

    @NotBlank
    private String channelName;

    private String channelDescription;
}