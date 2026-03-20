package com.devpath.api.community.dto;

import com.devpath.domain.community.entity.Post;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
@Builder
public class PostResponse {
    private Long id;
    private String authorName;
    private String category;
    private String title;
    private String content;
    private int viewCount;
    private int likeCount;
    private LocalDateTime createdAt;

    // Entity -> DTO 변환 정적 메서드
    public static PostResponse from(Post post) {
        return PostResponse.builder()
                .id(post.getId())
                .authorName(post.getUser().getName())
                .category(post.getCategory().name())
                .title(post.getTitle())
                .content(post.getContent())
                .viewCount(post.getViewCount())
                .likeCount(post.getLikeCount())
                .createdAt(post.getCreatedAt())
                .build();
    }
}