package com.devpath.api.review.dto;

import com.devpath.api.review.entity.Review;
import com.devpath.api.review.entity.ReviewStatus;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
@Builder
public class ReviewResponse {

    private Long id;
    private Long courseId;
    private Long learnerId;
    private Integer rating;
    private String content;
    private ReviewStatus status;
    private Boolean isHidden;
    private LocalDateTime createdAt;

    public static ReviewResponse from(Review review) {
        return ReviewResponse.builder()
                .id(review.getId())
                .courseId(review.getCourseId())
                .learnerId(review.getLearnerId())
                .rating(review.getRating())
                .content(review.getContent())
                .status(review.getStatus())
                .isHidden(review.getIsHidden())
                .createdAt(review.getCreatedAt())
                .build();
    }
}