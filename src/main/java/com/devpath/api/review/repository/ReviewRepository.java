package com.devpath.api.review.repository;

import com.devpath.api.review.entity.Review;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ReviewRepository extends JpaRepository<Review, Long> {

    List<Review> findByCourseIdAndIsDeletedFalse(Long courseId);

    Optional<Review> findByIdAndIsDeletedFalse(Long id);
}