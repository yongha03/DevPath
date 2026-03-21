package com.devpath.domain.community.repository;

import com.devpath.domain.community.entity.Post;
import com.devpath.domain.community.entity.CommunityCategory;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface PostRepository extends JpaRepository<Post, Long> {
    // 삭제되지 않은 게시글만 카테고리별로 조회
    List<Post> findByCategoryAndIsDeletedFalseOrderByCreatedAtDesc(CommunityCategory category);
}