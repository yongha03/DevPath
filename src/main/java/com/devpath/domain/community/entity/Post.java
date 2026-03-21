package com.devpath.domain.community.entity;

import com.devpath.domain.user.entity.User;
import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "community_posts")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED) // 무분별한 객체 생성 방지
public class Post {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY) // 지연 로딩 필수 (N+1 방지)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CommunityCategory category;

    @Column(nullable = false, length = 255)
    private String title;

    @Column(columnDefinition = "TEXT", nullable = false)
    private String content;

    private int viewCount = 0;
    private int likeCount = 0;

    @Column(name = "is_deleted")
    private boolean isDeleted = false; // Soft Delete 플래그

    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "updated_at")
    private LocalDateTime updatedAt = LocalDateTime.now();

    @Builder
    public Post(User user, CommunityCategory category, String title, String content) {
        this.user = user;
        this.category = category;
        this.title = title;
        this.content = content;
    }

    // 비즈니스 메서드 (Setter 대체)
    public void updatePost(String title, String content, CommunityCategory category) {
        this.title = title;
        this.content = content;
        this.category = category;
        this.updatedAt = LocalDateTime.now();
    }

    // 조회수 증가 비즈니스 로직
    public void incrementViewCount() {
        this.viewCount++;
    }

    // Soft Delete 처리 로직
    public void deletePost() {
        this.isDeleted = true;
        this.updatedAt = LocalDateTime.now();
    }
}