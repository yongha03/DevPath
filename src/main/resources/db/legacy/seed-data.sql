-- ============================================================
-- DevPath 개발 환경 시드 데이터
--
-- 이 파일은 서버 기동 시 자동으로 실행된다 (spring.sql.init.mode=always).
-- 모든 INSERT는 WHERE NOT EXISTS 조건이 붙어 있어 중복 실행해도 안전하다.
--
-- [주의] 이 파일에 없는 데이터(강의, 수강생 등)는 환경마다 다를 수 있다.
--        팀원 간 데이터를 맞추려면 이 파일에 추가해야 한다.
--
-- 섹션 순서:
--   1. Roles         - 권한 (LEARNER / INSTRUCTOR / ADMIN)
--   2. Users         - 기본 계정 3개 (learner / instructor / admin)
--   3. User Profiles - 강사·관리자 프로필
--   4. Tags          - 기술 스택 태그
--   5. Roadmaps      - 공식 로드맵 및 노드
--   6. Courses       - 샘플 강의 5개 (PUBLISHED 2, DRAFT 2, IN_REVIEW 1)
--   7. Course 부속 데이터 (섹션·강의·목표·태그 등)
--   8. Enrollments   - 수강 신청 샘플
--   9. QnA           - 질문·답변 샘플
--  10. Reviews       - 수강평 샘플
-- ============================================================

-- ============================================================
-- 1. Roles
-- ============================================================
INSERT INTO roles (role_name, description)
SELECT 'ROLE_LEARNER', 'General learner'
WHERE NOT EXISTS (
    SELECT 1
    FROM roles
    WHERE role_name = 'ROLE_LEARNER'
);

INSERT INTO roles (role_name, description)
SELECT 'ROLE_INSTRUCTOR', 'Can create and manage courses'
WHERE NOT EXISTS (
    SELECT 1
    FROM roles
    WHERE role_name = 'ROLE_INSTRUCTOR'
);

INSERT INTO roles (role_name, description)
SELECT 'ROLE_ADMIN', 'System administrator'
WHERE NOT EXISTS (
    SELECT 1
    FROM roles
    WHERE role_name = 'ROLE_ADMIN'
);

-- ============================================================
-- 2. Users  (비밀번호: devpath1234)
-- ============================================================
INSERT INTO users (email, password, name, role_name, is_active, created_at, updated_at)
SELECT
    'learner@devpath.com',
    '$2a$10$lEubudcVnsxZ6EAO3.joFOPndlLjv9.bi5FcO4z59a74fCMjqZA.O',
    '이학습',
    'ROLE_LEARNER',
    TRUE,
    NOW(),
    NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM users
    WHERE email = 'learner@devpath.com'
);

INSERT INTO users (email, password, name, role_name, is_active, created_at, updated_at)
SELECT
    'instructor@devpath.com',
    '$2a$10$xh6.EW/FRzJBWfxqpdXh2uTVoepPhUxQRUH5OEwk90IpYeKjegkj.',
    '홍지훈',
    'ROLE_INSTRUCTOR',
    TRUE,
    NOW(),
    NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM users
    WHERE email = 'instructor@devpath.com'
);

INSERT INTO users (email, password, name, role_name, is_active, is_super_admin, created_at, updated_at)
SELECT
    'admin@devpath.com',
    '$2a$10$xh6.EW/FRzJBWfxqpdXh2uTVoepPhUxQRUH5OEwk90IpYeKjegkj.',
    '박서연',
    'ROLE_ADMIN',
    TRUE,
    TRUE,
    NOW(),
    NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM users
    WHERE email = 'admin@devpath.com'
);

UPDATE users
SET password = '$2a$10$xh6.EW/FRzJBWfxqpdXh2uTVoepPhUxQRUH5OEwk90IpYeKjegkj.'
WHERE email IN ('learner@devpath.com', 'instructor@devpath.com');

UPDATE users
SET password = '$2a$10$lEubudcVnsxZ6EAO3.joFOPndlLjv9.bi5FcO4z59a74fCMjqZA.O'
WHERE email = 'admin@devpath.com';

-- ============================================================
-- 3. User Profiles
-- ============================================================
INSERT INTO user_profiles (
    user_id,
    profile_image,
    channel_name,
    bio,
    phone,
    github_url,
    blog_url,
    is_public,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    NULL,
    '홍지훈 백엔드 연구소',
    'Spring Boot와 Security를 실전 중심으로 가르치는 강사입니다.',
    '010-0000-0001',
    'https://github.com/instructor-hong',
    'https://blog.devpath.com/hong',
    TRUE,
    NOW(),
    NOW()
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM user_profiles up
      WHERE up.user_id = u.user_id
  );

INSERT INTO user_profiles (
    user_id,
    profile_image,
    channel_name,
    bio,
    phone,
    github_url,
    blog_url,
    is_public,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    NULL,
    'DevPath 관리자',
    'DevPath 플랫폼 운영과 학습 경험 개선을 담당하고 있습니다.',
    '010-0000-0002',
    'https://github.com/admin-park',
    'https://blog.devpath.com/admin',
    TRUE,
    NOW(),
    NOW()
FROM users u
WHERE u.email = 'admin@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM user_profiles up
      WHERE up.user_id = u.user_id
  );

UPDATE user_profiles up
SET
    profile_image = NULL,
    channel_name = '홍지훈 백엔드 연구소',
    bio = 'Spring Boot와 Security를 실전 중심으로 가르치는 강사입니다.',
    github_url = 'https://github.com/instructor-hong',
    blog_url = 'https://blog.devpath.com/hong',
    is_public = TRUE,
    updated_at = NOW()
FROM users u
WHERE up.user_id = u.user_id
  AND u.email = 'instructor@devpath.com';

UPDATE user_profiles up
SET
    profile_image = NULL,
    channel_name = 'DevPath 관리자',
    bio = 'DevPath 플랫폼 운영과 학습 경험 개선을 담당하고 있습니다.',
    github_url = 'https://github.com/admin-park',
    blog_url = 'https://blog.devpath.com/admin',
    is_public = TRUE,
    updated_at = NOW()
FROM users u
WHERE up.user_id = u.user_id
  AND u.email = 'admin@devpath.com';

-- ============================================================
-- 4. Tags
-- ============================================================
INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'Java', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (
    SELECT 1
    FROM tags
    WHERE name = 'Java'
);

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'Spring Boot', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (
    SELECT 1
    FROM tags
    WHERE name = 'Spring Boot'
);

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'JPA', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (
    SELECT 1
    FROM tags
    WHERE name = 'JPA'
);

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'Spring Security', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (
    SELECT 1
    FROM tags
    WHERE name = 'Spring Security'
);

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'HTTP', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (
    SELECT 1
    FROM tags
    WHERE name = 'HTTP'
);

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'PostgreSQL', 'Database', TRUE, FALSE
WHERE NOT EXISTS (
    SELECT 1
    FROM tags
    WHERE name = 'PostgreSQL'
);

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'Redis', 'Database', TRUE, FALSE
WHERE NOT EXISTS (
    SELECT 1
    FROM tags
    WHERE name = 'Redis'
);

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'Docker', 'DevOps', TRUE, FALSE
WHERE NOT EXISTS (
    SELECT 1
    FROM tags
    WHERE name = 'Docker'
);

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'React', 'Frontend', TRUE, FALSE
WHERE NOT EXISTS (
    SELECT 1
    FROM tags
    WHERE name = 'React'
);

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'TypeScript', 'Frontend', TRUE, FALSE
WHERE NOT EXISTS (
    SELECT 1
    FROM tags
    WHERE name = 'TypeScript'
);

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'Python', 'AI', TRUE, FALSE
WHERE NOT EXISTS (
    SELECT 1
    FROM tags
    WHERE name = 'Python'
);

-- ============================================================
-- 5. Roadmaps & Nodes
-- ============================================================
INSERT INTO roadmaps (creator_id, title, description, is_official, is_public, is_deleted, created_at)
SELECT
    u.user_id,
    'Backend Master Roadmap',
    'Official DevPath roadmap covering Java, Spring Boot, JPA, security, and deployment.',
    TRUE,
    TRUE,
    FALSE,
    CURRENT_TIMESTAMP
FROM users u
WHERE u.email = 'admin@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM roadmaps
      WHERE title = 'Backend Master Roadmap'
  );

UPDATE roadmaps
SET info_title = '백엔드 개발이란 무엇인가요?',
    info_content = $$<div class="p-6 text-sm text-gray-700 leading-relaxed space-y-6">
  <div>
    <p class="mb-2"><span class="font-bold text-gray-900">백엔드 개발</span>은 웹 개발의 서버 측 부분을 의미하며, 서버 로직, 데이터베이스 및 API를 생성하고 관리하는 데 중점을 둡니다.</p>
    <p>사용자 인증, 권한 부여 및 사용자 요청 처리를 포함하며, 일반적으로 <span class="font-bold text-gray-800 bg-yellow-100 px-1 rounded">Python, Java, Ruby, PHP, JavaScript(Node.js) 및 .NET</span> 과 같은 백엔드 개발 언어를 사용합니다.</p>
  </div>
  <div>
    <strong class="block text-gray-900 text-base mb-2">👨‍💻 백엔드 개발자는 무슨 일을 하나요?</strong>
    <p class="mb-4">백엔드 개발자는 웹 애플리케이션의 서버 측 구성 요소를 개발하고 유지 관리하는 데 집중합니다. 주로 <strong>서버 측 API 개발, 데이터베이스 운영 처리</strong>, 그리고 백엔드 시스템이 많은 트래픽을 효율적으로 처리할 수 있도록 보장하는 역할을 담당합니다.</p>
    <div class="bg-white p-5 rounded-xl border border-gray-200 shadow-sm">
      <strong class="block text-[#00C471] mb-2"><i class="fas fa-check-circle mr-1"></i> 주요 업무</strong>
      <ul class="list-disc pl-5 space-y-1 text-gray-600">
        <li><strong>외부 서비스 통합:</strong> 결제 게이트웨이 및 클라우드 서비스와 같은 외부 서비스 통합</li>
        <li><strong>성능 최적화:</strong> 시스템 성능 및 확장성(Scalability) 향상</li>
        <li><strong>데이터 보안:</strong> 데이터 처리 및 보안에 매우 중요한 역할을 수행</li>
        <li><strong>협업 지원:</strong> 프론트엔드 개발자가 원활한 사용자 경험을 제공할 수 있도록 지원하는 핵심 역할</li>
      </ul>
    </div>
  </div>
</div>$$
WHERE title = 'Backend Master Roadmap';

INSERT INTO roadmaps (creator_id, title, description, is_official, is_public, is_deleted, created_at)
SELECT
    u.user_id,
    'Frontend Entry Roadmap',
    'Starter roadmap for React, TypeScript, and UI fundamentals.',
    TRUE,
    TRUE,
    FALSE,
    CURRENT_TIMESTAMP
FROM users u
WHERE u.email = 'admin@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM roadmaps
      WHERE title = 'Frontend Entry Roadmap'
  );

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order)
SELECT
    r.roadmap_id,
    'Java Basics',
    'Learn variables, control flow, loops, and object-oriented basics.',
    'CONCEPT',
    1
FROM roadmaps r
WHERE r.title = 'Backend Master Roadmap'
  AND NOT EXISTS (
      SELECT 1
      FROM roadmap_nodes
      WHERE roadmap_id = r.roadmap_id
        AND title = 'Java Basics'
  );

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order)
SELECT
    r.roadmap_id,
    'HTTP Fundamentals',
    'Understand HTTP methods, status codes, headers, and REST basics.',
    'CONCEPT',
    2
FROM roadmaps r
WHERE r.title = 'Backend Master Roadmap'
  AND NOT EXISTS (
      SELECT 1
      FROM roadmap_nodes
      WHERE roadmap_id = r.roadmap_id
        AND title = 'HTTP Fundamentals'
  );

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order)
SELECT
    r.roadmap_id,
    'Spring Boot Basics',
    'Understand DI, IoC, and the core annotations used in Spring Boot.',
    'CONCEPT',
    3
FROM roadmaps r
WHERE r.title = 'Backend Master Roadmap'
  AND NOT EXISTS (
      SELECT 1
      FROM roadmap_nodes
      WHERE roadmap_id = r.roadmap_id
        AND title = 'Spring Boot Basics'
  );

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order)
SELECT
    r.roadmap_id,
    'Spring Data JPA',
    'Learn ORM, entity mapping, and repository-based persistence.',
    'CONCEPT',
    4
FROM roadmaps r
WHERE r.title = 'Backend Master Roadmap'
  AND NOT EXISTS (
      SELECT 1
      FROM roadmap_nodes
      WHERE roadmap_id = r.roadmap_id
        AND title = 'Spring Data JPA'
  );

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order)
SELECT
    r.roadmap_id,
    'Docker Deployment Basics',
    'Package and run backend services with Docker and compose.',
    'PRACTICE',
    6
FROM roadmaps r
WHERE r.title = 'Backend Master Roadmap'
  AND NOT EXISTS (
      SELECT 1
      FROM roadmap_nodes
      WHERE roadmap_id = r.roadmap_id
        AND title = 'Docker Deployment Basics'
  );

INSERT INTO node_required_tags (node_id, tag_id)
SELECT n.node_id, t.tag_id
FROM roadmap_nodes n, tags t
WHERE n.title = 'Java Basics'
  AND t.name = 'Java'
  AND NOT EXISTS (
      SELECT 1
      FROM node_required_tags req
      WHERE req.node_id = n.node_id
        AND req.tag_id = t.tag_id
  );

INSERT INTO node_required_tags (node_id, tag_id)
SELECT n.node_id, t.tag_id
FROM roadmap_nodes n, tags t
WHERE n.title = 'Spring Boot Basics'
  AND t.name = 'Spring Boot'
  AND NOT EXISTS (
      SELECT 1
      FROM node_required_tags req
      WHERE req.node_id = n.node_id
        AND req.tag_id = t.tag_id
  );

INSERT INTO node_required_tags (node_id, tag_id)
SELECT n.node_id, t.tag_id
FROM roadmap_nodes n, tags t
WHERE n.title = 'Spring Data JPA'
  AND t.name = 'JPA'
  AND NOT EXISTS (
      SELECT 1
      FROM node_required_tags req
      WHERE req.node_id = n.node_id
        AND req.tag_id = t.tag_id
  );

INSERT INTO user_tech_stacks (user_id, tag_id)
SELECT u.user_id, t.tag_id
FROM users u, tags t
WHERE u.email = 'learner@devpath.com'
  AND t.name = 'Java'
  AND NOT EXISTS (
      SELECT 1
      FROM user_tech_stacks uts
      WHERE uts.user_id = u.user_id
        AND uts.tag_id = t.tag_id
  );

INSERT INTO user_tech_stacks (user_id, tag_id)
SELECT u.user_id, t.tag_id
FROM users u, tags t
WHERE u.email = 'learner@devpath.com'
  AND t.name = 'HTTP'
  AND NOT EXISTS (
      SELECT 1
      FROM user_tech_stacks uts
      WHERE uts.user_id = u.user_id
        AND uts.tag_id = t.tag_id
  );

INSERT INTO user_tech_stacks (user_id, tag_id)
SELECT u.user_id, t.tag_id
FROM users u, tags t
WHERE u.email = 'instructor@devpath.com'
  AND t.name = 'Spring Boot'
  AND NOT EXISTS (
      SELECT 1
      FROM user_tech_stacks uts
      WHERE uts.user_id = u.user_id
        AND uts.tag_id = t.tag_id
  );

INSERT INTO user_tech_stacks (user_id, tag_id)
SELECT u.user_id, t.tag_id
FROM users u, tags t
WHERE u.email = 'instructor@devpath.com'
  AND t.name = 'JPA'
  AND NOT EXISTS (
      SELECT 1
      FROM user_tech_stacks uts
      WHERE uts.user_id = u.user_id
        AND uts.tag_id = t.tag_id
  );

INSERT INTO user_tech_stacks (user_id, tag_id)
SELECT u.user_id, t.tag_id
FROM users u, tags t
WHERE u.email = 'instructor@devpath.com'
  AND t.name = 'Docker'
  AND NOT EXISTS (
      SELECT 1
      FROM user_tech_stacks uts
      WHERE uts.user_id = u.user_id
        AND uts.tag_id = t.tag_id
  );


-- ============================================================
-- 6. Courses  (총 5개)
--    - PUBLISHED  : Spring Boot Intro, React Dashboard Sprint
--    - IN_REVIEW  : 스프링 부트 3.0 완전 정복
--    - DRAFT      : JPA Practical Design, 제목 없는 강의 (초안)
--
-- [주의] 이 파일에 정의된 강의만 모든 환경에서 동일하게 존재한다.
--        로컬 DB에 직접 추가한 강의는 이 파일에도 추가해야 팀원과 맞춰진다.
-- ============================================================
INSERT INTO courses (
    instructor_id,
    title,
    subtitle,
    description,
    thumbnail_url,
    intro_video_url,
    video_asset_key,
    duration_seconds,
    price,
    original_price,
    currency,
    difficulty_level,
    language,
    has_certificate,
    status,
    published_at
)
SELECT
    u.user_id,
    'Spring Boot Intro',
    'Fast path to practical API development',
    'Backend starter course covering Spring Boot, JPA, and security basics.',
    'https://images.unsplash.com/photo-1517694712202-14dd9538aa97?auto=format&fit=crop&w=1200&q=80',
    '/videos/trailers/spring-boot.mp4',
    'assets/courses/trailers/spring-boot.mp4',
    55200,
    99000,
    129000,
    'KRW',
    'BEGINNER',
    'ko',
    TRUE,
    'PUBLISHED',
    NOW()
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM courses
      WHERE title = 'Spring Boot Intro'
  );

INSERT INTO courses (
    instructor_id,
    title,
    subtitle,
    description,
    thumbnail_url,
    intro_video_url,
    video_asset_key,
    duration_seconds,
    price,
    original_price,
    currency,
    difficulty_level,
    language,
    has_certificate,
    status,
    published_at
)
SELECT
    u.user_id,
    'JPA Practical Design',
    'Entity design to query optimization',
    'Practical JPA patterns and performance optimization techniques.',
    'https://images.unsplash.com/photo-1555066931-4365d14bab8c?auto=format&fit=crop&w=1200&q=80',
    '/videos/trailers/jpa.mp4',
    'assets/courses/trailers/jpa.mp4',
    110,
    129000,
    99000,
    'KRW',
    'INTERMEDIATE',
    'ko',
    TRUE,
    'DRAFT',
    NULL
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM courses
      WHERE title = 'JPA Practical Design'
  );

INSERT INTO courses (
    instructor_id,
    title,
    subtitle,
    description,
    thumbnail_url,
    intro_video_url,
    video_asset_key,
    duration_seconds,
    price,
    original_price,
    currency,
    difficulty_level,
    language,
    has_certificate,
    status,
    published_at
)
SELECT
    u.user_id,
    'React Dashboard Sprint',
    'Build analytics dashboards with React',
    'Frontend course focused on React dashboard layouts, reusable widgets, and product-ready charts.',
    'https://images.unsplash.com/photo-1460925895917-afdab827c52f?auto=format&fit=crop&w=1200&q=80',
    '/videos/trailers/react-dashboard.mp4',
    'assets/courses/trailers/react-dashboard.mp4',
    88,
    79000,
    109000,
    'KRW',
    'INTERMEDIATE',
    'ko',
    TRUE,
    'PUBLISHED',
    NOW()
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM courses
      WHERE title = 'React Dashboard Sprint'
  );

INSERT INTO courses (
    instructor_id,
    title,
    subtitle,
    description,
    thumbnail_url,
    intro_video_url,
    video_asset_key,
    duration_seconds,
    price,
    original_price,
    currency,
    difficulty_level,
    language,
    has_certificate,
    status,
    published_at
)
SELECT
    u.user_id,
    '스프링 부트 3.0 완전 정복',
    '실무 백엔드 프로젝트를 위한 스프링 부트 집중 과정',
    '심사 중인 강의 예시로 사용하는 스프링 부트 3 기반 백엔드 실전 강의입니다.',
    'https://images.unsplash.com/photo-1516321318423-f06f85e504b3?auto=format&fit=crop&w=1200&q=80',
    '/videos/trailers/spring-boot-advanced.mp4',
    'assets/courses/trailers/spring-boot-advanced.mp4',
    28800,
    119000,
    149000,
    'KRW',
    'INTERMEDIATE',
    'ko',
    TRUE,
    'IN_REVIEW',
    TIMESTAMP '2026-01-29 13:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM courses
      WHERE title = '스프링 부트 3.0 완전 정복'
  );

INSERT INTO courses (
    instructor_id,
    title,
    subtitle,
    description,
    thumbnail_url,
    intro_video_url,
    video_asset_key,
    duration_seconds,
    price,
    original_price,
    currency,
    difficulty_level,
    language,
    has_certificate,
    status,
    published_at
)
SELECT
    u.user_id,
    '제목 없는 강의 (초안)',
    '초안 강의 카드 표시용 샘플 데이터',
    '강의 관리 화면의 작성 중 카드 예시에 사용하는 초안 강의입니다.',
    NULL,
    NULL,
    NULL,
    0,
    0,
    0,
    'KRW',
    NULL,
    'ko',
    FALSE,
    'DRAFT',
    TIMESTAMP '2026-01-30 11:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM courses
      WHERE title = '제목 없는 강의 (초안)'
  );

-- ============================================================
-- 7. Course 부속 데이터 (섹션·강의·목표·수강 대상·태그 등)
-- ============================================================
INSERT INTO course_prerequisites (course_id, prerequisite)
SELECT c.course_id, 'Java syntax basics'
FROM courses c
WHERE c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1
      FROM course_prerequisites cp
      WHERE cp.course_id = c.course_id
        AND cp.prerequisite = 'Java syntax basics'
  );

INSERT INTO course_prerequisites (course_id, prerequisite)
SELECT c.course_id, 'HTTP fundamentals'
FROM courses c
WHERE c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1
      FROM course_prerequisites cp
      WHERE cp.course_id = c.course_id
        AND cp.prerequisite = 'HTTP fundamentals'
  );

INSERT INTO course_job_relevance (course_id, job_relevance)
SELECT c.course_id, 'Backend developer'
FROM courses c
WHERE c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1
      FROM course_job_relevance cj
      WHERE cj.course_id = c.course_id
        AND cj.job_relevance = 'Backend developer'
  );

INSERT INTO course_job_relevance (course_id, job_relevance)
SELECT c.course_id, 'Server engineer'
FROM courses c
WHERE c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1
      FROM course_job_relevance cj
      WHERE cj.course_id = c.course_id
        AND cj.job_relevance = 'Server engineer'
  );

INSERT INTO course_objectives (course_id, objective_text, display_order)
SELECT c.course_id, 'Build a Spring Boot application from scratch.', 0
FROM courses c
WHERE c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1
      FROM course_objectives co
      WHERE co.course_id = c.course_id
        AND co.display_order = 0
  );

INSERT INTO course_objectives (course_id, objective_text, display_order)
SELECT c.course_id, 'Implement CRUD APIs with JPA.', 1
FROM courses c
WHERE c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1
      FROM course_objectives co
      WHERE co.course_id = c.course_id
        AND co.display_order = 1
  );

INSERT INTO course_target_audiences (course_id, audience_description, display_order)
SELECT c.course_id, 'Backend job seekers', 0
FROM courses c
WHERE c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1
      FROM course_target_audiences cta
      WHERE cta.course_id = c.course_id
        AND cta.display_order = 0
  );

INSERT INTO course_target_audiences (course_id, audience_description, display_order)
SELECT c.course_id, 'Developers new to Spring projects', 1
FROM courses c
WHERE c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1
      FROM course_target_audiences cta
      WHERE cta.course_id = c.course_id
        AND cta.display_order = 1
  );

INSERT INTO course_sections (course_id, title, description, sort_order, is_published)
SELECT c.course_id, 'Spring Core', 'DI, IoC, bean lifecycle basics', 1, TRUE
FROM courses c
WHERE c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1
      FROM course_sections cs
      WHERE cs.course_id = c.course_id
        AND cs.sort_order = 1
  );

INSERT INTO course_sections (course_id, title, description, sort_order, is_published)
SELECT c.course_id, 'JPA Basic Mapping', 'Entity relationships and mapping strategy', 2, TRUE
FROM courses c
WHERE c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1
      FROM course_sections cs
      WHERE cs.course_id = c.course_id
        AND cs.sort_order = 2
  );

INSERT INTO lessons (
    section_id,
    title,
    description,
    lesson_type,
    video_url,
    video_asset_key,
    video_provider,
    thumbnail_url,
    duration_seconds,
    is_preview,
    is_published,
    sort_order
)
SELECT
    cs.section_id,
    'Understanding DI and IoC',
    'Understand dependency injection and inversion of control.',
    'VIDEO',
    'https://cdn.devpath.com/lessons/spring-core-1.mp4',
    'asset-spring-boot-001',
    'r2',
    'https://cdn.devpath.com/lessons/thumbnails/spring-core-1.png',
    780,
    TRUE,
    TRUE,
    1
FROM course_sections cs
JOIN courses c ON c.course_id = cs.course_id
WHERE c.title = 'Spring Boot Intro'
  AND cs.sort_order = 1
  AND NOT EXISTS (
      SELECT 1
      FROM lessons l
      WHERE l.section_id = cs.section_id
        AND l.sort_order = 1
  );

INSERT INTO lessons (
    section_id,
    title,
    description,
    lesson_type,
    video_url,
    video_asset_key,
    video_provider,
    thumbnail_url,
    duration_seconds,
    is_preview,
    is_published,
    sort_order
)
SELECT
    cs.section_id,
    'Bean registration and lifecycle',
    'Learn bean creation and lifecycle callbacks.',
    'VIDEO',
    'https://cdn.devpath.com/lessons/spring-core-2.mp4',
    'asset-spring-boot-002',
    'r2',
    'https://cdn.devpath.com/lessons/thumbnails/spring-core-2.png',
    920,
    FALSE,
    TRUE,
    2
FROM course_sections cs
JOIN courses c ON c.course_id = cs.course_id
WHERE c.title = 'Spring Boot Intro'
  AND cs.sort_order = 1
  AND NOT EXISTS (
      SELECT 1
      FROM lessons l
      WHERE l.section_id = cs.section_id
        AND l.sort_order = 2
  );

INSERT INTO lessons (
    section_id,
    title,
    description,
    lesson_type,
    video_url,
    video_asset_key,
    video_provider,
    thumbnail_url,
    duration_seconds,
    is_preview,
    is_published,
    sort_order
)
SELECT
    cs.section_id,
    'Entity relationships and mapping',
    'Map one-to-one, one-to-many, and many-to-many relationships.',
    'VIDEO',
    'https://cdn.devpath.com/lessons/jpa-1.mp4',
    'asset-jpa-001',
    'r2',
    'https://cdn.devpath.com/lessons/thumbnails/jpa-1.png',
    1100,
    FALSE,
    TRUE,
    1
FROM course_sections cs
JOIN courses c ON c.course_id = cs.course_id
WHERE c.title = 'Spring Boot Intro'
  AND cs.sort_order = 2
  AND NOT EXISTS (
      SELECT 1
      FROM lessons l
      WHERE l.section_id = cs.section_id
        AND l.sort_order = 1
  );

INSERT INTO course_materials (lesson_id, material_type, material_url, asset_key, original_file_name, sort_order)
SELECT
    l.lesson_id,
    'SLIDE',
    '/materials/spring-core.pdf',
    'materials/spring-core.pdf',
    'spring-core.pdf',
    0
FROM lessons l
WHERE l.title = 'Understanding DI and IoC'
  AND NOT EXISTS (
      SELECT 1
      FROM course_materials cm
      WHERE cm.lesson_id = l.lesson_id
        AND cm.original_file_name = 'spring-core.pdf'
  );

INSERT INTO course_materials (lesson_id, material_type, material_url, asset_key, original_file_name, sort_order)
SELECT
    l.lesson_id,
    'CODE',
    '/materials/jpa-sample.zip',
    'materials/jpa-sample.zip',
    'jpa-sample.zip',
    0
FROM lessons l
WHERE l.title = 'Entity relationships and mapping'
  AND NOT EXISTS (
      SELECT 1
      FROM course_materials cm
      WHERE cm.lesson_id = l.lesson_id
        AND cm.original_file_name = 'jpa-sample.zip'
  );

INSERT INTO course_tag_maps (course_id, tag_id, proficiency_level)
SELECT c.course_id, t.tag_id, 3
FROM courses c, tags t
WHERE c.title = 'Spring Boot Intro'
  AND t.name = 'Spring Boot'
  AND NOT EXISTS (
      SELECT 1
      FROM course_tag_maps ctm
      WHERE ctm.course_id = c.course_id
        AND ctm.tag_id = t.tag_id
  );

INSERT INTO course_tag_maps (course_id, tag_id, proficiency_level)
SELECT c.course_id, t.tag_id, 3
FROM courses c, tags t
WHERE c.title = 'Spring Boot Intro'
  AND t.name = 'Java'
  AND NOT EXISTS (
      SELECT 1
      FROM course_tag_maps ctm
      WHERE ctm.course_id = c.course_id
        AND ctm.tag_id = t.tag_id
  );

INSERT INTO course_tag_maps (course_id, tag_id, proficiency_level)
SELECT c.course_id, t.tag_id, 3
FROM courses c, tags t
WHERE c.title = 'JPA Practical Design'
  AND t.name = 'JPA'
  AND NOT EXISTS (
      SELECT 1
      FROM course_tag_maps ctm
      WHERE ctm.course_id = c.course_id
        AND ctm.tag_id = t.tag_id
  );

INSERT INTO course_tag_maps (course_id, tag_id, proficiency_level)
SELECT c.course_id, t.tag_id, 3
FROM courses c, tags t
WHERE c.title = 'JPA Practical Design'
  AND t.name = 'Java'
  AND NOT EXISTS (
      SELECT 1
      FROM course_tag_maps ctm
      WHERE ctm.course_id = c.course_id
        AND ctm.tag_id = t.tag_id
  );

INSERT INTO course_tag_maps (course_id, tag_id, proficiency_level)
SELECT c.course_id, t.tag_id, 3
FROM courses c, tags t
WHERE c.title = 'JPA Practical Design'
  AND t.name = 'PostgreSQL'
  AND NOT EXISTS (
      SELECT 1
      FROM course_tag_maps ctm
      WHERE ctm.course_id = c.course_id
        AND ctm.tag_id = t.tag_id
  );

INSERT INTO course_tag_maps (course_id, tag_id, proficiency_level)
SELECT c.course_id, t.tag_id, 3
FROM courses c, tags t
WHERE c.title = 'React Dashboard Sprint'
  AND t.name = 'React'
  AND NOT EXISTS (
      SELECT 1
      FROM course_tag_maps ctm
      WHERE ctm.course_id = c.course_id
        AND ctm.tag_id = t.tag_id
  );

INSERT INTO course_tag_maps (course_id, tag_id, proficiency_level)
SELECT c.course_id, t.tag_id, 3
FROM courses c, tags t
WHERE c.title = 'React Dashboard Sprint'
  AND t.name = 'TypeScript'
  AND NOT EXISTS (
      SELECT 1
      FROM course_tag_maps ctm
      WHERE ctm.course_id = c.course_id
        AND ctm.tag_id = t.tag_id
  );

INSERT INTO course_tag_maps (course_id, tag_id, proficiency_level)
SELECT c.course_id, t.tag_id, 3
FROM courses c, tags t
WHERE c.title = '스프링 부트 3.0 완전 정복'
  AND t.name = 'Spring Boot'
  AND NOT EXISTS (
      SELECT 1
      FROM course_tag_maps ctm
      WHERE ctm.course_id = c.course_id
        AND ctm.tag_id = t.tag_id
  );

INSERT INTO course_tag_maps (course_id, tag_id, proficiency_level)
SELECT c.course_id, t.tag_id, 3
FROM courses c, tags t
WHERE c.title = '스프링 부트 3.0 완전 정복'
  AND t.name = 'Java'
  AND NOT EXISTS (
      SELECT 1
      FROM course_tag_maps ctm
      WHERE ctm.course_id = c.course_id
        AND ctm.tag_id = t.tag_id
  );

INSERT INTO course_tag_maps (course_id, tag_id, proficiency_level)
SELECT c.course_id, t.tag_id, 3
FROM courses c, tags t
WHERE c.title = '스프링 부트 3.0 완전 정복'
  AND t.name = 'Spring Security'
  AND NOT EXISTS (
      SELECT 1
      FROM course_tag_maps ctm
      WHERE ctm.course_id = c.course_id
        AND ctm.tag_id = t.tag_id
  );

INSERT INTO course_tag_maps (course_id, tag_id, proficiency_level)
SELECT c.course_id, t.tag_id, 3
FROM courses c, tags t
WHERE c.title = '제목 없는 강의 (초안)'
  AND t.name = 'Java'
  AND NOT EXISTS (
      SELECT 1
      FROM course_tag_maps ctm
      WHERE ctm.course_id = c.course_id
        AND ctm.tag_id = t.tag_id
  );

INSERT INTO course_tag_maps (course_id, tag_id, proficiency_level)
SELECT c.course_id, t.tag_id, 3
FROM courses c, tags t
WHERE c.title = '제목 없는 강의 (초안)'
  AND t.name = 'Spring Boot'
  AND NOT EXISTS (
      SELECT 1
      FROM course_tag_maps ctm
      WHERE ctm.course_id = c.course_id
        AND ctm.tag_id = t.tag_id
  );

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'JWT', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (
    SELECT 1
    FROM tags
    WHERE name = 'JWT'
);

INSERT INTO node_required_tags (node_id, tag_id)
SELECT n.node_id, t.tag_id
FROM roadmap_nodes n, tags t
WHERE n.title = 'Security and JWT'
  AND t.name = 'Spring Security'
  AND NOT EXISTS (
      SELECT 1
      FROM node_required_tags req
      WHERE req.node_id = n.node_id
        AND req.tag_id = t.tag_id
  );

INSERT INTO node_required_tags (node_id, tag_id)
SELECT n.node_id, t.tag_id
FROM roadmap_nodes n, tags t
WHERE n.title = 'Security and JWT'
  AND t.name = 'JWT'
  AND NOT EXISTS (
      SELECT 1
      FROM node_required_tags req
      WHERE req.node_id = n.node_id
        AND req.tag_id = t.tag_id
  );

INSERT INTO node_required_tags (node_id, tag_id)
SELECT n.node_id, t.tag_id
FROM roadmap_nodes n, tags t
WHERE n.title = 'Docker Deployment Basics'
  AND t.name = 'Docker'
  AND NOT EXISTS (
      SELECT 1
      FROM node_required_tags req
      WHERE req.node_id = n.node_id
        AND req.tag_id = t.tag_id
  );

INSERT INTO course_tag_maps (course_id, tag_id, proficiency_level)
SELECT c.course_id, t.tag_id, 3
FROM courses c, tags t
WHERE c.title = 'Spring Boot Intro'
  AND t.name = 'Spring Security'
  AND NOT EXISTS (
      SELECT 1
      FROM course_tag_maps ctm
      WHERE ctm.course_id = c.course_id
        AND ctm.tag_id = t.tag_id
  );

INSERT INTO course_tag_maps (course_id, tag_id, proficiency_level)
SELECT c.course_id, t.tag_id, 3
FROM courses c, tags t
WHERE c.title = 'Spring Boot Intro'
  AND t.name = 'JWT'
  AND NOT EXISTS (
      SELECT 1
      FROM course_tag_maps ctm
      WHERE ctm.course_id = c.course_id
        AND ctm.tag_id = t.tag_id
  );

INSERT INTO course_announcements (
    course_id,
    announcement_type,
    title,
    content,
    is_pinned,
    display_order,
    published_at,
    exposure_start_at,
    exposure_end_at,
    event_banner_text,
    event_link,
    created_at,
    updated_at
)
SELECT
    c.course_id,
    'EVENT',
    '오프라인 스프링 시큐리티 특강 안내',
    '오프라인 스프링 시큐리티 특강과 Q&A 세션 일정을 안내드립니다.',
    TRUE,
    0,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP,
    TIMESTAMP '2099-12-31 23:59:59',
    '3월 오프라인 특강',
    'https://devpath.com/events/security-special',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
FROM courses c
WHERE c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1
      FROM course_announcements ca
      WHERE ca.course_id = c.course_id
        AND ca.title = '오프라인 스프링 시큐리티 특강 안내'
  );

INSERT INTO course_announcements (
    course_id,
    announcement_type,
    title,
    content,
    is_pinned,
    display_order,
    published_at,
    exposure_start_at,
    exposure_end_at,
    event_banner_text,
    event_link,
    created_at,
    updated_at
)
SELECT
    c.course_id,
    'NORMAL',
    '강의 자료 업데이트 안내',
    '스프링 부트 입문 강의의 최신 자료와 예제 파일이 업데이트되었습니다.',
    FALSE,
    1,
    CURRENT_TIMESTAMP,
    NULL,
    NULL,
    NULL,
    NULL,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
FROM courses c
WHERE c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1
      FROM course_announcements ca
      WHERE ca.course_id = c.course_id
        AND ca.title = '강의 자료 업데이트 안내'
  );

UPDATE course_announcements
SET title = '오프라인 스프링 시큐리티 특강 안내',
    content = '오프라인 스프링 시큐리티 특강과 Q&A 세션 일정을 안내드립니다.',
    event_banner_text = '3월 오프라인 특강'
WHERE title = 'Offline security special event'
   OR title = '오프라인 스프링 시큐리티 특강 안내';

UPDATE course_announcements
SET title = '강의 자료 업데이트 안내',
    content = '스프링 부트 입문 강의의 최신 자료와 예제 파일이 업데이트되었습니다.'
WHERE title = 'Course material update'
   OR title = '강의 자료 업데이트 안내';

INSERT INTO qna_question_templates
    (template_type, name, description, guide_example, sort_order, is_active, created_at, updated_at)
SELECT 'DEBUGGING', '디버깅 질문',
       '오류나 장애의 원인을 파악하고 싶을 때 사용하는 질문 템플릿입니다.',
       '에러 메시지, 발생 시점, 이미 확인한 내용을 함께 적어주면 빠르게 원인을 좁힐 수 있습니다.',
       1, TRUE, NOW(), NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM qna_question_templates
    WHERE template_type = 'DEBUGGING'
);

INSERT INTO qna_question_templates
    (template_type, name, description, guide_example, sort_order, is_active, created_at, updated_at)
SELECT 'IMPLEMENTATION', '구현 질문',
       '기능을 구현하는 과정에서 구조나 접근 방식에 대한 도움이 필요할 때 사용하는 템플릿입니다.',
       '만들고 싶은 기능, 현재 설계, 막히는 지점을 구체적으로 적어주세요.',
       2, TRUE, NOW(), NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM qna_question_templates
    WHERE template_type = 'IMPLEMENTATION'
);

INSERT INTO qna_question_templates
    (template_type, name, description, guide_example, sort_order, is_active, created_at, updated_at)
SELECT 'CODE_REVIEW', '코드 리뷰 질문',
       '코드 품질, 가독성, 트레이드오프에 대한 피드백이 필요할 때 사용하는 템플릿입니다.',
       '관련 코드, 기대 동작, 어떤 피드백이 가장 필요한지 함께 적어주세요.',
       3, TRUE, NOW(), NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM qna_question_templates
    WHERE template_type = 'CODE_REVIEW'
);

INSERT INTO qna_question_templates
    (template_type, name, description, guide_example, sort_order, is_active, created_at, updated_at)
SELECT 'CAREER', '커리어 질문',
       '학습 방향, 포트폴리오, 직무 준비에 대한 조언이 필요할 때 사용하는 템플릿입니다.',
       '현재 수준, 목표 직무, 다음에 결정하려는 내용을 함께 적어주세요.',
       4, TRUE, NOW(), NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM qna_question_templates
    WHERE template_type = 'CAREER'
);

INSERT INTO qna_question_templates
    (template_type, name, description, guide_example, sort_order, is_active, created_at, updated_at)
SELECT 'STUDY', '학습 질문',
       '다음 학습 계획이나 복습 방법이 필요할 때 사용하는 템플릿입니다.',
       '현재 공부 중인 주제, 이미 이해한 내용, 원하는 학습 계획을 적어주세요.',
       5, TRUE, NOW(), NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM qna_question_templates
    WHERE template_type = 'STUDY'
);

INSERT INTO qna_question_templates
    (template_type, name, description, guide_example, sort_order, is_active, created_at, updated_at)
SELECT 'PROJECT', '프로젝트 질문',
       '프로젝트 범위 설정, 구조 설계, 개선 방향이 필요할 때 사용하는 템플릿입니다.',
       '프로젝트 목표, 현재 진행 상황, 검토받고 싶은 결정 포인트를 적어주세요.',
       6, TRUE, NOW(), NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM qna_question_templates
    WHERE template_type = 'PROJECT'
);

-- ===========================

-- ============================================================
-- B SECTION: 기능별 샘플 데이터
-- ============================================================

-- [B-01] 수강평 (review / review_reply / review_report / review_template)
INSERT INTO review (
    course_id, learner_id, rating, content, status, is_hidden, is_deleted, issue_tags_raw, created_at, updated_at
)
SELECT c.course_id, u.user_id, 5,
       '예제가 실무에 바로 연결돼서 좋았고, 설명 흐름도 자연스러워서 끝까지 집중해서 들을 수 있었습니다.',
       'ANSWERED', FALSE, FALSE, '설명_자세해요,예제가_실전적이에요',
       '2026-02-10 10:00:00', '2026-02-10 10:00:00'
FROM users u, courses c
WHERE u.email = 'learner@devpath.com'
  AND c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1 FROM review r
      WHERE r.course_id = c.course_id AND r.learner_id = u.user_id
  );

INSERT INTO review (
    course_id, learner_id, rating, content, status, is_hidden, is_deleted, issue_tags_raw, created_at, updated_at
)
SELECT c.course_id, u.user_id, 3,
       '주제 자체는 정말 유용했지만 엔티티 매핑과 fetch 전략 부분은 조금 더 천천히 설명해주셨으면 좋겠습니다.',
       'UNANSWERED', FALSE, FALSE, '조금_빨라요,도식이_더_필요해요',
       '2026-02-12 14:00:00', '2026-02-12 14:00:00'
FROM users u, courses c
WHERE u.email = 'learner@devpath.com'
  AND c.title = 'JPA Practical Design'
  AND NOT EXISTS (
      SELECT 1 FROM review r
      WHERE r.course_id = c.course_id AND r.learner_id = u.user_id
  );

INSERT INTO review (
    course_id, learner_id, rating, content, status, is_hidden, is_deleted, issue_tags_raw, created_at, updated_at
)
SELECT c.course_id, u.user_id, 5,
       '대시보드 실습 위주라서 바로 따라 만들 수 있었고, 차트와 레이아웃을 한 번에 정리하기 좋았습니다.',
       'ANSWERED', FALSE, FALSE, '실습_구성이_좋아요,예제가_바로_써먹기_좋아요',
       '2026-02-14 11:30:00', '2026-02-14 11:30:00'
FROM users u, courses c
WHERE u.email = 'learner2@devpath.com'
  AND c.title = 'React Dashboard Sprint'
  AND NOT EXISTS (
      SELECT 1 FROM review r
      WHERE r.course_id = c.course_id AND r.learner_id = u.user_id
  );

INSERT INTO review (
    course_id, learner_id, rating, content, status, is_hidden, is_deleted, issue_tags_raw, created_at, updated_at
)
SELECT c.course_id, u.user_id, 4,
       '차트 옵션 설명은 좋았는데 상태 관리와 API 연결 파트는 조금 더 천천히 짚어주면 더 좋을 것 같습니다.',
       'UNANSWERED', FALSE, FALSE, '상태관리_설명이_더_필요해요,API_연결_보강이_필요해요',
       '2026-02-16 16:20:00', '2026-02-16 16:20:00'
FROM users u, courses c
WHERE u.email = 'learner3@devpath.com'
  AND c.title = 'React Dashboard Sprint'
  AND NOT EXISTS (
      SELECT 1 FROM review r
      WHERE r.course_id = c.course_id AND r.learner_id = u.user_id
  );

INSERT INTO review_reply (
    review_id, instructor_id, content, is_deleted, created_at, updated_at
)
SELECT r.id, iu.user_id,
       '좋은 피드백 감사합니다. 다음 업데이트에서 매핑 다이어그램을 더 보강하고 해당 구간은 조금 더 천천히 설명하겠습니다.',
       FALSE, '2026-02-10 12:00:00', '2026-02-10 12:00:00'
FROM review r, users iu, courses c
WHERE iu.email = 'instructor@devpath.com'
  AND c.title = 'Spring Boot Intro'
  AND r.course_id = c.course_id
  AND NOT EXISTS (
      SELECT 1 FROM review_reply rr WHERE rr.review_id = r.id AND rr.is_deleted = FALSE
  );

INSERT INTO review_reply (
    review_id, instructor_id, content, is_deleted, created_at, updated_at
)
SELECT r.id, iu.user_id,
       '좋은 피드백 감사합니다. 차트 구성 실습은 유지하면서 다음 업데이트에서 API 연결과 상태 관리 설명을 더 세분화해두겠습니다.',
       FALSE, '2026-02-14 13:10:00', '2026-02-14 13:10:00'
FROM review r
JOIN users iu ON iu.email = 'instructor@devpath.com'
JOIN users lu ON lu.user_id = r.learner_id
JOIN courses c ON c.course_id = r.course_id
WHERE c.title = 'React Dashboard Sprint'
  AND lu.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM review_reply rr WHERE rr.review_id = r.id AND rr.is_deleted = FALSE
  );

INSERT INTO review_report (
    review_id, reporter_id, reason, is_resolved, resolved_by, resolved_at, created_at, updated_at
)
SELECT r.id, au.user_id,
       '표현이 다소 모호해 공개 노출 전에 한 번 더 확인이 필요합니다.',
       FALSE, NULL, NULL, '2026-02-13 09:00:00', '2026-02-13 09:00:00'
FROM review r, users au, courses c
WHERE au.email = 'admin@devpath.com'
  AND c.title = 'JPA Practical Design'
  AND r.course_id = c.course_id
  AND NOT EXISTS (
      SELECT 1 FROM review_report rp WHERE rp.review_id = r.id
  );

INSERT INTO review_template (
    instructor_id, title, content, is_deleted, created_at, updated_at
)
SELECT iu.user_id, '감사 인사',
       '정성스러운 리뷰 남겨주셔서 감사합니다. 남겨주신 의견은 다음 개정에 바로 반영하겠습니다.',
       FALSE, '2026-02-01 00:00:00', '2026-02-01 00:00:00'
FROM users iu
WHERE iu.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM review_template rt
      WHERE rt.instructor_id = iu.user_id AND rt.title = '감사 인사'
  );

INSERT INTO review_template (
    instructor_id, title, content, is_deleted, created_at, updated_at
)
SELECT iu.user_id, '사과 및 개선 약속',
       '불편을 드려 죄송합니다. 말씀해주신 내용을 확인했고, 강의 개정 목록에 반영해 보충 자료와 함께 정리하겠습니다.',
       FALSE, '2026-02-02 00:00:00', '2026-02-02 00:00:00'
FROM users iu
WHERE iu.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM review_template rt
      WHERE rt.instructor_id = iu.user_id AND rt.title = '사과 및 개선 약속'
  );

INSERT INTO review_template (
    instructor_id, title, content, is_deleted, created_at, updated_at
)
SELECT iu.user_id, '학습 가이드 제안',
       '해당 구간이 어렵게 느껴지셨다면 이전 섹션의 보충 강의와 함께 다시 보시면 이해가 훨씬 쉬워집니다. 필요한 자료도 추가로 보완하겠습니다.',
       FALSE, '2026-02-03 00:00:00', '2026-02-03 00:00:00'
FROM users iu
WHERE iu.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM review_template rt
      WHERE rt.instructor_id = iu.user_id AND rt.title = '학습 가이드 제안'
  );

INSERT INTO review_template (
    instructor_id, title, content, is_deleted, created_at, updated_at
)
SELECT iu.user_id, '만족 리뷰 답글',
       '좋게 봐주셔서 감사합니다. 앞으로도 실무에 바로 연결되는 예제와 설명으로 더 만족스러운 강의를 만들어가겠습니다.',
       FALSE, '2026-02-04 00:00:00', '2026-02-04 00:00:00'
FROM users iu
WHERE iu.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM review_template rt
      WHERE rt.instructor_id = iu.user_id AND rt.title = '만족 리뷰 답글'
  );

-- [B-02] QnA (질문 / 답변 / 임시저장 / 답변 템플릿)
INSERT INTO qna_questions (
    user_id, template_type, difficulty, title, content, adopted_answer_id,
    course_id, lecture_timestamp, qna_status, view_count, is_deleted, created_at, updated_at
)
SELECT u.user_id, 'DEBUGGING', 'EASY',
       'BeanCreationException이 발생할 때 어디부터 확인해야 하나요?',
       '스프링 부트를 실행하면 BeanCreationException이 발생합니다. 어떤 빈부터 확인해야 하고, 원인을 빠르게 좁히는 순서가 궁금합니다.',
       NULL, c.course_id, NULL, 'ANSWERED', 3, FALSE, '2026-02-05 00:00:00', '2026-02-06 00:00:00'
FROM users u, courses c
WHERE u.email = 'learner@devpath.com'
  AND c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1 FROM qna_questions q WHERE q.title = 'BeanCreationException이 발생할 때 어디부터 확인해야 하나요?'
  );

INSERT INTO qna_questions (
    user_id, template_type, difficulty, title, content, adopted_answer_id,
    course_id, lecture_timestamp, qna_status, view_count, is_deleted, created_at, updated_at
)
SELECT u.user_id, 'IMPLEMENTATION', 'MEDIUM',
       'JPA 무한 참조를 안전하게 끊는 방법이 궁금합니다',
       '엔티티를 JSON으로 직렬화하면 양방향 연관관계 때문에 순환 참조가 발생합니다. 가장 안전하게 막는 방법이 무엇인가요?',
       NULL, c.course_id, '00:12:44', 'UNANSWERED', 5, FALSE, '2026-02-08 00:00:00', '2026-02-09 00:00:00'
FROM users u, courses c
WHERE u.email = 'learner@devpath.com'
  AND c.title = 'JPA Practical Design'
  AND NOT EXISTS (
      SELECT 1 FROM qna_questions q WHERE q.title = 'JPA 무한 참조를 안전하게 끊는 방법이 궁금합니다'
  );

INSERT INTO qna_questions (
    user_id, template_type, difficulty, title, content, adopted_answer_id,
    course_id, lecture_timestamp, qna_status, view_count, is_deleted, created_at, updated_at
)
SELECT u.user_id, 'DEBUGGING', 'MEDIUM',
       'application.yml 설정이 반영되지 않는 이유가 궁금합니다',
       'application.yml에서 값을 바꿨는데 실행하면 이전 설정처럼 동작합니다. 프로필 우선순위나 환경 변수 때문에 덮어써지는 상황을 어떻게 확인하면 좋을까요?',
       NULL, c.course_id, '00:04:12', 'UNANSWERED', 2, FALSE, '2026-02-09 10:00:00', '2026-02-09 10:00:00'
FROM users u, courses c
WHERE u.email = 'learner@devpath.com'
  AND c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1 FROM qna_questions q WHERE q.title = 'application.yml 설정이 반영되지 않는 이유가 궁금합니다'
  );

INSERT INTO qna_questions (
    user_id, template_type, difficulty, title, content, adopted_answer_id,
    course_id, lecture_timestamp, qna_status, view_count, is_deleted, created_at, updated_at
)
SELECT u.user_id, 'DEBUGGING', 'MEDIUM',
       'SecurityConfig 변경 후 로그인 흐름이 막히는 이유가 궁금합니다',
       'SecurityConfig를 수정한 뒤부터 로그인 페이지 리다이렉트가 꼬이거나 403이 발생합니다. 필터 체인과 permitAll 설정을 어떤 순서로 보면 좋을까요?',
       NULL, c.course_id, '00:15:42', 'UNANSWERED', 4, FALSE, '2026-02-11 09:20:00', '2026-02-11 09:20:00'
FROM users u, courses c
WHERE u.email = 'learner2@devpath.com'
  AND c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1 FROM qna_questions q WHERE q.title = 'SecurityConfig 변경 후 로그인 흐름이 막히는 이유가 궁금합니다'
  );

INSERT INTO qna_questions (
    user_id, template_type, difficulty, title, content, adopted_answer_id,
    course_id, lecture_timestamp, qna_status, view_count, is_deleted, created_at, updated_at
)
SELECT u.user_id, 'IMPLEMENTATION', 'MEDIUM',
       'React Query와 Chart.js 데이터를 같이 관리할 때 구조를 어떻게 나누면 좋을까요?',
       '대시보드 페이지에서 React Query로 받아온 응답을 차트용 데이터로 가공하고 있는데, 컴포넌트가 길어져서 구조를 어떻게 나누는 게 좋은지 궁금합니다.',
       NULL, c.course_id, '00:18:25', 'ANSWERED', 4, FALSE, '2026-02-15 09:30:00', '2026-02-15 10:20:00'
FROM users u, courses c
WHERE u.email = 'learner2@devpath.com'
  AND c.title = 'React Dashboard Sprint'
  AND NOT EXISTS (
      SELECT 1 FROM qna_questions q WHERE q.title = 'React Query와 Chart.js 데이터를 같이 관리할 때 구조를 어떻게 나누면 좋을까요?'
  );

INSERT INTO qna_questions (
    user_id, template_type, difficulty, title, content, adopted_answer_id,
    course_id, lecture_timestamp, qna_status, view_count, is_deleted, created_at, updated_at
)
SELECT u.user_id, 'DEBUGGING', 'EASY',
       'recharts 툴팁 포맷팅이 렌더링마다 바뀌는 문제를 어떻게 보면 될까요?',
       '같은 데이터인데도 툴팁 숫자 형식이 간헐적으로 달라 보입니다. 포맷 함수를 어디에 두는 게 안전한지 궁금합니다.',
       NULL, c.course_id, '00:27:40', 'UNANSWERED', 2, FALSE, '2026-02-16 19:05:00', '2026-02-16 19:05:00'
FROM users u, courses c
WHERE u.email = 'learner3@devpath.com'
  AND c.title = 'React Dashboard Sprint'
  AND NOT EXISTS (
      SELECT 1 FROM qna_questions q WHERE q.title = 'recharts 툴팁 포맷팅이 렌더링마다 바뀌는 문제를 어떻게 보면 될까요?'
  );

INSERT INTO qna_answers (
    question_id, user_id, content, is_adopted, is_deleted, created_at, updated_at
)
SELECT q.question_id, iu.user_id,
       '스택 트레이스에서 가장 아래쪽 원인 메시지부터 확인한 뒤, 설정 클래스, 컴포넌트 스캔 범위, 생성자 의존성을 순서대로 점검해보세요.',
       FALSE, FALSE, '2026-02-06 09:00:00', '2026-02-06 09:00:00'
FROM qna_questions q, users iu
WHERE q.title = 'BeanCreationException이 발생할 때 어디부터 확인해야 하나요?'
  AND iu.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM qna_answers a WHERE a.question_id = q.question_id AND a.is_deleted = FALSE
  );

INSERT INTO qna_answers (
    question_id, user_id, content, is_adopted, is_deleted, created_at, updated_at
)
SELECT q.question_id, iu.user_id,
       '서버 응답 fetch와 차트 데이터 가공을 한 컴포넌트에 다 넣기보다, 조회 훅과 차트 변환 함수로 분리해두면 읽기와 테스트가 훨씬 쉬워집니다.',
       FALSE, FALSE, '2026-02-15 11:00:00', '2026-02-15 11:00:00'
FROM qna_questions q
JOIN users iu ON iu.email = 'instructor@devpath.com'
WHERE q.title = 'React Query와 Chart.js 데이터를 같이 관리할 때 구조를 어떻게 나누면 좋을까요?'
  AND NOT EXISTS (
      SELECT 1 FROM qna_answers a WHERE a.question_id = q.question_id AND a.is_deleted = FALSE
  );

INSERT INTO qna_answer_draft (
    question_id, instructor_id, draft_content, is_deleted, saved_at, updated_at
)
SELECT q.question_id, iu.user_id,
       'API 응답은 DTO로 분리하고, 꼭 엔티티를 직접 직렬화해야 할 때만 참조 관련 어노테이션을 제한적으로 사용하는 방식이 가장 안전합니다.',
       FALSE, '2026-02-09 00:00:00', '2026-02-09 00:00:00'
FROM qna_questions q, users iu
WHERE q.title = 'JPA 무한 참조를 안전하게 끊는 방법이 궁금합니다'
  AND iu.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM qna_answer_draft d
      WHERE d.question_id = q.question_id AND d.instructor_id = iu.user_id AND d.is_deleted = FALSE
  );

INSERT INTO qna_template (
    instructor_id, title, content, is_deleted, created_at, updated_at
)
SELECT iu.user_id, '시작 오류 점검 순서',
       '스택 트레이스 순서, 설정 클래스, 환경 변수, 최근 변경한 의존성을 먼저 점검해보세요.',
       FALSE, '2026-01-10 00:00:00', '2026-01-10 00:00:00'
FROM users iu
WHERE iu.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM qna_template qt
      WHERE qt.instructor_id = iu.user_id AND qt.title = '시작 오류 점검 순서'
  );

INSERT INTO qna_template (
    instructor_id, title, content, is_deleted, created_at, updated_at
)
SELECT iu.user_id, '직렬화 및 연관관계 점검 체크리스트',
       '도메인 구조를 바꾸기 전에 쿼리 수, fetch 전략, 엔티티 그래프 사용 여부를 먼저 비교해보세요.',
       FALSE, '2026-01-10 00:00:00', '2026-01-10 00:00:00'
FROM users iu
WHERE iu.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM qna_template qt
      WHERE qt.instructor_id = iu.user_id AND qt.title = '직렬화 및 연관관계 점검 체크리스트'
  );

INSERT INTO qna_template (
    instructor_id, title, content, is_deleted, created_at, updated_at
)
SELECT iu.user_id, '코드 리뷰형 답변',
       '문제 코드와 기대 결과를 기준으로 원인, 수정 포인트, 다시 확인할 항목을 순서대로 정리해보세요.',
       FALSE, '2026-01-11 00:00:00', '2026-01-11 00:00:00'
FROM users iu
WHERE iu.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM qna_template qt
      WHERE qt.instructor_id = iu.user_id AND qt.title = '코드 리뷰형 답변'
  );

-- [B-03] 강사 커뮤니티 (게시글 / 댓글 / 좋아요)
INSERT INTO instructor_post (
    instructor_id, title, content, post_type, like_count, comment_count, is_deleted, created_at, updated_at
)
SELECT iu.user_id,
       '[Notice] Weekly live QnA schedule',
       'Every Thursday 20:00 KST. Please post questions in advance.',
       'NOTICE', 1, 2, FALSE, '2026-01-15 00:00:00', '2026-01-15 00:00:00'
FROM users iu
WHERE iu.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM instructor_post ip WHERE ip.title = '[Notice] Weekly live QnA schedule'
  );

INSERT INTO instructor_post (
    instructor_id, title, content, post_type, like_count, comment_count, is_deleted, created_at, updated_at
)
SELECT iu.user_id,
       'How to avoid N+1 with JPA',
       'Check fetch joins, entity graphs, and batch size settings before changing repository structure.',
       'GENERAL', 1, 1, FALSE, '2026-01-20 00:00:00', '2026-01-20 00:00:00'
FROM users iu
WHERE iu.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM instructor_post ip WHERE ip.title = 'How to avoid N+1 with JPA'
  );

INSERT INTO instructor_comment (
    post_id, author_id, parent_comment_id, content, like_count, is_deleted, created_at
)
SELECT ip.id, lu.user_id, NULL,
       'The weekly QnA slot is useful. Please share the agenda early if possible.',
       1, FALSE, '2026-01-16 00:00:00'
FROM instructor_post ip, users lu
WHERE ip.title = '[Notice] Weekly live QnA schedule'
  AND lu.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM instructor_comment ic
      WHERE ic.post_id = ip.id AND ic.parent_comment_id IS NULL
        AND ic.content = 'The weekly QnA slot is useful. Please share the agenda early if possible.'
  );

INSERT INTO instructor_comment (
    post_id, author_id, parent_comment_id, content, like_count, is_deleted, created_at
)
SELECT ip.id, iu.user_id, parent.id,
       'Got it. I will pin the agenda every Monday morning.',
       0, FALSE, '2026-01-16 09:00:00'
FROM instructor_post ip, users iu, instructor_comment parent
WHERE ip.title = '[Notice] Weekly live QnA schedule'
  AND iu.email = 'instructor@devpath.com'
  AND parent.post_id = ip.id
  AND parent.parent_comment_id IS NULL
  AND parent.content = 'The weekly QnA slot is useful. Please share the agenda early if possible.'
  AND NOT EXISTS (
      SELECT 1 FROM instructor_comment child
      WHERE child.parent_comment_id = parent.id
        AND child.content = 'Got it. I will pin the agenda every Monday morning.'
  );

INSERT INTO instructor_comment (
    post_id, author_id, parent_comment_id, content, like_count, is_deleted, created_at
)
SELECT ip.id, lu.user_id, NULL,
       'A side-by-side example of fetch join versus lazy loading would be even better.',
       0, FALSE, '2026-01-21 00:00:00'
FROM instructor_post ip, users lu
WHERE ip.title = 'How to avoid N+1 with JPA'
  AND lu.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM instructor_comment ic
      WHERE ic.post_id = ip.id
        AND ic.content = 'A side-by-side example of fetch join versus lazy loading would be even better.'
  );

INSERT INTO instructor_post_like (post_id, user_id, created_at)
SELECT ip.id, lu.user_id, '2026-01-21 10:00:00'
FROM instructor_post ip, users lu
WHERE ip.title = 'How to avoid N+1 with JPA'
  AND lu.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM instructor_post_like pl WHERE pl.post_id = ip.id AND pl.user_id = lu.user_id
  );

INSERT INTO instructor_comment_like (comment_id, user_id, created_at)
SELECT ic.id, iu.user_id, '2026-01-16 10:00:00'
FROM instructor_comment ic, users iu
WHERE ic.content = 'The weekly QnA slot is useful. Please share the agenda early if possible.'
  AND iu.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM instructor_comment_like cl WHERE cl.comment_id = ic.id AND cl.user_id = iu.user_id
  );

-- [B-04] 마케팅 (쿠폰 / 프로모션 / 전환 통계)
INSERT INTO coupon (
    instructor_id, coupon_code, coupon_title, discount_type, discount_value, target_course_id,
    max_usage_count, usage_count, expires_at, is_deleted, created_at
)
SELECT iu.user_id, 'HELLO2026', '새해 맞이 할인', 'RATE', 30, NULL,
       100, 45, '2026-05-31 23:59:59', FALSE, '2026-04-01 09:00:00'
FROM users iu
WHERE iu.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM coupon cp WHERE cp.coupon_code = 'HELLO2026'
  );

INSERT INTO coupon (
    instructor_id, coupon_code, coupon_title, discount_type, discount_value, target_course_id,
    max_usage_count, usage_count, expires_at, is_deleted, created_at
)
SELECT iu.user_id, 'JAVA_LAUNCH', '자바 실전 과정 기념', 'AMOUNT', 15000, c.course_id,
       200, 82, '2026-06-15 23:59:59', FALSE, '2026-04-05 10:30:00'
FROM users iu, courses c
WHERE iu.email = 'instructor@devpath.com'
  AND c.title = 'JPA Practical Design'
  AND NOT EXISTS (
      SELECT 1 FROM coupon cp WHERE cp.coupon_code = 'JAVA_LAUNCH'
  );

INSERT INTO promotion (
    instructor_id, course_id, promotion_type, discount_rate, start_at, end_at,
    is_active, is_deleted, created_at
)
SELECT iu.user_id, c.course_id, 'TIME_SALE', 15,
       '2026-04-12 00:00:00', '2026-04-30 23:59:59',
       TRUE, FALSE, '2026-04-12 00:00:00'
FROM users iu, courses c
WHERE iu.email = 'instructor@devpath.com'
  AND c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1 FROM promotion p WHERE p.course_id = c.course_id AND p.promotion_type = 'TIME_SALE'
  );

INSERT INTO conversion_stat (
    instructor_id, course_id, total_visitors, total_signups, total_purchases, calculated_at
)
SELECT iu.user_id, NULL, 1200, 180, 42, '2026-02-28 23:00:00'
FROM users iu
WHERE iu.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM conversion_stat cs
      WHERE cs.instructor_id = iu.user_id AND cs.course_id IS NULL AND cs.calculated_at = '2026-02-28 23:00:00'
  );

INSERT INTO conversion_stat (
    instructor_id, course_id, total_visitors, total_signups, total_purchases, calculated_at
)
SELECT iu.user_id, c.course_id, 700, 120, 33, '2026-02-28 23:00:00'
FROM users iu, courses c
WHERE iu.email = 'instructor@devpath.com'
  AND c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1 FROM conversion_stat cs
      WHERE cs.instructor_id = iu.user_id AND cs.course_id = c.course_id AND cs.calculated_at = '2026-02-28 23:00:00'
  );

INSERT INTO conversion_stat (
    instructor_id, course_id, total_visitors, total_signups, total_purchases, calculated_at
)
SELECT iu.user_id, c.course_id, 500, 60, 9, '2026-02-28 23:00:00'
FROM users iu, courses c
WHERE iu.email = 'instructor@devpath.com'
  AND c.title = 'JPA Practical Design'
  AND NOT EXISTS (
      SELECT 1 FROM conversion_stat cs
      WHERE cs.instructor_id = iu.user_id AND cs.course_id = c.course_id AND cs.calculated_at = '2026-02-28 23:00:00'
  );

-- [B-05] 정산·환불 (환불 요청 / 심사 / 정산 / 정산 보류)
INSERT INTO settlement (
    instructor_id, course_id, gross_amount, fee_amount, amount,
    status, is_deleted, purchased_at, settled_at, created_at
)
SELECT iu.user_id, c.course_id, 99000, 19800, 79200,
       'COMPLETED', FALSE, '2025-08-14 14:20:00', '2025-08-21 11:00:00', '2025-08-21 11:00:00'
FROM users iu, courses c
WHERE iu.email = 'instructor@devpath.com'
  AND c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1 FROM settlement s
      WHERE s.instructor_id = iu.user_id
        AND s.course_id = c.course_id
        AND s.purchased_at = '2025-08-14 14:20:00'
  );

INSERT INTO settlement (
    instructor_id, course_id, gross_amount, fee_amount, amount,
    status, is_deleted, purchased_at, settled_at, created_at
)
SELECT iu.user_id, c.course_id, 79000, 15800, 63200,
       'COMPLETED', FALSE, '2025-09-02 10:05:00', '2025-09-09 14:00:00', '2025-09-09 14:00:00'
FROM users iu, courses c
WHERE iu.email = 'instructor@devpath.com'
  AND c.title = 'React Dashboard Sprint'
  AND NOT EXISTS (
      SELECT 1 FROM settlement s
      WHERE s.instructor_id = iu.user_id
        AND s.course_id = c.course_id
        AND s.purchased_at = '2025-09-02 10:05:00'
  );

INSERT INTO settlement (
    instructor_id, course_id, gross_amount, fee_amount, amount,
    status, is_deleted, purchased_at, settled_at, created_at
)
SELECT iu.user_id, c.course_id, 129000, 25800, 103200,
       'COMPLETED', FALSE, '2025-10-11 16:40:00', '2025-10-18 10:30:00', '2025-10-18 10:30:00'
FROM users iu, courses c
WHERE iu.email = 'instructor@devpath.com'
  AND c.title = 'JPA Practical Design'
  AND NOT EXISTS (
      SELECT 1 FROM settlement s
      WHERE s.instructor_id = iu.user_id
        AND s.course_id = c.course_id
        AND s.purchased_at = '2025-10-11 16:40:00'
  );

INSERT INTO settlement (
    instructor_id, course_id, gross_amount, fee_amount, amount,
    status, is_deleted, purchased_at, settled_at, created_at
)
SELECT iu.user_id, c.course_id, 99000, 19800, 79200,
       'COMPLETED', FALSE, '2025-11-23 11:15:00', '2025-11-30 15:00:00', '2025-11-30 15:00:00'
FROM users iu, courses c
WHERE iu.email = 'instructor@devpath.com'
  AND c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1 FROM settlement s
      WHERE s.instructor_id = iu.user_id
        AND s.course_id = c.course_id
        AND s.purchased_at = '2025-11-23 11:15:00'
  );

INSERT INTO settlement (
    instructor_id, course_id, gross_amount, fee_amount, amount,
    status, is_deleted, purchased_at, settled_at, created_at
)
SELECT iu.user_id, c.course_id, 99000, 19800, 79200,
       'COMPLETED', FALSE, '2025-12-18 09:45:00', '2025-12-25 13:20:00', '2025-12-25 13:20:00'
FROM users iu, courses c
WHERE iu.email = 'instructor@devpath.com'
  AND c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1 FROM settlement s
      WHERE s.instructor_id = iu.user_id
        AND s.course_id = c.course_id
        AND s.purchased_at = '2025-12-18 09:45:00'
  );

INSERT INTO settlement (
    instructor_id, course_id, gross_amount, fee_amount, amount,
    status, is_deleted, purchased_at, settled_at, created_at
)
SELECT iu.user_id, c.course_id, 99000, 19800, 79200,
       'COMPLETED', FALSE, '2026-01-20 09:45:00', '2026-01-27 18:30:00', '2026-01-27 18:30:00'
FROM users iu, courses c
WHERE iu.email = 'instructor@devpath.com'
  AND c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1 FROM settlement s
      WHERE s.instructor_id = iu.user_id
        AND s.course_id = c.course_id
        AND s.purchased_at = '2026-01-20 09:45:00'
  );

INSERT INTO settlement (
    instructor_id, course_id, gross_amount, fee_amount, amount,
    status, is_deleted, purchased_at, settled_at, created_at
)
SELECT iu.user_id, c.course_id, 129000, 25800, 103200,
       'PENDING', FALSE, '2026-01-29 14:30:00', NULL, '2026-01-29 14:30:00'
FROM users iu, courses c
WHERE iu.email = 'instructor@devpath.com'
  AND c.title = 'JPA Practical Design'
  AND NOT EXISTS (
      SELECT 1 FROM settlement s
      WHERE s.instructor_id = iu.user_id
        AND s.course_id = c.course_id
        AND s.purchased_at = '2026-01-29 14:30:00'
  );

INSERT INTO settlement (
    instructor_id, course_id, gross_amount, fee_amount, amount,
    status, is_deleted, purchased_at, settled_at, created_at
)
SELECT iu.user_id, c.course_id, 79000, 15800, 63200,
       'PENDING', FALSE, '2026-01-29 12:15:00', NULL, '2026-01-29 12:15:00'
FROM users iu, courses c
WHERE iu.email = 'instructor@devpath.com'
  AND c.title = 'React Dashboard Sprint'
  AND NOT EXISTS (
      SELECT 1 FROM settlement s
      WHERE s.instructor_id = iu.user_id
        AND s.course_id = c.course_id
        AND s.purchased_at = '2026-01-29 12:15:00'
  );

INSERT INTO settlement (
    instructor_id, course_id, gross_amount, fee_amount, amount,
    status, is_deleted, purchased_at, settled_at, created_at
)
SELECT iu.user_id, c.course_id, 99000, 19800, 79200,
       'HELD', FALSE, '2026-01-27 18:10:00', NULL, '2026-01-27 18:10:00'
FROM users iu, courses c
WHERE iu.email = 'instructor@devpath.com'
  AND c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1 FROM settlement s
      WHERE s.instructor_id = iu.user_id
        AND s.course_id = c.course_id
        AND s.purchased_at = '2026-01-27 18:10:00'
  );

INSERT INTO settlement_hold (
    settlement_id, admin_id, reason, held_at
)
SELECT s.id, au.user_id, 'Refund dispute review in progress', '2026-01-28 10:00:00'
FROM settlement s, users au
WHERE s.status = 'HELD'
  AND s.purchased_at = '2026-01-27 18:10:00'
  AND au.email = 'admin@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM settlement_hold sh WHERE sh.settlement_id = s.id
  );

INSERT INTO refund_request (
    learner_id, course_id, instructor_id, reason, enrolled_at, progress_percent_snapshot,
    refund_amount, status, is_deleted, requested_at, processed_at
)
SELECT lu.user_id, c.course_id, iu.user_id,
       'I am still within the refund window and the progress is low.',
       '2026-02-26 09:00:00', 10, 99000, 'PENDING', FALSE, '2026-02-27 10:00:00', NULL
FROM users lu, users iu, courses c
WHERE lu.email = 'learner@devpath.com'
  AND iu.email = 'instructor@devpath.com'
  AND c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1 FROM refund_request rr
      WHERE rr.learner_id = lu.user_id AND rr.course_id = c.course_id AND rr.status = 'PENDING'
  );

INSERT INTO refund_request (
    learner_id, course_id, instructor_id, reason, enrolled_at, progress_percent_snapshot,
    refund_amount, status, is_deleted, requested_at, processed_at
)
SELECT lu.user_id, c.course_id, iu.user_id,
       'Requested after watching too much content, should be rejected.',
       '2026-02-10 09:00:00', 55, 129000, 'REJECTED', FALSE, '2026-02-20 10:00:00', '2026-02-21 11:00:00'
FROM users lu, users iu, courses c
WHERE lu.email = 'learner@devpath.com'
  AND iu.email = 'instructor@devpath.com'
  AND c.title = 'JPA Practical Design'
  AND NOT EXISTS (
      SELECT 1 FROM refund_request rr
      WHERE rr.learner_id = lu.user_id AND rr.course_id = c.course_id AND rr.status = 'REJECTED'
  );

INSERT INTO refund_review (
    refund_request_id, admin_id, decision, reason, processed_at
)
SELECT rr.id, au.user_id, 'REJECTED',
       'Rejected because progress snapshot exceeded the refundable threshold.',
       '2026-02-21 11:00:00'
FROM refund_request rr, users au
WHERE rr.status = 'REJECTED'
  AND au.email = 'admin@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM refund_review rv WHERE rv.refund_request_id = rr.id
  );

-- [B-06] 계정 제한 (이용 제한 / 비활성 / 탈퇴 계정 샘플)
INSERT INTO users (
    email, password, name, role_name, is_active, account_status, created_at, updated_at
)
SELECT 'restricted-user@devpath.com',
       '$2a$10$RcdWJBwl.kuttYmqm/BN..6aZKeLNlq9DiNFHbZgZxfTzzNDD33o2',
       '정민재', 'ROLE_LEARNER', FALSE, 'RESTRICTED',
       '2026-02-01 00:00:00', '2026-02-15 00:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM users WHERE email = 'restricted-user@devpath.com'
);

INSERT INTO users (
    email, password, name, role_name, is_active, account_status, created_at, updated_at
)
SELECT 'deactivated-user@devpath.com',
       '$2a$10$RcdWJBwl.kuttYmqm/BN..6aZKeLNlq9DiNFHbZgZxfTzzNDD33o2',
       '오서연', 'ROLE_LEARNER', FALSE, 'DEACTIVATED',
       '2026-02-01 00:00:00', '2026-02-16 00:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM users WHERE email = 'deactivated-user@devpath.com'
);

INSERT INTO users (
    email, password, name, role_name, is_active, account_status, created_at, updated_at
)
SELECT 'withdrawn-user@devpath.com',
       '$2a$10$RcdWJBwl.kuttYmqm/BN..6aZKeLNlq9DiNFHbZgZxfTzzNDD33o2',
       '강도윤', 'ROLE_LEARNER', FALSE, 'WITHDRAWN',
       '2026-02-01 00:00:00', '2026-02-17 00:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM users WHERE email = 'withdrawn-user@devpath.com'
);

-- [B-07] 운영 (공지사항 / 관리자 권한 / 계정 로그)
INSERT INTO notice (
    author_id, title, content, is_pinned, is_deleted, created_at, updated_at
)
SELECT au.user_id,
       '[System] March maintenance window',
       'The platform will be unavailable from 02:00 to 03:00 KST for maintenance.',
       TRUE, FALSE, '2026-03-01 00:00:00', '2026-03-01 00:00:00'
FROM users au
WHERE au.email = 'admin@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM notice n WHERE n.title = '[System] March maintenance window'
  );

INSERT INTO admin_role (
    role_name, description, is_deleted, created_at, updated_at
)
SELECT 'ROLE_ADMIN_OPERATION',
       'Operations role for moderation, notice, settlement, and refund handling',
       FALSE, '2026-03-01 00:00:00', '2026-03-01 00:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM admin_role ar WHERE ar.role_name = 'ROLE_ADMIN_OPERATION' AND ar.is_deleted = FALSE
);

INSERT INTO admin_permission (
    admin_role_id, permission_code, description, is_deleted, created_at
)
SELECT ar.id, 'ADMIN_NOTICE_WRITE', 'Can write and edit notices', FALSE, '2026-03-01 00:00:00'
FROM admin_role ar
WHERE ar.role_name = 'ROLE_ADMIN_OPERATION'
  AND NOT EXISTS (
      SELECT 1 FROM admin_permission ap
      WHERE ap.admin_role_id = ar.id AND ap.permission_code = 'ADMIN_NOTICE_WRITE' AND ap.is_deleted = FALSE
  );

INSERT INTO admin_permission (
    admin_role_id, permission_code, description, is_deleted, created_at
)
SELECT ar.id, 'ADMIN_MODERATION_RESOLVE', 'Can resolve reports and blind content', FALSE, '2026-03-01 00:00:00'
FROM admin_role ar
WHERE ar.role_name = 'ROLE_ADMIN_OPERATION'
  AND NOT EXISTS (
      SELECT 1 FROM admin_permission ap
      WHERE ap.admin_role_id = ar.id AND ap.permission_code = 'ADMIN_MODERATION_RESOLVE' AND ap.is_deleted = FALSE
  );

INSERT INTO account_log (
    target_user_id, admin_id, log_type, reason, processed_at
)
SELECT tu.user_id, au.user_id, 'RESTRICT',
       'Restricted due to repeated abusive comments.',
       '2026-02-15 10:00:00'
FROM users tu, users au
WHERE tu.email = 'restricted-user@devpath.com'
  AND au.email = 'admin@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM account_log al
      WHERE al.target_user_id = tu.user_id AND al.log_type = 'RESTRICT'
  );

INSERT INTO account_log (
    target_user_id, admin_id, log_type, reason, processed_at
)
SELECT tu.user_id, au.user_id, 'DEACTIVATE',
       'Temporarily deactivated at user request.',
       '2026-02-16 10:00:00'
FROM users tu, users au
WHERE tu.email = 'deactivated-user@devpath.com'
  AND au.email = 'admin@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM account_log al
      WHERE al.target_user_id = tu.user_id AND al.log_type = 'DEACTIVATE'
  );

INSERT INTO account_log (
    target_user_id, admin_id, log_type, reason, processed_at
)
SELECT tu.user_id, au.user_id, 'WITHDRAW',
       'Permanent account withdrawal completed.',
       '2026-02-17 10:00:00'
FROM users tu, users au
WHERE tu.email = 'withdrawn-user@devpath.com'
  AND au.email = 'admin@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM account_log al
      WHERE al.target_user_id = tu.user_id AND al.log_type = 'WITHDRAW'
  );

-- [B-08] 알림·메시지 (강사 알림 / DM 방 / DM 메시지)
INSERT INTO instructor_notification (
    instructor_id, type, message, is_read, created_at
)
SELECT iu.user_id, 'REVIEW',
       'A new course review requires your reply.',
       FALSE, '2026-03-02 09:00:00'
FROM users iu
WHERE iu.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM instructor_notification n
      WHERE n.instructor_id = iu.user_id AND n.type = 'REVIEW' AND n.message = 'A new course review requires your reply.'
  );

INSERT INTO instructor_notification (
    instructor_id, type, message, is_read, created_at
)
SELECT iu.user_id, 'QNA',
       'A new Q&A question is waiting in your inbox.',
       FALSE, '2026-03-02 09:05:00'
FROM users iu
WHERE iu.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM instructor_notification n
      WHERE n.instructor_id = iu.user_id AND n.type = 'QNA' AND n.message = 'A new Q&A question is waiting in your inbox.'
  );

INSERT INTO dm_room (
    instructor_id, learner_id, is_deleted, created_at
)
SELECT iu.user_id, lu.user_id, FALSE, '2026-03-03 10:00:00'
FROM users iu, users lu
WHERE iu.email = 'instructor@devpath.com'
  AND lu.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM dm_room dr WHERE dr.instructor_id = iu.user_id AND dr.learner_id = lu.user_id AND dr.is_deleted = FALSE
  );

INSERT INTO dm_message (
    room_id, sender_id, message, is_deleted, created_at
)
SELECT dr.id, lu.user_id,
       'Hi, I have one follow-up question about the Spring Boot example code.',
       FALSE, '2026-03-03 10:01:00'
FROM dm_room dr, users iu, users lu
WHERE dr.instructor_id = iu.user_id
  AND dr.learner_id = lu.user_id
  AND iu.email = 'instructor@devpath.com'
  AND lu.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM dm_message dm
      WHERE dm.room_id = dr.id
        AND dm.message = 'Hi, I have one follow-up question about the Spring Boot example code.'
  );

INSERT INTO dm_message (
    room_id, sender_id, message, is_deleted, created_at
)
SELECT dr.id, iu.user_id,
       'Sure. Send the stack trace and the request payload, and I will help you narrow it down.',
       FALSE, '2026-03-03 10:03:00'
FROM dm_room dr, users iu, users lu
WHERE dr.instructor_id = iu.user_id
  AND dr.learner_id = lu.user_id
  AND iu.email = 'instructor@devpath.com'
  AND lu.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM dm_message dm
      WHERE dm.room_id = dr.id
        AND dm.message = 'Sure. Send the stack trace and the request payload, and I will help you narrow it down.'
  );

-- ========================================
-- B SECTION SEQUENCE FIX
-- ========================================
SELECT setval('review_id_seq', (SELECT COALESCE(MAX(id), 1) FROM review));
SELECT setval('review_reply_id_seq', (SELECT COALESCE(MAX(id), 1) FROM review_reply));
SELECT setval('review_report_id_seq', (SELECT COALESCE(MAX(id), 1) FROM review_report));
SELECT setval('review_template_id_seq', (SELECT COALESCE(MAX(id), 1) FROM review_template));
SELECT setval('qna_questions_question_id_seq', (SELECT COALESCE(MAX(question_id), 1) FROM qna_questions));
SELECT setval('qna_answers_answer_id_seq', (SELECT COALESCE(MAX(answer_id), 1) FROM qna_answers));
SELECT setval('qna_answer_draft_id_seq', (SELECT COALESCE(MAX(id), 1) FROM qna_answer_draft));
SELECT setval('qna_template_id_seq', (SELECT COALESCE(MAX(id), 1) FROM qna_template));
SELECT setval('instructor_post_id_seq', (SELECT COALESCE(MAX(id), 1) FROM instructor_post));
SELECT setval('instructor_comment_id_seq', (SELECT COALESCE(MAX(id), 1) FROM instructor_comment));
SELECT setval('instructor_post_like_id_seq', (SELECT COALESCE(MAX(id), 1) FROM instructor_post_like));
SELECT setval('instructor_comment_like_id_seq', (SELECT COALESCE(MAX(id), 1) FROM instructor_comment_like));
SELECT setval('coupon_id_seq', (SELECT COALESCE(MAX(id), 1) FROM coupon));
SELECT setval('promotion_id_seq', (SELECT COALESCE(MAX(id), 1) FROM promotion));
SELECT setval('conversion_stat_id_seq', (SELECT COALESCE(MAX(id), 1) FROM conversion_stat));
SELECT setval('refund_request_id_seq', (SELECT COALESCE(MAX(id), 1) FROM refund_request));
SELECT setval('refund_review_id_seq', (SELECT COALESCE(MAX(id), 1) FROM refund_review));
SELECT setval('settlement_id_seq', (SELECT COALESCE(MAX(id), 1) FROM settlement));
SELECT setval('settlement_hold_id_seq', (SELECT COALESCE(MAX(id), 1) FROM settlement_hold));
SELECT setval('admin_role_id_seq', (SELECT COALESCE(MAX(id), 1) FROM admin_role));
SELECT setval('admin_permission_id_seq', (SELECT COALESCE(MAX(id), 1) FROM admin_permission));
SELECT setval('account_log_id_seq', (SELECT COALESCE(MAX(id), 1) FROM account_log));
SELECT setval('notice_id_seq', (SELECT COALESCE(MAX(id), 1) FROM notice));
SELECT setval('instructor_notification_id_seq', (SELECT COALESCE(MAX(id), 1) FROM instructor_notification));
SELECT setval('dm_room_id_seq', (SELECT COALESCE(MAX(id), 1) FROM dm_room));
SELECT setval('dm_message_id_seq', (SELECT COALESCE(MAX(id), 1) FROM dm_message));

-- ========================================
-- C SECTION USERS
-- ========================================
INSERT INTO users (email, password, name, role_name, is_active, created_at, updated_at)
SELECT
    'learner2@devpath.com',
    '$2a$10$RcdWJBwl.kuttYmqm/BN..6aZKeLNlq9DiNFHbZgZxfTzzNDD33o2',
    '박지민',
    'ROLE_LEARNER',
    TRUE,
    NOW(),
    TIMESTAMP '2026-01-20 09:00:00'
WHERE NOT EXISTS (
    SELECT 1
    FROM users
    WHERE email = 'learner2@devpath.com'
);

INSERT INTO users (email, password, name, role_name, is_active, created_at, updated_at)
SELECT
    'learner3@devpath.com',
    '$2a$10$RcdWJBwl.kuttYmqm/BN..6aZKeLNlq9DiNFHbZgZxfTzzNDD33o2',
    '이서준',
    'ROLE_LEARNER',
    TRUE,
    NOW(),
    NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM users
    WHERE email = 'learner3@devpath.com'
);

INSERT INTO review (
    course_id, learner_id, rating, content, status, is_hidden, is_deleted, issue_tags_raw, created_at, updated_at
)
SELECT c.course_id, u.user_id, 2,
       '중반 이후부터 설명 속도가 빨라져서 따라가기 어려웠습니다. 초보자 기준으로 한 번 더 짚어주는 보충 설명이나 요약 자료가 있으면 좋겠습니다.',
       'UNANSWERED', FALSE, FALSE, '속도가_빨라요,초보자에겐_어려워요',
       '2026-02-15 19:30:00', '2026-02-15 19:30:00'
FROM users u, courses c
WHERE u.email = 'learner2@devpath.com'
  AND c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1 FROM review r
      WHERE r.course_id = c.course_id AND r.learner_id = u.user_id
  );

-- ========================================
-- C SECTION STUDY
-- ========================================
INSERT INTO study_group (name, description, status, max_members, is_deleted, created_at)
SELECT
    'Spring Boot API Study Crew',
    'Spring Boot, JPA, Security를 같이 학습하는 모집중 스터디 그룹',
    'RECRUITING',
    5,
    FALSE,
    '2026-03-24 09:00:00'
WHERE NOT EXISTS (
    SELECT 1
    FROM study_group
    WHERE name = 'Spring Boot API Study Crew'
      AND is_deleted = FALSE
);

INSERT INTO study_group (name, description, status, max_members, is_deleted, created_at)
SELECT
    'Algorithm Deep Dive',
    '모집이 끝나고 진행중인 알고리즘 스터디 그룹',
    'IN_PROGRESS',
    4,
    FALSE,
    '2026-03-20 19:00:00'
WHERE NOT EXISTS (
    SELECT 1
    FROM study_group
    WHERE name = 'Algorithm Deep Dive'
      AND is_deleted = FALSE
);

-- 현재 스키마에서는 study_group_application 대신 study_group_member.join_status 로 신청/승인/거절을 표현한다.
INSERT INTO study_group_member (group_id, learner_id, join_status, joined_at)
SELECT
    sg.id,
    u.user_id,
    'APPROVED',
    '2026-03-24 09:10:00'
FROM study_group sg, users u
WHERE sg.name = 'Spring Boot API Study Crew'
  AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM study_group_member sgm
      WHERE sgm.group_id = sg.id
        AND sgm.learner_id = u.user_id
  );

INSERT INTO study_group_member (group_id, learner_id, join_status, joined_at)
SELECT
    sg.id,
    u.user_id,
    'PENDING',
    NULL
FROM study_group sg, users u
WHERE sg.name = 'Spring Boot API Study Crew'
  AND u.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM study_group_member sgm
      WHERE sgm.group_id = sg.id
        AND sgm.learner_id = u.user_id
  );

INSERT INTO study_group_member (group_id, learner_id, join_status, joined_at)
SELECT
    sg.id,
    u.user_id,
    'REJECTED',
    NULL
FROM study_group sg, users u
WHERE sg.name = 'Spring Boot API Study Crew'
  AND u.email = 'learner3@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM study_group_member sgm
      WHERE sgm.group_id = sg.id
        AND sgm.learner_id = u.user_id
  );

INSERT INTO study_group_member (group_id, learner_id, join_status, joined_at)
SELECT
    sg.id,
    u.user_id,
    'APPROVED',
    '2026-03-21 10:00:00'
FROM study_group sg, users u
WHERE sg.name = 'Algorithm Deep Dive'
  AND u.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM study_group_member sgm
      WHERE sgm.group_id = sg.id
        AND sgm.learner_id = u.user_id
  );

INSERT INTO study_match (requester_id, receiver_id, node_id, status, created_at)
SELECT
    requester.user_id,
    receiver.user_id,
    rn.node_id,
    'RECOMMENDED',
    '2026-03-25 08:30:00'
FROM users requester, users receiver, roadmaps r, roadmap_nodes rn
WHERE requester.email = 'learner@devpath.com'
  AND receiver.email = 'learner2@devpath.com'
  AND r.title = 'Backend Master Roadmap'
  AND rn.roadmap_id = r.roadmap_id
  AND rn.title = 'Java Basics'
  AND NOT EXISTS (
      SELECT 1
      FROM study_match sm
      WHERE sm.requester_id = requester.user_id
        AND sm.receiver_id = receiver.user_id
        AND sm.node_id = rn.node_id
  );

INSERT INTO study_match (requester_id, receiver_id, node_id, status, created_at)
SELECT
    requester.user_id,
    receiver.user_id,
    rn.node_id,
    'ACCEPTED',
    '2026-03-26 20:15:00'
FROM users requester, users receiver, roadmaps r, roadmap_nodes rn
WHERE requester.email = 'learner2@devpath.com'
  AND receiver.email = 'learner3@devpath.com'
  AND r.title = 'Backend Master Roadmap'
  AND rn.roadmap_id = r.roadmap_id
  AND rn.title = 'HTTP Fundamentals'
  AND NOT EXISTS (
      SELECT 1
      FROM study_match sm
      WHERE sm.requester_id = requester.user_id
        AND sm.receiver_id = receiver.user_id
        AND sm.node_id = rn.node_id
  );

-- ========================================
-- C SECTION PLANNER
-- ========================================
INSERT INTO learner_goal (learner_id, goal_type, target_value, is_active)
SELECT
    u.user_id,
    'WEEKLY_NODE_CLEAR',
    3,
    TRUE
FROM users u
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM learner_goal lg
      WHERE lg.learner_id = u.user_id
        AND lg.goal_type = 'WEEKLY_NODE_CLEAR'
        AND lg.target_value = 3
  );

INSERT INTO learner_goal (learner_id, goal_type, target_value, is_active)
SELECT
    u.user_id,
    'WEEKLY_STUDY_TIME',
    10,
    TRUE
FROM users u
WHERE u.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM learner_goal lg
      WHERE lg.learner_id = u.user_id
        AND lg.goal_type = 'WEEKLY_STUDY_TIME'
        AND lg.target_value = 10
  );

INSERT INTO learner_goal (learner_id, goal_type, target_value, is_active)
SELECT
    u.user_id,
    'CUSTOM',
    1,
    TRUE
FROM users u
WHERE u.email = 'learner3@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM learner_goal lg
      WHERE lg.learner_id = u.user_id
        AND lg.goal_type = 'CUSTOM'
        AND lg.target_value = 1
  );

INSERT INTO weekly_plan (learner_id, plan_content, status, created_at)
SELECT
    u.user_id,
    '월/수/금: Spring Boot Intro 2개 레슨 수강, 화/목: HTTP Fundamentals 복습, 토: 퀴즈 정리',
    'PLANNED',
    '2026-03-24 07:00:00'
FROM users u
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM weekly_plan wp
      WHERE wp.learner_id = u.user_id
        AND wp.plan_content = '월/수/금: Spring Boot Intro 2개 레슨 수강, 화/목: HTTP Fundamentals 복습, 토: 퀴즈 정리'
  );

INSERT INTO weekly_plan (learner_id, plan_content, status, created_at)
SELECT
    u.user_id,
    '주간 계획 조정본: JPA 파트 난이도가 높아 실습 비중을 늘리고, 토요일에 과제 제출까지 완료',
    'IN_PROGRESS',
    '2026-03-25 07:10:00'
FROM users u
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM weekly_plan wp
      WHERE wp.learner_id = u.user_id
        AND wp.plan_content = '주간 계획 조정본: JPA 파트 난이도가 높아 실습 비중을 늘리고, 토요일에 과제 제출까지 완료'
  );

INSERT INTO weekly_plan (learner_id, plan_content, status, created_at)
SELECT
    u.user_id,
    '이번 주 목표: 알고리즘 5문제 풀이, 스터디 발표 자료 준비, 프로젝트 아이디어 초안 작성',
    'PLANNED',
    '2026-03-24 08:00:00'
FROM users u
WHERE u.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM weekly_plan wp
      WHERE wp.learner_id = u.user_id
        AND wp.plan_content = '이번 주 목표: 알고리즘 5문제 풀이, 스터디 발표 자료 준비, 프로젝트 아이디어 초안 작성'
  );

INSERT INTO streak (learner_id, current_streak, longest_streak, last_study_date)
SELECT
    u.user_id,
    5,
    8,
    DATE '2026-03-30'
FROM users u
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM streak s
      WHERE s.learner_id = u.user_id
  );

INSERT INTO streak (learner_id, current_streak, longest_streak, last_study_date)
SELECT
    u.user_id,
    2,
    4,
    DATE '2026-03-29'
FROM users u
WHERE u.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM streak s
      WHERE s.learner_id = u.user_id
  );

INSERT INTO recovery_plan (learner_id, plan_details, created_at)
SELECT
    u.user_id,
    '스트릭 복구 플랜: 오늘 30분 복습, 내일 1시간 실습, 모레 퀴즈 재응시로 루틴 복구',
    '2026-03-30 06:30:00'
FROM users u
WHERE u.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM recovery_plan rp
      WHERE rp.learner_id = u.user_id
        AND rp.plan_details = '스트릭 복구 플랜: 오늘 30분 복습, 내일 1시간 실습, 모레 퀴즈 재응시로 루틴 복구'
  );

-- ========================================
-- C SECTION NOTIFICATION
-- ========================================
INSERT INTO learner_notification (learner_id, type, message, is_read, created_at)
SELECT
    u.user_id,
    'STUDY_GROUP',
    'Spring Boot API Study Crew 참여 신청이 승인되었습니다.',
    FALSE,
    '2026-03-26 09:00:00'
FROM users u
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM learner_notification n
      WHERE n.learner_id = u.user_id
        AND n.message = 'Spring Boot API Study Crew 참여 신청이 승인되었습니다.'
  );

INSERT INTO learner_notification (learner_id, type, message, is_read, created_at)
SELECT
    u.user_id,
    'PLANNER',
    '이번 주 학습 플랜이 생성되었습니다. 첫 번째 일정은 월요일 19:00입니다.',
    FALSE,
    '2026-03-24 07:05:00'
FROM users u
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM learner_notification n
      WHERE n.learner_id = u.user_id
        AND n.message = '이번 주 학습 플랜이 생성되었습니다. 첫 번째 일정은 월요일 19:00입니다.'
  );

INSERT INTO learner_notification (learner_id, type, message, is_read, created_at)
SELECT
    u.user_id,
    'PROJECT',
    '프로젝트 역할이 BACKEND로 배정되었습니다.',
    TRUE,
    '2026-03-27 10:30:00'
FROM users u
WHERE u.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM learner_notification n
      WHERE n.learner_id = u.user_id
        AND n.message = '프로젝트 역할이 BACKEND로 배정되었습니다.'
  );

INSERT INTO learner_notification (learner_id, type, message, is_read, created_at)
SELECT
    u.user_id,
    'STREAK',
    '학습 스트릭이 5일째 유지 중입니다. 오늘도 이어가보세요.',
    TRUE,
    '2026-03-30 21:00:00'
FROM users u
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM learner_notification n
      WHERE n.learner_id = u.user_id
        AND n.message = '학습 스트릭이 5일째 유지 중입니다. 오늘도 이어가보세요.'
  );

-- ========================================
-- C SECTION DASHBOARD
-- ========================================
INSERT INTO dashboard_snapshot (learner_id, total_study_hours, completed_nodes, snapshot_date)
SELECT u.user_id, 2, 0, DATE '2026-03-24'
FROM users u
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM dashboard_snapshot ds
      WHERE ds.learner_id = u.user_id
        AND ds.snapshot_date = DATE '2026-03-24'
  );

INSERT INTO dashboard_snapshot (learner_id, total_study_hours, completed_nodes, snapshot_date)
SELECT u.user_id, 3, 1, DATE '2026-03-25'
FROM users u
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM dashboard_snapshot ds
      WHERE ds.learner_id = u.user_id
        AND ds.snapshot_date = DATE '2026-03-25'
  );

INSERT INTO dashboard_snapshot (learner_id, total_study_hours, completed_nodes, snapshot_date)
SELECT u.user_id, 1, 1, DATE '2026-03-26'
FROM users u
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM dashboard_snapshot ds
      WHERE ds.learner_id = u.user_id
        AND ds.snapshot_date = DATE '2026-03-26'
  );

INSERT INTO dashboard_snapshot (learner_id, total_study_hours, completed_nodes, snapshot_date)
SELECT u.user_id, 4, 2, DATE '2026-03-27'
FROM users u
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM dashboard_snapshot ds
      WHERE ds.learner_id = u.user_id
        AND ds.snapshot_date = DATE '2026-03-27'
  );

INSERT INTO dashboard_snapshot (learner_id, total_study_hours, completed_nodes, snapshot_date)
SELECT u.user_id, 2, 2, DATE '2026-03-28'
FROM users u
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM dashboard_snapshot ds
      WHERE ds.learner_id = u.user_id
        AND ds.snapshot_date = DATE '2026-03-28'
  );

INSERT INTO dashboard_snapshot (learner_id, total_study_hours, completed_nodes, snapshot_date)
SELECT u.user_id, 5, 3, DATE '2026-03-29'
FROM users u
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM dashboard_snapshot ds
      WHERE ds.learner_id = u.user_id
        AND ds.snapshot_date = DATE '2026-03-29'
  );

INSERT INTO dashboard_snapshot (learner_id, total_study_hours, completed_nodes, snapshot_date)
SELECT u.user_id, 3, 3, DATE '2026-03-30'
FROM users u
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM dashboard_snapshot ds
      WHERE ds.learner_id = u.user_id
        AND ds.snapshot_date = DATE '2026-03-30'
  );

INSERT INTO dashboard_snapshot (learner_id, total_study_hours, completed_nodes, snapshot_date)
SELECT u.user_id, 2, 1, DATE '2026-03-30'
FROM users u
WHERE u.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM dashboard_snapshot ds
      WHERE ds.learner_id = u.user_id
        AND ds.snapshot_date = DATE '2026-03-30'
  );

-- ========================================
-- C SECTION PROJECT
-- ========================================
INSERT INTO project (owner_id, name, description, project_type, status, visibility, recruiting_status, is_deleted, created_at)
SELECT
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    'DevPath Team Workspace',
    'DevPath 팀 협업 워크스페이스용 프로젝트. 역할 배정, 멘토링, Proof 제출 테스트용 데이터',
    'SQUAD',
    'IN_PROGRESS',
    'PUBLIC',
    'OPEN',
    FALSE,
    '2026-03-23 14:00:00'
WHERE NOT EXISTS (
    SELECT 1
    FROM project
    WHERE name = 'DevPath Team Workspace'
      AND is_deleted = FALSE
);

INSERT INTO project (owner_id, name, description, project_type, status, visibility, recruiting_status, is_deleted, created_at)
SELECT
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    'Portfolio Builder Squad',
    '포트폴리오 제작 중심의 준비중 프로젝트. 초대 거절/멘토링 승인 시나리오 테스트용 데이터',
    'SQUAD',
    'PREPARING',
    'PUBLIC',
    'CLOSED',
    FALSE,
    '2026-03-22 11:00:00'
WHERE NOT EXISTS (
    SELECT 1
    FROM project
    WHERE name = 'Portfolio Builder Squad'
      AND is_deleted = FALSE
);

INSERT INTO project_role (project_id, role_type, required_count)
SELECT
    p.id,
    'LEADER',
    1
FROM project p
WHERE p.name = 'DevPath Team Workspace'
  AND NOT EXISTS (
      SELECT 1
      FROM project_role pr
      WHERE pr.project_id = p.id
        AND pr.role_type = 'LEADER'
  );

INSERT INTO project_role (project_id, role_type, required_count)
SELECT
    p.id,
    'BACKEND',
    2
FROM project p
WHERE p.name = 'DevPath Team Workspace'
  AND NOT EXISTS (
      SELECT 1
      FROM project_role pr
      WHERE pr.project_id = p.id
        AND pr.role_type = 'BACKEND'
  );

INSERT INTO project_role (project_id, role_type, required_count)
SELECT
    p.id,
    'FRONTEND',
    1
FROM project p
WHERE p.name = 'DevPath Team Workspace'
  AND NOT EXISTS (
      SELECT 1
      FROM project_role pr
      WHERE pr.project_id = p.id
        AND pr.role_type = 'FRONTEND'
  );

INSERT INTO project_role (project_id, role_type, required_count)
SELECT
    p.id,
    'FULLSTACK',
    2
FROM project p
WHERE p.name = 'Portfolio Builder Squad'
  AND NOT EXISTS (
      SELECT 1
      FROM project_role pr
      WHERE pr.project_id = p.id
        AND pr.role_type = 'FULLSTACK'
  );

INSERT INTO project_member (project_id, learner_id, role_type, joined_at)
SELECT
    p.id,
    u.user_id,
    'LEADER',
    '2026-03-23 14:10:00'
FROM project p, users u
WHERE p.name = 'DevPath Team Workspace'
  AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM project_member pm
      WHERE pm.project_id = p.id
        AND pm.learner_id = u.user_id
  );

INSERT INTO project_member (project_id, learner_id, role_type, joined_at)
SELECT
    p.id,
    u.user_id,
    'BACKEND',
    '2026-03-24 10:00:00'
FROM project p, users u
WHERE p.name = 'DevPath Team Workspace'
  AND u.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM project_member pm
      WHERE pm.project_id = p.id
        AND pm.learner_id = u.user_id
  );

INSERT INTO project_member (project_id, learner_id, role_type, joined_at)
SELECT
    p.id,
    u.user_id,
    'FULLSTACK',
    '2026-03-22 11:30:00'
FROM project p, users u
WHERE p.name = 'Portfolio Builder Squad'
  AND u.email = 'learner3@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM project_member pm
      WHERE pm.project_id = p.id
        AND pm.learner_id = u.user_id
  );

INSERT INTO project_invitation (project_id, inviter_id, invitee_id, status, created_at)
SELECT
    p.id,
    inviter.user_id,
    invitee.user_id,
    'PENDING',
    '2026-03-28 13:00:00'
FROM project p, users inviter, users invitee
WHERE p.name = 'DevPath Team Workspace'
  AND inviter.email = 'learner@devpath.com'
  AND invitee.email = 'learner3@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM project_invitation pi
      WHERE pi.project_id = p.id
        AND pi.inviter_id = inviter.user_id
        AND pi.invitee_id = invitee.user_id
  );

INSERT INTO project_invitation (project_id, inviter_id, invitee_id, status, created_at)
SELECT
    p.id,
    inviter.user_id,
    invitee.user_id,
    'ACCEPTED',
    '2026-03-24 09:40:00'
FROM project p, users inviter, users invitee
WHERE p.name = 'DevPath Team Workspace'
  AND inviter.email = 'learner@devpath.com'
  AND invitee.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM project_invitation pi
      WHERE pi.project_id = p.id
        AND pi.inviter_id = inviter.user_id
        AND pi.invitee_id = invitee.user_id
  );

INSERT INTO project_invitation (project_id, inviter_id, invitee_id, status, created_at)
SELECT
    p.id,
    inviter.user_id,
    invitee.user_id,
    'REJECTED',
    '2026-03-25 16:20:00'
FROM project p, users inviter, users invitee
WHERE p.name = 'Portfolio Builder Squad'
  AND inviter.email = 'learner3@devpath.com'
  AND invitee.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM project_invitation pi
      WHERE pi.project_id = p.id
        AND pi.inviter_id = inviter.user_id
        AND pi.invitee_id = invitee.user_id
  );

INSERT INTO mentoring_application (project_id, mentor_id, message, status, created_at)
SELECT
    p.id,
    mentor.user_id,
    'Spring Security 구조 리뷰와 API 인증 흐름 피드백이 필요합니다.',
    'PENDING',
    '2026-03-29 15:00:00'
FROM project p, users mentor
WHERE p.name = 'DevPath Team Workspace'
  AND mentor.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM mentoring_application ma
      WHERE ma.project_id = p.id
        AND ma.mentor_id = mentor.user_id
        AND ma.message = 'Spring Security 구조 리뷰와 API 인증 흐름 피드백이 필요합니다.'
  );

INSERT INTO mentoring_application (project_id, mentor_id, message, status, created_at)
SELECT
    p.id,
    mentor.user_id,
    '포트폴리오 초안 구조와 README 작성 방향에 대한 피드백 요청',
    'APPROVED',
    '2026-03-27 12:00:00'
FROM project p, users mentor
WHERE p.name = 'Portfolio Builder Squad'
  AND mentor.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM mentoring_application ma
      WHERE ma.project_id = p.id
        AND ma.mentor_id = mentor.user_id
        AND ma.message = '포트폴리오 초안 구조와 README 작성 방향에 대한 피드백 요청'
  );

INSERT INTO project_idea_post (author_id, title, content, status, is_deleted, created_at)
SELECT
    u.user_id,
    '캡스톤용 DevPath 협업 워크스페이스 고도화 아이디어',
    '프로젝트 멤버 초대, 역할 배정, Proof Card 제출 흐름을 하나의 시연 시나리오로 묶는 기능 제안',
    'PUBLISHED',
    FALSE,
    '2026-03-26 18:00:00'
FROM users u
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM project_idea_post pip
      WHERE pip.author_id = u.user_id
        AND pip.title = '캡스톤용 DevPath 협업 워크스페이스 고도화 아이디어'
  );

INSERT INTO project_idea_post (author_id, title, content, status, is_deleted, created_at)
SELECT
    u.user_id,
    '개인 포트폴리오 빌더 연동 초안',
    '학습 이력과 프로젝트 산출물을 한 번에 정리하는 포트폴리오 빌더 페이지 연결안',
    'DRAFT',
    FALSE,
    '2026-03-28 20:10:00'
FROM users u
WHERE u.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM project_idea_post pip
      WHERE pip.author_id = u.user_id
        AND pip.title = '개인 포트폴리오 빌더 연동 초안'
  );

-- proof_card_ref_id 는 현재 문자열 참조값만 저장하므로 Swagger 검증용 더미 ref 값을 직접 넣는다.
-- 중복 제출 방지 테스트용 ref: PROOF-C-001
INSERT INTO project_proof_submission (project_id, submitter_id, proof_card_ref_id, submitted_at)
SELECT
    p.id,
    u.user_id,
    'PROOF-C-001',
    '2026-03-29 11:00:00'
FROM project p, users u
WHERE p.name = 'DevPath Team Workspace'
  AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM project_proof_submission pps
      WHERE pps.project_id = p.id
        AND pps.submitter_id = u.user_id
        AND pps.proof_card_ref_id = 'PROOF-C-001'
  );

INSERT INTO project_proof_submission (project_id, submitter_id, proof_card_ref_id, submitted_at)
SELECT
    p.id,
    u.user_id,
    'PROOF-C-002',
    '2026-03-29 11:20:00'
FROM project p, users u
WHERE p.name = 'DevPath Team Workspace'
  AND u.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM project_proof_submission pps
      WHERE pps.project_id = p.id
        AND pps.submitter_id = u.user_id
        AND pps.proof_card_ref_id = 'PROOF-C-002'
  );

INSERT INTO project_proof_submission (project_id, submitter_id, proof_card_ref_id, submitted_at)
SELECT
    p.id,
    u.user_id,
    'PROOF-C-003',
    '2026-03-30 09:30:00'
FROM project p, users u
WHERE p.name = 'Portfolio Builder Squad'
  AND u.email = 'learner3@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM project_proof_submission pps
      WHERE pps.project_id = p.id
        AND pps.submitter_id = u.user_id
        AND pps.proof_card_ref_id = 'PROOF-C-003'
  );

-- ========================================
-- C SECTION SEQUENCE FIX
-- ========================================
SELECT setval('study_group_id_seq', (SELECT COALESCE(MAX(id), 1) FROM study_group));
SELECT setval('study_group_member_id_seq', (SELECT COALESCE(MAX(id), 1) FROM study_group_member));
SELECT setval('study_match_id_seq', (SELECT COALESCE(MAX(id), 1) FROM study_match));
SELECT setval('learner_goal_id_seq', (SELECT COALESCE(MAX(id), 1) FROM learner_goal));
SELECT setval('weekly_plan_id_seq', (SELECT COALESCE(MAX(id), 1) FROM weekly_plan));
SELECT setval('streak_id_seq', (SELECT COALESCE(MAX(id), 1) FROM streak));
SELECT setval('recovery_plan_id_seq', (SELECT COALESCE(MAX(id), 1) FROM recovery_plan));
SELECT setval('learner_notification_id_seq', (SELECT COALESCE(MAX(id), 1) FROM learner_notification));
SELECT setval('dashboard_snapshot_id_seq', (SELECT COALESCE(MAX(id), 1) FROM dashboard_snapshot));
SELECT setval('project_id_seq', (SELECT COALESCE(MAX(id), 1) FROM project));
SELECT setval('project_invitation_id_seq', (SELECT COALESCE(MAX(id), 1) FROM project_invitation));
SELECT setval('project_member_id_seq', (SELECT COALESCE(MAX(id), 1) FROM project_member));
SELECT setval('project_role_id_seq', (SELECT COALESCE(MAX(id), 1) FROM project_role));
SELECT setval('mentoring_application_id_seq', (SELECT COALESCE(MAX(id), 1) FROM mentoring_application));
SELECT setval('project_idea_post_id_seq', (SELECT COALESCE(MAX(id), 1) FROM project_idea_post));
SELECT setval('project_proof_submission_id_seq', (SELECT COALESCE(MAX(id), 1) FROM project_proof_submission));

-- ========================================
-- A SECTION LEARNING AUTOMATION / PROOF / HISTORY
-- ========================================
INSERT INTO quizzes (
    node_id,
    title,
    description,
    quiz_type,
    total_score,
    is_published,
    is_active,
    expose_answer,
    expose_explanation,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    rn.node_id,
    'Spring Boot Intro Checkpoint Quiz',
    'Checkpoint quiz for the Java Basics roadmap node.',
    'MANUAL',
    100,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    FALSE,
    TIMESTAMP '2026-03-28 20:50:00',
    TIMESTAMP '2026-03-28 20:50:00'
FROM roadmap_nodes rn
JOIN roadmaps r ON r.roadmap_id = rn.roadmap_id
WHERE r.title = 'Backend Master Roadmap'
  AND rn.title = 'Java Basics'
  AND NOT EXISTS (
      SELECT 1
      FROM quizzes q
      WHERE q.title = 'Spring Boot Intro Checkpoint Quiz'
        AND q.node_id = rn.node_id
  );

INSERT INTO quiz_questions (
    quiz_id,
    question_type,
    question_text,
    explanation,
    points,
    display_order,
    source_timestamp,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    q.quiz_id,
    'MULTIPLE_CHOICE',
    'Which statement best describes dependency injection in Spring?',
    'Spring manages object wiring for application components.',
    100,
    1,
    NULL,
    FALSE,
    TIMESTAMP '2026-03-28 20:50:00',
    TIMESTAMP '2026-03-28 20:50:00'
FROM quizzes q
JOIN roadmap_nodes rn ON rn.node_id = q.node_id
JOIN roadmaps r ON r.roadmap_id = rn.roadmap_id
WHERE q.title = 'Spring Boot Intro Checkpoint Quiz'
  AND r.title = 'Backend Master Roadmap'
  AND rn.title = 'Java Basics'
  AND NOT EXISTS (
      SELECT 1
      FROM quiz_questions qq
      WHERE qq.quiz_id = q.quiz_id
        AND qq.display_order = 1
  );

INSERT INTO quiz_question_options (
    question_id,
    option_text,
    is_correct,
    display_order,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    qq.question_id,
    option_seed.option_text,
    option_seed.is_correct,
    option_seed.display_order,
    FALSE,
    TIMESTAMP '2026-03-28 20:50:00',
    TIMESTAMP '2026-03-28 20:50:00'
FROM quiz_questions qq
JOIN quizzes q ON q.quiz_id = qq.quiz_id
JOIN (
    SELECT 'Constructor injection' AS option_text, FALSE AS is_correct, 1 AS display_order
    UNION ALL
    SELECT 'Field injection', FALSE, 2
    UNION ALL
    SELECT 'Manual new object creation', FALSE, 3
    UNION ALL
    SELECT 'Spring manages object wiring for application components.', TRUE, 4
) option_seed ON TRUE
WHERE q.title = 'Spring Boot Intro Checkpoint Quiz'
  AND qq.display_order = 1
  AND NOT EXISTS (
      SELECT 1
      FROM quiz_question_options qo
      WHERE qo.question_id = qq.question_id
  );

INSERT INTO assignments (
    node_id,
    title,
    description,
    submission_type,
    due_at,
    allowed_file_formats,
    readme_required,
    test_required,
    lint_required,
    submission_rule_description,
    total_score,
    is_published,
    is_active,
    allow_late_submission,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    rn.node_id,
    'Spring Boot Intro Practice Submission',
    'Practice submission for the HTTP Fundamentals roadmap node.',
    'MULTIPLE',
    TIMESTAMP '2026-04-05 23:59:59',
    'md,txt,zip',
    TRUE,
    TRUE,
    TRUE,
    'Submit a README, test result summary, and repository URL.',
    100,
    TRUE,
    TRUE,
    FALSE,
    FALSE,
    TIMESTAMP '2026-03-28 21:00:00',
    TIMESTAMP '2026-03-28 21:00:00'
FROM roadmap_nodes rn
JOIN roadmaps r ON r.roadmap_id = rn.roadmap_id
WHERE r.title = 'Backend Master Roadmap'
  AND rn.title = 'HTTP Fundamentals'
  AND NOT EXISTS (
      SELECT 1
      FROM assignments a
      WHERE a.title = 'Spring Boot Intro Practice Submission'
        AND a.node_id = rn.node_id
  );

INSERT INTO lesson_progress (
    user_id,
    lesson_id,
    progress_percent,
    progress_seconds,
    default_playback_rate,
    is_pip_enabled,
    is_completed,
    last_watched_at,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    l.lesson_id,
    100,
    1800,
    1.25,
    TRUE,
    TRUE,
    TIMESTAMP '2026-03-28 21:10:00',
    TIMESTAMP '2026-03-28 21:10:00',
    TIMESTAMP '2026-03-28 21:10:00'
FROM users u
JOIN lessons l ON l.title = 'Understanding DI and IoC'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM lesson_progress lp
      WHERE lp.user_id = u.user_id
        AND lp.lesson_id = l.lesson_id
  );

INSERT INTO lesson_progress (
    user_id,
    lesson_id,
    progress_percent,
    progress_seconds,
    default_playback_rate,
    is_pip_enabled,
    is_completed,
    last_watched_at,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    l.lesson_id,
    45,
    640,
    1.00,
    FALSE,
    FALSE,
    TIMESTAMP '2026-03-29 20:25:00',
    TIMESTAMP '2026-03-29 20:25:00',
    TIMESTAMP '2026-03-29 20:25:00'
FROM users u
JOIN lessons l ON l.title = 'Entity relationships and mapping'
WHERE u.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM lesson_progress lp
      WHERE lp.user_id = u.user_id
        AND lp.lesson_id = l.lesson_id
  );

INSERT INTO quiz_attempts (
    quiz_id,
    learner_id,
    score,
    max_score,
    started_at,
    completed_at,
    time_spent_seconds,
    is_passed,
    attempt_number,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    q.quiz_id,
    u.user_id,
    90,
    100,
    TIMESTAMP '2026-03-28 21:20:00',
    TIMESTAMP '2026-03-28 21:27:00',
    420,
    TRUE,
    1,
    FALSE,
    TIMESTAMP '2026-03-28 21:20:00',
    TIMESTAMP '2026-03-28 21:27:00'
FROM quizzes q
JOIN users u ON u.email = 'learner@devpath.com'
WHERE q.title = 'Spring Boot Intro Checkpoint Quiz'
  AND NOT EXISTS (
      SELECT 1
      FROM quiz_attempts qa
      WHERE qa.quiz_id = q.quiz_id
        AND qa.learner_id = u.user_id
        AND qa.attempt_number = 1
        AND qa.is_deleted = FALSE
  );

INSERT INTO quiz_attempts (
    quiz_id,
    learner_id,
    score,
    max_score,
    started_at,
    completed_at,
    time_spent_seconds,
    is_passed,
    attempt_number,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    q.quiz_id,
    u.user_id,
    40,
    100,
    TIMESTAMP '2026-03-29 20:30:00',
    TIMESTAMP '2026-03-29 20:36:00',
    360,
    FALSE,
    1,
    FALSE,
    TIMESTAMP '2026-03-29 20:30:00',
    TIMESTAMP '2026-03-29 20:36:00'
FROM quizzes q
JOIN users u ON u.email = 'learner2@devpath.com'
WHERE q.title = 'Spring Boot Intro Checkpoint Quiz'
  AND NOT EXISTS (
      SELECT 1
      FROM quiz_attempts qa
      WHERE qa.quiz_id = q.quiz_id
        AND qa.learner_id = u.user_id
        AND qa.attempt_number = 1
        AND qa.is_deleted = FALSE
  );

INSERT INTO assignment_submissions (
    assignment_id,
    learner_id,
    grader_id,
    submission_text,
    submission_url,
    is_late,
    submission_status,
    submitted_at,
    graded_at,
    readme_passed,
    test_passed,
    lint_passed,
    file_format_passed,
    quality_score,
    total_score,
    individual_feedback,
    common_feedback,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    a.assignment_id,
    lu.user_id,
    iu.user_id,
    'Final practice submission with README, test summary, and deployment notes.',
    'https://github.com/devpath-samples/spring-boot-intro-final',
    FALSE,
    'GRADED',
    TIMESTAMP '2026-03-28 22:10:00',
    TIMESTAMP '2026-03-28 23:00:00',
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    96,
    95,
    'Requirements are complete and the automated checks are stable.',
    'README quality and test coverage are both strong.',
    FALSE,
    TIMESTAMP '2026-03-28 22:10:00',
    TIMESTAMP '2026-03-28 23:00:00'
FROM assignments a
JOIN users lu ON lu.email = 'learner@devpath.com'
JOIN users iu ON iu.email = 'instructor@devpath.com'
WHERE a.title = 'Spring Boot Intro Practice Submission'
  AND NOT EXISTS (
      SELECT 1
      FROM assignment_submissions s
      WHERE s.assignment_id = a.assignment_id
        AND s.learner_id = lu.user_id
        AND s.is_deleted = FALSE
  );

INSERT INTO assignment_submissions (
    assignment_id,
    learner_id,
    grader_id,
    submission_text,
    submission_url,
    is_late,
    submission_status,
    submitted_at,
    graded_at,
    readme_passed,
    test_passed,
    lint_passed,
    file_format_passed,
    quality_score,
    total_score,
    individual_feedback,
    common_feedback,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    a.assignment_id,
    lu.user_id,
    NULL,
    'Draft submission. README and tests still need work.',
    NULL,
    FALSE,
    'PRECHECK_FAILED',
    NULL,
    NULL,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    52,
    NULL,
    NULL,
    NULL,
    FALSE,
    TIMESTAMP '2026-03-29 21:10:00',
    TIMESTAMP '2026-03-29 21:10:00'
FROM assignments a
JOIN users lu ON lu.email = 'learner2@devpath.com'
WHERE a.title = 'Spring Boot Intro Practice Submission'
  AND NOT EXISTS (
      SELECT 1
      FROM assignment_submissions s
      WHERE s.assignment_id = a.assignment_id
        AND s.learner_id = lu.user_id
        AND s.is_deleted = FALSE
  );

INSERT INTO til_drafts (
    user_id,
    lesson_id,
    title,
    content,
    table_of_contents,
    status,
    published_url,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    l.lesson_id,
    'Spring Bean Lifecycle Notes',
    '# Bean lifecycle' || E'\n\n' ||
    '## Key points' || E'\n' ||
    '- singleton scope' || E'\n' ||
    '- initialization callback' || E'\n\n' ||
    '## Reflection' || E'\n' ||
    'Understanding the lifecycle makes debugging much faster.',
    '[{"text":"Bean lifecycle","level":1},{"text":"Key points","level":2},{"text":"Reflection","level":2}]',
    'PUBLISHED',
    'https://velog.io/@devpath/bean-lifecycle',
    FALSE,
    TIMESTAMP '2026-03-28 22:30:00',
    TIMESTAMP '2026-03-28 22:45:00'
FROM users u
JOIN lessons l ON l.title = 'Understanding DI and IoC'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM til_drafts t
      WHERE t.user_id = u.user_id
        AND t.title = 'Spring Bean Lifecycle Notes'
        AND t.is_deleted = FALSE
  );

INSERT INTO til_drafts (
    user_id,
    lesson_id,
    title,
    content,
    table_of_contents,
    status,
    published_url,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    l.lesson_id,
    'JPA Mapping Memo',
    '# Relationship mapping' || E'\n\n' ||
    '## TODO' || E'\n' ||
    '- review helper methods' || E'\n' ||
    '- verify lazy loading behavior',
    '[{"text":"Relationship mapping","level":1},{"text":"TODO","level":2}]',
    'DRAFT',
    NULL,
    FALSE,
    TIMESTAMP '2026-03-29 20:50:00',
    TIMESTAMP '2026-03-29 20:50:00'
FROM users u
JOIN lessons l ON l.title = 'Entity relationships and mapping'
WHERE u.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM til_drafts t
      WHERE t.user_id = u.user_id
        AND t.title = 'JPA Mapping Memo'
        AND t.is_deleted = FALSE
  );

INSERT INTO timestamp_notes (
    user_id,
    lesson_id,
    timestamp_second,
    content,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    l.lesson_id,
    315,
    'Separate bean registration timing from dependency injection timing.',
    FALSE,
    TIMESTAMP '2026-03-28 21:05:00',
    TIMESTAMP '2026-03-28 21:05:00'
FROM users u
JOIN lessons l ON l.title = 'Understanding DI and IoC'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM timestamp_notes n
      WHERE n.user_id = u.user_id
        AND n.lesson_id = l.lesson_id
        AND n.timestamp_second = 315
        AND n.is_deleted = FALSE
  );

INSERT INTO timestamp_notes (
    user_id,
    lesson_id,
    timestamp_second,
    content,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    l.lesson_id,
    540,
    'Recheck when the lazy loading proxy gets initialized.',
    FALSE,
    TIMESTAMP '2026-03-29 20:15:00',
    TIMESTAMP '2026-03-29 20:15:00'
FROM users u
JOIN lessons l ON l.title = 'Entity relationships and mapping'
WHERE u.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM timestamp_notes n
      WHERE n.user_id = u.user_id
        AND n.lesson_id = l.lesson_id
        AND n.timestamp_second = 540
        AND n.is_deleted = FALSE
  );

INSERT INTO supplement_recommendations (
    user_id,
    node_id,
    reason,
    priority,
    coverage_percent,
    missing_tag_count,
    status,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    rn.node_id,
    'Additional study is recommended because required tags are still missing.',
    1,
    62.5,
    2,
    'PENDING',
    TIMESTAMP '2026-03-29 22:00:00',
    TIMESTAMP '2026-03-29 22:00:00'
FROM users u
JOIN roadmap_nodes rn ON rn.title = 'HTTP Fundamentals'
JOIN roadmaps r ON r.roadmap_id = rn.roadmap_id
WHERE u.email = 'learner2@devpath.com'
  AND r.title = 'Backend Master Roadmap'
  AND NOT EXISTS (
      SELECT 1
      FROM supplement_recommendations sr
      WHERE sr.user_id = u.user_id
        AND sr.node_id = rn.node_id
  );

INSERT INTO node_clearances (
    user_id,
    node_id,
    clearance_status,
    lesson_completion_rate,
    required_tags_satisfied,
    missing_tag_count,
    lesson_completed,
    quiz_passed,
    assignment_passed,
    proof_eligible,
    cleared_at,
    last_calculated_at,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    rn.node_id,
    'CLEARED',
    100.00,
    TRUE,
    0,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TIMESTAMP '2026-03-28 23:05:00',
    TIMESTAMP '2026-03-28 23:05:00',
    TIMESTAMP '2026-03-28 23:05:00',
    TIMESTAMP '2026-03-28 23:05:00'
FROM users u
JOIN roadmap_nodes rn ON rn.title = 'Java Basics'
JOIN roadmaps r ON r.roadmap_id = rn.roadmap_id
WHERE u.email = 'learner@devpath.com'
  AND r.title = 'Backend Master Roadmap'
  AND NOT EXISTS (
      SELECT 1
      FROM node_clearances nc
      WHERE nc.user_id = u.user_id
        AND nc.node_id = rn.node_id
  );

INSERT INTO node_clearances (
    user_id,
    node_id,
    clearance_status,
    lesson_completion_rate,
    required_tags_satisfied,
    missing_tag_count,
    lesson_completed,
    quiz_passed,
    assignment_passed,
    proof_eligible,
    cleared_at,
    last_calculated_at,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    rn.node_id,
    'NOT_CLEARED',
    45.00,
    FALSE,
    2,
    FALSE,
    FALSE,
    FALSE,
    FALSE,
    NULL,
    TIMESTAMP '2026-03-29 22:05:00',
    TIMESTAMP '2026-03-29 22:05:00',
    TIMESTAMP '2026-03-29 22:05:00'
FROM users u
JOIN roadmap_nodes rn ON rn.title = 'HTTP Fundamentals'
JOIN roadmaps r ON r.roadmap_id = rn.roadmap_id
WHERE u.email = 'learner2@devpath.com'
  AND r.title = 'Backend Master Roadmap'
  AND NOT EXISTS (
      SELECT 1
      FROM node_clearances nc
      WHERE nc.user_id = u.user_id
        AND nc.node_id = rn.node_id
  );

INSERT INTO proof_cards (
    user_id,
    node_id,
    node_clearance_id,
    title,
    description,
    proof_card_status,
    issued_at,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    rn.node_id,
    nc.node_clearance_id,
    'Spring Boot Intro Node Clear',
    'Sample proof card for a learner who completed lessons, quiz, and assignment.',
    'ISSUED',
    TIMESTAMP '2026-03-28 23:10:00',
    TIMESTAMP '2026-03-28 23:10:00',
    TIMESTAMP '2026-03-28 23:10:00'
FROM node_clearances nc
JOIN users u ON u.user_id = nc.user_id
JOIN roadmap_nodes rn ON rn.node_id = nc.node_id
WHERE u.email = 'learner@devpath.com'
  AND nc.clearance_status = 'CLEARED'
  AND NOT EXISTS (
      SELECT 1
      FROM proof_cards pc
      WHERE pc.node_clearance_id = nc.node_clearance_id
  );

INSERT INTO proof_card_tags (
    proof_card_id,
    tag_id,
    skill_evidence_type
)
WITH target_card AS (
    SELECT pc.proof_card_id
    FROM proof_cards pc
    JOIN users u ON u.user_id = pc.user_id
    WHERE u.email = 'learner@devpath.com'
    ORDER BY pc.proof_card_id
    LIMIT 1
),
ranked_tags AS (
    SELECT t.tag_id, ROW_NUMBER() OVER (ORDER BY t.tag_id) AS rn
    FROM tags t
    WHERE t.is_deleted = FALSE
)
SELECT
    c.proof_card_id,
    t.tag_id,
    'VERIFIED'
FROM target_card c
JOIN ranked_tags t ON t.rn = 1
WHERE NOT EXISTS (
    SELECT 1
    FROM proof_card_tags pct
    WHERE pct.proof_card_id = c.proof_card_id
      AND pct.tag_id = t.tag_id
      AND pct.skill_evidence_type = 'VERIFIED'
);

INSERT INTO proof_card_tags (
    proof_card_id,
    tag_id,
    skill_evidence_type
)
WITH target_card AS (
    SELECT pc.proof_card_id
    FROM proof_cards pc
    JOIN users u ON u.user_id = pc.user_id
    WHERE u.email = 'learner@devpath.com'
    ORDER BY pc.proof_card_id
    LIMIT 1
),
ranked_tags AS (
    SELECT t.tag_id, ROW_NUMBER() OVER (ORDER BY t.tag_id) AS rn
    FROM tags t
    WHERE t.is_deleted = FALSE
)
SELECT
    c.proof_card_id,
    t.tag_id,
    'HELD'
FROM target_card c
JOIN ranked_tags t ON t.rn = 2
WHERE NOT EXISTS (
    SELECT 1
    FROM proof_card_tags pct
    WHERE pct.proof_card_id = c.proof_card_id
      AND pct.tag_id = t.tag_id
      AND pct.skill_evidence_type = 'HELD'
);

INSERT INTO certificates (
    proof_card_id,
    certificate_number,
    certificate_status,
    issued_at,
    pdf_file_name,
    pdf_generated_at,
    last_downloaded_at,
    created_at,
    updated_at
)
SELECT
    pc.proof_card_id,
    'CERT-20260328-' || LPAD(pc.proof_card_id::text, 4, '0'),
    'PDF_READY',
    TIMESTAMP '2026-03-28 23:20:00',
    'proof-card-' || pc.proof_card_id::text || '.pdf',
    TIMESTAMP '2026-03-28 23:20:00',
    TIMESTAMP '2026-03-29 09:10:00',
    TIMESTAMP '2026-03-28 23:20:00',
    TIMESTAMP '2026-03-29 09:10:00'
FROM proof_cards pc
JOIN users u ON u.user_id = pc.user_id
WHERE u.email = 'learner@devpath.com'
  AND pc.title = 'Spring Boot Intro Node Clear'
  AND NOT EXISTS (
      SELECT 1
      FROM certificates c
      WHERE c.proof_card_id = pc.proof_card_id
  );

INSERT INTO proof_card_shares (
    proof_card_id,
    share_token,
    share_status,
    expires_at,
    access_count,
    created_at,
    updated_at
)
SELECT
    pc.proof_card_id,
    'proof-share-token-a-20260328',
    'ACTIVE',
    TIMESTAMP '2026-12-31 23:59:59',
    3,
    TIMESTAMP '2026-03-28 23:30:00',
    TIMESTAMP '2026-03-29 10:00:00'
FROM proof_cards pc
JOIN users u ON u.user_id = pc.user_id
WHERE u.email = 'learner@devpath.com'
  AND pc.title = 'Spring Boot Intro Node Clear'
  AND NOT EXISTS (
      SELECT 1
      FROM proof_card_shares ps
      WHERE ps.share_token = 'proof-share-token-a-20260328'
  );

INSERT INTO learning_history_share_links (
    user_id,
    share_token,
    title,
    expires_at,
    access_count,
    is_active,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    'learning-history-token-a-20260328',
    'Learning history share link',
    TIMESTAMP '2026-12-31 23:59:59',
    5,
    TRUE,
    TIMESTAMP '2026-03-28 23:40:00',
    TIMESTAMP '2026-03-29 10:05:00'
FROM users u
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM learning_history_share_links l
      WHERE l.share_token = 'learning-history-token-a-20260328'
  );

INSERT INTO certificate_download_histories (
    certificate_id,
    downloaded_by,
    download_reason,
    downloaded_at
)
SELECT
    c.certificate_id,
    u.user_id,
    'Downloaded for portfolio attachment.',
    TIMESTAMP '2026-03-29 09:10:00'
FROM certificates c
JOIN proof_cards pc ON pc.proof_card_id = c.proof_card_id
JOIN users u ON u.email = 'learner@devpath.com'
WHERE pc.user_id = u.user_id
  AND pc.title = 'Spring Boot Intro Node Clear'
  AND NOT EXISTS (
      SELECT 1
      FROM certificate_download_histories h
      WHERE h.certificate_id = c.certificate_id
        AND h.downloaded_by = u.user_id
        AND h.download_reason = 'Downloaded for portfolio attachment.'
  );

INSERT INTO learning_automation_rules (
    rule_key,
    rule_name,
    description,
    rule_value,
    priority,
    rule_status,
    created_at,
    updated_at
)
SELECT
    'TAG_MATCH_THRESHOLD',
    'Tag match threshold',
    'Defines the minimum required tag coverage for automatic recommendation.',
    '0.80',
    1,
    'ENABLED',
    TIMESTAMP '2026-03-27 10:00:00',
    TIMESTAMP '2026-03-27 10:00:00'
WHERE NOT EXISTS (
    SELECT 1
    FROM learning_automation_rules r
    WHERE r.rule_key = 'TAG_MATCH_THRESHOLD'
);

INSERT INTO learning_automation_rules (
    rule_key,
    rule_name,
    description,
    rule_value,
    priority,
    rule_status,
    created_at,
    updated_at
)
SELECT
    'NODE_CLEARANCE_REQUIRES_COMPLETION',
    'Node clearance completion rule',
    'Requires full lesson completion and evaluation pass for node clearance.',
    'LESSON_100_AND_EVALUATION_PASS',
    2,
    'ENABLED',
    TIMESTAMP '2026-03-27 10:01:00',
    TIMESTAMP '2026-03-27 10:01:00'
WHERE NOT EXISTS (
    SELECT 1
    FROM learning_automation_rules r
    WHERE r.rule_key = 'NODE_CLEARANCE_REQUIRES_COMPLETION'
);

INSERT INTO learning_automation_rules (
    rule_key,
    rule_name,
    description,
    rule_value,
    priority,
    rule_status,
    created_at,
    updated_at
)
SELECT
    'SUPPLEMENT_RECOMMENDATION_PRIORITY',
    'Supplement recommendation priority',
    'Ranks supplement recommendations by missing tag count and coverage gap.',
    'MISSING_TAG_COUNT_DESC',
    3,
    'ENABLED',
    TIMESTAMP '2026-03-27 10:02:00',
    TIMESTAMP '2026-03-27 10:02:00'
WHERE NOT EXISTS (
    SELECT 1
    FROM learning_automation_rules r
    WHERE r.rule_key = 'SUPPLEMENT_RECOMMENDATION_PRIORITY'
);

INSERT INTO learning_automation_rules (
    rule_key,
    rule_name,
    description,
    rule_value,
    priority,
    rule_status,
    created_at,
    updated_at
)
SELECT
    'PROOF_CARD_AUTO_ISSUE',
    'Proof card auto issue rule',
    'Issues proof cards only for proof-eligible node clearances.',
    'PROOF_ELIGIBLE_ONLY',
    4,
    'ENABLED',
    TIMESTAMP '2026-03-27 10:03:00',
    TIMESTAMP '2026-03-27 10:03:00'
WHERE NOT EXISTS (
    SELECT 1
    FROM learning_automation_rules r
    WHERE r.rule_key = 'PROOF_CARD_AUTO_ISSUE'
);

INSERT INTO learning_metric_samples (
    course_id,
    metric_type,
    metric_label,
    metric_value,
    sampled_at,
    created_at
)
SELECT
    c.course_id,
    'COMPLETION_RATE',
    'Completion rate',
    78.4,
    TIMESTAMP '2026-03-30 23:00:00',
    TIMESTAMP '2026-03-30 23:00:00'
FROM courses c
WHERE c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1
      FROM learning_metric_samples s
      WHERE s.course_id = c.course_id
        AND s.metric_type = 'COMPLETION_RATE'
        AND s.metric_label = 'Completion rate'
        AND s.sampled_at = TIMESTAMP '2026-03-30 23:00:00'
  );

INSERT INTO learning_metric_samples (
    course_id,
    metric_type,
    metric_label,
    metric_value,
    sampled_at,
    created_at
)
SELECT
    c.course_id,
    'AVERAGE_WATCH_TIME',
    'Average watch time',
    1420.0,
    TIMESTAMP '2026-03-30 23:00:00',
    TIMESTAMP '2026-03-30 23:00:00'
FROM courses c
WHERE c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1
      FROM learning_metric_samples s
      WHERE s.course_id = c.course_id
        AND s.metric_type = 'AVERAGE_WATCH_TIME'
        AND s.metric_label = 'Average watch time'
        AND s.sampled_at = TIMESTAMP '2026-03-30 23:00:00'
  );

INSERT INTO learning_metric_samples (
    course_id,
    metric_type,
    metric_label,
    metric_value,
    sampled_at,
    created_at
)
SELECT
    c.course_id,
    'QUIZ_STATS',
    'Average quiz score',
    65.0,
    TIMESTAMP '2026-03-30 23:00:00',
    TIMESTAMP '2026-03-30 23:00:00'
FROM courses c
WHERE c.title = 'JPA Practical Design'
  AND NOT EXISTS (
      SELECT 1
      FROM learning_metric_samples s
      WHERE s.course_id = c.course_id
        AND s.metric_type = 'QUIZ_STATS'
        AND s.metric_label = 'Average quiz score'
        AND s.sampled_at = TIMESTAMP '2026-03-30 23:00:00'
  );

INSERT INTO learning_metric_samples (
    course_id,
    metric_type,
    metric_label,
    metric_value,
    sampled_at,
    created_at
)
SELECT
    c.course_id,
    'ASSIGNMENT_STATS',
    'Average assignment score',
    73.5,
    TIMESTAMP '2026-03-30 23:00:00',
    TIMESTAMP '2026-03-30 23:00:00'
FROM courses c
WHERE c.title = 'JPA Practical Design'
  AND NOT EXISTS (
      SELECT 1
      FROM learning_metric_samples s
      WHERE s.course_id = c.course_id
        AND s.metric_type = 'ASSIGNMENT_STATS'
        AND s.metric_label = 'Average assignment score'
        AND s.sampled_at = TIMESTAMP '2026-03-30 23:00:00'
  );

INSERT INTO learning_metric_samples (
    course_id,
    metric_type,
    metric_label,
    metric_value,
    sampled_at,
    created_at
)
SELECT
    c.course_id,
    'WEAK_POINT',
    'Weak point ratio',
    31.2,
    TIMESTAMP '2026-03-30 23:00:00',
    TIMESTAMP '2026-03-30 23:00:00'
FROM courses c
WHERE c.title = 'JPA Practical Design'
  AND NOT EXISTS (
      SELECT 1
      FROM learning_metric_samples s
      WHERE s.course_id = c.course_id
        AND s.metric_type = 'WEAK_POINT'
        AND s.metric_label = 'Weak point ratio'
        AND s.sampled_at = TIMESTAMP '2026-03-30 23:00:00'
  );

-- ========================================
-- A-CASE NODE CLEARANCE BRANCHES
-- ========================================
INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'A_CASE_TAG_JAVA', 'BACKEND', FALSE, FALSE
WHERE NOT EXISTS (
    SELECT 1
    FROM tags
    WHERE name = 'A_CASE_TAG_JAVA'
);

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'A_CASE_TAG_SPRING', 'BACKEND', FALSE, FALSE
WHERE NOT EXISTS (
    SELECT 1
    FROM tags
    WHERE name = 'A_CASE_TAG_SPRING'
);

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'A_CASE_TAG_DB', 'BACKEND', FALSE, FALSE
WHERE NOT EXISTS (
    SELECT 1
    FROM tags
    WHERE name = 'A_CASE_TAG_DB'
);

UPDATE tags
SET is_official = FALSE
WHERE name IN ('A_CASE_TAG_JAVA', 'A_CASE_TAG_SPRING', 'A_CASE_TAG_DB');

INSERT INTO user_tech_stacks (user_id, tag_id)
SELECT u.user_id, t.tag_id
FROM users u
JOIN tags t ON t.name = 'A_CASE_TAG_JAVA'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM user_tech_stacks uts
      WHERE uts.user_id = u.user_id
        AND uts.tag_id = t.tag_id
  );

INSERT INTO user_tech_stacks (user_id, tag_id)
SELECT u.user_id, t.tag_id
FROM users u
JOIN tags t ON t.name = 'A_CASE_TAG_SPRING'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM user_tech_stacks uts
      WHERE uts.user_id = u.user_id
        AND uts.tag_id = t.tag_id
  );

INSERT INTO user_tech_stacks (user_id, tag_id)
SELECT u.user_id, t.tag_id
FROM users u
JOIN tags t ON t.name = 'A_CASE_TAG_DB'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM user_tech_stacks uts
      WHERE uts.user_id = u.user_id
        AND uts.tag_id = t.tag_id
  );

INSERT INTO user_tech_stacks (user_id, tag_id)
SELECT u.user_id, t.tag_id
FROM users u
JOIN tags t ON t.name = 'A_CASE_TAG_JAVA'
WHERE u.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM user_tech_stacks uts
      WHERE uts.user_id = u.user_id
        AND uts.tag_id = t.tag_id
  );

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order)
WITH target_roadmap AS (
    SELECT r.roadmap_id
    FROM roadmaps r
    WHERE COALESCE(r.is_deleted, FALSE) = FALSE
    ORDER BY COALESCE(r.is_official, FALSE) DESC, r.roadmap_id ASC
    LIMIT 1
)
SELECT
    tr.roadmap_id,
    '[A-CASE-A] Full pass',
    'Node for the full-pass clearance branch.',
    'CONCEPT',
    901
FROM target_roadmap tr
WHERE NOT EXISTS (
    SELECT 1
    FROM roadmap_nodes rn
    WHERE rn.title = '[A-CASE-A] Full pass'
);

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order)
WITH target_roadmap AS (
    SELECT r.roadmap_id
    FROM roadmaps r
    WHERE COALESCE(r.is_deleted, FALSE) = FALSE
    ORDER BY COALESCE(r.is_official, FALSE) DESC, r.roadmap_id ASC
    LIMIT 1
)
SELECT
    tr.roadmap_id,
    '[A-CASE-B] Missing tag',
    'Node for the missing-tag clearance branch.',
    'CONCEPT',
    902
FROM target_roadmap tr
WHERE NOT EXISTS (
    SELECT 1
    FROM roadmap_nodes rn
    WHERE rn.title = '[A-CASE-B] Missing tag'
);

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order)
WITH target_roadmap AS (
    SELECT r.roadmap_id
    FROM roadmaps r
    WHERE COALESCE(r.is_deleted, FALSE) = FALSE
    ORDER BY COALESCE(r.is_official, FALSE) DESC, r.roadmap_id ASC
    LIMIT 1
)
SELECT
    tr.roadmap_id,
    '[A-CASE-C] Quiz failed',
    'Node for the quiz-failed clearance branch.',
    'CONCEPT',
    903
FROM target_roadmap tr
WHERE NOT EXISTS (
    SELECT 1
    FROM roadmap_nodes rn
    WHERE rn.title = '[A-CASE-C] Quiz failed'
);

INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id
FROM roadmap_nodes rn
JOIN tags t ON t.name = 'A_CASE_TAG_JAVA'
WHERE rn.title = '[A-CASE-A] Full pass'
  AND NOT EXISTS (
      SELECT 1
      FROM node_required_tags nrt
      WHERE nrt.node_id = rn.node_id
        AND nrt.tag_id = t.tag_id
  );

INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id
FROM roadmap_nodes rn
JOIN tags t ON t.name = 'A_CASE_TAG_SPRING'
WHERE rn.title = '[A-CASE-A] Full pass'
  AND NOT EXISTS (
      SELECT 1
      FROM node_required_tags nrt
      WHERE nrt.node_id = rn.node_id
        AND nrt.tag_id = t.tag_id
  );

INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id
FROM roadmap_nodes rn
JOIN tags t ON t.name = 'A_CASE_TAG_JAVA'
WHERE rn.title = '[A-CASE-B] Missing tag'
  AND NOT EXISTS (
      SELECT 1
      FROM node_required_tags nrt
      WHERE nrt.node_id = rn.node_id
        AND nrt.tag_id = t.tag_id
  );

INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id
FROM roadmap_nodes rn
JOIN tags t ON t.name = 'A_CASE_TAG_DB'
WHERE rn.title = '[A-CASE-B] Missing tag'
  AND NOT EXISTS (
      SELECT 1
      FROM node_required_tags nrt
      WHERE nrt.node_id = rn.node_id
        AND nrt.tag_id = t.tag_id
  );

INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id
FROM roadmap_nodes rn
JOIN tags t ON t.name = 'A_CASE_TAG_JAVA'
WHERE rn.title = '[A-CASE-C] Quiz failed'
  AND NOT EXISTS (
      SELECT 1
      FROM node_required_tags nrt
      WHERE nrt.node_id = rn.node_id
        AND nrt.tag_id = t.tag_id
  );

INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id
FROM roadmap_nodes rn
JOIN tags t ON t.name = 'A_CASE_TAG_SPRING'
WHERE rn.title = '[A-CASE-C] Quiz failed'
  AND NOT EXISTS (
      SELECT 1
      FROM node_required_tags nrt
      WHERE nrt.node_id = rn.node_id
        AND nrt.tag_id = t.tag_id
  );

INSERT INTO node_completion_rules (node_id, criteria_type, criteria_value, created_at, updated_at)
SELECT
    rn.node_id,
    'QUIZ_AND_ASSIGNMENT',
    'LESSON_100_AND_REQUIRED_TAGS_AND_QUIZ_AND_ASSIGNMENT',
    TIMESTAMP '2026-03-30 10:00:00',
    TIMESTAMP '2026-03-30 10:00:00'
FROM roadmap_nodes rn
WHERE rn.title = '[A-CASE-A] Full pass'
  AND NOT EXISTS (
      SELECT 1
      FROM node_completion_rules ncr
      WHERE ncr.node_id = rn.node_id
  );

INSERT INTO node_completion_rules (node_id, criteria_type, criteria_value, created_at, updated_at)
SELECT
    rn.node_id,
    'QUIZ_AND_ASSIGNMENT',
    'LESSON_100_AND_REQUIRED_TAGS_AND_QUIZ_AND_ASSIGNMENT',
    TIMESTAMP '2026-03-30 10:01:00',
    TIMESTAMP '2026-03-30 10:01:00'
FROM roadmap_nodes rn
WHERE rn.title = '[A-CASE-B] Missing tag'
  AND NOT EXISTS (
      SELECT 1
      FROM node_completion_rules ncr
      WHERE ncr.node_id = rn.node_id
  );

INSERT INTO node_completion_rules (node_id, criteria_type, criteria_value, created_at, updated_at)
SELECT
    rn.node_id,
    'QUIZ_AND_ASSIGNMENT',
    'LESSON_100_AND_REQUIRED_TAGS_AND_QUIZ_AND_ASSIGNMENT',
    TIMESTAMP '2026-03-30 10:02:00',
    TIMESTAMP '2026-03-30 10:02:00'
FROM roadmap_nodes rn
WHERE rn.title = '[A-CASE-C] Quiz failed'
  AND NOT EXISTS (
      SELECT 1
      FROM node_completion_rules ncr
      WHERE ncr.node_id = rn.node_id
  );

INSERT INTO courses (
    instructor_id,
    title,
    subtitle,
    description,
    thumbnail_url,
    price,
    original_price,
    currency,
    difficulty_level,
    language,
    has_certificate,
    status,
    published_at,
    duration_seconds
)
SELECT
    iu.user_id,
    '[A-CASE-A] Node Clearance Course',
    'Case A only course',
    'Course used to verify lesson completion, tags, quiz, and assignment pass.',
    'https://images.unsplash.com/photo-1498050108023-c5249f4df085?auto=format&fit=crop&w=1200&q=80',
    0,
    0,
    'KRW',
    'BEGINNER',
    'ko',
    TRUE,
    'PUBLISHED',
    TIMESTAMP '2026-03-30 11:00:00',
    900
FROM users iu
WHERE iu.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM courses c
      WHERE c.title = '[A-CASE-A] Node Clearance Course'
  );

INSERT INTO courses (
    instructor_id,
    title,
    subtitle,
    description,
    thumbnail_url,
    price,
    original_price,
    currency,
    difficulty_level,
    language,
    has_certificate,
    status,
    published_at,
    duration_seconds
)
SELECT
    iu.user_id,
    '[A-CASE-B] Tag Missing Course',
    'Case B only course',
    'Course used to verify the missing required tag branch.',
    'https://images.unsplash.com/photo-1504639725590-34d0984388bd?auto=format&fit=crop&w=1200&q=80',
    0,
    0,
    'KRW',
    'BEGINNER',
    'ko',
    TRUE,
    'PUBLISHED',
    TIMESTAMP '2026-03-30 11:05:00',
    900
FROM users iu
WHERE iu.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM courses c
      WHERE c.title = '[A-CASE-B] Tag Missing Course'
  );

INSERT INTO courses (
    instructor_id,
    title,
    subtitle,
    description,
    thumbnail_url,
    price,
    original_price,
    currency,
    difficulty_level,
    language,
    has_certificate,
    status,
    published_at,
    duration_seconds
)
SELECT
    iu.user_id,
    '[A-CASE-C] Quiz Fail Course',
    'Case C only course',
    'Course used to verify the quiz failed branch.',
    'https://images.unsplash.com/photo-1515879218367-8466d910aaa4?auto=format&fit=crop&w=1200&q=80',
    0,
    0,
    'KRW',
    'BEGINNER',
    'ko',
    TRUE,
    'PUBLISHED',
    TIMESTAMP '2026-03-30 11:10:00',
    900
FROM users iu
WHERE iu.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM courses c
      WHERE c.title = '[A-CASE-C] Quiz Fail Course'
  );

UPDATE courses
SET thumbnail_url = 'https://images.unsplash.com/photo-1517694712202-14dd9538aa97?auto=format&fit=crop&w=1200&q=80'
WHERE title = 'Spring Boot Intro';

UPDATE courses
SET duration_seconds = 55200,
    difficulty_level = 'INTERMEDIATE',
    published_at = TIMESTAMP '2026-01-20 09:00:00'
WHERE title = 'Spring Boot Intro';

UPDATE courses
SET thumbnail_url = 'https://images.unsplash.com/photo-1555066931-4365d14bab8c?auto=format&fit=crop&w=1200&q=80'
WHERE title = 'JPA Practical Design';

UPDATE courses
SET thumbnail_url = 'https://images.unsplash.com/photo-1460925895917-afdab827c52f?auto=format&fit=crop&w=1200&q=80'
WHERE title = 'React Dashboard Sprint';

UPDATE courses
SET published_at = TIMESTAMP '2026-01-29 13:00:00'
WHERE title = '스프링 부트 3.0 완전 정복';

UPDATE courses
SET published_at = TIMESTAMP '2026-01-30 11:00:00'
WHERE title = '제목 없는 강의 (초안)';

UPDATE courses
SET status = 'DRAFT',
    has_certificate = FALSE,
    duration_seconds = 0
WHERE title = '제목 없는 강의 (초안)';

UPDATE courses
SET thumbnail_url = 'https://images.unsplash.com/photo-1498050108023-c5249f4df085?auto=format&fit=crop&w=1200&q=80'
WHERE title = '[A-CASE-A] Node Clearance Course';

UPDATE courses
SET thumbnail_url = 'https://images.unsplash.com/photo-1504639725590-34d0984388bd?auto=format&fit=crop&w=1200&q=80'
WHERE title = '[A-CASE-B] Tag Missing Course';

UPDATE courses
SET thumbnail_url = 'https://images.unsplash.com/photo-1515879218367-8466d910aaa4?auto=format&fit=crop&w=1200&q=80'
WHERE title = '[A-CASE-C] Quiz Fail Course';

INSERT INTO course_tag_maps (course_id, tag_id, proficiency_level)
SELECT c.course_id, t.tag_id, 3
FROM courses c, tags t
WHERE c.title = '[A-CASE-A] Node Clearance Course'
  AND t.name = 'A_CASE_TAG_JAVA'
  AND NOT EXISTS (
      SELECT 1
      FROM course_tag_maps ctm
      WHERE ctm.course_id = c.course_id
        AND ctm.tag_id = t.tag_id
  );

INSERT INTO course_tag_maps (course_id, tag_id, proficiency_level)
SELECT c.course_id, t.tag_id, 3
FROM courses c, tags t
WHERE c.title = '[A-CASE-A] Node Clearance Course'
  AND t.name = 'A_CASE_TAG_SPRING'
  AND NOT EXISTS (
      SELECT 1
      FROM course_tag_maps ctm
      WHERE ctm.course_id = c.course_id
        AND ctm.tag_id = t.tag_id
  );

INSERT INTO course_tag_maps (course_id, tag_id, proficiency_level)
SELECT c.course_id, t.tag_id, 3
FROM courses c, tags t
WHERE c.title = '[A-CASE-B] Tag Missing Course'
  AND t.name = 'A_CASE_TAG_JAVA'
  AND NOT EXISTS (
      SELECT 1
      FROM course_tag_maps ctm
      WHERE ctm.course_id = c.course_id
        AND ctm.tag_id = t.tag_id
  );

INSERT INTO course_tag_maps (course_id, tag_id, proficiency_level)
SELECT c.course_id, t.tag_id, 3
FROM courses c, tags t
WHERE c.title = '[A-CASE-C] Quiz Fail Course'
  AND t.name = 'A_CASE_TAG_JAVA'
  AND NOT EXISTS (
      SELECT 1
      FROM course_tag_maps ctm
      WHERE ctm.course_id = c.course_id
        AND ctm.tag_id = t.tag_id
  );

INSERT INTO course_tag_maps (course_id, tag_id, proficiency_level)
SELECT c.course_id, t.tag_id, 3
FROM courses c, tags t
WHERE c.title = '[A-CASE-C] Quiz Fail Course'
  AND t.name = 'A_CASE_TAG_SPRING'
  AND NOT EXISTS (
      SELECT 1
      FROM course_tag_maps ctm
      WHERE ctm.course_id = c.course_id
        AND ctm.tag_id = t.tag_id
  );

INSERT INTO course_sections (course_id, title, description, sort_order, is_published)
SELECT
    c.course_id,
    'SECTION 1',
    'Case A section',
    1,
    TRUE
FROM courses c
WHERE c.title = '[A-CASE-A] Node Clearance Course'
  AND NOT EXISTS (
      SELECT 1
      FROM course_sections cs
      WHERE cs.course_id = c.course_id
        AND cs.title = 'SECTION 1'
  );

INSERT INTO course_sections (course_id, title, description, sort_order, is_published)
SELECT
    c.course_id,
    'SECTION 1',
    'Case B section',
    1,
    TRUE
FROM courses c
WHERE c.title = '[A-CASE-B] Tag Missing Course'
  AND NOT EXISTS (
      SELECT 1
      FROM course_sections cs
      WHERE cs.course_id = c.course_id
        AND cs.title = 'SECTION 1'
  );

INSERT INTO course_sections (course_id, title, description, sort_order, is_published)
SELECT
    c.course_id,
    'SECTION 1',
    'Case C section',
    1,
    TRUE
FROM courses c
WHERE c.title = '[A-CASE-C] Quiz Fail Course'
  AND NOT EXISTS (
      SELECT 1
      FROM course_sections cs
      WHERE cs.course_id = c.course_id
        AND cs.title = 'SECTION 1'
  );

INSERT INTO lessons (
    section_id,
    title,
    description,
    lesson_type,
    duration_seconds,
    is_preview,
    is_published,
    sort_order
)
SELECT
    cs.section_id,
    '[A-CASE-A] LESSON 1',
    'Case A lesson',
    'VIDEO',
    900,
    FALSE,
    TRUE,
    1
FROM course_sections cs
JOIN courses c ON c.course_id = cs.course_id
WHERE c.title = '[A-CASE-A] Node Clearance Course'
  AND NOT EXISTS (
      SELECT 1
      FROM lessons l
      WHERE l.section_id = cs.section_id
        AND l.title = '[A-CASE-A] LESSON 1'
  );

INSERT INTO lessons (
    section_id,
    title,
    description,
    lesson_type,
    duration_seconds,
    is_preview,
    is_published,
    sort_order
)
SELECT
    cs.section_id,
    '[A-CASE-B] LESSON 1',
    'Case B lesson',
    'VIDEO',
    900,
    FALSE,
    TRUE,
    1
FROM course_sections cs
JOIN courses c ON c.course_id = cs.course_id
WHERE c.title = '[A-CASE-B] Tag Missing Course'
  AND NOT EXISTS (
      SELECT 1
      FROM lessons l
      WHERE l.section_id = cs.section_id
        AND l.title = '[A-CASE-B] LESSON 1'
  );

INSERT INTO lessons (
    section_id,
    title,
    description,
    lesson_type,
    duration_seconds,
    is_preview,
    is_published,
    sort_order
)
SELECT
    cs.section_id,
    '[A-CASE-C] LESSON 1',
    'Case C lesson',
    'VIDEO',
    900,
    FALSE,
    TRUE,
    1
FROM course_sections cs
JOIN courses c ON c.course_id = cs.course_id
WHERE c.title = '[A-CASE-C] Quiz Fail Course'
  AND NOT EXISTS (
      SELECT 1
      FROM lessons l
      WHERE l.section_id = cs.section_id
        AND l.title = '[A-CASE-C] LESSON 1'
  );

INSERT INTO course_node_mappings (course_id, node_id, created_at)
SELECT
    c.course_id,
    rn.node_id,
    TIMESTAMP '2026-03-30 11:30:00'
FROM courses c
JOIN roadmap_nodes rn ON rn.title = '[A-CASE-A] Full pass'
WHERE c.title = '[A-CASE-A] Node Clearance Course'
  AND NOT EXISTS (
      SELECT 1
      FROM course_node_mappings cnm
      WHERE cnm.course_id = c.course_id
        AND cnm.node_id = rn.node_id
  );

INSERT INTO course_node_mappings (course_id, node_id, created_at)
SELECT
    c.course_id,
    rn.node_id,
    TIMESTAMP '2026-03-30 11:31:00'
FROM courses c
JOIN roadmap_nodes rn ON rn.title = '[A-CASE-B] Missing tag'
WHERE c.title = '[A-CASE-B] Tag Missing Course'
  AND NOT EXISTS (
      SELECT 1
      FROM course_node_mappings cnm
      WHERE cnm.course_id = c.course_id
        AND cnm.node_id = rn.node_id
  );

INSERT INTO course_node_mappings (course_id, node_id, created_at)
SELECT
    c.course_id,
    rn.node_id,
    TIMESTAMP '2026-03-30 11:32:00'
FROM courses c
JOIN roadmap_nodes rn ON rn.title = '[A-CASE-C] Quiz failed'
WHERE c.title = '[A-CASE-C] Quiz Fail Course'
  AND NOT EXISTS (
      SELECT 1
      FROM course_node_mappings cnm
      WHERE cnm.course_id = c.course_id
        AND cnm.node_id = rn.node_id
  );

INSERT INTO quizzes (
    node_id,
    title,
    description,
    quiz_type,
    total_score,
    is_published,
    is_active,
    expose_answer,
    expose_explanation,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    rn.node_id,
    '[A-CASE-A] QUIZ',
    'Quiz for the full-pass branch.',
    'MANUAL',
    100,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    FALSE,
    TIMESTAMP '2026-03-30 12:00:00',
    TIMESTAMP '2026-03-30 12:00:00'
FROM roadmap_nodes rn
WHERE rn.title = '[A-CASE-A] Full pass'
  AND NOT EXISTS (
      SELECT 1
      FROM quizzes q
      WHERE q.title = '[A-CASE-A] QUIZ'
  );

INSERT INTO quiz_questions (
    quiz_id,
    question_type,
    question_text,
    explanation,
    points,
    display_order,
    source_timestamp,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    q.quiz_id,
    'MULTIPLE_CHOICE',
    'What must be true for the A-case node to clear?',
    'Lessons, tags, quiz, and assignment must all pass.',
    100,
    1,
    NULL,
    FALSE,
    TIMESTAMP '2026-03-30 12:00:00',
    TIMESTAMP '2026-03-30 12:00:00'
FROM quizzes q
JOIN roadmap_nodes rn ON rn.node_id = q.node_id
WHERE q.title = '[A-CASE-A] QUIZ'
  AND rn.title = '[A-CASE-A] Full pass'
  AND NOT EXISTS (
      SELECT 1
      FROM quiz_questions qq
      WHERE qq.quiz_id = q.quiz_id
        AND qq.display_order = 1
  );

INSERT INTO quiz_question_options (
    question_id,
    option_text,
    is_correct,
    display_order,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    qq.question_id,
    option_seed.option_text,
    option_seed.is_correct,
    option_seed.display_order,
    FALSE,
    TIMESTAMP '2026-03-30 12:00:00',
    TIMESTAMP '2026-03-30 12:00:00'
FROM quiz_questions qq
JOIN quizzes q ON q.quiz_id = qq.quiz_id
JOIN (
    SELECT 'Only lessons' AS option_text, FALSE AS is_correct, 1 AS display_order
    UNION ALL
    SELECT 'Lessons and tags', FALSE, 2
    UNION ALL
    SELECT 'Lessons, tags, quiz, and assignment', TRUE, 3
    UNION ALL
    SELECT 'Only quiz and assignment', FALSE, 4
) option_seed ON TRUE
WHERE q.title = '[A-CASE-A] QUIZ'
  AND qq.display_order = 1
  AND NOT EXISTS (
      SELECT 1
      FROM quiz_question_options qo
      WHERE qo.question_id = qq.question_id
  );

INSERT INTO quizzes (
    node_id,
    title,
    description,
    quiz_type,
    total_score,
    is_published,
    is_active,
    expose_answer,
    expose_explanation,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    rn.node_id,
    '[A-CASE-B] QUIZ',
    'Quiz for the missing-tag branch.',
    'MANUAL',
    100,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    FALSE,
    TIMESTAMP '2026-03-30 12:05:00',
    TIMESTAMP '2026-03-30 12:05:00'
FROM roadmap_nodes rn
WHERE rn.title = '[A-CASE-B] Missing tag'
  AND NOT EXISTS (
      SELECT 1
      FROM quizzes q
      WHERE q.title = '[A-CASE-B] QUIZ'
  );

INSERT INTO quiz_questions (
    quiz_id,
    question_type,
    question_text,
    explanation,
    points,
    display_order,
    source_timestamp,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    q.quiz_id,
    'MULTIPLE_CHOICE',
    'Why should the B-case node remain uncleared?',
    'A required tag is still missing.',
    100,
    1,
    NULL,
    FALSE,
    TIMESTAMP '2026-03-30 12:05:00',
    TIMESTAMP '2026-03-30 12:05:00'
FROM quizzes q
JOIN roadmap_nodes rn ON rn.node_id = q.node_id
WHERE q.title = '[A-CASE-B] QUIZ'
  AND rn.title = '[A-CASE-B] Missing tag'
  AND NOT EXISTS (
      SELECT 1
      FROM quiz_questions qq
      WHERE qq.quiz_id = q.quiz_id
        AND qq.display_order = 1
  );

INSERT INTO quiz_question_options (
    question_id,
    option_text,
    is_correct,
    display_order,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    qq.question_id,
    option_seed.option_text,
    option_seed.is_correct,
    option_seed.display_order,
    FALSE,
    TIMESTAMP '2026-03-30 12:05:00',
    TIMESTAMP '2026-03-30 12:05:00'
FROM quiz_questions qq
JOIN quizzes q ON q.quiz_id = qq.quiz_id
JOIN (
    SELECT 'No lessons were completed' AS option_text, FALSE AS is_correct, 1 AS display_order
    UNION ALL
    SELECT 'A required tag is missing', TRUE, 2
    UNION ALL
    SELECT 'The assignment is absent', FALSE, 3
    UNION ALL
    SELECT 'The node has no course', FALSE, 4
) option_seed ON TRUE
WHERE q.title = '[A-CASE-B] QUIZ'
  AND qq.display_order = 1
  AND NOT EXISTS (
      SELECT 1
      FROM quiz_question_options qo
      WHERE qo.question_id = qq.question_id
  );

INSERT INTO quizzes (
    node_id,
    title,
    description,
    quiz_type,
    total_score,
    is_published,
    is_active,
    expose_answer,
    expose_explanation,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    rn.node_id,
    '[A-CASE-C] QUIZ',
    'Quiz for the quiz-failed branch.',
    'MANUAL',
    100,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    FALSE,
    TIMESTAMP '2026-03-30 12:10:00',
    TIMESTAMP '2026-03-30 12:10:00'
FROM roadmap_nodes rn
WHERE rn.title = '[A-CASE-C] Quiz failed'
  AND NOT EXISTS (
      SELECT 1
      FROM quizzes q
      WHERE q.title = '[A-CASE-C] QUIZ'
  );

INSERT INTO quiz_questions (
    quiz_id,
    question_type,
    question_text,
    explanation,
    points,
    display_order,
    source_timestamp,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    q.quiz_id,
    'MULTIPLE_CHOICE',
    'Why should the C-case node remain uncleared?',
    'The quiz was failed even though the tags and assignment passed.',
    100,
    1,
    NULL,
    FALSE,
    TIMESTAMP '2026-03-30 12:10:00',
    TIMESTAMP '2026-03-30 12:10:00'
FROM quizzes q
JOIN roadmap_nodes rn ON rn.node_id = q.node_id
WHERE q.title = '[A-CASE-C] QUIZ'
  AND rn.title = '[A-CASE-C] Quiz failed'
  AND NOT EXISTS (
      SELECT 1
      FROM quiz_questions qq
      WHERE qq.quiz_id = q.quiz_id
        AND qq.display_order = 1
  );

INSERT INTO quiz_question_options (
    question_id,
    option_text,
    is_correct,
    display_order,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    qq.question_id,
    option_seed.option_text,
    option_seed.is_correct,
    option_seed.display_order,
    FALSE,
    TIMESTAMP '2026-03-30 12:10:00',
    TIMESTAMP '2026-03-30 12:10:00'
FROM quiz_questions qq
JOIN quizzes q ON q.quiz_id = qq.quiz_id
JOIN (
    SELECT 'A tag is missing' AS option_text, FALSE AS is_correct, 1 AS display_order
    UNION ALL
    SELECT 'The lesson is incomplete', FALSE, 2
    UNION ALL
    SELECT 'The quiz failed', TRUE, 3
    UNION ALL
    SELECT 'No assignment exists', FALSE, 4
) option_seed ON TRUE
WHERE q.title = '[A-CASE-C] QUIZ'
  AND qq.display_order = 1
  AND NOT EXISTS (
      SELECT 1
      FROM quiz_question_options qo
      WHERE qo.question_id = qq.question_id
  );

INSERT INTO assignments (
    node_id,
    title,
    description,
    submission_type,
    due_at,
    allowed_file_formats,
    readme_required,
    test_required,
    lint_required,
    submission_rule_description,
    total_score,
    is_published,
    is_active,
    allow_late_submission,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    rn.node_id,
    '[A-CASE-A] ASSIGNMENT',
    'Assignment for the full-pass branch.',
    'MULTIPLE',
    TIMESTAMP '2026-12-31 23:59:59',
    'zip,pdf',
    TRUE,
    TRUE,
    TRUE,
    'README, tests, lint, and file format must all pass.',
    100,
    TRUE,
    TRUE,
    FALSE,
    FALSE,
    TIMESTAMP '2026-03-30 12:20:00',
    TIMESTAMP '2026-03-30 12:20:00'
FROM roadmap_nodes rn
WHERE rn.title = '[A-CASE-A] Full pass'
  AND NOT EXISTS (
      SELECT 1
      FROM assignments a
      WHERE a.title = '[A-CASE-A] ASSIGNMENT'
  );

INSERT INTO assignments (
    node_id,
    title,
    description,
    submission_type,
    due_at,
    allowed_file_formats,
    readme_required,
    test_required,
    lint_required,
    submission_rule_description,
    total_score,
    is_published,
    is_active,
    allow_late_submission,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    rn.node_id,
    '[A-CASE-B] ASSIGNMENT',
    'Assignment for the missing-tag branch.',
    'MULTIPLE',
    TIMESTAMP '2026-12-31 23:59:59',
    'zip,pdf',
    TRUE,
    TRUE,
    TRUE,
    'README, tests, lint, and file format must all pass.',
    100,
    TRUE,
    TRUE,
    FALSE,
    FALSE,
    TIMESTAMP '2026-03-30 12:25:00',
    TIMESTAMP '2026-03-30 12:25:00'
FROM roadmap_nodes rn
WHERE rn.title = '[A-CASE-B] Missing tag'
  AND NOT EXISTS (
      SELECT 1
      FROM assignments a
      WHERE a.title = '[A-CASE-B] ASSIGNMENT'
  );

INSERT INTO assignments (
    node_id,
    title,
    description,
    submission_type,
    due_at,
    allowed_file_formats,
    readme_required,
    test_required,
    lint_required,
    submission_rule_description,
    total_score,
    is_published,
    is_active,
    allow_late_submission,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    rn.node_id,
    '[A-CASE-C] ASSIGNMENT',
    'Assignment for the quiz-failed branch.',
    'MULTIPLE',
    TIMESTAMP '2026-12-31 23:59:59',
    'zip,pdf',
    TRUE,
    TRUE,
    TRUE,
    'README, tests, lint, and file format must all pass.',
    100,
    TRUE,
    TRUE,
    FALSE,
    FALSE,
    TIMESTAMP '2026-03-30 12:30:00',
    TIMESTAMP '2026-03-30 12:30:00'
FROM roadmap_nodes rn
WHERE rn.title = '[A-CASE-C] Quiz failed'
  AND NOT EXISTS (
      SELECT 1
      FROM assignments a
      WHERE a.title = '[A-CASE-C] ASSIGNMENT'
  );

INSERT INTO lesson_progress (
    user_id,
    lesson_id,
    progress_percent,
    progress_seconds,
    default_playback_rate,
    is_pip_enabled,
    is_completed,
    last_watched_at,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    l.lesson_id,
    100,
    900,
    1.25,
    TRUE,
    TRUE,
    TIMESTAMP '2026-03-30 13:00:00',
    TIMESTAMP '2026-03-30 13:00:00',
    TIMESTAMP '2026-03-30 13:00:00'
FROM users u
JOIN lessons l ON l.title = '[A-CASE-A] LESSON 1'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM lesson_progress lp
      WHERE lp.user_id = u.user_id
        AND lp.lesson_id = l.lesson_id
  );

INSERT INTO lesson_progress (
    user_id,
    lesson_id,
    progress_percent,
    progress_seconds,
    default_playback_rate,
    is_pip_enabled,
    is_completed,
    last_watched_at,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    l.lesson_id,
    100,
    900,
    1.00,
    FALSE,
    TRUE,
    TIMESTAMP '2026-03-30 13:05:00',
    TIMESTAMP '2026-03-30 13:05:00',
    TIMESTAMP '2026-03-30 13:05:00'
FROM users u
JOIN lessons l ON l.title = '[A-CASE-B] LESSON 1'
WHERE u.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM lesson_progress lp
      WHERE lp.user_id = u.user_id
        AND lp.lesson_id = l.lesson_id
  );

INSERT INTO lesson_progress (
    user_id,
    lesson_id,
    progress_percent,
    progress_seconds,
    default_playback_rate,
    is_pip_enabled,
    is_completed,
    last_watched_at,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    l.lesson_id,
    100,
    900,
    1.50,
    TRUE,
    TRUE,
    TIMESTAMP '2026-03-30 13:10:00',
    TIMESTAMP '2026-03-30 13:10:00',
    TIMESTAMP '2026-03-30 13:10:00'
FROM users u
JOIN lessons l ON l.title = '[A-CASE-C] LESSON 1'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM lesson_progress lp
      WHERE lp.user_id = u.user_id
        AND lp.lesson_id = l.lesson_id
  );

INSERT INTO quiz_attempts (
    quiz_id,
    learner_id,
    score,
    max_score,
    started_at,
    completed_at,
    time_spent_seconds,
    is_passed,
    attempt_number,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    q.quiz_id,
    u.user_id,
    95,
    100,
    TIMESTAMP '2026-03-30 13:20:00',
    TIMESTAMP '2026-03-30 13:25:00',
    300,
    TRUE,
    1,
    FALSE,
    TIMESTAMP '2026-03-30 13:20:00',
    TIMESTAMP '2026-03-30 13:25:00'
FROM quizzes q
JOIN users u ON u.email = 'learner@devpath.com'
WHERE q.title = '[A-CASE-A] QUIZ'
  AND NOT EXISTS (
      SELECT 1
      FROM quiz_attempts qa
      WHERE qa.quiz_id = q.quiz_id
        AND qa.learner_id = u.user_id
        AND qa.attempt_number = 1
        AND qa.is_deleted = FALSE
  );

INSERT INTO quiz_attempts (
    quiz_id,
    learner_id,
    score,
    max_score,
    started_at,
    completed_at,
    time_spent_seconds,
    is_passed,
    attempt_number,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    q.quiz_id,
    u.user_id,
    88,
    100,
    TIMESTAMP '2026-03-30 13:26:00',
    TIMESTAMP '2026-03-30 13:31:00',
    300,
    TRUE,
    1,
    FALSE,
    TIMESTAMP '2026-03-30 13:26:00',
    TIMESTAMP '2026-03-30 13:31:00'
FROM quizzes q
JOIN users u ON u.email = 'learner2@devpath.com'
WHERE q.title = '[A-CASE-B] QUIZ'
  AND NOT EXISTS (
      SELECT 1
      FROM quiz_attempts qa
      WHERE qa.quiz_id = q.quiz_id
        AND qa.learner_id = u.user_id
        AND qa.attempt_number = 1
        AND qa.is_deleted = FALSE
  );

INSERT INTO quiz_attempts (
    quiz_id,
    learner_id,
    score,
    max_score,
    started_at,
    completed_at,
    time_spent_seconds,
    is_passed,
    attempt_number,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    q.quiz_id,
    u.user_id,
    40,
    100,
    TIMESTAMP '2026-03-30 13:32:00',
    TIMESTAMP '2026-03-30 13:37:00',
    300,
    FALSE,
    1,
    FALSE,
    TIMESTAMP '2026-03-30 13:32:00',
    TIMESTAMP '2026-03-30 13:37:00'
FROM quizzes q
JOIN users u ON u.email = 'learner@devpath.com'
WHERE q.title = '[A-CASE-C] QUIZ'
  AND NOT EXISTS (
      SELECT 1
      FROM quiz_attempts qa
      WHERE qa.quiz_id = q.quiz_id
        AND qa.learner_id = u.user_id
        AND qa.attempt_number = 1
        AND qa.is_deleted = FALSE
  );

INSERT INTO assignment_submissions (
    assignment_id,
    learner_id,
    grader_id,
    submission_text,
    submission_url,
    is_late,
    submission_status,
    submitted_at,
    graded_at,
    readme_passed,
    test_passed,
    lint_passed,
    file_format_passed,
    quality_score,
    total_score,
    individual_feedback,
    common_feedback,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    a.assignment_id,
    lu.user_id,
    iu.user_id,
    'Case A submission',
    'https://github.com/devpath/a-case-a',
    FALSE,
    'GRADED',
    TIMESTAMP '2026-03-30 13:40:00',
    TIMESTAMP '2026-03-30 13:50:00',
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    97,
    96,
    'All branch conditions are satisfied.',
    'Case A feedback',
    FALSE,
    TIMESTAMP '2026-03-30 13:40:00',
    TIMESTAMP '2026-03-30 13:50:00'
FROM assignments a
JOIN users lu ON lu.email = 'learner@devpath.com'
JOIN users iu ON iu.email = 'instructor@devpath.com'
WHERE a.title = '[A-CASE-A] ASSIGNMENT'
  AND NOT EXISTS (
      SELECT 1
      FROM assignment_submissions s
      WHERE s.assignment_id = a.assignment_id
        AND s.learner_id = lu.user_id
        AND s.is_deleted = FALSE
  );

INSERT INTO assignment_submissions (
    assignment_id,
    learner_id,
    grader_id,
    submission_text,
    submission_url,
    is_late,
    submission_status,
    submitted_at,
    graded_at,
    readme_passed,
    test_passed,
    lint_passed,
    file_format_passed,
    quality_score,
    total_score,
    individual_feedback,
    common_feedback,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    a.assignment_id,
    lu.user_id,
    iu.user_id,
    'Case B submission',
    'https://github.com/devpath/a-case-b',
    FALSE,
    'GRADED',
    TIMESTAMP '2026-03-30 13:41:00',
    TIMESTAMP '2026-03-30 13:51:00',
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    94,
    93,
    'Submission passes even though one required tag is missing.',
    'Case B feedback',
    FALSE,
    TIMESTAMP '2026-03-30 13:41:00',
    TIMESTAMP '2026-03-30 13:51:00'
FROM assignments a
JOIN users lu ON lu.email = 'learner2@devpath.com'
JOIN users iu ON iu.email = 'instructor@devpath.com'
WHERE a.title = '[A-CASE-B] ASSIGNMENT'
  AND NOT EXISTS (
      SELECT 1
      FROM assignment_submissions s
      WHERE s.assignment_id = a.assignment_id
        AND s.learner_id = lu.user_id
        AND s.is_deleted = FALSE
  );

INSERT INTO assignment_submissions (
    assignment_id,
    learner_id,
    grader_id,
    submission_text,
    submission_url,
    is_late,
    submission_status,
    submitted_at,
    graded_at,
    readme_passed,
    test_passed,
    lint_passed,
    file_format_passed,
    quality_score,
    total_score,
    individual_feedback,
    common_feedback,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    a.assignment_id,
    lu.user_id,
    iu.user_id,
    'Case C submission',
    'https://github.com/devpath/a-case-c',
    FALSE,
    'GRADED',
    TIMESTAMP '2026-03-30 13:42:00',
    TIMESTAMP '2026-03-30 13:52:00',
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    95,
    95,
    'Assignment passes but the quiz branch still fails.',
    'Case C feedback',
    FALSE,
    TIMESTAMP '2026-03-30 13:42:00',
    TIMESTAMP '2026-03-30 13:52:00'
FROM assignments a
JOIN users lu ON lu.email = 'learner@devpath.com'
JOIN users iu ON iu.email = 'instructor@devpath.com'
WHERE a.title = '[A-CASE-C] ASSIGNMENT'
  AND NOT EXISTS (
      SELECT 1
      FROM assignment_submissions s
      WHERE s.assignment_id = a.assignment_id
        AND s.learner_id = lu.user_id
        AND s.is_deleted = FALSE
  );

INSERT INTO node_clearances (
    user_id,
    node_id,
    clearance_status,
    lesson_completion_rate,
    required_tags_satisfied,
    missing_tag_count,
    lesson_completed,
    quiz_passed,
    assignment_passed,
    proof_eligible,
    cleared_at,
    last_calculated_at,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    rn.node_id,
    'CLEARED',
    100.00,
    TRUE,
    0,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TIMESTAMP '2026-03-30 14:00:00',
    TIMESTAMP '2026-03-30 14:00:00',
    TIMESTAMP '2026-03-30 14:00:00',
    TIMESTAMP '2026-03-30 14:00:00'
FROM users u
JOIN roadmap_nodes rn ON rn.title = '[A-CASE-A] Full pass'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM node_clearances nc
      WHERE nc.user_id = u.user_id
        AND nc.node_id = rn.node_id
  );

INSERT INTO node_clearances (
    user_id,
    node_id,
    clearance_status,
    lesson_completion_rate,
    required_tags_satisfied,
    missing_tag_count,
    lesson_completed,
    quiz_passed,
    assignment_passed,
    proof_eligible,
    cleared_at,
    last_calculated_at,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    rn.node_id,
    'NOT_CLEARED',
    100.00,
    FALSE,
    1,
    TRUE,
    TRUE,
    TRUE,
    FALSE,
    NULL,
    TIMESTAMP '2026-03-30 14:05:00',
    TIMESTAMP '2026-03-30 14:05:00',
    TIMESTAMP '2026-03-30 14:05:00'
FROM users u
JOIN roadmap_nodes rn ON rn.title = '[A-CASE-B] Missing tag'
WHERE u.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM node_clearances nc
      WHERE nc.user_id = u.user_id
        AND nc.node_id = rn.node_id
  );

INSERT INTO node_clearances (
    user_id,
    node_id,
    clearance_status,
    lesson_completion_rate,
    required_tags_satisfied,
    missing_tag_count,
    lesson_completed,
    quiz_passed,
    assignment_passed,
    proof_eligible,
    cleared_at,
    last_calculated_at,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    rn.node_id,
    'NOT_CLEARED',
    100.00,
    TRUE,
    0,
    TRUE,
    FALSE,
    TRUE,
    FALSE,
    NULL,
    TIMESTAMP '2026-03-30 14:10:00',
    TIMESTAMP '2026-03-30 14:10:00',
    TIMESTAMP '2026-03-30 14:10:00'
FROM users u
JOIN roadmap_nodes rn ON rn.title = '[A-CASE-C] Quiz failed'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM node_clearances nc
      WHERE nc.user_id = u.user_id
        AND nc.node_id = rn.node_id
  );

-- ========================================
-- A-PROOF IDEMPOTENCY BRANCHES
-- ========================================
INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order)
WITH target_roadmap AS (
    SELECT r.roadmap_id
    FROM roadmaps r
    WHERE COALESCE(r.is_deleted, FALSE) = FALSE
    ORDER BY COALESCE(r.is_official, FALSE) DESC, r.roadmap_id ASC
    LIMIT 1
)
SELECT
    tr.roadmap_id,
    '[A-PROOF-ISSUABLE] Proof card issuable',
    'Proof-eligible clearance without a proof card for first-issue verification.',
    'CONCEPT',
    904
FROM target_roadmap tr
WHERE NOT EXISTS (
    SELECT 1
    FROM roadmap_nodes rn
    WHERE rn.title = '[A-PROOF-ISSUABLE] Proof card issuable'
);

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order)
WITH target_roadmap AS (
    SELECT r.roadmap_id
    FROM roadmaps r
    WHERE COALESCE(r.is_deleted, FALSE) = FALSE
    ORDER BY COALESCE(r.is_official, FALSE) DESC, r.roadmap_id ASC
    LIMIT 1
)
SELECT
    tr.roadmap_id,
    '[A-PROOF-PREISSUED] Proof card preissued',
    'Preissued proof card and certificate chain for idempotent reuse verification.',
    'CONCEPT',
    905
FROM target_roadmap tr
WHERE NOT EXISTS (
    SELECT 1
    FROM roadmap_nodes rn
    WHERE rn.title = '[A-PROOF-PREISSUED] Proof card preissued'
);

INSERT INTO node_clearances (
    user_id,
    node_id,
    clearance_status,
    lesson_completion_rate,
    required_tags_satisfied,
    missing_tag_count,
    lesson_completed,
    quiz_passed,
    assignment_passed,
    proof_eligible,
    cleared_at,
    last_calculated_at,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    rn.node_id,
    'CLEARED',
    100.00,
    TRUE,
    0,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TIMESTAMP '2026-03-30 15:00:00',
    TIMESTAMP '2026-03-30 15:00:00',
    TIMESTAMP '2026-03-30 15:00:00',
    TIMESTAMP '2026-03-30 15:00:00'
FROM users u
JOIN roadmap_nodes rn ON rn.title = '[A-PROOF-ISSUABLE] Proof card issuable'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM node_clearances nc
      WHERE nc.user_id = u.user_id
        AND nc.node_id = rn.node_id
  );

INSERT INTO node_clearances (
    user_id,
    node_id,
    clearance_status,
    lesson_completion_rate,
    required_tags_satisfied,
    missing_tag_count,
    lesson_completed,
    quiz_passed,
    assignment_passed,
    proof_eligible,
    cleared_at,
    last_calculated_at,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    rn.node_id,
    'CLEARED',
    100.00,
    TRUE,
    0,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TIMESTAMP '2026-03-30 15:05:00',
    TIMESTAMP '2026-03-30 15:05:00',
    TIMESTAMP '2026-03-30 15:05:00',
    TIMESTAMP '2026-03-30 15:05:00'
FROM users u
JOIN roadmap_nodes rn ON rn.title = '[A-PROOF-PREISSUED] Proof card preissued'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM node_clearances nc
      WHERE nc.user_id = u.user_id
        AND nc.node_id = rn.node_id
  );

INSERT INTO proof_cards (
    user_id,
    node_id,
    node_clearance_id,
    title,
    description,
    proof_card_status,
    issued_at,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    rn.node_id,
    nc.node_clearance_id,
    '[A-PROOF-PREISSUED] Proof card',
    'Preissued proof card for idempotent reuse verification.',
    'ISSUED',
    TIMESTAMP '2026-03-30 15:10:00',
    TIMESTAMP '2026-03-30 15:10:00',
    TIMESTAMP '2026-03-30 15:10:00'
FROM node_clearances nc
JOIN users u ON u.user_id = nc.user_id
JOIN roadmap_nodes rn ON rn.node_id = nc.node_id
WHERE u.email = 'learner@devpath.com'
  AND rn.title = '[A-PROOF-PREISSUED] Proof card preissued'
  AND nc.proof_eligible = TRUE
  AND NOT EXISTS (
      SELECT 1
      FROM proof_cards pc
      WHERE pc.node_clearance_id = nc.node_clearance_id
  );

INSERT INTO proof_card_tags (
    proof_card_id,
    tag_id,
    skill_evidence_type
)
WITH target_card AS (
    SELECT pc.proof_card_id
    FROM proof_cards pc
    JOIN roadmap_nodes rn ON rn.node_id = pc.node_id
    WHERE rn.title = '[A-PROOF-PREISSUED] Proof card preissued'
    LIMIT 1
),
ranked_tags AS (
    SELECT t.tag_id, ROW_NUMBER() OVER (ORDER BY t.tag_id) AS rn
    FROM tags t
    WHERE t.is_deleted = FALSE
)
SELECT
    c.proof_card_id,
    t.tag_id,
    'VERIFIED'
FROM target_card c
JOIN ranked_tags t ON t.rn = 1
WHERE NOT EXISTS (
    SELECT 1
    FROM proof_card_tags pct
    WHERE pct.proof_card_id = c.proof_card_id
      AND pct.tag_id = t.tag_id
      AND pct.skill_evidence_type = 'VERIFIED'
);

INSERT INTO proof_card_tags (
    proof_card_id,
    tag_id,
    skill_evidence_type
)
WITH target_card AS (
    SELECT pc.proof_card_id
    FROM proof_cards pc
    JOIN roadmap_nodes rn ON rn.node_id = pc.node_id
    WHERE rn.title = '[A-PROOF-PREISSUED] Proof card preissued'
    LIMIT 1
),
ranked_tags AS (
    SELECT t.tag_id, ROW_NUMBER() OVER (ORDER BY t.tag_id) AS rn
    FROM tags t
    WHERE t.is_deleted = FALSE
)
SELECT
    c.proof_card_id,
    t.tag_id,
    'HELD'
FROM target_card c
JOIN ranked_tags t ON t.rn = 2
WHERE NOT EXISTS (
    SELECT 1
    FROM proof_card_tags pct
    WHERE pct.proof_card_id = c.proof_card_id
      AND pct.tag_id = t.tag_id
      AND pct.skill_evidence_type = 'HELD'
);

INSERT INTO certificates (
    proof_card_id,
    certificate_number,
    certificate_status,
    issued_at,
    pdf_file_name,
    pdf_generated_at,
    last_downloaded_at,
    created_at,
    updated_at
)
SELECT
    pc.proof_card_id,
    'CERT-A-PREISSUED-20260330',
    'PDF_READY',
    TIMESTAMP '2026-03-30 15:15:00',
    'certificate-CERT-A-PREISSUED-20260330.pdf',
    TIMESTAMP '2026-03-30 15:16:00',
    TIMESTAMP '2026-03-30 15:20:00',
    TIMESTAMP '2026-03-30 15:15:00',
    TIMESTAMP '2026-03-30 15:20:00'
FROM proof_cards pc
JOIN roadmap_nodes rn ON rn.node_id = pc.node_id
WHERE rn.title = '[A-PROOF-PREISSUED] Proof card preissued'
  AND NOT EXISTS (
      SELECT 1
      FROM certificates c
      WHERE c.proof_card_id = pc.proof_card_id
  );

INSERT INTO proof_card_shares (
    proof_card_id,
    share_token,
    share_status,
    expires_at,
    access_count,
    created_at,
    updated_at
)
SELECT
    pc.proof_card_id,
    'proof-preissued-token-20260330',
    'ACTIVE',
    TIMESTAMP '2026-12-31 23:59:59',
    2,
    TIMESTAMP '2026-03-30 15:18:00',
    TIMESTAMP '2026-03-30 15:21:00'
FROM proof_cards pc
JOIN roadmap_nodes rn ON rn.node_id = pc.node_id
WHERE rn.title = '[A-PROOF-PREISSUED] Proof card preissued'
  AND NOT EXISTS (
      SELECT 1
      FROM proof_card_shares ps
      WHERE ps.share_token = 'proof-preissued-token-20260330'
  );

INSERT INTO certificate_download_histories (
    certificate_id,
    downloaded_by,
    download_reason,
    downloaded_at
)
SELECT
    c.certificate_id,
    u.user_id,
    'Preissued certificate download verification.',
    TIMESTAMP '2026-03-30 15:20:00'
FROM certificates c
JOIN proof_cards pc ON pc.proof_card_id = c.proof_card_id
JOIN roadmap_nodes rn ON rn.node_id = pc.node_id
JOIN users u ON u.email = 'learner@devpath.com'
WHERE rn.title = '[A-PROOF-PREISSUED] Proof card preissued'
  AND pc.user_id = u.user_id
  AND NOT EXISTS (
      SELECT 1
      FROM certificate_download_histories h
      WHERE h.certificate_id = c.certificate_id
        AND h.downloaded_by = u.user_id
        AND h.download_reason = 'Preissued certificate download verification.'
  );

-- ========================================
-- A-HISTORY READ MODEL
-- ========================================
INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order)
WITH target_roadmap AS (
    SELECT r.roadmap_id
    FROM roadmaps r
    WHERE COALESCE(r.is_deleted, FALSE) = FALSE
    ORDER BY COALESCE(r.is_official, FALSE) DESC, r.roadmap_id ASC
    LIMIT 1
)
SELECT
    tr.roadmap_id,
    '[A-HISTORY-READ-1] History read node 1',
    'Completed-node fixture for learning-history assembly.',
    'CONCEPT',
    906
FROM target_roadmap tr
WHERE NOT EXISTS (
    SELECT 1
    FROM roadmap_nodes rn
    WHERE rn.title = '[A-HISTORY-READ-1] History read node 1'
);

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order)
WITH target_roadmap AS (
    SELECT r.roadmap_id
    FROM roadmaps r
    WHERE COALESCE(r.is_deleted, FALSE) = FALSE
    ORDER BY COALESCE(r.is_official, FALSE) DESC, r.roadmap_id ASC
    LIMIT 1
)
SELECT
    tr.roadmap_id,
    '[A-HISTORY-READ-2] History read node 2',
    'Second completed-node fixture for learning-history assembly.',
    'CONCEPT',
    907
FROM target_roadmap tr
WHERE NOT EXISTS (
    SELECT 1
    FROM roadmap_nodes rn
    WHERE rn.title = '[A-HISTORY-READ-2] History read node 2'
);

INSERT INTO node_clearances (
    user_id,
    node_id,
    clearance_status,
    lesson_completion_rate,
    required_tags_satisfied,
    missing_tag_count,
    lesson_completed,
    quiz_passed,
    assignment_passed,
    proof_eligible,
    cleared_at,
    last_calculated_at,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    rn.node_id,
    'CLEARED',
    100.00,
    TRUE,
    0,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TIMESTAMP '2026-03-30 16:00:00',
    TIMESTAMP '2026-03-30 16:00:00',
    TIMESTAMP '2026-03-30 16:00:00',
    TIMESTAMP '2026-03-30 16:00:00'
FROM users u
JOIN roadmap_nodes rn ON rn.title = '[A-HISTORY-READ-1] History read node 1'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM node_clearances nc
      WHERE nc.user_id = u.user_id
        AND nc.node_id = rn.node_id
  );

INSERT INTO node_clearances (
    user_id,
    node_id,
    clearance_status,
    lesson_completion_rate,
    required_tags_satisfied,
    missing_tag_count,
    lesson_completed,
    quiz_passed,
    assignment_passed,
    proof_eligible,
    cleared_at,
    last_calculated_at,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    rn.node_id,
    'CLEARED',
    100.00,
    TRUE,
    0,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TIMESTAMP '2026-03-30 16:05:00',
    TIMESTAMP '2026-03-30 16:05:00',
    TIMESTAMP '2026-03-30 16:05:00',
    TIMESTAMP '2026-03-30 16:05:00'
FROM users u
JOIN roadmap_nodes rn ON rn.title = '[A-HISTORY-READ-2] History read node 2'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM node_clearances nc
      WHERE nc.user_id = u.user_id
        AND nc.node_id = rn.node_id
  );

INSERT INTO assignment_submissions (
    assignment_id,
    learner_id,
    grader_id,
    submission_text,
    submission_url,
    is_late,
    submission_status,
    submitted_at,
    graded_at,
    readme_passed,
    test_passed,
    lint_passed,
    file_format_passed,
    quality_score,
    total_score,
    individual_feedback,
    common_feedback,
    is_deleted,
    created_at,
    updated_at
)
WITH first_assignment AS (
    SELECT a.assignment_id
    FROM assignments a
    ORDER BY a.assignment_id
    LIMIT 1
)
SELECT
    a.assignment_id,
    lu.user_id,
    iu.user_id,
    'Submission for learning-history read-model verification.',
    'https://github.com/devpath/history-read-model',
    FALSE,
    'GRADED',
    TIMESTAMP '2026-03-30 16:10:00',
    TIMESTAMP '2026-03-30 16:20:00',
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    91,
    92,
    'Assignment entry for learning-history verification.',
    'Learning-history common feedback',
    FALSE,
    TIMESTAMP '2026-03-30 16:10:00',
    TIMESTAMP '2026-03-30 16:20:00'
FROM first_assignment a
JOIN users lu ON lu.email = 'learner@devpath.com'
JOIN users iu ON iu.email = 'instructor@devpath.com'
WHERE NOT EXISTS (
    SELECT 1
    FROM assignment_submissions s
    WHERE s.assignment_id = a.assignment_id
      AND s.learner_id = lu.user_id
      AND s.submission_url = 'https://github.com/devpath/history-read-model'
      AND s.is_deleted = FALSE
);

INSERT INTO til_drafts (
    user_id,
    lesson_id,
    title,
    content,
    table_of_contents,
    status,
    published_url,
    is_deleted,
    created_at,
    updated_at
)
WITH first_lesson AS (
    SELECT l.lesson_id
    FROM lessons l
    ORDER BY l.lesson_id
    LIMIT 1
)
SELECT
    u.user_id,
    fl.lesson_id,
    'Learning history verification TIL 1',
    '# Learning history notes' || E'\n\n' ||
    '## Completed nodes' || E'\n' ||
    '- reviewed completed-node aggregation' || E'\n\n' ||
    '## Reflection' || E'\n' ||
    'validated the read-model response shape.',
    '[{"level":1,"title":"Learning history notes","anchor":"learning-history-notes"},{"level":2,"title":"Completed nodes","anchor":"completed-nodes"},{"level":2,"title":"Reflection","anchor":"reflection"}]',
    'PUBLISHED',
    'https://velog.io/@devpath/history-read-model-1',
    FALSE,
    TIMESTAMP '2026-03-30 16:30:00',
    TIMESTAMP '2026-03-30 16:35:00'
FROM users u
CROSS JOIN first_lesson fl
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM til_drafts t
      WHERE t.user_id = u.user_id
        AND t.title = 'Learning history verification TIL 1'
        AND t.is_deleted = FALSE
  );

INSERT INTO til_drafts (
    user_id,
    lesson_id,
    title,
    content,
    table_of_contents,
    status,
    published_url,
    is_deleted,
    created_at,
    updated_at
)
WITH first_lesson AS (
    SELECT l.lesson_id
    FROM lessons l
    ORDER BY l.lesson_id
    LIMIT 1
)
SELECT
    u.user_id,
    fl.lesson_id,
    'Learning history verification TIL 2',
    '# Second history TIL' || E'\n\n' ||
    '## Assignment record' || E'\n' ||
    '- checked submission status and score' || E'\n\n' ||
    '## Next action' || E'\n' ||
    'verify share-link and organize responses.',
    '[{"level":1,"title":"Second history TIL","anchor":"second-history-til"},{"level":2,"title":"Assignment record","anchor":"assignment-record"},{"level":2,"title":"Next action","anchor":"next-action"}]',
    'DRAFT',
    NULL,
    FALSE,
    TIMESTAMP '2026-03-30 16:40:00',
    TIMESTAMP '2026-03-30 16:40:00'
FROM users u
CROSS JOIN first_lesson fl
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM til_drafts t
      WHERE t.user_id = u.user_id
        AND t.title = 'Learning history verification TIL 2'
        AND t.is_deleted = FALSE
  );

INSERT INTO learning_history_share_links (
    user_id,
    share_token,
    title,
    expires_at,
    access_count,
    is_active,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    'learning-history-read-model-20260330',
    'Learning history read-model link',
    TIMESTAMP '2026-12-31 23:59:59',
    1,
    TRUE,
    TIMESTAMP '2026-03-30 16:50:00',
    TIMESTAMP '2026-03-30 16:55:00'
FROM users u
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM learning_history_share_links l
      WHERE l.share_token = 'learning-history-read-model-20260330'
  );

-- ========================================
-- A-RECOMMENDATION CHANGE SIGNALS
-- ========================================

INSERT INTO learning_automation_rules (
    rule_key,
    rule_name,
    description,
    rule_value,
    priority,
    rule_status,
    created_at,
    updated_at
)
SELECT
    'RECOMMENDATION_CHANGE_ENABLED',
    'Recommendation change feature enabled',
    'Enables recommendation change suggestion creation.',
    'true',
    10,
    'ENABLED',
    TIMESTAMP '2026-03-30 17:00:00',
    TIMESTAMP '2026-03-30 17:00:00'
WHERE NOT EXISTS (
    SELECT 1
    FROM learning_automation_rules r
    WHERE r.rule_key = 'RECOMMENDATION_CHANGE_ENABLED'
);

INSERT INTO learning_automation_rules (
    rule_key,
    rule_name,
    description,
    rule_value,
    priority,
    rule_status,
    created_at,
    updated_at
)
SELECT
    'RECOMMENDATION_CHANGE_MAX_LIMIT',
    'Recommendation change max suggestion limit',
    'Defines the max number of recommendation change suggestions generated in one call.',
    '10',
    11,
    'ENABLED',
    TIMESTAMP '2026-03-30 17:01:00',
    TIMESTAMP '2026-03-30 17:01:00'
WHERE NOT EXISTS (
    SELECT 1
    FROM learning_automation_rules r
    WHERE r.rule_key = 'RECOMMENDATION_CHANGE_MAX_LIMIT'
);

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order)
WITH target_roadmap AS (
    SELECT r.roadmap_id
    FROM roadmaps r
    WHERE COALESCE(r.is_deleted, FALSE) = FALSE
    ORDER BY COALESCE(r.is_official, FALSE) DESC, r.roadmap_id ASC
    LIMIT 1
)
SELECT
    tr.roadmap_id,
    '[A-RECO-1] Recommendation change suggestion node 1',
    'Recommendation change suggestion verification node 1',
    'CONCEPT',
    908
FROM target_roadmap tr
WHERE NOT EXISTS (
    SELECT 1
    FROM roadmap_nodes rn
    WHERE rn.title = '[A-RECO-1] Recommendation change suggestion node 1'
);

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order)
WITH target_roadmap AS (
    SELECT r.roadmap_id
    FROM roadmaps r
    WHERE COALESCE(r.is_deleted, FALSE) = FALSE
    ORDER BY COALESCE(r.is_official, FALSE) DESC, r.roadmap_id ASC
    LIMIT 1
)
SELECT
    tr.roadmap_id,
    '[A-RECO-2] Recommendation change suggestion node 2',
    'Recommendation change suggestion verification node 2',
    'CONCEPT',
    909
FROM target_roadmap tr
WHERE NOT EXISTS (
    SELECT 1
    FROM roadmap_nodes rn
    WHERE rn.title = '[A-RECO-2] Recommendation change suggestion node 2'
);

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order)
WITH target_roadmap AS (
    SELECT r.roadmap_id
    FROM roadmaps r
    WHERE COALESCE(r.is_deleted, FALSE) = FALSE
    ORDER BY COALESCE(r.is_official, FALSE) DESC, r.roadmap_id ASC
    LIMIT 1
)
SELECT
    tr.roadmap_id,
    '[A-RECO-3] Recommendation change suggestion node 3',
    'Recommendation change recalculate verification node 3',
    'CONCEPT',
    910
FROM target_roadmap tr
WHERE NOT EXISTS (
    SELECT 1
    FROM roadmap_nodes rn
    WHERE rn.title = '[A-RECO-3] Recommendation change suggestion node 3'
);

INSERT INTO til_drafts (
    user_id,
    lesson_id,
    title,
    content,
    table_of_contents,
    status,
    published_url,
    is_deleted,
    created_at,
    updated_at
)
WITH first_lesson AS (
    SELECT l.lesson_id
    FROM lessons l
    ORDER BY l.lesson_id
    LIMIT 1
)
SELECT
    u.user_id,
    fl.lesson_id,
    'Recommendation change signal TIL',
    '# Recommendation change signal' || E'\n\n' ||
    '## Weak areas' || E'\n' ||
    '- JPA associations and lazy loading need review' || E'\n\n' ||
    '## Next action' || E'\n' ||
    '- Verify supplement recommendation changes.',
    '[{"level":1,"title":"Recommendation change signal","anchor":"recommendation-change-signal"},{"level":2,"title":"Weak areas","anchor":"weak-areas"},{"level":2,"title":"Next action","anchor":"next-action"}]',
    'DRAFT',
    NULL,
    FALSE,
    TIMESTAMP '2026-03-30 17:05:00',
    TIMESTAMP '2026-03-30 17:05:00'
FROM users u
CROSS JOIN first_lesson fl
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM til_drafts t
      WHERE t.user_id = u.user_id
        AND t.title = 'Recommendation change signal TIL'
        AND t.is_deleted = FALSE
  );

INSERT INTO diagnosis_quizzes (
    user_id,
    roadmap_id,
    question_count,
    difficulty,
    created_at,
    submitted_at
)
WITH target_roadmap AS (
    SELECT r.roadmap_id
    FROM roadmaps r
    WHERE COALESCE(r.is_deleted, FALSE) = FALSE
    ORDER BY COALESCE(r.is_official, FALSE) DESC, r.roadmap_id ASC
    LIMIT 1
)
SELECT
    u.user_id,
    tr.roadmap_id,
    5,
    'INTERMEDIATE',
    TIMESTAMP '2026-03-30 17:10:00',
    TIMESTAMP '2026-03-30 17:12:00'
FROM users u
CROSS JOIN target_roadmap tr
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM diagnosis_quizzes dq
      WHERE dq.user_id = u.user_id
        AND dq.roadmap_id = tr.roadmap_id
        AND dq.created_at = TIMESTAMP '2026-03-30 17:10:00'
  );

INSERT INTO diagnosis_results (
    user_id,
    roadmap_id,
    quiz_id,
    score,
    max_score,
    weak_areas,
    recommended_nodes,
    created_at
)
WITH target_quiz AS (
    SELECT dq.quiz_id, dq.user_id, dq.roadmap_id
    FROM diagnosis_quizzes dq
    JOIN users u ON u.user_id = dq.user_id
    WHERE u.email = 'learner@devpath.com'
      AND dq.created_at = TIMESTAMP '2026-03-30 17:10:00'
    LIMIT 1
)
SELECT
    tq.user_id,
    tq.roadmap_id,
    tq.quiz_id,
    48,
    100,
    '["JPA","Lazy Loading","Entity Graph"]',
    '["[A-RECO-1] Recommendation change suggestion node 1","[A-RECO-2] Recommendation change suggestion node 2"]',
    TIMESTAMP '2026-03-30 17:13:00'
FROM target_quiz tq
WHERE NOT EXISTS (
    SELECT 1
    FROM diagnosis_results dr
    WHERE dr.user_id = tq.user_id
      AND dr.quiz_id = tq.quiz_id
  );

INSERT INTO risk_warnings (
    user_id,
    node_id,
    warning_type,
    risk_level,
    message,
    is_acknowledged,
    acknowledged_at,
    created_at
)
SELECT
    u.user_id,
    rn.node_id,
    'PREREQUISITE_GAP',
    'HIGH',
    'Prerequisite knowledge gap detected before entering the next node.',
    FALSE,
    NULL,
    TIMESTAMP '2026-03-30 17:15:00'
FROM users u
JOIN roadmap_nodes rn ON rn.title = '[A-RECO-1] Recommendation change suggestion node 1'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM risk_warnings rw
      WHERE rw.user_id = u.user_id
        AND rw.node_id = rn.node_id
        AND rw.warning_type = 'PREREQUISITE_GAP'
  );

INSERT INTO risk_warnings (
    user_id,
    node_id,
    warning_type,
    risk_level,
    message,
    is_acknowledged,
    acknowledged_at,
    created_at
)
SELECT
    u.user_id,
    rn.node_id,
    'DROP_OFF_RISK',
    'MEDIUM',
    'Recent study patterns indicate a moderate drop-off risk for this node.',
    FALSE,
    NULL,
    TIMESTAMP '2026-03-30 17:16:00'
FROM users u
JOIN roadmap_nodes rn ON rn.title = '[A-RECO-2] Recommendation change suggestion node 2'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM risk_warnings rw
      WHERE rw.user_id = u.user_id
        AND rw.node_id = rn.node_id
        AND rw.warning_type = 'DROP_OFF_RISK'
  );

INSERT INTO supplement_recommendations (
    user_id,
    node_id,
    reason,
    priority,
    coverage_percent,
    missing_tag_count,
    status,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    rn.node_id,
    'JPA associations and lazy loading need reinforcement before moving forward.',
    1,
    48.0,
    3,
    'PENDING',
    TIMESTAMP '2026-03-30 17:20:00',
    TIMESTAMP '2026-03-30 17:20:00'
FROM users u
JOIN roadmap_nodes rn ON rn.title = '[A-RECO-1] Recommendation change suggestion node 1'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM supplement_recommendations sr
      WHERE sr.user_id = u.user_id
        AND sr.node_id = rn.node_id
  );

INSERT INTO supplement_recommendations (
    user_id,
    node_id,
    reason,
    priority,
    coverage_percent,
    missing_tag_count,
    status,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    rn.node_id,
    'The next node should be delayed until the missing prerequisites are filled.',
    2,
    55.0,
    2,
    'PENDING',
    TIMESTAMP '2026-03-30 17:21:00',
    TIMESTAMP '2026-03-30 17:21:00'
FROM users u
JOIN roadmap_nodes rn ON rn.title = '[A-RECO-2] Recommendation change suggestion node 2'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM supplement_recommendations sr
      WHERE sr.user_id = u.user_id
        AND sr.node_id = rn.node_id
  );

INSERT INTO supplement_recommendations (
    user_id,
    node_id,
    reason,
    priority,
    coverage_percent,
    missing_tag_count,
    status,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    rn.node_id,
    'Pending recommendation kept for recalculate-next-nodes verification.',
    3,
    61.0,
    1,
    'PENDING',
    TIMESTAMP '2026-03-30 17:22:00',
    TIMESTAMP '2026-03-30 17:22:00'
FROM users u
JOIN roadmap_nodes rn ON rn.title = '[A-RECO-3] Recommendation change suggestion node 3'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM supplement_recommendations sr
      WHERE sr.user_id = u.user_id
        AND sr.node_id = rn.node_id
  );

INSERT INTO recommendation_changes (
    user_id,
    node_id,
    source_recommendation_id,
    reason,
    context_summary,
    node_change_type,
    change_status,
    decision_status,
    suggested_at,
    applied_at,
    ignored_at,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    rn.node_id,
    sr.recommendation_id,
    sr.reason,
    'tilCount=4, weaknessSignal=true, warningCount=2, historyCount=2',
    'ADD',
    'SUGGESTED',
    'UNDECIDED',
    TIMESTAMP '2026-03-30 17:25:00',
    NULL,
    NULL,
    TIMESTAMP '2026-03-30 17:25:00',
    TIMESTAMP '2026-03-30 17:25:00'
FROM users u
JOIN roadmap_nodes rn ON rn.title = '[A-RECO-1] Recommendation change suggestion node 1'
JOIN supplement_recommendations sr
  ON sr.user_id = u.user_id
 AND sr.node_id = rn.node_id
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM recommendation_changes rc
      WHERE rc.user_id = u.user_id
        AND rc.node_id = rn.node_id
        AND rc.change_status = 'SUGGESTED'
  );

INSERT INTO recommendation_changes (
    user_id,
    node_id,
    source_recommendation_id,
    reason,
    context_summary,
    node_change_type,
    change_status,
    decision_status,
    suggested_at,
    applied_at,
    ignored_at,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    rn.node_id,
    sr.recommendation_id,
    sr.reason,
    'tilCount=4, weaknessSignal=true, warningCount=2, historyCount=2',
    'ADD',
    'SUGGESTED',
    'UNDECIDED',
    TIMESTAMP '2026-03-30 17:26:00',
    NULL,
    NULL,
    TIMESTAMP '2026-03-30 17:26:00',
    TIMESTAMP '2026-03-30 17:26:00'
FROM users u
JOIN roadmap_nodes rn ON rn.title = '[A-RECO-2] Recommendation change suggestion node 2'
JOIN supplement_recommendations sr
  ON sr.user_id = u.user_id
 AND sr.node_id = rn.node_id
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM recommendation_changes rc
      WHERE rc.user_id = u.user_id
        AND rc.node_id = rn.node_id
        AND rc.change_status = 'SUGGESTED'
  );

INSERT INTO recommendation_changes (
    user_id,
    node_id,
    source_recommendation_id,
    reason,
    context_summary,
    node_change_type,
    change_status,
    decision_status,
    suggested_at,
    applied_at,
    ignored_at,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    rn.node_id,
    sr.recommendation_id,
    sr.reason,
    'tilCount=4, weaknessSignal=true, warningCount=2, historyCount=2',
    'ADD',
    'SUGGESTED',
    'UNDECIDED',
    TIMESTAMP '2026-03-30 17:27:00',
    NULL,
    NULL,
    TIMESTAMP '2026-03-30 17:27:00',
    TIMESTAMP '2026-03-30 17:27:00'
FROM users u
JOIN roadmap_nodes rn ON rn.title = '[A-RECO-3] Recommendation change suggestion node 3'
JOIN supplement_recommendations sr
  ON sr.user_id = u.user_id
 AND sr.node_id = rn.node_id
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM recommendation_changes rc
      WHERE rc.user_id = u.user_id
        AND rc.node_id = rn.node_id
        AND rc.change_status = 'SUGGESTED'
  );

INSERT INTO recommendation_changes (
    user_id,
    node_id,
    source_recommendation_id,
    reason,
    context_summary,
    node_change_type,
    change_status,
    decision_status,
    suggested_at,
    applied_at,
    ignored_at,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    rn.node_id,
    NULL,
    'Previously applied recommendation change sample.',
    'tilCount=2, weaknessSignal=true, warningCount=1, historyCount=0',
    'ADD',
    'APPLIED',
    'APPLIED',
    TIMESTAMP '2026-03-28 17:00:00',
    TIMESTAMP '2026-03-28 17:10:00',
    NULL,
    TIMESTAMP '2026-03-28 17:00:00',
    TIMESTAMP '2026-03-28 17:10:00'
FROM users u
JOIN roadmap_nodes rn ON rn.title = '[A-RECO-1] Recommendation change suggestion node 1'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM recommendation_changes rc
      WHERE rc.user_id = u.user_id
        AND rc.node_id = rn.node_id
        AND rc.change_status = 'APPLIED'
  );

INSERT INTO recommendation_changes (
    user_id,
    node_id,
    source_recommendation_id,
    reason,
    context_summary,
    node_change_type,
    change_status,
    decision_status,
    suggested_at,
    applied_at,
    ignored_at,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    rn.node_id,
    NULL,
    'Previously ignored recommendation change sample.',
    'tilCount=1, weaknessSignal=false, warningCount=1, historyCount=1',
    'ADD',
    'IGNORED',
    'IGNORED',
    TIMESTAMP '2026-03-29 18:00:00',
    NULL,
    TIMESTAMP '2026-03-29 18:05:00',
    TIMESTAMP '2026-03-29 18:00:00',
    TIMESTAMP '2026-03-29 18:05:00'
FROM users u
JOIN roadmap_nodes rn ON rn.title = '[A-RECO-2] Recommendation change suggestion node 2'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM recommendation_changes rc
      WHERE rc.user_id = u.user_id
        AND rc.node_id = rn.node_id
        AND rc.change_status = 'IGNORED'
  );

INSERT INTO recommendation_histories (
    user_id,
    recommendation_id,
    node_id,
    before_status,
    after_status,
    action_type,
    context,
    created_at
)
SELECT
    rc.user_id,
    rc.recommendation_change_id,
    rc.node_id,
    'SUGGESTED',
    'APPLIED',
    'CHANGE_APPLY',
    'Previously applied recommendation change sample.',
    TIMESTAMP '2026-03-28 17:10:00'
FROM recommendation_changes rc
JOIN users u ON u.user_id = rc.user_id
JOIN roadmap_nodes rn ON rn.node_id = rc.node_id
WHERE u.email = 'learner@devpath.com'
  AND rn.title = '[A-RECO-1] Recommendation change suggestion node 1'
  AND rc.change_status = 'APPLIED'
  AND NOT EXISTS (
      SELECT 1
      FROM recommendation_histories rh
      WHERE rh.recommendation_id = rc.recommendation_change_id
        AND rh.action_type = 'CHANGE_APPLY'
  );

INSERT INTO recommendation_histories (
    user_id,
    recommendation_id,
    node_id,
    before_status,
    after_status,
    action_type,
    context,
    created_at
)
SELECT
    rc.user_id,
    rc.recommendation_change_id,
    rc.node_id,
    'SUGGESTED',
    'IGNORED',
    'CHANGE_IGNORE',
    'Previously ignored recommendation change sample.',
    TIMESTAMP '2026-03-29 18:05:00'
FROM recommendation_changes rc
JOIN users u ON u.user_id = rc.user_id
JOIN roadmap_nodes rn ON rn.node_id = rc.node_id
WHERE u.email = 'learner@devpath.com'
  AND rn.title = '[A-RECO-2] Recommendation change suggestion node 2'
  AND rc.change_status = 'IGNORED'
  AND NOT EXISTS (
      SELECT 1
      FROM recommendation_histories rh
      WHERE rh.recommendation_id = rc.recommendation_change_id
        AND rh.action_type = 'CHANGE_IGNORE'
  );

INSERT INTO course_enrollments (
    user_id,
    course_id,
    status,
    enrolled_at,
    completed_at,
    progress_percentage,
    last_accessed_at
)
SELECT
    u.user_id,
    c.course_id,
    'COMPLETED',
    TIMESTAMP '2026-02-03 09:00:00',
    TIMESTAMP '2026-03-10 22:10:00',
    100,
    TIMESTAMP '2026-03-10 22:10:00'
FROM users u
JOIN courses c ON c.title = 'Spring Boot Intro'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM course_enrollments ce
      WHERE ce.user_id = u.user_id
        AND ce.course_id = c.course_id
  );

INSERT INTO course_enrollments (
    user_id,
    course_id,
    status,
    enrolled_at,
    completed_at,
    progress_percentage,
    last_accessed_at
)
SELECT
    u.user_id,
    c.course_id,
    'ACTIVE',
    TIMESTAMP '2026-02-08 13:30:00',
    NULL,
    62,
    TIMESTAMP '2026-03-28 21:15:00'
FROM users u
JOIN courses c ON c.title = 'Spring Boot Intro'
WHERE u.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM course_enrollments ce
      WHERE ce.user_id = u.user_id
        AND ce.course_id = c.course_id
  );

INSERT INTO course_enrollments (
    user_id,
    course_id,
    status,
    enrolled_at,
    completed_at,
    progress_percentage,
    last_accessed_at
)
SELECT
    u.user_id,
    c.course_id,
    'ACTIVE',
    TIMESTAMP '2026-02-11 18:20:00',
    NULL,
    54,
    TIMESTAMP '2026-03-29 20:40:00'
FROM users u
JOIN courses c ON c.title = 'JPA Practical Design'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM course_enrollments ce
      WHERE ce.user_id = u.user_id
        AND ce.course_id = c.course_id
  );

INSERT INTO course_enrollments (
    user_id,
    course_id,
    status,
    enrolled_at,
    completed_at,
    progress_percentage,
    last_accessed_at
)
SELECT
    u.user_id,
    c.course_id,
    'ACTIVE',
    TIMESTAMP '2026-02-12 19:10:00',
    NULL,
    37,
    TIMESTAMP '2026-03-27 23:05:00'
FROM users u
JOIN courses c ON c.title = 'JPA Practical Design'
WHERE u.email = 'learner3@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM course_enrollments ce
      WHERE ce.user_id = u.user_id
        AND ce.course_id = c.course_id
  );

INSERT INTO course_enrollments (
    user_id,
    course_id,
    status,
    enrolled_at,
    completed_at,
    progress_percentage,
    last_accessed_at
)
SELECT
    u.user_id,
    c.course_id,
    'ACTIVE',
    TIMESTAMP '2026-02-14 10:40:00',
    NULL,
    68,
    TIMESTAMP '2026-03-30 18:25:00'
FROM users u
JOIN courses c ON c.title = 'React Dashboard Sprint'
WHERE u.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM course_enrollments ce
      WHERE ce.user_id = u.user_id
        AND ce.course_id = c.course_id
  );

INSERT INTO course_enrollments (
    user_id,
    course_id,
    status,
    enrolled_at,
    completed_at,
    progress_percentage,
    last_accessed_at
)
SELECT
    u.user_id,
    c.course_id,
    'ACTIVE',
    TIMESTAMP '2026-02-16 09:10:00',
    NULL,
    46,
    TIMESTAMP '2026-03-31 09:35:00'
FROM users u
JOIN courses c ON c.title = 'React Dashboard Sprint'
WHERE u.email = 'learner3@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM course_enrollments ce
      WHERE ce.user_id = u.user_id
        AND ce.course_id = c.course_id
  );

-- ========================================
-- A-INSTRUCTOR ANALYTICS
-- ========================================

INSERT INTO course_enrollments (
    user_id,
    course_id,
    status,
    enrolled_at,
    completed_at,
    progress_percentage,
    last_accessed_at
)
SELECT
    u.user_id,
    c.course_id,
    'COMPLETED',
    TIMESTAMP '2026-03-30 18:05:00',
    TIMESTAMP '2026-03-30 18:50:00',
    100,
    TIMESTAMP '2026-03-30 18:50:00'
FROM users u
JOIN courses c ON c.title = '[A-CASE-A] Node Clearance Course'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM course_enrollments ce
      WHERE ce.user_id = u.user_id
        AND ce.course_id = c.course_id
  );

INSERT INTO course_enrollments (
    user_id,
    course_id,
    status,
    enrolled_at,
    completed_at,
    progress_percentage,
    last_accessed_at
)
SELECT
    u.user_id,
    c.course_id,
    'ACTIVE',
    TIMESTAMP '2026-03-30 18:06:00',
    NULL,
    72,
    TIMESTAMP '2026-03-30 18:40:00'
FROM users u
JOIN courses c ON c.title = '[A-CASE-A] Node Clearance Course'
WHERE u.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM course_enrollments ce
      WHERE ce.user_id = u.user_id
        AND ce.course_id = c.course_id
  );

INSERT INTO course_enrollments (
    user_id,
    course_id,
    status,
    enrolled_at,
    completed_at,
    progress_percentage,
    last_accessed_at
)
SELECT
    u.user_id,
    c.course_id,
    'ACTIVE',
    TIMESTAMP '2026-03-30 18:07:00',
    NULL,
    28,
    TIMESTAMP '2026-03-30 18:22:00'
FROM users u
JOIN courses c ON c.title = '[A-CASE-A] Node Clearance Course'
WHERE u.email = 'learner3@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM course_enrollments ce
      WHERE ce.user_id = u.user_id
        AND ce.course_id = c.course_id
  );

INSERT INTO course_enrollments (
    user_id,
    course_id,
    status,
    enrolled_at,
    completed_at,
    progress_percentage,
    last_accessed_at
)
SELECT
    u.user_id,
    c.course_id,
    'COMPLETED',
    TIMESTAMP '2026-03-30 18:10:00',
    TIMESTAMP '2026-03-30 18:55:00',
    100,
    TIMESTAMP '2026-03-30 18:55:00'
FROM users u
JOIN courses c ON c.title = '[A-CASE-B] Tag Missing Course'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM course_enrollments ce
      WHERE ce.user_id = u.user_id
        AND ce.course_id = c.course_id
  );

INSERT INTO course_enrollments (
    user_id,
    course_id,
    status,
    enrolled_at,
    completed_at,
    progress_percentage,
    last_accessed_at
)
SELECT
    u.user_id,
    c.course_id,
    'ACTIVE',
    TIMESTAMP '2026-03-30 18:11:00',
    NULL,
    83,
    TIMESTAMP '2026-03-30 18:46:00'
FROM users u
JOIN courses c ON c.title = '[A-CASE-B] Tag Missing Course'
WHERE u.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM course_enrollments ce
      WHERE ce.user_id = u.user_id
        AND ce.course_id = c.course_id
  );

INSERT INTO course_enrollments (
    user_id,
    course_id,
    status,
    enrolled_at,
    completed_at,
    progress_percentage,
    last_accessed_at
)
SELECT
    u.user_id,
    c.course_id,
    'ACTIVE',
    TIMESTAMP '2026-03-30 18:12:00',
    NULL,
    56,
    TIMESTAMP '2026-03-30 18:33:00'
FROM users u
JOIN courses c ON c.title = '[A-CASE-B] Tag Missing Course'
WHERE u.email = 'learner3@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM course_enrollments ce
      WHERE ce.user_id = u.user_id
        AND ce.course_id = c.course_id
  );

INSERT INTO course_enrollments (
    user_id,
    course_id,
    status,
    enrolled_at,
    completed_at,
    progress_percentage,
    last_accessed_at
)
SELECT
    u.user_id,
    c.course_id,
    'ACTIVE',
    TIMESTAMP '2026-03-30 18:13:00',
    NULL,
    49,
    TIMESTAMP '2026-03-30 18:28:00'
FROM users u
JOIN courses c ON c.title = '[A-CASE-C] Quiz Fail Course'
WHERE u.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM course_enrollments ce
      WHERE ce.user_id = u.user_id
        AND ce.course_id = c.course_id
  );

INSERT INTO course_enrollments (
    user_id,
    course_id,
    status,
    enrolled_at,
    completed_at,
    progress_percentage,
    last_accessed_at
)
SELECT
    u.user_id,
    c.course_id,
    'COMPLETED',
    TIMESTAMP '2026-03-30 18:14:00',
    TIMESTAMP '2026-03-30 18:58:00',
    100,
    TIMESTAMP '2026-03-30 18:58:00'
FROM users u
JOIN courses c ON c.title = '[A-CASE-C] Quiz Fail Course'
WHERE u.email = 'learner3@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM course_enrollments ce
      WHERE ce.user_id = u.user_id
        AND ce.course_id = c.course_id
  );

INSERT INTO lesson_progress (
    user_id,
    lesson_id,
    progress_percent,
    progress_seconds,
    default_playback_rate,
    is_pip_enabled,
    is_completed,
    last_watched_at,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    l.lesson_id,
    68,
    620,
    1.25,
    TRUE,
    FALSE,
    TIMESTAMP '2026-03-30 18:20:00',
    TIMESTAMP '2026-03-30 18:20:00',
    TIMESTAMP '2026-03-30 18:20:00'
FROM users u
JOIN lessons l ON l.title = '[A-CASE-A] LESSON 1'
WHERE u.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM lesson_progress lp
      WHERE lp.user_id = u.user_id
        AND lp.lesson_id = l.lesson_id
  );

INSERT INTO lesson_progress (
    user_id,
    lesson_id,
    progress_percent,
    progress_seconds,
    default_playback_rate,
    is_pip_enabled,
    is_completed,
    last_watched_at,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    l.lesson_id,
    24,
    210,
    1.00,
    FALSE,
    FALSE,
    TIMESTAMP '2026-03-30 18:21:00',
    TIMESTAMP '2026-03-30 18:21:00',
    TIMESTAMP '2026-03-30 18:21:00'
FROM users u
JOIN lessons l ON l.title = '[A-CASE-A] LESSON 1'
WHERE u.email = 'learner3@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM lesson_progress lp
      WHERE lp.user_id = u.user_id
        AND lp.lesson_id = l.lesson_id
  );

INSERT INTO lesson_progress (
    user_id,
    lesson_id,
    progress_percent,
    progress_seconds,
    default_playback_rate,
    is_pip_enabled,
    is_completed,
    last_watched_at,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    l.lesson_id,
    100,
    900,
    1.50,
    TRUE,
    TRUE,
    TIMESTAMP '2026-03-30 18:24:00',
    TIMESTAMP '2026-03-30 18:24:00',
    TIMESTAMP '2026-03-30 18:24:00'
FROM users u
JOIN lessons l ON l.title = '[A-CASE-B] LESSON 1'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM lesson_progress lp
      WHERE lp.user_id = u.user_id
        AND lp.lesson_id = l.lesson_id
  );

INSERT INTO lesson_progress (
    user_id,
    lesson_id,
    progress_percent,
    progress_seconds,
    default_playback_rate,
    is_pip_enabled,
    is_completed,
    last_watched_at,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    l.lesson_id,
    52,
    470,
    1.00,
    FALSE,
    FALSE,
    TIMESTAMP '2026-03-30 18:25:00',
    TIMESTAMP '2026-03-30 18:25:00',
    TIMESTAMP '2026-03-30 18:25:00'
FROM users u
JOIN lessons l ON l.title = '[A-CASE-B] LESSON 1'
WHERE u.email = 'learner3@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM lesson_progress lp
      WHERE lp.user_id = u.user_id
        AND lp.lesson_id = l.lesson_id
  );

INSERT INTO lesson_progress (
    user_id,
    lesson_id,
    progress_percent,
    progress_seconds,
    default_playback_rate,
    is_pip_enabled,
    is_completed,
    last_watched_at,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    l.lesson_id,
    44,
    390,
    1.25,
    TRUE,
    FALSE,
    TIMESTAMP '2026-03-30 18:26:00',
    TIMESTAMP '2026-03-30 18:26:00',
    TIMESTAMP '2026-03-30 18:26:00'
FROM users u
JOIN lessons l ON l.title = '[A-CASE-C] LESSON 1'
WHERE u.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM lesson_progress lp
      WHERE lp.user_id = u.user_id
        AND lp.lesson_id = l.lesson_id
  );

INSERT INTO lesson_progress (
    user_id,
    lesson_id,
    progress_percent,
    progress_seconds,
    default_playback_rate,
    is_pip_enabled,
    is_completed,
    last_watched_at,
    created_at,
    updated_at
)
SELECT
    u.user_id,
    l.lesson_id,
    100,
    900,
    1.75,
    TRUE,
    TRUE,
    TIMESTAMP '2026-03-30 18:27:00',
    TIMESTAMP '2026-03-30 18:27:00',
    TIMESTAMP '2026-03-30 18:27:00'
FROM users u
JOIN lessons l ON l.title = '[A-CASE-C] LESSON 1'
WHERE u.email = 'learner3@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM lesson_progress lp
      WHERE lp.user_id = u.user_id
        AND lp.lesson_id = l.lesson_id
  );

INSERT INTO quiz_attempts (
    quiz_id,
    learner_id,
    score,
    max_score,
    started_at,
    completed_at,
    time_spent_seconds,
    is_passed,
    attempt_number,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    q.quiz_id,
    u.user_id,
    45,
    100,
    TIMESTAMP '2026-03-30 18:30:00',
    TIMESTAMP '2026-03-30 18:35:00',
    300,
    FALSE,
    1,
    FALSE,
    TIMESTAMP '2026-03-30 18:30:00',
    TIMESTAMP '2026-03-30 18:35:00'
FROM quizzes q
JOIN users u ON u.email = 'learner2@devpath.com'
WHERE q.title = '[A-CASE-A] QUIZ'
  AND NOT EXISTS (
      SELECT 1
      FROM quiz_attempts qa
      WHERE qa.quiz_id = q.quiz_id
        AND qa.learner_id = u.user_id
        AND qa.attempt_number = 1
        AND qa.is_deleted = FALSE
  );

INSERT INTO quiz_attempts (
    quiz_id,
    learner_id,
    score,
    max_score,
    started_at,
    completed_at,
    time_spent_seconds,
    is_passed,
    attempt_number,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    q.quiz_id,
    u.user_id,
    82,
    100,
    TIMESTAMP '2026-03-30 18:31:00',
    TIMESTAMP '2026-03-30 18:36:00',
    280,
    TRUE,
    1,
    FALSE,
    TIMESTAMP '2026-03-30 18:31:00',
    TIMESTAMP '2026-03-30 18:36:00'
FROM quizzes q
JOIN users u ON u.email = 'learner3@devpath.com'
WHERE q.title = '[A-CASE-A] QUIZ'
  AND NOT EXISTS (
      SELECT 1
      FROM quiz_attempts qa
      WHERE qa.quiz_id = q.quiz_id
        AND qa.learner_id = u.user_id
        AND qa.attempt_number = 1
        AND qa.is_deleted = FALSE
  );

INSERT INTO quiz_attempts (
    quiz_id,
    learner_id,
    score,
    max_score,
    started_at,
    completed_at,
    time_spent_seconds,
    is_passed,
    attempt_number,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    q.quiz_id,
    u.user_id,
    90,
    100,
    TIMESTAMP '2026-03-30 18:32:00',
    TIMESTAMP '2026-03-30 18:37:00',
    260,
    TRUE,
    1,
    FALSE,
    TIMESTAMP '2026-03-30 18:32:00',
    TIMESTAMP '2026-03-30 18:37:00'
FROM quizzes q
JOIN users u ON u.email = 'learner@devpath.com'
WHERE q.title = '[A-CASE-B] QUIZ'
  AND NOT EXISTS (
      SELECT 1
      FROM quiz_attempts qa
      WHERE qa.quiz_id = q.quiz_id
        AND qa.learner_id = u.user_id
        AND qa.attempt_number = 1
        AND qa.is_deleted = FALSE
  );

INSERT INTO quiz_attempts (
    quiz_id,
    learner_id,
    score,
    max_score,
    started_at,
    completed_at,
    time_spent_seconds,
    is_passed,
    attempt_number,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    q.quiz_id,
    u.user_id,
    38,
    100,
    TIMESTAMP '2026-03-30 18:33:00',
    TIMESTAMP '2026-03-30 18:38:00',
    310,
    FALSE,
    1,
    FALSE,
    TIMESTAMP '2026-03-30 18:33:00',
    TIMESTAMP '2026-03-30 18:38:00'
FROM quizzes q
JOIN users u ON u.email = 'learner3@devpath.com'
WHERE q.title = '[A-CASE-B] QUIZ'
  AND NOT EXISTS (
      SELECT 1
      FROM quiz_attempts qa
      WHERE qa.quiz_id = q.quiz_id
        AND qa.learner_id = u.user_id
        AND qa.attempt_number = 1
        AND qa.is_deleted = FALSE
  );

INSERT INTO quiz_attempts (
    quiz_id,
    learner_id,
    score,
    max_score,
    started_at,
    completed_at,
    time_spent_seconds,
    is_passed,
    attempt_number,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    q.quiz_id,
    u.user_id,
    42,
    100,
    TIMESTAMP '2026-03-30 18:34:00',
    TIMESTAMP '2026-03-30 18:39:00',
    320,
    FALSE,
    1,
    FALSE,
    TIMESTAMP '2026-03-30 18:34:00',
    TIMESTAMP '2026-03-30 18:39:00'
FROM quizzes q
JOIN users u ON u.email = 'learner2@devpath.com'
WHERE q.title = '[A-CASE-C] QUIZ'
  AND NOT EXISTS (
      SELECT 1
      FROM quiz_attempts qa
      WHERE qa.quiz_id = q.quiz_id
        AND qa.learner_id = u.user_id
        AND qa.attempt_number = 1
        AND qa.is_deleted = FALSE
  );

INSERT INTO quiz_attempts (
    quiz_id,
    learner_id,
    score,
    max_score,
    started_at,
    completed_at,
    time_spent_seconds,
    is_passed,
    attempt_number,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    q.quiz_id,
    u.user_id,
    84,
    100,
    TIMESTAMP '2026-03-30 18:35:00',
    TIMESTAMP '2026-03-30 18:40:00',
    270,
    TRUE,
    1,
    FALSE,
    TIMESTAMP '2026-03-30 18:35:00',
    TIMESTAMP '2026-03-30 18:40:00'
FROM quizzes q
JOIN users u ON u.email = 'learner3@devpath.com'
WHERE q.title = '[A-CASE-C] QUIZ'
  AND NOT EXISTS (
      SELECT 1
      FROM quiz_attempts qa
      WHERE qa.quiz_id = q.quiz_id
        AND qa.learner_id = u.user_id
        AND qa.attempt_number = 1
        AND qa.is_deleted = FALSE
  );

INSERT INTO assignment_submissions (
    assignment_id,
    learner_id,
    grader_id,
    submission_text,
    submission_url,
    is_late,
    submission_status,
    submitted_at,
    graded_at,
    readme_passed,
    test_passed,
    lint_passed,
    file_format_passed,
    quality_score,
    total_score,
    individual_feedback,
    common_feedback,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    a.assignment_id,
    lu.user_id,
    iu.user_id,
    'Instructor analytics submission A-2',
    'https://github.com/devpath/instructor-analytics-a-2',
    FALSE,
    'GRADED',
    TIMESTAMP '2026-03-30 18:41:00',
    TIMESTAMP '2026-03-30 18:51:00',
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    61,
    58,
    'Needs stronger test coverage.',
    'A course analytics sample',
    FALSE,
    TIMESTAMP '2026-03-30 18:41:00',
    TIMESTAMP '2026-03-30 18:51:00'
FROM assignments a
JOIN users lu ON lu.email = 'learner2@devpath.com'
JOIN users iu ON iu.email = 'instructor@devpath.com'
WHERE a.title = '[A-CASE-A] ASSIGNMENT'
  AND NOT EXISTS (
      SELECT 1
      FROM assignment_submissions s
      WHERE s.assignment_id = a.assignment_id
        AND s.learner_id = lu.user_id
        AND s.submission_url = 'https://github.com/devpath/instructor-analytics-a-2'
        AND s.is_deleted = FALSE
  );

INSERT INTO assignment_submissions (
    assignment_id,
    learner_id,
    grader_id,
    submission_text,
    submission_url,
    is_late,
    submission_status,
    submitted_at,
    graded_at,
    readme_passed,
    test_passed,
    lint_passed,
    file_format_passed,
    quality_score,
    total_score,
    individual_feedback,
    common_feedback,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    a.assignment_id,
    lu.user_id,
    iu.user_id,
    'Instructor analytics submission A-3',
    'https://github.com/devpath/instructor-analytics-a-3',
    FALSE,
    'GRADED',
    TIMESTAMP '2026-03-30 18:42:00',
    TIMESTAMP '2026-03-30 18:52:00',
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    84,
    81,
    'Solid structure with minor gaps.',
    'A course analytics sample',
    FALSE,
    TIMESTAMP '2026-03-30 18:42:00',
    TIMESTAMP '2026-03-30 18:52:00'
FROM assignments a
JOIN users lu ON lu.email = 'learner3@devpath.com'
JOIN users iu ON iu.email = 'instructor@devpath.com'
WHERE a.title = '[A-CASE-A] ASSIGNMENT'
  AND NOT EXISTS (
      SELECT 1
      FROM assignment_submissions s
      WHERE s.assignment_id = a.assignment_id
        AND s.learner_id = lu.user_id
        AND s.submission_url = 'https://github.com/devpath/instructor-analytics-a-3'
        AND s.is_deleted = FALSE
  );

INSERT INTO assignment_submissions (
    assignment_id,
    learner_id,
    grader_id,
    submission_text,
    submission_url,
    is_late,
    submission_status,
    submitted_at,
    graded_at,
    readme_passed,
    test_passed,
    lint_passed,
    file_format_passed,
    quality_score,
    total_score,
    individual_feedback,
    common_feedback,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    a.assignment_id,
    lu.user_id,
    iu.user_id,
    'Instructor analytics submission B-1',
    'https://github.com/devpath/instructor-analytics-b-1',
    FALSE,
    'GRADED',
    TIMESTAMP '2026-03-30 18:43:00',
    TIMESTAMP '2026-03-30 18:53:00',
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    89,
    88,
    'Stable submission quality.',
    'B course analytics sample',
    FALSE,
    TIMESTAMP '2026-03-30 18:43:00',
    TIMESTAMP '2026-03-30 18:53:00'
FROM assignments a
JOIN users lu ON lu.email = 'learner@devpath.com'
JOIN users iu ON iu.email = 'instructor@devpath.com'
WHERE a.title = '[A-CASE-B] ASSIGNMENT'
  AND NOT EXISTS (
      SELECT 1
      FROM assignment_submissions s
      WHERE s.assignment_id = a.assignment_id
        AND s.learner_id = lu.user_id
        AND s.submission_url = 'https://github.com/devpath/instructor-analytics-b-1'
        AND s.is_deleted = FALSE
  );

INSERT INTO assignment_submissions (
    assignment_id,
    learner_id,
    grader_id,
    submission_text,
    submission_url,
    is_late,
    submission_status,
    submitted_at,
    graded_at,
    readme_passed,
    test_passed,
    lint_passed,
    file_format_passed,
    quality_score,
    total_score,
    individual_feedback,
    common_feedback,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    a.assignment_id,
    lu.user_id,
    NULL,
    'Instructor analytics submission B-3',
    'https://github.com/devpath/instructor-analytics-b-3',
    FALSE,
    'PRECHECK_FAILED',
    TIMESTAMP '2026-03-30 18:44:00',
    NULL,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    34,
    NULL,
    NULL,
    NULL,
    FALSE,
    TIMESTAMP '2026-03-30 18:44:00',
    TIMESTAMP '2026-03-30 18:44:00'
FROM assignments a
JOIN users lu ON lu.email = 'learner3@devpath.com'
WHERE a.title = '[A-CASE-B] ASSIGNMENT'
  AND NOT EXISTS (
      SELECT 1
      FROM assignment_submissions s
      WHERE s.assignment_id = a.assignment_id
        AND s.learner_id = lu.user_id
        AND s.submission_url = 'https://github.com/devpath/instructor-analytics-b-3'
        AND s.is_deleted = FALSE
  );

INSERT INTO assignment_submissions (
    assignment_id,
    learner_id,
    grader_id,
    submission_text,
    submission_url,
    is_late,
    submission_status,
    submitted_at,
    graded_at,
    readme_passed,
    test_passed,
    lint_passed,
    file_format_passed,
    quality_score,
    total_score,
    individual_feedback,
    common_feedback,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    a.assignment_id,
    lu.user_id,
    iu.user_id,
    'Instructor analytics submission C-2',
    'https://github.com/devpath/instructor-analytics-c-2',
    FALSE,
    'GRADED',
    TIMESTAMP '2026-03-30 18:45:00',
    TIMESTAMP '2026-03-30 18:55:00',
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    47,
    42,
    'Quality needs more work.',
    'C course analytics sample',
    FALSE,
    TIMESTAMP '2026-03-30 18:45:00',
    TIMESTAMP '2026-03-30 18:55:00'
FROM assignments a
JOIN users lu ON lu.email = 'learner2@devpath.com'
JOIN users iu ON iu.email = 'instructor@devpath.com'
WHERE a.title = '[A-CASE-C] ASSIGNMENT'
  AND NOT EXISTS (
      SELECT 1
      FROM assignment_submissions s
      WHERE s.assignment_id = a.assignment_id
        AND s.learner_id = lu.user_id
        AND s.submission_url = 'https://github.com/devpath/instructor-analytics-c-2'
        AND s.is_deleted = FALSE
  );

INSERT INTO assignment_submissions (
    assignment_id,
    learner_id,
    grader_id,
    submission_text,
    submission_url,
    is_late,
    submission_status,
    submitted_at,
    graded_at,
    readme_passed,
    test_passed,
    lint_passed,
    file_format_passed,
    quality_score,
    total_score,
    individual_feedback,
    common_feedback,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    a.assignment_id,
    lu.user_id,
    iu.user_id,
    'Instructor analytics submission C-3',
    'https://github.com/devpath/instructor-analytics-c-3',
    FALSE,
    'GRADED',
    TIMESTAMP '2026-03-30 18:46:00',
    TIMESTAMP '2026-03-30 18:56:00',
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    95,
    94,
    'Excellent submission quality.',
    'C course analytics sample',
    FALSE,
    TIMESTAMP '2026-03-30 18:46:00',
    TIMESTAMP '2026-03-30 18:56:00'
FROM assignments a
JOIN users lu ON lu.email = 'learner3@devpath.com'
JOIN users iu ON iu.email = 'instructor@devpath.com'
WHERE a.title = '[A-CASE-C] ASSIGNMENT'
  AND NOT EXISTS (
      SELECT 1
      FROM assignment_submissions s
      WHERE s.assignment_id = a.assignment_id
        AND s.learner_id = lu.user_id
        AND s.submission_url = 'https://github.com/devpath/instructor-analytics-c-3'
        AND s.is_deleted = FALSE
  );

-- ========================================
-- A-ADMIN LEARNING RULES AND METRICS
-- ========================================

INSERT INTO learning_automation_rules (
    rule_key,
    rule_name,
    description,
    rule_value,
    priority,
    rule_status,
    created_at,
    updated_at
)
SELECT
    'TAG_AUTO_CLASSIFICATION_ENABLED',
    'Tag auto classification rule',
    'Enables tag-based automatic course classification.',
    'true',
    20,
    'ENABLED',
    TIMESTAMP '2026-03-30 19:00:00',
    TIMESTAMP '2026-03-30 19:00:00'
WHERE NOT EXISTS (
    SELECT 1
    FROM learning_automation_rules r
    WHERE r.rule_key = 'TAG_AUTO_CLASSIFICATION_ENABLED'
);

INSERT INTO learning_automation_rules (
    rule_key,
    rule_name,
    description,
    rule_value,
    priority,
    rule_status,
    created_at,
    updated_at
)
SELECT
    'NODE_CLEARANCE_AUTO_JUDGE',
    'Node clearance auto judge rule',
    'Evaluates lessons, required tags, quizzes, and assignments together.',
    'LESSON_100_AND_REQUIRED_TAGS_AND_EVALUATION_PASS',
    21,
    'ENABLED',
    TIMESTAMP '2026-03-30 19:01:00',
    TIMESTAMP '2026-03-30 19:01:00'
WHERE NOT EXISTS (
    SELECT 1
    FROM learning_automation_rules r
    WHERE r.rule_key = 'NODE_CLEARANCE_AUTO_JUDGE'
);

INSERT INTO learning_automation_rules (
    rule_key,
    rule_name,
    description,
    rule_value,
    priority,
    rule_status,
    created_at,
    updated_at
)
SELECT
    'SUPPLEMENT_RECOMMENDATION_ENABLED',
    'Supplement recommendation rule',
    'Creates supplement recommendations from learning risk and tag gaps.',
    'true',
    22,
    'ENABLED',
    TIMESTAMP '2026-03-30 19:02:00',
    TIMESTAMP '2026-03-30 19:02:00'
WHERE NOT EXISTS (
    SELECT 1
    FROM learning_automation_rules r
    WHERE r.rule_key = 'SUPPLEMENT_RECOMMENDATION_ENABLED'
);

INSERT INTO learning_automation_rules (
    rule_key,
    rule_name,
    description,
    rule_value,
    priority,
    rule_status,
    created_at,
    updated_at
)
SELECT
    'PROOF_CARD_AUTO_ISSUE',
    'Proof card auto issue rule',
    'Auto-issues proof cards only for proof-eligible clearances.',
    'PROOF_ELIGIBLE_ONLY',
    23,
    'ENABLED',
    TIMESTAMP '2026-03-30 19:03:00',
    TIMESTAMP '2026-03-30 19:03:00'
WHERE NOT EXISTS (
    SELECT 1
    FROM learning_automation_rules r
    WHERE r.rule_key = 'PROOF_CARD_AUTO_ISSUE'
);

INSERT INTO learning_automation_rules (
    rule_key,
    rule_name,
    description,
    rule_value,
    priority,
    rule_status,
    created_at,
    updated_at
)
SELECT
    'PROOF_CARD_MANUAL_ISSUE',
    'Proof card manual issue rule',
    'Allows manual proof card issuance or re-issuance by admins.',
    'true',
    24,
    'DISABLED',
    TIMESTAMP '2026-03-30 19:04:00',
    TIMESTAMP '2026-03-30 19:04:00'
WHERE NOT EXISTS (
    SELECT 1
    FROM learning_automation_rules r
    WHERE r.rule_key = 'PROOF_CARD_MANUAL_ISSUE'
);

INSERT INTO learning_automation_rules (
    rule_key,
    rule_name,
    description,
    rule_value,
    priority,
    rule_status,
    created_at,
    updated_at
)
SELECT
    'RECOMMENDATION_CHANGE_ENABLED',
    'Recommendation change rule',
    'Enables recommendation change suggestion and apply flows.',
    'true',
    25,
    'ENABLED',
    TIMESTAMP '2026-03-30 19:05:00',
    TIMESTAMP '2026-03-30 19:05:00'
WHERE NOT EXISTS (
    SELECT 1
    FROM learning_automation_rules r
    WHERE r.rule_key = 'RECOMMENDATION_CHANGE_ENABLED'
);

INSERT INTO learning_metric_samples (
    course_id,
    metric_type,
    metric_label,
    metric_value,
    sampled_at,
    created_at
)
SELECT
    c.course_id,
    'OVERVIEW',
    'adminOverviewBaseline',
    72.4,
    TIMESTAMP '2026-03-30 19:10:00',
    TIMESTAMP '2026-03-30 19:10:00'
FROM courses c
WHERE c.title = '[A-CASE-A] Node Clearance Course'
  AND NOT EXISTS (
      SELECT 1
      FROM learning_metric_samples s
      WHERE s.course_id = c.course_id
        AND s.metric_type = 'OVERVIEW'
        AND s.metric_label = 'adminOverviewBaseline'
        AND s.sampled_at = TIMESTAMP '2026-03-30 19:10:00'
  );

INSERT INTO learning_metric_samples (
    course_id,
    metric_type,
    metric_label,
    metric_value,
    sampled_at,
    created_at
)
SELECT
    c.course_id,
    'COMPLETION_RATE',
    'roadmapCompletionRate',
    41.67,
    TIMESTAMP '2026-03-30 19:11:00',
    TIMESTAMP '2026-03-30 19:11:00'
FROM courses c
WHERE c.title = '[A-CASE-A] Node Clearance Course'
  AND NOT EXISTS (
      SELECT 1
      FROM learning_metric_samples s
      WHERE s.course_id = c.course_id
        AND s.metric_type = 'COMPLETION_RATE'
        AND s.metric_label = 'roadmapCompletionRate'
        AND s.sampled_at = TIMESTAMP '2026-03-30 19:11:00'
  );

INSERT INTO learning_metric_samples (
    course_id,
    metric_type,
    metric_label,
    metric_value,
    sampled_at,
    created_at
)
SELECT
    c.course_id,
    'AVERAGE_WATCH_TIME',
    'averageLearningDurationSeconds',
    611.67,
    TIMESTAMP '2026-03-30 19:12:00',
    TIMESTAMP '2026-03-30 19:12:00'
FROM courses c
WHERE c.title = '[A-CASE-A] Node Clearance Course'
  AND NOT EXISTS (
      SELECT 1
      FROM learning_metric_samples s
      WHERE s.course_id = c.course_id
        AND s.metric_type = 'AVERAGE_WATCH_TIME'
        AND s.metric_label = 'averageLearningDurationSeconds'
        AND s.sampled_at = TIMESTAMP '2026-03-30 19:12:00'
  );

INSERT INTO learning_metric_samples (
    course_id,
    metric_type,
    metric_label,
    metric_value,
    sampled_at,
    created_at
)
SELECT
    c.course_id,
    'QUIZ_STATS',
    'quizQualityScore',
    63.5,
    TIMESTAMP '2026-03-30 19:13:00',
    TIMESTAMP '2026-03-30 19:13:00'
FROM courses c
WHERE c.title = '[A-CASE-C] Quiz Fail Course'
  AND NOT EXISTS (
      SELECT 1
      FROM learning_metric_samples s
      WHERE s.course_id = c.course_id
        AND s.metric_type = 'QUIZ_STATS'
        AND s.metric_label = 'quizQualityScore'
        AND s.sampled_at = TIMESTAMP '2026-03-30 19:13:00'
  );

INSERT INTO learning_metric_samples (
    course_id,
    metric_type,
    metric_label,
    metric_value,
    sampled_at,
    created_at
)
SELECT
    c.course_id,
    'ASSIGNMENT_STATS',
    'assignmentAverageScore',
    76.8,
    TIMESTAMP '2026-03-30 19:14:00',
    TIMESTAMP '2026-03-30 19:14:00'
FROM courses c
WHERE c.title = '[A-CASE-B] Tag Missing Course'
  AND NOT EXISTS (
      SELECT 1
      FROM learning_metric_samples s
      WHERE s.course_id = c.course_id
        AND s.metric_type = 'ASSIGNMENT_STATS'
        AND s.metric_label = 'assignmentAverageScore'
        AND s.sampled_at = TIMESTAMP '2026-03-30 19:14:00'
  );

INSERT INTO learning_metric_samples (
    course_id,
    metric_type,
    metric_label,
    metric_value,
    sampled_at,
    created_at
)
SELECT
    c.course_id,
    'DROP_OFF',
    'dropOffRate',
    33.33,
    TIMESTAMP '2026-03-30 19:15:00',
    TIMESTAMP '2026-03-30 19:15:00'
FROM courses c
WHERE c.title = '[A-CASE-A] Node Clearance Course'
  AND NOT EXISTS (
      SELECT 1
      FROM learning_metric_samples s
      WHERE s.course_id = c.course_id
        AND s.metric_type = 'DROP_OFF'
        AND s.metric_label = 'dropOffRate'
        AND s.sampled_at = TIMESTAMP '2026-03-30 19:15:00'
  );

INSERT INTO learning_metric_samples (
    course_id,
    metric_type,
    metric_label,
    metric_value,
    sampled_at,
    created_at
)
SELECT
    c.course_id,
    'DIFFICULTY',
    'difficultyScore',
    58.2,
    TIMESTAMP '2026-03-30 19:16:00',
    TIMESTAMP '2026-03-30 19:16:00'
FROM courses c
WHERE c.title = '[A-CASE-C] Quiz Fail Course'
  AND NOT EXISTS (
      SELECT 1
      FROM learning_metric_samples s
      WHERE s.course_id = c.course_id
        AND s.metric_type = 'DIFFICULTY'
        AND s.metric_label = 'difficultyScore'
        AND s.sampled_at = TIMESTAMP '2026-03-30 19:16:00'
  );

INSERT INTO learning_metric_samples (
    course_id,
    metric_type,
    metric_label,
    metric_value,
    sampled_at,
    created_at
)
SELECT
    c.course_id,
    'FUNNEL',
    'completionFunnel',
    66.67,
    TIMESTAMP '2026-03-30 19:17:00',
    TIMESTAMP '2026-03-30 19:17:00'
FROM courses c
WHERE c.title = '[A-CASE-B] Tag Missing Course'
  AND NOT EXISTS (
      SELECT 1
      FROM learning_metric_samples s
      WHERE s.course_id = c.course_id
        AND s.metric_type = 'FUNNEL'
        AND s.metric_label = 'completionFunnel'
        AND s.sampled_at = TIMESTAMP '2026-03-30 19:17:00'
  );

INSERT INTO learning_metric_samples (
    course_id,
    metric_type,
    metric_label,
    metric_value,
    sampled_at,
    created_at
)
SELECT
    c.course_id,
    'WEAK_POINT',
    'weakPointRatio',
    29.4,
    TIMESTAMP '2026-03-30 19:18:00',
    TIMESTAMP '2026-03-30 19:18:00'
FROM courses c
WHERE c.title = '[A-CASE-C] Quiz Fail Course'
  AND NOT EXISTS (
      SELECT 1
      FROM learning_metric_samples s
      WHERE s.course_id = c.course_id
        AND s.metric_type = 'WEAK_POINT'
        AND s.metric_label = 'weakPointRatio'
        AND s.sampled_at = TIMESTAMP '2026-03-30 19:18:00'
  );

-- ========================================
-- A SECTION STABILITY FOOTER
-- ========================================

UPDATE tags
SET is_deleted = FALSE
WHERE is_deleted IS NULL;

UPDATE lesson_progress
SET is_pip_enabled = FALSE
WHERE is_pip_enabled IS NULL;

UPDATE quiz_attempts
SET is_deleted = FALSE
WHERE is_deleted IS NULL;

UPDATE assignment_submissions
SET is_deleted = FALSE
WHERE is_deleted IS NULL;

UPDATE til_drafts
SET is_deleted = FALSE
WHERE is_deleted IS NULL;

UPDATE timestamp_notes
SET is_deleted = FALSE
WHERE is_deleted IS NULL;

UPDATE learning_history_share_links
SET is_active = TRUE
WHERE is_active IS NULL;

SELECT setval(pg_get_serial_sequence('users', 'user_id'), COALESCE((SELECT MAX(user_id) FROM users), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('tags', 'tag_id'), COALESCE((SELECT MAX(tag_id) FROM tags), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('roadmap_nodes', 'node_id'), COALESCE((SELECT MAX(node_id) FROM roadmap_nodes), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('courses', 'course_id'), COALESCE((SELECT MAX(course_id) FROM courses), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('course_sections', 'section_id'), COALESCE((SELECT MAX(section_id) FROM course_sections), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('lessons', 'lesson_id'), COALESCE((SELECT MAX(lesson_id) FROM lessons), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('quizzes', 'quiz_id'), COALESCE((SELECT MAX(quiz_id) FROM quizzes), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('assignments', 'assignment_id'), COALESCE((SELECT MAX(assignment_id) FROM assignments), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('course_node_mappings', 'course_node_mapping_id'), COALESCE((SELECT MAX(course_node_mapping_id) FROM course_node_mappings), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('course_enrollments', 'enrollment_id'), COALESCE((SELECT MAX(enrollment_id) FROM course_enrollments), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('lesson_progress', 'progress_id'), COALESCE((SELECT MAX(progress_id) FROM lesson_progress), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('quiz_attempts', 'attempt_id'), COALESCE((SELECT MAX(attempt_id) FROM quiz_attempts), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('assignment_submissions', 'submission_id'), COALESCE((SELECT MAX(submission_id) FROM assignment_submissions), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('til_drafts', 'til_id'), COALESCE((SELECT MAX(til_id) FROM til_drafts), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('timestamp_notes', 'note_id'), COALESCE((SELECT MAX(note_id) FROM timestamp_notes), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('supplement_recommendations', 'recommendation_id'), COALESCE((SELECT MAX(recommendation_id) FROM supplement_recommendations), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('node_clearances', 'node_clearance_id'), COALESCE((SELECT MAX(node_clearance_id) FROM node_clearances), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('proof_cards', 'proof_card_id'), COALESCE((SELECT MAX(proof_card_id) FROM proof_cards), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('proof_card_shares', 'proof_card_share_id'), COALESCE((SELECT MAX(proof_card_share_id) FROM proof_card_shares), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('learning_history_share_links', 'learning_history_share_link_id'), COALESCE((SELECT MAX(learning_history_share_link_id) FROM learning_history_share_links), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('certificates', 'certificate_id'), COALESCE((SELECT MAX(certificate_id) FROM certificates), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('certificate_download_histories', 'certificate_download_history_id'), COALESCE((SELECT MAX(certificate_download_history_id) FROM certificate_download_histories), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('learning_automation_rules', 'learning_automation_rule_id'), COALESCE((SELECT MAX(learning_automation_rule_id) FROM learning_automation_rules), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('learning_metric_samples', 'learning_metric_sample_id'), COALESCE((SELECT MAX(learning_metric_sample_id) FROM learning_metric_samples), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('recommendation_changes', 'recommendation_change_id'), COALESCE((SELECT MAX(recommendation_change_id) FROM recommendation_changes), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('recommendation_histories', 'history_id'), COALESCE((SELECT MAX(history_id) FROM recommendation_histories), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('diagnosis_quizzes', 'quiz_id'), COALESCE((SELECT MAX(quiz_id) FROM diagnosis_quizzes), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('diagnosis_results', 'result_id'), COALESCE((SELECT MAX(result_id) FROM diagnosis_results), 0) + 1, false);
SELECT setval(pg_get_serial_sequence('risk_warnings', 'warning_id'), COALESCE((SELECT MAX(warning_id) FROM risk_warnings), 0) + 1, false);

INSERT INTO users (email, password, name, role_name, is_active, created_at, updated_at)
SELECT
    'learner4@devpath.com',
    '$2a$10$RcdWJBwl.kuttYmqm/BN..6aZKeLNlq9DiNFHbZgZxfTzzNDD33o2',
    '최유진',
    'ROLE_LEARNER',
    TRUE,
    NOW(),
    NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM users
    WHERE email = 'learner4@devpath.com'
);

UPDATE study_group
SET status = 'RECRUITING'
WHERE name = 'Spring Boot API Study Crew'
  AND is_deleted = FALSE;

UPDATE study_group
SET status = 'IN_PROGRESS'
WHERE name = 'Algorithm Deep Dive'
  AND is_deleted = FALSE;

INSERT INTO study_group_member (group_id, learner_id, join_status, joined_at)
SELECT
    sg.id,
    u.user_id,
    'PENDING',
    NULL
FROM study_group sg, users u
WHERE sg.name = 'Algorithm Deep Dive'
  AND u.email = 'learner3@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM study_group_member sgm
      WHERE sgm.group_id = sg.id
        AND sgm.learner_id = u.user_id
  );

INSERT INTO study_group_member (group_id, learner_id, join_status, joined_at)
SELECT
    sg.id,
    u.user_id,
    'PENDING',
    NULL
FROM study_group sg, users u
WHERE sg.name = 'Spring Boot API Study Crew'
  AND u.email = 'learner4@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM study_group_member sgm
      WHERE sgm.group_id = sg.id
        AND sgm.learner_id = u.user_id
  );

INSERT INTO learner_notification (learner_id, type, message, is_read, created_at)
SELECT
    u.user_id,
    'STUDY_GROUP',
    'Algorithm Deep Dive 스터디 참여 신청이 접수되었습니다.',
    FALSE,
    '2026-03-30 09:10:00'
FROM users u
WHERE u.email = 'learner3@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM learner_notification n
      WHERE n.learner_id = u.user_id
        AND n.message = 'Algorithm Deep Dive 스터디 참여 신청이 접수되었습니다.'
  );

INSERT INTO learner_notification (learner_id, type, message, is_read, created_at)
SELECT
    u.user_id,
    'PROJECT',
    'DevPath Team Workspace 프로젝트 초대가 도착했습니다.',
    FALSE,
    '2026-03-30 10:00:00'
FROM users u
WHERE u.email = 'learner3@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM learner_notification n
      WHERE n.learner_id = u.user_id
        AND n.message = 'DevPath Team Workspace 프로젝트 초대가 도착했습니다.'
  );

INSERT INTO learner_notification (learner_id, type, message, is_read, created_at)
SELECT
    u.user_id,
    'PLANNER',
    '이번 주 학습 플랜 조정이 완료되었습니다.',
    TRUE,
    '2026-03-30 10:30:00'
FROM users u
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM learner_notification n
      WHERE n.learner_id = u.user_id
        AND n.message = '이번 주 학습 플랜 조정이 완료되었습니다.'
  );

UPDATE streak
SET current_streak = 5,
    longest_streak = GREATEST(longest_streak, 5),
    last_study_date = DATE '2026-03-30'
WHERE learner_id = (
    SELECT user_id
    FROM users
    WHERE email = 'learner@devpath.com'
);

INSERT INTO recovery_plan (learner_id, plan_details, created_at)
SELECT
    u.user_id,
    '복귀 플랜: 오늘 30분 복습, 내일 1시간 실습, 모레 스터디 발표 준비',
    '2026-03-30 07:00:00'
FROM users u
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM recovery_plan rp
      WHERE rp.learner_id = u.user_id
        AND rp.plan_details = '복귀 플랜: 오늘 30분 복습, 내일 1시간 실습, 모레 스터디 발표 준비'
  );

UPDATE project_invitation
SET status = 'PENDING'
WHERE project_id = (
    SELECT id
    FROM project
    WHERE name = 'DevPath Team Workspace'
      AND is_deleted = FALSE
)
AND invitee_id = (
    SELECT user_id
    FROM users
    WHERE email = 'learner3@devpath.com'
);

INSERT INTO project_role (project_id, role_type, required_count)
SELECT
    p.id,
    'DESIGNER',
    1
FROM project p
WHERE p.name = 'DevPath Team Workspace'
  AND NOT EXISTS (
      SELECT 1
      FROM project_role pr
      WHERE pr.project_id = p.id
        AND pr.role_type = 'DESIGNER'
  );

INSERT INTO mentoring_application (project_id, mentor_id, message, status, created_at)
SELECT
    p.id,
    mentor.user_id,
    '프로젝트 API 설계 리뷰와 시연 흐름 검토가 필요합니다.',
    'PENDING',
    '2026-03-30 11:00:00'
FROM project p, users mentor
WHERE p.name = 'DevPath Team Workspace'
  AND mentor.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM mentoring_application ma
      WHERE ma.project_id = p.id
        AND ma.message = '프로젝트 API 설계 리뷰와 시연 흐름 검토가 필요합니다.'
  );

INSERT INTO project_idea_post (author_id, title, content, status, is_deleted, created_at)
SELECT
    u.user_id,
    '스터디 그룹-프로젝트 연동 아이디어',
    '같은 노드 학습자 자동 매칭 후 프로젝트 팀 빌딩으로 자연스럽게 이어지는 흐름을 제안합니다.',
    'PUBLISHED',
    FALSE,
    '2026-03-30 12:00:00'
FROM users u
WHERE u.email = 'learner3@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM project_idea_post pip
      WHERE pip.author_id = u.user_id
        AND pip.title = '스터디 그룹-프로젝트 연동 아이디어'
  );

INSERT INTO project_proof_submission (project_id, submitter_id, proof_card_ref_id, submitted_at)
SELECT
    p.id,
    u.user_id,
    'PROOF-C-004',
    '2026-03-30 12:30:00'
FROM project p, users u
WHERE p.name = 'DevPath Team Workspace'
  AND u.email = 'learner3@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM project_proof_submission pps
      WHERE pps.project_id = p.id
        AND pps.submitter_id = u.user_id
        AND pps.proof_card_ref_id = 'PROOF-C-004'
  );

SELECT setval('users_user_id_seq', (SELECT COALESCE(MAX(user_id), 1) FROM users));
SELECT setval('study_group_member_id_seq', (SELECT COALESCE(MAX(id), 1) FROM study_group_member));
SELECT setval('learner_notification_id_seq', (SELECT COALESCE(MAX(id), 1) FROM learner_notification));
SELECT setval('recovery_plan_id_seq', (SELECT COALESCE(MAX(id), 1) FROM recovery_plan));
SELECT setval('project_role_id_seq', (SELECT COALESCE(MAX(id), 1) FROM project_role));
SELECT setval('mentoring_application_id_seq', (SELECT COALESCE(MAX(id), 1) FROM mentoring_application));
SELECT setval('project_idea_post_id_seq', (SELECT COALESCE(MAX(id), 1) FROM project_idea_post));
SELECT setval('project_proof_submission_id_seq', (SELECT COALESCE(MAX(id), 1) FROM project_proof_submission));

-- ============================================================
-- Backend Master Roadmap 노드 전면 교체 (기존 영문 노드 → 한국어 상세 노드)
-- ============================================================

-- Backend Master Roadmap 노드 삭제 전 모든 FK 의존 테이블 정리
-- 완전한 FK 체인 순서 (가장 깊은 자식 → 부모 순)
-- 1단계: quiz_answers (quiz_attempts, quiz_questions, quiz_question_options 참조)
DELETE FROM quiz_answers
WHERE attempt_id IN (
    SELECT qa.attempt_id FROM quiz_attempts qa
    WHERE qa.quiz_id IN (
        SELECT quiz_id FROM quizzes
        WHERE node_id IN (SELECT node_id FROM roadmap_nodes
            WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap'))
    )
);

-- 2단계: quiz_question_options (quiz_questions 참조)
DELETE FROM quiz_question_options
WHERE question_id IN (
    SELECT qq.question_id FROM quiz_questions qq
    WHERE qq.quiz_id IN (
        SELECT quiz_id FROM quizzes
        WHERE node_id IN (SELECT node_id FROM roadmap_nodes
            WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap'))
    )
);

-- 3단계: quiz_attempts (quizzes 참조)
DELETE FROM quiz_attempts
WHERE quiz_id IN (
    SELECT quiz_id FROM quizzes
    WHERE node_id IN (SELECT node_id FROM roadmap_nodes
        WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap'))
);

-- 4단계: quiz_questions (quizzes 참조)
DELETE FROM quiz_questions
WHERE quiz_id IN (
    SELECT quiz_id FROM quizzes
    WHERE node_id IN (SELECT node_id FROM roadmap_nodes
        WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap'))
);

-- 5단계: quizzes (roadmap_nodes 참조)
DELETE FROM quizzes
WHERE node_id IN (
    SELECT node_id FROM roadmap_nodes
    WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap')
);

-- 6단계: assignment_submission_files (assignment_submissions 참조)
DELETE FROM assignment_submission_files
WHERE submission_id IN (
    SELECT s.submission_id FROM assignment_submissions s
    WHERE s.assignment_id IN (
        SELECT assignment_id FROM assignments
        WHERE node_id IN (SELECT node_id FROM roadmap_nodes
            WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap'))
    )
);

-- 7단계: assignment_submissions (assignments 참조)
DELETE FROM assignment_submissions
WHERE assignment_id IN (
    SELECT assignment_id FROM assignments
    WHERE node_id IN (SELECT node_id FROM roadmap_nodes
        WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap'))
);

-- 8단계: assignment_rubrics (assignments 참조)
DELETE FROM assignment_rubrics
WHERE assignment_id IN (
    SELECT assignment_id FROM assignments
    WHERE node_id IN (SELECT node_id FROM roadmap_nodes
        WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap'))
);

-- 9단계: assignments (roadmap_nodes 참조)
DELETE FROM assignments
WHERE node_id IN (
    SELECT node_id FROM roadmap_nodes
    WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap')
);

-- 10단계: certificate_download_histories (certificates 참조)
DELETE FROM certificate_download_histories
WHERE certificate_id IN (
    SELECT c.certificate_id FROM certificates c
    JOIN proof_cards pc ON pc.proof_card_id = c.proof_card_id
    WHERE pc.node_id IN (
        SELECT node_id FROM roadmap_nodes
        WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap')
    )
);

-- 11단계: certificates (proof_cards 참조)
DELETE FROM certificates
WHERE proof_card_id IN (
    SELECT pc.proof_card_id FROM proof_cards pc
    WHERE pc.node_id IN (
        SELECT node_id FROM roadmap_nodes
        WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap')
    )
);

-- 12단계: proof_card_shares, proof_card_tags (proof_cards 참조)
DELETE FROM proof_card_shares
WHERE proof_card_id IN (
    SELECT pc.proof_card_id FROM proof_cards pc
    WHERE pc.node_id IN (
        SELECT node_id FROM roadmap_nodes
        WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap')
    )
);

DELETE FROM proof_card_tags
WHERE proof_card_id IN (
    SELECT pc.proof_card_id FROM proof_cards pc
    WHERE pc.node_id IN (
        SELECT node_id FROM roadmap_nodes
        WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap')
    )
);

-- 13단계: proof_cards (roadmap_nodes, node_clearances 참조)
DELETE FROM proof_cards
WHERE node_id IN (
    SELECT node_id FROM roadmap_nodes
    WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap')
);

-- 14단계: node_clearance_reasons (node_clearances 참조)
DELETE FROM node_clearance_reasons
WHERE node_clearance_id IN (
    SELECT nc.node_clearance_id FROM node_clearances nc
    WHERE nc.node_id IN (
        SELECT node_id FROM roadmap_nodes
        WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap')
    )
);

-- 15단계: node_clearances (roadmap_nodes 참조)
DELETE FROM node_clearances
WHERE node_id IN (
    SELECT node_id FROM roadmap_nodes
    WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap')
);

-- 16단계: course_node_mappings (roadmap_nodes 참조)
DELETE FROM course_node_mappings
WHERE node_id IN (
    SELECT node_id FROM roadmap_nodes
    WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap')
);

-- 17단계: recommendation_changes, recommendation_histories, risk_warnings, supplement_recommendations
DELETE FROM recommendation_changes
WHERE node_id IN (
    SELECT node_id FROM roadmap_nodes
    WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap')
);

DELETE FROM recommendation_histories
WHERE node_id IN (
    SELECT node_id FROM roadmap_nodes
    WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap')
);

DELETE FROM risk_warnings
WHERE node_id IN (
    SELECT node_id FROM roadmap_nodes
    WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap')
);

DELETE FROM supplement_recommendations
WHERE node_id IN (
    SELECT node_id FROM roadmap_nodes
    WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap')
);

-- 18단계: node_completion_rules, node_recommendations, node_required_tags
DELETE FROM node_completion_rules
WHERE node_id IN (
    SELECT node_id FROM roadmap_nodes
    WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap')
);

DELETE FROM node_recommendations
WHERE node_id IN (
    SELECT node_id FROM roadmap_nodes
    WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap')
);

DELETE FROM node_required_tags
WHERE node_id IN (
    SELECT node_id FROM roadmap_nodes
    WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap')
);

-- 19단계: custom_node_prerequisites (custom_roadmap_nodes 참조)
DELETE FROM custom_node_prerequisites
WHERE custom_node_id IN (
    SELECT crn.custom_node_id FROM custom_roadmap_nodes crn
    WHERE crn.original_node_id IN (
        SELECT node_id FROM roadmap_nodes
        WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap')
    )
) OR prerequisite_custom_node_id IN (
    SELECT crn.custom_node_id FROM custom_roadmap_nodes crn
    WHERE crn.original_node_id IN (
        SELECT node_id FROM roadmap_nodes
        WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap')
    )
);

-- 20단계: custom_roadmap_nodes (roadmap_nodes 참조)
DELETE FROM custom_roadmap_nodes
WHERE original_node_id IN (
    SELECT node_id FROM roadmap_nodes
    WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap')
);

-- 21단계: custom_roadmaps (roadmaps 참조)
DELETE FROM custom_roadmaps
WHERE original_roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap');

-- 22단계: roadmap_node_resources (roadmap_nodes 참조)
DELETE FROM roadmap_node_resources
WHERE node_id IN (
    SELECT node_id FROM roadmap_nodes
    WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap')
);

-- 23단계: roadmap_nodes 삭제 (모든 자식 정리 완료)
DELETE FROM roadmap_nodes
WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap');

-- 척추 노드 (lane_key = NULL)
INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, lane_key)
SELECT r.roadmap_id, '인터넷 & 웹 기초',
       '백엔드 개발자는 브라우저 요청이 DNS 조회, TCP/TLS 연결, HTTP 요청/응답을 거쳐 서버 애플리케이션까지 도달하는 흐름을 이해해야 합니다. 이 단계에서는 URL을 입력했을 때 어떤 네트워크 계층을 지나고 서버가 어떤 기준으로 응답을 만드는지 익힙니다.',
       'CONCEPT', 1, 'HTTP 요청/응답: 클라이언트가 리소스를 요청하고 서버가 상태 코드와 본문을 돌려주는 구조,DNS: 도메인 이름을 실제 서버 IP로 찾는 이름 해석 시스템,HTTPS와 TLS: 통신 내용을 암호화하고 서버 신뢰성을 검증하는 보안 계층,브라우저와 서버 흐름: URL 입력부터 렌더링 직전까지 이어지는 전체 요청 경로', NULL
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, lane_key)
SELECT r.roadmap_id, 'OS & 터미널',
       '운영체제는 백엔드 애플리케이션이 실제로 실행되는 바닥입니다. 파일 권한, 프로세스, 포트, 로그, 환경 변수, 메모리 사용량을 터미널에서 확인할 수 있어야 장애 상황에서 원인을 좁힐 수 있습니다.',
       'CONCEPT', 2, '프로세스와 스레드: 프로그램 실행 단위와 동시 처리의 기본 구조,파일 시스템과 권한: 서버 파일 위치와 읽기 쓰기 실행 권한을 다루는 기준,셸 명령과 파이프: 로그 확인과 배포 작업을 자동화하는 터미널 활용법,포트와 I/O: 네트워크 연결과 입출력 자원이 애플리케이션에 미치는 영향', NULL
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, lane_key)
SELECT r.roadmap_id, 'Java 기초',
       'Spring Boot를 제대로 쓰려면 Java 문법을 단순 암기보다 객체 모델과 타입 시스템 관점에서 이해해야 합니다. 클래스, 인터페이스, 컬렉션, 예외 처리, 제네릭을 익히면 서비스 계층과 도메인 코드를 안정적으로 설계할 수 있습니다.',
       'CONCEPT', 3, 'JVM: Java 코드가 운영체제와 무관하게 실행되는 런타임 구조,OOP: 책임을 가진 객체들이 협력하도록 코드를 나누는 설계 방식,컬렉션 프레임워크: List Set Map으로 데이터를 목적에 맞게 다루는 표준 도구,예외 처리: 실패 상황을 호출 흐름 안에서 명확하게 다루는 방법,제네릭: 타입 안정성을 유지하면서 재사용 가능한 코드를 만드는 문법', NULL
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, lane_key)
SELECT r.roadmap_id, 'Git & 버전 관리',
       'Git은 코드 저장 도구를 넘어 팀 작업의 변경 이력과 의사결정을 남기는 시스템입니다. 브랜치 전략, 커밋 단위, PR 리뷰 흐름을 이해하면 기능 개발과 버그 수정이 섞이지 않고 안전하게 배포할 수 있습니다.',
       'PRACTICE', 4, '커밋: 의미 있는 변경 단위를 기록하는 기본 단위,브랜치: 기능 개발과 배포 라인을 분리하는 작업 공간,Pull Request: 코드 리뷰와 변경 검증을 거쳐 병합하는 협업 절차,충돌 해결: 같은 코드 영역의 변경을 사람이 판단해 정리하는 과정', NULL
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, lane_key)
SELECT r.roadmap_id, 'RDB & SQL',
       '대부분의 백엔드 서비스는 관계형 데이터베이스에 핵심 데이터를 저장합니다. 테이블 설계, JOIN, 인덱스, 트랜잭션을 이해해야 데이터 정합성을 지키면서도 조회 성능을 유지할 수 있습니다.',
       'CONCEPT', 5, '테이블과 관계: 데이터를 행과 열로 저장하고 외래키로 연결하는 구조,JOIN: 여러 테이블에 나뉜 데이터를 하나의 결과로 조합하는 방법,인덱스: 조회 속도를 높이지만 쓰기 비용을 함께 고려해야 하는 자료구조,트랜잭션과 ACID: 여러 데이터 변경을 하나의 안전한 작업 단위로 묶는 원칙', NULL
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, lane_key)
SELECT r.roadmap_id, 'REST API 설계',
       'REST API는 프론트엔드와 백엔드가 약속하는 가장 흔한 통신 규칙입니다. URI를 리소스 중심으로 설계하고 HTTP 메서드와 상태 코드를 일관되게 쓰면 클라이언트가 예측 가능한 API를 사용할 수 있습니다.',
       'CONCEPT', 6, '리소스 중심 URI: 행위보다 대상을 기준으로 API 주소를 설계하는 방식,HTTP 메서드: GET POST PUT PATCH DELETE의 의도를 구분하는 약속,상태 코드: 요청 결과를 숫자로 명확하게 전달하는 표준,OpenAPI: API 사용법과 스키마를 문서로 공유하는 명세', NULL
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, lane_key)
SELECT r.roadmap_id, 'Spring Boot & MVC',
       'Spring Boot는 설정 부담을 줄여 애플리케이션을 빠르게 띄우고 Spring MVC는 요청이 컨트롤러까지 도달하는 웹 계층 흐름을 담당합니다. DI, Bean, DispatcherServlet, 계층 구조를 이해해야 기능이 커져도 코드가 무너지지 않습니다.',
       'CONCEPT', 7, 'DI와 IoC: 객체 생성과 의존성 연결을 프레임워크가 관리하는 구조,Bean: Spring 컨테이너가 생명주기를 관리하는 객체,DispatcherServlet: HTTP 요청을 컨트롤러로 라우팅하는 MVC의 중심 진입점,3계층 구조: Controller Service Repository로 책임을 나누는 기본 설계', NULL
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, lane_key)
SELECT r.roadmap_id, 'Spring Data JPA',
       'JPA는 객체 중심 코드와 관계형 데이터베이스 사이의 차이를 줄여주는 ORM 기술입니다. 엔티티 매핑과 연관관계를 제대로 잡지 못하면 N+1, 영속성 컨텍스트, 트랜잭션 경계 문제로 성능과 데이터 정합성이 흔들릴 수 있습니다.',
       'CONCEPT', 8, 'Entity 매핑: 객체 필드와 데이터베이스 테이블 컬럼을 연결하는 규칙,연관관계: 객체 참조와 외래키 관계를 일관되게 표현하는 방법,영속성 컨텍스트: 엔티티 변경을 추적하고 DB 반영 시점을 관리하는 공간,Fetch 전략: 연관 데이터를 즉시 가져올지 늦게 가져올지 정하는 기준,N+1 문제: 반복 조회로 SQL이 과도하게 발생하는 성능 문제', NULL
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

-- 분기 노드 (sort 9-10, 좌: Redis, 우: 테스트)
INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, lane_key)
SELECT r.roadmap_id, 'Redis 기초',
       'Redis는 단순 캐시 저장소가 아니라 빠른 읽기 쓰기와 다양한 자료구조를 제공하는 인메모리 데이터 저장소입니다. 캐시, 랭킹, 임시 토큰, 카운터처럼 응답 속도가 중요한 기능에서 TTL과 자료구조 선택이 핵심입니다.',
       'PRACTICE', 9, '인메모리 저장소: 디스크보다 빠른 메모리에 데이터를 보관하는 방식,String Hash List Set ZSet: 목적에 따라 선택하는 Redis 핵심 자료구조,TTL: 일정 시간이 지나면 데이터를 자동 삭제하는 만료 전략,캐시 전략: DB 부하를 줄이기 위해 자주 읽는 데이터를 임시 저장하는 방식', 1
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, lane_key)
SELECT r.roadmap_id, 'Redis 심화',
       'Redis를 서비스 운영에 깊게 쓰면 세션 저장, 토큰 무효화, Pub/Sub, 분산 락처럼 여러 서버가 공유해야 하는 상태를 다루게 됩니다. 특히 분산 환경에서는 락 만료 시간과 장애 상황을 고려하지 않으면 중복 처리나 데이터 꼬임이 생길 수 있습니다.',
       'PRACTICE', 10, '세션 저장: 여러 서버가 같은 로그인 상태를 공유하도록 저장하는 방식,JWT 블랙리스트: 만료 전 토큰을 강제로 무효화하기 위한 차단 목록,Pub/Sub: 발행자와 구독자가 메시지를 비동기로 주고받는 패턴,분산 락: 여러 인스턴스가 같은 작업을 동시에 처리하지 못하게 막는 장치', 1
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, lane_key)
SELECT r.roadmap_id, 'JUnit5 & Mockito',
       '테스트 코드는 기능이 의도대로 동작하는지 반복해서 확인하게 해주는 안전장치입니다. JUnit5로 테스트 구조를 만들고 Mockito로 외부 의존성을 대체하면 서비스 로직을 빠르고 독립적으로 검증할 수 있습니다.',
       'PRACTICE', 9, '테스트 생명주기: 테스트 실행 전후 준비와 정리를 관리하는 흐름,Assertion: 실제 결과가 기대값과 맞는지 검증하는 표현,Mock과 Spy: 외부 의존성이나 일부 동작을 테스트용 객체로 대체하는 방법,verify: 협력 객체가 기대한 방식으로 호출됐는지 확인하는 검증', 2
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, lane_key)
SELECT r.roadmap_id, 'Spring Boot 테스트',
       'Spring 애플리케이션은 단위 테스트만으로는 필터, 컨트롤러, DI 설정, DB 연동 흐름을 모두 검증하기 어렵습니다. 테스트 슬라이스와 통합 테스트를 구분해서 사용하면 빠른 피드백과 실제 동작 검증을 균형 있게 가져갈 수 있습니다.',
       'PRACTICE', 10, '@SpringBootTest: 전체 애플리케이션 컨텍스트를 띄워 통합 흐름을 확인하는 테스트,@WebMvcTest: 웹 계층만 가볍게 띄워 컨트롤러 요청 응답을 검증하는 테스트,MockMvc: 실제 서버 없이 MVC 요청을 시뮬레이션하는 도구,TestRestTemplate: 테스트 환경에서 실제 HTTP 호출 흐름을 확인하는 도구', 2
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

-- 척추 뒷부분 (sort 11-15, lane_key = NULL)
INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, lane_key)
SELECT r.roadmap_id, 'Spring Security & JWT',
       '인증과 인가는 사용자가 누구인지 확인하고 어떤 기능을 쓸 수 있는지 결정하는 백엔드 핵심 영역입니다. Spring Security의 필터 체인과 JWT 흐름을 이해해야 로그인, 토큰 재발급, 권한 체크, OAuth2 연동을 안전하게 구현할 수 있습니다.',
       'CONCEPT', 11, '인증과 인가: 사용자의 신원 확인과 접근 권한 판단을 구분하는 개념,SecurityFilterChain: 요청이 컨트롤러에 도달하기 전 보안 처리를 수행하는 필터 흐름,JWT: 서버 세션 없이 인증 정보를 전달하는 토큰 형식,OAuth2 로그인: 외부 제공자의 인증 결과를 서비스 로그인으로 연결하는 방식', NULL
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, lane_key)
SELECT r.roadmap_id, 'Docker & CI/CD',
       'Docker는 애플리케이션 실행 환경을 이미지로 고정해 개발 PC와 서버의 차이를 줄여줍니다. CI/CD 파이프라인까지 연결하면 코드 변경이 테스트, 이미지 빌드, 배포 단계로 자동 이어져 반복 작업과 실수를 줄일 수 있습니다.',
       'PRACTICE', 12, '이미지와 컨테이너: 실행 환경을 패키징하고 독립된 프로세스로 실행하는 단위,Dockerfile: 애플리케이션 이미지를 만드는 빌드 절차 정의서,docker-compose: 여러 컨테이너를 한 번에 실행하고 연결하는 설정,GitHub Actions: 코드 변경을 기준으로 빌드 테스트 배포를 자동화하는 도구', NULL
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, lane_key)
SELECT r.roadmap_id, 'SOLID & 디자인패턴',
       '객체지향 설계 원칙과 디자인 패턴은 코드가 커질수록 변경 비용을 낮추기 위한 공통 언어입니다. SOLID를 기준으로 책임을 나누고 반복되는 문제에는 검증된 패턴을 적용하면 서비스 로직의 결합도를 줄일 수 있습니다.',
       'CONCEPT', 13, 'SRP: 하나의 클래스가 하나의 변경 이유만 갖도록 책임을 분리하는 원칙,OCP: 기존 코드를 덜 수정하고 확장으로 기능을 추가하는 원칙,DIP: 구체 구현보다 추상에 의존해 결합도를 낮추는 원칙,전략 패턴: 실행 시점에 알고리즘이나 정책을 바꿔 끼우는 패턴,팩토리 패턴: 객체 생성 책임을 별도 구성 요소로 분리하는 패턴', NULL
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, lane_key)
SELECT r.roadmap_id, '웹 보안 기초',
       '웹 보안은 기능이 완성된 뒤 덧붙이는 작업이 아니라 API 설계부터 함께 고려해야 하는 기본 조건입니다. OWASP Top 10, XSS, CSRF, SQL Injection, CORS, HTTPS를 이해하면 흔한 공격 경로를 줄이고 안전한 기본값을 만들 수 있습니다.',
       'CONCEPT', 14, 'XSS: 악성 스크립트가 사용자 브라우저에서 실행되는 공격,CSRF: 로그인된 사용자의 권한으로 원치 않는 요청을 보내게 만드는 공격,SQL Injection: 입력값으로 SQL을 조작해 데이터를 탈취하거나 변경하는 공격,CORS: 브라우저가 다른 출처 요청을 제한하고 허용하는 보안 정책,HTTPS와 TLS: 네트워크 구간에서 데이터 변조와 도청을 줄이는 암호화 계층', NULL
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, lane_key)
SELECT r.roadmap_id, '메시지 큐 & MSA',
       '메시지 큐와 MSA는 서비스가 커졌을 때 기능을 분리하고 비동기 처리를 안정적으로 운영하기 위한 선택지입니다. Kafka의 Topic, Producer, Consumer 흐름과 API Gateway의 진입점 역할을 이해하면 서비스 간 결합을 줄이면서 확장할 수 있습니다.',
       'CONCEPT', 15, '메시지 큐: 작업을 즉시 처리하지 않고 큐에 쌓아 비동기로 처리하는 구조,Kafka Topic과 Partition: 메시지를 분류하고 병렬 처리를 가능하게 하는 저장 단위,Producer와 Consumer: 메시지를 발행하고 읽어 처리하는 구성 요소,API Gateway: 여러 서비스 앞에서 라우팅 인증 공통 처리를 담당하는 진입점,서비스 분리 기준: 하나의 기능을 독립 서비스로 나눌지 판단하는 경계', NULL
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

-- Backend Master Roadmap 노드 추천 무료 자료
INSERT INTO roadmap_node_resources
    (node_id, title, url, description, source_type, sort_order, active, created_at, updated_at)
SELECT rn.node_id,
       resources.title,
       resources.url,
       resources.description,
       resources.source_type,
       resources.sort_order,
       TRUE,
       NOW(),
       NOW()
FROM roadmap_nodes rn
JOIN roadmaps r ON r.roadmap_id = rn.roadmap_id
JOIN (
    VALUES
        ('인터넷 & 웹 기초', 'MDN HTTP 개요', 'https://developer.mozilla.org/en-US/docs/Web/HTTP', 'HTTP 메시지, 메서드, 상태 코드와 브라우저-서버 통신 흐름을 정리합니다.', 'DOCS', 1),
        ('인터넷 & 웹 기초', 'MDN DNS 용어', 'https://developer.mozilla.org/en-US/docs/Glossary/DNS', 'DNS가 도메인 이름을 IP 주소로 해석하는 기본 흐름을 확인합니다.', 'DOCS', 2),
        ('OS & 터미널', 'GNU Bash Manual', 'https://www.gnu.org/software/bash/manual/bash.html', '셸 명령, 파이프, 리다이렉션과 스크립트 기초를 공식 매뉴얼로 확인합니다.', 'OFFICIAL', 1),
        ('OS & 터미널', 'Linux man-pages intro', 'https://man7.org/linux/man-pages/man1/intro.1.html', 'Linux 명령어 매뉴얼 구조와 터미널 도움말 읽는 법을 익힙니다.', 'DOCS', 2),
        ('Java 기초', 'Oracle Java Tutorials', 'https://docs.oracle.com/javase/tutorial/java/index.html', '클래스, 객체, 상속, 인터페이스 등 Java 언어 기본기를 공식 튜토리얼로 학습합니다.', 'OFFICIAL', 1),
        ('Java 기초', 'Java SE API Documentation', 'https://docs.oracle.com/en/java/javase/21/docs/api/index.html', '표준 라이브러리와 컬렉션 API를 실제 문서 기준으로 찾아봅니다.', 'OFFICIAL', 2),
        ('Git & 버전 관리', 'Pro Git Book', 'https://git-scm.com/book/en/v2', 'Git의 커밋, 브랜치, 병합, 리베이스를 공식 무료 책으로 학습합니다.', 'OFFICIAL', 1),
        ('Git & 버전 관리', 'GitHub Git 시작하기', 'https://docs.github.com/en/get-started/using-git/about-git', 'GitHub 기반 협업에서 Git이 어떻게 쓰이는지 확인합니다.', 'OFFICIAL', 2),
        ('RDB & SQL', 'PostgreSQL SQL Tutorial', 'https://www.postgresql.org/docs/current/tutorial-sql.html', 'SELECT, WHERE, JOIN 등 SQL 기본 문법을 PostgreSQL 공식 문서로 학습합니다.', 'OFFICIAL', 1),
        ('RDB & SQL', 'PostgreSQL Transactions', 'https://www.postgresql.org/docs/current/tutorial-transactions.html', '트랜잭션과 ACID 흐름을 공식 튜토리얼로 확인합니다.', 'OFFICIAL', 2),
        ('REST API 설계', 'HTTP Semantics RFC 9110', 'https://www.rfc-editor.org/rfc/rfc9110.html', 'HTTP 메서드, 상태 코드, 캐싱 등 REST API 설계의 기반이 되는 표준 문서입니다.', 'OFFICIAL', 1),
        ('REST API 설계', 'OpenAPI Specification', 'https://spec.openapis.org/oas/latest.html', 'OpenAPI 3 문서화 구조와 스키마 작성 방식을 확인합니다.', 'OFFICIAL', 2),
        ('Spring Boot & MVC', 'Spring Framework MVC Reference', 'https://docs.spring.io/spring-framework/reference/web/webmvc.html', 'DispatcherServlet, Controller, 요청 매핑 등 Spring MVC 핵심 흐름을 학습합니다.', 'OFFICIAL', 1),
        ('Spring Boot & MVC', 'Spring Framework IoC Container', 'https://docs.spring.io/spring-framework/reference/core/beans/introduction.html', 'Bean, DI, IoC 컨테이너 개념을 Spring 공식 문서로 확인합니다.', 'OFFICIAL', 2),
        ('Spring Data JPA', 'Spring Data JPA Reference', 'https://docs.spring.io/spring-data/jpa/reference/', 'Repository, 쿼리 메서드, JPA 연동 방식을 공식 문서로 학습합니다.', 'OFFICIAL', 1),
        ('Spring Data JPA', 'Hibernate ORM User Guide', 'https://docs.hibernate.org/orm/current/userguide/html_single/', '엔티티 매핑, 연관관계, Fetch 전략과 N+1 문제의 기반을 확인합니다.', 'OFFICIAL', 2),
        ('Redis 기초', 'Redis Data Types', 'https://redis.io/docs/latest/develop/data-types/', 'String, Hash, List, Set, Sorted Set 등 Redis 핵심 자료구조를 확인합니다.', 'OFFICIAL', 1),
        ('Redis 기초', 'Redis EXPIRE', 'https://redis.io/docs/latest/commands/expire/', 'TTL과 만료 정책을 Redis 공식 명령 문서로 확인합니다.', 'OFFICIAL', 2),
        ('Redis 심화', 'Redis Pub/Sub', 'https://redis.io/docs/latest/develop/pubsub/', 'Pub/Sub 메시징 패턴과 구독 흐름을 공식 문서로 학습합니다.', 'OFFICIAL', 1),
        ('Redis 심화', 'Redisson Locks and Synchronizers', 'https://redisson.pro/docs/data-and-services/locks-and-synchronizers/', '분산 락 구현에 자주 쓰이는 Redisson 락 API를 확인합니다.', 'DOCS', 2),
        ('JUnit5 & Mockito', 'JUnit 5 User Guide', 'https://junit.org/junit5/docs/5.10.3/user-guide/index.html', '테스트 생명주기, assertion, parameterized test 등 JUnit 5 사용법을 확인합니다.', 'OFFICIAL', 1),
        ('JUnit5 & Mockito', 'Mockito Documentation', 'https://site.mockito.org/', 'Mock, Spy, verify 기반 단위 테스트 작성 흐름을 확인합니다.', 'OFFICIAL', 2),
        ('Spring Boot 테스트', 'Spring Boot Testing Reference', 'https://docs.spring.io/spring-boot/reference/testing/index.html', '@SpringBootTest, test slice, MockMvc 연동 등 Spring Boot 테스트 구성을 확인합니다.', 'OFFICIAL', 1),
        ('Spring Boot 테스트', 'Spring Framework MockMvc', 'https://docs.spring.io/spring-framework/reference/testing/mockmvc.html', 'MockMvc로 컨트롤러 테스트를 작성하는 공식 예제를 확인합니다.', 'OFFICIAL', 2),
        ('Spring Security & JWT', 'Spring Security Reference', 'https://docs.spring.io/spring-security/reference/index.html', 'SecurityFilterChain, 인증/인가, OAuth2 리소스 서버 구성을 공식 문서로 확인합니다.', 'OFFICIAL', 1),
        ('Spring Security & JWT', 'JSON Web Token RFC 7519', 'https://www.rfc-editor.org/rfc/rfc7519.html', 'JWT 구조와 클레임 규칙을 표준 문서로 확인합니다.', 'OFFICIAL', 2),
        ('Docker & CI/CD', 'Dockerfile Reference', 'https://docs.docker.com/reference/dockerfile/', 'Dockerfile 명령어와 이미지 빌드 방식을 공식 문서로 학습합니다.', 'OFFICIAL', 1),
        ('Docker & CI/CD', 'GitHub Actions Documentation', 'https://docs.github.com/en/actions', '워크플로우, job, step 기반 CI/CD 파이프라인 구성을 확인합니다.', 'OFFICIAL', 2),
        ('SOLID & 디자인패턴', 'Refactoring Guru Design Patterns', 'https://refactoring.guru/design-patterns', 'Singleton, Factory, Strategy, Observer 등 GoF 패턴을 예제로 확인합니다.', 'DOCS', 1),
        ('SOLID & 디자인패턴', 'Java Design Patterns', 'https://java-design-patterns.com/', 'Java 코드 기반 디자인 패턴 구현 예시를 무료로 살펴봅니다.', 'DOCS', 2),
        ('웹 보안 기초', 'OWASP Top 10', 'https://owasp.org/www-project-top-ten/', '웹 애플리케이션 주요 보안 위험과 대응 방향을 공식 프로젝트에서 확인합니다.', 'OFFICIAL', 1),
        ('웹 보안 기초', 'MDN CORS Guide', 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS', '브라우저 CORS 동작 방식과 서버 설정 흐름을 확인합니다.', 'DOCS', 2),
        ('메시지 큐 & MSA', 'Apache Kafka Documentation', 'https://kafka.apache.org/documentation/', 'Topic, Producer, Consumer, Broker 개념과 메시징 흐름을 공식 문서로 학습합니다.', 'OFFICIAL', 1),
        ('메시지 큐 & MSA', 'Spring Cloud Gateway Reference', 'https://docs.spring.io/spring-cloud-gateway/reference/', 'API Gateway 라우팅, 필터, 서비스 진입점 패턴을 확인합니다.', 'OFFICIAL', 2)
) AS resources(node_title, title, url, description, source_type, sort_order)
  ON resources.node_title = rn.title
WHERE r.title = 'Backend Master Roadmap'
  AND NOT EXISTS (
      SELECT 1
      FROM roadmap_node_resources existing
      WHERE existing.node_id = rn.node_id
        AND existing.url = resources.url
  );

-- learner@devpath.com 커스텀 로드맵 재생성
INSERT INTO custom_roadmaps (user_id, original_roadmap_id, title, progress_rate, is_builder_origin, created_at, updated_at)
SELECT u.user_id, r.roadmap_id, r.title, 0, false,
       TIMESTAMP '2026-03-28 10:00:00', TIMESTAMP '2026-03-28 10:00:00'
FROM users u
JOIN roadmaps r ON r.title = 'Backend Master Roadmap'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM custom_roadmaps cr
      WHERE cr.user_id = u.user_id AND cr.original_roadmap_id = r.roadmap_id
  );

INSERT INTO custom_roadmap_nodes (custom_roadmap_id, original_node_id, status, custom_sort_order, started_at, completed_at)
SELECT cr.custom_roadmap_id,
       rn.node_id,
       CASE
           WHEN rn.sort_order <= 2 THEN 'COMPLETED'
           WHEN rn.sort_order = 3  THEN 'IN_PROGRESS'
           ELSE 'NOT_STARTED'
       END,
       rn.sort_order,
       CASE WHEN rn.sort_order <= 3 THEN TIMESTAMP '2026-03-28 10:00:00' ELSE NULL END,
       CASE WHEN rn.sort_order <= 2 THEN TIMESTAMP '2026-03-29 18:00:00' ELSE NULL END
FROM custom_roadmaps cr
JOIN users u ON u.user_id = cr.user_id
JOIN roadmaps r ON r.roadmap_id = cr.original_roadmap_id
JOIN roadmap_nodes rn ON rn.roadmap_id = r.roadmap_id
WHERE u.email = 'learner@devpath.com'
  AND r.title = 'Backend Master Roadmap'
  AND NOT EXISTS (
      SELECT 1 FROM custom_roadmap_nodes crn
      WHERE crn.custom_roadmap_id = cr.custom_roadmap_id
        AND crn.original_node_id = rn.node_id
  );

-- sort 1, 2 노드 NodeClearance 레코드 (CLEARED 상태)
INSERT INTO node_clearances
    (user_id, node_id, clearance_status, lesson_completion_rate, required_tags_satisfied,
     missing_tag_count, lesson_completed, quiz_passed, assignment_passed, proof_eligible,
     cleared_at, last_calculated_at, created_at, updated_at)
SELECT u.user_id, rn.node_id,
       'CLEARED', 1.00, TRUE, 0, TRUE, TRUE, TRUE, TRUE,
       TIMESTAMP '2026-03-29 18:00:00',
       TIMESTAMP '2026-03-29 18:00:00',
       TIMESTAMP '2026-03-29 18:00:00',
       TIMESTAMP '2026-03-29 18:00:00'
FROM users u
JOIN roadmaps r ON r.title = 'Backend Master Roadmap'
JOIN roadmap_nodes rn ON rn.roadmap_id = r.roadmap_id AND rn.sort_order <= 2
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM node_clearances nc
      WHERE nc.user_id = u.user_id AND nc.node_id = rn.node_id
  );


-- ========================================
-- Backend Master Roadmap 노드 필수 태그 (sub_topics 기반 정제)
-- ========================================

-- 신규 태그 추가
INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'DNS', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'DNS');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT '도메인', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = '도메인');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT '웹 호스팅', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = '웹 호스팅');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT '브라우저', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = '브라우저');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT '프로세스 관리', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = '프로세스 관리');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT '스레드', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = '스레드');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT '메모리 관리', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = '메모리 관리');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'I/O 관리', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'I/O 관리');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'OOP', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'OOP');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT '상속', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = '상속');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT '인터페이스', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = '인터페이스');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT '제네릭', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = '제네릭');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT '컬렉션', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = '컬렉션');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'Git', 'DevOps', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'Git');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT '브랜치 전략', 'DevOps', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = '브랜치 전략');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'GitFlow', 'DevOps', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'GitFlow');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'Pull Request', 'DevOps', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'Pull Request');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT '코드 리뷰', 'DevOps', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = '코드 리뷰');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'SQL', 'Database', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'SQL');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'JOIN', 'Database', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'JOIN');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT '서브쿼리', 'Database', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = '서브쿼리');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT '인덱스', 'Database', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = '인덱스');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT '트랜잭션', 'Database', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = '트랜잭션');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'REST', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'REST');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'URI 설계', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'URI 설계');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'HTTP 메서드', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'HTTP 메서드');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'HTTP 상태코드', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'HTTP 상태코드');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'Swagger', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'Swagger');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'DI/IoC', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'DI/IoC');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'Spring Bean', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'Spring Bean');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'Spring MVC', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'Spring MVC');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT '3계층 구조', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = '3계층 구조');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'Entity 매핑', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'Entity 매핑');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'JPQL', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'JPQL');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'FetchType', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'FetchType');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'N+1 문제', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'N+1 문제');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'QueryDSL', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'QueryDSL');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'Redis 자료구조', 'Database', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'Redis 자료구조');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'Redis TTL', 'Database', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'Redis TTL');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'Spring Cache', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'Spring Cache');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'Redis Session', 'Database', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'Redis Session');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'Pub/Sub', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'Pub/Sub');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT '분산 락', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = '분산 락');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'JUnit5', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'JUnit5');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'Mockito', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'Mockito');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'BDD', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'BDD');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT '단위 테스트', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = '단위 테스트');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'MockMvc', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'MockMvc');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT '통합 테스트', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = '통합 테스트');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT '테스트 커버리지', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = '테스트 커버리지');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'OAuth2', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'OAuth2');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT '소셜 로그인', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = '소셜 로그인');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'docker-compose', 'DevOps', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'docker-compose');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'GitHub Actions', 'DevOps', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'GitHub Actions');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'CI/CD', 'DevOps', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'CI/CD');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'AWS EC2', 'DevOps', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'AWS EC2');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'SOLID 원칙', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'SOLID 원칙');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT '디자인 패턴', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = '디자인 패턴');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'Singleton', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'Singleton');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'Factory 패턴', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'Factory 패턴');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'Strategy 패턴', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'Strategy 패턴');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'OWASP', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'OWASP');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'XSS', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'XSS');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'CSRF', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'CSRF');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'SQL Injection', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'SQL Injection');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'HTTPS', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'HTTPS');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'CORS', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'CORS');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'Kafka', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'Kafka');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'Kafka 토픽', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'Kafka 토픽');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'MSA', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'MSA');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'API Gateway', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'API Gateway');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT '서비스 분리', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = '서비스 분리');

-- 노드별 필수 태그 연결
-- 인터넷 & 웹 기초
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = '인터넷 & 웹 기초' AND t.name = 'HTTP'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = '인터넷 & 웹 기초' AND t.name = 'DNS'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = '인터넷 & 웹 기초' AND t.name = '도메인'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = '인터넷 & 웹 기초' AND t.name = '웹 호스팅'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = '인터넷 & 웹 기초' AND t.name = '브라우저'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- OS & 터미널
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'OS & 터미널' AND t.name = 'Linux'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'OS & 터미널' AND t.name = '프로세스 관리'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'OS & 터미널' AND t.name = '스레드'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'OS & 터미널' AND t.name = '메모리 관리'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'OS & 터미널' AND t.name = 'I/O 관리'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- Java 기초
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Java 기초' AND t.name = 'Java'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Java 기초' AND t.name = 'OOP'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Java 기초' AND t.name = '상속'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Java 기초' AND t.name = '인터페이스'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Java 기초' AND t.name = '제네릭'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Java 기초' AND t.name = '컬렉션'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- Git & 버전 관리
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Git & 버전 관리' AND t.name = 'Git'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Git & 버전 관리' AND t.name = '브랜치 전략'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Git & 버전 관리' AND t.name = 'GitFlow'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Git & 버전 관리' AND t.name = 'Pull Request'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Git & 버전 관리' AND t.name = '코드 리뷰'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- RDB & SQL
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'RDB & SQL' AND t.name = 'SQL'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'RDB & SQL' AND t.name = 'JOIN'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'RDB & SQL' AND t.name = '서브쿼리'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'RDB & SQL' AND t.name = '인덱스'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'RDB & SQL' AND t.name = '트랜잭션'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'RDB & SQL' AND t.name = 'PostgreSQL'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- REST API 설계
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'REST API 설계' AND t.name = 'REST'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'REST API 설계' AND t.name = 'HTTP'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'REST API 설계' AND t.name = 'URI 설계'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'REST API 설계' AND t.name = 'HTTP 메서드'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'REST API 설계' AND t.name = 'HTTP 상태코드'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'REST API 설계' AND t.name = 'Swagger'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- Spring Boot & MVC
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Spring Boot & MVC' AND t.name = 'Spring Boot'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Spring Boot & MVC' AND t.name = 'DI/IoC'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Spring Boot & MVC' AND t.name = 'Spring Bean'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Spring Boot & MVC' AND t.name = 'Spring MVC'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Spring Boot & MVC' AND t.name = '3계층 구조'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- Spring Data JPA
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Spring Data JPA' AND t.name = 'JPA'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Spring Data JPA' AND t.name = 'Entity 매핑'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Spring Data JPA' AND t.name = 'JPQL'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Spring Data JPA' AND t.name = 'FetchType'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Spring Data JPA' AND t.name = 'N+1 문제'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Spring Data JPA' AND t.name = 'QueryDSL'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- Redis 기초
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Redis 기초' AND t.name = 'Redis'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Redis 기초' AND t.name = 'Redis 자료구조'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Redis 기초' AND t.name = 'Redis TTL'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Redis 기초' AND t.name = 'Spring Cache'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- Redis 심화
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Redis 심화' AND t.name = 'Redis'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Redis 심화' AND t.name = 'Redis Session'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Redis 심화' AND t.name = 'Pub/Sub'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Redis 심화' AND t.name = '분산 락'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- JUnit5 & Mockito
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'JUnit5 & Mockito' AND t.name = 'JUnit5'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'JUnit5 & Mockito' AND t.name = 'Mockito'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'JUnit5 & Mockito' AND t.name = 'BDD'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'JUnit5 & Mockito' AND t.name = '단위 테스트'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- Spring Boot 테스트
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Spring Boot 테스트' AND t.name = 'Spring Boot'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Spring Boot 테스트' AND t.name = 'MockMvc'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Spring Boot 테스트' AND t.name = '통합 테스트'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Spring Boot 테스트' AND t.name = '테스트 커버리지'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- Spring Security & JWT
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Spring Security & JWT' AND t.name = 'Spring Security'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Spring Security & JWT' AND t.name = 'JWT'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Spring Security & JWT' AND t.name = 'OAuth2'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Spring Security & JWT' AND t.name = '소셜 로그인'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- Docker & CI/CD
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Docker & CI/CD' AND t.name = 'Docker'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Docker & CI/CD' AND t.name = 'docker-compose'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Docker & CI/CD' AND t.name = 'GitHub Actions'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Docker & CI/CD' AND t.name = 'CI/CD'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Docker & CI/CD' AND t.name = 'AWS EC2'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- SOLID & 디자인패턴
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'SOLID & 디자인패턴' AND t.name = 'SOLID 원칙'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'SOLID & 디자인패턴' AND t.name = '디자인 패턴'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'SOLID & 디자인패턴' AND t.name = 'Singleton'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'SOLID & 디자인패턴' AND t.name = 'Factory 패턴'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'SOLID & 디자인패턴' AND t.name = 'Strategy 패턴'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- 웹 보안 기초
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = '웹 보안 기초' AND t.name = 'OWASP'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = '웹 보안 기초' AND t.name = 'XSS'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = '웹 보안 기초' AND t.name = 'CSRF'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = '웹 보안 기초' AND t.name = 'SQL Injection'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = '웹 보안 기초' AND t.name = 'HTTPS'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = '웹 보안 기초' AND t.name = 'CORS'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- 메시지 큐 & MSA
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = '메시지 큐 & MSA' AND t.name = 'Kafka'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = '메시지 큐 & MSA' AND t.name = 'Kafka 토픽'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = '메시지 큐 & MSA' AND t.name = 'MSA'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = '메시지 큐 & MSA' AND t.name = 'API Gateway'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = '메시지 큐 & MSA' AND t.name = '서비스 분리'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- learner 기술 스택: 클리어 노드 + Java 기초 필수 태그 전체 보유
INSERT INTO user_tech_stacks (user_id, tag_id)
SELECT u.user_id, t.tag_id FROM users u, tags t
WHERE u.email = 'learner@devpath.com' AND t.name = 'HTTP'
  AND NOT EXISTS (SELECT 1 FROM user_tech_stacks uts WHERE uts.user_id = u.user_id AND uts.tag_id = t.tag_id);
INSERT INTO user_tech_stacks (user_id, tag_id)
SELECT u.user_id, t.tag_id FROM users u, tags t
WHERE u.email = 'learner@devpath.com' AND t.name = 'DNS'
  AND NOT EXISTS (SELECT 1 FROM user_tech_stacks uts WHERE uts.user_id = u.user_id AND uts.tag_id = t.tag_id);
INSERT INTO user_tech_stacks (user_id, tag_id)
SELECT u.user_id, t.tag_id FROM users u, tags t
WHERE u.email = 'learner@devpath.com' AND t.name = '도메인'
  AND NOT EXISTS (SELECT 1 FROM user_tech_stacks uts WHERE uts.user_id = u.user_id AND uts.tag_id = t.tag_id);
INSERT INTO user_tech_stacks (user_id, tag_id)
SELECT u.user_id, t.tag_id FROM users u, tags t
WHERE u.email = 'learner@devpath.com' AND t.name = '웹 호스팅'
  AND NOT EXISTS (SELECT 1 FROM user_tech_stacks uts WHERE uts.user_id = u.user_id AND uts.tag_id = t.tag_id);
INSERT INTO user_tech_stacks (user_id, tag_id)
SELECT u.user_id, t.tag_id FROM users u, tags t
WHERE u.email = 'learner@devpath.com' AND t.name = '브라우저'
  AND NOT EXISTS (SELECT 1 FROM user_tech_stacks uts WHERE uts.user_id = u.user_id AND uts.tag_id = t.tag_id);
INSERT INTO user_tech_stacks (user_id, tag_id)
SELECT u.user_id, t.tag_id FROM users u, tags t
WHERE u.email = 'learner@devpath.com' AND t.name = 'Linux'
  AND NOT EXISTS (SELECT 1 FROM user_tech_stacks uts WHERE uts.user_id = u.user_id AND uts.tag_id = t.tag_id);
INSERT INTO user_tech_stacks (user_id, tag_id)
SELECT u.user_id, t.tag_id FROM users u, tags t
WHERE u.email = 'learner@devpath.com' AND t.name = '프로세스 관리'
  AND NOT EXISTS (SELECT 1 FROM user_tech_stacks uts WHERE uts.user_id = u.user_id AND uts.tag_id = t.tag_id);
INSERT INTO user_tech_stacks (user_id, tag_id)
SELECT u.user_id, t.tag_id FROM users u, tags t
WHERE u.email = 'learner@devpath.com' AND t.name = '스레드'
  AND NOT EXISTS (SELECT 1 FROM user_tech_stacks uts WHERE uts.user_id = u.user_id AND uts.tag_id = t.tag_id);
INSERT INTO user_tech_stacks (user_id, tag_id)
SELECT u.user_id, t.tag_id FROM users u, tags t
WHERE u.email = 'learner@devpath.com' AND t.name = '메모리 관리'
  AND NOT EXISTS (SELECT 1 FROM user_tech_stacks uts WHERE uts.user_id = u.user_id AND uts.tag_id = t.tag_id);
INSERT INTO user_tech_stacks (user_id, tag_id)
SELECT u.user_id, t.tag_id FROM users u, tags t
WHERE u.email = 'learner@devpath.com' AND t.name = 'I/O 관리'
  AND NOT EXISTS (SELECT 1 FROM user_tech_stacks uts WHERE uts.user_id = u.user_id AND uts.tag_id = t.tag_id);
INSERT INTO user_tech_stacks (user_id, tag_id)
SELECT u.user_id, t.tag_id FROM users u, tags t
WHERE u.email = 'learner@devpath.com' AND t.name = 'Java'
  AND NOT EXISTS (SELECT 1 FROM user_tech_stacks uts WHERE uts.user_id = u.user_id AND uts.tag_id = t.tag_id);
INSERT INTO user_tech_stacks (user_id, tag_id)
SELECT u.user_id, t.tag_id FROM users u, tags t
WHERE u.email = 'learner@devpath.com' AND t.name = 'OOP'
  AND NOT EXISTS (SELECT 1 FROM user_tech_stacks uts WHERE uts.user_id = u.user_id AND uts.tag_id = t.tag_id);
INSERT INTO user_tech_stacks (user_id, tag_id)
SELECT u.user_id, t.tag_id FROM users u, tags t
WHERE u.email = 'learner@devpath.com' AND t.name = '상속'
  AND NOT EXISTS (SELECT 1 FROM user_tech_stacks uts WHERE uts.user_id = u.user_id AND uts.tag_id = t.tag_id);
INSERT INTO user_tech_stacks (user_id, tag_id)
SELECT u.user_id, t.tag_id FROM users u, tags t
WHERE u.email = 'learner@devpath.com' AND t.name = '인터페이스'
  AND NOT EXISTS (SELECT 1 FROM user_tech_stacks uts WHERE uts.user_id = u.user_id AND uts.tag_id = t.tag_id);
INSERT INTO user_tech_stacks (user_id, tag_id)
SELECT u.user_id, t.tag_id FROM users u, tags t
WHERE u.email = 'learner@devpath.com' AND t.name = '제네릭'
  AND NOT EXISTS (SELECT 1 FROM user_tech_stacks uts WHERE uts.user_id = u.user_id AND uts.tag_id = t.tag_id);
INSERT INTO user_tech_stacks (user_id, tag_id)
SELECT u.user_id, t.tag_id FROM users u, tags t
WHERE u.email = 'learner@devpath.com' AND t.name = '컬렉션'
  AND NOT EXISTS (SELECT 1 FROM user_tech_stacks uts WHERE uts.user_id = u.user_id AND uts.tag_id = t.tag_id);

-- Java 기초 node_clearances: 태그 모두 충족, 레슨 80% 진행, 아직 미클리어
-- (진단 퀴즈 추천 테스트용 — 클리어 처리 시 추천 로직 동작 확인)
INSERT INTO node_clearances
    (user_id, node_id, clearance_status, lesson_completion_rate, required_tags_satisfied,
     missing_tag_count, lesson_completed, quiz_passed, assignment_passed, proof_eligible,
     cleared_at, last_calculated_at, created_at, updated_at)
SELECT u.user_id, rn.node_id,
       'NOT_CLEARED', 0.80, TRUE, 0, FALSE, FALSE, FALSE, FALSE,
       NULL,
       TIMESTAMP '2026-04-10 12:00:00',
       TIMESTAMP '2026-04-10 12:00:00',
       TIMESTAMP '2026-04-10 12:00:00'
FROM users u
JOIN roadmaps r ON r.title = 'Backend Master Roadmap'
JOIN roadmap_nodes rn ON rn.roadmap_id = r.roadmap_id AND rn.title = 'Java 기초'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM node_clearances nc
      WHERE nc.user_id = u.user_id AND nc.node_id = rn.node_id
  );

-- ========================================
-- learner@devpath.com Proof Card 샘플 데이터
-- (인터넷 & 웹 기초, OS & 터미널 — CLEARED 노드 기준)
-- ========================================

INSERT INTO proof_cards (user_id, node_id, node_clearance_id, title, description, proof_card_status, issued_at, created_at, updated_at)
SELECT u.user_id, rn.node_id, nc.node_clearance_id,
       '인터넷 & 웹 기초 수료',
       '인터넷 동작 원리, HTTP, DNS, 웹 호스팅 개념을 학습하고 검증받았습니다.',
       'ISSUED',
       TIMESTAMP '2026-03-29 18:00:00',
       TIMESTAMP '2026-03-29 18:00:00',
       TIMESTAMP '2026-03-29 18:00:00'
FROM users u
JOIN roadmaps r ON r.title = 'Backend Master Roadmap'
JOIN roadmap_nodes rn ON rn.roadmap_id = r.roadmap_id AND rn.title = '인터넷 & 웹 기초'
JOIN node_clearances nc ON nc.user_id = u.user_id AND nc.node_id = rn.node_id
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM proof_cards pc
      WHERE pc.user_id = u.user_id AND pc.node_id = rn.node_id
  );

INSERT INTO proof_cards (user_id, node_id, node_clearance_id, title, description, proof_card_status, issued_at, created_at, updated_at)
SELECT u.user_id, rn.node_id, nc.node_clearance_id,
       'OS & 터미널 수료',
       'Linux 명령어, 프로세스/스레드, 메모리·I/O 관리를 학습하고 검증받았습니다.',
       'ISSUED',
       TIMESTAMP '2026-03-29 19:00:00',
       TIMESTAMP '2026-03-29 19:00:00',
       TIMESTAMP '2026-03-29 19:00:00'
FROM users u
JOIN roadmaps r ON r.title = 'Backend Master Roadmap'
JOIN roadmap_nodes rn ON rn.roadmap_id = r.roadmap_id AND rn.title = 'OS & 터미널'
JOIN node_clearances nc ON nc.user_id = u.user_id AND nc.node_id = rn.node_id
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM proof_cards pc
      WHERE pc.user_id = u.user_id AND pc.node_id = rn.node_id
  );

-- proof_card_tags: 인터넷 & 웹 기초
INSERT INTO proof_card_tags (proof_card_id, tag_id, skill_evidence_type)
SELECT pc.proof_card_id, t.tag_id, 'VERIFIED'
FROM proof_cards pc
JOIN users u ON u.user_id = pc.user_id AND u.email = 'learner@devpath.com'
JOIN roadmap_nodes rn ON rn.node_id = pc.node_id AND rn.title = '인터넷 & 웹 기초'
JOIN tags t ON t.name IN ('HTTP', 'DNS', '도메인', '웹 호스팅', '브라우저')
WHERE NOT EXISTS (
    SELECT 1 FROM proof_card_tags pct
    WHERE pct.proof_card_id = pc.proof_card_id AND pct.tag_id = t.tag_id
);

-- proof_card_tags: OS & 터미널
INSERT INTO proof_card_tags (proof_card_id, tag_id, skill_evidence_type)
SELECT pc.proof_card_id, t.tag_id, 'VERIFIED'
FROM proof_cards pc
JOIN users u ON u.user_id = pc.user_id AND u.email = 'learner@devpath.com'
JOIN roadmap_nodes rn ON rn.node_id = pc.node_id AND rn.title = 'OS & 터미널'
JOIN tags t ON t.name IN ('Linux', '프로세스 관리', '스레드', '메모리 관리', 'I/O 관리')
WHERE NOT EXISTS (
    SELECT 1 FROM proof_card_tags pct
    WHERE pct.proof_card_id = pc.proof_card_id AND pct.tag_id = t.tag_id
);
-- ============================================================
-- [TEST DATA END]
-- ============================================================

-- ============================================================
-- SAMPLE VIDEO DATA: 로컬 샘플 영상 연결 (개발/테스트용)
-- public/samples/ 에 있는 영상 파일을 video_url로 지정
-- ============================================================

-- 기존 Spring Boot Intro 강의에 로컬 샘플 영상 연결
UPDATE lessons
SET video_url = '/samples/lesson-spring-di.mp4',
    duration_seconds = 20,
    thumbnail_url = 'https://images.unsplash.com/photo-1517694712202-14dd9538aa97?auto=format&fit=crop&w=800&q=60'
WHERE title = 'Understanding DI and IoC';

UPDATE lessons
SET video_url = '/samples/lesson-spring-bean.mp4',
    duration_seconds = 20,
    thumbnail_url = 'https://images.unsplash.com/photo-1517694712202-14dd9538aa97?auto=format&fit=crop&w=800&q=60'
WHERE title = 'Bean registration and lifecycle';

UPDATE lessons
SET video_url = '/samples/lesson-os-context.mp4',
    duration_seconds = 20,
    thumbnail_url = 'https://images.unsplash.com/photo-1555066931-4365d14bab8c?auto=format&fit=crop&w=800&q=60'
WHERE title = 'Entity relationships and mapping';

-- 운영체제 이해하기 강의 (학습 플레이어 UI 확인용)
INSERT INTO courses (
    instructor_id, title, subtitle, description,
    thumbnail_url, intro_video_url, video_asset_key,
    duration_seconds, price, original_price, currency,
    difficulty_level, language, has_certificate, status, published_at
)
SELECT
    u.user_id,
    '운영체제 이해하기',
    'CS 핵심: 프로세스, 스레드, 메모리 관리',
    '백엔드·시스템 프로그래밍 입문자를 위한 운영체제 핵심 개념 강의입니다. 프로세스·스레드 구조부터 컨텍스트 스위칭, 메모리 관리까지 실무에 필요한 OS 지식을 다룹니다.',
    'https://images.unsplash.com/photo-1518770660439-4636190af475?auto=format&fit=crop&w=1200&q=80',
    '/samples/sample-intro.mp4',
    NULL,
    60,
    89000, 119000, 'KRW',
    'BEGINNER', 'ko', TRUE, 'PUBLISHED', TIMESTAMP '2026-03-01 10:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM courses WHERE title = '운영체제 이해하기');

-- 섹션 1: 운영체제 기초
INSERT INTO course_sections (course_id, title, description, sort_order, is_published)
SELECT c.course_id, '운영체제 기초', 'OS 개념, 프로세스, 스레드', 1, TRUE
FROM courses c
WHERE c.title = '운영체제 이해하기'
  AND NOT EXISTS (
      SELECT 1 FROM course_sections cs
      WHERE cs.course_id = c.course_id AND cs.sort_order = 1
  );

-- 강의 1: OS란 무엇인가? (미리보기 허용, OCR 테스트용 영상)
INSERT INTO lessons (
    section_id, title, description, lesson_type,
    video_url, video_asset_key, video_provider,
    thumbnail_url, duration_seconds, is_preview, is_published, sort_order
)
SELECT
    cs.section_id,
    'OS란 무엇인가?',
    '운영체제의 역할과 구성요소를 소개합니다.',
    'VIDEO',
    '/samples/ocr-code-demo.mp4',
    NULL, NULL,
    'https://images.unsplash.com/photo-1518770660439-4636190af475?auto=format&fit=crop&w=800&q=60',
    14, TRUE, TRUE, 1
FROM course_sections cs
JOIN courses c ON c.course_id = cs.course_id
WHERE c.title = '운영체제 이해하기' AND cs.sort_order = 1
  AND NOT EXISTS (
      SELECT 1 FROM lessons l WHERE l.section_id = cs.section_id AND l.sort_order = 1
  );

-- 강의 2: 프로세스와 스레드의 이해 (OCR 테스트용 영상)
INSERT INTO lessons (
    section_id, title, description, lesson_type,
    video_url, video_asset_key, video_provider,
    thumbnail_url, duration_seconds, is_preview, is_published, sort_order
)
SELECT
    cs.section_id,
    '프로세스와 스레드의 이해',
    'PCB 구조, 스레드 모델, 생성 비용 차이를 설명합니다.',
    'VIDEO',
    '/samples/ocr-code-demo.mp4',
    NULL, NULL,
    'https://images.unsplash.com/photo-1518770660439-4636190af475?auto=format&fit=crop&w=800&q=60',
    14, FALSE, TRUE, 2
FROM course_sections cs
JOIN courses c ON c.course_id = cs.course_id
WHERE c.title = '운영체제 이해하기' AND cs.sort_order = 1
  AND NOT EXISTS (
      SELECT 1 FROM lessons l WHERE l.section_id = cs.section_id AND l.sort_order = 2
  );

-- 강의 3: 컨텍스트 스위칭 심화 (코드 OCR 테스트용 영상)
INSERT INTO lessons (
    section_id, title, description, lesson_type,
    video_url, video_asset_key, video_provider,
    thumbnail_url, duration_seconds, is_preview, is_published, sort_order
)
SELECT
    cs.section_id,
    '컨텍스트 스위칭 심화',
    '컨텍스트 스위칭 동작 원리와 오버헤드를 코드로 확인합니다. (OCR 기능 테스트용)',
    'VIDEO',
    '/samples/ocr-code-demo.mp4',
    NULL, NULL,
    'https://images.unsplash.com/photo-1518770660439-4636190af475?auto=format&fit=crop&w=800&q=60',
    14, FALSE, TRUE, 3
FROM course_sections cs
JOIN courses c ON c.course_id = cs.course_id
WHERE c.title = '운영체제 이해하기' AND cs.sort_order = 1
  AND NOT EXISTS (
      SELECT 1 FROM lessons l WHERE l.section_id = cs.section_id AND l.sort_order = 3
  );

-- 이미 DB에 들어간 lesson-os-*.mp4 참조를 ocr-code-demo.mp4 로 통일하고 duration 보정
UPDATE lessons
SET video_url = '/samples/ocr-code-demo.mp4', duration_seconds = 14
WHERE title IN ('OS란 무엇인가?', '프로세스와 스레드의 이해', '컨텍스트 스위칭 심화')
  AND video_url <> '/samples/ocr-code-demo.mp4';

-- duration_seconds가 잘못 들어간 경우(예: 20) 보정
UPDATE lessons
SET duration_seconds = 14
WHERE title IN ('OS란 무엇인가?', '프로세스와 스레드의 이해', '컨텍스트 스위칭 심화')
  AND video_url = '/samples/ocr-code-demo.mp4'
  AND duration_seconds <> 14;

-- 운영체제 강의 Q&A 샘플 데이터
INSERT INTO qna_questions (
    user_id, template_type, difficulty, title, content, adopted_answer_id,
    course_id, lecture_timestamp, qna_status, view_count, is_deleted, created_at, updated_at
)
SELECT u.user_id, 'STUDY', 'EASY',
       '스레드 풀과 컨텍스트 스위칭 질문',
       '스레드 풀을 사용하는 주된 이유가 스레드 생성 비용 때문인가요, 아니면 컨텍스트 스위칭 비용을 줄이기 위함인가요?',
       NULL, c.course_id, '02:15', 'ANSWERED', 7, FALSE,
       TIMESTAMP '2026-04-12 14:30:00', TIMESTAMP '2026-04-12 20:00:00'
FROM users u, courses c
WHERE u.email = 'learner@devpath.com'
  AND c.title = '운영체제 이해하기'
  AND NOT EXISTS (
      SELECT 1 FROM qna_questions q WHERE q.title = '스레드 풀과 컨텍스트 스위칭 질문'
  );

INSERT INTO qna_questions (
    user_id, template_type, difficulty, title, content, adopted_answer_id,
    course_id, lecture_timestamp, qna_status, view_count, is_deleted, created_at, updated_at
)
SELECT u.user_id, 'STUDY', 'MEDIUM',
       '프로세스 통신(IPC) 관련해서요',
       '파이프 말고 공유 메모리를 사용할 때의 치명적인 단점이 있다면 무엇이 있을까요? 동기화 처리 말고 성능상 단점도 존재하는지 궁금합니다.',
       NULL, c.course_id, NULL, 'UNANSWERED', 3, FALSE,
       TIMESTAMP '2026-04-13 03:00:00', TIMESTAMP '2026-04-13 03:00:00'
FROM users u, courses c
WHERE u.email = 'learner2@devpath.com'
  AND c.title = '운영체제 이해하기'
  AND NOT EXISTS (
      SELECT 1 FROM qna_questions q WHERE q.title = '프로세스 통신(IPC) 관련해서요'
  );

-- 스레드 풀 질문에 강사 답변 추가
INSERT INTO qna_answers (question_id, user_id, content, is_adopted, is_deleted, created_at, updated_at)
SELECT q.question_id, u.user_id,
       '안녕하세요!

좋은 질문입니다. 스레드 풀의 주된 목적은 스레드 생성 및 소멸 비용을 줄이는 것에 있습니다.
스레드를 미리 만들어두고 재사용함으로써 OS에 스레드 생성 요청을 하는 오버헤드를 막는 것이죠.

컨텍스트 스위칭 자체를 막아주지는 않지만, 너무 많은 스레드가 무분별하게 생성되어 발생하는 과도한 스위칭 현상은 스레드 풀의 개수 제한을 통해 어느 정도 방어할 수 있습니다.',
       TRUE, FALSE,
       TIMESTAMP '2026-04-12 20:00:00', TIMESTAMP '2026-04-12 20:00:00'
FROM qna_questions q
JOIN users u ON u.email = 'instructor@devpath.com'
WHERE q.title = '스레드 풀과 컨텍스트 스위칭 질문'
  AND NOT EXISTS (
      SELECT 1 FROM qna_answers a WHERE a.question_id = q.question_id
  );

-- adopted_answer_id 업데이트
UPDATE qna_questions
SET adopted_answer_id = (
    SELECT a.answer_id FROM qna_answers a WHERE a.question_id = qna_questions.question_id LIMIT 1
)
WHERE title = '스레드 풀과 컨텍스트 스위칭 질문'
  AND adopted_answer_id IS NULL;

-- 운영체제 이해하기 강의 수강 등록 (learner@devpath.com)
INSERT INTO course_enrollments (
    user_id, course_id, status, enrolled_at, completed_at, progress_percentage, last_accessed_at
)
SELECT u.user_id, c.course_id,
       'ACTIVE',
       TIMESTAMP '2026-04-10 10:00:00',
       NULL,
       0,
       TIMESTAMP '2026-04-10 10:00:00'
FROM users u
JOIN courses c ON c.title = '운영체제 이해하기'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM course_enrollments ce
      WHERE ce.user_id = u.user_id AND ce.course_id = c.course_id
  );

-- ============================================================
-- [SAMPLE VIDEO DATA END]
-- ============================================================

-- ============================================================
-- 강의 목록 메뉴 기본 구성
-- ============================================================
INSERT INTO lecture_catalog_categories (category_key, label, title, icon_class, sort_order, is_active)
SELECT seed.category_key, seed.label, seed.title, seed.icon_class, seed.sort_order, seed.is_active
FROM (
    VALUES
        ('all', '전체', '전체 강의', 'fas fa-th-large', 0, TRUE),
        ('dev', '개발', '개발 · 프로그래밍', 'fas fa-laptop-code', 1, TRUE),
        ('ai', 'AI', '인공지능(AI)', 'fas fa-robot', 2, TRUE),
        ('data', '데이터', '데이터 사이언스', 'fas fa-database', 3, TRUE),
        ('infra', '인프라', '인프라 · 보안', 'fas fa-server', 4, TRUE),
        ('mobile', '모바일', '모바일 앱 개발', 'fas fa-mobile-alt', 5, TRUE),
        ('career', '커리어', '커리어 · 자기계발', 'fas fa-briefcase', 6, TRUE)
) AS seed(category_key, label, title, icon_class, sort_order, is_active)
WHERE NOT EXISTS (
    SELECT 1
    FROM lecture_catalog_categories category
    WHERE category.category_key = seed.category_key
);

INSERT INTO lecture_catalog_mega_menu_items (category_id, label, sort_order)
SELECT category.id, seed.label, seed.sort_order
FROM (
    VALUES
        ('dev', '웹 개발 (Web)', 0),
        ('dev', '프론트엔드', 1),
        ('dev', '백엔드', 2),
        ('dev', '풀스택', 3),
        ('dev', '게임 개발', 4),
        ('dev', '프로그래밍 언어', 5),
        ('ai', 'AI Engineer', 0),
        ('ai', 'Data Scientist', 1),
        ('ai', '머신러닝 (ML)', 2),
        ('ai', '딥러닝 (DL)', 3),
        ('ai', 'ChatGPT / LLM', 4),
        ('ai', '프롬프트 엔지니어링', 5),
        ('data', '데이터 분석', 0),
        ('data', '데이터 엔지니어링', 1),
        ('data', 'SQL / DB', 2),
        ('data', 'NoSQL (Mongo)', 3),
        ('data', '시각화 (Tableau)', 4),
        ('data', '빅데이터', 5),
        ('infra', 'DevOps', 0),
        ('infra', 'AWS / Cloud', 1),
        ('infra', 'Docker / K8s', 2),
        ('infra', '보안 (Security)', 3),
        ('infra', 'Linux / Shell', 4),
        ('infra', '네트워크', 5),
        ('mobile', 'Android App', 0),
        ('mobile', 'iOS App', 1),
        ('mobile', 'Flutter', 2),
        ('mobile', 'React Native', 3),
        ('mobile', 'Kotlin / Swift', 4),
        ('career', '취업 / 이직', 0),
        ('career', '이력서 / 면접', 1),
        ('career', '기획 (PM/PO)', 2),
        ('career', 'UX / UI 디자인', 3),
        ('career', '비즈니스 스킬', 4),
        ('career', '개발자 글쓰기', 5)
) AS seed(category_key, label, sort_order)
JOIN lecture_catalog_categories category
    ON category.category_key = seed.category_key
WHERE NOT EXISTS (
    SELECT 1
    FROM lecture_catalog_mega_menu_items item
    WHERE item.category_id = category.id
      AND item.label = seed.label
);

INSERT INTO lecture_catalog_groups (category_id, name, sort_order)
SELECT category.id, seed.name, seed.sort_order
FROM (
    VALUES
        ('all', '탐색 분야', 0),
        ('dev', '언어 (Language)', 0),
        ('dev', '프론트엔드', 1),
        ('dev', '백엔드', 2),
        ('dev', 'CS & 기타', 3),
        ('ai', '직무별', 0),
        ('ai', '핵심 기술', 1),
        ('ai', 'LLM & 프롬프트', 2),
        ('ai', '라이브러리', 3),
        ('data', '직무별', 0),
        ('data', '데이터베이스', 1),
        ('data', '분석 & 시각화', 2),
        ('data', '빅데이터', 3),
        ('infra', 'DevOps', 0),
        ('infra', '컨테이너', 1),
        ('infra', '시스템', 2),
        ('infra', '보안', 3),
        ('mobile', '네이티브', 0),
        ('mobile', '크로스 플랫폼', 1),
        ('mobile', '기타', 2),
        ('career', '매니지먼트', 0),
        ('career', '기획/디자인', 1),
        ('career', '취업', 2),
        ('career', '오피스', 3)
) AS seed(category_key, name, sort_order)
JOIN lecture_catalog_categories category
    ON category.category_key = seed.category_key
WHERE NOT EXISTS (
    SELECT 1
    FROM lecture_catalog_groups group_item
    WHERE group_item.category_id = category.id
      AND group_item.name = seed.name
);

INSERT INTO lecture_catalog_group_items (group_id, name, linked_category_key, sort_order)
SELECT group_item.id, seed.item_name, seed.linked_category_key, seed.sort_order
FROM (
    VALUES
        ('all', '탐색 분야', '웹 개발', 'dev', 0),
        ('all', '탐색 분야', 'AI/머신러닝', 'ai', 1),
        ('all', '탐색 분야', '데이터 분석', 'data', 2),
        ('all', '탐색 분야', '인프라', 'infra', 3),
        ('all', '탐색 분야', '모바일 앱', 'mobile', 4),
        ('all', '탐색 분야', '커리어', 'career', 5),
        ('dev', '언어 (Language)', 'Java', NULL, 0),
        ('dev', '언어 (Language)', 'Python', NULL, 1),
        ('dev', '언어 (Language)', 'JavaScript', NULL, 2),
        ('dev', '언어 (Language)', 'TypeScript', NULL, 3),
        ('dev', '언어 (Language)', 'C++', NULL, 4),
        ('dev', '언어 (Language)', 'C#', NULL, 5),
        ('dev', '언어 (Language)', 'Go', NULL, 6),
        ('dev', '언어 (Language)', 'Rust', NULL, 7),
        ('dev', '언어 (Language)', 'Kotlin', NULL, 8),
        ('dev', '언어 (Language)', 'Swift', NULL, 9),
        ('dev', '프론트엔드', 'React', NULL, 0),
        ('dev', '프론트엔드', 'Vue.js', NULL, 1),
        ('dev', '프론트엔드', 'Angular', NULL, 2),
        ('dev', '프론트엔드', 'Svelte', NULL, 3),
        ('dev', '프론트엔드', 'Next.js', NULL, 4),
        ('dev', '프론트엔드', 'HTML/CSS', NULL, 5),
        ('dev', '프론트엔드', 'Tailwind', NULL, 6),
        ('dev', '백엔드', 'Spring Boot', NULL, 0),
        ('dev', '백엔드', 'Node.js', NULL, 1),
        ('dev', '백엔드', 'Django', NULL, 2),
        ('dev', '백엔드', 'FastAPI', NULL, 3),
        ('dev', '백엔드', 'NestJS', NULL, 4),
        ('dev', '백엔드', 'ASP.NET', NULL, 5),
        ('dev', '백엔드', 'PHP', NULL, 6),
        ('dev', 'CS & 기타', '자료구조/알고리즘', NULL, 0),
        ('dev', 'CS & 기타', '테스트', NULL, 1),
        ('dev', 'CS & 기타', '게임 개발', NULL, 2),
        ('dev', 'CS & 기타', '아키텍처', NULL, 3),
        ('ai', '직무별', 'AI Engineer', NULL, 0),
        ('ai', '직무별', 'Data Scientist', NULL, 1),
        ('ai', '직무별', 'MLOps', NULL, 2),
        ('ai', '직무별', 'Researcher', NULL, 3),
        ('ai', '핵심 기술', 'Machine Learning', NULL, 0),
        ('ai', '핵심 기술', 'Deep Learning', NULL, 1),
        ('ai', '핵심 기술', 'NLP', NULL, 2),
        ('ai', '핵심 기술', 'Computer Vision', NULL, 3),
        ('ai', '핵심 기술', 'Reinforcement Learning', NULL, 4),
        ('ai', 'LLM & 프롬프트', 'ChatGPT', NULL, 0),
        ('ai', 'LLM & 프롬프트', 'LangChain', NULL, 1),
        ('ai', 'LLM & 프롬프트', 'Prompt Engineering', NULL, 2),
        ('ai', 'LLM & 프롬프트', 'RAG', NULL, 3),
        ('ai', 'LLM & 프롬프트', 'Fine-tuning', NULL, 4),
        ('ai', '라이브러리', 'PyTorch', NULL, 0),
        ('ai', '라이브러리', 'TensorFlow', NULL, 1),
        ('ai', '라이브러리', 'Keras', NULL, 2),
        ('ai', '라이브러리', 'Scikit-learn', NULL, 3),
        ('ai', '라이브러리', 'HuggingFace', NULL, 4),
        ('data', '직무별', 'Data Analyst', NULL, 0),
        ('data', '직무별', 'Data Engineer', NULL, 1),
        ('data', '직무별', 'DBA', NULL, 2),
        ('data', '직무별', 'Big Data Engineer', NULL, 3),
        ('data', '데이터베이스', 'MySQL', NULL, 0),
        ('data', '데이터베이스', 'PostgreSQL', NULL, 1),
        ('data', '데이터베이스', 'Oracle', NULL, 2),
        ('data', '데이터베이스', 'MongoDB', NULL, 3),
        ('data', '데이터베이스', 'Redis', NULL, 4),
        ('data', '데이터베이스', 'Elasticsearch', NULL, 5),
        ('data', '분석 & 시각화', 'Tableau', NULL, 0),
        ('data', '분석 & 시각화', 'Power BI', NULL, 1),
        ('data', '분석 & 시각화', 'Excel', NULL, 2),
        ('data', '분석 & 시각화', 'Google Analytics', NULL, 3),
        ('data', '분석 & 시각화', 'Pandas', NULL, 4),
        ('data', '빅데이터', 'Hadoop', NULL, 0),
        ('data', '빅데이터', 'Spark', NULL, 1),
        ('data', '빅데이터', 'Kafka', NULL, 2),
        ('data', '빅데이터', 'Airflow', NULL, 3),
        ('data', '빅데이터', 'Data Lake', NULL, 4),
        ('infra', 'DevOps', 'DevOps General', NULL, 0),
        ('infra', 'DevOps', 'DevSecOps', NULL, 1),
        ('infra', 'DevOps', 'AWS', NULL, 2),
        ('infra', 'DevOps', 'Azure', NULL, 3),
        ('infra', 'DevOps', 'GCP', NULL, 4),
        ('infra', 'DevOps', 'System Design', NULL, 5),
        ('infra', '컨테이너', 'Docker', NULL, 0),
        ('infra', '컨테이너', 'Kubernetes', NULL, 1),
        ('infra', '컨테이너', 'Terraform', NULL, 2),
        ('infra', '컨테이너', 'CI/CD Pipelines', NULL, 3),
        ('infra', '시스템', 'Linux', NULL, 0),
        ('infra', '시스템', 'Shell Script', NULL, 1),
        ('infra', '시스템', 'Network Administration', NULL, 2),
        ('infra', '보안', 'Cyber Security', NULL, 0),
        ('infra', '보안', 'Web Hacking', NULL, 1),
        ('infra', '보안', 'Cloud Security', NULL, 2),
        ('mobile', '네이티브', 'Android (Kotlin)', NULL, 0),
        ('mobile', '네이티브', 'iOS (Swift)', NULL, 1),
        ('mobile', '네이티브', 'SwiftUI', NULL, 2),
        ('mobile', '네이티브', 'Jetpack Compose', NULL, 3),
        ('mobile', '크로스 플랫폼', 'Flutter', NULL, 0),
        ('mobile', '크로스 플랫폼', 'React Native', NULL, 1),
        ('mobile', '크로스 플랫폼', 'Xamarin', NULL, 2),
        ('mobile', '기타', 'Mobile Design', NULL, 0),
        ('mobile', '기타', 'App Store Release', NULL, 1),
        ('career', '매니지먼트', 'Product Manager', NULL, 0),
        ('career', '매니지먼트', 'Engineering Manager', NULL, 1),
        ('career', '매니지먼트', 'Developer Relations', NULL, 2),
        ('career', '기획/디자인', 'UX / UI Design', NULL, 0),
        ('career', '기획/디자인', 'Figma', NULL, 1),
        ('career', '기획/디자인', 'Technical Writer', NULL, 2),
        ('career', '기획/디자인', 'IT 서비스 기획', NULL, 3),
        ('career', '취업', '이력서', NULL, 0),
        ('career', '취업', '자소서', NULL, 1),
        ('career', '취업', '기술 면접', NULL, 2),
        ('career', '취업', '포트폴리오', NULL, 3),
        ('career', '취업', '연봉 협상', NULL, 4),
        ('career', '오피스', '개발자 글쓰기', NULL, 0),
        ('career', '오피스', '커뮤니케이션', NULL, 1),
        ('career', '오피스', '문서화', NULL, 2)
) AS seed(category_key, group_name, item_name, linked_category_key, sort_order)
JOIN lecture_catalog_categories category
    ON category.category_key = seed.category_key
JOIN lecture_catalog_groups group_item
    ON group_item.category_id = category.id
   AND group_item.name = seed.group_name
WHERE NOT EXISTS (
    SELECT 1
    FROM lecture_catalog_group_items item
    WHERE item.group_id = group_item.id
      AND item.name = seed.item_name
);

-- ============================================================
-- PUBLIC CATALOG DATA: lecture-list.html 실제 API 노출용 공개 강의
--   - instructor@devpath.com: 2개
--   - frontend@devpath.com  : 3개
--   - data@devpath.com      : 3개
-- ============================================================

INSERT INTO users (
    email, password, name, role_name, is_active,
    account_status, instructor_status, instructor_grade,
    created_at, updated_at
)
SELECT
    'frontend@devpath.com',
    '$2a$10$xh6.EW/FRzJBWfxqpdXh2uTVoepPhUxQRUH5OEwk90IpYeKjegkj.',
    '김강사',
    'ROLE_INSTRUCTOR',
    TRUE,
    'ACTIVE',
    'APPROVED',
    'PRO',
    TIMESTAMP '2026-04-01 09:00:00',
    TIMESTAMP '2026-04-01 09:00:00'
WHERE NOT EXISTS (SELECT 1 FROM users WHERE email = 'frontend@devpath.com');

INSERT INTO users (
    email, password, name, role_name, is_active,
    account_status, instructor_status, instructor_grade,
    created_at, updated_at
)
SELECT
    'data@devpath.com',
    '$2a$10$xh6.EW/FRzJBWfxqpdXh2uTVoepPhUxQRUH5OEwk90IpYeKjegkj.',
    '이민수',
    'ROLE_INSTRUCTOR',
    TRUE,
    'ACTIVE',
    'APPROVED',
    'PRO',
    TIMESTAMP '2026-04-01 09:05:00',
    TIMESTAMP '2026-04-01 09:05:00'
WHERE NOT EXISTS (SELECT 1 FROM users WHERE email = 'data@devpath.com');

UPDATE users
SET account_status = 'ACTIVE',
    instructor_status = 'APPROVED',
    instructor_grade = COALESCE(instructor_grade, 'PRO'),
    is_active = TRUE
WHERE email IN ('instructor@devpath.com', 'frontend@devpath.com', 'data@devpath.com');

INSERT INTO user_profiles (
    user_id, profile_image, channel_name, bio, channel_description,
    phone, date_of_birth, github_url, blog_url, is_public,
    created_at, updated_at
)
SELECT
    u.user_id,
    'https://images.unsplash.com/photo-1494790108377-be9c29b29330?auto=format&fit=crop&w=400&q=80',
    '프론트엔드 크래프트',
    'React, Next.js, Flutter로 제품 출시까지 이어지는 프론트엔드 강의를 만듭니다.',
    '프론트엔드 구조 설계, UI 품질, 모바일 앱 출시까지 실무 흐름으로 다루는 채널입니다.',
    NULL, NULL,
    'https://github.com/frontend-craft',
    'https://blog.devpath.com/frontend-craft',
    TRUE,
    TIMESTAMP '2026-04-01 09:00:00',
    TIMESTAMP '2026-04-01 09:00:00'
FROM users u
WHERE u.email = 'frontend@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM user_profiles up WHERE up.user_id = u.user_id);

INSERT INTO user_profiles (
    user_id, profile_image, channel_name, bio, channel_description,
    phone, date_of_birth, github_url, blog_url, is_public,
    created_at, updated_at
)
SELECT
    u.user_id,
    'https://images.unsplash.com/photo-1500648767791-00dcc994a43e?auto=format&fit=crop&w=400&q=80',
    'AI 데이터 연구소',
    'LLM 서비스, 데이터 분석, 커리어 준비를 실습 중심으로 안내합니다.',
    'AI 서비스 구현, 데이터 분석 기본기, 개발자 커리어 문서화를 함께 다루는 채널입니다.',
    NULL, NULL,
    'https://github.com/ai-data-lab',
    'https://blog.devpath.com/ai-data-lab',
    TRUE,
    TIMESTAMP '2026-04-01 09:05:00',
    TIMESTAMP '2026-04-01 09:05:00'
FROM users u
WHERE u.email = 'data@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM user_profiles up WHERE up.user_id = u.user_id);

UPDATE user_profiles up
SET
    channel_name = CASE u.email
        WHEN 'frontend@devpath.com' THEN '프론트엔드 크래프트'
        WHEN 'data@devpath.com' THEN 'AI 데이터 연구소'
        ELSE up.channel_name
    END,
    updated_at = NOW()
FROM users u
WHERE up.user_id = u.user_id
  AND u.email IN ('frontend@devpath.com', 'data@devpath.com');

INSERT INTO tags (name, category, is_official, is_deleted)
WITH catalog_tags(name, category) AS (
    VALUES
        ('Kubernetes', 'DevOps'),
        ('DevOps', 'DevOps'),
        ('Next.js', 'Frontend'),
        ('Tailwind', 'Frontend'),
        ('Flutter', 'Mobile'),
        ('모바일', 'Mobile'),
        ('앱 출시', 'Mobile'),
        ('AI', 'AI'),
        ('LLM', 'AI'),
        ('RAG', 'AI'),
        ('LangChain', 'AI'),
        ('SQL', 'Data'),
        ('Pandas', 'Data'),
        ('데이터', 'Data'),
        ('이력서', 'Career'),
        ('기술 면접', 'Career'),
        ('포트폴리오', 'Career')
)
SELECT ct.name, ct.category, TRUE, FALSE
FROM catalog_tags ct
WHERE NOT EXISTS (SELECT 1 FROM tags t WHERE t.name = ct.name);

INSERT INTO user_tech_stacks (user_id, tag_id)
WITH instructor_tags(email, tag_name) AS (
    VALUES
        ('instructor@devpath.com', 'Java'),
        ('instructor@devpath.com', 'Spring Boot'),
        ('instructor@devpath.com', 'Docker'),
        ('instructor@devpath.com', 'Kubernetes'),
        ('frontend@devpath.com', 'React'),
        ('frontend@devpath.com', 'TypeScript'),
        ('frontend@devpath.com', 'Next.js'),
        ('frontend@devpath.com', 'Flutter'),
        ('frontend@devpath.com', 'Tailwind'),
        ('data@devpath.com', 'AI'),
        ('data@devpath.com', 'LLM'),
        ('data@devpath.com', 'RAG'),
        ('data@devpath.com', 'SQL'),
        ('data@devpath.com', 'Pandas'),
        ('data@devpath.com', '기술 면접')
)
SELECT u.user_id, t.tag_id
FROM instructor_tags it
JOIN users u ON u.email = it.email
JOIN tags t ON t.name = it.tag_name
WHERE NOT EXISTS (
    SELECT 1
    FROM user_tech_stacks uts
    WHERE uts.user_id = u.user_id
      AND uts.tag_id = t.tag_id
);

-- 기존 테스트/샘플 공개 강의는 학습자 공개 목록에서 제외한다.
UPDATE courses
SET status = 'DRAFT',
    published_at = NULL
WHERE title IN (
    'Spring Boot Intro',
    'React Dashboard Sprint',
    '운영체제 이해하기',
    '[A-CASE-A] Node Clearance Course',
    '[A-CASE-B] Tag Missing Course',
    '[A-CASE-C] Quiz Fail Course'
);

INSERT INTO courses (
    instructor_id, title, subtitle, description,
    thumbnail_url, intro_video_url, video_asset_key, duration_seconds,
    price, original_price, currency, difficulty_level, language,
    has_certificate, status, published_at
)
WITH catalog_courses(
    instructor_email, title, subtitle, description, thumbnail_url,
    duration_seconds, price, original_price, difficulty_level, has_certificate, published_at
) AS (
    VALUES
        ('instructor@devpath.com', '실무 Spring Boot 백엔드 입문', 'REST API, JPA, 인증까지 한 번에 잡는 백엔드 시작 과정', 'Java 기본기를 가진 학습자가 Spring Boot 프로젝트 구조, REST API 설계, JPA 매핑, JWT 인증 흐름을 실제 서비스 형태로 연결해 보는 강의입니다.', 'https://images.unsplash.com/photo-1515879218367-8466d910aaa4?auto=format&fit=crop&w=1200&q=80', 32400, 89000, 129000, 'BEGINNER', TRUE, TIMESTAMP '2026-04-01 09:00:00'),
        ('instructor@devpath.com', 'Docker & Kubernetes 운영 실전', '컨테이너 이미지부터 배포 매니페스트까지 다루는 운영 입문', 'Docker 이미지 빌드, Compose 기반 로컬 환경, Kubernetes Deployment와 Service를 연결해 운영 가능한 백엔드 배포 흐름을 익힙니다.', 'https://images.unsplash.com/photo-1667372393119-3d4c48d07fc9?auto=format&fit=crop&w=1200&q=80', 39600, 109000, 159000, 'ADVANCED', TRUE, TIMESTAMP '2026-04-02 09:00:00'),
        ('frontend@devpath.com', 'React 19 프론트엔드 실전 가이드', '상태 설계, UI 품질, 테스트까지 연결하는 React 실무 과정', '컴포넌트 경계, 상태 배치, 폼 처리, Tailwind 스타일링, Playwright 테스트를 통해 프론트엔드 기능을 안정적으로 출시하는 방법을 다룹니다.', 'https://images.unsplash.com/photo-1498050108023-c5249f4df085?auto=format&fit=crop&w=1200&q=80', 28800, 79000, 119000, 'INTERMEDIATE', TRUE, TIMESTAMP '2026-04-03 09:00:00'),
        ('frontend@devpath.com', 'Next.js 14 제품 개발 실전', 'App Router 기반으로 배포 가능한 제품 화면 만들기', 'Next.js App Router, 서버 컴포넌트, 캐싱, 인증, 메타데이터, 이미지 최적화까지 제품 출시 전에 필요한 구현 포인트를 실습합니다.', 'https://images.unsplash.com/photo-1555949963-aa79dcee981c?auto=format&fit=crop&w=1200&q=80', 34200, 99000, 139000, 'INTERMEDIATE', TRUE, TIMESTAMP '2026-04-04 09:00:00'),
        ('frontend@devpath.com', 'Flutter로 MVP 앱 출시하기', '아이디어 검증용 모바일 앱을 빠르게 만들고 출시 준비하기', 'Flutter 위젯 구조, 상태 관리, API 연동, 폼 검증, 앱 아이콘과 권한 설정을 거쳐 MVP 앱 출시 체크리스트까지 완성합니다.', 'https://images.unsplash.com/photo-1512941937669-90a1b58e7e9c?auto=format&fit=crop&w=1200&q=80', 25200, 69000, 99000, 'BEGINNER', TRUE, TIMESTAMP '2026-04-05 09:00:00'),
        ('data@devpath.com', 'ChatGPT API와 RAG 서비스 만들기', 'LLM API 호출부터 문서 기반 Q&A 챗봇까지', '프롬프트 구조, API 호출, 임베딩, 벡터 검색, LangChain 기반 RAG 파이프라인을 연결해 문서 기반 AI 서비스를 구현합니다.', 'https://images.unsplash.com/photo-1677442136019-21780ecad995?auto=format&fit=crop&w=1200&q=80', 36000, 99000, 149000, 'INTERMEDIATE', TRUE, TIMESTAMP '2026-04-06 09:00:00'),
        ('data@devpath.com', 'SQL로 끝내는 데이터 분석 기본기', 'JOIN, GROUP BY, 윈도우 함수, Pandas 리포트까지', '데이터 분석에 필요한 SQL 핵심 문법과 Pandas 후처리를 묶어 매출, 리텐션, 사용자 행동 데이터를 직접 분석하는 강의입니다.', 'https://images.unsplash.com/photo-1551288049-bebda4e38f71?auto=format&fit=crop&w=1200&q=80', 21600, 49000, 89000, 'BEGINNER', TRUE, TIMESTAMP '2026-04-07 09:00:00'),
        ('data@devpath.com', '개발자 이력서와 기술 면접 패키지', '프로젝트 경험을 채용 문서와 면접 답변으로 바꾸는 과정', '프로젝트 경험 정리, 이력서 문장 작성, 포트폴리오 링크 구성, 기술 면접 답변 구조화를 통해 지원 준비물을 완성합니다.', 'https://images.unsplash.com/photo-1454165804606-c3d57bc86b40?auto=format&fit=crop&w=1200&q=80', 18000, 0, 59000, 'BEGINNER', FALSE, TIMESTAMP '2026-04-08 09:00:00')
)
SELECT
    u.user_id, cc.title, cc.subtitle, cc.description,
    cc.thumbnail_url, '/samples/sample-intro.mp4', NULL, cc.duration_seconds,
    cc.price, cc.original_price, 'KRW', cc.difficulty_level, 'ko',
    cc.has_certificate, 'PUBLISHED', cc.published_at
FROM catalog_courses cc
JOIN users u ON u.email = cc.instructor_email
WHERE NOT EXISTS (SELECT 1 FROM courses c WHERE c.title = cc.title);

INSERT INTO course_prerequisites (course_id, prerequisite)
WITH prereq_seed AS (
    SELECT '실무 Spring Boot 백엔드 입문' AS course_title, 'Java 문법과 객체지향 기본 개념을 알고 있어야 합니다.' AS prereq_text UNION ALL
    SELECT '실무 Spring Boot 백엔드 입문', 'HTTP 요청/응답과 JSON 구조를 이해하고 있으면 좋습니다.' UNION ALL
    SELECT 'Docker & Kubernetes 운영 실전', 'Linux 터미널 기본 명령어를 사용할 수 있어야 합니다.' UNION ALL
    SELECT 'Docker & Kubernetes 운영 실전', '간단한 웹 애플리케이션 배포 경험이 있으면 좋습니다.' UNION ALL
    SELECT 'React 19 프론트엔드 실전 가이드', 'HTML, CSS, JavaScript 기본 문법을 알고 있어야 합니다.' UNION ALL
    SELECT 'React 19 프론트엔드 실전 가이드', 'React 컴포넌트를 한 번 이상 만들어 본 경험이 있으면 좋습니다.' UNION ALL
    SELECT 'Next.js 14 제품 개발 실전', 'React의 props, state, hooks 개념을 이해하고 있어야 합니다.' UNION ALL
    SELECT 'Next.js 14 제품 개발 실전', 'REST API를 호출해 화면에 데이터를 표시해 본 경험이 있으면 좋습니다.' UNION ALL
    SELECT 'Flutter로 MVP 앱 출시하기', '프로그래밍 기초 문법과 비동기 처리 개념을 알고 있으면 좋습니다.' UNION ALL
    SELECT 'Flutter로 MVP 앱 출시하기', '모바일 앱 화면 구성에 관심이 있는 입문자를 대상으로 합니다.' UNION ALL
    SELECT 'ChatGPT API와 RAG 서비스 만들기', 'Python 또는 JavaScript로 API를 호출해 본 경험이 있으면 좋습니다.' UNION ALL
    SELECT 'ChatGPT API와 RAG 서비스 만들기', 'JSON, HTTP, 환경 변수 관리의 기본 개념을 알고 있어야 합니다.' UNION ALL
    SELECT 'SQL로 끝내는 데이터 분석 기본기', '엑셀 또는 스프레드시트로 데이터를 정리해 본 경험이 있으면 충분합니다.' UNION ALL
    SELECT 'SQL로 끝내는 데이터 분석 기본기', 'Python 기본 문법을 알면 Pandas 파트를 더 쉽게 따라올 수 있습니다.' UNION ALL
    SELECT '개발자 이력서와 기술 면접 패키지', '진행했거나 진행 중인 개인/팀 프로젝트가 하나 이상 있으면 좋습니다.' UNION ALL
    SELECT '개발자 이력서와 기술 면접 패키지', '지원하고 싶은 직무 또는 포지션을 정해두면 실습 효과가 높습니다.'
)
SELECT c.course_id, p.prereq_text
FROM prereq_seed p
JOIN courses c ON c.title = p.course_title
WHERE NOT EXISTS (
    SELECT 1 FROM course_prerequisites cp
    WHERE cp.course_id = c.course_id AND cp.prerequisite = p.prereq_text
);

INSERT INTO course_job_relevance (course_id, job_relevance)
WITH relevance(course_title, relevance_text) AS (
    VALUES
        ('실무 Spring Boot 백엔드 입문', '백엔드 개발자 주니어 과제 전형 준비'),
        ('실무 Spring Boot 백엔드 입문', 'Spring Boot 기반 사내 서비스 API 개발'),
        ('Docker & Kubernetes 운영 실전', 'DevOps 엔지니어와 플랫폼 엔지니어의 배포 운영 업무'),
        ('Docker & Kubernetes 운영 실전', '백엔드 서비스 컨테이너화와 클러스터 운영'),
        ('React 19 프론트엔드 실전 가이드', '프론트엔드 개발자 실무 UI 구현과 테스트 자동화'),
        ('React 19 프론트엔드 실전 가이드', '제품 대시보드와 관리 화면 개발'),
        ('Next.js 14 제품 개발 실전', 'Next.js 기반 스타트업 제품 개발'),
        ('Next.js 14 제품 개발 실전', 'SEO와 성능을 고려한 웹 서비스 출시'),
        ('Flutter로 MVP 앱 출시하기', '초기 스타트업 MVP 앱 개발'),
        ('Flutter로 MVP 앱 출시하기', '프론트엔드 개발자의 모바일 앱 확장 역량'),
        ('ChatGPT API와 RAG 서비스 만들기', 'AI 기능을 포함한 SaaS 프로토타입 개발'),
        ('ChatGPT API와 RAG 서비스 만들기', '사내 문서 검색 챗봇과 고객지원 자동화'),
        ('SQL로 끝내는 데이터 분석 기본기', '데이터 기반 제품 개선과 운영 리포트 작성'),
        ('SQL로 끝내는 데이터 분석 기본기', '주니어 데이터 분석가와 PM의 지표 분석 업무'),
        ('개발자 이력서와 기술 면접 패키지', '신입/주니어 개발자 채용 준비'),
        ('개발자 이력서와 기술 면접 패키지', '프로젝트 경험을 포트폴리오와 면접 답변으로 전환')
)
SELECT c.course_id, r.relevance_text
FROM relevance r
JOIN courses c ON c.title = r.course_title
WHERE NOT EXISTS (
    SELECT 1 FROM course_job_relevance cj
    WHERE cj.course_id = c.course_id AND cj.job_relevance = r.relevance_text
);

INSERT INTO course_objectives (course_id, objective_text, display_order)
WITH objectives(course_title, objective_body, display_order) AS (
    VALUES
        ('실무 Spring Boot 백엔드 입문', '계층형 구조로 REST API를 설계하고 구현할 수 있습니다.', 1),
        ('실무 Spring Boot 백엔드 입문', 'JPA 매핑과 JWT 인증을 연결해 기본 백엔드 기능을 완성할 수 있습니다.', 2),
        ('Docker & Kubernetes 운영 실전', 'Dockerfile과 Compose로 재현 가능한 로컬 실행 환경을 만들 수 있습니다.', 1),
        ('Docker & Kubernetes 운영 실전', 'Kubernetes Deployment, Service, ConfigMap을 이용해 서비스를 배포할 수 있습니다.', 2),
        ('React 19 프론트엔드 실전 가이드', '상태 위치와 컴포넌트 경계를 판단해 유지보수 가능한 화면을 만들 수 있습니다.', 1),
        ('React 19 프론트엔드 실전 가이드', 'Tailwind와 Playwright를 활용해 UI 품질을 점검할 수 있습니다.', 2),
        ('Next.js 14 제품 개발 실전', 'App Router 기반 라우팅, 레이아웃, 서버 컴포넌트 구조를 설계할 수 있습니다.', 1),
        ('Next.js 14 제품 개발 실전', '캐싱, 인증, 이미지 최적화를 적용해 배포 가능한 제품 화면을 완성할 수 있습니다.', 2),
        ('Flutter로 MVP 앱 출시하기', 'Flutter 위젯 구조와 상태 관리를 이용해 앱 화면을 구성할 수 있습니다.', 1),
        ('Flutter로 MVP 앱 출시하기', 'API 연동과 빌드 설정을 거쳐 MVP 앱 출시 준비를 할 수 있습니다.', 2),
        ('ChatGPT API와 RAG 서비스 만들기', 'LLM API 호출 구조와 프롬프트 메시지 설계를 이해할 수 있습니다.', 1),
        ('ChatGPT API와 RAG 서비스 만들기', '임베딩, 검색, 생성을 연결해 RAG 기반 Q&A 서비스를 만들 수 있습니다.', 2),
        ('SQL로 끝내는 데이터 분석 기본기', 'JOIN, GROUP BY, 윈도우 함수로 업무 지표를 직접 계산할 수 있습니다.', 1),
        ('SQL로 끝내는 데이터 분석 기본기', 'Pandas로 분석 결과를 정리하고 리포트용 테이블을 만들 수 있습니다.', 2),
        ('개발자 이력서와 기술 면접 패키지', '프로젝트 경험을 성과 중심 이력서 문장으로 바꿀 수 있습니다.', 1),
        ('개발자 이력서와 기술 면접 패키지', '기술 면접 질문에 구조적으로 답변하는 연습 흐름을 만들 수 있습니다.', 2)
)
SELECT c.course_id, o.objective_body, o.display_order
FROM objectives o
JOIN courses c ON c.title = o.course_title
WHERE NOT EXISTS (
    SELECT 1 FROM course_objectives co
    WHERE co.course_id = c.course_id AND co.display_order = o.display_order
);

INSERT INTO course_target_audiences (course_id, audience_description, display_order)
WITH audiences(course_title, audience_body, display_order) AS (
    VALUES
        ('실무 Spring Boot 백엔드 입문', 'Spring Boot 백엔드 개발을 처음 실무 형태로 배우려는 학습자', 1),
        ('실무 Spring Boot 백엔드 입문', 'API 과제 전형을 준비하는 주니어 개발자', 2),
        ('Docker & Kubernetes 운영 실전', '컨테이너 배포와 운영 흐름을 익히려는 백엔드 개발자', 1),
        ('Docker & Kubernetes 운영 실전', 'Kubernetes 매니페스트를 직접 작성해 보고 싶은 DevOps 입문자', 2),
        ('React 19 프론트엔드 실전 가이드', 'React 실무 코드 구조와 테스트를 정리하고 싶은 프론트엔드 개발자', 1),
        ('React 19 프론트엔드 실전 가이드', '대시보드나 관리자 화면을 안정적으로 만들고 싶은 학습자', 2),
        ('Next.js 14 제품 개발 실전', 'Next.js App Router 기반 제품을 만들어 보고 싶은 개발자', 1),
        ('Next.js 14 제품 개발 실전', '성능, SEO, 인증을 함께 고려해야 하는 웹 서비스 담당자', 2),
        ('Flutter로 MVP 앱 출시하기', '빠르게 모바일 앱 MVP를 만들어 검증하고 싶은 개발자', 1),
        ('Flutter로 MVP 앱 출시하기', '웹 개발 경험을 모바일 앱 개발로 확장하려는 학습자', 2),
        ('ChatGPT API와 RAG 서비스 만들기', 'LLM API로 실제 기능을 만들어 보고 싶은 웹/백엔드 개발자', 1),
        ('ChatGPT API와 RAG 서비스 만들기', '사내 문서 기반 챗봇이나 검색 기능을 기획하는 개발자', 2),
        ('SQL로 끝내는 데이터 분석 기본기', 'SQL로 제품 지표를 직접 확인해야 하는 개발자와 PM', 1),
        ('SQL로 끝내는 데이터 분석 기본기', '데이터 분석 직무 전환을 준비하는 입문자', 2),
        ('개발자 이력서와 기술 면접 패키지', '신입 또는 주니어 개발자 채용을 준비하는 학습자', 1),
        ('개발자 이력서와 기술 면접 패키지', '프로젝트 경험은 있지만 문서화와 면접 답변이 막히는 개발자', 2)
)
SELECT c.course_id, a.audience_body, a.display_order
FROM audiences a
JOIN courses c ON c.title = a.course_title
WHERE NOT EXISTS (
    SELECT 1 FROM course_target_audiences cta
    WHERE cta.course_id = c.course_id AND cta.display_order = a.display_order
);

INSERT INTO course_tag_maps (course_id, tag_id, proficiency_level)
WITH course_tags(course_title, tag_name, proficiency_level) AS (
    VALUES
        ('실무 Spring Boot 백엔드 입문', 'Java', 2),
        ('실무 Spring Boot 백엔드 입문', 'Spring Boot', 3),
        ('실무 Spring Boot 백엔드 입문', 'JPA', 2),
        ('Docker & Kubernetes 운영 실전', 'Docker', 3),
        ('Docker & Kubernetes 운영 실전', 'Kubernetes', 3),
        ('Docker & Kubernetes 운영 실전', 'DevOps', 2),
        ('React 19 프론트엔드 실전 가이드', 'React', 3),
        ('React 19 프론트엔드 실전 가이드', 'TypeScript', 2),
        ('React 19 프론트엔드 실전 가이드', 'Tailwind', 2),
        ('Next.js 14 제품 개발 실전', 'Next.js', 3),
        ('Next.js 14 제품 개발 실전', 'React', 3),
        ('Next.js 14 제품 개발 실전', 'TypeScript', 2),
        ('Flutter로 MVP 앱 출시하기', 'Flutter', 3),
        ('Flutter로 MVP 앱 출시하기', '모바일', 2),
        ('Flutter로 MVP 앱 출시하기', '앱 출시', 2),
        ('ChatGPT API와 RAG 서비스 만들기', 'AI', 2),
        ('ChatGPT API와 RAG 서비스 만들기', 'LLM', 3),
        ('ChatGPT API와 RAG 서비스 만들기', 'RAG', 3),
        ('ChatGPT API와 RAG 서비스 만들기', 'LangChain', 2),
        ('SQL로 끝내는 데이터 분석 기본기', 'SQL', 3),
        ('SQL로 끝내는 데이터 분석 기본기', 'Pandas', 2),
        ('SQL로 끝내는 데이터 분석 기본기', '데이터', 2),
        ('개발자 이력서와 기술 면접 패키지', '이력서', 3),
        ('개발자 이력서와 기술 면접 패키지', '기술 면접', 3),
        ('개발자 이력서와 기술 면접 패키지', '포트폴리오', 2)
)
SELECT c.course_id, t.tag_id, ct.proficiency_level
FROM course_tags ct
JOIN courses c ON c.title = ct.course_title
JOIN tags t ON t.name = ct.tag_name
WHERE NOT EXISTS (
    SELECT 1 FROM course_tag_maps ctm
    WHERE ctm.course_id = c.course_id AND ctm.tag_id = t.tag_id
);

INSERT INTO course_sections (course_id, title, description, sort_order, is_published)
WITH sections(course_title, section_title, section_description, sort_order) AS (
    VALUES
        ('실무 Spring Boot 백엔드 입문', 'Spring Boot 프로젝트 시작', '프로젝트 구조, 계층 분리, REST API 흐름을 잡습니다.', 1),
        ('실무 Spring Boot 백엔드 입문', 'JPA와 인증 기본기', '데이터 모델링과 JWT 인증을 연결해 백엔드 기본 기능을 완성합니다.', 2),
        ('Docker & Kubernetes 운영 실전', '컨테이너 운영 기초', 'Dockerfile, 이미지, 컨테이너, Compose 실행 흐름을 다룹니다.', 1),
        ('Docker & Kubernetes 운영 실전', 'Kubernetes 배포 흐름', 'Deployment, Service, ConfigMap, Secret을 이용한 클러스터 배포를 익힙니다.', 2),
        ('React 19 프론트엔드 실전 가이드', 'React 구조 설계', '컴포넌트 경계와 상태 배치를 기준 있게 결정합니다.', 1),
        ('React 19 프론트엔드 실전 가이드', 'UI 품질과 테스트', 'Tailwind 스타일링과 Playwright 테스트로 화면 품질을 점검합니다.', 2),
        ('Next.js 14 제품 개발 실전', 'App Router와 데이터 흐름', '라우팅, 레이아웃, 서버 컴포넌트, 캐싱 전략을 연결합니다.', 1),
        ('Next.js 14 제품 개발 실전', '배포 가능한 제품 완성', '인증, 이미지 최적화, 메타데이터, 출시 점검을 다룹니다.', 2),
        ('Flutter로 MVP 앱 출시하기', 'Flutter 앱 구조', '위젯 트리, 상태 관리, 라우팅, 폼 검증으로 앱의 뼈대를 만듭니다.', 1),
        ('Flutter로 MVP 앱 출시하기', '출시 준비', 'API 연동, 에러 처리, 빌드 설정과 스토어 제출 준비를 진행합니다.', 2),
        ('ChatGPT API와 RAG 서비스 만들기', 'LLM API 기본', '프롬프트, 메시지 구조, API 호출과 응답 처리를 다룹니다.', 1),
        ('ChatGPT API와 RAG 서비스 만들기', 'RAG 파이프라인', '문서 청킹, 임베딩, 검색, 생성을 하나의 서비스 흐름으로 연결합니다.', 2),
        ('SQL로 끝내는 데이터 분석 기본기', 'SQL 분석 기초', 'SELECT, JOIN, GROUP BY, 윈도우 함수로 업무 지표를 계산합니다.', 1),
        ('SQL로 끝내는 데이터 분석 기본기', 'Pandas 리포트 자동화', 'CSV 정리, 결측치 처리, 집계 테이블 작성으로 리포트를 자동화합니다.', 2),
        ('개발자 이력서와 기술 면접 패키지', '이력서 스토리라인', '프로젝트 경험을 성과 중심 문장과 STAR 구조로 정리합니다.', 1),
        ('개발자 이력서와 기술 면접 패키지', '면접과 포트폴리오', '기술 면접 답변과 GitHub 포트폴리오 정리를 함께 진행합니다.', 2)
)
SELECT c.course_id, s.section_title, s.section_description, s.sort_order, TRUE
FROM sections s
JOIN courses c ON c.title = s.course_title
WHERE NOT EXISTS (
    SELECT 1 FROM course_sections cs
    WHERE cs.course_id = c.course_id AND cs.sort_order = s.sort_order
);

INSERT INTO lessons (
    section_id, title, description, lesson_type,
    video_url, video_asset_key, video_provider,
    thumbnail_url, duration_seconds, is_preview, is_published, sort_order
)
WITH lessons_seed(course_title, section_order, lesson_order, lesson_title, lesson_description, lesson_type, video_url, duration_seconds, is_preview) AS (
    VALUES
        ('실무 Spring Boot 백엔드 입문', 1, 1, '프로젝트 구조와 개발 환경 세팅', 'Gradle 프로젝트 구조와 로컬 실행 환경을 맞춥니다.', 'VIDEO', '/samples/ocr-code-demo.mp4', 780, TRUE),
        ('실무 Spring Boot 백엔드 입문', 1, 2, 'REST API 흐름과 계층 분리', 'Controller, Service, Repository의 책임을 나누어 구현합니다.', 'VIDEO', '/samples/sample-intro.mp4', 960, FALSE),
        ('실무 Spring Boot 백엔드 입문', 1, 3, '섹션 마무리 퀴즈: Controller-Service-Repository 흐름', '요청 흐름과 계층별 책임을 점검합니다.', 'READING', NULL, 300, FALSE),
        ('실무 Spring Boot 백엔드 입문', 2, 1, 'Entity 설계와 Repository 작성', '회원 도메인을 기준으로 Entity와 Repository를 작성합니다.', 'VIDEO', '/samples/ocr-code-demo.mp4', 1020, FALSE),
        ('실무 Spring Boot 백엔드 입문', 2, 2, 'Spring Security와 JWT 인증 흐름', '로그인 요청부터 토큰 검증까지의 흐름을 연결합니다.', 'VIDEO', '/samples/sample-intro.mp4', 1080, FALSE),
        ('실무 Spring Boot 백엔드 입문', 2, 3, '실습 과제: 회원 API와 JWT 로그인 완성', '회원 가입, 로그인, 인증 테스트 결과를 제출합니다.', 'CODING', NULL, 900, FALSE),
        ('Docker & Kubernetes 운영 실전', 1, 1, 'Dockerfile 작성과 이미지 빌드', '멀티 스테이지 빌드와 이미지 태그 전략을 익힙니다.', 'VIDEO', '/samples/ocr-code-demo.mp4', 840, TRUE),
        ('Docker & Kubernetes 운영 실전', 1, 2, 'Docker Compose로 로컬 환경 구성', 'DB와 애플리케이션을 Compose로 함께 실행합니다.', 'VIDEO', '/samples/sample-intro.mp4', 960, FALSE),
        ('Docker & Kubernetes 운영 실전', 1, 3, '섹션 마무리 퀴즈: 이미지와 컨테이너 생명주기', '이미지, 컨테이너, 볼륨의 차이를 점검합니다.', 'READING', NULL, 300, FALSE),
        ('Docker & Kubernetes 운영 실전', 2, 1, 'Deployment와 Service 이해', 'Pod 복제와 네트워크 노출 방식을 실습합니다.', 'VIDEO', '/samples/ocr-code-demo.mp4', 1020, FALSE),
        ('Docker & Kubernetes 운영 실전', 2, 2, 'ConfigMap과 Secret 적용', '환경 설정과 민감 정보를 분리해 배포합니다.', 'VIDEO', '/samples/sample-intro.mp4', 900, FALSE),
        ('Docker & Kubernetes 운영 실전', 2, 3, '실습 과제: 무중단 배포 매니페스트 작성', 'Deployment, Service, ConfigMap을 포함한 배포 파일을 제출합니다.', 'CODING', NULL, 900, FALSE),
        ('React 19 프론트엔드 실전 가이드', 1, 1, '컴포넌트 경계와 상태 배치', '상태가 살아야 할 위치와 컴포넌트 책임을 정합니다.', 'VIDEO', '/samples/ocr-code-demo.mp4', 900, TRUE),
        ('React 19 프론트엔드 실전 가이드', 1, 2, 'Actions와 폼 처리 패턴', '폼 제출, 낙관적 업데이트, 오류 메시지 흐름을 구성합니다.', 'VIDEO', '/samples/sample-intro.mp4', 960, FALSE),
        ('React 19 프론트엔드 실전 가이드', 1, 3, '섹션 마무리 퀴즈: 상태 설계 판단 기준', '지역 상태와 공유 상태를 구분하는 기준을 점검합니다.', 'READING', NULL, 300, FALSE),
        ('React 19 프론트엔드 실전 가이드', 2, 1, 'Tailwind 유틸리티 설계', '반복 스타일을 줄이고 화면 단위를 안정적으로 구성합니다.', 'VIDEO', '/samples/ocr-code-demo.mp4', 840, FALSE),
        ('React 19 프론트엔드 실전 가이드', 2, 2, 'Playwright로 사용자 흐름 테스트', '로그인부터 주요 액션까지 E2E 테스트를 작성합니다.', 'VIDEO', '/samples/sample-intro.mp4', 1020, FALSE),
        ('React 19 프론트엔드 실전 가이드', 2, 3, '실습 과제: 대시보드 화면 완성', '학습 현황 대시보드의 목록, 필터, 통계 카드, 상세 확인 흐름을 구현하고 E2E 테스트 결과를 제출합니다.', 'CODING', NULL, 900, FALSE),
        ('Next.js 14 제품 개발 실전', 1, 1, '라우팅과 레이아웃 구조 설계', 'App Router에서 공통 레이아웃과 상세 페이지를 분리합니다.', 'VIDEO', '/samples/ocr-code-demo.mp4', 900, TRUE),
        ('Next.js 14 제품 개발 실전', 1, 2, '서버 컴포넌트와 캐싱 전략', '서버 렌더링 데이터와 캐시 무효화 기준을 정합니다.', 'VIDEO', '/samples/sample-intro.mp4', 1080, FALSE),
        ('Next.js 14 제품 개발 실전', 1, 3, '섹션 마무리 퀴즈: App Router 데이터 흐름', '서버 컴포넌트와 클라이언트 컴포넌트의 역할을 점검합니다.', 'READING', NULL, 300, FALSE),
        ('Next.js 14 제품 개발 실전', 2, 1, '인증과 권한 처리', '세션 확인과 보호 라우트 처리 흐름을 구현합니다.', 'VIDEO', '/samples/ocr-code-demo.mp4', 960, FALSE),
        ('Next.js 14 제품 개발 실전', 2, 2, '이미지 최적화와 메타데이터', '제품 상세 화면의 이미지, title, description을 정리합니다.', 'VIDEO', '/samples/sample-intro.mp4', 840, FALSE),
        ('Next.js 14 제품 개발 실전', 2, 3, '실습 과제: 예약 상세 페이지 출시 체크리스트', '예약 상세 페이지를 만들고 성능, 접근성, SEO 점검 결과를 제출합니다.', 'CODING', NULL, 900, FALSE),
        ('Flutter로 MVP 앱 출시하기', 1, 1, '위젯 트리와 상태 관리', 'StatelessWidget, StatefulWidget, 상태 변경 흐름을 정리합니다.', 'VIDEO', '/samples/ocr-code-demo.mp4', 840, TRUE),
        ('Flutter로 MVP 앱 출시하기', 1, 2, '라우팅과 폼 검증', '화면 이동과 입력 검증을 이용해 가입 화면을 만듭니다.', 'VIDEO', '/samples/sample-intro.mp4', 900, FALSE),
        ('Flutter로 MVP 앱 출시하기', 1, 3, '섹션 마무리 퀴즈: 위젯과 상태 흐름', '위젯 분리와 상태 갱신 범위를 점검합니다.', 'READING', NULL, 300, FALSE),
        ('Flutter로 MVP 앱 출시하기', 2, 1, 'REST API 연동과 에러 처리', 'HTTP 요청, 로딩, 실패 메시지 처리를 구현합니다.', 'VIDEO', '/samples/ocr-code-demo.mp4', 960, FALSE),
        ('Flutter로 MVP 앱 출시하기', 2, 2, '앱 아이콘, 권한, 빌드 설정', '출시 전에 필요한 앱 메타데이터와 빌드 설정을 정리합니다.', 'VIDEO', '/samples/sample-intro.mp4', 780, FALSE),
        ('Flutter로 MVP 앱 출시하기', 2, 3, '실습 과제: 스토어 제출용 MVP 화면 완성', '핵심 화면 3개와 빌드 체크리스트를 제출합니다.', 'CODING', NULL, 900, FALSE),
        ('ChatGPT API와 RAG 서비스 만들기', 1, 1, '프롬프트와 메시지 구조', 'system, user, assistant 메시지의 역할과 프롬프트 템플릿을 정리합니다.', 'VIDEO', '/samples/ocr-code-demo.mp4', 900, TRUE),
        ('ChatGPT API와 RAG 서비스 만들기', 1, 2, 'LLM API 호출과 응답 처리', '환경 변수, 요청 본문, 스트리밍 응답 처리 흐름을 구현합니다.', 'VIDEO', '/samples/sample-intro.mp4', 1080, FALSE),
        ('ChatGPT API와 RAG 서비스 만들기', 1, 3, '섹션 마무리 퀴즈: 프롬프트와 토큰 관리', '프롬프트 구성과 토큰 비용을 점검합니다.', 'READING', NULL, 300, FALSE),
        ('ChatGPT API와 RAG 서비스 만들기', 2, 1, '문서 청킹과 임베딩 저장', '문서를 검색 가능한 단위로 나누고 임베딩을 저장합니다.', 'VIDEO', '/samples/ocr-code-demo.mp4', 1020, FALSE),
        ('ChatGPT API와 RAG 서비스 만들기', 2, 2, 'LangChain으로 검색-생성 연결', '검색 결과를 프롬프트에 넣어 답변을 생성합니다.', 'VIDEO', '/samples/sample-intro.mp4', 1140, FALSE),
        ('ChatGPT API와 RAG 서비스 만들기', 2, 3, '실습 과제: 사내 문서 Q&A 챗봇 프로토타입', '문서 업로드, 검색, 답변 생성 흐름이 있는 프로토타입을 제출합니다.', 'CODING', NULL, 900, FALSE),
        ('SQL로 끝내는 데이터 분석 기본기', 1, 1, 'SELECT, JOIN, GROUP BY 핵심', '업무 데이터 분석에 가장 자주 쓰는 SQL 패턴을 정리합니다.', 'VIDEO', '/samples/ocr-code-demo.mp4', 840, TRUE),
        ('SQL로 끝내는 데이터 분석 기본기', 1, 2, '윈도우 함수로 순위와 누적 계산', 'ROW_NUMBER, SUM OVER로 랭킹과 누적 지표를 계산합니다.', 'VIDEO', '/samples/sample-intro.mp4', 960, FALSE),
        ('SQL로 끝내는 데이터 분석 기본기', 1, 3, '섹션 마무리 퀴즈: 집계 쿼리 읽기', 'GROUP BY와 윈도우 함수의 차이를 점검합니다.', 'READING', NULL, 300, FALSE),
        ('SQL로 끝내는 데이터 분석 기본기', 2, 1, 'CSV 정리와 결측치 처리', 'Pandas로 원본 데이터를 정리하고 결측치를 처리합니다.', 'VIDEO', '/samples/ocr-code-demo.mp4', 900, FALSE),
        ('SQL로 끝내는 데이터 분석 기본기', 2, 2, '시각화용 집계 테이블 만들기', '차트에 바로 연결할 수 있는 분석 테이블을 만듭니다.', 'VIDEO', '/samples/sample-intro.mp4', 840, FALSE),
        ('SQL로 끝내는 데이터 분석 기본기', 2, 3, '실습 과제: 매출 리텐션 리포트 작성', 'SQL 결과와 Pandas 요약을 이용해 리포트를 제출합니다.', 'CODING', NULL, 900, FALSE),
        ('개발자 이력서와 기술 면접 패키지', 1, 1, '경력 없는 프로젝트를 성과로 쓰기', '기능 나열을 줄이고 문제, 행동, 결과 중심 문장으로 바꿉니다.', 'VIDEO', '/samples/ocr-code-demo.mp4', 780, TRUE),
        ('개발자 이력서와 기술 면접 패키지', 1, 2, 'STAR 방식으로 경험 정리하기', 'Situation, Task, Action, Result 구조로 경험을 정리합니다.', 'VIDEO', '/samples/sample-intro.mp4', 840, FALSE),
        ('개발자 이력서와 기술 면접 패키지', 1, 3, '섹션 마무리 퀴즈: 이력서 문장 점검', '좋은 이력서 문장과 나쁜 문장을 구분합니다.', 'READING', NULL, 300, FALSE),
        ('개발자 이력서와 기술 면접 패키지', 2, 1, 'CS와 프로젝트 질문 답변 구조', '기술 선택 이유, 트러블슈팅, 개선 경험을 답변으로 구성합니다.', 'VIDEO', '/samples/ocr-code-demo.mp4', 900, FALSE),
        ('개발자 이력서와 기술 면접 패키지', 2, 2, 'GitHub README와 배포 링크 정리', '면접관이 바로 확인할 수 있는 README와 데모 링크를 정리합니다.', 'VIDEO', '/samples/sample-intro.mp4', 720, FALSE),
        ('개발자 이력서와 기술 면접 패키지', 2, 3, '실습 과제: 지원 포지션 맞춤 이력서 완성', '지원 포지션 하나를 정해 이력서와 프로젝트 설명을 제출합니다.', 'CODING', NULL, 900, FALSE)
)
SELECT
    cs.section_id,
    ls.lesson_title,
    ls.lesson_description,
    ls.lesson_type,
    ls.video_url,
    NULL,
    NULL,
    c.thumbnail_url,
    ls.duration_seconds,
    ls.is_preview,
    TRUE,
    ls.lesson_order
FROM lessons_seed ls
JOIN courses c ON c.title = ls.course_title
JOIN course_sections cs ON cs.course_id = c.course_id AND cs.sort_order = ls.section_order
WHERE NOT EXISTS (
    SELECT 1 FROM lessons l
    WHERE l.section_id = cs.section_id AND l.sort_order = ls.lesson_order
);

INSERT INTO roadmaps (creator_id, title, description, is_official, is_public, is_deleted, created_at)
SELECT
    u.user_id,
    'DevPath 공개 강의 평가 데이터',
    '공개 강의 섹션 마지막 퀴즈와 과제를 연결하기 위한 내부 로드맵입니다.',
    FALSE,
    FALSE,
    FALSE,
    TIMESTAMP '2026-04-01 10:00:00'
FROM users u
WHERE u.email = 'admin@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM roadmaps r WHERE r.title = 'DevPath 공개 강의 평가 데이터');

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, section_order)
WITH activity_nodes(course_title, section_order, activity_kind, node_title, node_content, sort_order) AS (
    VALUES
        ('실무 Spring Boot 백엔드 입문', 1, 'QUIZ', '[CATALOG] 실무 Spring Boot 백엔드 입문 - 1 QUIZ', 'Spring Boot 계층 구조와 요청 흐름을 확인하는 퀴즈입니다.', 1001),
        ('실무 Spring Boot 백엔드 입문', 2, 'ASSIGNMENT', '[CATALOG] 실무 Spring Boot 백엔드 입문 - 2 ASSIGNMENT', '회원 API와 JWT 로그인 흐름을 완성하는 과제입니다.', 1002),
        ('Docker & Kubernetes 운영 실전', 1, 'QUIZ', '[CATALOG] Docker & Kubernetes 운영 실전 - 1 QUIZ', '이미지, 컨테이너, Compose 실행 흐름을 확인하는 퀴즈입니다.', 1011),
        ('Docker & Kubernetes 운영 실전', 2, 'ASSIGNMENT', '[CATALOG] Docker & Kubernetes 운영 실전 - 2 ASSIGNMENT', 'Kubernetes 배포 매니페스트를 작성하는 과제입니다.', 1012),
        ('React 19 프론트엔드 실전 가이드', 1, 'QUIZ', '[CATALOG] React 19 프론트엔드 실전 가이드 - 1 QUIZ', 'React 상태 설계와 컴포넌트 경계를 확인하는 퀴즈입니다.', 1021),
        ('React 19 프론트엔드 실전 가이드', 2, 'ASSIGNMENT', '[CATALOG] React 19 프론트엔드 실전 가이드 - 2 ASSIGNMENT', $$아래 요구사항을 만족하는 학습 현황 대시보드를 React 19와 TypeScript로 구현하세요.

상황. DevPath 학습자가 수강 중인 강의와 로드맵 진행 상태를 한 화면에서 확인하고, 상태별로 빠르게 필터링할 수 있는 내부 대시보드를 만든다고 가정합니다.

필수 구현.
1. 강의와 로드맵 목록을 배열 데이터 또는 API 응답 형태로 구성하고, 검색어와 상태 필터(전체, 진행 중, 완료, 미시작)에 따라 목록을 갱신하세요.
2. 필터 결과를 기준으로 총 학습 항목 수, 진행 중 항목 수, 평균 진행률, 이번 주 학습 시간을 계산해 통계 카드에 표시하세요.
3. 최근 학습 항목을 선택하면 제목, 진행률, 다음 학습 액션이 포함된 상세 영역 또는 모달을 표시하세요.
4. 로딩, 빈 결과, 오류 상태를 각각 다른 UI로 분리하고 Tailwind 유틸리티가 과도하게 반복되지 않도록 컴포넌트를 나누세요.
5. 모바일 390px, 데스크톱 1280px 기준에서 카드와 목록이 겹치거나 줄이 깨지지 않도록 반응형 레이아웃을 적용하세요.

테스트.
Playwright로 검색어 입력, 상태 필터 변경, 통계 카드 재계산, 최근 학습 항목 상세 열기 흐름을 검증하세요.

제출물.
GitHub URL 또는 zip 파일, 실행 방법, 주요 컴포넌트 구조, 테스트 실행 결과, 구현 화면 캡처를 README에 포함해 제출하세요.$$,
            1022),
        ('Next.js 14 제품 개발 실전', 1, 'QUIZ', '[CATALOG] Next.js 14 제품 개발 실전 - 1 QUIZ', 'App Router와 서버 컴포넌트 역할을 확인하는 퀴즈입니다.', 1031),
        ('Next.js 14 제품 개발 실전', 2, 'ASSIGNMENT', '[CATALOG] Next.js 14 제품 개발 실전 - 2 ASSIGNMENT', '예약 상세 페이지 출시 체크리스트를 완성하는 과제입니다.', 1032),
        ('Flutter로 MVP 앱 출시하기', 1, 'QUIZ', '[CATALOG] Flutter로 MVP 앱 출시하기 - 1 QUIZ', '위젯 구조와 상태 흐름을 확인하는 퀴즈입니다.', 1041),
        ('Flutter로 MVP 앱 출시하기', 2, 'ASSIGNMENT', '[CATALOG] Flutter로 MVP 앱 출시하기 - 2 ASSIGNMENT', '스토어 제출용 MVP 화면을 완성하는 과제입니다.', 1042),
        ('ChatGPT API와 RAG 서비스 만들기', 1, 'QUIZ', '[CATALOG] ChatGPT API와 RAG 서비스 만들기 - 1 QUIZ', '프롬프트 구성과 토큰 관리 기준을 확인하는 퀴즈입니다.', 1051),
        ('ChatGPT API와 RAG 서비스 만들기', 2, 'ASSIGNMENT', '[CATALOG] ChatGPT API와 RAG 서비스 만들기 - 2 ASSIGNMENT', '문서 기반 Q&A 챗봇 프로토타입을 완성하는 과제입니다.', 1052),
        ('SQL로 끝내는 데이터 분석 기본기', 1, 'QUIZ', '[CATALOG] SQL로 끝내는 데이터 분석 기본기 - 1 QUIZ', '집계 쿼리와 윈도우 함수 차이를 확인하는 퀴즈입니다.', 1061),
        ('SQL로 끝내는 데이터 분석 기본기', 2, 'ASSIGNMENT', '[CATALOG] SQL로 끝내는 데이터 분석 기본기 - 2 ASSIGNMENT', '매출 리텐션 리포트를 작성하는 과제입니다.', 1062),
        ('개발자 이력서와 기술 면접 패키지', 1, 'QUIZ', '[CATALOG] 개발자 이력서와 기술 면접 패키지 - 1 QUIZ', '이력서 문장과 STAR 구조를 확인하는 퀴즈입니다.', 1071),
        ('개발자 이력서와 기술 면접 패키지', 2, 'ASSIGNMENT', '[CATALOG] 개발자 이력서와 기술 면접 패키지 - 2 ASSIGNMENT', '지원 포지션 맞춤 이력서를 완성하는 과제입니다.', 1072)
)
SELECT
    r.roadmap_id,
    an.node_title,
    an.node_content,
    an.activity_kind,
    an.sort_order,
    an.course_title,
    an.section_order
FROM activity_nodes an
JOIN roadmaps r ON r.title = 'DevPath 공개 강의 평가 데이터'
WHERE NOT EXISTS (SELECT 1 FROM roadmap_nodes rn WHERE rn.title = an.node_title);

INSERT INTO course_node_mappings (course_id, node_id, created_at)
SELECT c.course_id, rn.node_id, TIMESTAMP '2026-04-01 10:10:00'
FROM courses c
JOIN roadmap_nodes rn ON rn.sub_topics = c.title
WHERE rn.title LIKE '[CATALOG]%'
  AND NOT EXISTS (
      SELECT 1 FROM course_node_mappings cnm
      WHERE cnm.course_id = c.course_id AND cnm.node_id = rn.node_id
  );

UPDATE lessons l
SET quiz_node_id = (
    SELECT rn.node_id
    FROM course_sections cs
    JOIN courses c ON c.course_id = cs.course_id
    JOIN roadmap_nodes rn ON rn.sub_topics = c.title
                         AND rn.section_order = cs.sort_order
                         AND rn.node_type = 'QUIZ'
    WHERE cs.section_id = l.section_id
)
WHERE l.sort_order = 3
  AND l.title LIKE '섹션 마무리 퀴즈:%'
  AND l.quiz_node_id IS NULL
  AND EXISTS (
      SELECT 1
      FROM course_sections cs
      JOIN courses c ON c.course_id = cs.course_id
      JOIN roadmap_nodes rn ON rn.sub_topics = c.title
                           AND rn.section_order = cs.sort_order
                           AND rn.node_type = 'QUIZ'
      WHERE cs.section_id = l.section_id
  );

UPDATE lessons l
SET assignment_node_id = (
    SELECT rn.node_id
    FROM course_sections cs
    JOIN courses c ON c.course_id = cs.course_id
    JOIN roadmap_nodes rn ON rn.sub_topics = c.title
                         AND rn.section_order = cs.sort_order
                         AND rn.node_type = 'ASSIGNMENT'
    WHERE cs.section_id = l.section_id
)
WHERE l.sort_order = 3
  AND l.title LIKE '실습 과제:%'
  AND l.assignment_node_id IS NULL
  AND EXISTS (
      SELECT 1
      FROM course_sections cs
      JOIN courses c ON c.course_id = cs.course_id
      JOIN roadmap_nodes rn ON rn.sub_topics = c.title
                           AND rn.section_order = cs.sort_order
                           AND rn.node_type = 'ASSIGNMENT'
      WHERE cs.section_id = l.section_id
  );

INSERT INTO quizzes (
    node_id, title, description, quiz_type, total_score, pass_score,
    time_limit_minutes, is_published, is_active, expose_answer,
    expose_explanation, is_deleted, created_at, updated_at
)
SELECT
    rn.node_id,
    rn.sub_topics || ' 섹션 점검 퀴즈',
    rn.content,
    'MANUAL',
    10,
    7,
    10,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    FALSE,
    TIMESTAMP '2026-04-01 10:20:00',
    TIMESTAMP '2026-04-01 10:20:00'
FROM roadmap_nodes rn
WHERE rn.title LIKE '[CATALOG]%'
  AND rn.node_type = 'QUIZ'
  AND NOT EXISTS (SELECT 1 FROM quizzes q WHERE q.node_id = rn.node_id);

INSERT INTO quiz_questions (
    quiz_id, question_type, question_text, explanation, points,
    display_order, source_timestamp, is_deleted, created_at, updated_at
)
SELECT
    q.quiz_id,
    'MULTIPLE_CHOICE',
    rn.sub_topics || ' 섹션을 마무리할 때 가장 먼저 확인해야 하는 것은 무엇인가요?',
    '섹션 핵심 개념과 실습 요구사항이 일치하는지 확인해야 실제 적용으로 이어질 수 있습니다.',
    10,
    1,
    NULL,
    FALSE,
    TIMESTAMP '2026-04-01 10:25:00',
    TIMESTAMP '2026-04-01 10:25:00'
FROM quizzes q
JOIN roadmap_nodes rn ON rn.node_id = q.node_id
WHERE rn.title LIKE '[CATALOG]%'
  AND NOT EXISTS (
      SELECT 1 FROM quiz_questions qq
      WHERE qq.quiz_id = q.quiz_id AND qq.display_order = 1
  );

INSERT INTO quiz_question_options (
    question_id, option_text, is_correct, display_order,
    is_deleted, created_at, updated_at
)
SELECT
    qq.question_id,
    '섹션 핵심 개념과 실습 요구사항이 일치하는지 확인한다',
    TRUE,
    1,
    FALSE,
    TIMESTAMP '2026-04-01 10:30:00',
    TIMESTAMP '2026-04-01 10:30:00'
FROM quiz_questions qq
JOIN quizzes q ON q.quiz_id = qq.quiz_id
JOIN roadmap_nodes rn ON rn.node_id = q.node_id
WHERE rn.title LIKE '[CATALOG]%'
  AND NOT EXISTS (
      SELECT 1 FROM quiz_question_options qo
      WHERE qo.question_id = qq.question_id AND qo.display_order = 1
  );

INSERT INTO quiz_question_options (
    question_id, option_text, is_correct, display_order,
    is_deleted, created_at, updated_at
)
SELECT
    qq.question_id,
    '도구 이름만 외우고 동작 흐름은 확인하지 않는다',
    FALSE,
    2,
    FALSE,
    TIMESTAMP '2026-04-01 10:30:00',
    TIMESTAMP '2026-04-01 10:30:00'
FROM quiz_questions qq
JOIN quizzes q ON q.quiz_id = qq.quiz_id
JOIN roadmap_nodes rn ON rn.node_id = q.node_id
WHERE rn.title LIKE '[CATALOG]%'
  AND NOT EXISTS (
      SELECT 1 FROM quiz_question_options qo
      WHERE qo.question_id = qq.question_id AND qo.display_order = 2
  );

INSERT INTO quiz_questions (
    quiz_id, question_type, question_text, explanation, points,
    display_order, source_timestamp, is_deleted, created_at, updated_at
)
WITH catalog_quiz_question_seed(course_title, question_text, explanation) AS (
    VALUES
        ('실무 Spring Boot 백엔드 입문', 'Spring Boot REST API 구조에서 Controller의 역할로 가장 적절한 것은 무엇인가요?', 'Controller는 HTTP 요청과 응답을 담당하고, 핵심 비즈니스 흐름은 Service로 위임하는 것이 일반적인 계층 분리 방식입니다.'),
        ('Docker & Kubernetes 운영 실전', 'Docker 이미지와 컨테이너의 관계로 가장 올바른 설명은 무엇인가요?', '이미지는 실행 가능한 템플릿이고, 컨테이너는 그 이미지를 기반으로 실행된 인스턴스입니다.'),
        ('React 19 프론트엔드 실전 가이드', 'React에서 상태 위치를 정할 때 가장 먼저 고려해야 하는 기준은 무엇인가요?', '상태는 필요한 컴포넌트들이 공유할 수 있는 가장 가까운 공통 부모에 두는 것이 기본 판단 기준입니다.'),
        ('Next.js 14 제품 개발 실전', 'Next.js App Router에서 서버 컴포넌트와 클라이언트 컴포넌트의 역할 구분으로 맞는 것은 무엇인가요?', '서버 컴포넌트는 서버 데이터 조회와 렌더링에 강하고, 클라이언트 컴포넌트는 브라우저 상호작용 상태를 담당합니다.'),
        ('Flutter로 MVP 앱 출시하기', 'Flutter 화면을 구현할 때 상태 변경 범위를 줄이는 이유로 가장 적절한 것은 무엇인가요?', '상태 변경 범위를 좁히면 필요한 위젯만 다시 그리도록 설계할 수 있어 화면 관리가 단순해집니다.'),
        ('ChatGPT API와 RAG 서비스 만들기', 'RAG 파이프라인의 핵심 흐름으로 가장 적절한 것은 무엇인가요?', '문서를 검색 가능한 단위로 나누고 임베딩한 뒤, 검색 결과를 프롬프트에 넣어 답변을 생성합니다.'),
        ('SQL로 끝내는 데이터 분석 기본기', 'GROUP BY와 윈도우 함수의 차이로 가장 올바른 설명은 무엇인가요?', 'GROUP BY는 행을 그룹별 결과로 줄이고, 윈도우 함수는 원래 행을 유지하면서 집계 값을 함께 계산합니다.'),
        ('개발자 이력서와 기술 면접 패키지', '프로젝트 경험을 이력서 문장으로 바꿀 때 가장 좋은 방식은 무엇인가요?', '문제, 행동, 결과를 연결하고 가능한 경우 수치나 근거를 붙이면 경험의 설득력이 높아집니다.')
)
SELECT
    q.quiz_id,
    'MULTIPLE_CHOICE',
    seed.question_text,
    seed.explanation,
    10,
    2,
    NULL,
    FALSE,
    TIMESTAMP '2026-04-01 10:35:00',
    TIMESTAMP '2026-04-01 10:35:00'
FROM catalog_quiz_question_seed seed
JOIN roadmap_nodes rn ON rn.sub_topics = seed.course_title
                     AND rn.node_type = 'QUIZ'
                     AND rn.title LIKE '[CATALOG]%'
JOIN quizzes q ON q.node_id = rn.node_id
WHERE NOT EXISTS (
    SELECT 1
    FROM quiz_questions qq
    WHERE qq.quiz_id = q.quiz_id
      AND qq.display_order = 2
);

INSERT INTO quiz_question_options (
    question_id, option_text, is_correct, display_order,
    is_deleted, created_at, updated_at
)
WITH catalog_quiz_option_seed(course_title, option_text, is_correct, display_order) AS (
    VALUES
        ('실무 Spring Boot 백엔드 입문', 'HTTP 요청과 응답을 받고 Service로 비즈니스 흐름을 위임한다', TRUE, 1),
        ('실무 Spring Boot 백엔드 입문', '데이터베이스 테이블을 직접 생성하고 인덱스를 관리한다', FALSE, 2),
        ('실무 Spring Boot 백엔드 입문', 'JVM 메모리 영역을 직접 할당하고 해제한다', FALSE, 3),
        ('실무 Spring Boot 백엔드 입문', '프론트엔드 화면 상태를 렌더링한다', FALSE, 4),
        ('Docker & Kubernetes 운영 실전', '이미지는 실행 템플릿이고 컨테이너는 실행된 인스턴스이다', TRUE, 1),
        ('Docker & Kubernetes 운영 실전', '컨테이너는 이미지를 만들기 전 반드시 먼저 존재해야 한다', FALSE, 2),
        ('Docker & Kubernetes 운영 실전', '이미지는 실행 중인 프로세스 하나만 의미한다', FALSE, 3),
        ('Docker & Kubernetes 운영 실전', '이미지와 컨테이너는 항상 같은 ID를 가진다', FALSE, 4),
        ('React 19 프론트엔드 실전 가이드', '상태를 필요한 컴포넌트들의 가장 가까운 공통 부모에 둔다', TRUE, 1),
        ('React 19 프론트엔드 실전 가이드', '모든 상태를 전역 저장소에만 둔다', FALSE, 2),
        ('React 19 프론트엔드 실전 가이드', '하위 컴포넌트마다 같은 상태를 복사해서 둔다', FALSE, 3),
        ('React 19 프론트엔드 실전 가이드', '상태 위치는 렌더링 결과와 무관하므로 임의로 정한다', FALSE, 4),
        ('Next.js 14 제품 개발 실전', '서버 컴포넌트는 서버 데이터 조회에, 클라이언트 컴포넌트는 상호작용 상태에 사용한다', TRUE, 1),
        ('Next.js 14 제품 개발 실전', '모든 컴포넌트에 use client를 붙여야 App Router가 동작한다', FALSE, 2),
        ('Next.js 14 제품 개발 실전', '서버 컴포넌트는 브라우저 클릭 이벤트를 직접 처리한다', FALSE, 3),
        ('Next.js 14 제품 개발 실전', '클라이언트 컴포넌트는 절대 props를 받을 수 없다', FALSE, 4),
        ('Flutter로 MVP 앱 출시하기', '상태 변경 범위를 좁혀 필요한 위젯만 다시 그리도록 설계한다', TRUE, 1),
        ('Flutter로 MVP 앱 출시하기', '모든 입력값을 하나의 전역 변수에 저장한다', FALSE, 2),
        ('Flutter로 MVP 앱 출시하기', '빌드 메서드 안에서 네트워크 요청을 무조건 반복 실행한다', FALSE, 3),
        ('Flutter로 MVP 앱 출시하기', '위젯 트리는 상태 관리와 관계가 없다', FALSE, 4),
        ('ChatGPT API와 RAG 서비스 만들기', '문서를 청킹하고 임베딩한 뒤 검색 결과를 프롬프트에 넣어 답변을 생성한다', TRUE, 1),
        ('ChatGPT API와 RAG 서비스 만들기', '모든 문서를 한 번에 프롬프트에 넣고 토큰 제한은 고려하지 않는다', FALSE, 2),
        ('ChatGPT API와 RAG 서비스 만들기', '검색 단계 없이 항상 모델 파라미터만 늘린다', FALSE, 3),
        ('ChatGPT API와 RAG 서비스 만들기', '임베딩은 사용자 로그인 토큰을 암호화하는 절차다', FALSE, 4),
        ('SQL로 끝내는 데이터 분석 기본기', 'GROUP BY는 행을 줄이고 윈도우 함수는 행을 유지한 채 계산한다', TRUE, 1),
        ('SQL로 끝내는 데이터 분석 기본기', 'GROUP BY와 윈도우 함수는 항상 완전히 같은 결과를 만든다', FALSE, 2),
        ('SQL로 끝내는 데이터 분석 기본기', '윈도우 함수는 SELECT 문에서 사용할 수 없다', FALSE, 3),
        ('SQL로 끝내는 데이터 분석 기본기', 'GROUP BY는 정렬만 수행하고 집계는 하지 않는다', FALSE, 4),
        ('개발자 이력서와 기술 면접 패키지', '문제, 행동, 결과를 연결하고 수치나 근거를 함께 적는다', TRUE, 1),
        ('개발자 이력서와 기술 면접 패키지', '사용한 기술 이름만 길게 나열한다', FALSE, 2),
        ('개발자 이력서와 기술 면접 패키지', '팀 프로젝트에서 본인의 역할을 일부러 숨긴다', FALSE, 3),
        ('개발자 이력서와 기술 면접 패키지', '결과나 배운 점 없이 기능 목록만 적는다', FALSE, 4)
)
SELECT
    qq.question_id,
    seed.option_text,
    seed.is_correct,
    seed.display_order,
    FALSE,
    TIMESTAMP '2026-04-01 10:40:00',
    TIMESTAMP '2026-04-01 10:40:00'
FROM catalog_quiz_option_seed seed
JOIN roadmap_nodes rn ON rn.sub_topics = seed.course_title
                     AND rn.node_type = 'QUIZ'
                     AND rn.title LIKE '[CATALOG]%'
JOIN quizzes q ON q.node_id = rn.node_id
JOIN quiz_questions qq ON qq.quiz_id = q.quiz_id
                       AND qq.display_order = 2
WHERE NOT EXISTS (
    SELECT 1
    FROM quiz_question_options qo
    WHERE qo.question_id = qq.question_id
      AND qo.display_order = seed.display_order
);

INSERT INTO assignments (
    node_id, title, description, submission_type, due_at, allowed_file_formats,
    readme_required, test_required, lint_required, submission_rule_description,
    total_score, pass_score, is_published, is_active, allow_late_submission,
    ai_review_enabled, allow_text_submission,
    allow_file_submission, allow_url_submission, is_deleted, created_at, updated_at
)
SELECT
    rn.node_id,
    rn.sub_topics || ' 섹션 실습 과제',
    rn.content,
    'MULTIPLE',
    TIMESTAMP '2026-05-31 23:59:59',
    'md,pdf,zip,github-url',
    TRUE,
    FALSE,
    FALSE,
    'GitHub URL, 실행 방법, 결과 캡처 또는 요약 문서를 함께 제출하세요.',
    100,
    70,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    FALSE,
    TIMESTAMP '2026-04-01 10:35:00',
    TIMESTAMP '2026-04-01 10:35:00'
FROM roadmap_nodes rn
WHERE rn.title LIKE '[CATALOG]%'
  AND rn.node_type = 'ASSIGNMENT'
  AND NOT EXISTS (SELECT 1 FROM assignments a WHERE a.node_id = rn.node_id);

-- React 19 섹션 2 과제는 학습 플레이어에서 SQL-backed assignments.description으로 노출된다.
UPDATE lessons
SET description = '학습 현황 대시보드의 목록, 필터, 통계 카드, 상세 확인 흐름을 구현하고 E2E 테스트 결과를 제출합니다.'
WHERE title = '실습 과제: 대시보드 화면 완성'
  AND section_id IN (
      SELECT cs.section_id
      FROM course_sections cs
      JOIN courses c ON c.course_id = cs.course_id
      WHERE c.title = 'React 19 프론트엔드 실전 가이드'
        AND cs.sort_order = 2
  );

UPDATE roadmap_nodes
SET content = $$아래 요구사항을 만족하는 학습 현황 대시보드를 React 19와 TypeScript로 구현하세요.

상황. DevPath 학습자가 수강 중인 강의와 로드맵 진행 상태를 한 화면에서 확인하고, 상태별로 빠르게 필터링할 수 있는 내부 대시보드를 만든다고 가정합니다.

필수 구현.
1. 강의와 로드맵 목록을 배열 데이터 또는 API 응답 형태로 구성하고, 검색어와 상태 필터(전체, 진행 중, 완료, 미시작)에 따라 목록을 갱신하세요.
2. 필터 결과를 기준으로 총 학습 항목 수, 진행 중 항목 수, 평균 진행률, 이번 주 학습 시간을 계산해 통계 카드에 표시하세요.
3. 최근 학습 항목을 선택하면 제목, 진행률, 다음 학습 액션이 포함된 상세 영역 또는 모달을 표시하세요.
4. 로딩, 빈 결과, 오류 상태를 각각 다른 UI로 분리하고 Tailwind 유틸리티가 과도하게 반복되지 않도록 컴포넌트를 나누세요.
5. 모바일 390px, 데스크톱 1280px 기준에서 카드와 목록이 겹치거나 줄이 깨지지 않도록 반응형 레이아웃을 적용하세요.

테스트.
Playwright로 검색어 입력, 상태 필터 변경, 통계 카드 재계산, 최근 학습 항목 상세 열기 흐름을 검증하세요.

제출물.
GitHub URL 또는 zip 파일, 실행 방법, 주요 컴포넌트 구조, 테스트 실행 결과, 구현 화면 캡처를 README에 포함해 제출하세요.$$
WHERE title = '[CATALOG] React 19 프론트엔드 실전 가이드 - 2 ASSIGNMENT'
  AND node_type = 'ASSIGNMENT'
  AND sub_topics = 'React 19 프론트엔드 실전 가이드'
  AND section_order = 2;

UPDATE assignments
SET title = '학습 현황 대시보드 구현 및 E2E 테스트 과제',
    description = $$아래 요구사항을 만족하는 학습 현황 대시보드를 React 19와 TypeScript로 구현하세요.

상황. DevPath 학습자가 수강 중인 강의와 로드맵 진행 상태를 한 화면에서 확인하고, 상태별로 빠르게 필터링할 수 있는 내부 대시보드를 만든다고 가정합니다.

필수 구현.
1. 강의와 로드맵 목록을 배열 데이터 또는 API 응답 형태로 구성하고, 검색어와 상태 필터(전체, 진행 중, 완료, 미시작)에 따라 목록을 갱신하세요.
2. 필터 결과를 기준으로 총 학습 항목 수, 진행 중 항목 수, 평균 진행률, 이번 주 학습 시간을 계산해 통계 카드에 표시하세요.
3. 최근 학습 항목을 선택하면 제목, 진행률, 다음 학습 액션이 포함된 상세 영역 또는 모달을 표시하세요.
4. 로딩, 빈 결과, 오류 상태를 각각 다른 UI로 분리하고 Tailwind 유틸리티가 과도하게 반복되지 않도록 컴포넌트를 나누세요.
5. 모바일 390px, 데스크톱 1280px 기준에서 카드와 목록이 겹치거나 줄이 깨지지 않도록 반응형 레이아웃을 적용하세요.

테스트.
Playwright로 검색어 입력, 상태 필터 변경, 통계 카드 재계산, 최근 학습 항목 상세 열기 흐름을 검증하세요.

제출물.
GitHub URL 또는 zip 파일, 실행 방법, 주요 컴포넌트 구조, 테스트 실행 결과, 구현 화면 캡처를 README에 포함해 제출하세요.$$,
    test_required = TRUE,
    submission_rule_description = 'README에 실행 방법, 구현 범위, Playwright 테스트 결과, 화면 캡처를 포함하고 GitHub URL 또는 zip 파일을 제출하세요.',
    updated_at = TIMESTAMP '2026-04-01 10:45:00'
WHERE node_id IN (
      SELECT rn.node_id
      FROM roadmap_nodes rn
      WHERE rn.title = '[CATALOG] React 19 프론트엔드 실전 가이드 - 2 ASSIGNMENT'
        AND rn.node_type = 'ASSIGNMENT'
        AND rn.sub_topics = 'React 19 프론트엔드 실전 가이드'
        AND rn.section_order = 2
  )
  AND is_deleted = FALSE;

INSERT INTO assignment_rubrics (
    assignment_id, criteria_name, criteria_description, max_points,
    display_order, is_deleted, created_at, updated_at
)
SELECT
    a.assignment_id,
    '요구사항 완성도',
    '섹션에서 요구한 핵심 기능과 산출물이 실행 가능한 형태로 제출되었습니다.',
    60,
    1,
    FALSE,
    TIMESTAMP '2026-04-01 10:40:00',
    TIMESTAMP '2026-04-01 10:40:00'
FROM assignments a
JOIN roadmap_nodes rn ON rn.node_id = a.node_id
WHERE rn.title LIKE '[CATALOG]%'
  AND NOT EXISTS (
      SELECT 1 FROM assignment_rubrics ar
      WHERE ar.assignment_id = a.assignment_id AND ar.display_order = 1
  );

INSERT INTO assignment_rubrics (
    assignment_id, criteria_name, criteria_description, max_points,
    display_order, is_deleted, created_at, updated_at
)
SELECT
    a.assignment_id,
    '문서화와 회고',
    '실행 방법, 판단 이유, 막힌 지점과 해결 과정을 README 또는 제출 문서에 정리했습니다.',
    40,
    2,
    FALSE,
    TIMESTAMP '2026-04-01 10:40:00',
    TIMESTAMP '2026-04-01 10:40:00'
FROM assignments a
JOIN roadmap_nodes rn ON rn.node_id = a.node_id
WHERE rn.title LIKE '[CATALOG]%'
  AND NOT EXISTS (
      SELECT 1 FROM assignment_rubrics ar
      WHERE ar.assignment_id = a.assignment_id AND ar.display_order = 2
  );

INSERT INTO course_announcements (
    course_id, announcement_type, title, content, is_pinned, display_order,
    published_at, exposure_start_at, exposure_end_at,
    event_banner_text, event_link, created_at, updated_at
)
WITH announcement_seed(course_title) AS (
    VALUES
        ('실무 Spring Boot 백엔드 입문'),
        ('Docker & Kubernetes 운영 실전'),
        ('React 19 프론트엔드 실전 가이드'),
        ('Next.js 14 제품 개발 실전'),
        ('Flutter로 MVP 앱 출시하기'),
        ('ChatGPT API와 RAG 서비스 만들기'),
        ('SQL로 끝내는 데이터 분석 기본기'),
        ('개발자 이력서와 기술 면접 패키지')
)
SELECT
    c.course_id,
    'NORMAL',
    a.course_title || ' 커리큘럼 업데이트',
    '섹션별 마지막 점검 활동과 실습 자료를 포함해 공개했습니다.',
    FALSE,
    1,
    TIMESTAMP '2026-04-09 09:00:00',
    TIMESTAMP '2026-04-09 09:00:00',
    NULL,
    NULL,
    NULL,
    TIMESTAMP '2026-04-09 09:00:00',
    TIMESTAMP '2026-04-09 09:00:00'
FROM announcement_seed a
JOIN courses c ON c.title = a.course_title
WHERE NOT EXISTS (
    SELECT 1 FROM course_announcements ca
    WHERE ca.course_id = c.course_id
      AND ca.title = a.course_title || ' 커리큘럼 업데이트'
);

-- ============================================================
-- BACKEND ROADMAP VIDEO CATALOG: 각 노드별 공개 영상 코스 추가
-- ============================================================
DROP TABLE IF EXISTS tmp_backend_roadmap_video_seed;

CREATE TABLE tmp_backend_roadmap_video_seed (
    node_title VARCHAR(255) NOT NULL,
    instructor_email VARCHAR(255) NOT NULL,
    difficulty_level VARCHAR(30) NOT NULL,
    published_at TIMESTAMP NOT NULL,
    thumbnail_url VARCHAR(1000) NOT NULL
);

INSERT INTO tmp_backend_roadmap_video_seed (
    node_title, instructor_email, difficulty_level, published_at, thumbnail_url
)
VALUES
    ('인터넷 & 웹 기초', 'frontend@devpath.com', 'BEGINNER', TIMESTAMP '2026-03-02 09:00:00', 'https://images.unsplash.com/photo-1510915228340-29c85a43dcfe?auto=format&fit=crop&w=1200&q=80'),
    ('OS & 터미널', 'instructor@devpath.com', 'BEGINNER', TIMESTAMP '2026-03-03 09:00:00', 'https://images.unsplash.com/photo-1498050108023-c5249f4df085?auto=format&fit=crop&w=1200&q=80'),
    ('Java 기초', 'instructor@devpath.com', 'BEGINNER', TIMESTAMP '2026-03-04 09:00:00', 'https://images.unsplash.com/photo-1517430816045-df4b7de11d1d?auto=format&fit=crop&w=1200&q=80'),
    ('Git & 버전 관리', 'frontend@devpath.com', 'BEGINNER', TIMESTAMP '2026-03-05 09:00:00', 'https://images.unsplash.com/photo-1496171367470-9ed9a91ea931?auto=format&fit=crop&w=1200&q=80'),
    ('RDB & SQL', 'data@devpath.com', 'BEGINNER', TIMESTAMP '2026-03-06 09:00:00', 'https://images.unsplash.com/photo-1461749280684-dccba630e2f6?auto=format&fit=crop&w=1200&q=80'),
    ('REST API 설계', 'frontend@devpath.com', 'INTERMEDIATE', TIMESTAMP '2026-03-07 09:00:00', 'https://images.unsplash.com/photo-1517248135467-4c7edcad34c4?auto=format&fit=crop&w=1200&q=80'),
    ('Spring Boot & MVC', 'instructor@devpath.com', 'INTERMEDIATE', TIMESTAMP '2026-03-08 09:00:00', 'https://images.unsplash.com/photo-1522542550221-31fd19575a2d?auto=format&fit=crop&w=1200&q=80'),
    ('Spring Data JPA', 'instructor@devpath.com', 'INTERMEDIATE', TIMESTAMP '2026-03-09 09:00:00', 'https://images.unsplash.com/photo-1516116216624-53e697fedbea?auto=format&fit=crop&w=1200&q=80'),
    ('Redis 기초', 'data@devpath.com', 'INTERMEDIATE', TIMESTAMP '2026-03-10 09:00:00', 'https://images.unsplash.com/photo-1504384308090-c894fdcc538d?auto=format&fit=crop&w=1200&q=80'),
    ('Redis 심화', 'data@devpath.com', 'ADVANCED', TIMESTAMP '2026-03-11 09:00:00', 'https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?auto=format&fit=crop&w=1200&q=80'),
    ('JUnit5 & Mockito', 'instructor@devpath.com', 'INTERMEDIATE', TIMESTAMP '2026-03-12 09:00:00', 'https://images.unsplash.com/photo-1526379095098-d400fd0bf935?auto=format&fit=crop&w=1200&q=80'),
    ('Spring Boot 테스트', 'instructor@devpath.com', 'INTERMEDIATE', TIMESTAMP '2026-03-13 09:00:00', 'https://images.unsplash.com/photo-1521737604893-d14cc237f11d?auto=format&fit=crop&w=1200&q=80'),
    ('Spring Security & JWT', 'instructor@devpath.com', 'ADVANCED', TIMESTAMP '2026-03-14 09:00:00', 'https://images.unsplash.com/photo-1522202176988-66273c2fd55f?auto=format&fit=crop&w=1200&q=80'),
    ('Docker & CI/CD', 'data@devpath.com', 'ADVANCED', TIMESTAMP '2026-03-15 09:00:00', 'https://images.unsplash.com/photo-1520607162513-77705c0f0d4a?auto=format&fit=crop&w=1200&q=80'),
    ('SOLID & 디자인패턴', 'instructor@devpath.com', 'INTERMEDIATE', TIMESTAMP '2026-03-16 09:00:00', 'https://images.unsplash.com/photo-1517148815978-75f6acaaf32c?auto=format&fit=crop&w=1200&q=80'),
    ('웹 보안 기초', 'frontend@devpath.com', 'INTERMEDIATE', TIMESTAMP '2026-03-17 09:00:00', 'https://images.unsplash.com/photo-1497366754035-f200968a6e72?auto=format&fit=crop&w=1200&q=80'),
    ('메시지 큐 & MSA', 'data@devpath.com', 'ADVANCED', TIMESTAMP '2026-03-18 09:00:00', 'https://images.unsplash.com/photo-1522252234503-e356532cafd5?auto=format&fit=crop&w=1200&q=80');

INSERT INTO courses (
    instructor_id, title, subtitle, description,
    thumbnail_url, intro_video_url, video_asset_key, duration_seconds,
    price, original_price, currency, difficulty_level, language,
    has_certificate, status, published_at
)
SELECT
    u.user_id,
    '로드맵 실전: ' || seed.node_title,
    seed.node_title || ' | ' || COALESCE(rn.sub_topics, '핵심 개념 정리'),
    rn.content || ' 필수 태그: ' || COALESCE(rn.sub_topics, seed.node_title)
        || '. 강의에서는 로드맵에서 요구하는 필수 태그를 실제 서비스 예제와 연결해 빠르게 정리합니다.',
    seed.thumbnail_url,
    CASE
        WHEN seed.node_title = 'OS & 터미널' THEN '/samples/lesson-os-process.mp4'
        WHEN seed.node_title IN ('Spring Boot & MVC', 'Spring Data JPA', 'Spring Boot 테스트', 'Spring Security & JWT')
            THEN '/samples/lesson-spring-di.mp4'
        ELSE '/samples/sample-intro.mp4'
    END,
    NULL,
    CASE seed.difficulty_level
        WHEN 'BEGINNER' THEN 7200
        WHEN 'INTERMEDIATE' THEN 9600
        ELSE 11400
    END,
    0,
    0,
    'KRW',
    seed.difficulty_level,
    'ko',
    TRUE,
    'PUBLISHED',
    seed.published_at
FROM tmp_backend_roadmap_video_seed seed
JOIN users u ON u.email = seed.instructor_email
JOIN roadmaps r ON r.title = 'Backend Master Roadmap'
JOIN roadmap_nodes rn ON rn.roadmap_id = r.roadmap_id AND rn.title = seed.node_title
WHERE NOT EXISTS (
    SELECT 1
    FROM courses c
    WHERE c.title = '로드맵 실전: ' || seed.node_title
);

UPDATE courses c
SET
    price = 0,
    original_price = 0,
    currency = 'KRW',
    thumbnail_url = seed.thumbnail_url
FROM tmp_backend_roadmap_video_seed seed
WHERE c.title = '로드맵 실전: ' || seed.node_title
  AND (
      COALESCE(c.price, -1) <> 0
      OR COALESCE(c.original_price, -1) <> 0
      OR COALESCE(c.currency, '') <> 'KRW'
      OR COALESCE(c.thumbnail_url, '') <> seed.thumbnail_url
  );

INSERT INTO course_prerequisites (course_id, prerequisite)
WITH prerequisite_seed(prerequisite_text, display_order) AS (
    VALUES
        ('백엔드 로드맵의 앞선 개념을 함께 보면 이해가 더 빠릅니다.', 1),
        ('기본적인 IDE 또는 터미널 사용 경험이 있으면 예제를 따라가기 쉽습니다.', 2)
)
SELECT c.course_id, ps.prerequisite_text
FROM tmp_backend_roadmap_video_seed seed
JOIN courses c ON c.title = '로드맵 실전: ' || seed.node_title
JOIN prerequisite_seed ps ON 1 = 1
WHERE NOT EXISTS (
    SELECT 1
    FROM course_prerequisites cp
    WHERE cp.course_id = c.course_id
      AND cp.prerequisite = ps.prerequisite_text
);

INSERT INTO course_job_relevance (course_id, job_relevance)
WITH relevance_seed(job_relevance, display_order) AS (
    VALUES
        ('백엔드 개발자', 1),
        ('서버 개발자', 2)
)
SELECT c.course_id, rs.job_relevance
FROM tmp_backend_roadmap_video_seed seed
JOIN courses c ON c.title = '로드맵 실전: ' || seed.node_title
JOIN relevance_seed rs ON 1 = 1
WHERE NOT EXISTS (
    SELECT 1
    FROM course_job_relevance cj
    WHERE cj.course_id = c.course_id
      AND cj.job_relevance = rs.job_relevance
);

INSERT INTO course_objectives (course_id, objective_text, display_order)
WITH objective_seed(display_order) AS (
    VALUES (1), (2)
)
SELECT
    c.course_id,
    CASE os.display_order
        WHEN 1 THEN seed.node_title || '의 핵심 개념과 요청/데이터 흐름을 설명할 수 있습니다.'
        ELSE '로드맵에서 요구하는 필수 태그를 예제와 연결해 실제 코드나 운영 흐름에 적용할 수 있습니다.'
    END,
    os.display_order
FROM tmp_backend_roadmap_video_seed seed
JOIN courses c ON c.title = '로드맵 실전: ' || seed.node_title
JOIN objective_seed os ON 1 = 1
WHERE NOT EXISTS (
    SELECT 1
    FROM course_objectives co
    WHERE co.course_id = c.course_id
      AND co.display_order = os.display_order
);

INSERT INTO course_target_audiences (course_id, audience_description, display_order)
WITH audience_seed(display_order) AS (
    VALUES (1), (2)
)
SELECT
    c.course_id,
    CASE ads.display_order
        WHEN 1 THEN seed.node_title || '를 실무 기준으로 다시 정리하고 싶은 백엔드 학습자'
        ELSE 'Backend Master Roadmap에서 해당 노드가 막혀 보강 영상이 필요한 주니어 개발자'
    END,
    ads.display_order
FROM tmp_backend_roadmap_video_seed seed
JOIN courses c ON c.title = '로드맵 실전: ' || seed.node_title
JOIN audience_seed ads ON 1 = 1
WHERE NOT EXISTS (
    SELECT 1
    FROM course_target_audiences cta
    WHERE cta.course_id = c.course_id
      AND cta.display_order = ads.display_order
);

INSERT INTO course_tag_maps (course_id, tag_id, proficiency_level)
SELECT
    c.course_id,
    nrt.tag_id,
    CASE seed.difficulty_level
        WHEN 'BEGINNER' THEN 2
        ELSE 3
    END
FROM tmp_backend_roadmap_video_seed seed
JOIN courses c ON c.title = '로드맵 실전: ' || seed.node_title
JOIN roadmaps r ON r.title = 'Backend Master Roadmap'
JOIN roadmap_nodes rn ON rn.roadmap_id = r.roadmap_id AND rn.title = seed.node_title
JOIN node_required_tags nrt ON nrt.node_id = rn.node_id
WHERE NOT EXISTS (
    SELECT 1
    FROM course_tag_maps ctm
    WHERE ctm.course_id = c.course_id
      AND ctm.tag_id = nrt.tag_id
);

INSERT INTO course_sections (course_id, title, description, sort_order, is_published)
WITH section_seed(sort_order) AS (
    VALUES (1), (2)
)
SELECT
    c.course_id,
    CASE ss.sort_order
        WHEN 1 THEN seed.node_title || ' 핵심 개념'
        ELSE seed.node_title || ' 실전 적용'
    END,
    CASE ss.sort_order
        WHEN 1 THEN seed.node_title || ' 노드에서 반드시 이해해야 할 개념과 용어를 짧은 예제로 정리합니다.'
        ELSE seed.node_title || '를 실제 서비스 흐름과 운영 체크포인트에 연결합니다.'
    END,
    ss.sort_order,
    TRUE
FROM tmp_backend_roadmap_video_seed seed
JOIN courses c ON c.title = '로드맵 실전: ' || seed.node_title
JOIN section_seed ss ON 1 = 1
WHERE NOT EXISTS (
    SELECT 1
    FROM course_sections cs
    WHERE cs.course_id = c.course_id
      AND cs.sort_order = ss.sort_order
);

INSERT INTO lessons (
    section_id, title, description, lesson_type,
    video_url, video_asset_key, video_provider,
    thumbnail_url, duration_seconds, is_preview, is_published, sort_order
)
WITH lesson_seed(section_order, lesson_order, title_suffix, description_body, video_url, duration_seconds, is_preview) AS (
    VALUES
        (1, 1, '개념 지도', '핵심 개념과 전체 흐름을 먼저 잡습니다.', '/samples/sample-intro.mp4', 780, TRUE),
        (1, 2, '필수 태그 해설', '로드맵 필수 태그를 예제와 함께 설명합니다.', '/samples/ocr-code-demo.mp4', 900, FALSE),
        (2, 1, '실무 시나리오', '실제 서비스나 운영 상황에서 어떻게 연결되는지 살펴봅니다.', '/samples/lesson-spring-di.mp4', 840, FALSE),
        (2, 2, '체크리스트와 흔한 실수', '자주 놓치는 포인트와 점검 순서를 정리합니다.', '/samples/lesson-os-context.mp4', 960, FALSE)
)
SELECT
    cs.section_id,
    seed.node_title || ' ' || ls.title_suffix,
    seed.node_title || ' 학습을 위해 ' || ls.description_body,
    'VIDEO',
    CASE
        WHEN seed.node_title = 'OS & 터미널' AND ls.section_order = 1 AND ls.lesson_order = 1
            THEN '/samples/lesson-os-process.mp4'
        WHEN seed.node_title = 'OS & 터미널' AND ls.section_order = 1 AND ls.lesson_order = 2
            THEN '/samples/lesson-os-thread.mp4'
        WHEN seed.node_title = 'OS & 터미널'
            THEN '/samples/lesson-os-context.mp4'
        WHEN seed.node_title IN ('Spring Boot & MVC', 'Spring Data JPA', 'Spring Boot 테스트', 'Spring Security & JWT')
            AND ls.section_order = 1
            THEN '/samples/lesson-spring-di.mp4'
        WHEN seed.node_title IN ('Spring Boot & MVC', 'Spring Data JPA', 'Spring Boot 테스트', 'Spring Security & JWT')
            THEN '/samples/lesson-spring-bean.mp4'
        ELSE ls.video_url
    END,
    NULL,
    NULL,
    c.thumbnail_url,
    ls.duration_seconds,
    ls.is_preview,
    TRUE,
    ls.lesson_order
FROM tmp_backend_roadmap_video_seed seed
JOIN courses c ON c.title = '로드맵 실전: ' || seed.node_title
JOIN lesson_seed ls ON 1 = 1
JOIN course_sections cs ON cs.course_id = c.course_id AND cs.sort_order = ls.section_order
WHERE NOT EXISTS (
    SELECT 1
    FROM lessons l
    WHERE l.section_id = cs.section_id
      AND l.sort_order = ls.lesson_order
);

-- 로드맵 실전: Git & 버전 관리 강의는 OCR 실습 영상과 섹션 평가/과제를 고정 연결한다.
UPDATE courses
SET intro_video_url = '/samples/ocr-code-demo.mp4',
    video_asset_key = NULL,
    updated_at = TIMESTAMP '2026-04-30 09:00:00'
WHERE title = '로드맵 실전: Git & 버전 관리'
  AND (
      COALESCE(intro_video_url, '') <> '/samples/ocr-code-demo.mp4'
      OR video_asset_key IS NOT NULL
  );

UPDATE lessons l
SET video_url = '/samples/ocr-code-demo.mp4',
    video_asset_key = NULL,
    video_provider = NULL
WHERE l.lesson_type = 'VIDEO'
  AND EXISTS (
      SELECT 1
      FROM course_sections cs
      JOIN courses c ON c.course_id = cs.course_id
      WHERE cs.section_id = l.section_id
        AND c.title = '로드맵 실전: Git & 버전 관리'
  )
  AND (
      COALESCE(l.video_url, '') <> '/samples/ocr-code-demo.mp4'
      OR l.video_asset_key IS NOT NULL
      OR l.video_provider IS NOT NULL
  );

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, section_order)
WITH git_activity_nodes(course_title, section_order, activity_kind, node_title, node_content, sort_order) AS (
    VALUES
        (
            '로드맵 실전: Git & 버전 관리',
            1,
            'QUIZ',
            '[ROADMAP COURSE] 로드맵 실전: Git & 버전 관리 - 1 QUIZ',
            '커밋 단위, 브랜치 전략, Pull Request 리뷰 흐름을 확인하는 섹션 1 마무리 퀴즈입니다.',
            1081
        ),
        (
            '로드맵 실전: Git & 버전 관리',
            2,
            'ASSIGNMENT',
            '[ROADMAP COURSE] 로드맵 실전: Git & 버전 관리 - 2 ASSIGNMENT',
            'feature 브랜치 생성부터 커밋 메시지, PR 본문, 리뷰 체크리스트까지 Git 협업 흐름을 문서로 정리하는 과제입니다.',
            1082
        )
)
SELECT
    r.roadmap_id,
    gan.node_title,
    gan.node_content,
    gan.activity_kind,
    gan.sort_order,
    gan.course_title,
    gan.section_order
FROM git_activity_nodes gan
JOIN roadmaps r ON r.title = 'DevPath 공개 강의 평가 데이터'
WHERE NOT EXISTS (
    SELECT 1
    FROM roadmap_nodes rn
    WHERE rn.title = gan.node_title
);

INSERT INTO course_node_mappings (course_id, node_id, created_at)
SELECT c.course_id, rn.node_id, TIMESTAMP '2026-04-30 09:05:00'
FROM courses c
JOIN roadmap_nodes rn ON rn.sub_topics = c.title
WHERE c.title = '로드맵 실전: Git & 버전 관리'
  AND rn.title IN (
      '[ROADMAP COURSE] 로드맵 실전: Git & 버전 관리 - 1 QUIZ',
      '[ROADMAP COURSE] 로드맵 실전: Git & 버전 관리 - 2 ASSIGNMENT'
  )
  AND NOT EXISTS (
      SELECT 1
      FROM course_node_mappings cnm
      WHERE cnm.course_id = c.course_id
        AND cnm.node_id = rn.node_id
  );

INSERT INTO lessons (
    section_id, title, description, lesson_type, video_url, video_asset_key, video_provider,
    thumbnail_url, duration_seconds, is_preview, is_published, sort_order, quiz_node_id
)
SELECT
    cs.section_id,
    '섹션 마무리 퀴즈: Git 협업 흐름 점검',
    '커밋 단위, 브랜치 전략, Pull Request 리뷰 목적을 확인하는 섹션 1 퀴즈입니다.',
    'READING',
    NULL,
    NULL,
    NULL,
    c.thumbnail_url,
    300,
    FALSE,
    TRUE,
    3,
    rn.node_id
FROM courses c
JOIN course_sections cs ON cs.course_id = c.course_id AND cs.sort_order = 1
JOIN roadmap_nodes rn ON rn.title = '[ROADMAP COURSE] 로드맵 실전: Git & 버전 관리 - 1 QUIZ'
WHERE c.title = '로드맵 실전: Git & 버전 관리'
  AND NOT EXISTS (
      SELECT 1
      FROM lessons l
      WHERE l.section_id = cs.section_id
        AND l.sort_order = 3
        AND l.title = '섹션 마무리 퀴즈: Git 협업 흐름 점검'
  );

UPDATE lessons l
SET quiz_node_id = (
    SELECT rn.node_id
    FROM course_sections cs
    JOIN courses c ON c.course_id = cs.course_id
    JOIN roadmap_nodes rn ON rn.title = '[ROADMAP COURSE] 로드맵 실전: Git & 버전 관리 - 1 QUIZ'
    WHERE cs.section_id = l.section_id
      AND c.title = '로드맵 실전: Git & 버전 관리'
      AND cs.sort_order = 1
)
WHERE l.sort_order = 3
  AND l.title = '섹션 마무리 퀴즈: Git 협업 흐름 점검'
  AND l.quiz_node_id IS NULL
  AND EXISTS (
      SELECT 1
      FROM course_sections cs
      JOIN courses c ON c.course_id = cs.course_id
      JOIN roadmap_nodes rn ON rn.title = '[ROADMAP COURSE] 로드맵 실전: Git & 버전 관리 - 1 QUIZ'
      WHERE cs.section_id = l.section_id
        AND c.title = '로드맵 실전: Git & 버전 관리'
        AND cs.sort_order = 1
  );

INSERT INTO lessons (
    section_id, title, description, lesson_type, video_url, video_asset_key, video_provider,
    thumbnail_url, duration_seconds, is_preview, is_published, sort_order, assignment_node_id
)
SELECT
    cs.section_id,
    '실습 과제: Git 브랜치 전략과 PR 회고',
    '기능 브랜치, 커밋 메시지, PR 본문, 리뷰 체크리스트를 하나의 협업 흐름으로 정리해 제출합니다.',
    'CODING',
    NULL,
    NULL,
    NULL,
    c.thumbnail_url,
    900,
    FALSE,
    TRUE,
    3,
    rn.node_id
FROM courses c
JOIN course_sections cs ON cs.course_id = c.course_id AND cs.sort_order = 2
JOIN roadmap_nodes rn ON rn.title = '[ROADMAP COURSE] 로드맵 실전: Git & 버전 관리 - 2 ASSIGNMENT'
WHERE c.title = '로드맵 실전: Git & 버전 관리'
  AND NOT EXISTS (
      SELECT 1
      FROM lessons l
      WHERE l.section_id = cs.section_id
        AND l.sort_order = 3
        AND l.title = '실습 과제: Git 브랜치 전략과 PR 회고'
  );

UPDATE lessons l
SET assignment_node_id = (
    SELECT rn.node_id
    FROM course_sections cs
    JOIN courses c ON c.course_id = cs.course_id
    JOIN roadmap_nodes rn ON rn.title = '[ROADMAP COURSE] 로드맵 실전: Git & 버전 관리 - 2 ASSIGNMENT'
    WHERE cs.section_id = l.section_id
      AND c.title = '로드맵 실전: Git & 버전 관리'
      AND cs.sort_order = 2
)
WHERE l.sort_order = 3
  AND l.title = '실습 과제: Git 브랜치 전략과 PR 회고'
  AND l.assignment_node_id IS NULL
  AND EXISTS (
      SELECT 1
      FROM course_sections cs
      JOIN courses c ON c.course_id = cs.course_id
      JOIN roadmap_nodes rn ON rn.title = '[ROADMAP COURSE] 로드맵 실전: Git & 버전 관리 - 2 ASSIGNMENT'
      WHERE cs.section_id = l.section_id
        AND c.title = '로드맵 실전: Git & 버전 관리'
        AND cs.sort_order = 2
  );

INSERT INTO quizzes (
    node_id, title, description, quiz_type, total_score, pass_score,
    time_limit_minutes, is_published, is_active, expose_answer,
    expose_explanation, is_deleted, created_at, updated_at
)
SELECT
    rn.node_id,
    'Git 브랜치와 PR 흐름 점검 퀴즈',
    '커밋 단위, 브랜치 전략, Pull Request 리뷰 흐름을 확인하는 섹션 1 마무리 퀴즈입니다.',
    'MANUAL',
    10,
    7,
    10,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    FALSE,
    TIMESTAMP '2026-04-30 09:10:00',
    TIMESTAMP '2026-04-30 09:10:00'
FROM roadmap_nodes rn
WHERE rn.title = '[ROADMAP COURSE] 로드맵 실전: Git & 버전 관리 - 1 QUIZ'
  AND NOT EXISTS (
      SELECT 1
      FROM quizzes q
      WHERE q.node_id = rn.node_id
  );

INSERT INTO quiz_questions (
    quiz_id, question_type, question_text, explanation, points,
    display_order, source_timestamp, is_deleted, created_at, updated_at
)
SELECT
    q.quiz_id,
    'MULTIPLE_CHOICE',
    'Git 협업에서 Pull Request를 여는 가장 적절한 목적은 무엇인가요?',
    'PR은 기능 브랜치의 변경 내용을 공유하고 리뷰와 자동 검증을 거쳐 안전하게 기본 브랜치에 병합하기 위한 절차입니다.',
    10,
    1,
    NULL,
    FALSE,
    TIMESTAMP '2026-04-30 09:15:00',
    TIMESTAMP '2026-04-30 09:15:00'
FROM quizzes q
JOIN roadmap_nodes rn ON rn.node_id = q.node_id
WHERE rn.title = '[ROADMAP COURSE] 로드맵 실전: Git & 버전 관리 - 1 QUIZ'
  AND NOT EXISTS (
      SELECT 1
      FROM quiz_questions qq
      WHERE qq.quiz_id = q.quiz_id
        AND qq.display_order = 1
  );

INSERT INTO quiz_question_options (
    question_id, option_text, is_correct, display_order,
    is_deleted, created_at, updated_at
)
WITH git_quiz_option_seed(option_text, is_correct, display_order) AS (
    VALUES
        ('변경 내용을 리뷰하고 자동 검증을 통과한 뒤 병합하기 위해서', TRUE, 1),
        ('로컬 커밋 기록을 모두 삭제하기 위해서', FALSE, 2),
        ('원격 저장소 연결 없이 브랜치를 만들기 위해서', FALSE, 3),
        ('충돌이 발생하지 않도록 Git 사용을 중단하기 위해서', FALSE, 4)
)
SELECT
    qq.question_id,
    seed.option_text,
    seed.is_correct,
    seed.display_order,
    FALSE,
    TIMESTAMP '2026-04-30 09:20:00',
    TIMESTAMP '2026-04-30 09:20:00'
FROM git_quiz_option_seed seed
JOIN roadmap_nodes rn ON rn.title = '[ROADMAP COURSE] 로드맵 실전: Git & 버전 관리 - 1 QUIZ'
JOIN quizzes q ON q.node_id = rn.node_id
JOIN quiz_questions qq ON qq.quiz_id = q.quiz_id AND qq.display_order = 1
WHERE NOT EXISTS (
    SELECT 1
    FROM quiz_question_options qo
    WHERE qo.question_id = qq.question_id
      AND qo.display_order = seed.display_order
);

INSERT INTO assignments (
    node_id, title, description, submission_type, due_at, allowed_file_formats,
    readme_required, test_required, lint_required, submission_rule_description,
    total_score, pass_score, is_published, is_active, allow_late_submission,
    ai_review_enabled, allow_text_submission,
    allow_file_submission, allow_url_submission, is_deleted, created_at, updated_at
)
SELECT
    rn.node_id,
    'Git 브랜치 전략과 PR 회고 과제',
    '기능 개발 흐름을 가정해 feature 브랜치를 만들고 의미 있는 커밋 단위로 변경 이력을 구성한 뒤, PR 설명과 충돌 해결/리뷰 체크리스트를 README로 정리합니다. 실제 코드를 작성하지 않아도 브랜치명, 커밋 메시지, PR 본문 예시가 포함되어야 합니다.',
    'MULTIPLE',
    TIMESTAMP '2026-05-31 23:59:59',
    'md,pdf,zip,github-url',
    TRUE,
    FALSE,
    FALSE,
    'GitHub 저장소 URL 또는 README 파일을 제출하세요. README에는 브랜치 전략, 커밋 메시지 3개 이상, PR 본문, 리뷰 체크리스트, 충돌 발생 시 해결 절차를 포함해야 합니다.',
    100,
    70,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    FALSE,
    TIMESTAMP '2026-04-30 09:25:00',
    TIMESTAMP '2026-04-30 09:25:00'
FROM roadmap_nodes rn
WHERE rn.title = '[ROADMAP COURSE] 로드맵 실전: Git & 버전 관리 - 2 ASSIGNMENT'
  AND NOT EXISTS (
      SELECT 1
      FROM assignments a
      WHERE a.node_id = rn.node_id
  );

INSERT INTO assignment_rubrics (
    assignment_id, criteria_name, criteria_description, max_points,
    display_order, is_deleted, created_at, updated_at
)
WITH git_assignment_rubric_seed(criteria_name, criteria_description, max_points, display_order) AS (
    VALUES
        ('Git 작업 흐름 구성', 'feature 브랜치 생성, 의미 있는 커밋 단위, PR 생성 흐름이 실제 협업 흐름에 맞게 정리되었습니다.', 40, 1),
        ('PR 설명과 리뷰 체크리스트', '변경 목적, 테스트/검증 방법, 리뷰어가 확인해야 할 항목을 PR 본문 형식으로 구체화했습니다.', 35, 2),
        ('충돌 해결과 회고', '충돌이 발생했을 때의 해결 순서와 브랜치 전략을 적용하며 배운 점을 정리했습니다.', 25, 3)
)
SELECT
    a.assignment_id,
    seed.criteria_name,
    seed.criteria_description,
    seed.max_points,
    seed.display_order,
    FALSE,
    TIMESTAMP '2026-04-30 09:30:00',
    TIMESTAMP '2026-04-30 09:30:00'
FROM git_assignment_rubric_seed seed
JOIN roadmap_nodes rn ON rn.title = '[ROADMAP COURSE] 로드맵 실전: Git & 버전 관리 - 2 ASSIGNMENT'
JOIN assignments a ON a.node_id = rn.node_id
WHERE NOT EXISTS (
    SELECT 1
    FROM assignment_rubrics ar
    WHERE ar.assignment_id = a.assignment_id
      AND ar.display_order = seed.display_order
);

INSERT INTO course_node_mappings (course_id, node_id, created_at)
SELECT
    c.course_id,
    rn.node_id,
    seed.published_at
FROM tmp_backend_roadmap_video_seed seed
JOIN courses c ON c.title = '로드맵 실전: ' || seed.node_title
JOIN roadmaps r ON r.title = 'Backend Master Roadmap'
JOIN roadmap_nodes rn ON rn.roadmap_id = r.roadmap_id AND rn.title = seed.node_title
WHERE NOT EXISTS (
    SELECT 1
    FROM course_node_mappings cnm
    WHERE cnm.course_id = c.course_id
      AND cnm.node_id = rn.node_id
);

INSERT INTO roadmap_node_resources (
    node_id, title, url, description, source_type, sort_order, active, created_at, updated_at
)
SELECT
    rn.node_id,
    c.title,
    'course-detail.html?courseId=' || c.course_id,
    '필수 태그: ' || COALESCE(rn.sub_topics, seed.node_title)
        || '. ' || seed.node_title || ' 노드를 영상 중심으로 빠르게 보강할 수 있는 공개 강의입니다.',
    'COURSE',
    3,
    TRUE,
    seed.published_at,
    seed.published_at
FROM tmp_backend_roadmap_video_seed seed
JOIN courses c ON c.title = '로드맵 실전: ' || seed.node_title
JOIN roadmaps r ON r.title = 'Backend Master Roadmap'
JOIN roadmap_nodes rn ON rn.roadmap_id = r.roadmap_id AND rn.title = seed.node_title
WHERE NOT EXISTS (
    SELECT 1
    FROM roadmap_node_resources existing
    WHERE existing.node_id = rn.node_id
      AND existing.url = 'course-detail.html?courseId=' || c.course_id
);

INSERT INTO course_announcements (
    course_id, announcement_type, title, content, is_pinned, display_order,
    published_at, exposure_start_at, exposure_end_at,
    event_banner_text, event_link, created_at, updated_at
)
SELECT
    c.course_id,
    'NORMAL',
    seed.node_title || ' 로드맵 연동 가이드',
    '이 강의는 Backend Master Roadmap의 "' || seed.node_title || '" 노드와 직접 연결됩니다. '
        || '필수 태그: ' || COALESCE(rn.sub_topics, seed.node_title)
        || '. 노드 상세의 필수 태그를 먼저 확인하고 예제를 따라오면 더 빠르게 이해할 수 있습니다.',
    FALSE,
    1,
    seed.published_at,
    seed.published_at,
    NULL,
    NULL,
    NULL,
    seed.published_at,
    seed.published_at
FROM tmp_backend_roadmap_video_seed seed
JOIN courses c ON c.title = '로드맵 실전: ' || seed.node_title
JOIN roadmaps r ON r.title = 'Backend Master Roadmap'
JOIN roadmap_nodes rn ON rn.roadmap_id = r.roadmap_id AND rn.title = seed.node_title
WHERE NOT EXISTS (
    SELECT 1
    FROM course_announcements ca
    WHERE ca.course_id = c.course_id
      AND ca.title = seed.node_title || ' 로드맵 연동 가이드'
);

DROP TABLE IF EXISTS tmp_backend_roadmap_video_seed;

-- ============================================================
-- BACKEND ROADMAP TAG VIDEO CATALOG: 필수 태그 중심 공개 강의 추가
-- ============================================================
DROP TABLE IF EXISTS tmp_backend_tag_video_tag_seed;
DROP TABLE IF EXISTS tmp_backend_tag_video_seed;

CREATE TABLE tmp_backend_tag_video_seed (
    course_title VARCHAR(255) NOT NULL,
    subtitle VARCHAR(255) NOT NULL,
    description VARCHAR(2000) NOT NULL,
    tag_summary VARCHAR(500) NOT NULL,
    instructor_email VARCHAR(255) NOT NULL,
    difficulty_level VARCHAR(30) NOT NULL,
    published_at TIMESTAMP NOT NULL,
    thumbnail_url VARCHAR(1000) NOT NULL,
    intro_video_url VARCHAR(255) NOT NULL
);

CREATE TABLE tmp_backend_tag_video_tag_seed (
    course_title VARCHAR(255) NOT NULL,
    tag_name VARCHAR(255) NOT NULL
);

INSERT INTO tmp_backend_tag_video_seed (
    course_title, subtitle, description, tag_summary,
    instructor_email, difficulty_level, published_at, thumbnail_url, intro_video_url
)
VALUES
    ('HTTP 요청/응답, 메서드, 상태코드', 'HTTP 규칙을 빠르게 잡는 백엔드 통신 기본기', 'HTTP 요청 라인, 헤더, 바디, 메서드, 상태코드를 예제로 풀어보고 클라이언트와 서버가 어떤 기준으로 응답을 해석하는지 정리합니다.', 'HTTP, HTTP 메서드, HTTP 상태코드', 'frontend@devpath.com', 'BEGINNER', TIMESTAMP '2026-03-19 09:00:00', 'https://picsum.photos/seed/devpath-backend-http-status/1200/675', '/samples/sample-intro.mp4'),
    ('DNS, 도메인, 웹 호스팅 입문', '주소 입력부터 서버 도착까지 이해하는 네트워크 시작점', '도메인이 DNS 조회를 거쳐 실제 서버 IP로 연결되고, 웹 호스팅 환경에서 요청이 어떤 서버로 전달되는지 흐름 중심으로 설명합니다.', 'DNS, 도메인, 웹 호스팅', 'frontend@devpath.com', 'BEGINNER', TIMESTAMP '2026-03-20 09:00:00', 'https://picsum.photos/seed/devpath-backend-dns-hosting/1200/675', '/samples/sample-intro.mp4'),
    ('브라우저 요청 흐름과 HTTP 응답 구조', '브라우저가 서버와 통신하는 전체 그림 정리', '브라우저가 URL을 해석하고 요청을 보내며 응답을 렌더링하기까지 어떤 단계와 기준을 거치는지 백엔드 관점에서 정리합니다.', '브라우저, HTTP', 'frontend@devpath.com', 'BEGINNER', TIMESTAMP '2026-03-21 09:00:00', 'https://picsum.photos/seed/devpath-backend-browser-http/1200/675', '/samples/sample-intro.mp4'),
    ('Linux 프로세스와 스레드 관리', '운영체제에서 애플리케이션 실행 단위를 이해하는 강의', '프로세스와 스레드의 차이, 스케줄링 관점, 장애 상황에서 어떤 정보를 먼저 봐야 하는지 터미널 예제와 함께 설명합니다.', 'Linux, 프로세스 관리, 스레드', 'instructor@devpath.com', 'BEGINNER', TIMESTAMP '2026-03-22 09:00:00', 'https://picsum.photos/seed/devpath-backend-linux-process-thread/1200/675', '/samples/lesson-os-process.mp4'),
    ('Linux 메모리 관리와 I/O 관리', '메모리와 디스크/네트워크 I/O를 같이 보는 운영 기본기', '메모리 사용량, 파일 디스크립터, 디스크와 네트워크 I/O 병목을 확인하는 방법을 예시 로그와 함께 정리합니다.', 'Linux, 메모리 관리, I/O 관리', 'instructor@devpath.com', 'BEGINNER', TIMESTAMP '2026-03-23 09:00:00', 'https://picsum.photos/seed/devpath-backend-linux-memory-io/1200/675', '/samples/lesson-os-context.mp4'),
    ('Java OOP와 상속 설계', '객체 모델과 상속 구조를 코드 관점에서 다지는 기초', 'Java 클래스 설계, 캡슐화, 상속 구조, 다형성이 서비스 코드에 어떤 영향을 주는지 작은 예제로 설명합니다.', 'Java, OOP, 상속', 'instructor@devpath.com', 'BEGINNER', TIMESTAMP '2026-03-24 09:00:00', 'https://picsum.photos/seed/devpath-backend-java-oop-inheritance/1200/675', '/samples/ocr-code-demo.mp4'),
    ('인터페이스, 제네릭, 컬렉션 실전', '타입 안정성과 재사용성을 높이는 Java 핵심 문법', '인터페이스 분리, 제네릭 타입 안정성, 컬렉션 사용 기준을 서비스 코드 예시와 함께 정리합니다.', '인터페이스, 제네릭, 컬렉션', 'instructor@devpath.com', 'BEGINNER', TIMESTAMP '2026-03-25 09:00:00', 'https://picsum.photos/seed/devpath-backend-java-generic-collection/1200/675', '/samples/ocr-code-demo.mp4'),
    ('Git 브랜치 전략과 GitFlow', '혼자와 팀 작업 모두에 바로 쓰는 버전 관리 흐름', '브랜치 전략을 왜 나누는지부터 GitFlow를 언제 쓰고 언제 단순화할지까지 실제 개발 흐름에 맞춰 설명합니다.', 'Git, 브랜치 전략, GitFlow', 'frontend@devpath.com', 'BEGINNER', TIMESTAMP '2026-03-26 09:00:00', 'https://picsum.photos/seed/devpath-backend-git-branch-flow/1200/675', '/samples/sample-intro.mp4'),
    ('Pull Request와 코드 리뷰 실무', '커밋 단위와 리뷰 포인트를 정리하는 협업 강의', 'Pull Request를 작게 쪼개는 기준, 리뷰 코멘트를 주고받는 방식, 충돌을 줄이는 협업 습관을 실무 관점에서 정리합니다.', 'Git, Pull Request, 코드 리뷰', 'frontend@devpath.com', 'BEGINNER', TIMESTAMP '2026-03-27 09:00:00', 'https://picsum.photos/seed/devpath-backend-pr-review/1200/675', '/samples/sample-intro.mp4'),
    ('SQL JOIN과 서브쿼리 패턴', '조회 로직을 안정적으로 조합하는 관계형 쿼리 기본기', 'JOIN 종류별 차이와 서브쿼리를 어디까지 허용할지, 실무에서 읽기 쉬운 SQL을 만드는 기준을 예제로 정리합니다.', 'SQL, JOIN, 서브쿼리', 'data@devpath.com', 'BEGINNER', TIMESTAMP '2026-03-28 09:00:00', 'https://picsum.photos/seed/devpath-backend-sql-join-subquery/1200/675', '/samples/ocr-code-demo.mp4'),
    ('인덱스, 트랜잭션, PostgreSQL 성능 기본기', '데이터 정합성과 조회 성능을 함께 보는 SQL 심화 입문', '인덱스가 언제 효율적인지, 트랜잭션 격리와 롤백이 어떤 의미인지, PostgreSQL에서 어떤 지점을 먼저 점검해야 하는지 다룹니다.', '인덱스, 트랜잭션, PostgreSQL', 'data@devpath.com', 'INTERMEDIATE', TIMESTAMP '2026-03-29 09:00:00', 'https://picsum.photos/seed/devpath-backend-postgres-index-transaction/1200/675', '/samples/ocr-code-demo.mp4'),
    ('REST URI 설계와 HTTP 메서드', '리소스 중심 API 설계 감각을 만드는 강의', 'REST 스타일에 맞는 URI를 설계하고 HTTP 메서드를 일관되게 적용하는 기준을 실제 API 예제에 맞춰 설명합니다.', 'REST, URI 설계, HTTP 메서드', 'frontend@devpath.com', 'INTERMEDIATE', TIMESTAMP '2026-03-30 09:00:00', 'https://picsum.photos/seed/devpath-backend-rest-uri-method/1200/675', '/samples/sample-intro.mp4'),
    ('Swagger와 REST API 문서화', 'OpenAPI 문서를 실무에 맞게 정리하는 방법', 'Swagger UI와 OpenAPI 문서를 통해 상태코드, 요청 바디, 응답 스키마를 일관되게 관리하는 방식을 설명합니다.', 'Swagger, REST, HTTP 상태코드', 'frontend@devpath.com', 'INTERMEDIATE', TIMESTAMP '2026-03-31 09:00:00', 'https://picsum.photos/seed/devpath-backend-swagger-rest/1200/675', '/samples/sample-intro.mp4'),
    ('Spring Boot DI/IoC와 Spring Bean 등록 흐름', '객체 생성과 연결을 프레임워크에 맡기는 구조 이해', 'DI/IoC의 의미, Bean 등록 방식, 자동 주입이 실제 서비스 코드에서 어떻게 동작하는지 요청 흐름에 맞춰 설명합니다.', 'Spring Boot, DI/IoC, Spring Bean', 'instructor@devpath.com', 'INTERMEDIATE', TIMESTAMP '2026-04-01 09:00:00', 'https://picsum.photos/seed/devpath-backend-spring-di-bean/1200/675', '/samples/lesson-spring-di.mp4'),
    ('Spring MVC 요청 처리와 3계층 구조', 'Controller부터 Service, Repository까지 흐름 정리', 'DispatcherServlet 이후 요청이 어떤 순서로 처리되는지와 3계층 구조가 왜 유지보수에 유리한지 예제로 설명합니다.', 'Spring Boot, Spring MVC, 3계층 구조', 'instructor@devpath.com', 'INTERMEDIATE', TIMESTAMP '2026-04-02 09:00:00', 'https://picsum.photos/seed/devpath-backend-spring-mvc-layered/1200/675', '/samples/lesson-spring-bean.mp4'),
    ('JPA Entity 매핑과 JPQL 실전', 'ORM 기본기를 흔들리지 않게 잡는 데이터 접근 강의', 'Entity 매핑 규칙, 식별자 전략, JPQL이 SQL과 어떻게 다른지, 조회 코드가 어디서 복잡해지는지 실습 예제로 정리합니다.', 'JPA, Entity 매핑, JPQL', 'instructor@devpath.com', 'INTERMEDIATE', TIMESTAMP '2026-04-03 09:00:00', 'https://picsum.photos/seed/devpath-backend-jpa-entity-jpql/1200/675', '/samples/lesson-spring-di.mp4'),
    ('FetchType, N+1, QueryDSL 최적화', 'JPA 성능 이슈를 초기에 피하는 실무 포인트', 'FetchType 설정이 조회 성능에 어떤 영향을 주는지, N+1 문제를 어떻게 찾고 QueryDSL로 어떻게 풀어갈지 설명합니다.', 'FetchType, N+1 문제, QueryDSL', 'instructor@devpath.com', 'ADVANCED', TIMESTAMP '2026-04-04 09:00:00', 'https://picsum.photos/seed/devpath-backend-jpa-querydsl-performance/1200/675', '/samples/lesson-spring-bean.mp4'),
    ('Redis 자료구조, TTL, Spring Cache', '캐시 설계에 필요한 Redis 기초를 한 번에 정리', 'Redis 자료구조 선택 기준, TTL 설계, Spring Cache와 연결할 때 주의할 점을 백엔드 응답 속도 관점에서 설명합니다.', 'Redis, Redis 자료구조, Redis TTL, Spring Cache', 'data@devpath.com', 'INTERMEDIATE', TIMESTAMP '2026-04-05 09:00:00', 'https://picsum.photos/seed/devpath-backend-redis-ttl-cache/1200/675', '/samples/sample-intro.mp4'),
    ('Redis Session, Pub/Sub, 분산 락', '여러 서버가 상태를 공유할 때 필요한 Redis 심화 패턴', '세션 저장, 메시지 전달, 분산 락을 어떤 상황에서 쓰는지와 TTL 및 장애 대응을 어떻게 함께 고려할지 설명합니다.', 'Redis, Redis Session, Pub/Sub, 분산 락', 'data@devpath.com', 'ADVANCED', TIMESTAMP '2026-04-06 09:00:00', 'https://picsum.photos/seed/devpath-backend-redis-session-lock/1200/675', '/samples/sample-intro.mp4'),
    ('JUnit5와 Mockito 단위 테스트', '서비스 로직을 빠르게 검증하는 테스트 기본기', '테스트 생명주기, Assertion, Mock과 Stub, verify와 BDD 스타일을 통해 서비스 단위 테스트를 작성하는 흐름을 다룹니다.', 'JUnit5, Mockito, BDD, 단위 테스트', 'instructor@devpath.com', 'INTERMEDIATE', TIMESTAMP '2026-04-07 09:00:00', 'https://picsum.photos/seed/devpath-backend-junit-mockito/1200/675', '/samples/ocr-code-demo.mp4'),
    ('MockMvc와 Spring Boot 통합 테스트', '웹 계층과 애플리케이션 컨텍스트를 같이 검증하는 방법', 'MockMvc, 테스트 슬라이스, 통합 테스트, 커버리지 점검을 통해 단위 테스트만으로 놓치기 쉬운 흐름을 보강합니다.', 'Spring Boot, MockMvc, 통합 테스트, 테스트 커버리지', 'instructor@devpath.com', 'INTERMEDIATE', TIMESTAMP '2026-04-08 09:00:00', 'https://picsum.photos/seed/devpath-backend-mockmvc-integration/1200/675', '/samples/lesson-spring-di.mp4'),
    ('Spring Security 필터 체인과 JWT 인증', '인증과 인가 흐름을 필터 레벨에서 이해하는 강의', 'SecurityFilterChain 안에서 인증이 어떻게 처리되는지, JWT 검증과 권한 체크가 어떤 순서로 일어나는지 설명합니다.', 'Spring Security, JWT', 'instructor@devpath.com', 'ADVANCED', TIMESTAMP '2026-04-09 09:00:00', 'https://picsum.photos/seed/devpath-backend-security-jwt/1200/675', '/samples/lesson-spring-bean.mp4'),
    ('OAuth2와 소셜 로그인 연동', '외부 인증 제공자를 서비스 로그인과 연결하는 실전 입문', 'OAuth2 로그인 흐름, 인가 코드, 사용자 정보 매핑, 소셜 로그인 이후 내부 계정과 연결하는 방식을 단계별로 정리합니다.', 'Spring Security, OAuth2, 소셜 로그인', 'instructor@devpath.com', 'ADVANCED', TIMESTAMP '2026-04-10 09:00:00', 'https://picsum.photos/seed/devpath-backend-oauth2-social-login/1200/675', '/samples/lesson-spring-bean.mp4'),
    ('Docker와 docker-compose 실전', '개발 환경과 실행 환경 차이를 줄이는 컨테이너 입문', '이미지와 컨테이너 개념, Dockerfile 작성 포인트, docker-compose로 여러 서비스를 묶어 실행하는 흐름을 설명합니다.', 'Docker, docker-compose', 'data@devpath.com', 'INTERMEDIATE', TIMESTAMP '2026-04-11 09:00:00', 'https://picsum.photos/seed/devpath-backend-docker-compose/1200/675', '/samples/sample-intro.mp4'),
    ('GitHub Actions와 CI/CD 자동화', '테스트부터 배포까지 자동화 파이프라인 만들기', 'GitHub Actions 워크플로우, CI/CD 기본 단계, AWS EC2 배포 연결 포인트를 예시 저장소 기준으로 정리합니다.', 'GitHub Actions, CI/CD, AWS EC2', 'data@devpath.com', 'ADVANCED', TIMESTAMP '2026-04-12 09:00:00', 'https://picsum.photos/seed/devpath-backend-github-actions-cicd/1200/675', '/samples/sample-intro.mp4'),
    ('SOLID 원칙과 디자인 패턴 실전', '객체지향 설계를 변경에 강하게 만드는 기준', 'SOLID 원칙을 코드 분리에 어떻게 적용하는지, Singleton, Factory 패턴, Strategy 패턴을 언제 선택할지 사례 중심으로 설명합니다.', 'SOLID 원칙, 디자인 패턴, Singleton, Factory 패턴, Strategy 패턴', 'instructor@devpath.com', 'INTERMEDIATE', TIMESTAMP '2026-04-13 09:00:00', 'https://picsum.photos/seed/devpath-backend-solid-patterns/1200/675', '/samples/ocr-code-demo.mp4'),
    ('OWASP, XSS, CSRF, SQL Injection, CORS', '백엔드 API에서 바로 막아야 할 웹 보안 기본기', 'OWASP Top 10 관점에서 XSS, CSRF, SQL Injection, CORS, HTTPS를 같이 보고 API 설계 단계에서 어떤 기본값을 잡아야 하는지 정리합니다.', 'OWASP, XSS, CSRF, SQL Injection, CORS, HTTPS', 'frontend@devpath.com', 'INTERMEDIATE', TIMESTAMP '2026-04-14 09:00:00', 'https://picsum.photos/seed/devpath-backend-web-security/1200/675', '/samples/sample-intro.mp4'),
    ('Kafka와 Kafka 토픽 흐름', '이벤트 스트림을 이해하기 위한 메시지 큐 입문', 'Kafka 브로커와 토픽 구조, 파티션이 왜 필요한지, 메시지가 어떤 흐름으로 저장되고 소비되는지 백엔드 서비스 기준으로 설명합니다.', 'Kafka, Kafka 토픽', 'data@devpath.com', 'ADVANCED', TIMESTAMP '2026-04-15 09:00:00', 'https://picsum.photos/seed/devpath-backend-kafka-topic/1200/675', '/samples/sample-intro.mp4'),
    ('MSA API Gateway와 서비스 분리 기준', '서비스 경계를 나누는 판단 기준을 잡는 설계 입문', 'API Gateway가 어떤 책임을 맡는지와 서비스 분리 기준을 어떻게 세우는지, MSA를 언제 도입해야 하는지 판단 포인트를 설명합니다.', 'MSA, API Gateway, 서비스 분리', 'data@devpath.com', 'ADVANCED', TIMESTAMP '2026-04-16 09:00:00', 'https://picsum.photos/seed/devpath-backend-msa-gateway/1200/675', '/samples/sample-intro.mp4');

INSERT INTO tmp_backend_tag_video_tag_seed (course_title, tag_name)
VALUES
    ('HTTP 요청/응답, 메서드, 상태코드', 'HTTP'),
    ('HTTP 요청/응답, 메서드, 상태코드', 'HTTP 메서드'),
    ('HTTP 요청/응답, 메서드, 상태코드', 'HTTP 상태코드'),
    ('DNS, 도메인, 웹 호스팅 입문', 'DNS'),
    ('DNS, 도메인, 웹 호스팅 입문', '도메인'),
    ('DNS, 도메인, 웹 호스팅 입문', '웹 호스팅'),
    ('브라우저 요청 흐름과 HTTP 응답 구조', '브라우저'),
    ('브라우저 요청 흐름과 HTTP 응답 구조', 'HTTP'),
    ('Linux 프로세스와 스레드 관리', 'Linux'),
    ('Linux 프로세스와 스레드 관리', '프로세스 관리'),
    ('Linux 프로세스와 스레드 관리', '스레드'),
    ('Linux 메모리 관리와 I/O 관리', 'Linux'),
    ('Linux 메모리 관리와 I/O 관리', '메모리 관리'),
    ('Linux 메모리 관리와 I/O 관리', 'I/O 관리'),
    ('Java OOP와 상속 설계', 'Java'),
    ('Java OOP와 상속 설계', 'OOP'),
    ('Java OOP와 상속 설계', '상속'),
    ('인터페이스, 제네릭, 컬렉션 실전', '인터페이스'),
    ('인터페이스, 제네릭, 컬렉션 실전', '제네릭'),
    ('인터페이스, 제네릭, 컬렉션 실전', '컬렉션'),
    ('Git 브랜치 전략과 GitFlow', 'Git'),
    ('Git 브랜치 전략과 GitFlow', '브랜치 전략'),
    ('Git 브랜치 전략과 GitFlow', 'GitFlow'),
    ('Pull Request와 코드 리뷰 실무', 'Git'),
    ('Pull Request와 코드 리뷰 실무', 'Pull Request'),
    ('Pull Request와 코드 리뷰 실무', '코드 리뷰'),
    ('SQL JOIN과 서브쿼리 패턴', 'SQL'),
    ('SQL JOIN과 서브쿼리 패턴', 'JOIN'),
    ('SQL JOIN과 서브쿼리 패턴', '서브쿼리'),
    ('인덱스, 트랜잭션, PostgreSQL 성능 기본기', '인덱스'),
    ('인덱스, 트랜잭션, PostgreSQL 성능 기본기', '트랜잭션'),
    ('인덱스, 트랜잭션, PostgreSQL 성능 기본기', 'PostgreSQL'),
    ('REST URI 설계와 HTTP 메서드', 'REST'),
    ('REST URI 설계와 HTTP 메서드', 'URI 설계'),
    ('REST URI 설계와 HTTP 메서드', 'HTTP 메서드'),
    ('Swagger와 REST API 문서화', 'Swagger'),
    ('Swagger와 REST API 문서화', 'REST'),
    ('Swagger와 REST API 문서화', 'HTTP 상태코드'),
    ('Spring Boot DI/IoC와 Spring Bean 등록 흐름', 'Spring Boot'),
    ('Spring Boot DI/IoC와 Spring Bean 등록 흐름', 'DI/IoC'),
    ('Spring Boot DI/IoC와 Spring Bean 등록 흐름', 'Spring Bean'),
    ('Spring MVC 요청 처리와 3계층 구조', 'Spring Boot'),
    ('Spring MVC 요청 처리와 3계층 구조', 'Spring MVC'),
    ('Spring MVC 요청 처리와 3계층 구조', '3계층 구조'),
    ('JPA Entity 매핑과 JPQL 실전', 'JPA'),
    ('JPA Entity 매핑과 JPQL 실전', 'Entity 매핑'),
    ('JPA Entity 매핑과 JPQL 실전', 'JPQL'),
    ('FetchType, N+1, QueryDSL 최적화', 'FetchType'),
    ('FetchType, N+1, QueryDSL 최적화', 'N+1 문제'),
    ('FetchType, N+1, QueryDSL 최적화', 'QueryDSL'),
    ('Redis 자료구조, TTL, Spring Cache', 'Redis'),
    ('Redis 자료구조, TTL, Spring Cache', 'Redis 자료구조'),
    ('Redis 자료구조, TTL, Spring Cache', 'Redis TTL'),
    ('Redis 자료구조, TTL, Spring Cache', 'Spring Cache'),
    ('Redis Session, Pub/Sub, 분산 락', 'Redis'),
    ('Redis Session, Pub/Sub, 분산 락', 'Redis Session'),
    ('Redis Session, Pub/Sub, 분산 락', 'Pub/Sub'),
    ('Redis Session, Pub/Sub, 분산 락', '분산 락'),
    ('JUnit5와 Mockito 단위 테스트', 'JUnit5'),
    ('JUnit5와 Mockito 단위 테스트', 'Mockito'),
    ('JUnit5와 Mockito 단위 테스트', 'BDD'),
    ('JUnit5와 Mockito 단위 테스트', '단위 테스트'),
    ('MockMvc와 Spring Boot 통합 테스트', 'Spring Boot'),
    ('MockMvc와 Spring Boot 통합 테스트', 'MockMvc'),
    ('MockMvc와 Spring Boot 통합 테스트', '통합 테스트'),
    ('MockMvc와 Spring Boot 통합 테스트', '테스트 커버리지'),
    ('Spring Security 필터 체인과 JWT 인증', 'Spring Security'),
    ('Spring Security 필터 체인과 JWT 인증', 'JWT'),
    ('OAuth2와 소셜 로그인 연동', 'Spring Security'),
    ('OAuth2와 소셜 로그인 연동', 'OAuth2'),
    ('OAuth2와 소셜 로그인 연동', '소셜 로그인'),
    ('Docker와 docker-compose 실전', 'Docker'),
    ('Docker와 docker-compose 실전', 'docker-compose'),
    ('GitHub Actions와 CI/CD 자동화', 'GitHub Actions'),
    ('GitHub Actions와 CI/CD 자동화', 'CI/CD'),
    ('GitHub Actions와 CI/CD 자동화', 'AWS EC2'),
    ('SOLID 원칙과 디자인 패턴 실전', 'SOLID 원칙'),
    ('SOLID 원칙과 디자인 패턴 실전', '디자인 패턴'),
    ('SOLID 원칙과 디자인 패턴 실전', 'Singleton'),
    ('SOLID 원칙과 디자인 패턴 실전', 'Factory 패턴'),
    ('SOLID 원칙과 디자인 패턴 실전', 'Strategy 패턴'),
    ('OWASP, XSS, CSRF, SQL Injection, CORS', 'OWASP'),
    ('OWASP, XSS, CSRF, SQL Injection, CORS', 'XSS'),
    ('OWASP, XSS, CSRF, SQL Injection, CORS', 'CSRF'),
    ('OWASP, XSS, CSRF, SQL Injection, CORS', 'SQL Injection'),
    ('OWASP, XSS, CSRF, SQL Injection, CORS', 'CORS'),
    ('OWASP, XSS, CSRF, SQL Injection, CORS', 'HTTPS'),
    ('Kafka와 Kafka 토픽 흐름', 'Kafka'),
    ('Kafka와 Kafka 토픽 흐름', 'Kafka 토픽'),
    ('MSA API Gateway와 서비스 분리 기준', 'MSA'),
    ('MSA API Gateway와 서비스 분리 기준', 'API Gateway'),
    ('MSA API Gateway와 서비스 분리 기준', '서비스 분리');

INSERT INTO courses (
    instructor_id, title, subtitle, description,
    thumbnail_url, intro_video_url, video_asset_key, duration_seconds,
    price, original_price, currency, difficulty_level, language,
    has_certificate, status, published_at
)
SELECT
    u.user_id,
    seed.course_title,
    seed.subtitle,
    seed.description,
    seed.thumbnail_url,
    seed.intro_video_url,
    NULL,
    CASE seed.difficulty_level
        WHEN 'BEGINNER' THEN 6600
        WHEN 'INTERMEDIATE' THEN 8400
        ELSE 10200
    END,
    0,
    0,
    'KRW',
    seed.difficulty_level,
    'ko',
    TRUE,
    'PUBLISHED',
    seed.published_at
FROM tmp_backend_tag_video_seed seed
JOIN users u ON u.email = seed.instructor_email
WHERE NOT EXISTS (
    SELECT 1
    FROM courses c
    WHERE c.title = seed.course_title
);

UPDATE courses c
SET
    price = 0,
    original_price = 0,
    currency = 'KRW',
    thumbnail_url = seed.thumbnail_url,
    intro_video_url = seed.intro_video_url,
    status = 'PUBLISHED',
    published_at = COALESCE(c.published_at, seed.published_at)
FROM tmp_backend_tag_video_seed seed
WHERE c.title = seed.course_title
  AND (
      COALESCE(c.price, -1) <> 0
      OR COALESCE(c.original_price, -1) <> 0
      OR COALESCE(c.currency, '') <> 'KRW'
      OR COALESCE(c.thumbnail_url, '') <> seed.thumbnail_url
      OR COALESCE(c.intro_video_url, '') <> seed.intro_video_url
      OR COALESCE(c.status, '') <> 'PUBLISHED'
      OR c.published_at IS NULL
  );

INSERT INTO course_prerequisites (course_id, prerequisite)
WITH prerequisite_seed(prerequisite_text, display_order) AS (
    VALUES
        ('백엔드 기본 문법 또는 웹 서비스 흐름을 알고 있으면 예제를 더 빠르게 이해할 수 있습니다.', 1),
        ('IDE 또는 터미널에서 간단한 프로젝트를 실행해 본 경험이 있으면 실습을 따라가기 쉽습니다.', 2)
)
SELECT c.course_id, ps.prerequisite_text
FROM tmp_backend_tag_video_seed seed
JOIN courses c ON c.title = seed.course_title
JOIN prerequisite_seed ps ON 1 = 1
WHERE NOT EXISTS (
    SELECT 1
    FROM course_prerequisites cp
    WHERE cp.course_id = c.course_id
      AND cp.prerequisite = ps.prerequisite_text
);

INSERT INTO course_job_relevance (course_id, job_relevance)
WITH relevance_seed(job_relevance, display_order) AS (
    VALUES
        ('백엔드 개발자', 1),
        ('서버 애플리케이션 개발과 운영을 준비하는 주니어 개발자', 2)
)
SELECT c.course_id, rs.job_relevance
FROM tmp_backend_tag_video_seed seed
JOIN courses c ON c.title = seed.course_title
JOIN relevance_seed rs ON 1 = 1
WHERE NOT EXISTS (
    SELECT 1
    FROM course_job_relevance cj
    WHERE cj.course_id = c.course_id
      AND cj.job_relevance = rs.job_relevance
);

INSERT INTO course_objectives (course_id, objective_text, display_order)
WITH objective_seed(display_order) AS (
    VALUES (1), (2)
)
SELECT
    c.course_id,
    CASE os.display_order
        WHEN 1 THEN seed.tag_summary || ' 관련 핵심 개념과 요청/데이터 흐름을 설명할 수 있습니다.'
        ELSE '관련 태그를 실제 백엔드 코드와 운영 시나리오에 연결해 적용할 수 있습니다.'
    END,
    os.display_order
FROM tmp_backend_tag_video_seed seed
JOIN courses c ON c.title = seed.course_title
JOIN objective_seed os ON 1 = 1
WHERE NOT EXISTS (
    SELECT 1
    FROM course_objectives co
    WHERE co.course_id = c.course_id
      AND co.display_order = os.display_order
);

INSERT INTO course_target_audiences (course_id, audience_description, display_order)
WITH audience_seed(display_order) AS (
    VALUES (1), (2)
)
SELECT
    c.course_id,
    CASE ads.display_order
        WHEN 1 THEN seed.tag_summary || ' 태그를 실무 기준으로 보강하고 싶은 백엔드 학습자'
        ELSE 'Backend Master Roadmap에서 특정 태그가 막혀 추가 설명이 필요한 주니어 개발자'
    END,
    ads.display_order
FROM tmp_backend_tag_video_seed seed
JOIN courses c ON c.title = seed.course_title
JOIN audience_seed ads ON 1 = 1
WHERE NOT EXISTS (
    SELECT 1
    FROM course_target_audiences cta
    WHERE cta.course_id = c.course_id
      AND cta.display_order = ads.display_order
);

INSERT INTO course_tag_maps (course_id, tag_id, proficiency_level)
SELECT
    c.course_id,
    t.tag_id,
    CASE seed.difficulty_level
        WHEN 'BEGINNER' THEN 2
        ELSE 3
    END
FROM tmp_backend_tag_video_seed seed
JOIN courses c ON c.title = seed.course_title
JOIN tmp_backend_tag_video_tag_seed ts ON ts.course_title = seed.course_title
JOIN tags t ON t.name = ts.tag_name
WHERE NOT EXISTS (
    SELECT 1
    FROM course_tag_maps ctm
    WHERE ctm.course_id = c.course_id
      AND ctm.tag_id = t.tag_id
);

INSERT INTO course_sections (course_id, title, description, sort_order, is_published)
WITH section_seed(sort_order) AS (
    VALUES (1), (2)
)
SELECT
    c.course_id,
    CASE ss.sort_order
        WHEN 1 THEN '핵심 태그 정리'
        ELSE '실전 적용과 체크리스트'
    END,
    CASE ss.sort_order
        WHEN 1 THEN seed.tag_summary || ' 개념을 빠르게 연결해 이해합니다.'
        ELSE seed.tag_summary || '를 실제 서비스와 운영 상황에 적용하는 방법을 정리합니다.'
    END,
    ss.sort_order,
    TRUE
FROM tmp_backend_tag_video_seed seed
JOIN courses c ON c.title = seed.course_title
JOIN section_seed ss ON 1 = 1
WHERE NOT EXISTS (
    SELECT 1
    FROM course_sections cs
    WHERE cs.course_id = c.course_id
      AND cs.sort_order = ss.sort_order
);

INSERT INTO lessons (
    section_id, title, description, lesson_type,
    video_url, video_asset_key, video_provider,
    thumbnail_url, duration_seconds, is_preview, is_published, sort_order
)
WITH lesson_seed(section_order, lesson_order, title_suffix, description_body, video_url, duration_seconds, is_preview) AS (
    VALUES
        (1, 1, '개념 지도', '핵심 태그의 전체 맥락을 먼저 잡습니다.', '/samples/sample-intro.mp4', 720, TRUE),
        (1, 2, '태그별 실전 포인트', '자주 헷갈리는 기준과 예제를 함께 정리합니다.', '/samples/ocr-code-demo.mp4', 900, FALSE),
        (2, 1, '실무 시나리오', '서비스 구현과 운영에서 어떻게 이어지는지 살펴봅니다.', '/samples/lesson-spring-di.mp4', 840, FALSE),
        (2, 2, '체크리스트', '학습 후 바로 점검할 포인트를 정리합니다.', '/samples/lesson-os-context.mp4', 780, FALSE)
)
SELECT
    cs.section_id,
    seed.course_title || ' ' || ls.title_suffix,
    seed.tag_summary || ' 학습을 위해 ' || ls.description_body,
    'VIDEO',
    CASE
        WHEN ls.section_order = 1 AND ls.lesson_order = 1
            THEN seed.intro_video_url
        WHEN seed.course_title LIKE 'Spring %'
            OR seed.course_title LIKE 'MockMvc%'
            OR seed.course_title LIKE 'OAuth2%'
            OR seed.course_title LIKE 'JPA %'
            OR seed.course_title LIKE 'FetchType%'
            THEN '/samples/lesson-spring-bean.mp4'
        WHEN seed.course_title LIKE 'Linux %'
            THEN '/samples/lesson-os-context.mp4'
        ELSE ls.video_url
    END,
    NULL,
    NULL,
    c.thumbnail_url,
    ls.duration_seconds,
    ls.is_preview,
    TRUE,
    ls.lesson_order
FROM tmp_backend_tag_video_seed seed
JOIN courses c ON c.title = seed.course_title
JOIN lesson_seed ls ON 1 = 1
JOIN course_sections cs ON cs.course_id = c.course_id AND cs.sort_order = ls.section_order
WHERE NOT EXISTS (
    SELECT 1
    FROM lessons l
    WHERE l.section_id = cs.section_id
      AND l.sort_order = ls.lesson_order
);

INSERT INTO course_node_mappings (course_id, node_id, created_at)
SELECT DISTINCT
    c.course_id,
    rn.node_id,
    seed.published_at
FROM tmp_backend_tag_video_seed seed
JOIN courses c ON c.title = seed.course_title
JOIN tmp_backend_tag_video_tag_seed ts ON ts.course_title = seed.course_title
JOIN tags t ON t.name = ts.tag_name
JOIN node_required_tags nrt ON nrt.tag_id = t.tag_id
JOIN roadmap_nodes rn ON rn.node_id = nrt.node_id
JOIN roadmaps r ON r.roadmap_id = rn.roadmap_id
WHERE r.title = 'Backend Master Roadmap'
  AND NOT EXISTS (
      SELECT 1
      FROM course_node_mappings cnm
      WHERE cnm.course_id = c.course_id
        AND cnm.node_id = rn.node_id
  );

INSERT INTO roadmap_node_resources (
    node_id, title, url, description, source_type, sort_order, active, created_at, updated_at
)
SELECT DISTINCT
    rn.node_id,
    c.title,
    'course-detail.html?courseId=' || c.course_id,
    '관련 태그: ' || seed.tag_summary || '. 노드에서 막힌 태그를 영상 중심으로 빠르게 보강할 수 있는 공개 강의입니다.',
    'COURSE',
    4,
    TRUE,
    seed.published_at,
    seed.published_at
FROM tmp_backend_tag_video_seed seed
JOIN courses c ON c.title = seed.course_title
JOIN tmp_backend_tag_video_tag_seed ts ON ts.course_title = seed.course_title
JOIN tags t ON t.name = ts.tag_name
JOIN node_required_tags nrt ON nrt.tag_id = t.tag_id
JOIN roadmap_nodes rn ON rn.node_id = nrt.node_id
JOIN roadmaps r ON r.roadmap_id = rn.roadmap_id
WHERE r.title = 'Backend Master Roadmap'
  AND NOT EXISTS (
      SELECT 1
      FROM roadmap_node_resources existing
      WHERE existing.node_id = rn.node_id
        AND existing.url = 'course-detail.html?courseId=' || c.course_id
  );

INSERT INTO course_announcements (
    course_id, announcement_type, title, content, is_pinned, display_order,
    published_at, exposure_start_at, exposure_end_at,
    event_banner_text, event_link, created_at, updated_at
)
SELECT
    c.course_id,
    'NORMAL',
    seed.course_title || ' 학습 가이드',
    '이 강의는 Backend Master Roadmap의 관련 태그를 빠르게 보강할 수 있도록 구성되었습니다. 태그: '
        || seed.tag_summary
        || '. 노드에서 막힌 태그를 먼저 확인한 뒤 필요한 섹션만 골라 들어도 흐름을 잡을 수 있습니다.',
    FALSE,
    1,
    seed.published_at,
    seed.published_at,
    NULL,
    NULL,
    NULL,
    seed.published_at,
    seed.published_at
FROM tmp_backend_tag_video_seed seed
JOIN courses c ON c.title = seed.course_title
WHERE NOT EXISTS (
    SELECT 1
    FROM course_announcements ca
    WHERE ca.course_id = c.course_id
      AND ca.title = seed.course_title || ' 학습 가이드'
);

DROP TABLE IF EXISTS tmp_backend_tag_video_tag_seed;
DROP TABLE IF EXISTS tmp_backend_tag_video_seed;

-- =============================================
-- 로드맵 빌더 모듈 데이터 (builder_modules)
-- =============================================

-- frontend (6)
INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'cs-net', 'frontend', '인터넷 & 네트워크', 'fas fa-globe', 'text-blue-500', 'bg-blue-50',
       '["HTTP/HTTPS","DNS 작동원리","도메인 & 호스팅"]', 1
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'cs-net' AND category = 'frontend');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'fe-html', 'frontend', 'HTML / CSS', 'fab fa-html5', 'text-orange-500', 'bg-orange-50',
       '["시맨틱 태그","Flexbox & Grid","반응형 웹","SEO 기초"]', 2
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'fe-html' AND category = 'frontend');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'fe-js', 'frontend', 'JavaScript', 'fab fa-js', 'text-yellow-500', 'bg-yellow-50',
       '["ES6+","DOM 조작","비동기(Promise/Async)","이벤트 루프"]', 3
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'fe-js' AND category = 'frontend');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'fe-ts', 'frontend', 'TypeScript', 'fas fa-file-code', 'text-blue-600', 'bg-blue-50',
       '["정적 타이핑","인터페이스","제네릭"]', 4
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'fe-ts' AND category = 'frontend');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'fe-react', 'frontend', 'React', 'fab fa-react', 'text-cyan-500', 'bg-cyan-50',
       '["컴포넌트 생명주기","React Hooks","상태 관리","라우팅"]', 5
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'fe-react' AND category = 'frontend');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'fe-next', 'frontend', 'Next.js', 'fas fa-n', 'text-black', 'bg-gray-200',
       '["SSR / SSG","App Router","API Routes","최적화"]', 6
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'fe-next' AND category = 'frontend');

-- backend (8)
INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'cs-net', 'backend', '인터넷 & 네트워크', 'fas fa-globe', 'text-blue-500', 'bg-blue-50',
       '["TCP/IP","HTTP 메서드","CORS","웹 소켓"]', 1
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'cs-net' AND category = 'backend');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'cs-os', 'backend', 'OS 및 일반 지식', 'fas fa-terminal', 'text-gray-700', 'bg-gray-200',
       '["터미널 명령어","프로세스와 스레드","메모리 관리","동시성"]', 2
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'cs-os' AND category = 'backend');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'be-java', 'backend', 'Java Programming', 'fab fa-java', 'text-red-500', 'bg-red-50',
       '["객체지향(OOP)","JVM 메모리 구조","컬렉션 프레임워크","스트림 API"]', 3
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'be-java' AND category = 'backend');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'be-spring', 'backend', 'Spring Boot', 'fas fa-leaf', 'text-green-500', 'bg-green-50',
       '["의존성 주입(DI)","AOP","Spring MVC","JPA / Hibernate"]', 4
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'be-spring' AND category = 'backend');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'db-rdb', 'backend', '관계형 데이터베이스', 'fas fa-database', 'text-indigo-500', 'bg-indigo-50',
       '["PostgreSQL / MySQL","정규화","트랜잭션(ACID)","인덱스 최적화"]', 5
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'db-rdb' AND category = 'backend');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'be-api', 'backend', 'API 설계', 'fas fa-network-wired', 'text-purple-500', 'bg-purple-50',
       '["RESTful 설계","GraphQL","JWT 인증","OAuth 2.0"]', 6
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'be-api' AND category = 'backend');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'be-redis', 'backend', 'Redis & 캐싱', 'fas fa-memory', 'text-red-500', 'bg-red-50',
       '["In-Memory DB","세션 관리","캐싱 전략","Pub/Sub"]', 7
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'be-redis' AND category = 'backend');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'infra-docker', 'backend', 'Docker', 'fab fa-docker', 'text-blue-600', 'bg-blue-50',
       '["컨테이너화","Dockerfile","Docker Compose","볼륨 관리"]', 8
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'infra-docker' AND category = 'backend');

-- devops (5)
INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'cs-os', 'devops', 'Linux Administration', 'fab fa-linux', 'text-black', 'bg-gray-200',
       '["쉘 스크립트","권한 관리(chmod)","시스템 모니터링","SSH"]', 1
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'cs-os' AND category = 'devops');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'infra-docker', 'devops', 'Docker 심화', 'fab fa-docker', 'text-blue-600', 'bg-blue-50',
       '["멀티스테이지 빌드","네트워크 브릿지","이미지 경량화"]', 2
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'infra-docker' AND category = 'devops');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'do-cicd', 'devops', 'CI/CD 파이프라인', 'fas fa-sync-alt', 'text-teal-500', 'bg-teal-50',
       '["GitHub Actions","Jenkins","파이프라인 구축","자동 배포"]', 3
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'do-cicd' AND category = 'devops');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'do-k8s', 'devops', 'Kubernetes', 'fas fa-dharmachakra', 'text-blue-500', 'bg-blue-50',
       '["Pod & Service","Deployment","Ingress","Helm Chart"]', 4
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'do-k8s' AND category = 'devops');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'do-aws', 'devops', 'AWS 인프라', 'fab fa-aws', 'text-orange-400', 'bg-orange-50',
       '["EC2 & VPC","S3 스토리지","IAM 권한","RDS & ElastiCache"]', 5
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'do-aws' AND category = 'devops');

-- fullstack (5)
INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'fe-react', 'fullstack', 'React / Next.js', 'fab fa-react', 'text-cyan-500', 'bg-cyan-50',
       '["클라이언트 UI","상태 관리","서버 사이드 렌더링"]', 1
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'fe-react' AND category = 'fullstack');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'fs-node', 'fullstack', 'Node.js / Express', 'fab fa-node-js', 'text-green-600', 'bg-green-50',
       '["JavaScript 런타임","미들웨어","REST API 구축"]', 2
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'fs-node' AND category = 'fullstack');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'be-spring', 'fullstack', 'Spring Boot (선택)', 'fas fa-leaf', 'text-green-500', 'bg-green-50',
       '["엔터프라이즈 백엔드","JPA 연동","보안 설정"]', 3
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'be-spring' AND category = 'fullstack');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'db-rdb', 'fullstack', 'PostgreSQL', 'fas fa-database', 'text-indigo-500', 'bg-indigo-50',
       '["RDBMS 기본","데이터 모델링"]', 4
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'db-rdb' AND category = 'fullstack');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'infra-docker', 'fullstack', 'Docker', 'fab fa-docker', 'text-blue-600', 'bg-blue-50',
       '["풀스택 앱 컨테이너화","Compose 연동"]', 5
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'infra-docker' AND category = 'fullstack');

-- ai (5)
INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'ai-py', 'ai', 'Python Programming', 'fab fa-python', 'text-blue-500', 'bg-blue-50',
       '["데이터 타입","Numpy","Pandas","데이터 전처리"]', 1
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'ai-py' AND category = 'ai');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'ai-math', 'ai', '수학 및 통계', 'fas fa-square-root-alt', 'text-gray-700', 'bg-gray-200',
       '["선형대수학","미적분","확률과 통계"]', 2
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'ai-math' AND category = 'ai');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'ai-ml', 'ai', 'Machine Learning', 'fas fa-robot', 'text-orange-500', 'bg-orange-50',
       '["Scikit-learn","지도 학습","비지도 학습","모델 평가"]', 3
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'ai-ml' AND category = 'ai');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'ai-dl', 'ai', 'Deep Learning', 'fas fa-brain', 'text-purple-500', 'bg-purple-50',
       '["PyTorch / TensorFlow","신경망 기초","CNN","RNN / LSTM"]', 4
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'ai-dl' AND category = 'ai');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'ai-nlp', 'ai', 'NLP & LLM', 'fas fa-language', 'text-green-600', 'bg-green-50',
       '["트랜스포머 아키텍처","Hugging Face","프롬프트 엔지니어링","RAG"]', 5
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'ai-nlp' AND category = 'ai');

-- data_engineer (5)
INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'ai-py', 'data_engineer', 'Python / Scala', 'fab fa-python', 'text-blue-500', 'bg-blue-50',
       '["데이터 파이프라인 개발","분산 처리 기초"]', 1
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'ai-py' AND category = 'data_engineer');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'db-rdb', 'data_engineer', 'Advanced SQL', 'fas fa-database', 'text-indigo-500', 'bg-indigo-50',
       '["복잡한 조인","윈도우 함수","쿼리 실행 계획 튜닝"]', 2
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'db-rdb' AND category = 'data_engineer');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'de-dw', 'data_engineer', 'Data Warehouse', 'fas fa-cubes', 'text-blue-400', 'bg-blue-50',
       '["BigQuery","Snowflake","데이터 마트 설계"]', 3
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'de-dw' AND category = 'data_engineer');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'de-spark', 'data_engineer', 'Apache Spark', 'fas fa-bolt', 'text-orange-500', 'bg-orange-50',
       '["RDD","Spark SQL","대용량 데이터 변환"]', 4
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'de-spark' AND category = 'data_engineer');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'de-kafka', 'data_engineer', 'Apache Kafka', 'fas fa-stream', 'text-black', 'bg-gray-200',
       '["이벤트 스트리밍","Pub/Sub 구조","실시간 파이프라인"]', 5
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'de-kafka' AND category = 'data_engineer');

-- android (5)
INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'app-kt', 'android', 'Kotlin Programming', 'fas fa-code', 'text-purple-600', 'bg-purple-50',
       '["코틀린 문법","Null 안정성","컬렉션 및 람다"]', 1
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'app-kt' AND category = 'android');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'app-and', 'android', 'Android Studio', 'fab fa-android', 'text-green-500', 'bg-green-50',
       '["IDE 활용","Gradle 빌드","에뮬레이터"]', 2
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'app-and' AND category = 'android');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'app-ui', 'android', 'Jetpack Compose', 'fas fa-layer-group', 'text-blue-500', 'bg-blue-50',
       '["선언형 UI","상태 호이스팅","애니메이션","레이아웃"]', 3
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'app-ui' AND category = 'android');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'app-coroutine', 'android', 'Coroutines & Flow', 'fas fa-water', 'text-cyan-500', 'bg-cyan-50',
       '["비동기 프로그래밍","백그라운드 스레드","데이터 스트림"]', 4
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'app-coroutine' AND category = 'android');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'app-arch', 'android', 'Architecture (MVVM)', 'fas fa-project-diagram', 'text-orange-500', 'bg-orange-50',
       '["ViewModel","LiveData","의존성 주입(Hilt)"]', 5
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'app-arch' AND category = 'android');

-- ios (4)
INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'app-swift', 'ios', 'Swift Programming', 'fab fa-apple', 'text-black', 'bg-gray-200',
       '["옵셔널","구조체와 클래스","프로토콜 지향 프로그래밍"]', 1
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'app-swift' AND category = 'ios');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'app-swiftui', 'ios', 'SwiftUI', 'fas fa-layer-group', 'text-blue-500', 'bg-blue-50',
       '["선언형 뷰","상태 관리(@State)","네비게이션"]', 2
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'app-swiftui' AND category = 'ios');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'app-combine', 'ios', 'Combine', 'fas fa-stream', 'text-purple-500', 'bg-purple-50',
       '["Publisher / Subscriber","데이터 바인딩"]', 3
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'app-combine' AND category = 'ios');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'app-coredata', 'ios', 'Core Data', 'fas fa-database', 'text-indigo-500', 'bg-indigo-50',
       '["로컬 데이터 저장","엔티티 관리","마이그레이션"]', 4
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'app-coredata' AND category = 'ios');

-- game (5)
INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'game-math', 'game', '3D Math & Physics', 'fas fa-square-root-alt', 'text-gray-700', 'bg-gray-200',
       '["벡터와 행렬","쿼터니언 회전","충돌 처리","물리 엔진"]', 1
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'game-math' AND category = 'game');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'game-cs', 'game', 'C# Programming', 'fas fa-code', 'text-purple-600', 'bg-purple-50',
       '["C# 문법","이벤트와 델리게이트","가비지 컬렉션"]', 2
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'game-cs' AND category = 'game');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'game-unity', 'game', 'Unity Engine', 'fab fa-unity', 'text-black', 'bg-gray-200',
       '["컴포넌트 패턴","씬 관리","애니메이터","UI 시스템"]', 3
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'game-unity' AND category = 'game');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'game-cpp', 'game', 'C++ Programming', 'fas fa-file-code', 'text-blue-600', 'bg-blue-50',
       '["포인터와 참조","메모리 관리","STL 라이브러리"]', 4
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'game-cpp' AND category = 'game');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'game-unreal', 'game', 'Unreal Engine', 'fas fa-gamepad', 'text-orange-500', 'bg-orange-50',
       '["블루프린트","액터 시스템","메테리얼 에디터"]', 5
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'game-unreal' AND category = 'game');

-- blockchain (4)
INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'bc-crypto', 'blockchain', 'Cryptography', 'fas fa-key', 'text-yellow-600', 'bg-yellow-50',
       '["해시 함수","공개키/개인키","디지털 서명"]', 1
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'bc-crypto' AND category = 'blockchain');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'bc-basics', 'blockchain', 'Blockchain Basics', 'fas fa-link', 'text-gray-700', 'bg-gray-200',
       '["P2P 네트워크","합의 알고리즘(PoW/PoS)","분산 원장"]', 2
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'bc-basics' AND category = 'blockchain');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'bc-sol', 'blockchain', 'Solidity', 'fab fa-ethereum', 'text-purple-500', 'bg-purple-50',
       '["EVM","토큰 표준(ERC-20)","가스비 최적화"]', 3
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'bc-sol' AND category = 'blockchain');

INSERT INTO builder_modules (module_id, category, title, icon, color, bg_color, topics, sort_order)
SELECT 'bc-web3', 'blockchain', 'Web3.js / Ethers.js', 'fas fa-plug', 'text-blue-500', 'bg-blue-50',
       '["DApp 구축","지갑 연동(Metamask)","RPC 통신"]', 4
WHERE NOT EXISTS (SELECT 1 FROM builder_modules WHERE module_id = 'bc-web3' AND category = 'blockchain');
UPDATE users
SET
    name = CASE email
        WHEN 'learner@devpath.com' THEN '김하늘'
        WHEN 'learner2@devpath.com' THEN '박지민'
        WHEN 'learner3@devpath.com' THEN '이서준'
        WHEN 'learner4@devpath.com' THEN '최유진'
        WHEN 'restricted-user@devpath.com' THEN '정민재'
        WHEN 'deactivated-user@devpath.com' THEN '오서연'
        WHEN 'withdrawn-user@devpath.com' THEN '강도윤'
        WHEN 'instructor@devpath.com' THEN '홍지훈'
        WHEN 'admin@devpath.com' THEN '박서연'
        ELSE name
    END,
    updated_at = NOW()
WHERE email IN (
    'learner@devpath.com',
    'learner2@devpath.com',
    'learner3@devpath.com',
    'learner4@devpath.com',
    'restricted-user@devpath.com',
    'deactivated-user@devpath.com',
    'withdrawn-user@devpath.com',
    'instructor@devpath.com',
    'admin@devpath.com'
);

-- [CATALOG] frontend@devpath.com 강사 대시보드 활동 데이터
INSERT INTO course_enrollments (
    user_id, course_id, status, enrolled_at, completed_at, progress_percentage, last_accessed_at
)
WITH frontend_enrollment_seed(
    learner_email, course_title, status, enrolled_at, completed_at, progress_percentage, last_accessed_at
) AS (
    VALUES
        ('learner@devpath.com', 'React 19 프론트엔드 실전 가이드', 'ACTIVE', TIMESTAMP '2026-04-02 10:00:00', CAST(NULL AS TIMESTAMP), 18, TIMESTAMP '2026-04-05 21:10:00'),
        ('learner2@devpath.com', 'React 19 프론트엔드 실전 가이드', 'COMPLETED', TIMESTAMP '2026-04-02 11:00:00', TIMESTAMP '2026-04-16 20:20:00', 100, TIMESTAMP '2026-04-16 20:20:00'),
        ('learner3@devpath.com', 'React 19 프론트엔드 실전 가이드', 'ACTIVE', TIMESTAMP '2026-04-03 10:30:00', CAST(NULL AS TIMESTAMP), 34, TIMESTAMP '2026-04-07 19:30:00'),
        ('learner4@devpath.com', 'React 19 프론트엔드 실전 가이드', 'ACTIVE', TIMESTAMP '2026-04-04 14:10:00', CAST(NULL AS TIMESTAMP), 52, TIMESTAMP '2026-04-15 22:10:00'),
        ('learner@devpath.com', 'Next.js 14 제품 개발 실전', 'ACTIVE', TIMESTAMP '2026-04-04 09:20:00', CAST(NULL AS TIMESTAMP), 12, TIMESTAMP '2026-04-04 22:40:00'),
        ('learner2@devpath.com', 'Next.js 14 제품 개발 실전', 'ACTIVE', TIMESTAMP '2026-04-05 13:00:00', CAST(NULL AS TIMESTAMP), 44, TIMESTAMP '2026-04-09 18:20:00'),
        ('learner3@devpath.com', 'Next.js 14 제품 개발 실전', 'COMPLETED', TIMESTAMP '2026-04-05 15:40:00', TIMESTAMP '2026-04-16 21:00:00', 100, TIMESTAMP '2026-04-16 21:00:00'),
        ('learner4@devpath.com', 'Next.js 14 제품 개발 실전', 'ACTIVE', TIMESTAMP '2026-04-06 10:15:00', CAST(NULL AS TIMESTAMP), 27, TIMESTAMP '2026-04-08 20:00:00'),
        ('learner@devpath.com', 'Flutter로 MVP 앱 출시하기', 'ACTIVE', TIMESTAMP '2026-04-06 09:00:00', CAST(NULL AS TIMESTAMP), 9, TIMESTAMP '2026-04-03 23:10:00'),
        ('learner2@devpath.com', 'Flutter로 MVP 앱 출시하기', 'ACTIVE', TIMESTAMP '2026-04-07 12:20:00', CAST(NULL AS TIMESTAMP), 63, TIMESTAMP '2026-04-14 21:30:00'),
        ('learner3@devpath.com', 'Flutter로 MVP 앱 출시하기', 'ACTIVE', TIMESTAMP '2026-04-07 19:00:00', CAST(NULL AS TIMESTAMP), 28, TIMESTAMP '2026-04-08 22:45:00'),
        ('learner4@devpath.com', 'Flutter로 MVP 앱 출시하기', 'COMPLETED', TIMESTAMP '2026-04-08 11:10:00', TIMESTAMP '2026-04-16 19:10:00', 100, TIMESTAMP '2026-04-16 19:10:00')
)
SELECT
    u.user_id,
    c.course_id,
    seed.status,
    seed.enrolled_at,
    seed.completed_at,
    seed.progress_percentage,
    seed.last_accessed_at
FROM frontend_enrollment_seed seed
JOIN users u ON u.email = seed.learner_email
JOIN courses c ON c.title = seed.course_title
WHERE NOT EXISTS (
    SELECT 1
    FROM course_enrollments ce
    WHERE ce.user_id = u.user_id
      AND ce.course_id = c.course_id
);

INSERT INTO lesson_progress (
    user_id, lesson_id, progress_percent, progress_seconds,
    default_playback_rate, is_pip_enabled, is_completed,
    last_watched_at, created_at, updated_at
)
WITH frontend_progress_seed(
    learner_email, course_title, lesson_title, progress_percent,
    progress_seconds, default_playback_rate, is_pip_enabled, is_completed, last_watched_at
) AS (
    VALUES
        ('learner@devpath.com', 'React 19 프론트엔드 실전 가이드', '컴포넌트 경계와 상태 배치', 100, 900, 1.25, TRUE, TRUE, TIMESTAMP '2026-04-04 21:00:00'),
        ('learner@devpath.com', 'React 19 프론트엔드 실전 가이드', 'Actions와 폼 처리 패턴', 35, 430, 1.00, FALSE, FALSE, TIMESTAMP '2026-04-05 21:10:00'),
        ('learner2@devpath.com', 'React 19 프론트엔드 실전 가이드', '컴포넌트 경계와 상태 배치', 100, 900, 1.25, TRUE, TRUE, TIMESTAMP '2026-04-12 20:00:00'),
        ('learner2@devpath.com', 'React 19 프론트엔드 실전 가이드', 'Actions와 폼 처리 패턴', 100, 960, 1.25, TRUE, TRUE, TIMESTAMP '2026-04-13 20:30:00'),
        ('learner2@devpath.com', 'React 19 프론트엔드 실전 가이드', 'Tailwind 유틸리티 설계', 100, 840, 1.25, TRUE, TRUE, TIMESTAMP '2026-04-15 20:10:00'),
        ('learner2@devpath.com', 'React 19 프론트엔드 실전 가이드', 'Playwright로 사용자 흐름 테스트', 100, 1020, 1.25, TRUE, TRUE, TIMESTAMP '2026-04-16 20:20:00'),
        ('learner3@devpath.com', 'React 19 프론트엔드 실전 가이드', '컴포넌트 경계와 상태 배치', 80, 720, 1.00, FALSE, FALSE, TIMESTAMP '2026-04-06 19:00:00'),
        ('learner3@devpath.com', 'React 19 프론트엔드 실전 가이드', 'Actions와 폼 처리 패턴', 25, 310, 1.00, FALSE, FALSE, TIMESTAMP '2026-04-07 19:30:00'),
        ('learner4@devpath.com', 'React 19 프론트엔드 실전 가이드', '컴포넌트 경계와 상태 배치', 100, 900, 1.10, FALSE, TRUE, TIMESTAMP '2026-04-12 21:30:00'),
        ('learner4@devpath.com', 'React 19 프론트엔드 실전 가이드', 'Tailwind 유틸리티 설계', 55, 460, 1.10, FALSE, FALSE, TIMESTAMP '2026-04-15 22:10:00'),
        ('learner@devpath.com', 'Next.js 14 제품 개발 실전', '라우팅과 레이아웃 구조 설계', 40, 360, 1.00, FALSE, FALSE, TIMESTAMP '2026-04-04 22:40:00'),
        ('learner2@devpath.com', 'Next.js 14 제품 개발 실전', '라우팅과 레이아웃 구조 설계', 100, 900, 1.25, TRUE, TRUE, TIMESTAMP '2026-04-08 18:00:00'),
        ('learner2@devpath.com', 'Next.js 14 제품 개발 실전', '서버 컴포넌트와 캐싱 전략', 45, 480, 1.00, FALSE, FALSE, TIMESTAMP '2026-04-09 18:20:00'),
        ('learner3@devpath.com', 'Next.js 14 제품 개발 실전', '라우팅과 레이아웃 구조 설계', 100, 900, 1.25, TRUE, TRUE, TIMESTAMP '2026-04-14 20:10:00'),
        ('learner3@devpath.com', 'Next.js 14 제품 개발 실전', '서버 컴포넌트와 캐싱 전략', 100, 1080, 1.25, TRUE, TRUE, TIMESTAMP '2026-04-15 20:30:00'),
        ('learner3@devpath.com', 'Next.js 14 제품 개발 실전', '인증과 권한 처리', 100, 960, 1.25, TRUE, TRUE, TIMESTAMP '2026-04-16 20:40:00'),
        ('learner4@devpath.com', 'Next.js 14 제품 개발 실전', '라우팅과 레이아웃 구조 설계', 55, 500, 1.00, FALSE, FALSE, TIMESTAMP '2026-04-08 20:00:00'),
        ('learner@devpath.com', 'Flutter로 MVP 앱 출시하기', '위젯 트리와 상태 관리', 20, 170, 1.00, FALSE, FALSE, TIMESTAMP '2026-04-03 23:10:00'),
        ('learner2@devpath.com', 'Flutter로 MVP 앱 출시하기', '위젯 트리와 상태 관리', 100, 840, 1.10, FALSE, TRUE, TIMESTAMP '2026-04-12 21:20:00'),
        ('learner2@devpath.com', 'Flutter로 MVP 앱 출시하기', '라우팅과 폼 검증', 80, 720, 1.10, FALSE, FALSE, TIMESTAMP '2026-04-14 21:30:00'),
        ('learner3@devpath.com', 'Flutter로 MVP 앱 출시하기', '위젯 트리와 상태 관리', 60, 500, 1.00, FALSE, FALSE, TIMESTAMP '2026-04-07 22:10:00'),
        ('learner3@devpath.com', 'Flutter로 MVP 앱 출시하기', '라우팅과 폼 검증', 10, 90, 1.00, FALSE, FALSE, TIMESTAMP '2026-04-08 22:45:00'),
        ('learner4@devpath.com', 'Flutter로 MVP 앱 출시하기', '위젯 트리와 상태 관리', 100, 840, 1.25, TRUE, TRUE, TIMESTAMP '2026-04-13 19:10:00'),
        ('learner4@devpath.com', 'Flutter로 MVP 앱 출시하기', '라우팅과 폼 검증', 100, 900, 1.25, TRUE, TRUE, TIMESTAMP '2026-04-14 19:40:00'),
        ('learner4@devpath.com', 'Flutter로 MVP 앱 출시하기', 'REST API 연동과 에러 처리', 100, 960, 1.25, TRUE, TRUE, TIMESTAMP '2026-04-15 19:30:00')
)
SELECT
    u.user_id,
    l.lesson_id,
    seed.progress_percent,
    seed.progress_seconds,
    seed.default_playback_rate,
    seed.is_pip_enabled,
    seed.is_completed,
    seed.last_watched_at,
    seed.last_watched_at,
    seed.last_watched_at
FROM frontend_progress_seed seed
JOIN users u ON u.email = seed.learner_email
JOIN courses c ON c.title = seed.course_title
JOIN course_sections cs ON cs.course_id = c.course_id
JOIN lessons l ON l.section_id = cs.section_id AND l.title = seed.lesson_title
WHERE NOT EXISTS (
    SELECT 1
    FROM lesson_progress lp
    WHERE lp.user_id = u.user_id
      AND lp.lesson_id = l.lesson_id
);

-- =========================================================
-- Mentoring common-assignment workspace reference data
-- =========================================================

INSERT INTO mentoring_posts (
    mentor_id,
    title,
    content,
    required_stacks,
    category,
    mentoring_type,
    duration_weeks,
    curriculum,
    deadline_at,
    current_participants,
    max_participants,
    view_count,
    status,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    mentor.user_id,
    '대용량 트래픽 처리를 위한 커머스 서버 구축',
    'Spring Boot, Redis, Kafka를 사용해 선착순 쿠폰 발급과 주문 흐름을 설계하고 성능 테스트까지 진행하는 공통 과제형 멘토링입니다.',
    'Spring Boot,Redis,Kafka,PostgreSQL,JMeter',
    'Backend',
    'study',
    4,
    E'1주차: 요구사항 분석, ERD 초안 작성, API 설계\n2주차: 회원, 상품, 주문 도메인 구현\n3주차: Redis 분산락과 Kafka 이벤트 파이프라인 적용\n4주차: JMeter 부하 테스트, 병목 분석, 최종 회고',
    CURRENT_DATE + 14,
    2,
    10,
    0,
    'OPEN',
    FALSE,
    TIMESTAMP '2026-05-01 10:00:00',
    TIMESTAMP '2026-05-24 18:00:00'
FROM users mentor
WHERE mentor.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM mentoring_posts post
      WHERE post.title = '대용량 트래픽 처리를 위한 커머스 서버 구축'
        AND post.mentor_id = mentor.user_id
        AND post.is_deleted = FALSE
  );

INSERT INTO mentoring_applications (
    mentoring_post_id,
    applicant_id,
    message,
    status,
    reject_reason,
    processed_at,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    post.mentoring_post_id,
    learner.user_id,
    '공통 과제형 멘토링 워크스페이스에서 실제 과제와 ERD 피드백을 받고 싶습니다.',
    'APPROVED',
    NULL,
    TIMESTAMP '2026-05-01 10:30:00',
    FALSE,
    TIMESTAMP '2026-05-01 10:20:00',
    TIMESTAMP '2026-05-01 10:30:00'
FROM mentoring_posts post
JOIN users learner ON learner.email IN ('learner@devpath.com', 'frontend@devpath.com')
WHERE post.title = '대용량 트래픽 처리를 위한 커머스 서버 구축'
  AND post.mentor_id = (SELECT user_id FROM users WHERE email = 'instructor@devpath.com')
  AND NOT EXISTS (
      SELECT 1
      FROM mentoring_applications application
      WHERE application.mentoring_post_id = post.mentoring_post_id
        AND application.applicant_id = learner.user_id
  );

INSERT INTO mentorings (
    mentoring_post_id,
    mentor_id,
    mentee_id,
    status,
    started_at,
    ended_at,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    post.mentoring_post_id,
    mentor.user_id,
    learner.user_id,
    'ONGOING',
    TIMESTAMP '2026-05-01 11:00:00',
    NULL,
    FALSE,
    TIMESTAMP '2026-05-01 11:00:00',
    TIMESTAMP '2026-05-24 18:00:00'
FROM mentoring_posts post
JOIN users mentor ON mentor.email = 'instructor@devpath.com'
JOIN users learner ON learner.email IN ('learner@devpath.com', 'frontend@devpath.com')
WHERE post.title = '대용량 트래픽 처리를 위한 커머스 서버 구축'
  AND NOT EXISTS (
      SELECT 1
      FROM mentorings mentoring
      WHERE mentoring.mentoring_post_id = post.mentoring_post_id
        AND mentoring.mentee_id = learner.user_id
        AND mentoring.is_deleted = FALSE
  );

INSERT INTO workspace (
    owner_id,
    name,
    description,
    type,
    status,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    mentor.user_id,
    '대용량 트래픽 처리를 위한 커머스 서버 구축',
    '공통 과제형 멘토링으로 쿠폰 발급, 주문 처리, Redis 분산락, Kafka 이벤트 흐름, ERD 설계를 함께 진행합니다.',
    'MENTORING',
    'ACTIVE',
    FALSE,
    TIMESTAMP '2026-05-01 11:10:00',
    TIMESTAMP '2026-05-24 18:00:00'
FROM users mentor
WHERE mentor.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM workspace workspace_seed
      WHERE workspace_seed.name = '대용량 트래픽 처리를 위한 커머스 서버 구축'
        AND workspace_seed.type = 'MENTORING'
        AND workspace_seed.is_deleted = FALSE
  );

INSERT INTO workspace_member (
    workspace_id,
    learner_id,
    joined_at,
    last_active_at
)
SELECT
    workspace_seed.id,
    learner.user_id,
    TIMESTAMP '2026-05-01 11:15:00',
    CASE
        WHEN learner.email = 'frontend@devpath.com' THEN TIMESTAMP '2026-05-24 21:30:00'
        ELSE TIMESTAMP '2026-05-24 20:45:00'
    END
FROM workspace workspace_seed
JOIN users learner ON learner.email IN ('learner@devpath.com', 'frontend@devpath.com')
WHERE workspace_seed.name = '대용량 트래픽 처리를 위한 커머스 서버 구축'
  AND workspace_seed.type = 'MENTORING'
  AND NOT EXISTS (
      SELECT 1
      FROM workspace_member member_seed
      WHERE member_seed.workspace_id = workspace_seed.id
        AND member_seed.learner_id = learner.user_id
  );

INSERT INTO workspace_notice (
    workspace_id,
    title,
    content,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    workspace_seed.id,
    notice_seed.title,
    notice_seed.content,
    FALSE,
    notice_seed.created_at,
    notice_seed.created_at
FROM workspace workspace_seed
CROSS JOIN (
    VALUES
        ('3주차 과제 안내', 'Redis 분산락 적용 후 Kafka 이벤트 발행 흐름까지 커밋하고, JMeter 결과 스크린샷을 자료실에 올려주세요.', TIMESTAMP '2026-05-21 09:00:00'),
        ('라이브 코드 리뷰 공지', '목요일 20시에 쿠폰 발급 API와 ERD 관계선을 중심으로 코드 리뷰를 진행합니다.', TIMESTAMP '2026-05-22 14:00:00'),
        ('ERD 피드백 기준', '식별자, 외래키, 인덱스 후보, 이벤트 로그 테이블을 구분해서 설계 근거를 남겨주세요.', TIMESTAMP '2026-05-23 10:30:00')
) AS notice_seed(title, content, created_at)
WHERE workspace_seed.name = '대용량 트래픽 처리를 위한 커머스 서버 구축'
  AND workspace_seed.type = 'MENTORING'
  AND NOT EXISTS (
      SELECT 1
      FROM workspace_notice notice
      WHERE notice.workspace_id = workspace_seed.id
        AND notice.title = notice_seed.title
        AND notice.is_deleted = FALSE
  );

INSERT INTO workspace_task (
    workspace_id,
    title,
    description,
    status,
    priority,
    assignee_id,
    due_date,
    created_by_id,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    workspace_seed.id,
    task_seed.title,
    task_seed.description,
    task_seed.status,
    task_seed.priority,
    learner.user_id,
    task_seed.due_date,
    mentor.user_id,
    FALSE,
    task_seed.created_at,
    task_seed.updated_at
FROM workspace workspace_seed
JOIN users mentor ON mentor.email = 'instructor@devpath.com'
JOIN (
    VALUES
        ('JMeter 부하 테스트 환경 세팅', '쿠폰 발급 API를 대상으로 100, 300, 500 동시 사용자 시나리오를 준비합니다.', 'TODO', 'MEDIUM', 'frontend@devpath.com', CURRENT_DATE + 2, TIMESTAMP '2026-05-20 09:00:00', TIMESTAMP '2026-05-22 09:00:00'),
        ('Kafka 파티션 분배 전략 정리', '주문 이벤트 토픽의 파티션 키와 컨슈머 그룹 전략을 회의록에 정리합니다.', 'TODO', 'LOW', 'learner@devpath.com', CURRENT_DATE + 3, TIMESTAMP '2026-05-20 10:00:00', TIMESTAMP '2026-05-22 10:00:00'),
        ('Redis 중복 발급 검증 로직 구현', 'user_id와 coupon_id 조합으로 중복 발급을 막고 테스트 케이스를 작성합니다.', 'IN_PROGRESS', 'HIGH', 'frontend@devpath.com', CURRENT_DATE + 1, TIMESTAMP '2026-05-18 10:00:00', TIMESTAMP '2026-05-24 18:30:00'),
        ('Docker Compose 로컬 실행 스크립트 정리', 'PostgreSQL, Redis, Kafka를 한 번에 올릴 수 있도록 README 명령을 정리합니다.', 'DONE', 'MEDIUM', 'learner@devpath.com', CURRENT_DATE - 1, TIMESTAMP '2026-05-16 11:00:00', TIMESTAMP '2026-05-21 19:00:00'),
        ('API 응답 DTO와 예외 코드 정리', '쿠폰 발급 실패, 재고 부족, 중복 요청 예외 코드를 통일합니다.', 'DONE', 'LOW', 'frontend@devpath.com', CURRENT_DATE - 2, TIMESTAMP '2026-05-15 13:00:00', TIMESTAMP '2026-05-20 20:00:00')
) AS task_seed(title, description, status, priority, assignee_email, due_date, created_at, updated_at)
ON TRUE
JOIN users learner ON learner.email = task_seed.assignee_email
WHERE workspace_seed.name = '대용량 트래픽 처리를 위한 커머스 서버 구축'
  AND workspace_seed.type = 'MENTORING'
  AND NOT EXISTS (
      SELECT 1
      FROM workspace_task task
      WHERE task.workspace_id = workspace_seed.id
        AND task.title = task_seed.title
        AND task.is_deleted = FALSE
  );

INSERT INTO calendar_event (
    workspace_id,
    title,
    description,
    start_at,
    end_at,
    created_by_id,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    workspace_seed.id,
    event_seed.title,
    event_seed.description,
    event_seed.start_at,
    event_seed.end_at,
    mentor.user_id,
    FALSE,
    event_seed.created_at,
    event_seed.created_at
FROM workspace workspace_seed
JOIN users mentor ON mentor.email = 'instructor@devpath.com'
CROSS JOIN (
    VALUES
        ('라이브 코드 리뷰 세션', '쿠폰 발급 API, Redis 락 범위, ERD 관계선을 함께 리뷰합니다.', CURRENT_DATE + TIME '20:00:00', CURRENT_DATE + TIME '21:30:00', TIMESTAMP '2026-05-20 08:30:00'),
        ('3주차 과제 마감', 'Redis/Kafka 적용 브랜치와 부하 테스트 결과를 제출합니다.', CURRENT_DATE + 3 + TIME '23:59:00', CURRENT_DATE + 4 + TIME '00:10:00', TIMESTAMP '2026-05-20 08:40:00'),
        ('Redis/Kafka 피드백 미팅', '병목 지점과 이벤트 재처리 전략을 멘토와 점검합니다.', CURRENT_DATE + 5 + TIME '19:30:00', CURRENT_DATE + 5 + TIME '20:30:00', TIMESTAMP '2026-05-21 09:30:00')
) AS event_seed(title, description, start_at, end_at, created_at)
WHERE workspace_seed.name = '대용량 트래픽 처리를 위한 커머스 서버 구축'
  AND workspace_seed.type = 'MENTORING'
  AND NOT EXISTS (
      SELECT 1
      FROM calendar_event event
      WHERE event.workspace_id = workspace_seed.id
        AND event.title = event_seed.title
        AND event.is_deleted = FALSE
  );

INSERT INTO workspace_file (
    workspace_id,
    parent_id,
    original_file_name,
    stored_file_name,
    file_path,
    file_size,
    content_type,
    item_type,
    storage_provider,
    object_key,
    uploaded_by_id,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    workspace_seed.id,
    NULL,
    file_seed.original_file_name,
    file_seed.stored_file_name,
    file_seed.file_path,
    file_seed.file_size,
    file_seed.content_type,
    file_seed.item_type,
    'LOCAL',
    file_seed.object_key,
    uploader.user_id,
    FALSE,
    file_seed.created_at,
    file_seed.created_at
FROM workspace workspace_seed
JOIN (
    VALUES
        ('3주차_Redis_Kafka_과제_가이드.pdf', 'redis-kafka-week3-guide.pdf', '/files/mentoring/common-assignment/redis-kafka-week3-guide.pdf', 1843200, 'application/pdf', 'FILE', 'mentoring/common-assignment/redis-kafka-week3-guide.pdf', 'instructor@devpath.com', TIMESTAMP '2026-05-21 09:10:00'),
        ('ERD_초안_피드백.png', 'commerce-erd-feedback.png', '/files/mentoring/common-assignment/commerce-erd-feedback.png', 921600, 'image/png', 'FILE', 'mentoring/common-assignment/commerce-erd-feedback.png', 'instructor@devpath.com', TIMESTAMP '2026-05-22 13:40:00'),
        ('성능테스트_체크리스트.md', 'performance-test-checklist.md', '/files/mentoring/common-assignment/performance-test-checklist.md', 32768, 'text/markdown', 'FILE', 'mentoring/common-assignment/performance-test-checklist.md', 'frontend@devpath.com', TIMESTAMP '2026-05-23 18:20:00'),
        ('Redis 분산락 참고 링크', 'redis-lock-reference.url', 'https://redis.io/docs/latest/develop/use/patterns/distributed-locks/', 0, 'text/uri-list', 'LINK', 'https://redis.io/docs/latest/develop/use/patterns/distributed-locks/', 'instructor@devpath.com', TIMESTAMP '2026-05-24 10:00:00')
) AS file_seed(original_file_name, stored_file_name, file_path, file_size, content_type, item_type, object_key, uploader_email, created_at)
ON TRUE
JOIN users uploader ON uploader.email = file_seed.uploader_email
WHERE workspace_seed.name = '대용량 트래픽 처리를 위한 커머스 서버 구축'
  AND workspace_seed.type = 'MENTORING'
  AND NOT EXISTS (
      SELECT 1
      FROM workspace_file file
      WHERE file.workspace_id = workspace_seed.id
        AND file.original_file_name = file_seed.original_file_name
        AND file.is_deleted = FALSE
  );

INSERT INTO qna_questions (
    user_id,
    template_type,
    difficulty,
    title,
    content,
    adopted_answer_id,
    course_id,
    lesson_id,
    lecture_timestamp,
    question_scope,
    mentoring_id,
    workspace_id,
    qna_status,
    view_count,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    author.user_id,
    question_seed.template_type,
    question_seed.difficulty,
    question_seed.title,
    question_seed.content,
    NULL,
    NULL,
    NULL,
    NULL,
    'WORKSPACE',
    NULL,
    workspace_seed.id,
    question_seed.qna_status,
    question_seed.view_count,
    FALSE,
    question_seed.created_at,
    question_seed.updated_at
FROM workspace workspace_seed
JOIN (
    VALUES
        ('frontend@devpath.com', 'IMPLEMENTATION', 'HARD', 'Redis 쿠폰 중복 발급 테스트 방식 질문', '동시 요청이 들어올 때 같은 user_id가 같은 coupon_id를 두 번 받지 않는지 어떤 단위 테스트와 통합 테스트로 나누면 좋을까요?', 'ANSWERED', 18, TIMESTAMP '2026-05-22 19:30:00', TIMESTAMP '2026-05-23 09:30:00'),
        ('learner@devpath.com', 'STUDY', 'MEDIUM', 'Kafka 파티션 개수 산정 기준 문의', '주문 이벤트 토픽을 만들 때 초기 파티션 개수를 트래픽 기준으로 어떻게 잡아야 하는지 궁금합니다.', 'UNANSWERED', 9, TIMESTAMP '2026-05-23 20:10:00', TIMESTAMP '2026-05-23 20:10:00'),
        ('frontend@devpath.com', 'PROJECT', 'MEDIUM', 'JMeter 결과에서 병목 지점 해석 질문', '평균 응답 시간은 안정적인데 p95가 튀는 경우 Redis 락 대기와 DB 커넥션 풀 중 어디를 먼저 의심해야 하나요?', 'UNANSWERED', 7, TIMESTAMP '2026-05-24 16:20:00', TIMESTAMP '2026-05-24 16:20:00')
) AS question_seed(author_email, template_type, difficulty, title, content, qna_status, view_count, created_at, updated_at)
ON TRUE
JOIN users author ON author.email = question_seed.author_email
WHERE workspace_seed.name = '대용량 트래픽 처리를 위한 커머스 서버 구축'
  AND workspace_seed.type = 'MENTORING'
  AND NOT EXISTS (
      SELECT 1
      FROM qna_questions question
      WHERE question.workspace_id = workspace_seed.id
        AND question.title = question_seed.title
        AND question.is_deleted = FALSE
  );

INSERT INTO qna_answers (
    question_id,
    user_id,
    content,
    is_adopted,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    question.question_id,
    mentor.user_id,
    '단위 테스트는 Redis 키 생성과 만료 정책을 분리해서 검증하고, 통합 테스트는 Testcontainers Redis 위에서 CountDownLatch로 동시 요청을 만들어 보세요. 최종 검증은 coupon_issue에 user_id, coupon_id 유니크 제약을 두고 DB 레벨까지 확인하는 흐름이 좋습니다.',
    TRUE,
    FALSE,
    TIMESTAMP '2026-05-23 09:30:00',
    TIMESTAMP '2026-05-23 09:30:00'
FROM qna_questions question
JOIN workspace workspace_seed ON workspace_seed.id = question.workspace_id
JOIN users mentor ON mentor.email = 'instructor@devpath.com'
WHERE workspace_seed.name = '대용량 트래픽 처리를 위한 커머스 서버 구축'
  AND question.title = 'Redis 쿠폰 중복 발급 테스트 방식 질문'
  AND NOT EXISTS (
      SELECT 1
      FROM qna_answers answer
      WHERE answer.question_id = question.question_id
        AND answer.user_id = mentor.user_id
        AND answer.is_deleted = FALSE
  );

UPDATE qna_questions question
SET adopted_answer_id = (
        SELECT MAX(answer.answer_id)
        FROM qna_answers answer
        WHERE answer.question_id = question.question_id
    ),
    qna_status = 'ANSWERED',
    updated_at = (
        SELECT MAX(answer.created_at)
        FROM qna_answers answer
        WHERE answer.question_id = question.question_id
    )
WHERE EXISTS (
      SELECT 1
      FROM workspace workspace_seed
      WHERE workspace_seed.id = question.workspace_id
        AND workspace_seed.name = '대용량 트래픽 처리를 위한 커머스 서버 구축'
  )
  AND question.title = 'Redis 쿠폰 중복 발급 테스트 방식 질문'
  AND question.adopted_answer_id IS NULL
  AND EXISTS (
      SELECT 1
      FROM qna_answers answer
      WHERE answer.question_id = question.question_id
  );

INSERT INTO meeting_note (
    workspace_id,
    title,
    content,
    created_by_id,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    workspace_seed.id,
    note_seed.title,
    note_seed.content,
    author.user_id,
    FALSE,
    note_seed.created_at,
    note_seed.created_at
FROM workspace workspace_seed
JOIN (
    VALUES
        ('2주차 라이브 멘토링 회의록', E'- 쿠폰 발급 API는 요청 검증, 재고 차감, 발급 기록 저장을 분리한다.\n- Redis 락은 쿠폰 단위로 잡고 DB 유니크 제약을 마지막 안전장치로 둔다.\n- Kafka 이벤트는 주문 생성 후 비동기 알림과 통계 집계에 사용한다.', 'instructor@devpath.com', TIMESTAMP '2026-05-16 21:10:00'),
        ('Redis 설계 리뷰 요약', E'락 키는 coupon:{couponId}:issue 형태로 통일합니다.\nTTL은 API 타임아웃보다 조금 길게 두고, 실패 시 재시도보다 명확한 실패 응답을 먼저 반환합니다.', 'frontend@devpath.com', TIMESTAMP '2026-05-23 21:00:00')
) AS note_seed(title, content, author_email, created_at)
ON TRUE
JOIN users author ON author.email = note_seed.author_email
WHERE workspace_seed.name = '대용량 트래픽 처리를 위한 커머스 서버 구축'
  AND workspace_seed.type = 'MENTORING'
  AND NOT EXISTS (
      SELECT 1
      FROM meeting_note note
      WHERE note.workspace_id = workspace_seed.id
        AND note.title = note_seed.title
        AND note.is_deleted = FALSE
  );

INSERT INTO workspace_erd_documents (
    workspace_id,
    mermaid_code,
    schema_json,
    version,
    updated_by_id,
    created_at,
    updated_at
)
SELECT
    workspace_seed.id,
    E'erDiagram\n    USERS ||--o{ ORDERS : places\n    USERS ||--o{ COUPON_ISSUES : receives\n    PRODUCTS ||--o{ ORDER_ITEMS : included\n    ORDERS ||--|{ ORDER_ITEMS : contains\n    COUPONS ||--o{ COUPON_ISSUES : issued\n    USERS {\n        BIGINT id PK\n        VARCHAR email\n        VARCHAR name\n    }\n    PRODUCTS {\n        BIGINT id PK\n        VARCHAR name\n        INT stock\n    }\n    ORDERS {\n        BIGINT id PK\n        BIGINT user_id FK\n        VARCHAR status\n    }\n    ORDER_ITEMS {\n        BIGINT id PK\n        BIGINT order_id FK\n        BIGINT product_id FK\n        INT quantity\n    }\n    COUPONS {\n        BIGINT id PK\n        VARCHAR name\n        INT total_quantity\n    }\n    COUPON_ISSUES {\n        BIGINT id PK\n        BIGINT coupon_id FK\n        BIGINT user_id FK\n        TIMESTAMP issued_at\n    }',
    $${
      "tables": [
        {"name":"USERS","x":150,"y":150,"columns":[{"name":"id","type":"BIGINT","key":"PK"},{"name":"email","type":"VARCHAR"},{"name":"name","type":"VARCHAR"}]},
        {"name":"ORDERS","x":550,"y":150,"columns":[{"name":"id","type":"BIGINT","key":"PK"},{"name":"user_id","type":"BIGINT","key":"FK"},{"name":"status","type":"VARCHAR"},{"name":"created_at","type":"TIMESTAMP"}]},
        {"name":"PRODUCTS","x":150,"y":390,"columns":[{"name":"id","type":"BIGINT","key":"PK"},{"name":"name","type":"VARCHAR"},{"name":"stock","type":"INT"}]},
        {"name":"ORDER_ITEMS","x":550,"y":390,"columns":[{"name":"id","type":"BIGINT","key":"PK"},{"name":"order_id","type":"BIGINT","key":"FK"},{"name":"product_id","type":"BIGINT","key":"FK"},{"name":"quantity","type":"INT"}]},
        {"name":"COUPONS","x":910,"y":170,"columns":[{"name":"id","type":"BIGINT","key":"PK"},{"name":"name","type":"VARCHAR"},{"name":"total_quantity","type":"INT"},{"name":"issued_count","type":"INT"}]},
        {"name":"COUPON_ISSUES","x":910,"y":430,"columns":[{"name":"id","type":"BIGINT","key":"PK"},{"name":"coupon_id","type":"BIGINT","key":"FK"},{"name":"user_id","type":"BIGINT","key":"FK"},{"name":"issued_at","type":"TIMESTAMP"}]}
      ],
      "relationships": [
        {"from":"USERS","to":"ORDERS","type":"1:N","label":"places"},
        {"from":"ORDERS","to":"ORDER_ITEMS","type":"1:N","label":"contains"},
        {"from":"PRODUCTS","to":"ORDER_ITEMS","type":"1:N","label":"included"},
        {"from":"COUPONS","to":"COUPON_ISSUES","type":"1:N","label":"issued"},
        {"from":"USERS","to":"COUPON_ISSUES","type":"1:N","label":"receives"}
      ]
    }$$,
    3,
    mentor.user_id,
    TIMESTAMP '2026-05-18 12:00:00',
    TIMESTAMP '2026-05-24 17:30:00'
FROM workspace workspace_seed
JOIN users mentor ON mentor.email = 'instructor@devpath.com'
WHERE workspace_seed.name = '대용량 트래픽 처리를 위한 커머스 서버 구축'
  AND workspace_seed.type = 'MENTORING'
ON CONFLICT (workspace_id) DO UPDATE
SET mermaid_code = EXCLUDED.mermaid_code,
    schema_json = EXCLUDED.schema_json,
    version = EXCLUDED.version,
    updated_by_id = EXCLUDED.updated_by_id,
    updated_at = EXCLUDED.updated_at;

INSERT INTO workspace_erd_versions (
    workspace_id,
    version,
    mermaid_code,
    schema_json,
    summary,
    updated_by_id,
    discussion_message_id,
    created_at
)
SELECT
    workspace_seed.id,
    version_seed.version,
    document_seed.mermaid_code,
    document_seed.schema_json,
    version_seed.summary,
    mentor.user_id,
    NULL,
    version_seed.created_at
FROM workspace workspace_seed
JOIN users mentor ON mentor.email = 'instructor@devpath.com'
JOIN workspace_erd_documents document_seed ON document_seed.workspace_id = workspace_seed.id
JOIN (
    VALUES
        (1, '초기 회원, 주문, 상품 테이블 초안 작성', TIMESTAMP '2026-05-18 12:00:00'),
        (2, '쿠폰 발급 테이블과 사용자 관계 추가', TIMESTAMP '2026-05-21 15:30:00'),
        (3, '주문 아이템 관계선과 Redis 중복 발급 검증 컬럼 정리', TIMESTAMP '2026-05-24 17:30:00')
) AS version_seed(version, summary, created_at)
ON TRUE
WHERE workspace_seed.name = '대용량 트래픽 처리를 위한 커머스 서버 구축'
  AND workspace_seed.type = 'MENTORING'
  AND NOT EXISTS (
      SELECT 1
      FROM workspace_erd_versions version
      WHERE version.workspace_id = workspace_seed.id
        AND version.version = version_seed.version
  );

INSERT INTO workspace_erd_comments (
    workspace_id,
    target_type,
    target_id,
    target_label,
    author_id,
    body,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    workspace_seed.id,
    comment_seed.target_type,
    comment_seed.target_id,
    comment_seed.target_label,
    author.user_id,
    comment_seed.body,
    FALSE,
    comment_seed.created_at,
    comment_seed.created_at
FROM workspace workspace_seed
JOIN (
    VALUES
        ('TABLE', 'COUPON_ISSUES', 'COUPON_ISSUES', 'coupon_id와 user_id 조합에 유니크 제약을 추가하면 중복 발급 방어가 명확해집니다.', 'instructor@devpath.com', TIMESTAMP '2026-05-22 11:00:00'),
        ('COLUMN', 'ORDERS.status', 'ORDERS.status', '상태 값은 enum 후보를 문서에 남기고 결제 실패 흐름까지 포함해 주세요.', 'frontend@devpath.com', TIMESTAMP '2026-05-24 18:00:00')
) AS comment_seed(target_type, target_id, target_label, body, author_email, created_at)
ON TRUE
JOIN users author ON author.email = comment_seed.author_email
WHERE workspace_seed.name = '대용량 트래픽 처리를 위한 커머스 서버 구축'
  AND workspace_seed.type = 'MENTORING'
  AND NOT EXISTS (
      SELECT 1
      FROM workspace_erd_comments comment
      WHERE comment.workspace_id = workspace_seed.id
        AND comment.target_id = comment_seed.target_id
        AND comment.body = comment_seed.body
        AND comment.is_deleted = FALSE
  );

INSERT INTO voice_channels (
    workspace_id,
    creator_id,
    name,
    description,
    current_session_started_at,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    workspace_seed.id,
    mentor.user_id,
    '목요 라이브 멘토링 룸',
    '3주차 Kafka 파티션 분배 전략과 Redis 쿠폰 발급 로직을 리뷰하는 라이브 룸입니다.',
    CURRENT_DATE + TIME '20:00:00',
    FALSE,
    TIMESTAMP '2026-05-20 12:00:00',
    TIMESTAMP '2026-05-24 19:50:00'
FROM workspace workspace_seed
JOIN users mentor ON mentor.email = 'instructor@devpath.com'
WHERE workspace_seed.name = '대용량 트래픽 처리를 위한 커머스 서버 구축'
  AND workspace_seed.type = 'MENTORING'
  AND NOT EXISTS (
      SELECT 1
      FROM voice_channels channel
      WHERE channel.workspace_id = workspace_seed.id
        AND channel.name = '목요 라이브 멘토링 룸'
        AND channel.is_deleted = FALSE
  );

INSERT INTO voice_participants (
    voice_channel_id,
    user_id,
    active,
    muted,
    hand_raised,
    speaking,
    joined_at,
    left_at,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    channel.voice_channel_id,
    participant_user.user_id,
    TRUE,
    participant_seed.muted,
    participant_seed.hand_raised,
    participant_seed.speaking,
    CURRENT_DATE + participant_seed.joined_time,
    NULL,
    FALSE,
    CURRENT_DATE + participant_seed.joined_time,
    CURRENT_DATE + participant_seed.joined_time
FROM voice_channels channel
JOIN workspace workspace_seed ON workspace_seed.id = channel.workspace_id
JOIN (
    VALUES
        ('instructor@devpath.com', FALSE, FALSE, TRUE, TIME '19:58:00'),
        ('frontend@devpath.com', TRUE, FALSE, FALSE, TIME '20:01:00'),
        ('learner@devpath.com', FALSE, TRUE, FALSE, TIME '20:02:00')
) AS participant_seed(email, muted, hand_raised, speaking, joined_time)
ON TRUE
JOIN users participant_user ON participant_user.email = participant_seed.email
WHERE workspace_seed.name = '대용량 트래픽 처리를 위한 커머스 서버 구축'
  AND channel.name = '목요 라이브 멘토링 룸'
  AND NOT EXISTS (
      SELECT 1
      FROM voice_participants participant
      WHERE participant.voice_channel_id = channel.voice_channel_id
        AND participant.user_id = participant_user.user_id
        AND participant.is_deleted = FALSE
  );

INSERT INTO voice_chat_messages (
    voice_channel_id,
    sender_id,
    content,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    channel.voice_channel_id,
    sender.user_id,
    chat_seed.content,
    FALSE,
    CURRENT_DATE + chat_seed.sent_time,
    CURRENT_DATE + chat_seed.sent_time
FROM voice_channels channel
JOIN workspace workspace_seed ON workspace_seed.id = channel.workspace_id
JOIN (
    VALUES
        ('instructor@devpath.com', '오늘은 coupon_issue 유니크 제약과 Kafka 파티션 키를 먼저 봅니다.', TIME '20:05:00'),
        ('frontend@devpath.com', 'JMeter 결과에서 p95가 튄 부분을 같이 확인 부탁드립니다.', TIME '20:07:00'),
        ('learner@devpath.com', 'Redis 락 TTL을 API 타임아웃보다 길게 두는 이유가 궁금합니다.', TIME '20:09:00')
) AS chat_seed(sender_email, content, sent_time)
ON TRUE
JOIN users sender ON sender.email = chat_seed.sender_email
WHERE workspace_seed.name = '대용량 트래픽 처리를 위한 커머스 서버 구축'
  AND channel.name = '목요 라이브 멘토링 룸'
  AND NOT EXISTS (
      SELECT 1
      FROM voice_chat_messages message
      WHERE message.voice_channel_id = channel.voice_channel_id
        AND message.sender_id = sender.user_id
        AND message.content = chat_seed.content
        AND message.is_deleted = FALSE
  );

INSERT INTO voice_meeting_minutes (
    voice_channel_id,
    updated_by_user_id,
    recording,
    transcript,
    summary,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    channel.voice_channel_id,
    mentor.user_id,
    TRUE,
    E'멘토: 오늘은 쿠폰 발급의 중복 방어와 Kafka 이벤트 흐름을 봅니다.\n멘티: p95 응답 시간이 튀는 구간은 Redis 락 대기와 DB 커넥션을 함께 확인하겠습니다.',
    '쿠폰 발급 API는 DB 유니크 제약과 Redis 락을 함께 사용하고, 주문 이벤트는 user_id보다 order_id 기반 파티션 키를 우선 검토하기로 했습니다.',
    FALSE,
    CURRENT_DATE + TIME '20:12:00',
    CURRENT_DATE + TIME '20:12:00'
FROM voice_channels channel
JOIN workspace workspace_seed ON workspace_seed.id = channel.workspace_id
JOIN users mentor ON mentor.email = 'instructor@devpath.com'
WHERE workspace_seed.name = '대용량 트래픽 처리를 위한 커머스 서버 구축'
  AND channel.name = '목요 라이브 멘토링 룸'
  AND NOT EXISTS (
      SELECT 1
      FROM voice_meeting_minutes minutes
      WHERE minutes.voice_channel_id = channel.voice_channel_id
        AND minutes.is_deleted = FALSE
  );

SELECT setval(pg_get_serial_sequence('mentoring_posts', 'mentoring_post_id'), COALESCE((SELECT MAX(mentoring_post_id) FROM mentoring_posts), 1));
SELECT setval(pg_get_serial_sequence('mentoring_applications', 'mentoring_application_id'), COALESCE((SELECT MAX(mentoring_application_id) FROM mentoring_applications), 1));
SELECT setval(pg_get_serial_sequence('mentorings', 'mentoring_id'), COALESCE((SELECT MAX(mentoring_id) FROM mentorings), 1));
SELECT setval(pg_get_serial_sequence('workspace', 'id'), COALESCE((SELECT MAX(id) FROM workspace), 1));
SELECT setval(pg_get_serial_sequence('workspace_member', 'id'), COALESCE((SELECT MAX(id) FROM workspace_member), 1));
SELECT setval(pg_get_serial_sequence('workspace_notice', 'id'), COALESCE((SELECT MAX(id) FROM workspace_notice), 1));
SELECT setval(pg_get_serial_sequence('workspace_task', 'id'), COALESCE((SELECT MAX(id) FROM workspace_task), 1));
SELECT setval(pg_get_serial_sequence('calendar_event', 'id'), COALESCE((SELECT MAX(id) FROM calendar_event), 1));
SELECT setval(pg_get_serial_sequence('workspace_file', 'id'), COALESCE((SELECT MAX(id) FROM workspace_file), 1));
SELECT setval(pg_get_serial_sequence('qna_questions', 'question_id'), COALESCE((SELECT MAX(question_id) FROM qna_questions), 1));
SELECT setval(pg_get_serial_sequence('qna_answers', 'answer_id'), COALESCE((SELECT MAX(answer_id) FROM qna_answers), 1));
SELECT setval(pg_get_serial_sequence('meeting_note', 'id'), COALESCE((SELECT MAX(id) FROM meeting_note), 1));
SELECT setval(pg_get_serial_sequence('workspace_erd_versions', 'version_id'), COALESCE((SELECT MAX(version_id) FROM workspace_erd_versions), 1));
SELECT setval(pg_get_serial_sequence('workspace_erd_comments', 'comment_id'), COALESCE((SELECT MAX(comment_id) FROM workspace_erd_comments), 1));
SELECT setval(pg_get_serial_sequence('voice_channels', 'voice_channel_id'), COALESCE((SELECT MAX(voice_channel_id) FROM voice_channels), 1));
SELECT setval(pg_get_serial_sequence('voice_participants', 'voice_participant_id'), COALESCE((SELECT MAX(voice_participant_id) FROM voice_participants), 1));
SELECT setval(pg_get_serial_sequence('voice_chat_messages', 'voice_chat_message_id'), COALESCE((SELECT MAX(voice_chat_message_id) FROM voice_chat_messages), 1));
SELECT setval(pg_get_serial_sequence('voice_meeting_minutes', 'voice_meeting_minutes_id'), COALESCE((SELECT MAX(voice_meeting_minutes_id) FROM voice_meeting_minutes), 1));

INSERT INTO quiz_attempts (
    quiz_id, learner_id, score, max_score, started_at, completed_at,
    time_spent_seconds, is_passed, attempt_number, is_deleted, created_at, updated_at
)
WITH frontend_quiz_attempt_seed(
    learner_email, course_title, score, max_score, started_at,
    completed_at, time_spent_seconds, is_passed, attempt_number
) AS (
    VALUES
        ('learner@devpath.com', 'React 19 프론트엔드 실전 가이드', 55, 100, TIMESTAMP '2026-04-06 19:00:00', TIMESTAMP '2026-04-06 19:08:00', 480, FALSE, 1),
        ('learner2@devpath.com', 'React 19 프론트엔드 실전 가이드', 92, 100, TIMESTAMP '2026-04-13 20:00:00', TIMESTAMP '2026-04-13 20:06:00', 360, TRUE, 1),
        ('learner3@devpath.com', 'React 19 프론트엔드 실전 가이드', 68, 100, TIMESTAMP '2026-04-07 20:00:00', TIMESTAMP '2026-04-07 20:09:00', 540, FALSE, 1),
        ('learner2@devpath.com', 'Next.js 14 제품 개발 실전', 74, 100, TIMESTAMP '2026-04-09 19:00:00', TIMESTAMP '2026-04-09 19:08:00', 500, TRUE, 1),
        ('learner3@devpath.com', 'Next.js 14 제품 개발 실전', 88, 100, TIMESTAMP '2026-04-15 21:00:00', TIMESTAMP '2026-04-15 21:07:00', 420, TRUE, 1),
        ('learner3@devpath.com', 'Flutter로 MVP 앱 출시하기', 48, 100, TIMESTAMP '2026-04-08 23:00:00', TIMESTAMP '2026-04-08 23:10:00', 600, FALSE, 1),
        ('learner4@devpath.com', 'Flutter로 MVP 앱 출시하기', 95, 100, TIMESTAMP '2026-04-14 20:00:00', TIMESTAMP '2026-04-14 20:06:00', 360, TRUE, 1)
)
SELECT
    q.quiz_id,
    u.user_id,
    seed.score,
    seed.max_score,
    seed.started_at,
    seed.completed_at,
    seed.time_spent_seconds,
    seed.is_passed,
    seed.attempt_number,
    FALSE,
    seed.started_at,
    seed.completed_at
FROM frontend_quiz_attempt_seed seed
JOIN users u ON u.email = seed.learner_email
JOIN roadmap_nodes rn ON rn.sub_topics = seed.course_title
                   AND rn.node_type = 'QUIZ'
                   AND rn.title LIKE '[CATALOG]%'
JOIN quizzes q ON q.node_id = rn.node_id
WHERE NOT EXISTS (
    SELECT 1
    FROM quiz_attempts qa
    WHERE qa.quiz_id = q.quiz_id
      AND qa.learner_id = u.user_id
      AND qa.attempt_number = seed.attempt_number
      AND qa.is_deleted = FALSE
);

INSERT INTO assignment_submissions (
    assignment_id, learner_id, grader_id, submission_text, submission_url,
    is_late, submission_status, submitted_at, graded_at,
    readme_passed, test_passed, lint_passed, file_format_passed,
    quality_score, total_score, individual_feedback, common_feedback,
    is_deleted, created_at, updated_at
)
WITH frontend_submission_seed(
    learner_email, course_title, submission_text, submission_url,
    is_late, submission_status, submitted_at, graded_at,
    readme_passed, test_passed, lint_passed, file_format_passed,
    quality_score, total_score, individual_feedback, common_feedback
) AS (
    VALUES
        ('learner2@devpath.com', 'React 19 프론트엔드 실전 가이드', '대시보드 필터와 Playwright 흐름을 제출했습니다.', 'https://github.com/devpath/frontend-react-dashboard-a', FALSE, 'GRADED', TIMESTAMP '2026-04-14 20:00:00', TIMESTAMP '2026-04-15 10:00:00', TRUE, TRUE, TRUE, TRUE, 91, 88, '테스트 흐름이 안정적입니다.', '프론트엔드 실습 과제 피드백'),
        ('learner3@devpath.com', 'React 19 프론트엔드 실전 가이드', '상태 배치와 Tailwind 스타일링 결과를 정리했습니다.', 'https://github.com/devpath/frontend-react-dashboard-b', FALSE, 'GRADED', TIMESTAMP '2026-04-08 20:00:00', TIMESTAMP '2026-04-09 11:00:00', TRUE, FALSE, TRUE, TRUE, 62, 58, '폼 오류 케이스 테스트가 부족합니다.', '프론트엔드 실습 과제 피드백'),
        ('learner3@devpath.com', 'Next.js 14 제품 개발 실전', '예약 상세 페이지와 SEO 점검표를 제출했습니다.', 'https://github.com/devpath/frontend-next-product-a', FALSE, 'GRADED', TIMESTAMP '2026-04-16 20:00:00', TIMESTAMP '2026-04-16 22:00:00', TRUE, TRUE, TRUE, TRUE, 89, 86, '캐싱 기준 설명이 좋습니다.', 'Next.js 제품 실습 과제 피드백'),
        ('learner2@devpath.com', 'Next.js 14 제품 개발 실전', '인증 처리와 이미지 최적화 내용을 제출했습니다.', 'https://github.com/devpath/frontend-next-product-b', TRUE, 'GRADED', TIMESTAMP '2026-04-10 20:00:00', TIMESTAMP '2026-04-11 10:00:00', TRUE, TRUE, FALSE, TRUE, 71, 64, '메타데이터 누락 항목을 보강해야 합니다.', 'Next.js 제품 실습 과제 피드백'),
        ('learner4@devpath.com', 'Flutter로 MVP 앱 출시하기', '스토어 제출용 MVP 화면과 빌드 체크리스트입니다.', 'https://github.com/devpath/frontend-flutter-mvp-a', FALSE, 'GRADED', TIMESTAMP '2026-04-15 18:00:00', TIMESTAMP '2026-04-16 09:30:00', TRUE, TRUE, TRUE, TRUE, 94, 92, '권한 설명과 빌드 문서가 명확합니다.', 'Flutter MVP 실습 과제 피드백'),
        ('learner3@devpath.com', 'Flutter로 MVP 앱 출시하기', '가입 화면 폼 검증과 API 실패 처리까지 제출했습니다.', 'https://github.com/devpath/frontend-flutter-mvp-b', FALSE, 'GRADED', TIMESTAMP '2026-04-09 22:00:00', TIMESTAMP '2026-04-10 12:00:00', TRUE, FALSE, TRUE, TRUE, 66, 61, '에러 상태 화면을 더 분리하면 좋습니다.', 'Flutter MVP 실습 과제 피드백')
)
SELECT
    a.assignment_id,
    lu.user_id,
    iu.user_id,
    seed.submission_text,
    seed.submission_url,
    seed.is_late,
    seed.submission_status,
    seed.submitted_at,
    seed.graded_at,
    seed.readme_passed,
    seed.test_passed,
    seed.lint_passed,
    seed.file_format_passed,
    seed.quality_score,
    seed.total_score,
    seed.individual_feedback,
    seed.common_feedback,
    FALSE,
    seed.submitted_at,
    seed.graded_at
FROM frontend_submission_seed seed
JOIN users lu ON lu.email = seed.learner_email
JOIN users iu ON iu.email = 'frontend@devpath.com'
JOIN roadmap_nodes rn ON rn.sub_topics = seed.course_title
                   AND rn.node_type = 'ASSIGNMENT'
                   AND rn.title LIKE '[CATALOG]%'
JOIN assignments a ON a.node_id = rn.node_id
WHERE NOT EXISTS (
    SELECT 1
    FROM assignment_submissions s
    WHERE s.assignment_id = a.assignment_id
      AND s.learner_id = lu.user_id
      AND s.submission_url = seed.submission_url
      AND s.is_deleted = FALSE
);

INSERT INTO qna_questions (
    user_id, template_type, difficulty, title, content,
    adopted_answer_id, course_id, lecture_timestamp,
    qna_status, view_count, is_deleted, created_at, updated_at
)
WITH frontend_qna_seed(
    learner_email, course_title, template_type, difficulty,
    title, content, lecture_timestamp, view_count, created_at
) AS (
    VALUES
        ('learner@devpath.com', 'React 19 프론트엔드 실전 가이드', 'IMPLEMENTATION', 'MEDIUM', 'Actions와 폼 처리에서 낙관적 업데이트 롤백은 어디에 두나요?', '폼 제출 실패 시 서버 에러 메시지와 로컬 상태를 함께 되돌리는 위치가 헷갈립니다.', '00:12:40', 18, TIMESTAMP '2026-04-14 09:20:00'),
        ('learner2@devpath.com', 'React 19 프론트엔드 실전 가이드', 'DEBUGGING', 'HARD', 'Playwright 로그인 플로우 테스트가 CI에서만 실패합니다', '로컬에서는 통과하는데 CI에서 세션 쿠키가 유지되지 않아 다음 화면으로 넘어가지 않습니다.', '00:31:10', 24, TIMESTAMP '2026-04-15 13:10:00'),
        ('learner3@devpath.com', 'React 19 프론트엔드 실전 가이드', 'STUDY', 'EASY', 'Tailwind 유틸리티가 길어질 때 컴포넌트를 어떻게 나누면 좋을까요?', '버튼과 카드에 클래스가 많아졌을 때 어느 기준으로 컴포넌트를 분리해야 하는지 궁금합니다.', '00:18:05', 11, TIMESTAMP '2026-04-16 10:30:00'),
        ('learner4@devpath.com', 'React 19 프론트엔드 실전 가이드', 'CODE_REVIEW', 'MEDIUM', '대시보드 카드 컴포넌트 분리 기준을 봐주세요', '필터 카드와 통계 카드가 props 구조는 비슷한데 스타일이 달라서 같은 컴포넌트로 묶어도 되는지 고민됩니다.', '00:44:20', 7, TIMESTAMP '2026-04-13 18:45:00'),
        ('learner@devpath.com', 'Next.js 14 제품 개발 실전', 'IMPLEMENTATION', 'MEDIUM', '서버 컴포넌트에서 쿠키 기반 인증을 읽는 위치가 궁금합니다', 'layout에서 세션을 읽는 방식과 page 단위로 읽는 방식 중 어떤 기준으로 나누는지 알고 싶습니다.', '00:16:25', 16, TIMESTAMP '2026-04-14 11:40:00'),
        ('learner2@devpath.com', 'Next.js 14 제품 개발 실전', 'STUDY', 'MEDIUM', 'revalidatePath와 router.refresh를 언제 구분해서 쓰나요?', '서버 액션 이후 목록을 갱신할 때 두 방법을 같이 써야 하는지 기준이 애매합니다.', '00:27:50', 21, TIMESTAMP '2026-04-15 16:20:00'),
        ('learner3@devpath.com', 'Next.js 14 제품 개발 실전', 'DEBUGGING', 'HARD', '이미지 최적화 후 LCP가 오히려 느려졌습니다', 'next/image로 바꾼 뒤 첫 화면 이미지가 늦게 표시됩니다. priority와 sizes 설정 기준을 알고 싶습니다.', '00:39:15', 29, TIMESTAMP '2026-04-16 14:00:00'),
        ('learner4@devpath.com', 'Next.js 14 제품 개발 실전', 'PROJECT', 'MEDIUM', '메타데이터 템플릿을 여러 상세 페이지에 공통 적용하고 싶습니다', '제품 상세, 검색 결과, 프로필 페이지에서 title 규칙을 재사용하려면 어느 레이어에 두는 게 좋을까요?', '00:48:30', 9, TIMESTAMP '2026-04-12 20:10:00'),
        ('learner@devpath.com', 'Flutter로 MVP 앱 출시하기', 'STUDY', 'EASY', '상태 관리에서 Riverpod을 꼭 써야 하나요?', '작은 MVP 앱에서도 기본 StatefulWidget만 쓰면 나중에 유지보수가 어려워지는지 궁금합니다.', '00:10:45', 13, TIMESTAMP '2026-04-16 09:10:00'),
        ('learner2@devpath.com', 'Flutter로 MVP 앱 출시하기', 'DEBUGGING', 'MEDIUM', 'Android 빌드에서 권한 안내 문구가 반영되지 않습니다', 'AndroidManifest와 store 설명 문구를 수정했는데 빌드 결과에서 이전 문구가 계속 보입니다.', '00:42:10', 17, TIMESTAMP '2026-04-15 19:20:00'),
        ('learner3@devpath.com', 'Flutter로 MVP 앱 출시하기', 'IMPLEMENTATION', 'MEDIUM', '폼 검증 에러 메시지를 화면마다 재사용하고 싶습니다', '가입, 로그인, 문의 화면에서 같은 검증 규칙을 쓰는데 위젯 분리와 함수 분리 중 어떤 방식이 좋을까요?', '00:21:55', 10, TIMESTAMP '2026-04-14 22:35:00'),
        ('learner4@devpath.com', 'Flutter로 MVP 앱 출시하기', 'PROJECT', 'EASY', '스토어 제출용 권한 설명 문구를 어디서 관리하나요?', '카메라와 파일 접근 권한 설명을 코드와 제출 문서에서 함께 관리하는 방법이 궁금합니다.', '00:55:00', 8, TIMESTAMP '2026-04-13 15:50:00')
)
SELECT
    u.user_id,
    seed.template_type,
    seed.difficulty,
    seed.title,
    seed.content,
    NULL,
    c.course_id,
    seed.lecture_timestamp,
    'UNANSWERED',
    seed.view_count,
    FALSE,
    seed.created_at,
    seed.created_at
FROM frontend_qna_seed seed
JOIN users u ON u.email = seed.learner_email
JOIN courses c ON c.title = seed.course_title
WHERE NOT EXISTS (
    SELECT 1
    FROM qna_questions q
    WHERE q.title = seed.title
      AND q.user_id = u.user_id
      AND q.course_id = c.course_id
);

UPDATE qna_questions q
SET lesson_id = first_lesson.lesson_id
FROM (
    SELECT ranked.course_id, ranked.lesson_id
    FROM (
        SELECT
            c.course_id,
            l.lesson_id,
            ROW_NUMBER() OVER (
                PARTITION BY c.course_id
                ORDER BY cs.sort_order, l.sort_order, l.lesson_id
            ) AS row_number
        FROM courses c
        JOIN course_sections cs ON cs.course_id = c.course_id
        JOIN lessons l ON l.section_id = cs.section_id
        WHERE COALESCE(cs.is_published, TRUE) = TRUE
          AND COALESCE(l.is_published, TRUE) = TRUE
          AND l.lesson_type = 'VIDEO'
    ) ranked
    WHERE ranked.row_number = 1
) first_lesson
WHERE q.course_id = first_lesson.course_id
  AND q.lesson_id IS NULL
  AND q.lecture_timestamp IS NOT NULL;

INSERT INTO review (
    course_id, learner_id, rating, content, status,
    is_hidden, is_deleted, issue_tags_raw, created_at, updated_at
)
WITH frontend_review_seed(
    learner_email, course_title, rating, content,
    status, is_hidden, issue_tags_raw, created_at
) AS (
    VALUES
        ('learner@devpath.com', 'React 19 프론트엔드 실전 가이드', 5, '상태 위치를 판단하는 기준이 실제 화면 예제로 연결돼서 이해하기 쉬웠습니다.', 'UNANSWERED', FALSE, CAST(NULL AS TEXT), TIMESTAMP '2026-04-16 19:20:00'),
        ('learner2@devpath.com', 'React 19 프론트엔드 실전 가이드', 4, 'Playwright 실습은 좋았는데 예제 코드 버전이 영상과 조금 달라 확인이 필요합니다.', 'UNANSWERED', FALSE, '예제_코드_버전_차이,설명_보강_필요', TIMESTAMP '2026-04-15 21:10:00'),
        ('learner3@devpath.com', 'React 19 프론트엔드 실전 가이드', 3, 'Tailwind 설명 중 화면 캡처와 실제 클래스명이 다른 구간이 있었습니다.', 'UNANSWERED', FALSE, '화면_캡처_불일치', TIMESTAMP '2026-04-14 18:40:00'),
        ('learner4@devpath.com', 'React 19 프론트엔드 실전 가이드', 5, '대시보드 화면을 작은 단위로 나누는 기준이 실무에 바로 적용하기 좋았습니다.', 'UNANSWERED', FALSE, CAST(NULL AS TEXT), TIMESTAMP '2026-04-13 20:25:00'),
        ('learner@devpath.com', 'Next.js 14 제품 개발 실전', 4, '서버 컴포넌트와 캐시 흐름은 좋았고 이미지 최적화 설명이 조금 더 있으면 좋겠습니다.', 'UNANSWERED', FALSE, '이미지_최적화_설명_보강', TIMESTAMP '2026-04-16 12:30:00'),
        ('learner2@devpath.com', 'Next.js 14 제품 개발 실전', 5, 'App Router 기준으로 제품 화면을 끝까지 만드는 흐름이 잘 잡혀 있습니다.', 'UNANSWERED', FALSE, CAST(NULL AS TEXT), TIMESTAMP '2026-04-15 17:50:00'),
        ('learner3@devpath.com', 'Next.js 14 제품 개발 실전', 3, '자료 링크 하나가 열리지 않고 메타데이터 예제 파일 위치가 영상과 달랐습니다.', 'UNANSWERED', FALSE, '링크_오류,자료_업데이트_필요', TIMESTAMP '2026-04-14 23:15:00'),
        ('learner4@devpath.com', 'Next.js 14 제품 개발 실전', 4, '인증과 권한 처리 파트가 실습 중심이라 따라가기 좋았습니다.', 'UNANSWERED', FALSE, CAST(NULL AS TEXT), TIMESTAMP '2026-04-13 13:10:00'),
        ('learner@devpath.com', 'Flutter로 MVP 앱 출시하기', 4, 'MVP 출시 체크리스트가 도움이 됐고 권한 설명 문구 예시가 더 있으면 좋겠습니다.', 'UNANSWERED', FALSE, '앱_권한_설명_보강', TIMESTAMP '2026-04-16 08:40:00'),
        ('learner2@devpath.com', 'Flutter로 MVP 앱 출시하기', 5, '웹 개발자 입장에서 Flutter 앱 구조를 이해하기 쉽게 설명해줍니다.', 'UNANSWERED', FALSE, CAST(NULL AS TEXT), TIMESTAMP '2026-04-15 10:25:00'),
        ('learner3@devpath.com', 'Flutter로 MVP 앱 출시하기', 2, '빌드 환경 버전 차이 때문에 실습이 막혔고 오류 재현 순서가 더 필요합니다.', 'UNANSWERED', FALSE, '빌드_환경_버전_차이,오류_재현_필요', TIMESTAMP '2026-04-14 09:35:00'),
        ('learner4@devpath.com', 'Flutter로 MVP 앱 출시하기', 5, '위젯 분리와 폼 검증 흐름을 짧은 MVP 예제로 익히기 좋았습니다.', 'UNANSWERED', FALSE, CAST(NULL AS TEXT), TIMESTAMP '2026-04-13 19:00:00')
)
SELECT
    c.course_id,
    u.user_id,
    seed.rating,
    seed.content,
    seed.status,
    seed.is_hidden,
    FALSE,
    seed.issue_tags_raw,
    seed.created_at,
    seed.created_at
FROM frontend_review_seed seed
JOIN users u ON u.email = seed.learner_email
JOIN courses c ON c.title = seed.course_title
WHERE NOT EXISTS (
    SELECT 1
    FROM review r
    WHERE r.course_id = c.course_id
      AND r.learner_id = u.user_id
      AND r.is_deleted = FALSE
);

-- [CATALOG] frontend@devpath.com 정산 관리 데이터
INSERT INTO settlement (
    instructor_id, course_id, gross_amount, fee_amount, amount,
    status, is_deleted, purchased_at, settled_at, created_at
)
WITH frontend_settlement_seed(
    course_title, gross_amount, fee_amount, amount,
    status, purchased_at, settled_at, created_at
) AS (
    VALUES
        ('React 19 프론트엔드 실전 가이드', 79000, 15800, 63200, 'COMPLETED', TIMESTAMP '2026-01-08 10:20:00', TIMESTAMP '2026-01-15 11:00:00', TIMESTAMP '2026-01-15 11:00:00'),
        ('Next.js 14 제품 개발 실전', 99000, 19800, 79200, 'COMPLETED', TIMESTAMP '2026-01-18 15:35:00', TIMESTAMP '2026-01-25 10:30:00', TIMESTAMP '2026-01-25 10:30:00'),
        ('React 19 프론트엔드 실전 가이드', 79000, 15800, 63200, 'COMPLETED', TIMESTAMP '2026-02-06 09:40:00', TIMESTAMP '2026-02-13 14:00:00', TIMESTAMP '2026-02-13 14:00:00'),
        ('Flutter로 MVP 앱 출시하기', 69000, 13800, 55200, 'COMPLETED', TIMESTAMP '2026-02-16 20:10:00', TIMESTAMP '2026-02-23 13:20:00', TIMESTAMP '2026-02-23 13:20:00'),
        ('Next.js 14 제품 개발 실전', 99000, 19800, 79200, 'COMPLETED', TIMESTAMP '2026-03-04 11:15:00', TIMESTAMP '2026-03-11 16:10:00', TIMESTAMP '2026-03-11 16:10:00'),
        ('React 19 프론트엔드 실전 가이드', 79000, 15800, 63200, 'COMPLETED', TIMESTAMP '2026-03-19 18:25:00', TIMESTAMP '2026-03-26 10:45:00', TIMESTAMP '2026-03-26 10:45:00'),
        ('Flutter로 MVP 앱 출시하기', 69000, 13800, 55200, 'COMPLETED', TIMESTAMP '2026-04-04 12:30:00', TIMESTAMP '2026-04-11 11:30:00', TIMESTAMP '2026-04-11 11:30:00'),
        ('Next.js 14 제품 개발 실전', 99000, 19800, 79200, 'COMPLETED', TIMESTAMP '2026-04-10 09:15:00', TIMESTAMP '2026-04-16 17:30:00', TIMESTAMP '2026-04-16 17:30:00'),
        ('React 19 프론트엔드 실전 가이드', 79000, 15800, 63200, 'PENDING', TIMESTAMP '2026-04-15 13:20:00', CAST(NULL AS TIMESTAMP), TIMESTAMP '2026-04-15 13:20:00'),
        ('Next.js 14 제품 개발 실전', 99000, 19800, 79200, 'PENDING', TIMESTAMP '2026-04-16 10:05:00', CAST(NULL AS TIMESTAMP), TIMESTAMP '2026-04-16 10:05:00'),
        ('Flutter로 MVP 앱 출시하기', 69000, 13800, 55200, 'PENDING', TIMESTAMP '2026-04-16 17:30:00', CAST(NULL AS TIMESTAMP), TIMESTAMP '2026-04-16 17:30:00'),
        ('Next.js 14 제품 개발 실전', 99000, 19800, 79200, 'HELD', TIMESTAMP '2026-04-13 16:40:00', CAST(NULL AS TIMESTAMP), TIMESTAMP '2026-04-13 16:40:00'),
        ('React 19 프론트엔드 실전 가이드', 79000, 15800, 63200, 'HELD', TIMESTAMP '2026-04-14 19:05:00', CAST(NULL AS TIMESTAMP), TIMESTAMP '2026-04-14 19:05:00')
)
SELECT
    iu.user_id,
    c.course_id,
    seed.gross_amount,
    seed.fee_amount,
    seed.amount,
    seed.status,
    FALSE,
    seed.purchased_at,
    seed.settled_at,
    seed.created_at
FROM frontend_settlement_seed seed
JOIN users iu ON iu.email = 'frontend@devpath.com'
JOIN courses c ON c.title = seed.course_title
WHERE NOT EXISTS (
    SELECT 1
    FROM settlement s
    WHERE s.instructor_id = iu.user_id
      AND s.course_id = c.course_id
      AND s.purchased_at = seed.purchased_at
      AND s.gross_amount = seed.gross_amount
      AND s.is_deleted = FALSE
);

INSERT INTO settlement_hold (
    settlement_id, admin_id, reason, held_at
)
WITH frontend_settlement_hold_seed(
    course_title, purchased_at, reason, held_at
) AS (
    VALUES
        ('Next.js 14 제품 개발 실전', TIMESTAMP '2026-04-13 16:40:00', '환불 문의가 접수되어 정산 확인 중입니다.', TIMESTAMP '2026-04-14 09:30:00'),
        ('React 19 프론트엔드 실전 가이드', TIMESTAMP '2026-04-14 19:05:00', '결제 수단 확인이 필요해 일시 보류되었습니다.', TIMESTAMP '2026-04-15 10:15:00')
)
SELECT
    s.id,
    au.user_id,
    seed.reason,
    seed.held_at
FROM frontend_settlement_hold_seed seed
JOIN users iu ON iu.email = 'frontend@devpath.com'
JOIN users au ON au.email = 'admin@devpath.com'
JOIN courses c ON c.title = seed.course_title
JOIN settlement s ON s.instructor_id = iu.user_id
                 AND s.course_id = c.course_id
                 AND s.purchased_at = seed.purchased_at
                 AND s.status = 'HELD'
                 AND s.is_deleted = FALSE
WHERE NOT EXISTS (
    SELECT 1
    FROM settlement_hold sh
    WHERE sh.settlement_id = s.id
);

-- [CATALOG] 사용자 신고 접수 시드 데이터
INSERT INTO moderation_report (
    reporter_user_id,
    target_user_id,
    content_id,
    reason,
    status,
    action_taken,
    resolved_by,
    resolved_at,
    created_at
)
SELECT
    reporter.user_id,
    target.user_id,
    NULL,
    '프로젝트 채팅에서 반복적인 비방 메시지를 보냈습니다.',
    'PENDING',
    NULL,
    NULL,
    NULL,
    TIMESTAMP '2026-04-15 09:20:00'
FROM users reporter
JOIN users target ON target.email = 'learner3@devpath.com'
WHERE reporter.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM moderation_report mr
      WHERE mr.reporter_user_id = reporter.user_id
        AND mr.target_user_id = target.user_id
        AND mr.content_id IS NULL
        AND mr.reason = '프로젝트 채팅에서 반복적인 비방 메시지를 보냈습니다.'
  );

INSERT INTO moderation_report (
    reporter_user_id,
    target_user_id,
    content_id,
    reason,
    status,
    action_taken,
    resolved_by,
    resolved_at,
    created_at
)
SELECT
    reporter.user_id,
    author.user_id,
    r.id,
    '수강 후기 내용에 개인 연락처가 그대로 노출되어 있습니다.',
    'PENDING',
    NULL,
    NULL,
    NULL,
    TIMESTAMP '2026-04-15 14:10:00'
FROM users reporter
JOIN users author ON author.email = 'learner2@devpath.com'
JOIN courses c ON c.title = 'React 19 프론트엔드 실전 가이드'
JOIN review r ON r.course_id = c.course_id
             AND r.learner_id = author.user_id
             AND r.is_deleted = FALSE
WHERE reporter.email = 'learner3@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM moderation_report mr
      WHERE mr.reporter_user_id = reporter.user_id
        AND mr.content_id = r.id
        AND mr.reason = '수강 후기 내용에 개인 연락처가 그대로 노출되어 있습니다.'
  );

INSERT INTO moderation_report (
    reporter_user_id,
    target_user_id,
    content_id,
    reason,
    status,
    action_taken,
    resolved_by,
    resolved_at,
    created_at
)
SELECT
    reporter.user_id,
    author.user_id,
    r.id,
    '후기 문구가 강의와 무관한 외부 홍보성 내용으로 보입니다.',
    'PENDING',
    NULL,
    NULL,
    NULL,
    TIMESTAMP '2026-04-16 11:45:00'
FROM users reporter
JOIN users author ON author.email = 'learner3@devpath.com'
JOIN courses c ON c.title = 'Flutter로 MVP 앱 출시하기'
JOIN review r ON r.course_id = c.course_id
             AND r.learner_id = author.user_id
             AND r.is_deleted = FALSE
WHERE reporter.email = 'learner2@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM moderation_report mr
      WHERE mr.reporter_user_id = reporter.user_id
        AND mr.content_id = r.id
        AND mr.reason = '후기 문구가 강의와 무관한 외부 홍보성 내용으로 보입니다.'
  );

INSERT INTO moderation_report (
    reporter_user_id,
    target_user_id,
    content_id,
    reason,
    status,
    action_taken,
    resolved_by,
    resolved_at,
    created_at
)
SELECT
    reporter.user_id,
    target.user_id,
    NULL,
    '프로필 소개에 외부 연락처 유도가 반복되어 관리자 검토 후 경고 처리했습니다.',
    'RESOLVED',
    'WARNING',
    admin_user.user_id,
    TIMESTAMP '2026-04-14 18:20:00',
    TIMESTAMP '2026-04-14 12:00:00'
FROM users reporter
JOIN users target ON target.email = 'frontend@devpath.com'
JOIN users admin_user ON admin_user.email = 'admin@devpath.com'
WHERE reporter.email = 'learner3@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM moderation_report mr
      WHERE mr.reporter_user_id = reporter.user_id
        AND mr.target_user_id = target.user_id
        AND mr.content_id IS NULL
        AND mr.reason = '프로필 소개에 외부 연락처 유도가 반복되어 관리자 검토 후 경고 처리했습니다.'
  );
-- ============================================================
-- 로드맵 허브 기본 구성
-- ============================================================
INSERT INTO roadmaps (creator_id, title, description, is_official, is_public, is_deleted, created_at)
SELECT
    admin_user.user_id,
    seed.title,
    CONCAT(seed.title, ' 학습 흐름을 담은 DevPath 공식 로드맵입니다.'),
    TRUE,
    TRUE,
    FALSE,
    CURRENT_TIMESTAMP
FROM (
    VALUES
        ('Full Stack'),
        ('DevOps'),
        ('DevSecOps'),
        ('Data Analyst'),
        ('AI Engineer'),
        ('AI and Data Scientist'),
        ('Data Engineer'),
        ('Android'),
        ('Machine Learning'),
        ('PostgreSQL'),
        ('iOS'),
        ('Blockchain'),
        ('QA'),
        ('Software Architect'),
        ('Cyber Security'),
        ('UX Design'),
        ('Technical Writer'),
        ('Game Developer'),
        ('Server Side Game Developer'),
        ('MLOps'),
        ('Product Manager'),
        ('Engineering Manager'),
        ('Developer Relations'),
        ('BI Analyst'),
        ('SQL'),
        ('Computer Science'),
        ('React'),
        ('Vue'),
        ('Angular'),
        ('JavaScript'),
        ('TypeScript'),
        ('Node.js'),
        ('Python'),
        ('System Design'),
        ('Java'),
        ('ASP.NET Core'),
        ('API Design'),
        ('Spring Boot'),
        ('Flutter'),
        ('C++'),
        ('Rust'),
        ('Go Roadmap'),
        ('Design and Architecture'),
        ('GraphQL'),
        ('React Native'),
        ('Design System'),
        ('Prompt Engineering'),
        ('MongoDB'),
        ('Linux'),
        ('Kubernetes'),
        ('Docker'),
        ('AWS'),
        ('Terraform'),
        ('Data Structures & Algorithms'),
        ('Redis'),
        ('Git and GitHub'),
        ('PHP'),
        ('Cloudflare'),
        ('AI Red Teaming'),
        ('AI Agents'),
        ('Next.js'),
        ('Code Review'),
        ('Kotlin'),
        ('HTML'),
        ('CSS'),
        ('Swift & Swift UI'),
        ('Shell / Bash'),
        ('Laravel'),
        ('Elasticsearch'),
        ('WordPress'),
        ('Django'),
        ('Ruby'),
        ('Ruby on Rails'),
        ('Claude Code'),
        ('Vibe Coding'),
        ('Scala'),
        ('OpenClaw')
) AS seed(title)
JOIN users admin_user ON admin_user.email = 'admin@devpath.com'
WHERE NOT EXISTS (
    SELECT 1
    FROM roadmaps roadmap
    WHERE roadmap.title = seed.title
);

DELETE FROM roadmap_hub_items
WHERE section_id IN (
    SELECT id
    FROM roadmap_hub_sections
    WHERE section_key IN ('project-ideas', 'best-practices')
);

DELETE FROM roadmap_hub_sections
WHERE section_key IN ('project-ideas', 'best-practices');

INSERT INTO roadmap_hub_sections (section_key, title, description, layout_type, sort_order, is_active)
SELECT seed.section_key, seed.title, seed.description, seed.layout_type, seed.sort_order, seed.is_active
FROM (
    VALUES
        ('role-based', '직무별 학습 로드맵', '직무별 학습 로드맵 허브 구성입니다.', 'CARD_GRID', 0, TRUE),
        ('skill-based', '기술별 학습 로드맵', '기술별 학습 로드맵 허브 구성입니다.', 'CHIP_GRID', 1, TRUE)
) AS seed(section_key, title, description, layout_type, sort_order, is_active)
WHERE NOT EXISTS (
    SELECT 1
    FROM roadmap_hub_sections section_item
    WHERE section_item.section_key = seed.section_key
);

UPDATE roadmap_hub_sections
SET
    title = CASE section_key
        WHEN 'role-based' THEN '직무별 학습 로드맵'
        WHEN 'skill-based' THEN '기술별 학습 로드맵'
        ELSE title
    END,
    description = CASE section_key
        WHEN 'role-based' THEN '직무별 학습 로드맵 허브 구성입니다.'
        WHEN 'skill-based' THEN '기술별 학습 로드맵 허브 구성입니다.'
        ELSE description
    END
WHERE section_key IN ('role-based', 'skill-based');

INSERT INTO roadmap_hub_items (
    section_id,
    title,
    subtitle,
    icon_class,
    linked_roadmap_id,
    sort_order,
    is_active,
    is_featured
)
SELECT
    section_item.id,
    seed.item_title,
    seed.subtitle,
    seed.icon_class,
    roadmap.roadmap_id,
    seed.sort_order,
    seed.is_active,
    seed.is_featured
FROM (
    VALUES
        ('role-based', '프론트엔드', 'Frontend', 'fas fa-desktop', 'Frontend Entry Roadmap', FALSE, 0, TRUE),
        ('role-based', '백엔드', 'Backend', 'fas fa-server', 'Backend Master Roadmap', TRUE, 1, TRUE),
        ('role-based', '풀스택', 'Full Stack', 'fas fa-layer-group', 'Full Stack', FALSE, 2, TRUE),
        ('role-based', '데브옵스', 'DevOps', 'fas fa-infinity', 'DevOps', TRUE, 3, TRUE),
        ('role-based', '데브섹옵스', 'DevSecOps', 'fas fa-shield-halved', 'DevSecOps', FALSE, 4, TRUE),
        ('role-based', '데이터 분석가', 'Data Analyst', 'fas fa-chart-line', 'Data Analyst', FALSE, 5, TRUE),
        ('role-based', 'AI 엔지니어', 'AI Engineer', 'fas fa-brain', 'AI Engineer', TRUE, 6, TRUE),
        ('role-based', 'AI·데이터 사이언티스트', 'AI and Data Scientist', 'fas fa-atom', 'AI and Data Scientist', FALSE, 7, TRUE),
        ('role-based', '데이터 엔지니어', 'Data Engineer', 'fas fa-database', 'Data Engineer', FALSE, 8, TRUE),
        ('role-based', '안드로이드', 'Android', 'fab fa-android', 'Android', FALSE, 9, TRUE),
        ('role-based', '머신러닝', 'Machine Learning', 'fas fa-microchip', 'Machine Learning', FALSE, 10, TRUE),
        ('role-based', 'PostgreSQL 전문가', 'PostgreSQL', 'fas fa-database', 'PostgreSQL', FALSE, 11, TRUE),
        ('role-based', 'iOS 개발자', 'iOS', 'fab fa-apple', 'iOS', FALSE, 12, TRUE),
        ('role-based', '블록체인', 'Blockchain', 'fas fa-link', 'Blockchain', FALSE, 13, TRUE),
        ('role-based', 'QA 엔지니어', 'QA', 'fas fa-vial', 'QA', FALSE, 14, TRUE),
        ('role-based', '소프트웨어 아키텍트', 'Software Architect', 'fas fa-sitemap', 'Software Architect', FALSE, 15, TRUE),
        ('role-based', '사이버 보안', 'Cyber Security', 'fas fa-user-shield', 'Cyber Security', TRUE, 16, TRUE),
        ('role-based', 'UX 디자인', 'UX Design', 'fas fa-bezier-curve', 'UX Design', FALSE, 17, TRUE),
        ('role-based', '테크니컬 라이터', 'Technical Writer', 'fas fa-pen-fancy', 'Technical Writer', FALSE, 18, TRUE),
        ('role-based', '게임 개발자', 'Game Developer', 'fas fa-gamepad', 'Game Developer', FALSE, 19, TRUE),
        ('role-based', '서버 사이드 게임 개발자', 'Server Side Game Developer', 'fas fa-dice-d20', 'Server Side Game Developer', FALSE, 20, TRUE),
        ('role-based', 'MLOps 엔지니어', 'MLOps', 'fas fa-gears', 'MLOps', TRUE, 21, TRUE),
        ('role-based', '프로덕트 매니저', 'Product Manager', 'fas fa-clipboard-list', 'Product Manager', FALSE, 22, TRUE),
        ('role-based', '엔지니어링 매니저', 'Engineering Manager', 'fas fa-users', 'Engineering Manager', FALSE, 23, TRUE),
        ('role-based', '데브렐', 'Developer Relations', 'fas fa-bullhorn', 'Developer Relations', FALSE, 24, TRUE),
        ('role-based', 'BI 분석가', 'BI Analyst', 'fas fa-chart-pie', 'BI Analyst', FALSE, 25, TRUE),
        ('skill-based', 'SQL', NULL, 'fas fa-database', 'SQL', FALSE, 0, TRUE),
        ('skill-based', 'Computer Science', NULL, 'fas fa-microchip', 'Computer Science', FALSE, 1, TRUE),
        ('skill-based', 'React', NULL, 'fab fa-react', 'React', FALSE, 2, TRUE),
        ('skill-based', 'Vue', NULL, 'fab fa-vuejs', 'Vue', FALSE, 3, TRUE),
        ('skill-based', 'Angular', NULL, 'fab fa-angular', 'Angular', FALSE, 4, TRUE),
        ('skill-based', 'JavaScript', NULL, 'fab fa-js', 'JavaScript', FALSE, 5, TRUE),
        ('skill-based', 'TypeScript', NULL, 'devpath-tech-icon devpath-icon-ts', 'TypeScript', FALSE, 6, TRUE),
        ('skill-based', 'Node.js', NULL, 'fab fa-node-js', 'Node.js', FALSE, 7, TRUE),
        ('skill-based', 'Python', NULL, 'fab fa-python', 'Python', FALSE, 8, TRUE),
        ('skill-based', 'System Design', NULL, 'fas fa-sitemap', 'System Design', FALSE, 9, TRUE),
        ('skill-based', 'Java', NULL, 'fab fa-java', 'Java', FALSE, 10, TRUE),
        ('skill-based', 'ASP.NET Core', NULL, 'fab fa-microsoft', 'ASP.NET Core', FALSE, 11, TRUE),
        ('skill-based', 'API Design', NULL, 'fas fa-plug', 'API Design', FALSE, 12, TRUE),
        ('skill-based', 'Spring Boot', NULL, 'fas fa-leaf', 'Spring Boot', FALSE, 13, TRUE),
        ('skill-based', 'Flutter', NULL, 'fas fa-mobile-alt', 'Flutter', FALSE, 14, TRUE),
        ('skill-based', 'C++', NULL, 'fas fa-code', 'C++', FALSE, 15, TRUE),
        ('skill-based', 'Rust', NULL, 'fab fa-rust', 'Rust', FALSE, 16, TRUE),
        ('skill-based', 'Go Roadmap', NULL, 'devpath-tech-icon devpath-icon-go', 'Go Roadmap', FALSE, 17, TRUE),
        ('skill-based', 'Design and Architecture', NULL, 'fas fa-drafting-compass', 'Design and Architecture', FALSE, 18, TRUE),
        ('skill-based', 'GraphQL', NULL, 'fas fa-project-diagram', 'GraphQL', FALSE, 19, TRUE),
        ('skill-based', 'React Native', NULL, 'fab fa-react', 'React Native', FALSE, 20, TRUE),
        ('skill-based', 'Design System', NULL, 'fas fa-palette', 'Design System', FALSE, 21, TRUE),
        ('skill-based', 'Prompt Engineering', NULL, 'fas fa-magic', 'Prompt Engineering', FALSE, 22, TRUE),
        ('skill-based', 'MongoDB', NULL, 'fas fa-leaf', 'MongoDB', FALSE, 23, TRUE),
        ('skill-based', 'Linux', NULL, 'fab fa-linux', 'Linux', FALSE, 24, TRUE),
        ('skill-based', 'Kubernetes', NULL, 'fas fa-dharmachakra', 'Kubernetes', FALSE, 25, TRUE),
        ('skill-based', 'Docker', NULL, 'fab fa-docker', 'Docker', FALSE, 26, TRUE),
        ('skill-based', 'AWS', NULL, 'fab fa-aws', 'AWS', FALSE, 27, TRUE),
        ('skill-based', 'Terraform', NULL, 'fas fa-cubes', 'Terraform', FALSE, 28, TRUE),
        ('skill-based', 'Data Structures & Algorithms', NULL, 'fas fa-project-diagram', 'Data Structures & Algorithms', FALSE, 29, TRUE),
        ('skill-based', 'Redis', NULL, 'fas fa-memory', 'Redis', FALSE, 30, TRUE),
        ('skill-based', 'Git and GitHub', NULL, 'fab fa-github', 'Git and GitHub', FALSE, 31, TRUE),
        ('skill-based', 'PHP', NULL, 'fab fa-php', 'PHP', FALSE, 32, TRUE),
        ('skill-based', 'Cloudflare', NULL, 'fab fa-cloudflare', 'Cloudflare', FALSE, 33, TRUE),
        ('skill-based', 'AI Red Teaming', NULL, 'fas fa-shield-alt', 'AI Red Teaming', FALSE, 34, TRUE),
        ('skill-based', 'AI Agents', NULL, 'fas fa-robot', 'AI Agents', FALSE, 35, TRUE),
        ('skill-based', 'Next.js', NULL, 'devpath-tech-icon devpath-icon-next', 'Next.js', FALSE, 36, TRUE),
        ('skill-based', 'Code Review', NULL, 'fas fa-code-branch', 'Code Review', FALSE, 37, TRUE),
        ('skill-based', 'Kotlin', NULL, 'devpath-tech-icon devpath-icon-kotlin', 'Kotlin', FALSE, 38, TRUE),
        ('skill-based', 'HTML', NULL, 'fab fa-html5', 'HTML', FALSE, 39, TRUE),
        ('skill-based', 'CSS', NULL, 'fab fa-css3-alt', 'CSS', FALSE, 40, TRUE),
        ('skill-based', 'Swift & Swift UI', NULL, 'fab fa-swift', 'Swift & Swift UI', FALSE, 41, TRUE),
        ('skill-based', 'Shell / Bash', NULL, 'devpath-tech-icon devpath-icon-bash', 'Shell / Bash', FALSE, 42, TRUE),
        ('skill-based', 'Laravel', NULL, 'fab fa-laravel', 'Laravel', FALSE, 43, TRUE),
        ('skill-based', 'Elasticsearch', NULL, 'fas fa-search', 'Elasticsearch', FALSE, 44, TRUE),
        ('skill-based', 'WordPress', NULL, 'fab fa-wordpress', 'WordPress', FALSE, 45, TRUE),
        ('skill-based', 'Django', NULL, 'fab fa-python', 'Django', FALSE, 46, TRUE),
        ('skill-based', 'Ruby', NULL, 'fas fa-gem', 'Ruby', FALSE, 47, TRUE),
        ('skill-based', 'Ruby on Rails', NULL, 'fas fa-train', 'Ruby on Rails', FALSE, 48, TRUE),
        ('skill-based', 'Claude Code', NULL, 'devpath-tech-icon devpath-icon-claude', 'Claude Code', FALSE, 49, TRUE),
        ('skill-based', 'Vibe Coding', NULL, 'fas fa-star', 'Vibe Coding', FALSE, 50, TRUE),
        ('skill-based', 'Scala', NULL, 'fas fa-layer-group', 'Scala', FALSE, 51, TRUE),
        ('skill-based', 'OpenClaw', NULL, 'devpath-tech-icon devpath-icon-openclaw', 'OpenClaw', FALSE, 52, TRUE)
) AS seed(
    section_key,
    item_title,
    subtitle,
    icon_class,
    linked_roadmap_title,
    is_featured,
    sort_order,
    is_active
)
JOIN roadmap_hub_sections section_item
    ON section_item.section_key = seed.section_key
LEFT JOIN roadmaps roadmap
    ON roadmap.title = seed.linked_roadmap_title
   AND roadmap.is_official = TRUE
   AND roadmap.is_deleted = FALSE
WHERE NOT EXISTS (
    SELECT 1
    FROM roadmap_hub_items item
    WHERE item.section_id = section_item.id
      AND (
          item.title = seed.item_title
          OR (seed.subtitle IS NOT NULL AND item.subtitle = seed.subtitle)
      )
);

DROP TABLE IF EXISTS tmp_roadmap_hub_item_category_seed;

CREATE TEMPORARY TABLE tmp_roadmap_hub_item_category_seed (
    section_key VARCHAR(80) NOT NULL,
    lookup_value VARCHAR(255) NOT NULL,
    item_category VARCHAR(80) NOT NULL
);

INSERT INTO tmp_roadmap_hub_item_category_seed (section_key, lookup_value, item_category)
VALUES
        ('role-based', 'Frontend', '웹 개발'),
        ('role-based', 'Backend', '웹 개발'),
        ('role-based', 'Full Stack', '웹 개발'),
        ('role-based', 'DevOps', '인프라/DevOps'),
        ('role-based', 'DevSecOps', '보안'),
        ('role-based', 'Data Analyst', '데이터/AI'),
        ('role-based', 'AI Engineer', '데이터/AI'),
        ('role-based', 'AI and Data Scientist', '데이터/AI'),
        ('role-based', 'Data Engineer', '데이터/AI'),
        ('role-based', 'Android', '모바일'),
        ('role-based', 'Machine Learning', '데이터/AI'),
        ('role-based', 'PostgreSQL', '데이터베이스'),
        ('role-based', 'iOS', '모바일'),
        ('role-based', 'Blockchain', '블록체인'),
        ('role-based', 'QA', '품질/테스트'),
        ('role-based', 'Software Architect', '아키텍처'),
        ('role-based', 'Cyber Security', '보안'),
        ('role-based', 'UX Design', '디자인'),
        ('role-based', 'Technical Writer', '문서/협업'),
        ('role-based', 'Game Developer', '게임'),
        ('role-based', 'Server Side Game Developer', '게임'),
        ('role-based', 'MLOps', '인프라/DevOps'),
        ('role-based', 'Product Manager', '기획/관리'),
        ('role-based', 'Engineering Manager', '기획/관리'),
        ('role-based', 'Developer Relations', '문서/협업'),
        ('role-based', 'BI Analyst', '데이터/AI'),
        ('skill-based', 'SQL', '데이터베이스'),
        ('skill-based', 'Computer Science', 'CS'),
        ('skill-based', 'React', '프론트엔드'),
        ('skill-based', 'Vue', '프론트엔드'),
        ('skill-based', 'Angular', '프론트엔드'),
        ('skill-based', 'JavaScript', '프론트엔드'),
        ('skill-based', 'TypeScript', '프론트엔드'),
        ('skill-based', 'Node.js', '백엔드'),
        ('skill-based', 'Python', '언어'),
        ('skill-based', 'System Design', 'CS'),
        ('skill-based', 'Java', '백엔드'),
        ('skill-based', 'ASP.NET Core', '백엔드'),
        ('skill-based', 'API Design', '백엔드'),
        ('skill-based', 'Spring Boot', '백엔드'),
        ('skill-based', 'Flutter', '모바일'),
        ('skill-based', 'C++', '언어'),
        ('skill-based', 'Rust', '언어'),
        ('skill-based', 'Go Roadmap', '언어'),
        ('skill-based', 'Design and Architecture', 'CS'),
        ('skill-based', 'GraphQL', '백엔드'),
        ('skill-based', 'React Native', '모바일'),
        ('skill-based', 'Design System', '디자인'),
        ('skill-based', 'Prompt Engineering', 'AI'),
        ('skill-based', 'MongoDB', '데이터베이스'),
        ('skill-based', 'Linux', 'DevOps/Cloud'),
        ('skill-based', 'Kubernetes', 'DevOps/Cloud'),
        ('skill-based', 'Docker', 'DevOps/Cloud'),
        ('skill-based', 'AWS', 'DevOps/Cloud'),
        ('skill-based', 'Terraform', 'DevOps/Cloud'),
        ('skill-based', 'Data Structures & Algorithms', 'CS'),
        ('skill-based', 'Redis', '데이터베이스'),
        ('skill-based', 'Git and GitHub', '도구'),
        ('skill-based', 'PHP', '백엔드'),
        ('skill-based', 'Cloudflare', 'DevOps/Cloud'),
        ('skill-based', 'AI Red Teaming', 'AI'),
        ('skill-based', 'AI Agents', 'AI'),
        ('skill-based', 'Next.js', '프론트엔드'),
        ('skill-based', 'Code Review', '도구'),
        ('skill-based', 'Kotlin', '언어'),
        ('skill-based', 'HTML', '프론트엔드'),
        ('skill-based', 'CSS', '프론트엔드'),
        ('skill-based', 'Swift & Swift UI', '모바일'),
        ('skill-based', 'Shell / Bash', '도구'),
        ('skill-based', 'Laravel', '백엔드'),
        ('skill-based', 'Elasticsearch', '데이터베이스'),
        ('skill-based', 'WordPress', '백엔드'),
        ('skill-based', 'Django', '백엔드'),
        ('skill-based', 'Ruby', '언어'),
        ('skill-based', 'Ruby on Rails', '백엔드'),
        ('skill-based', 'Claude Code', 'AI'),
        ('skill-based', 'Vibe Coding', 'AI'),
        ('skill-based', 'Scala', '언어'),
        ('skill-based', 'OpenClaw', 'AI');

UPDATE roadmap_hub_items item
SET item_category = seed.item_category
FROM tmp_roadmap_hub_item_category_seed seed
JOIN roadmap_hub_sections section_item
    ON section_item.section_key = seed.section_key
WHERE item.section_id = section_item.id
  AND (item.title = seed.lookup_value OR item.subtitle = seed.lookup_value)
  AND (item.item_category IS NULL OR item.item_category = '');

DROP TABLE IF EXISTS tmp_roadmap_hub_item_category_seed;

DROP TABLE IF EXISTS tmp_roadmap_hub_skill_icon_seed;

CREATE TEMPORARY TABLE tmp_roadmap_hub_skill_icon_seed (
    item_title VARCHAR(255) NOT NULL,
    icon_class VARCHAR(255) NOT NULL
);

INSERT INTO tmp_roadmap_hub_skill_icon_seed (item_title, icon_class)
VALUES
        ('SQL', 'fas fa-database'),
        ('Computer Science', 'fas fa-microchip'),
        ('React', 'fab fa-react'),
        ('Vue', 'fab fa-vuejs'),
        ('Angular', 'fab fa-angular'),
        ('JavaScript', 'fab fa-js'),
        ('TypeScript', 'devpath-tech-icon devpath-icon-ts'),
        ('Node.js', 'fab fa-node-js'),
        ('Python', 'fab fa-python'),
        ('System Design', 'fas fa-sitemap'),
        ('Java', 'fab fa-java'),
        ('ASP.NET Core', 'fab fa-microsoft'),
        ('API Design', 'fas fa-plug'),
        ('Spring Boot', 'fas fa-leaf'),
        ('Flutter', 'fas fa-mobile-alt'),
        ('C++', 'fas fa-code'),
        ('Rust', 'fab fa-rust'),
        ('Go Roadmap', 'devpath-tech-icon devpath-icon-go'),
        ('Design and Architecture', 'fas fa-drafting-compass'),
        ('GraphQL', 'fas fa-project-diagram'),
        ('React Native', 'fab fa-react'),
        ('Design System', 'fas fa-palette'),
        ('Prompt Engineering', 'fas fa-magic'),
        ('MongoDB', 'fas fa-leaf'),
        ('Linux', 'fab fa-linux'),
        ('Kubernetes', 'fas fa-dharmachakra'),
        ('Docker', 'fab fa-docker'),
        ('AWS', 'fab fa-aws'),
        ('Terraform', 'fas fa-cubes'),
        ('Data Structures & Algorithms', 'fas fa-project-diagram'),
        ('Redis', 'fas fa-memory'),
        ('Git and GitHub', 'fab fa-github'),
        ('PHP', 'fab fa-php'),
        ('Cloudflare', 'fab fa-cloudflare'),
        ('AI Red Teaming', 'fas fa-shield-alt'),
        ('AI Agents', 'fas fa-robot'),
        ('Next.js', 'devpath-tech-icon devpath-icon-next'),
        ('Code Review', 'fas fa-code-branch'),
        ('Kotlin', 'devpath-tech-icon devpath-icon-kotlin'),
        ('HTML', 'fab fa-html5'),
        ('CSS', 'fab fa-css3-alt'),
        ('Swift & Swift UI', 'fab fa-swift'),
        ('Shell / Bash', 'devpath-tech-icon devpath-icon-bash'),
        ('Laravel', 'fab fa-laravel'),
        ('Elasticsearch', 'fas fa-search'),
        ('WordPress', 'fab fa-wordpress'),
        ('Django', 'fab fa-python'),
        ('Ruby', 'fas fa-gem'),
        ('Ruby on Rails', 'fas fa-train'),
        ('Claude Code', 'devpath-tech-icon devpath-icon-claude'),
        ('Vibe Coding', 'fas fa-star'),
        ('Scala', 'fas fa-layer-group'),
        ('OpenClaw', 'devpath-tech-icon devpath-icon-openclaw');

UPDATE roadmap_hub_items item
SET icon_class = (
    SELECT seed.icon_class
    FROM tmp_roadmap_hub_skill_icon_seed seed
    WHERE seed.item_title = item.title
)
WHERE item.section_id IN (
    SELECT section_item.id
    FROM roadmap_hub_sections section_item
    WHERE section_item.section_key = 'skill-based'
)
  AND EXISTS (
      SELECT 1
      FROM tmp_roadmap_hub_skill_icon_seed seed
      WHERE seed.item_title = item.title
  );

DROP TABLE IF EXISTS tmp_roadmap_hub_skill_icon_seed;

DROP TABLE IF EXISTS tmp_roadmap_hub_item_color_seed;

CREATE TEMPORARY TABLE tmp_roadmap_hub_item_color_seed (
    section_key VARCHAR(100) NOT NULL,
    item_title VARCHAR(255),
    subtitle VARCHAR(255),
    icon_color VARCHAR(20) NOT NULL
);

INSERT INTO tmp_roadmap_hub_item_color_seed (section_key, item_title, subtitle, icon_color)
VALUES
        ('role-based', NULL, 'Frontend', '#38BDF8'),
        ('role-based', NULL, 'Backend', '#00C471'),
        ('role-based', NULL, 'Full Stack', '#8B5CF6'),
        ('role-based', NULL, 'DevOps', '#F59E0B'),
        ('role-based', NULL, 'DevSecOps', '#EF4444'),
        ('role-based', NULL, 'Data Analyst', '#06B6D4'),
        ('role-based', NULL, 'AI Engineer', '#A855F7'),
        ('role-based', NULL, 'AI and Data Scientist', '#6366F1'),
        ('role-based', NULL, 'Data Engineer', '#0EA5E9'),
        ('role-based', NULL, 'Android', '#3DDC84'),
        ('role-based', NULL, 'Machine Learning', '#F97316'),
        ('role-based', NULL, 'PostgreSQL', '#336791'),
        ('role-based', NULL, 'iOS', '#111827'),
        ('role-based', NULL, 'Blockchain', '#F7931A'),
        ('role-based', NULL, 'QA', '#14B8A6'),
        ('role-based', NULL, 'Software Architect', '#64748B'),
        ('role-based', NULL, 'Cyber Security', '#DC2626'),
        ('role-based', NULL, 'UX Design', '#EC4899'),
        ('role-based', NULL, 'Technical Writer', '#475569'),
        ('role-based', NULL, 'Game Developer', '#7C3AED'),
        ('role-based', NULL, 'Server Side Game Developer', '#2563EB'),
        ('role-based', NULL, 'MLOps', '#22C55E'),
        ('role-based', NULL, 'Product Manager', '#F59E0B'),
        ('role-based', NULL, 'Engineering Manager', '#0F766E'),
        ('role-based', NULL, 'Developer Relations', '#EAB308'),
        ('role-based', NULL, 'BI Analyst', '#0284C7'),
        ('skill-based', 'SQL', NULL, '#336791'),
        ('skill-based', 'Computer Science', NULL, '#64748B'),
        ('skill-based', 'React', NULL, '#61DAFB'),
        ('skill-based', 'Vue', NULL, '#42B883'),
        ('skill-based', 'Angular', NULL, '#DD0031'),
        ('skill-based', 'JavaScript', NULL, '#F7DF1E'),
        ('skill-based', 'TypeScript', NULL, '#3178C6'),
        ('skill-based', 'Node.js', NULL, '#339933'),
        ('skill-based', 'Python', NULL, '#3776AB'),
        ('skill-based', 'System Design', NULL, '#475569'),
        ('skill-based', 'Java', NULL, '#F89820'),
        ('skill-based', 'ASP.NET Core', NULL, '#512BD4'),
        ('skill-based', 'API Design', NULL, '#F97316'),
        ('skill-based', 'Spring Boot', NULL, '#6DB33F'),
        ('skill-based', 'Flutter', NULL, '#02569B'),
        ('skill-based', 'C++', NULL, '#00599C'),
        ('skill-based', 'Rust', NULL, '#DEA584'),
        ('skill-based', 'Go Roadmap', NULL, '#00ADD8'),
        ('skill-based', 'Design and Architecture', NULL, '#8B5CF6'),
        ('skill-based', 'GraphQL', NULL, '#E10098'),
        ('skill-based', 'React Native', NULL, '#61DAFB'),
        ('skill-based', 'Design System', NULL, '#EC4899'),
        ('skill-based', 'Prompt Engineering', NULL, '#8B5CF6'),
        ('skill-based', 'MongoDB', NULL, '#47A248'),
        ('skill-based', 'Linux', NULL, '#FCC624'),
        ('skill-based', 'Kubernetes', NULL, '#326CE5'),
        ('skill-based', 'Docker', NULL, '#2496ED'),
        ('skill-based', 'AWS', NULL, '#FF9900'),
        ('skill-based', 'Terraform', NULL, '#7B42BC'),
        ('skill-based', 'Data Structures & Algorithms', NULL, '#0EA5E9'),
        ('skill-based', 'Redis', NULL, '#DC382D'),
        ('skill-based', 'Git and GitHub', NULL, '#181717'),
        ('skill-based', 'PHP', NULL, '#777BB4'),
        ('skill-based', 'Cloudflare', NULL, '#F38020'),
        ('skill-based', 'AI Red Teaming', NULL, '#EF4444'),
        ('skill-based', 'AI Agents', NULL, '#9333EA'),
        ('skill-based', 'Next.js', NULL, '#111827'),
        ('skill-based', 'Code Review', NULL, '#10B981'),
        ('skill-based', 'Kotlin', NULL, '#7F52FF'),
        ('skill-based', 'HTML', NULL, '#E34F26'),
        ('skill-based', 'CSS', NULL, '#1572B6'),
        ('skill-based', 'Swift & Swift UI', NULL, '#FA7343'),
        ('skill-based', 'Shell / Bash', NULL, '#4EAA25'),
        ('skill-based', 'Laravel', NULL, '#FF2D20'),
        ('skill-based', 'Elasticsearch', NULL, '#005571'),
        ('skill-based', 'WordPress', NULL, '#21759B'),
        ('skill-based', 'Django', NULL, '#092E20'),
        ('skill-based', 'Ruby', NULL, '#CC342D'),
        ('skill-based', 'Ruby on Rails', NULL, '#CC0000'),
        ('skill-based', 'Claude Code', NULL, '#D97757'),
        ('skill-based', 'Vibe Coding', NULL, '#F59E0B'),
        ('skill-based', 'Scala', NULL, '#DC322F'),
        ('skill-based', 'OpenClaw', NULL, '#0F172A');

UPDATE roadmap_hub_items item
SET icon_color = (
    SELECT seed.icon_color
    FROM tmp_roadmap_hub_item_color_seed seed
    JOIN roadmap_hub_sections section_item
        ON section_item.section_key = seed.section_key
    WHERE item.section_id = section_item.id
      AND (
          (seed.item_title IS NOT NULL AND item.title = seed.item_title)
          OR (seed.subtitle IS NOT NULL AND item.subtitle = seed.subtitle)
      )
)
WHERE EXISTS (
    SELECT 1
    FROM tmp_roadmap_hub_item_color_seed seed
    JOIN roadmap_hub_sections section_item
        ON section_item.section_key = seed.section_key
    WHERE item.section_id = section_item.id
      AND (
          (seed.item_title IS NOT NULL AND item.title = seed.item_title)
          OR (seed.subtitle IS NOT NULL AND item.subtitle = seed.subtitle)
      )
);

DROP TABLE IF EXISTS tmp_roadmap_hub_item_color_seed;

UPDATE roadmap_hub_items item
SET
    title = CASE item.subtitle
        WHEN 'Frontend' THEN '프론트엔드'
        WHEN 'Backend' THEN '백엔드'
        WHEN 'Full Stack' THEN '풀스택'
        WHEN 'DevOps' THEN '데브옵스'
        WHEN 'DevSecOps' THEN '데브섹옵스'
        WHEN 'Data Analyst' THEN '데이터 분석가'
        WHEN 'AI Engineer' THEN 'AI 엔지니어'
        WHEN 'AI and Data Scientist' THEN 'AI·데이터 사이언티스트'
        WHEN 'Data Engineer' THEN '데이터 엔지니어'
        WHEN 'Android' THEN '안드로이드'
        WHEN 'Machine Learning' THEN '머신러닝'
        WHEN 'PostgreSQL' THEN 'PostgreSQL 전문가'
        WHEN 'iOS' THEN 'iOS 개발자'
        WHEN 'Blockchain' THEN '블록체인'
        WHEN 'QA' THEN 'QA 엔지니어'
        WHEN 'Software Architect' THEN '소프트웨어 아키텍트'
        WHEN 'Cyber Security' THEN '사이버 보안'
        WHEN 'UX Design' THEN 'UX 디자인'
        WHEN 'Technical Writer' THEN '테크니컬 라이터'
        WHEN 'Game Developer' THEN '게임 개발자'
        WHEN 'Server Side Game Developer' THEN '서버 사이드 게임 개발자'
        WHEN 'MLOps' THEN 'MLOps 엔지니어'
        WHEN 'Product Manager' THEN '프로덕트 매니저'
        WHEN 'Engineering Manager' THEN '엔지니어링 매니저'
        WHEN 'Developer Relations' THEN '데브렐'
        WHEN 'BI Analyst' THEN 'BI 분석가'
        ELSE item.title
    END,
    is_featured = CASE
        WHEN item.subtitle IN ('Backend', 'AI Engineer', 'DevOps', 'MLOps', 'Cyber Security') THEN TRUE
        ELSE FALSE
    END
FROM roadmap_hub_sections section_item
WHERE item.section_id = section_item.id
  AND section_item.section_key = 'role-based';

-- ============================================================
-- Roadmap Hub 공식 로드맵 상세 데이터 보강
-- - Backend Master Roadmap은 위쪽의 전용 상세 seed를 유지한다.
-- - 허브에 연결된 나머지 공식 로드맵은 분야별 profile을 기준으로 소개/노드/분기/선수조건/태그를 생성한다.
-- ============================================================
DROP TABLE IF EXISTS roadmap_hub_node_profile_seed;
DROP TABLE IF EXISTS roadmap_hub_node_detail_seed;

CREATE TEMPORARY TABLE roadmap_hub_node_profile_seed (
    display_name VARCHAR(120) PRIMARY KEY,
    intro_topic TEXT NOT NULL,
    core_topic TEXT NOT NULL,
    tool_topic TEXT NOT NULL,
    practice_topic TEXT NOT NULL,
    model_topic TEXT NOT NULL,
    quality_topic TEXT NOT NULL,
    perf_topic TEXT NOT NULL,
    ops_topic TEXT NOT NULL,
    arch_topic TEXT NOT NULL,
    security_topic TEXT NOT NULL,
    project_topic TEXT NOT NULL
);

INSERT INTO roadmap_hub_node_profile_seed (
    display_name,
    intro_topic,
    core_topic,
    tool_topic,
    practice_topic,
    model_topic,
    quality_topic,
    perf_topic,
    ops_topic,
    arch_topic,
    security_topic,
    project_topic
) VALUES
    ('Frontend', '브라우저 화면 구현과 사용자 흐름', 'HTML CSS JavaScript 렌더링', 'Vite React DevTools 브라우저 디버거', '반응형 UI와 폼 검증', '클라이언트 상태 서버 상태 라우팅', '접근성 웹 성능 크로스브라우징', '번들 크기와 렌더링 비용', '정적 배포와 프리뷰 환경', '컴포넌트 계층과 디자인 시스템', 'XSS 입력 검증 토큰 저장', 'API 연동 대시보드 화면'),
    ('Full Stack', '화면 API 데이터 저장소를 연결하는 제품 전체 흐름', 'HTTP 인증 UI 상태 데이터 모델링', 'React Spring Boot PostgreSQL Docker GitHub Actions', '로그인 CRUD 관리자 화면 통합 구현', '도메인 엔티티 API 계약 클라이언트 캐시', '단위 통합 E2E 테스트와 장애 로그', 'API 응답 시간 프론트 렌더링 DB 인덱스', '컨테이너 배포 CI 파이프라인 환경 분리', '계층형 구조 모듈 경계 프론트 백엔드 계약', '인증 인가 세션 토큰 민감 정보 보호', '풀스택 서비스 MVP와 배포 링크'),
    ('DevOps', '개발과 운영 사이 배포 흐름을 자동화하는 책임', 'CI CD 인프라 모니터링 장애 대응', 'GitHub Actions Docker Kubernetes Terraform Prometheus', '빌드 테스트 이미지 배포 파이프라인 구축', '환경 변수 시크릿 배포 전략 인프라 상태', '재현 가능한 배포 롤백 헬스체크', '배포 시간 리소스 사용량 스케일링 지표', '알림 로그 메트릭 백업 복구 절차', '클러스터 네트워크 서비스 디스커버리 구성', '시크릿 관리 권한 분리 이미지 취약점 점검', '컨테이너 서비스 CI CD와 모니터링'),
    ('DevSecOps', '보안을 개발 배포 운영 흐름 안에 넣는 책임', '위협 모델링 SAST DAST 시크릿 관리', 'GitHub Advanced Security Trivy OWASP ZAP Vault', '취약점 스캔이 포함된 배포 파이프라인', '보안 정책 예외 승인 감사 로그', '보안 게이트 오탐 관리 규정 준수', '스캔 시간과 릴리스 차단 기준 조율', '취약점 알림 패치 추적 사고 대응', '제로 트러스트 네트워크 권한 최소화', '공급망 보안 의존성 서명 SBOM', '보안 검사가 포함된 서비스 배포 흐름'),
    ('Data Analyst', '비즈니스 질문을 데이터 지표로 바꾸는 분석 흐름', 'SQL 통계 지표 정의 코호트 분석', 'SQL BI 도구 스프레드시트 Python 노트북', '매출 전환 리텐션 대시보드 작성', '이벤트 로그 차원 측정값 데이터 마트', '지표 검증 결측치 이상치 재현성', '쿼리 비용과 대시보드 로딩 시간', '정기 리포트 자동 갱신 권한 관리', '분석 데이터 모델과 지표 사전', '개인정보 마스킹 접근 권한', '제품 개선 의사결정 분석 리포트'),
    ('AI Engineer', 'AI 모델을 제품 기능으로 연결하는 엔지니어링 흐름', '모델 추론 벡터 검색 프롬프트 API', 'Python FastAPI LangChain 벡터DB Docker', '문서 질의응답 챗봇 기능 구현', '임베딩 청크 메타데이터 프롬프트 상태', '정답 품질 평가 hallucination 테스트', '추론 지연 토큰 비용 캐시 전략', '모델 서빙 로그 관찰 프롬프트 버전 관리', 'RAG 파이프라인 에이전트 도구 호출 구조', '프롬프트 주입 데이터 유출 안전장치', '운영 가능한 AI 기능 프로토타입'),
    ('AI and Data Scientist', '데이터로 가설을 검증하고 모델 성능을 설명하는 흐름', '통계 머신러닝 피처 엔지니어링 실험 설계', 'Python pandas scikit-learn Jupyter MLflow', '예측 모델 학습과 성능 비교 실험', '피처 테이블 학습 검증 테스트 분리', '교차검증 편향 분산 재현 가능한 실험', '학습 시간 메모리 모델 복잡도 조절', '실험 추적 모델 등록 결과 공유', '모델링 파이프라인과 데이터 누수 방지', '개인정보 익명화 모델 편향 점검', '문제 정의부터 모델 리포트까지'),
    ('Data Engineer', '데이터를 안정적으로 수집 변환 제공하는 파이프라인', '배치 스트리밍 ETL ELT 데이터 웨어하우스', 'Airflow Spark Kafka dbt Snowflake', '원천 데이터 적재와 변환 잡 구성', '스키마 파티션 데이터 계보 품질 규칙', '데이터 테스트 재처리 중복 방지', '잡 실행 시간 파일 크기 파티션 최적화', '스케줄링 알림 재시도 백필 운영', '레이크하우스와 웨어하우스 계층 설계', '민감 데이터 권한 마스킹 감사', '분석용 데이터 마트와 파이프라인'),
    ('Android', 'Android 앱 화면과 기기 기능을 구현하는 흐름', 'Kotlin Activity Fragment Compose 생명주기', 'Android Studio Gradle Emulator Jetpack', '리스트 상세 화면과 로컬 저장 구현', 'ViewModel 상태 네비게이션 Room 데이터', 'UI 테스트 접근성 크래시 리포트', '렌더링 지연 배터리 네트워크 비용', '스토어 배포 버전 코드 Crashlytics', 'Clean Architecture 모듈화 의존성 주입', '권한 저장소 암호화 네트워크 보안', 'API 연동 Android 앱 완성'),
    ('Machine Learning', '데이터에서 패턴을 학습하는 모델 개발 흐름', '지도학습 비지도학습 평가 지표 피처', 'Python scikit-learn pandas matplotlib', '분류 회귀 모델 학습 실습', '데이터셋 분할 피처 스케일링 레이블', '검증 지표 과적합 데이터 누수 점검', '모델 복잡도 학습 시간 추론 속도', '모델 저장 추론 스크립트 실험 기록', '파이프라인 전처리 모델 평가 구조', '편향 개인정보 설명 가능성', '문제별 ML 모델 비교 리포트'),
    ('PostgreSQL', '관계형 데이터 저장과 조회 성능을 설계하는 흐름', '테이블 관계 SQL 트랜잭션 인덱스', 'psql pgAdmin EXPLAIN 백업 도구', '정규화된 스키마와 조회 쿼리 작성', '제약조건 외래키 뷰 파티션', 'ACID 락 격리수준 쿼리 검증', '실행 계획 인덱스 튜닝 VACUUM', '백업 복구 복제 모니터링', '스키마 설계와 마이그레이션 전략', '권한 Row Level Security 감사 로그', '업무용 PostgreSQL 데이터 모델'),
    ('iOS', 'Apple 생태계 앱 화면과 상태 흐름을 구현하는 과정', 'Swift SwiftUI UIKit 생명주기', 'Xcode Simulator Instruments TestFlight', '목록 상세 폼 화면과 네트워크 연동', 'Observable 상태 네비게이션 CoreData', 'UI 테스트 접근성 크래시 분석', '앱 시작 시간 메모리 렌더링 최적화', '프로비저닝 TestFlight 릴리스 관리', 'MVVM 모듈화 의존성 주입', '키체인 권한 개인정보 보호', 'API 연동 iOS 앱 완성'),
    ('Blockchain', '탈중앙 네트워크와 스마트 컨트랙트 서비스 구조', '트랜잭션 지갑 컨센서스 스마트 컨트랙트', 'Solidity Hardhat MetaMask Ethers.js', '토큰 전송과 컨트랙트 호출 DApp', '온체인 상태 이벤트 인덱싱 지갑 연결', '컨트랙트 테스트 감사 재현성', '가스 비용 저장소 접근 최적화', '테스트넷 배포 모니터링 업그레이드', '프록시 패턴 오라클 브릿지 구조', '재진입 공격 권한 검증 키 관리', '스마트 컨트랙트 기반 DApp'),
    ('QA', '제품 품질을 요구사항과 테스트로 검증하는 흐름', '테스트 케이스 결함 리포트 회귀 테스트', 'TestRail Playwright Postman JMeter', '기능 테스트와 API 테스트 시나리오 작성', '요구사항 추적 결함 상태 테스트 데이터', '재현 절차 우선순위 커버리지', '테스트 실행 시간 병렬화 안정성', '릴리스 검수 자동화 리포트', '테스트 전략과 품질 게이트 설계', '권한 입력값 장애 상황 보안 테스트', '릴리스 품질 검증 리포트'),
    ('Software Architect', '시스템 요구사항을 구조와 기술 결정으로 바꾸는 역할', '품질 속성 트레이드오프 아키텍처 패턴', 'C4 다이어그램 ADR 모델링 도구', '서비스 경계와 통신 방식 설계', '도메인 모델 데이터 흐름 의존성', '아키텍처 리뷰 위험 식별 검증 계획', '확장성 처리량 지연시간 비용', '운영성 관찰성 장애 격리 전략', '모듈 분리 이벤트 기반 마이크로서비스', '보안 경계 권한 데이터 보호', '아키텍처 결정 기록과 설계 문서'),
    ('Cyber Security', '시스템을 공격 관점에서 분석하고 방어하는 흐름', '네트워크 웹 취약점 암호 권한', 'Burp Suite Nmap Wireshark SIEM', '취약점 진단과 침투 테스트 리포트', '자산 위협 공격 경로 로그 이벤트', '재현 가능한 취약점 검증과 심각도 평가', '스캔 범위 탐지 속도 오탐 관리', '보안 모니터링 사고 대응 플레이북', '방어 계층 인증 네트워크 분리', 'OWASP 권한 상승 데이터 유출 방지', '웹 서비스 보안 진단 보고서'),
    ('UX Design', '사용자 문제를 화면 흐름과 인터랙션으로 해결하는 과정', '리서치 정보구조 와이어프레임 사용성', 'Figma FigJam 프로토타입 사용자 인터뷰', '핵심 사용자 여정과 화면 시안 제작', '페르소나 태스크 플로우 디자인 토큰', '사용성 테스트 접근성 디자인 리뷰', '전환율 과업 성공률 인터랙션 비용', '디자인 핸드오프 피드백 반영 버전 관리', '정보구조 네비게이션 컴포넌트 패턴', '개인정보 동의 오류 방지 접근성', '검증 가능한 프로토타입과 UX 리포트'),
    ('Technical Writer', '복잡한 기술을 정확한 문서와 가이드로 전달하는 역할', '독자 분석 정보 설계 API 문서', 'Markdown OpenAPI Docs-as-Code Git', '설치 가이드와 튜토리얼 작성', '문서 구조 용어집 버전 릴리스 노트', '정확성 검수 링크 검증 스타일 가이드', '문서 탐색성 검색성 읽기 시간', '문서 배포 변경 이력 피드백 수집', '문서 IA와 콘텐츠 재사용 전략', '민감 정보 제거 권한별 문서 분리', '개발자 온보딩 문서 세트'),
    ('Game Developer', '게임 규칙을 상호작용과 플레이 경험으로 구현하는 흐름', '게임 루프 물리 입력 애니메이션', 'Unity Unreal Godot Blender 디버거', '플레이어 이동 전투 UI 프로토타입', '씬 오브젝트 상태 저장 리소스 관리', '플레이 테스트 밸런스 버그 재현', '프레임 레이트 드로우콜 메모리 최적화', '빌드 패키징 패치 크래시 수집', '엔티티 컴포넌트 씬 전환 구조', '치트 방지 세이브 보호 입력 검증', '플레이 가능한 게임 프로토타입'),
    ('Server Side Game Developer', '멀티플레이 게임 서버와 실시간 상태를 운영하는 흐름', '세션 매치메이킹 동기화 권위 서버', 'Netty WebSocket Redis Kubernetes', '실시간 방 생성과 상태 동기화 구현', '플레이어 상태 룸 서버 이벤트 큐', '부하 테스트 지연 재접속 시나리오', '틱 레이트 네트워크 지연 서버 부하', '매치 서버 배포 모니터링 장애 복구', '샤딩 로비 게임 서버 분리', '치트 검증 권위 서버 토큰 보호', '멀티플레이 게임 서버 데모'),
    ('MLOps', '모델 개발부터 배포 모니터링까지 연결하는 운영 흐름', '모델 레지스트리 피처 스토어 서빙 모니터링', 'MLflow Kubeflow Docker Kubernetes Airflow', '모델 학습 배포 파이프라인 구축', '데이터 버전 모델 버전 피처 계약', '재현성 모델 검증 드리프트 테스트', '추론 지연 처리량 리소스 비용', '모델 모니터링 재학습 롤백 운영', '학습 서빙 파이프라인 분리 구조', '모델 접근 권한 데이터 보호 승인', '운영 가능한 ML 배포 파이프라인'),
    ('Product Manager', '문제를 정의하고 제품 우선순위를 결정하는 흐름', '고객 문제 KPI 로드맵 우선순위', 'Jira Notion Figma Analytics 도구', 'PRD 작성과 실험 계획 수립', '사용자 세그먼트 지표 백로그 릴리스 범위', '가설 검증 성공 기준 리스크 관리', '전환율 리텐션 실험 비용 최적화', '릴리스 커뮤니케이션 피드백 루프', '제품 전략과 기능 의존성 구조', '개인정보 정책 권한 장애 대응 요구사항', '문제 정의부터 출시 회고까지'),
    ('Engineering Manager', '팀이 지속적으로 성과를 내도록 사람과 시스템을 관리하는 역할', '목표 설정 피드백 채용 실행 관리', '1on1 문서화 로드맵 지표 대시보드', '스프린트 운영과 팀 실행 리듬 정리', '역할 책임 의사결정 지표 리스크', '성과 리뷰 성장 계획 팀 건강도', '리드타임 병목 WIP 배포 빈도', '온콜 회고 프로세스 개선 운영', '팀 구조 책임 위임 의사결정 체계', '권한 갈등 보안 책임 사고 대응', '팀 운영 계획과 성장 로드맵'),
    ('Developer Relations', '개발자 커뮤니티와 제품 사용 경험을 연결하는 역할', 'API 이해 콘텐츠 커뮤니티 피드백', 'GitHub Discord 블로그 데모 도구', '샘플 앱 튜토리얼과 발표 자료 제작', '개발자 여정 피드백 이슈 콘텐츠 캘린더', '문서 정확성 데모 재현성 커뮤니티 반응', '온보딩 시간 샘플 실행 성공률', '릴리스 소통 이벤트 운영 피드백 정리', '커뮤니티 채널 콘텐츠 퍼널 설계', '민감 정보 공개 방지 라이선스 준수', '개발자 온보딩 캠페인과 데모'),
    ('BI Analyst', '조직 의사결정용 지표와 리포트를 설계하는 흐름', '지표 정의 데이터 모델 대시보드 스토리텔링', 'SQL Power BI Tableau Looker', '경영 KPI 대시보드와 리포트 작성', '팩트 차원 테이블 필터 권한 모델', '수치 검산 데이터 신뢰도 알림 기준', '쿼리 성능 캐시 대시보드 응답 시간', '정기 리포트 배포 권한 관리', '스타 스키마 시맨틱 레이어 설계', '민감 지표 접근 제어 감사', '의사결정용 BI 대시보드'),
    ('SQL', '데이터를 질문에 맞게 조회하고 변형하는 능력', 'SELECT JOIN GROUP BY 서브쿼리 윈도우 함수', 'PostgreSQL MySQL psql SQL 클라이언트', '분석용 조회 쿼리와 집계 작성', '테이블 관계 키 제약조건 NULL 처리', '쿼리 결과 검산 중복 누락 점검', '인덱스 실행 계획 쿼리 비용', '뷰 저장 프로시저 배치 실행', '정규화와 조회 패턴별 스키마 설계', 'SQL Injection 권한 최소화', '실무 데이터 분석 쿼리 모음'),
    ('Computer Science', '소프트웨어가 동작하는 기본 원리를 이해하는 기반', '자료구조 운영체제 네트워크 데이터베이스', 'C Python Linux 디버거 시각화 도구', '알고리즘과 시스템 동작 실험', '메모리 프로세스 파일 네트워크 모델', '복잡도 검증 경계값 테스트', '시간복잡도 공간복잡도 병목 분석', '프로세스 스케줄링 I/O 관찰', '계층 구조 추상화 인터페이스 설계', '권한 격리 암호화 기본 원리', 'CS 개념 실험 노트와 구현'),
    ('React', '컴포넌트 기반으로 상태 변화에 반응하는 UI 개발', 'JSX props state Hooks 렌더링', 'Vite React DevTools Testing Library', '컴포넌트 분리와 이벤트 처리 구현', '전역 상태 서버 상태 라우터 구조', '컴포넌트 테스트 접근성 회귀 확인', '메모이제이션 렌더링 횟수 번들 분석', '정적 빌드 배포 환경 변수 관리', '컴포넌트 합성 상태 경계 설계', 'XSS 안전한 렌더링 토큰 저장', 'API 연동 React 미니 앱'),
    ('Vue', '템플릿과 반응형 상태로 화면을 구성하는 UI 개발', 'Composition API 반응성 컴포넌트 라우터', 'Vite Vue Devtools Pinia Vitest', '폼 목록 상세 화면 컴포넌트 구현', 'ref reactive store route 상태 모델', '컴포넌트 테스트 접근성 스타일 검증', '반응성 추적 번들 크기 렌더링 최적화', '정적 배포 빌드 환경 분리', '컴포저블과 컴포넌트 책임 분리', 'XSS 템플릿 안전성 인증 토큰', 'API 연동 Vue 애플리케이션'),
    ('Angular', '프레임워크 구조로 대규모 프론트엔드를 구성하는 흐름', 'Component Service DI RxJS 라우팅', 'Angular CLI DevTools Jasmine Karma', '모듈형 화면과 폼 검증 구현', 'Observable 상태 서비스 계층 라우트 데이터', '단위 테스트 E2E 접근성 검증', 'Change Detection lazy loading 번들 최적화', '환경별 빌드 배포 릴리스 관리', '모듈 경계 DI 계층 구조', 'XSS sanitization guard 인증 보호', '업무용 Angular 관리 화면'),
    ('JavaScript', '웹 런타임에서 동작하는 언어와 비동기 흐름', '스코프 클로저 프로토타입 비동기 이벤트 루프', '브라우저 DevTools Node.js npm ESLint', 'DOM 조작과 비동기 API 호출 구현', '객체 배열 모듈 이벤트 상태', '단위 테스트 타입 체크 린트 규칙', '이벤트 루프 렌더링 블로킹 메모리', '패키지 빌드 배포 스크립트 관리', '모듈 패턴 함수형 객체지향 구조', 'XSS 입력 검증 의존성 취약점', '순수 JavaScript 웹 기능'),
    ('TypeScript', 'JavaScript 코드에 타입 계약을 세우는 개발 흐름', '타입 추론 제네릭 유니언 인터페이스', 'tsconfig ESLint Vite 타입 검사', '타입 안전한 API 응답 처리 구현', '도메인 타입 DTO 상태 타입 모델', '컴파일 오류 테스트 타입 커버리지', '타입 복잡도 빌드 시간 최적화', '패키지 타입 배포 버전 관리', '타입 계층 모듈 공개 API 설계', '민감 데이터 타입 분리 안전한 파싱', '타입 기반 프론트엔드 모듈'),
    ('Node.js', 'JavaScript 런타임으로 서버와 도구를 만드는 흐름', '이벤트 루프 Express 비동기 I/O 모듈', 'Node npm Express Jest Docker', 'REST API와 파일 처리 기능 구현', '요청 응답 미들웨어 데이터베이스 연결', 'API 테스트 에러 핸들링 로깅', '비동기 처리량 메모리 누수 프로파일링', '프로세스 관리 배포 환경 변수', '계층형 서버 구조와 모듈 분리', '인증 rate limit 입력 검증', 'Node.js API 서버'),
    ('Python', '간결한 문법으로 자동화 데이터 웹 기능을 만드는 흐름', '자료형 함수 모듈 예외 가상환경', 'Python pip venv pytest Jupyter', 'CLI 자동화와 데이터 처리 스크립트', '파일 데이터프레임 객체 패키지 구조', 'pytest 타입 힌트 린트 예외 검증', '반복문 벡터화 I/O 병목 최적화', '패키징 스케줄링 로그 관리', '모듈 패키지 객체 책임 분리', '입력 검증 시크릿 관리 의존성 점검', '자동화 스크립트와 분석 노트북'),
    ('System Design', '대규모 서비스를 요구사항과 품질 속성으로 설계하는 사고', '확장성 가용성 캐시 큐 샤딩', '다이어그램 ADR 부하 산정 도구', 'URL 단축기 피드 설계 연습', '요구사항 트래픽 저장소 API 계약', '병목 검증 장애 시나리오 일관성', '캐시 히트율 처리량 지연시간', '모니터링 롤백 장애 복구 절차', '마이크로서비스 이벤트 소싱 CQRS 구조', '인증 권한 데이터 암호화 위협 모델', '시스템 설계 문서와 발표 자료'),
    ('Java', '객체지향과 JVM 기반 애플리케이션 개발', '클래스 인터페이스 컬렉션 예외 제네릭', 'JDK IntelliJ Gradle JUnit', '콘솔 앱과 서비스 로직 구현', '객체 모델 컬렉션 스트림 패키지 구조', '단위 테스트 예외 케이스 코드 스타일', 'JVM 메모리 GC 컬렉션 성능', 'JAR 빌드 실행 환경 설정', 'OOP 계층 SOLID 패키지 분리', '입력 검증 직렬화 의존성 취약점', 'Java 서비스 모듈'),
    ('ASP.NET Core', 'C# 기반 웹 API와 서버 애플리케이션 개발', 'Controller Middleware DI Entity Framework', 'Visual Studio dotnet CLI SQL Server Swagger', 'CRUD API와 인증 흐름 구현', 'DbContext DTO 서비스 계층 라우팅', 'xUnit 통합 테스트 로깅', 'Kestrel 응답 시간 EF 쿼리 최적화', 'IIS Docker Azure 배포 설정', 'Clean Architecture 레이어드 구조', 'Identity 권한 CORS 시크릿 관리', 'ASP.NET Core 업무 API'),
    ('API Design', '클라이언트와 서버가 안정적으로 통신하는 계약 설계', 'REST 리소스 상태 코드 스키마 버전', 'OpenAPI Swagger Postman Mock Server', '회원 주문 같은 리소스 API 설계', '요청 응답 DTO 오류 모델 페이지네이션', '계약 테스트 호환성 에러 응답 검증', '응답 크기 캐싱 rate limit 최적화', '문서 배포 변경 로그 사용량 모니터링', 'API 버전 관리 리소스 경계 설계', '인증 인가 입력 검증 데이터 노출 방지', 'OpenAPI 명세와 샘플 서버'),
    ('Spring Boot', 'Spring 생태계로 웹 서비스와 비즈니스 로직을 구현하는 흐름', 'DI Bean MVC JPA Security', 'IntelliJ Gradle Spring Initializr Docker', 'REST API와 데이터 저장 기능 구현', 'Controller Service Repository Entity 구조', 'JUnit MockMvc 통합 테스트 로깅', 'JPA 쿼리 캐시 응답 시간 최적화', '프로파일 배포 Actuator 모니터링', '계층형 아키텍처 트랜잭션 경계', 'Spring Security JWT CORS 검증', 'Spring Boot 서비스 API'),
    ('Flutter', '하나의 코드베이스로 모바일 UI를 만드는 개발 흐름', 'Widget State Navigator async layout', 'Flutter SDK Dart DevTools Emulator', '크로스플랫폼 앱 화면과 API 연동', 'Provider Bloc 라우팅 로컬 저장소', '위젯 테스트 접근성 크래시 분석', '빌드 크기 렌더링 jank 최적화', '스토어 빌드 flavor 릴리스 관리', '위젯 트리 상태 관리 아키텍처', '토큰 저장 권한 플랫폼 보안', 'Flutter 모바일 앱'),
    ('C++', '성능과 메모리 제어가 필요한 시스템 개발', '포인터 RAII STL 템플릿 동시성', 'CMake gdb clang-tidy sanitizer', '자료구조와 파일 처리 프로그램 구현', '메모리 소유권 객체 수명 스레드 상태', '단위 테스트 메모리 오류 정적 분석', '할당 비용 캐시 지역성 알고리즘 최적화', '빌드 타깃 패키징 크래시 덤프 분석', '모듈 경계 헤더 라이브러리 설계', '버퍼 오버플로우 UB 입력 검증', '성능 중심 C++ 모듈'),
    ('Rust', '메모리 안전성과 성능을 함께 잡는 시스템 개발', '소유권 borrow trait enum async', 'Cargo rustfmt clippy Tokio', 'CLI 도구와 파일 처리 기능 구현', '소유권 수명 에러 처리 모듈 구조', '단위 테스트 property test clippy', 'zero-cost abstraction 할당 최소화', 'crate 배포 cross compile 로그', 'trait 기반 설계 모듈 경계', '메모리 안전성 입력 검증 unsafe 격리', 'Rust CLI 또는 서버 모듈'),
    ('Go Roadmap', '단순한 문법으로 동시성 서버와 도구를 만드는 흐름', 'goroutine channel interface error handling', 'Go toolchain gin sqlc pprof', 'HTTP API와 concurrent worker 구현', 'struct interface context 데이터 흐름', 'go test race detector 에러 케이스', 'goroutine 누수 pprof latency 최적화', 'binary 배포 systemd Docker 운영', '패키지 경계 interface 의존성 설계', 'context timeout 입력 검증', 'Go API 서버와 CLI 도구'),
    ('Design and Architecture', '문제 구조를 설계 원칙과 아키텍처 결정으로 풀어내는 흐름', 'SOLID DDD 패턴 품질 속성', 'C4 ADR UML 모델링 도구', '모듈 경계와 책임 분리 설계', '도메인 이벤트 의존성 데이터 흐름', '설계 리뷰 리스크 검증 테스트 전략', '확장 비용 복잡도 성능 트레이드오프', '운영성 로그 메트릭 장애 격리', '레이어드 헥사고날 이벤트 기반 구조', '보안 경계 권한 데이터 보호', '아키텍처 설계 문서'),
    ('GraphQL', '클라이언트가 필요한 데이터를 선언적으로 요청하는 API 방식', 'Schema Query Mutation Resolver Type', 'Apollo GraphQL Codegen GraphiQL', '게시글 댓글 API 스키마 구현', '타입 관계 resolver 데이터로더 캐시', '스키마 테스트 N+1 검증 에러 정책', 'DataLoader 쿼리 복잡도 캐싱', '스키마 배포 버전 호환성 모니터링', 'Federation 모듈화 스키마 경계', '권한 필드 마스킹 introspection 제한', 'GraphQL API와 클라이언트 연동'),
    ('React Native', 'React 방식으로 모바일 앱을 만드는 개발 흐름', 'Native component navigation bridge state', 'Expo React Native CLI Flipper EAS', '모바일 화면과 디바이스 기능 연동', 'navigation store async storage API 상태', '기기 테스트 접근성 크래시 분석', 'bridge 비용 렌더링 리스트 최적화', 'EAS build OTA 업데이트 스토어 배포', '네이티브 모듈 상태 관리 구조', '권한 토큰 저장 플랫폼 보안', 'React Native 모바일 앱'),
    ('Design System', '제품 UI를 일관된 컴포넌트와 규칙으로 운영하는 체계', '디자인 토큰 컴포넌트 패턴 접근성', 'Figma Storybook Tokens Studio npm', '버튼 입력 카드 컴포넌트 라이브러리', '토큰 테마 variant 상태 문서 구조', '시각 회귀 테스트 접근성 체크', 'CSS 번들 크기 렌더링 영향', '패키지 버전 배포 변경 로그', '토큰 계층 컴포넌트 API 설계', '색 대비 포커스 상태 사용성 안전장치', 'Storybook 기반 디자인 시스템'),
    ('Prompt Engineering', 'AI 모델이 원하는 결과를 내도록 맥락과 제약을 설계하는 기술', '지시문 컨텍스트 예시 평가 기준', 'ChatGPT Playground eval 도구', '요약 분류 생성 프롬프트 실험', '입력 형식 출력 스키마 메모리 컨텍스트', '정확도 일관성 hallucination 평가', '토큰 비용 응답 지연 프롬프트 압축', '프롬프트 버전 관리 로그 분석', '프롬프트 체인 도구 호출 구조', '프롬프트 주입 민감 정보 차단', '업무 자동화 프롬프트 세트'),
    ('MongoDB', '문서 기반 데이터 모델과 조회 패턴을 설계하는 흐름', 'Document Collection Index Aggregation', 'MongoDB Compass mongosh Atlas', '게시글 댓글 문서 모델 구현', '임베디드 문서 참조 스키마 유연성', '쿼리 결과 검증 스키마 validation', '인덱스 aggregation pipeline 최적화', 'Atlas 백업 복제 모니터링', '조회 패턴 중심 문서 모델 설계', '역할 권한 암호화 injection 방지', 'MongoDB 기반 서비스 저장소'),
    ('Linux', '서버 운영체제를 명령어와 프로세스로 다루는 능력', '파일 권한 프로세스 네트워크 systemd', 'bash ssh journalctl top vim', '로그 확인과 서비스 실행 자동화', '파일 시스템 사용자 환경 변수 포트', '명령 결과 검증 권한 오류 추적', 'CPU 메모리 I/O 네트워크 병목 분석', 'systemd cron 로그 로테이션 운영', '디렉터리 구조 프로세스 격리', '사용자 권한 방화벽 SSH 보안', 'Linux 서버 운영 실습'),
    ('Kubernetes', '컨테이너 서비스를 클러스터에서 운영하는 플랫폼', 'Pod Deployment Service Ingress ConfigMap', 'kubectl Helm kind Prometheus', '웹 서비스를 클러스터에 배포', '리소스 요청 제한 Secret 볼륨 네임스페이스', 'readiness liveness rollout 검증', 'autoscaling scheduling resource tuning', 'Helm 배포 로그 모니터링 롤백', '네트워크 정책 서비스 메시 구조', 'RBAC Secret 이미지 보안', 'Kubernetes 운영 배포 구성'),
    ('Docker', '애플리케이션 실행 환경을 이미지와 컨테이너로 고정하는 기술', 'Image Container Dockerfile Compose volume', 'Docker CLI Compose Registry', '웹 앱 컨테이너 이미지 작성', '레이어 환경 변수 네트워크 볼륨', '컨테이너 실행 검증 헬스체크', '이미지 크기 빌드 캐시 시작 시간', '레지스트리 푸시 Compose 운영', '멀티스테이지 빌드 서비스 분리', '이미지 취약점 rootless 시크릿 관리', 'Docker 기반 개발 배포 환경'),
    ('AWS', '클라우드 인프라에서 서비스를 배포 운영하는 흐름', 'EC2 S3 RDS IAM VPC Lambda', 'AWS Console CLI CloudWatch CDK', '웹 서비스 배포와 스토리지 구성', '네트워크 보안그룹 IAM 정책 리소스 태그', '헬스체크 백업 알림 권한 검증', '비용 성능 오토스케일링 지표', 'CloudWatch 로그 배포 롤백 운영', 'VPC 서브넷 로드밸런서 아키텍처', 'IAM 최소권한 암호화 키 관리', 'AWS 기반 서비스 인프라'),
    ('Terraform', '인프라를 코드로 정의하고 변경 이력을 관리하는 기술', 'Provider Resource State Module Plan', 'Terraform CLI AWS provider remote backend', 'VPC 서버 데이터베이스 코드화', 'state 변수 output workspace 구조', 'plan 검토 drift 탐지 정책 검증', '모듈 재사용 배포 시간 최적화', 'remote state lock CI 적용 운영', '모듈 경계 환경별 인프라 설계', '시크릿 노출 방지 IAM 최소권한', 'Terraform 인프라 코드 저장소'),
    ('Data Structures & Algorithms', '문제를 효율적으로 풀기 위한 자료 표현과 절차', '배열 리스트 트리 그래프 정렬 탐색', 'Python Java C++ 시각화 도구', '자료구조 구현과 문제 풀이', '노드 간선 해시 힙 스택 큐', '정답 검증 경계값 복잡도 분석', '시간복잡도 공간복잡도 최적화', '풀이 기록 테스트 케이스 관리', '문제 유형별 알고리즘 선택 구조', '오버플로우 입력 범위 예외 처리', '알고리즘 풀이 노트와 구현'),
    ('Redis', '메모리 기반 데이터 구조로 빠른 기능을 만드는 저장소', 'String Hash List Set ZSet TTL', 'redis-cli RedisInsight Docker', '캐시 세션 랭킹 기능 구현', '키 설계 만료 정책 자료구조 선택', '캐시 정합성 장애 재현 테스트', '메모리 사용량 eviction latency 최적화', 'replication persistence 모니터링', '캐시 전략 분산 락 PubSub 구조', '인증 네트워크 접근 키 노출 방지', 'Redis 캐시와 랭킹 서비스'),
    ('Git and GitHub', '변경 이력을 관리하고 협업 흐름을 만드는 도구', 'commit branch merge rebase pull request', 'Git CLI GitHub Actions Codespaces', '브랜치 전략과 PR 리뷰 실습', '커밋 단위 충돌 이력 태그 릴리스', '리뷰 체크리스트 CI 상태 검증', '히스토리 정리 큰 파일 관리', '릴리스 태그 자동화 이슈 연결', 'trunk based flow GitFlow 저장소 구조', '권한 보호 브랜치 시크릿 관리', '협업 저장소와 릴리스 기록'),
    ('PHP', '서버 렌더링과 웹 백엔드를 빠르게 만드는 언어', 'Composer PDO 세션 라우팅 템플릿', 'PHP CLI Composer Xdebug PHPUnit', '게시판 CRUD와 로그인 구현', '요청 응답 세션 데이터베이스 연결', 'PHPUnit 입력 검증 오류 로그', 'OPcache 쿼리 수 응답 시간 최적화', '배포 환경 composer autoload 운영', 'MVC 구조와 서비스 계층 분리', 'SQL Injection XSS CSRF 방어', 'PHP 웹 애플리케이션'),
    ('Cloudflare', '엣지 네트워크로 보안 성능 배포를 강화하는 플랫폼', 'DNS CDN WAF Workers Pages', 'Cloudflare Dashboard Wrangler analytics', '정적 사이트와 Workers API 배포', 'DNS 레코드 캐시 규칙 라우팅', 'WAF 규칙 로그 캐시 동작 검증', '캐시 hit ratio edge latency 최적화', 'Pages 배포 DNS 모니터링 운영', '엣지 함수 CDN 보안 계층 구조', 'DDoS 방어 TLS 토큰 보호', 'Cloudflare 기반 엣지 서비스'),
    ('AI Red Teaming', 'AI 시스템을 공격 관점에서 검증하는 보안 흐름', 'prompt injection jailbreak data exfiltration evaluation', 'LLM eval harness proxy logging 도구', 'AI 기능 공격 시나리오 작성', '프롬프트 정책 데이터 흐름 위험 모델', '공격 재현성 심각도 완화 검증', '평가 케이스 수 토큰 비용 최적화', '취약점 리포트 회귀 테스트 운영', '방어 계층 정책 필터 모니터링 구조', '민감 정보 유출 권한 우회 방지', 'AI 보안 평가 리포트'),
    ('AI Agents', '모델이 도구를 호출하며 작업을 수행하는 시스템 설계', 'tool calling planning memory orchestration', 'LangGraph OpenAI SDK vector DB workflow tool', '도구 호출 기반 업무 자동화 에이전트', '상태 메모리 작업 큐 도구 스키마', 'eval 시나리오 실패 복구 테스트', '토큰 비용 latency tool 호출 수 최적화', '실행 로그 모니터링 프롬프트 버전 관리', 'planner executor retriever 구조', '권한 제한 tool sandbox prompt injection 방어', '업무 자동화 AI 에이전트'),
    ('Next.js', 'React 기반 풀스택 웹 앱을 라우팅과 렌더링 전략으로 구성하는 프레임워크', 'App Router Server Component Route Handler', 'Next.js Vercel TypeScript Prisma', '페이지 라우팅과 API route 구현', '서버 상태 캐시 렌더링 경계 폼 액션', '컴포넌트 테스트 접근성 SEO 확인', 'ISR streaming bundle 이미지 최적화', 'Vercel 배포 환경 변수 로그', '서버 클라이언트 컴포넌트 경계 설계', '인증 쿠키 CSRF 데이터 노출 방지', 'Next.js 풀스택 웹 앱'),
    ('Code Review', '코드 변경의 의도 품질 위험을 검토하는 협업 기술', 'diff 읽기 설계 의도 테스트 위험', 'GitHub Pull Request static analysis checklist', 'PR 리뷰와 개선 제안 작성', '변경 범위 의존성 테스트 근거', '버그 재현 리뷰 기준 회귀 위험', '리뷰 시간 코멘트 품질 병목 개선', '리뷰 프로세스 CODEOWNERS 자동화', '모듈 경계 책임 변경 영향 분석', '보안 취약점 권한 데이터 노출 점검', '실전 PR 리뷰 리포트'),
    ('Kotlin', '간결한 타입 시스템으로 JVM과 Android 개발을 하는 언어', 'null safety data class coroutine extension', 'IntelliJ Gradle JUnit Android Studio', 'Kotlin 서비스 로직과 비동기 처리 구현', 'sealed class flow domain model package', '단위 테스트 null 처리 예외 케이스', 'coroutine dispatcher allocation 최적화', 'JAR Android build 배포 설정', '함수형 OOP 혼합 모듈 설계', 'null 안전성 직렬화 입력 검증', 'Kotlin 기반 앱 또는 API 모듈'),
    ('HTML', '웹 문서의 의미 구조와 접근성 기반을 만드는 기술', 'semantic tag form media metadata', '브라우저 DevTools validator accessibility checker', '시맨틱 랜딩 페이지와 폼 작성', '문서 구조 폼 데이터 링크 메타 정보', '접근성 검사 유효성 검사 SEO 확인', 'DOM 크기 렌더링 차단 요소 최적화', '정적 파일 배포 검색 엔진 노출', '정보 구조 heading landmark 설계', '폼 보안 rel 속성 개인정보 입력', '접근성 있는 HTML 페이지'),
    ('CSS', '화면 배치 스타일 반응형 표현을 제어하는 기술', 'box model flex grid cascade responsive', 'DevTools Sass PostCSS Tailwind', '반응형 레이아웃과 컴포넌트 스타일 작성', '토큰 변수 breakpoint 상태 스타일', '크로스브라우징 접근성 시각 회귀', 'layout shift selector 비용 애니메이션 최적화', 'CSS 빌드 purge 배포 관리', '레이어 cascade 컴포넌트 스타일 구조', '색 대비 focus-visible 사용자 설정 존중', '반응형 UI 스타일 시스템'),
    ('Swift & Swift UI', 'Swift 언어와 선언형 UI로 Apple 앱을 만드는 흐름', 'Swift type system SwiftUI state binding', 'Xcode Instruments TestFlight Swift Package Manager', 'SwiftUI 화면과 데이터 바인딩 구현', 'Observable 상태 navigation persistence', '단위 UI 테스트 preview 접근성', '렌더링 diff 메모리 앱 시작 시간', 'TestFlight 배포 빌드 설정 운영', 'MVVM state ownership view composition', 'Keychain 개인정보 권한 관리', 'SwiftUI iOS 앱'),
    ('Shell / Bash', '터미널 작업을 스크립트로 자동화하는 기술', 'pipe redirect variable function exit code', 'bash shellcheck cron ssh awk sed', '로그 처리와 배포 보조 스크립트 작성', '파일 경로 환경 변수 인자 처리', 'shellcheck dry run 오류 처리 검증', '프로세스 수 I/O 호출 최적화', 'cron systemd 로그 로테이션 운영', '작은 명령 조합과 스크립트 모듈화', '권한 chmod 시크릿 노출 방지', '운영 자동화 Bash 스크립트'),
    ('Laravel', 'PHP 기반으로 웹 서비스를 빠르게 만드는 프레임워크', 'Route Controller Eloquent Blade Middleware', 'Composer Artisan Sail PHPUnit', '인증 포함 CRUD 웹 서비스 구현', 'Model migration request validation session', 'Feature test validation 에러 로그', '쿼리 eager loading cache 최적화', 'queue schedule deployment env 운영', 'MVC service repository 구조', 'CSRF policy guard secret 관리', 'Laravel 업무 웹 서비스'),
    ('Elasticsearch', '검색과 로그 분석을 위한 분산 검색 엔진', 'index mapping analyzer query aggregation', 'Kibana Dev Tools Beats Logstash', '문서 검색과 필터 기능 구현', '문서 스키마 역색인 relevance score', '검색 결과 검증 mapping 테스트', 'shard 수 query latency heap 최적화', 'snapshot rollover monitoring 운영', 'index lifecycle cluster architecture', '권한 TLS field masking', '검색 서비스와 로그 대시보드'),
    ('WordPress', '콘텐츠 관리 사이트를 테마와 플러그인으로 구성하는 플랫폼', 'theme plugin post type taxonomy hook', 'WordPress Admin WP CLI Local', '커스텀 테마와 게시글 타입 구현', '콘텐츠 모델 메뉴 위젯 사용자 권한', '브라우저 테스트 플러그인 충돌 점검', '캐시 이미지 최적화 쿼리 수 개선', '백업 업데이트 배포 운영', '테마 구조 플러그인 책임 분리', '권한 nonce 업데이트 취약점 관리', 'WordPress 콘텐츠 사이트'),
    ('Django', 'Python 기반으로 안전한 웹 서비스를 빠르게 만드는 프레임워크', 'Model View Template ORM Admin', 'Django CLI pytest DRF PostgreSQL', '게시판 API와 관리자 기능 구현', 'Model migration serializer form session', '테스트 클라이언트 validation 권한 검증', 'ORM query prefetch cache 최적화', 'settings 분리 collectstatic 배포 운영', 'app 구조 service layer DRF 설계', 'CSRF authentication permission secret 관리', 'Django 웹 서비스 API'),
    ('Ruby', '표현력 있는 객체지향 스크립팅 언어 개발', 'object block module gem metaprogramming', 'Ruby CLI bundler RSpec irb', 'CLI 도구와 데이터 처리 구현', '객체 메시지 예외 gem 구조', 'RSpec 테스트 rubocop 스타일 검증', '객체 할당 enumerable 성능 최적화', 'gem 배포 스크립트 실행 운영', '모듈 mixin 책임 분리', '입력 검증 의존성 취약점 관리', 'Ruby 자동화 도구'),
    ('Ruby on Rails', '컨벤션 기반으로 웹 서비스를 빠르게 만드는 프레임워크', 'MVC ActiveRecord routing migration', 'Rails CLI bundler RSpec PostgreSQL', 'CRUD와 인증이 있는 웹 앱 구현', 'Model association controller view job', 'request spec validation authorization 검증', 'N+1 query cache background job 최적화', 'asset pipeline migration deploy 운영', 'MVC service object background job 구조', 'CSRF strong parameter secret 관리', 'Rails 웹 애플리케이션'),
    ('Claude Code', 'AI 코딩 에이전트를 개발 작업에 안전하게 연결하는 흐름', 'prompt context tool execution code review', 'Claude Code Git terminal test runner', '이슈 기반 코드 수정과 테스트 실행', '작업 컨텍스트 파일 변경 diff 기록', '테스트 결과 리뷰 hallucination 검증', '토큰 사용량 컨텍스트 크기 반복 비용', '작업 로그 커밋 단위 리뷰 운영', '에이전트 작업 범위와 책임 분리', '비밀키 보호 명령 권한 검토', 'AI 보조 개발 작업 기록'),
    ('Vibe Coding', 'AI와 빠르게 시제품을 만들되 검증으로 품질을 잡는 흐름', '요구사항 프롬프트 프로토타입 리뷰', 'ChatGPT Claude Cursor GitHub', '아이디어를 동작하는 MVP로 구현', '기능 명세 화면 흐름 코드 변경 이력', '실행 테스트 코드 리뷰 요구사항 대조', '반복 생성 비용과 수정 속도 관리', '버전 관리 피드백 반영 릴리스', '프롬프트 설계와 사람 검수 경계', '민감 정보 입력 금지 라이선스 확인', 'AI 협업 프로토타입 프로젝트'),
    ('Scala', '함수형과 객체지향을 함께 쓰는 JVM 언어 개발', 'case class pattern matching collection Future', 'sbt ScalaTest IntelliJ Akka', '데이터 처리와 API 모듈 구현', 'immutable data algebraic type stream', 'property test 타입 안정성 검증', 'lazy evaluation collection 성능 최적화', 'JAR 배포 로그 설정 운영', '함수형 계층 effect 처리 구조', '타입 안전성 입력 검증 의존성 관리', 'Scala 서비스 또는 데이터 모듈'),
    ('OpenClaw', 'AI 코딩 워크플로를 로컬 도구와 연결하는 실험적 개발 흐름', 'agent task context tool orchestration', 'OpenClaw Git terminal editor test command', '에이전트 작업 단위와 검증 루프 구성', '작업 지시 파일 범위 실행 로그 상태', '테스트 결과 diff 검토 실패 복구', '컨텍스트 크기 명령 실행 시간 최적화', '작업 기록 승인 절차 릴리스 관리', '에이전트 권한 경계와 도구 체인 설계', '명령 실행 제한 비밀 정보 보호', 'AI 에이전트 개발 워크플로');

UPDATE roadmaps r
SET
    description = detail.display_name || ' 로드맵은 ' || detail.intro_topic || '부터 ' || detail.project_topic || '까지 이어지는 DevPath 공식 학습 경로입니다.',
    info_title = detail.display_name || ' 로드맵이란 무엇인가요?',
    info_content =
        '<div class="p-6 text-sm text-gray-700 leading-relaxed space-y-6">' ||
        '<div><p class="mb-2"><span class="font-bold text-gray-900">' || detail.display_name || '</span> 로드맵은 ' || detail.intro_topic ||
        '을 기준으로 기초 개념, 실습, 품질 기준, 심화 분기를 이어 갑니다.</p><p>' || detail.core_topic ||
        '을 먼저 잡고, ' || detail.practice_topic || '을 직접 만들면서 ' || detail.project_topic || '로 정리할 수 있게 구성했습니다.</p></div>' ||
        '<div class="bg-white p-5 rounded-xl border border-gray-200 shadow-sm">' ||
        '<strong class="block text-[#00C471] mb-2"><i class="fas fa-check-circle mr-1"></i> 이 로드맵에서 익히는 것</strong>' ||
        '<ul class="list-disc pl-5 space-y-1 text-gray-600">' ||
        '<li><strong>핵심 개념:</strong> ' || detail.core_topic || '</li>' ||
        '<li><strong>실습 흐름:</strong> ' || detail.practice_topic || '</li>' ||
        '<li><strong>품질 기준:</strong> ' || detail.quality_topic || '</li>' ||
        '<li><strong>심화 분기:</strong> ' || detail.perf_topic || ', ' || detail.arch_topic || '</li>' ||
        '<li><strong>포트폴리오:</strong> ' || detail.project_topic || '</li>' ||
        '</ul></div></div>'
FROM (
    SELECT
        target.roadmap_id,
        target.display_name,
        profile.intro_topic,
        profile.core_topic,
        profile.practice_topic,
        profile.quality_topic,
        profile.perf_topic,
        profile.arch_topic,
        profile.project_topic
    FROM (
        SELECT
            r.roadmap_id,
            r.title AS roadmap_title,
            COALESCE(MAX(item.subtitle), r.title) AS display_name
        FROM roadmap_hub_items item
        JOIN roadmap_hub_sections section_item ON section_item.id = item.section_id
        JOIN roadmaps r ON r.roadmap_id = item.linked_roadmap_id
        WHERE item.linked_roadmap_id IS NOT NULL
          AND item.is_active = TRUE
          AND section_item.is_active = TRUE
          AND r.is_official = TRUE
          AND r.is_deleted = FALSE
          AND r.title <> 'Backend Master Roadmap'
        GROUP BY r.roadmap_id, r.title
        HAVING COALESCE(MAX(item.subtitle), r.title) <> 'Backend'
    ) target
    JOIN roadmap_hub_node_profile_seed profile ON profile.display_name = target.display_name
) detail
WHERE r.roadmap_id = detail.roadmap_id;

CREATE TEMPORARY TABLE roadmap_hub_node_detail_seed AS
WITH target_roadmaps AS (
    SELECT
        r.roadmap_id,
        r.title AS roadmap_title,
        COALESCE(MAX(item.subtitle), r.title) AS display_name
    FROM roadmap_hub_items item
    JOIN roadmap_hub_sections section_item ON section_item.id = item.section_id
    JOIN roadmaps r ON r.roadmap_id = item.linked_roadmap_id
    WHERE item.linked_roadmap_id IS NOT NULL
      AND item.is_active = TRUE
      AND section_item.is_active = TRUE
      AND r.is_official = TRUE
      AND r.is_deleted = FALSE
      AND r.title <> 'Backend Master Roadmap'
    GROUP BY r.roadmap_id, r.title
    HAVING COALESCE(MAX(item.subtitle), r.title) <> 'Backend'
),
node_seed(sort_order, lane_key, node_type, stage_label) AS (
    VALUES
        (1, CAST(NULL AS INTEGER), 'CONCEPT', 'FOUNDATION'),
        (2, CAST(NULL AS INTEGER), 'CONCEPT', 'FOUNDATION'),
        (3, CAST(NULL AS INTEGER), 'CONCEPT', 'FOUNDATION'),
        (4, CAST(NULL AS INTEGER), 'PRACTICE', 'PRACTICE'),
        (5, CAST(NULL AS INTEGER), 'PRACTICE', 'PRACTICE'),
        (6, CAST(NULL AS INTEGER), 'PRACTICE', 'PRACTICE'),
        (7, CAST(NULL AS INTEGER), 'CONCEPT', 'PRACTICE'),
        (8, 1, 'PRACTICE', 'ADVANCED'),
        (9, 1, 'PRACTICE', 'ADVANCED'),
        (8, 2, 'CONCEPT', 'ADVANCED'),
        (9, 2, 'PRACTICE', 'ADVANCED'),
        (10, CAST(NULL AS INTEGER), 'PROJECT', 'ADVANCED'),
        (11, CAST(NULL AS INTEGER), 'PROJECT', 'ADVANCED')
),
node_detail AS (
    SELECT
        target.roadmap_id,
        target.display_name,
        seed.node_type,
        seed.sort_order,
        seed.lane_key,
        CASE
            WHEN seed.sort_order = 1 THEN profile.core_topic
            WHEN seed.sort_order = 2 THEN profile.tool_topic
            WHEN seed.sort_order = 3 THEN profile.practice_topic
            WHEN seed.sort_order = 4 THEN profile.model_topic
            WHEN seed.sort_order = 5 THEN profile.quality_topic
            WHEN seed.sort_order = 6 THEN profile.security_topic
            WHEN seed.sort_order = 7 THEN '협업 산출물과 변경 기록'
            WHEN seed.sort_order = 8 AND seed.lane_key = 1 THEN profile.perf_topic
            WHEN seed.sort_order = 9 AND seed.lane_key = 1 THEN profile.ops_topic
            WHEN seed.sort_order = 8 AND seed.lane_key = 2 THEN profile.arch_topic
            WHEN seed.sort_order = 9 AND seed.lane_key = 2 THEN '보안 심화 ' || profile.security_topic
            WHEN seed.sort_order = 10 THEN profile.project_topic
            ELSE '포트폴리오 ' || profile.project_topic
        END AS title_topic,
        CASE
            WHEN seed.sort_order = 1 THEN profile.tool_topic
            WHEN seed.sort_order = 2 THEN profile.core_topic
            WHEN seed.sort_order = 3 THEN profile.tool_topic
            WHEN seed.sort_order = 4 THEN profile.tool_topic
            WHEN seed.sort_order = 5 THEN profile.tool_topic
            WHEN seed.sort_order = 6 THEN profile.tool_topic
            WHEN seed.sort_order = 7 THEN profile.tool_topic
            WHEN seed.sort_order = 8 AND seed.lane_key = 1 THEN profile.tool_topic
            WHEN seed.sort_order = 9 AND seed.lane_key = 1 THEN profile.tool_topic
            WHEN seed.sort_order = 8 AND seed.lane_key = 2 THEN profile.tool_topic
            WHEN seed.sort_order = 9 AND seed.lane_key = 2 THEN profile.tool_topic
            WHEN seed.sort_order = 10 THEN profile.tool_topic
            ELSE profile.tool_topic
        END AS related_topic,
        CASE
            WHEN seed.sort_order = 1 THEN target.display_name || ' 학습은 ' || profile.core_topic || '을 기준으로 시작합니다. 이 단계에서는 ' || profile.intro_topic || '의 범위를 잡고, 최종적으로 ' || profile.project_topic || '까지 이어질 학습 흐름을 확인합니다.'
            WHEN seed.sort_order = 2 THEN profile.tool_topic || '을 설치하고 기본 작업 흐름을 맞춥니다. 실습을 반복할 수 있도록 프로젝트 구조, 실행 명령, 디버깅 방법, 협업 규칙을 함께 세팅합니다.'
            WHEN seed.sort_order = 3 THEN profile.practice_topic || '을 작은 단위로 직접 구현합니다. 입력을 받고 처리한 뒤 결과를 확인하는 흐름을 만들면서 ' || profile.model_topic || '이 코드 안에서 어떻게 드러나는지 확인합니다.'
            WHEN seed.sort_order = 4 THEN profile.model_topic || '을 기준으로 데이터와 상태 흐름을 설계합니다. 어떤 정보를 어디에 두고, 어떤 이벤트가 변경을 만들며, 어떤 산출물이 남아야 하는지 ' || profile.arch_topic || ' 관점으로 정리합니다.'
            WHEN seed.sort_order = 5 THEN profile.quality_topic || '을 기준으로 결과물을 검증합니다. 정상 동작만 확인하지 않고 실패 케이스, 경계값, 리뷰 기준을 포함해 품질 기준을 세웁니다.'
            WHEN seed.sort_order = 6 THEN profile.security_topic || '을 중심으로 안정성을 보강합니다. 권한, 입력값, 예외, 장애 상황을 검토하고 운영 중 문제가 생겼을 때 추적 가능한 기준을 만듭니다.'
            WHEN seed.sort_order = 7 THEN profile.project_topic || '을 팀에 설명할 수 있도록 문서와 변경 기록을 남깁니다. 이슈, PR, 의사결정 이유, 테스트 결과를 정리해 다음 사람이 ' || profile.tool_topic || ' 흐름을 그대로 재현할 수 있게 만듭니다.'
            WHEN seed.sort_order = 8 AND seed.lane_key = 1 THEN profile.perf_topic || '을 깊게 다룹니다. 측정 지표를 먼저 정하고 병목을 찾은 뒤, ' || target.display_name || ' 결과물에서 가장 효과가 큰 최적화 순서를 선택합니다.'
            WHEN seed.sort_order = 9 AND seed.lane_key = 1 THEN profile.ops_topic || '을 운영 관점에서 설계합니다. 배포, 모니터링, 알림, 롤백, 반복 작업 자동화를 정리해 학습 결과물이 한 번 만들고 끝나는 수준에 머물지 않게 합니다.'
            WHEN seed.sort_order = 8 AND seed.lane_key = 2 THEN profile.arch_topic || '을 기준으로 구조를 다시 봅니다. 책임 경계, 모듈 분리, 확장 전략을 점검하고 ' || profile.model_topic || '이 커져도 유지보수 가능한 형태인지 판단합니다.'
            WHEN seed.sort_order = 9 AND seed.lane_key = 2 THEN profile.security_topic || '을 심화 기준으로 점검합니다. 권한, 입력값, 예외, 장애 상황을 검토하고 운영 중 문제가 생겼을 때 추적 가능한 기준을 만듭니다.'
            WHEN seed.sort_order = 10 THEN profile.project_topic || '을 하나의 완성물로 묶습니다. 요구사항, 설계, 구현, 검증, 회고가 모두 남도록 만들고 ' || profile.quality_topic || '을 통과한 결과물을 목표로 합니다.'
            ELSE profile.project_topic || ' 포트폴리오는 왜 만들었고 어떤 선택을 했는지 설명할 수 있어야 합니다. ' || profile.core_topic || ', ' || profile.arch_topic || ', ' || profile.security_topic || '에서 내린 판단을 면접 답변처럼 정리합니다.'
        END AS content
    FROM target_roadmaps target
    JOIN roadmap_hub_node_profile_seed profile ON profile.display_name = target.display_name
    CROSS JOIN node_seed seed
)
SELECT
    node_detail.roadmap_id,
    node_detail.title_topic AS title,
    node_detail.content,
    node_detail.node_type,
    node_detail.sort_order,
    node_detail.title_topic || ': 핵심 주제,' || node_detail.related_topic || ': 관련 기술' AS sub_topics,
    node_detail.lane_key
FROM node_detail;

UPDATE roadmap_nodes rn
SET
    title = detail.title,
    content = detail.content,
    node_type = detail.node_type,
    sub_topics = detail.sub_topics
FROM roadmap_hub_node_detail_seed detail
WHERE rn.roadmap_id = detail.roadmap_id
  AND rn.sort_order = detail.sort_order
  AND (
      rn.lane_key = detail.lane_key
      OR (rn.lane_key IS NULL AND detail.lane_key IS NULL)
  );

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, lane_key)
SELECT
    detail.roadmap_id,
    detail.title,
    detail.content,
    detail.node_type,
    detail.sort_order,
    detail.sub_topics,
    detail.lane_key
FROM roadmap_hub_node_detail_seed detail
WHERE NOT EXISTS (
    SELECT 1
    FROM roadmap_nodes existing
    WHERE existing.roadmap_id = detail.roadmap_id
      AND existing.sort_order = detail.sort_order
      AND (
          existing.lane_key = detail.lane_key
          OR (existing.lane_key IS NULL AND detail.lane_key IS NULL)
      )
);

DROP TABLE IF EXISTS roadmap_hub_node_detail_seed;
DROP TABLE IF EXISTS roadmap_hub_node_profile_seed;

INSERT INTO tags (name, category, is_official, is_deleted)
WITH target_roadmaps AS (
    SELECT
        r.roadmap_id,
        COALESCE(MAX(item.subtitle), r.title) AS display_name,
        CASE
            WHEN MAX(CASE WHEN section_item.section_key = 'role-based' THEN 1 ELSE 0 END) = 1 THEN 'Role Roadmap'
            ELSE 'Skill Roadmap'
        END AS tag_category
    FROM roadmap_hub_items item
    JOIN roadmap_hub_sections section_item ON section_item.id = item.section_id
    JOIN roadmaps r ON r.roadmap_id = item.linked_roadmap_id
    WHERE item.linked_roadmap_id IS NOT NULL
      AND item.is_active = TRUE
      AND section_item.is_active = TRUE
      AND r.is_official = TRUE
      AND r.is_deleted = FALSE
      AND r.title <> 'Backend Master Roadmap'
    GROUP BY r.roadmap_id, r.title
    HAVING COALESCE(MAX(item.subtitle), r.title) <> 'Backend'
),
target_nodes AS (
    SELECT
        target.display_name,
        target.tag_category,
        rn.node_id,
        rn.sort_order,
        rn.sub_topics
    FROM target_roadmaps target
    JOIN roadmap_nodes rn ON rn.roadmap_id = target.roadmap_id
),
topic_segments AS (
    SELECT
        target_nodes.node_id,
        target_nodes.tag_category,
        split_item.segment_order,
        split_part(btrim(split_item.segment), ':', 1) AS topic_text
    FROM target_nodes
    CROSS JOIN LATERAL regexp_split_to_table(COALESCE(target_nodes.sub_topics, ''), ',') WITH ORDINALITY AS split_item(segment, segment_order)
),
raw_topic_tokens AS (
    SELECT
        topic_segments.node_id,
        topic_segments.tag_category,
        topic_segments.segment_order,
        split_token.token_order,
        regexp_replace(
            regexp_replace(
                btrim(regexp_replace(split_token.token, '[^[:alnum:]가-힣+#./&-]+', '', 'g')),
                '하는$',
                ''
            ),
            '(으로|로|과|와|은|는|이|가|을|를|의)$',
            ''
        ) AS tag_name
    FROM topic_segments
    CROSS JOIN LATERAL regexp_split_to_table(topic_segments.topic_text, '\s+') WITH ORDINALITY AS split_token(token, token_order)
),
filtered_topic_tokens AS (
    SELECT node_id, tag_category, tag_name, segment_order, token_order
    FROM raw_topic_tokens
    WHERE tag_name <> ''
      AND char_length(tag_name) BETWEEN 2 AND 40
      AND tag_name NOT IN ('개요', '로드맵', '이해', '역할', '정의', '학습', '목표', '책임', '범위', '가능한', 'and', 'or', 'with', '및')
),
deduped_topic_tokens AS (
    SELECT
        node_id,
        tag_name,
        tag_category AS category,
        CASE WHEN tag_name ~ '[A-Za-z]' THEN 1 ELSE 0 END AS has_english,
        MIN(segment_order) AS segment_order,
        MIN(token_order) AS token_order
    FROM filtered_topic_tokens
    GROUP BY node_id, tag_name, tag_category
),
ranked_topic_tokens AS (
    SELECT
        node_id,
        tag_name,
        category,
        has_english,
        segment_order,
        token_order,
        ROW_NUMBER() OVER (PARTITION BY node_id ORDER BY segment_order, token_order, tag_name) AS overall_rank,
        ROW_NUMBER() OVER (PARTITION BY node_id, has_english ORDER BY segment_order, token_order, tag_name) AS language_rank
    FROM deduped_topic_tokens
),
preferred_topic_tokens AS (
    SELECT node_id, tag_name, category, has_english, segment_order, token_order, overall_rank, 0 AS priority
    FROM ranked_topic_tokens
    WHERE has_english = 1
      AND language_rank <= 4
    UNION ALL
    SELECT node_id, tag_name, category, has_english, segment_order, token_order, overall_rank, 1 AS priority
    FROM ranked_topic_tokens
    WHERE has_english = 0
      AND segment_order = 1
    UNION ALL
    SELECT node_id, tag_name, category, has_english, segment_order, token_order, overall_rank, 2 AS priority
    FROM ranked_topic_tokens
    WHERE has_english = 1
    UNION ALL
    SELECT node_id, tag_name, category, has_english, segment_order, token_order, overall_rank, 3 AS priority
    FROM ranked_topic_tokens
    WHERE has_english = 0
),
unique_topic_tokens AS (
    SELECT node_id, tag_name, category, has_english, segment_order, token_order, overall_rank, priority
    FROM (
        SELECT
            node_id,
            tag_name,
            category,
            has_english,
            segment_order,
            token_order,
            overall_rank,
            priority,
            ROW_NUMBER() OVER (PARTITION BY node_id, tag_name ORDER BY priority, overall_rank) AS duplicate_rank
        FROM preferred_topic_tokens
    ) unique_candidates
    WHERE duplicate_rank = 1
),
generated_tags AS (
    SELECT node_id, tag_name, category
    FROM (
        SELECT
            node_id,
            tag_name,
            category,
            ROW_NUMBER() OVER (PARTITION BY node_id ORDER BY priority, overall_rank, tag_name) AS tag_rank
        FROM unique_topic_tokens
    ) ranked_tags
    WHERE tag_rank <= 5
)
SELECT generated_tags.tag_name, MIN(generated_tags.category), TRUE, FALSE
FROM generated_tags
LEFT JOIN tags existing ON existing.name = generated_tags.tag_name
WHERE existing.tag_id IS NULL
GROUP BY generated_tags.tag_name;

INSERT INTO node_required_tags (node_id, tag_id)
WITH target_roadmaps AS (
    SELECT
        r.roadmap_id,
        COALESCE(MAX(item.subtitle), r.title) AS display_name
    FROM roadmap_hub_items item
    JOIN roadmap_hub_sections section_item ON section_item.id = item.section_id
    JOIN roadmaps r ON r.roadmap_id = item.linked_roadmap_id
    WHERE item.linked_roadmap_id IS NOT NULL
      AND item.is_active = TRUE
      AND section_item.is_active = TRUE
      AND r.is_official = TRUE
      AND r.is_deleted = FALSE
      AND r.title <> 'Backend Master Roadmap'
    GROUP BY r.roadmap_id, r.title
    HAVING COALESCE(MAX(item.subtitle), r.title) <> 'Backend'
),
target_nodes AS (
    SELECT
        target.display_name,
        rn.node_id,
        rn.sort_order,
        rn.sub_topics
    FROM target_roadmaps target
    JOIN roadmap_nodes rn ON rn.roadmap_id = target.roadmap_id
),
topic_segments AS (
    SELECT
        target_nodes.node_id,
        split_item.segment_order,
        split_part(btrim(split_item.segment), ':', 1) AS topic_text
    FROM target_nodes
    CROSS JOIN LATERAL regexp_split_to_table(COALESCE(target_nodes.sub_topics, ''), ',') WITH ORDINALITY AS split_item(segment, segment_order)
),
raw_topic_tokens AS (
    SELECT
        topic_segments.node_id,
        topic_segments.segment_order,
        split_token.token_order,
        regexp_replace(
            regexp_replace(
                btrim(regexp_replace(split_token.token, '[^[:alnum:]가-힣+#./&-]+', '', 'g')),
                '하는$',
                ''
            ),
            '(으로|로|과|와|은|는|이|가|을|를|의)$',
            ''
        ) AS tag_name
    FROM topic_segments
    CROSS JOIN LATERAL regexp_split_to_table(topic_segments.topic_text, '\s+') WITH ORDINALITY AS split_token(token, token_order)
),
filtered_topic_tokens AS (
    SELECT node_id, tag_name, segment_order, token_order
    FROM raw_topic_tokens
    WHERE tag_name <> ''
      AND char_length(tag_name) BETWEEN 2 AND 40
      AND tag_name NOT IN ('개요', '로드맵', '이해', '역할', '정의', '학습', '목표', '책임', '범위', '가능한', 'and', 'or', 'with', '및')
),
deduped_topic_tokens AS (
    SELECT
        node_id,
        tag_name,
        CASE WHEN tag_name ~ '[A-Za-z]' THEN 1 ELSE 0 END AS has_english,
        MIN(segment_order) AS segment_order,
        MIN(token_order) AS token_order
    FROM filtered_topic_tokens
    GROUP BY node_id, tag_name
),
ranked_topic_tokens AS (
    SELECT
        node_id,
        tag_name,
        has_english,
        segment_order,
        token_order,
        ROW_NUMBER() OVER (PARTITION BY node_id ORDER BY segment_order, token_order, tag_name) AS overall_rank,
        ROW_NUMBER() OVER (PARTITION BY node_id, has_english ORDER BY segment_order, token_order, tag_name) AS language_rank
    FROM deduped_topic_tokens
),
preferred_topic_tokens AS (
    SELECT node_id, tag_name, has_english, segment_order, token_order, overall_rank, 0 AS priority
    FROM ranked_topic_tokens
    WHERE has_english = 1
      AND language_rank <= 4
    UNION ALL
    SELECT node_id, tag_name, has_english, segment_order, token_order, overall_rank, 1 AS priority
    FROM ranked_topic_tokens
    WHERE has_english = 0
      AND segment_order = 1
    UNION ALL
    SELECT node_id, tag_name, has_english, segment_order, token_order, overall_rank, 2 AS priority
    FROM ranked_topic_tokens
    WHERE has_english = 1
    UNION ALL
    SELECT node_id, tag_name, has_english, segment_order, token_order, overall_rank, 3 AS priority
    FROM ranked_topic_tokens
    WHERE has_english = 0
),
unique_topic_tokens AS (
    SELECT node_id, tag_name, has_english, segment_order, token_order, overall_rank, priority
    FROM (
        SELECT
            node_id,
            tag_name,
            has_english,
            segment_order,
            token_order,
            overall_rank,
            priority,
            ROW_NUMBER() OVER (PARTITION BY node_id, tag_name ORDER BY priority, overall_rank) AS duplicate_rank
        FROM preferred_topic_tokens
    ) unique_candidates
    WHERE duplicate_rank = 1
),
node_tag_candidates AS (
    SELECT node_id, tag_name
    FROM (
        SELECT
            node_id,
            tag_name,
            ROW_NUMBER() OVER (PARTITION BY node_id ORDER BY priority, overall_rank, tag_name) AS tag_rank
        FROM unique_topic_tokens
    ) ranked_tags
    WHERE tag_rank <= 5
)
SELECT DISTINCT node_tags.node_id, tag_item.tag_id
FROM node_tag_candidates node_tags
JOIN tags tag_item ON tag_item.name = node_tags.tag_name
WHERE NOT EXISTS (
    SELECT 1
    FROM node_required_tags existing
    WHERE existing.node_id = node_tags.node_id
      AND existing.tag_id = tag_item.tag_id
);

-- 비백엔드 공식 로드맵 노드 태그는 백엔드 로드맵과 비슷하게 노드 sub_topics의 핵심 주제어 5개 안팎만 사용한다.
-- 로드맵 이해, 역할 정의, 학습 목표처럼 학습 행동을 설명하는 범용 태그는 필수 태그로 사용하지 않는다.

-- Roadmap Hub official roadmap free reference resources
-- Adds primary official/free documentation links to every node of each official roadmap.
INSERT INTO roadmap_node_resources (
    node_id, title, url, description, source_type, sort_order, active, created_at, updated_at
)
WITH roadmap_resource_seed(roadmap_title, resource_title, url, description, source_type, sort_order) AS (
    VALUES
        ('Frontend Entry Roadmap', 'MDN Web Docs', 'https://developer.mozilla.org/en-US/docs/Web', 'Free web platform reference for HTML, CSS, JavaScript, Web APIs, performance, and security.', 'DOCS', 1),
        ('Frontend Entry Roadmap', 'React Learn', 'https://react.dev/learn', 'Official React learning path for component-based UI development.', 'OFFICIAL', 2),
        ('Backend Master Roadmap', 'Spring Boot Reference', 'https://docs.spring.io/spring-boot/index.html', 'Official Spring Boot reference for backend application development and production features.', 'OFFICIAL', 1),
        ('Backend Master Roadmap', 'Java Documentation', 'https://docs.oracle.com/en/java/', 'Official Java documentation for language, platform, and standard library references.', 'OFFICIAL', 2),
        ('Full Stack', 'MDN Web Docs', 'https://developer.mozilla.org/en-US/docs/Web', 'Free web platform reference for full stack developers working across browser and API boundaries.', 'DOCS', 1),
        ('Full Stack', 'Spring Boot Reference', 'https://docs.spring.io/spring-boot/index.html', 'Official backend reference for building APIs and production-ready services.', 'OFFICIAL', 2),
        ('DevOps', 'Docker Docs', 'https://docs.docker.com/', 'Official Docker documentation for images, containers, Compose, and build workflows.', 'OFFICIAL', 1),
        ('DevOps', 'Kubernetes Documentation', 'https://kubernetes.io/docs/home/', 'Official Kubernetes documentation for deployment, scaling, services, and cluster operations.', 'OFFICIAL', 2),
        ('DevSecOps', 'OWASP Top 10', 'https://owasp.org/www-project-top-ten/', 'Free OWASP reference for common web application security risks and mitigations.', 'OFFICIAL', 1),
        ('DevSecOps', 'Kubernetes Security Documentation', 'https://kubernetes.io/docs/concepts/security/', 'Official Kubernetes security concepts for workloads, access, policy, and cluster hardening.', 'OFFICIAL', 2),
        ('Data Analyst', 'Pandas Documentation', 'https://pandas.pydata.org/docs/', 'Official pandas documentation for tabular data analysis and transformation.', 'OFFICIAL', 1),
        ('Data Analyst', 'Power BI Documentation', 'https://learn.microsoft.com/en-us/power-bi/', 'Microsoft Learn documentation for Power BI modeling, visualization, and reporting.', 'OFFICIAL', 2),
        ('AI Engineer', 'OpenAI API Documentation', 'https://platform.openai.com/docs', 'Official OpenAI API documentation for models, prompting, tool use, and production integration.', 'OFFICIAL', 1),
        ('AI Engineer', 'Anthropic Claude Documentation', 'https://docs.anthropic.com/en/docs/overview', 'Official Anthropic documentation for building with Claude and AI workflows.', 'OFFICIAL', 2),
        ('AI and Data Scientist', 'Scikit-learn User Guide', 'https://scikit-learn.org/stable/user_guide.html', 'Official scikit-learn guide for classical machine learning workflows.', 'OFFICIAL', 1),
        ('AI and Data Scientist', 'Pandas Documentation', 'https://pandas.pydata.org/docs/', 'Official pandas documentation for data preparation, exploration, and analysis.', 'OFFICIAL', 2),
        ('Data Engineer', 'Apache Spark Documentation', 'https://spark.apache.org/docs/latest/', 'Official Spark documentation for distributed data processing.', 'OFFICIAL', 1),
        ('Data Engineer', 'Apache Airflow Documentation', 'https://airflow.apache.org/docs/', 'Official Airflow documentation for workflow scheduling and data pipeline orchestration.', 'OFFICIAL', 2),
        ('Android', 'Android Developers Documentation', 'https://developer.android.com/docs', 'Official Android developer documentation for app architecture, UI, storage, and platform APIs.', 'OFFICIAL', 1),
        ('Android', 'Kotlin Documentation', 'https://kotlinlang.org/docs/home.html', 'Official Kotlin documentation for language features used in Android development.', 'OFFICIAL', 2),
        ('Machine Learning', 'Scikit-learn User Guide', 'https://scikit-learn.org/stable/user_guide.html', 'Official scikit-learn guide for modeling, validation, and preprocessing.', 'OFFICIAL', 1),
        ('Machine Learning', 'PyTorch Tutorials', 'https://pytorch.org/tutorials/', 'Official PyTorch tutorials for deep learning implementation and experimentation.', 'OFFICIAL', 2),
        ('PostgreSQL', 'PostgreSQL Documentation', 'https://www.postgresql.org/docs/', 'Official PostgreSQL documentation for SQL, indexes, transactions, and administration.', 'OFFICIAL', 1),
        ('PostgreSQL', 'PostgreSQL Tutorial', 'https://www.postgresql.org/docs/current/tutorial.html', 'Official PostgreSQL tutorial for practical database fundamentals.', 'OFFICIAL', 2),
        ('iOS', 'Apple Developer Documentation', 'https://developer.apple.com/documentation/', 'Official Apple developer documentation for iOS frameworks and platform APIs.', 'OFFICIAL', 1),
        ('iOS', 'Swift Documentation', 'https://developer.apple.com/swift/', 'Apple Swift documentation and learning resources for iOS development.', 'OFFICIAL', 2),
        ('Blockchain', 'Ethereum Developer Documentation', 'https://ethereum.org/developers/docs/', 'Ethereum documentation for smart contracts, accounts, transactions, and dapps.', 'DOCS', 1),
        ('Blockchain', 'Solidity Documentation', 'https://docs.soliditylang.org/', 'Official Solidity documentation for smart contract language fundamentals.', 'OFFICIAL', 2),
        ('QA', 'Playwright Documentation', 'https://playwright.dev/docs/intro', 'Official Playwright documentation for reliable browser and end-to-end testing.', 'OFFICIAL', 1),
        ('QA', 'Selenium Documentation', 'https://www.selenium.dev/documentation/', 'Official Selenium documentation for browser automation and test architecture.', 'OFFICIAL', 2),
        ('Software Architect', 'AWS Well-Architected Framework', 'https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html', 'AWS guidance for reliability, security, performance, cost, and operational excellence.', 'OFFICIAL', 1),
        ('Software Architect', 'Microsoft Azure Architecture Center', 'https://learn.microsoft.com/en-us/azure/architecture/', 'Microsoft architecture guidance for cloud application design and system patterns.', 'OFFICIAL', 2),
        ('Cyber Security', 'OWASP Top 10', 'https://owasp.org/www-project-top-ten/', 'Free OWASP reference for common application security risks.', 'OFFICIAL', 1),
        ('Cyber Security', 'NIST Cybersecurity Framework', 'https://www.nist.gov/cyberframework', 'NIST cybersecurity framework reference for identifying and managing security risk.', 'OFFICIAL', 2),
        ('UX Design', 'Material Design', 'https://m3.material.io/', 'Google Material Design guidance for accessible interface components and interaction patterns.', 'OFFICIAL', 1),
        ('UX Design', 'W3C Web Accessibility Initiative', 'https://www.w3.org/WAI/fundamentals/', 'W3C accessibility fundamentals for inclusive UX decisions.', 'OFFICIAL', 2),
        ('Technical Writer', 'Google Developer Documentation Style Guide', 'https://developers.google.com/style', 'Google style guide for clear developer documentation.', 'OFFICIAL', 1),
        ('Technical Writer', 'Microsoft Writing Style Guide', 'https://learn.microsoft.com/en-us/style-guide/welcome/', 'Microsoft writing guidance for concise, consistent technical content.', 'OFFICIAL', 2),
        ('Game Developer', 'Unity Manual', 'https://docs.unity3d.com/Manual/UnityManual.html', 'Official Unity manual for game object, scene, asset, and build workflows.', 'OFFICIAL', 1),
        ('Game Developer', 'Unreal Engine Documentation', 'https://dev.epicgames.com/documentation/en-us/unreal-engine/', 'Official Unreal Engine documentation for gameplay systems and production workflows.', 'OFFICIAL', 2),
        ('Server Side Game Developer', 'Unity Netcode Documentation', 'https://docs-multiplayer.unity3d.com/netcode/current/about/', 'Official Unity Netcode documentation for multiplayer and server-aware game systems.', 'OFFICIAL', 1),
        ('Server Side Game Developer', 'Nakama Documentation', 'https://docs.nakama.io/', 'Free Nakama documentation for realtime multiplayer, authentication, and game server features.', 'DOCS', 2),
        ('MLOps', 'MLflow Documentation', 'https://mlflow.org/docs/latest/index.html', 'Official MLflow documentation for experiment tracking, model packaging, and registry workflows.', 'OFFICIAL', 1),
        ('MLOps', 'Kubeflow Documentation', 'https://www.kubeflow.org/docs/', 'Kubeflow documentation for ML workflows on Kubernetes.', 'DOCS', 2),
        ('Product Manager', 'Atlassian Product Management Guide', 'https://www.atlassian.com/agile/product-management', 'Free product management guide for discovery, prioritization, and delivery collaboration.', 'DOCS', 1),
        ('Product Manager', 'Atlassian Agile Guide', 'https://www.atlassian.com/agile', 'Free agile product delivery guide for backlog, iteration, and team coordination.', 'DOCS', 2),
        ('Engineering Manager', 'Google Engineering Practices', 'https://google.github.io/eng-practices/', 'Free Google engineering practices for code review, readability, and engineering quality.', 'DOCS', 1),
        ('Engineering Manager', 'Microsoft Engineering Playbook', 'https://github.com/microsoft/code-with-engineering-playbook', 'Free Microsoft engineering playbook for team practices and delivery standards.', 'DOCS', 2),
        ('Developer Relations', 'Google Developer Communities', 'https://developers.google.com/community', 'Google developer community material for programs, events, and developer engagement.', 'OFFICIAL', 1),
        ('Developer Relations', 'GitHub Community Documentation', 'https://docs.github.com/en/communities', 'GitHub documentation for community health, contribution workflows, and collaboration.', 'OFFICIAL', 2),
        ('BI Analyst', 'Power BI Documentation', 'https://learn.microsoft.com/en-us/power-bi/', 'Microsoft Power BI documentation for modeling, dashboards, and analytics reports.', 'OFFICIAL', 1),
        ('BI Analyst', 'Tableau Help', 'https://help.tableau.com/current/guides/get-started-tutorial/en-us/get-started-tutorial-home.htm', 'Free Tableau getting started guide for BI dashboard creation.', 'DOCS', 2),
        ('SQL', 'PostgreSQL Documentation', 'https://www.postgresql.org/docs/', 'Official PostgreSQL documentation for SQL, transactions, indexes, and query behavior.', 'OFFICIAL', 1),
        ('SQL', 'SQLite Documentation', 'https://www.sqlite.org/docs.html', 'Official SQLite documentation for SQL features and embedded database behavior.', 'OFFICIAL', 2),
        ('Computer Science', 'CS50', 'https://cs50.harvard.edu/x/', 'Free Harvard CS50 course material for computer science fundamentals.', 'DOCS', 1),
        ('Computer Science', 'MIT OpenCourseWare Computer Science', 'https://ocw.mit.edu/search/?d=Electrical%20Engineering%20and%20Computer%20Science', 'Free MIT OpenCourseWare materials for computer science and engineering foundations.', 'DOCS', 2),
        ('React', 'React Learn', 'https://react.dev/learn', 'Official React learning path for components, state, effects, and UI composition.', 'OFFICIAL', 1),
        ('React', 'React Reference', 'https://react.dev/reference/react', 'Official React API reference for hooks, components, and runtime APIs.', 'OFFICIAL', 2),
        ('Vue', 'Vue Guide', 'https://vuejs.org/guide/introduction.html', 'Official Vue guide for progressive UI development and component patterns.', 'OFFICIAL', 1),
        ('Vue', 'Vue API Reference', 'https://vuejs.org/api/', 'Official Vue API reference for application, reactivity, and component APIs.', 'OFFICIAL', 2),
        ('Angular', 'Angular Overview', 'https://angular.dev/overview', 'Official Angular documentation for framework concepts and application structure.', 'OFFICIAL', 1),
        ('Angular', 'Angular Tutorials', 'https://angular.dev/tutorials', 'Official Angular tutorials for component and application implementation.', 'OFFICIAL', 2),
        ('JavaScript', 'MDN JavaScript', 'https://developer.mozilla.org/en-US/docs/Web/JavaScript', 'MDN JavaScript reference for language fundamentals and browser use.', 'DOCS', 1),
        ('JavaScript', 'ECMAScript Specification', 'https://tc39.es/ecma262/', 'Official ECMAScript language specification for JavaScript semantics.', 'OFFICIAL', 2),
        ('TypeScript', 'TypeScript Documentation', 'https://www.typescriptlang.org/docs/', 'Official TypeScript documentation and handbook entry point.', 'OFFICIAL', 1),
        ('TypeScript', 'TypeScript Handbook', 'https://www.typescriptlang.org/docs/handbook/intro.html', 'Official TypeScript handbook for types, generics, narrowing, and project structure.', 'OFFICIAL', 2),
        ('Node.js', 'Node.js Learn', 'https://nodejs.org/en/learn', 'Official Node.js learning material for runtime fundamentals and application patterns.', 'OFFICIAL', 1),
        ('Node.js', 'Node.js API Documentation', 'https://nodejs.org/api/', 'Official Node.js API reference for runtime modules and server-side JavaScript APIs.', 'OFFICIAL', 2),
        ('Python', 'Python Documentation', 'https://docs.python.org/3/', 'Official Python documentation for language, standard library, and tutorials.', 'OFFICIAL', 1),
        ('Python', 'Python Tutorial', 'https://docs.python.org/3/tutorial/', 'Official Python tutorial for language fundamentals and idiomatic usage.', 'OFFICIAL', 2),
        ('System Design', 'AWS Well-Architected Framework', 'https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html', 'AWS framework for designing secure, reliable, efficient, and cost-aware systems.', 'OFFICIAL', 1),
        ('System Design', 'Azure Architecture Center', 'https://learn.microsoft.com/en-us/azure/architecture/', 'Microsoft guidance for cloud system architecture patterns and tradeoffs.', 'OFFICIAL', 2),
        ('Java', 'Java Documentation', 'https://docs.oracle.com/en/java/', 'Official Java documentation for platform and language references.', 'OFFICIAL', 1),
        ('Java', 'Oracle Java Tutorials', 'https://docs.oracle.com/javase/tutorial/', 'Oracle Java tutorials for core language and platform fundamentals.', 'OFFICIAL', 2),
        ('ASP.NET Core', 'ASP.NET Core Documentation', 'https://learn.microsoft.com/en-us/aspnet/core/', 'Microsoft documentation for ASP.NET Core web applications and APIs.', 'OFFICIAL', 1),
        ('ASP.NET Core', '.NET Documentation', 'https://learn.microsoft.com/en-us/dotnet/', 'Microsoft .NET documentation for runtime, libraries, and application development.', 'OFFICIAL', 2),
        ('API Design', 'OpenAPI Specification', 'https://spec.openapis.org/oas/latest.html', 'Official OpenAPI specification for describing HTTP APIs.', 'OFFICIAL', 1),
        ('API Design', 'Microsoft REST API Guidelines', 'https://github.com/microsoft/api-guidelines', 'Free Microsoft API design guidelines for RESTful service consistency.', 'DOCS', 2),
        ('Spring Boot', 'Spring Boot Reference', 'https://docs.spring.io/spring-boot/index.html', 'Official Spring Boot reference for application development and operations.', 'OFFICIAL', 1),
        ('Spring Boot', 'Spring Guides', 'https://spring.io/guides', 'Official Spring guides for practical framework examples.', 'OFFICIAL', 2),
        ('Flutter', 'Flutter Documentation', 'https://docs.flutter.dev/', 'Official Flutter documentation for UI, platform integration, state, and deployment.', 'OFFICIAL', 1),
        ('Flutter', 'Dart Documentation', 'https://dart.dev/guides', 'Official Dart documentation for the language and ecosystem used by Flutter.', 'OFFICIAL', 2),
        ('C++', 'Cppreference', 'https://en.cppreference.com/w/', 'Free C++ language and standard library reference.', 'DOCS', 1),
        ('C++', 'ISO C++ Get Started', 'https://isocpp.org/get-started', 'Free ISO C++ getting started resources and language guidance.', 'DOCS', 2),
        ('Rust', 'The Rust Book', 'https://doc.rust-lang.org/book/', 'Official Rust book for ownership, borrowing, lifetimes, and practical Rust programming.', 'OFFICIAL', 1),
        ('Rust', 'Rust Standard Library', 'https://doc.rust-lang.org/std/', 'Official Rust standard library reference.', 'OFFICIAL', 2),
        ('Go Roadmap', 'Go Documentation', 'https://go.dev/doc/', 'Official Go documentation for language, tools, modules, and effective usage.', 'OFFICIAL', 1),
        ('Go Roadmap', 'Effective Go', 'https://go.dev/doc/effective_go', 'Official guide to idiomatic Go programming practices.', 'OFFICIAL', 2),
        ('Design and Architecture', 'AWS Well-Architected Framework', 'https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html', 'AWS architecture guidance for tradeoff-driven system design.', 'OFFICIAL', 1),
        ('Design and Architecture', 'Azure Architecture Center', 'https://learn.microsoft.com/en-us/azure/architecture/', 'Microsoft architecture center for design patterns and reference architectures.', 'OFFICIAL', 2),
        ('GraphQL', 'GraphQL Learn', 'https://graphql.org/learn/', 'Official GraphQL learning material for schemas, queries, mutations, and execution.', 'OFFICIAL', 1),
        ('GraphQL', 'GraphQL Specification', 'https://spec.graphql.org/', 'Official GraphQL specification reference.', 'OFFICIAL', 2),
        ('React Native', 'React Native Documentation', 'https://reactnative.dev/docs/getting-started', 'Official React Native documentation for native app development with React.', 'OFFICIAL', 1),
        ('React Native', 'Expo Documentation', 'https://docs.expo.dev/', 'Official Expo documentation for React Native tooling and app delivery.', 'OFFICIAL', 2),
        ('Design System', 'Material Design', 'https://m3.material.io/', 'Google Material Design system guidance for components, patterns, and accessibility.', 'OFFICIAL', 1),
        ('Design System', 'Storybook Documentation', 'https://storybook.js.org/docs', 'Official Storybook documentation for component-driven UI development.', 'OFFICIAL', 2),
        ('Prompt Engineering', 'OpenAI Prompt Engineering Guide', 'https://platform.openai.com/docs/guides/prompt-engineering', 'OpenAI guide for prompt design and model instruction patterns.', 'OFFICIAL', 1),
        ('Prompt Engineering', 'Anthropic Prompt Engineering', 'https://docs.anthropic.com/en/docs/build-with-claude/prompt-engineering/overview', 'Anthropic guide for structuring prompts and improving Claude responses.', 'OFFICIAL', 2),
        ('MongoDB', 'MongoDB Documentation', 'https://www.mongodb.com/docs/', 'Official MongoDB documentation for data modeling, queries, indexes, and operations.', 'OFFICIAL', 1),
        ('MongoDB', 'MongoDB Manual', 'https://www.mongodb.com/docs/manual/', 'Official MongoDB manual for server behavior and database features.', 'OFFICIAL', 2),
        ('Linux', 'Linux man-pages', 'https://man7.org/linux/man-pages/', 'Free Linux manual pages for commands, system calls, and core operating system behavior.', 'DOCS', 1),
        ('Linux', 'GNU Bash Manual', 'https://www.gnu.org/software/bash/manual/bash.html', 'Official GNU Bash manual for shell usage and scripting fundamentals.', 'OFFICIAL', 2),
        ('Kubernetes', 'Kubernetes Documentation', 'https://kubernetes.io/docs/home/', 'Official Kubernetes documentation for workloads, networking, storage, and operations.', 'OFFICIAL', 1),
        ('Kubernetes', 'Kubernetes Concepts', 'https://kubernetes.io/docs/concepts/', 'Official Kubernetes concepts guide for cluster architecture and resource models.', 'OFFICIAL', 2),
        ('Docker', 'Docker Docs', 'https://docs.docker.com/', 'Official Docker documentation for container development and operations.', 'OFFICIAL', 1),
        ('Docker', 'Dockerfile Reference', 'https://docs.docker.com/reference/dockerfile/', 'Official Dockerfile reference for image build instructions.', 'OFFICIAL', 2),
        ('AWS', 'AWS Documentation', 'https://docs.aws.amazon.com/', 'Official AWS documentation entry point for cloud services.', 'OFFICIAL', 1),
        ('AWS', 'AWS Well-Architected Framework', 'https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html', 'AWS framework for secure, reliable, performant, and cost-aware cloud design.', 'OFFICIAL', 2),
        ('Terraform', 'Terraform Documentation', 'https://developer.hashicorp.com/terraform/docs', 'Official Terraform documentation for infrastructure as code workflows.', 'OFFICIAL', 1),
        ('Terraform', 'Terraform AWS Provider Documentation', 'https://registry.terraform.io/providers/hashicorp/aws/latest/docs', 'Official Terraform Registry documentation for AWS provider resources.', 'OFFICIAL', 2),
        ('Data Structures & Algorithms', 'VisuAlgo', 'https://visualgo.net/en', 'Free visual explanations for core data structures and algorithms.', 'DOCS', 1),
        ('Data Structures & Algorithms', 'CP Algorithms', 'https://cp-algorithms.com/', 'Free algorithm reference covering graph, dynamic programming, math, and data structures.', 'DOCS', 2),
        ('Redis', 'Redis Documentation', 'https://redis.io/docs/latest/', 'Official Redis documentation for data structures, commands, and deployment concepts.', 'OFFICIAL', 1),
        ('Redis', 'Redis Commands', 'https://redis.io/docs/latest/commands/', 'Official Redis command reference.', 'OFFICIAL', 2),
        ('Git and GitHub', 'Git Documentation', 'https://git-scm.com/doc', 'Official Git documentation and book for version control workflows.', 'OFFICIAL', 1),
        ('Git and GitHub', 'GitHub Docs', 'https://docs.github.com/en', 'Official GitHub documentation for repositories, pull requests, actions, and collaboration.', 'OFFICIAL', 2),
        ('PHP', 'PHP Documentation', 'https://www.php.net/docs.php', 'Official PHP documentation for language and standard library references.', 'OFFICIAL', 1),
        ('PHP', 'PHP The Right Way', 'https://phptherightway.com/', 'Free community guide for modern PHP practices.', 'DOCS', 2),
        ('Cloudflare', 'Cloudflare Docs', 'https://developers.cloudflare.com/', 'Official Cloudflare developer documentation for edge, security, and deployment products.', 'OFFICIAL', 1),
        ('Cloudflare', 'Cloudflare Workers Docs', 'https://developers.cloudflare.com/workers/', 'Official Cloudflare Workers documentation for edge compute applications.', 'OFFICIAL', 2),
        ('AI Red Teaming', 'OWASP LLM Top 10', 'https://owasp.org/www-project-top-10-for-large-language-model-applications/', 'OWASP guidance for common LLM application risks and mitigations.', 'OFFICIAL', 1),
        ('AI Red Teaming', 'NIST AI Risk Management Framework', 'https://www.nist.gov/itl/ai-risk-management-framework', 'NIST framework for managing AI system risks.', 'OFFICIAL', 2),
        ('AI Agents', 'OpenAI Agents Guide', 'https://platform.openai.com/docs/guides/agents', 'OpenAI guide for building agentic workflows and tool-using AI systems.', 'OFFICIAL', 1),
        ('AI Agents', 'LangChain Documentation', 'https://python.langchain.com/docs/', 'LangChain documentation for agent and orchestration patterns.', 'DOCS', 2),
        ('Next.js', 'Next.js Documentation', 'https://nextjs.org/docs', 'Official Next.js documentation for routing, rendering, data fetching, and deployment.', 'OFFICIAL', 1),
        ('Next.js', 'React Learn', 'https://react.dev/learn', 'Official React learning path for the UI foundation used by Next.js.', 'OFFICIAL', 2),
        ('Code Review', 'Google Engineering Practices Code Review', 'https://google.github.io/eng-practices/review/', 'Free Google guidance for code review process and reviewer expectations.', 'DOCS', 1),
        ('Code Review', 'GitHub Pull Request Reviews', 'https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/reviewing-changes-in-pull-requests', 'Official GitHub documentation for reviewing changes in pull requests.', 'OFFICIAL', 2),
        ('Kotlin', 'Kotlin Documentation', 'https://kotlinlang.org/docs/home.html', 'Official Kotlin documentation for language, multiplatform, and tooling fundamentals.', 'OFFICIAL', 1),
        ('Kotlin', 'Android Kotlin Guide', 'https://developer.android.com/kotlin', 'Official Android Kotlin guide for app development.', 'OFFICIAL', 2),
        ('HTML', 'MDN HTML', 'https://developer.mozilla.org/en-US/docs/Web/HTML', 'MDN HTML reference for semantic markup and web document structure.', 'DOCS', 1),
        ('HTML', 'WHATWG HTML Standard', 'https://html.spec.whatwg.org/', 'Living HTML standard for browser behavior and markup semantics.', 'OFFICIAL', 2),
        ('CSS', 'MDN CSS', 'https://developer.mozilla.org/en-US/docs/Web/CSS', 'MDN CSS reference for styling, layout, animation, and responsive design.', 'DOCS', 1),
        ('CSS', 'CSS Working Group Drafts', 'https://drafts.csswg.org/', 'W3C CSS Working Group drafts and specifications.', 'OFFICIAL', 2),
        ('Swift & Swift UI', 'Swift Documentation', 'https://developer.apple.com/swift/', 'Apple Swift documentation and language resources.', 'OFFICIAL', 1),
        ('Swift & Swift UI', 'SwiftUI Documentation', 'https://developer.apple.com/documentation/swiftui/', 'Official Apple SwiftUI framework documentation.', 'OFFICIAL', 2),
        ('Shell / Bash', 'GNU Bash Manual', 'https://www.gnu.org/software/bash/manual/bash.html', 'Official GNU Bash manual for shell scripting and command behavior.', 'OFFICIAL', 1),
        ('Shell / Bash', 'ShellCheck Wiki', 'https://www.shellcheck.net/wiki/Home', 'Free ShellCheck reference for shell script diagnostics and best practices.', 'DOCS', 2),
        ('Laravel', 'Laravel Documentation', 'https://laravel.com/docs', 'Official Laravel documentation for framework fundamentals and application development.', 'OFFICIAL', 1),
        ('Laravel', 'PHP Documentation', 'https://www.php.net/docs.php', 'Official PHP language and standard library documentation used by Laravel developers.', 'OFFICIAL', 2),
        ('Elasticsearch', 'Elastic Docs', 'https://www.elastic.co/guide/', 'Official Elastic documentation for Elasticsearch, search, ingest, and operations.', 'OFFICIAL', 1),
        ('Elasticsearch', 'Elasticsearch Guide', 'https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html', 'Official Elasticsearch reference guide.', 'OFFICIAL', 2),
        ('WordPress', 'WordPress Developer Resources', 'https://developer.wordpress.org/', 'Official WordPress developer resources for themes, plugins, APIs, and blocks.', 'OFFICIAL', 1),
        ('WordPress', 'Learn WordPress', 'https://learn.wordpress.org/', 'Free WordPress learning materials and tutorials.', 'DOCS', 2),
        ('Django', 'Django Getting Started', 'https://www.djangoproject.com/start/', 'Official Django getting started resources.', 'OFFICIAL', 1),
        ('Django', 'Django Documentation', 'https://docs.djangoproject.com/en/stable/', 'Official Django documentation for models, views, templates, and deployment.', 'OFFICIAL', 2),
        ('Ruby', 'Ruby Documentation', 'https://www.ruby-lang.org/en/documentation/', 'Official Ruby documentation entry point.', 'OFFICIAL', 1),
        ('Ruby', 'Ruby in Twenty Minutes', 'https://www.ruby-lang.org/en/documentation/quickstart/', 'Official Ruby quickstart tutorial.', 'OFFICIAL', 2),
        ('Ruby on Rails', 'Ruby on Rails Guides', 'https://guides.rubyonrails.org/', 'Official Rails guides for MVC, Active Record, routing, and deployment.', 'OFFICIAL', 1),
        ('Ruby on Rails', 'Ruby Documentation', 'https://www.ruby-lang.org/en/documentation/', 'Official Ruby documentation for the language foundation behind Rails.', 'OFFICIAL', 2),
        ('Claude Code', 'Claude Code Documentation', 'https://docs.anthropic.com/en/docs/claude-code/overview', 'Official Anthropic Claude Code documentation for setup and agentic coding workflows.', 'OFFICIAL', 1),
        ('Claude Code', 'Claude Code Web Docs', 'https://code.claude.com/docs', 'Claude Code documentation for terminal, IDE, and browser workflows.', 'OFFICIAL', 2),
        ('Vibe Coding', 'Claude Code Documentation', 'https://docs.anthropic.com/en/docs/claude-code/overview', 'Official Claude Code documentation for AI-assisted coding workflows.', 'OFFICIAL', 1),
        ('Vibe Coding', 'OpenAI API Documentation', 'https://platform.openai.com/docs', 'Official OpenAI API documentation for AI coding assistants and workflow automation.', 'OFFICIAL', 2),
        ('Scala', 'Scala Documentation', 'https://docs.scala-lang.org/', 'Official Scala documentation and learning material.', 'OFFICIAL', 1),
        ('Scala', 'Scala 3 Book', 'https://docs.scala-lang.org/scala3/book/introduction.html', 'Official Scala 3 book for language fundamentals.', 'OFFICIAL', 2),
        ('OpenClaw', 'GitHub OpenClaw Search', 'https://github.com/search?q=OpenClaw&type=repositories', 'Free GitHub search entry for OpenClaw-related repositories and examples.', 'LINK', 1),
        ('OpenClaw', 'Open Source Guides', 'https://opensource.guide/', 'Free guide for evaluating and contributing to open source projects.', 'DOCS', 2)
)
SELECT
    rn.node_id,
    seed.resource_title,
    seed.url,
    seed.description,
    seed.source_type,
    seed.sort_order,
    TRUE,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
FROM roadmap_resource_seed seed
JOIN roadmaps r ON r.title = seed.roadmap_title
JOIN roadmap_nodes rn ON rn.roadmap_id = r.roadmap_id
WHERE r.is_official = TRUE
  AND r.is_deleted = FALSE
  AND NOT EXISTS (
      SELECT 1
      FROM roadmap_node_resources existing
      WHERE existing.node_id = rn.node_id
        AND existing.url = seed.url
  );

-- =========================
-- WEEK9_B_MENTORING_MARKET_SEED
-- =========================

-- B-1. Mentoring / Market 테스트 유저
INSERT INTO users (email, password, name, role_name, is_active, created_at, updated_at)
SELECT
    'week9.b.mentor@devpath.com',
    '$2a$10$xh6.EW/FRzJBWfxqpdXh2uTVoepPhUxQRUH5OEwk90IpYeKjegkj.',
    'B멘토 김태형',
    'ROLE_INSTRUCTOR',
    TRUE,
    NOW(),
    NOW()
WHERE NOT EXISTS (
    SELECT 1 FROM users WHERE email = 'week9.b.mentor@devpath.com'
);

INSERT INTO users (email, password, name, role_name, is_active, created_at, updated_at)
SELECT
    'week9.b.mentee@devpath.com',
    '$2a$10$xh6.EW/FRzJBWfxqpdXh2uTVoepPhUxQRUH5OEwk90IpYeKjegkj.',
    'B멘티 이서연',
    'ROLE_LEARNER',
    TRUE,
    NOW(),
    NOW()
WHERE NOT EXISTS (
    SELECT 1 FROM users WHERE email = 'week9.b.mentee@devpath.com'
);

-- B-2. 멘토링 공고
INSERT INTO mentoring_posts (
    mentor_id,
    title,
    content,
    required_stacks,
    max_participants,
    status,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    mentor.user_id,
    'WEEK9 B 백엔드 멘토링 공고',
    'Spring Boot, PR 리뷰, 채용시장 분석 기능을 함께 구현하는 멘토링입니다.',
    'Java, Spring Boot, JPA, PostgreSQL, Docker',
    5,
    'OPEN',
    FALSE,
    NOW(),
    NOW()
FROM users mentor
WHERE mentor.email = 'week9.b.mentor@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM mentoring_posts mp
      WHERE mp.title = 'WEEK9 B 백엔드 멘토링 공고'
        AND mp.is_deleted = FALSE
  );

-- B-3. 멘토링 신청
INSERT INTO mentoring_applications (
    mentoring_post_id,
    applicant_id,
    message,
    status,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    post.mentoring_post_id,
    mentee.user_id,
    '백엔드 PR 리뷰와 채용시장 분석 기능을 함께 학습하고 싶습니다.',
    'APPROVED',
    FALSE,
    NOW(),
    NOW()
FROM mentoring_posts post
JOIN users mentee ON mentee.email = 'week9.b.mentee@devpath.com'
WHERE post.title = 'WEEK9 B 백엔드 멘토링 공고'
  AND NOT EXISTS (
      SELECT 1
      FROM mentoring_applications ma
      WHERE ma.mentoring_post_id = post.mentoring_post_id
        AND ma.applicant_id = mentee.user_id
        AND ma.is_deleted = FALSE
  );

-- B-4. 승인된 멘토링
INSERT INTO mentorings (
    mentoring_post_id,
    mentor_id,
    mentee_id,
    status,
    started_at,
    ended_at,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    post.mentoring_post_id,
    mentor.user_id,
    mentee.user_id,
    'ONGOING',
    NOW(),
    NULL,
    FALSE,
    NOW(),
    NOW()
FROM mentoring_posts post
JOIN users mentor ON mentor.email = 'week9.b.mentor@devpath.com'
JOIN users mentee ON mentee.email = 'week9.b.mentee@devpath.com'
WHERE post.title = 'WEEK9 B 백엔드 멘토링 공고'
  AND NOT EXISTS (
      SELECT 1
      FROM mentorings m
      WHERE m.mentoring_post_id = post.mentoring_post_id
        AND m.mentor_id = mentor.user_id
        AND m.mentee_id = mentee.user_id
        AND m.is_deleted = FALSE
  );

-- B-5. 멘토링 미션
INSERT INTO mentoring_missions (
    mentoring_id,
    week_number,
    title,
    description,
    status,
    due_at,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    mentoring.mentoring_id,
    1,
    '1주차 PR 리뷰 미션',
    '멘토링 공고, 신청, PR 제출 흐름을 Swagger로 검증하고 PR 링크를 제출합니다.',
    'OPEN',
    NOW() + INTERVAL '7' DAY,
    FALSE,
    NOW(),
    NOW()
FROM mentorings mentoring
JOIN mentoring_posts post ON post.mentoring_post_id = mentoring.mentoring_post_id
WHERE post.title = 'WEEK9 B 백엔드 멘토링 공고'
  AND NOT EXISTS (
      SELECT 1
      FROM mentoring_missions mission
      WHERE mission.mentoring_id = mentoring.mentoring_id
        AND mission.week_number = 1
        AND mission.is_deleted = FALSE
  );

-- B-6. 멘토링 자료
INSERT INTO mentoring_materials (
    mentoring_mission_id,
    type,
    title,
    content,
    url,
    sort_order,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    mission.mentoring_mission_id,
    'URL',
    'PR 리뷰 체크리스트',
    'PR 제출 전 Controller/Service/DTO/Swagger 기준을 확인합니다.',
    'https://devpath.example.com/materials/week9-b-pr-checklist',
    1,
    FALSE,
    NOW(),
    NOW()
FROM mentoring_missions mission
JOIN mentorings mentoring ON mentoring.mentoring_id = mission.mentoring_id
JOIN mentoring_posts post ON post.mentoring_post_id = mentoring.mentoring_post_id
WHERE post.title = 'WEEK9 B 백엔드 멘토링 공고'
  AND mission.week_number = 1
  AND NOT EXISTS (
      SELECT 1
      FROM mentoring_materials material
      WHERE material.mentoring_mission_id = mission.mentoring_mission_id
        AND material.title = 'PR 리뷰 체크리스트'
        AND material.is_deleted = FALSE
  );

-- B-7. 미션 제출
INSERT INTO mission_submissions (
    mentoring_mission_id,
    submitter_id,
    status,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    mission.mentoring_mission_id,
    mentee.user_id,
    'SUBMITTED',
    FALSE,
    NOW(),
    NOW()
FROM mentoring_missions mission
JOIN mentorings mentoring ON mentoring.mentoring_id = mission.mentoring_id
JOIN mentoring_posts post ON post.mentoring_post_id = mentoring.mentoring_post_id
JOIN users mentee ON mentee.email = 'week9.b.mentee@devpath.com'
WHERE post.title = 'WEEK9 B 백엔드 멘토링 공고'
  AND mission.week_number = 1
  AND NOT EXISTS (
      SELECT 1
      FROM mission_submissions submission
      WHERE submission.mentoring_mission_id = mission.mentoring_mission_id
        AND submission.submitter_id = mentee.user_id
        AND submission.is_deleted = FALSE
  );

-- B-8. PR 제출
INSERT INTO pull_request_submissions (
    mission_submission_id,
    title,
    pr_url,
    description,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    submission.mission_submission_id,
    'WEEK9 B PR 제출',
    'https://github.com/yongha03/DevPath/pull/9001',
    '멘토링 신청부터 Q&A, 회의, AI 리뷰, 채용 분석 흐름까지 구현한 PR입니다.',
    FALSE,
    NOW(),
    NOW()
FROM mission_submissions submission
JOIN mentoring_missions mission ON mission.mentoring_mission_id = submission.mentoring_mission_id
JOIN mentorings mentoring ON mentoring.mentoring_id = mission.mentoring_id
JOIN mentoring_posts post ON post.mentoring_post_id = mentoring.mentoring_post_id
WHERE post.title = 'WEEK9 B 백엔드 멘토링 공고'
  AND mission.week_number = 1
  AND NOT EXISTS (
      SELECT 1
      FROM pull_request_submissions prs
      WHERE prs.mission_submission_id = submission.mission_submission_id
        AND prs.pr_url = 'https://github.com/yongha03/DevPath/pull/9001'
        AND prs.is_deleted = FALSE
  );

-- B-9. PR 리뷰
INSERT INTO pull_request_reviews (
    pull_request_submission_id,
    reviewer_id,
    comment,
    status,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    prs.pull_request_submission_id,
    mentor.user_id,
    'Controller가 얇고 Service 중심으로 비즈니스 로직이 분리되어 있습니다. Swagger 검증 흐름도 확인했습니다.',
    'APPROVED',
    FALSE,
    NOW(),
    NOW()
FROM pull_request_submissions prs
JOIN mission_submissions submission ON submission.mission_submission_id = prs.mission_submission_id
JOIN mentoring_missions mission ON mission.mentoring_mission_id = submission.mentoring_mission_id
JOIN mentorings mentoring ON mentoring.mentoring_id = mission.mentoring_id
JOIN mentoring_posts post ON post.mentoring_post_id = mentoring.mentoring_post_id
JOIN users mentor ON mentor.email = 'week9.b.mentor@devpath.com'
WHERE post.title = 'WEEK9 B 백엔드 멘토링 공고'
  AND prs.pr_url = 'https://github.com/yongha03/DevPath/pull/9001'
  AND NOT EXISTS (
      SELECT 1
      FROM pull_request_reviews review
      WHERE review.pull_request_submission_id = prs.pull_request_submission_id
        AND review.reviewer_id = mentor.user_id
        AND review.is_deleted = FALSE
  );

-- B-10. 라운지 신청
INSERT INTO lounge_applications (
    sender_id,
    receiver_id,
    type,
    target_id,
    target_title,
    title,
    content,
    status,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    mentee.user_id,
    mentor.user_id,
    'SQUAD_APPLICATION',
    1,
    'WEEK9 B 백엔드 라운지',
    'WEEK9 B 라운지 참여 신청',
    '백엔드 B 담당 기능 구현 라운지에 참여하고 싶습니다.',
    'APPROVED',
    FALSE,
    NOW(),
    NOW()
FROM users mentee
JOIN users mentor ON mentor.email = 'week9.b.mentor@devpath.com'
WHERE mentee.email = 'week9.b.mentee@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM lounge_applications app
      WHERE app.title = 'WEEK9 B 라운지 참여 신청'
        AND app.sender_id = mentee.user_id
        AND app.receiver_id = mentor.user_id
        AND app.is_deleted = FALSE
  );

-- B-11. 라운지 메시지
INSERT INTO application_messages (
    lounge_application_id,
    sender_id,
    content,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    app.lounge_application_id,
    mentee.user_id,
    '신청 승인 감사합니다. PR 리뷰와 채용 분석 기능부터 확인하겠습니다.',
    FALSE,
    NOW(),
    NOW()
FROM lounge_applications app
JOIN users mentee ON mentee.email = 'week9.b.mentee@devpath.com'
WHERE app.title = 'WEEK9 B 라운지 참여 신청'
  AND NOT EXISTS (
      SELECT 1
      FROM application_messages msg
      WHERE msg.lounge_application_id = app.lounge_application_id
        AND msg.sender_id = mentee.user_id
        AND msg.content = '신청 승인 감사합니다. PR 리뷰와 채용 분석 기능부터 확인하겠습니다.'
        AND msg.is_deleted = FALSE
  );

-- B-12. 멘토링 Q&A 질문
INSERT INTO mentoring_questions (
    mentoring_id,
    writer_id,
    title,
    content,
    status,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    mentoring.mentoring_id,
    mentee.user_id,
    'PR 리뷰 기준 질문',
    'AI 코드 리뷰에서 @Data, @Setter, EAGER 로딩 감지가 제대로 되는지 확인하고 싶습니다.',
    'ANSWERED',
    FALSE,
    NOW(),
    NOW()
FROM mentorings mentoring
JOIN mentoring_posts post ON post.mentoring_post_id = mentoring.mentoring_post_id
JOIN users mentee ON mentee.email = 'week9.b.mentee@devpath.com'
WHERE post.title = 'WEEK9 B 백엔드 멘토링 공고'
  AND NOT EXISTS (
      SELECT 1
      FROM mentoring_questions q
      WHERE q.mentoring_id = mentoring.mentoring_id
        AND q.title = 'PR 리뷰 기준 질문'
        AND q.is_deleted = FALSE
  );

-- B-13. 멘토링 Q&A 답변
INSERT INTO mentoring_answers (
    mentoring_question_id,
    writer_id,
    content,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    question.mentoring_question_id,
    mentor.user_id,
    'Swagger 테스트에서는 diffText에 @Data, @Setter, FetchType.EAGER, password, TODO를 포함해서 감지 결과를 확인하면 됩니다.',
    FALSE,
    NOW(),
    NOW()
FROM mentoring_questions question
JOIN users mentor ON mentor.email = 'week9.b.mentor@devpath.com'
WHERE question.title = 'PR 리뷰 기준 질문'
  AND NOT EXISTS (
      SELECT 1
      FROM mentoring_answers answer
      WHERE answer.mentoring_question_id = question.mentoring_question_id
        AND answer.writer_id = mentor.user_id
        AND answer.is_deleted = FALSE
  );

-- B-14. 회의방
INSERT INTO meeting_rooms (
    mentoring_id,
    host_id,
    title,
    meeting_url,
    recording_url,
    scheduled_at,
    started_at,
    ended_at,
    status,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    mentoring.mentoring_id,
    mentor.user_id,
    'WEEK9 B 멘토링 회의',
    'https://meet.jit.si/devpath-week9-b-mentoring',
    'https://storage.devpath.local/recordings/week9-b-meeting.mp4',
    NOW() + INTERVAL '1' DAY,
    NOW(),
    NULL,
    'OPEN',
    FALSE,
    NOW(),
    NOW()
FROM mentorings mentoring
JOIN mentoring_posts post ON post.mentoring_post_id = mentoring.mentoring_post_id
JOIN users mentor ON mentor.email = 'week9.b.mentor@devpath.com'
WHERE post.title = 'WEEK9 B 백엔드 멘토링 공고'
  AND NOT EXISTS (
      SELECT 1
      FROM meeting_rooms meeting
      WHERE meeting.mentoring_id = mentoring.mentoring_id
        AND meeting.title = 'WEEK9 B 멘토링 회의'
        AND meeting.is_deleted = FALSE
  );

-- B-15. 보이스 채널
INSERT INTO voice_channels (
    workspace_id,
    creator_id,
    name,
    description,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    1,
    mentor.user_id,
    'WEEK9 B 보이스 채널',
    '백엔드 B 담당 기능 구현 중 음성 논의를 위한 상태 저장용 채널입니다.',
    FALSE,
    NOW(),
    NOW()
FROM users mentor
WHERE mentor.email = 'week9.b.mentor@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM voice_channels channel
      WHERE channel.workspace_id = 1
        AND channel.name = 'WEEK9 B 보이스 채널'
        AND channel.is_deleted = FALSE
  );

-- B-16. AI 코드 리뷰
INSERT INTO ai_code_reviews (
    requester_id,
    pull_request_submission_id,
    title,
    diff_text,
    summary,
    comment_count,
    provider_name,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    mentee.user_id,
    prs.pull_request_submission_id,
    'WEEK9 B AI 코드 리뷰',
    '+ @Data
+ @Setter
+ @ManyToOne(fetch = FetchType.EAGER)
+ private String password;
+ // TODO: 예외 처리 추가 필요',
    '총 5개의 컨벤션 위반 가능성이 감지되었습니다.',
    5,
    'RULE_BASED',
    FALSE,
    NOW(),
    NOW()
FROM pull_request_submissions prs
JOIN mission_submissions submission ON submission.mission_submission_id = prs.mission_submission_id
JOIN users mentee ON mentee.email = 'week9.b.mentee@devpath.com'
WHERE prs.pr_url = 'https://github.com/yongha03/DevPath/pull/9001'
  AND NOT EXISTS (
      SELECT 1
      FROM ai_code_reviews review
      WHERE review.title = 'WEEK9 B AI 코드 리뷰'
        AND review.requester_id = mentee.user_id
        AND review.is_deleted = FALSE
  );

INSERT INTO ai_review_comments (
    ai_code_review_id,
    category,
    line_number,
    title,
    message,
    suggestion,
    status,
    decided_at,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    review.ai_code_review_id,
    'LOMBOK_CONVENTION',
    1,
    '@Data 사용 감지',
    '@Data는 무분별한 setter와 순환 참조 위험을 만들 수 있습니다.',
    '@Getter, @NoArgsConstructor(access = AccessLevel.PROTECTED), @Builder 조합을 사용하세요.',
    'PENDING',
    NULL,
    FALSE,
    NOW(),
    NOW()
FROM ai_code_reviews review
WHERE review.title = 'WEEK9 B AI 코드 리뷰'
  AND NOT EXISTS (
      SELECT 1
      FROM ai_review_comments comment
      WHERE comment.ai_code_review_id = review.ai_code_review_id
        AND comment.title = '@Data 사용 감지'
        AND comment.is_deleted = FALSE
  );

-- B-17. 기업
INSERT INTO companies (
    name,
    description,
    website_url,
    logo_url,
    industry,
    location,
    verification_status,
    verification_memo,
    verified_at,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    'WEEK9 B DevPath Labs',
    '개발자 성장과 채용 분석을 연결하는 HR Tech 기업입니다.',
    'https://devpath.example.com',
    'https://cdn.example.com/devpath-labs-logo.png',
    'HR Tech',
    'SEOUL',
    'VERIFIED',
    'WEEK9 B 테스트 기업 인증 완료',
    NOW(),
    FALSE,
    NOW(),
    NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM companies company
    WHERE company.name = 'WEEK9 B DevPath Labs'
      AND company.is_deleted = FALSE
);

-- B-18. 채용 공고
INSERT INTO job_postings (
    company_id,
    title,
    job_role,
    description,
    required_skills,
    region,
    career_level,
    source_url,
    source,
    status,
    deadline,
    external_job_id,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    company.company_id,
    'WEEK9 B 백엔드 주니어 개발자 채용',
    'Backend Developer',
    'Java, Spring Boot, JPA 기반 백엔드 API 개발 경험이 필요합니다. Docker와 AWS 사용 경험이 있으면 좋습니다.',
    'Java, Spring Boot, JPA, PostgreSQL, Docker, AWS',
    '서울',
    'JUNIOR',
    'https://jobs.example.com/week9-b-backend',
    'INTERNAL',
    'OPEN',
    CURRENT_DATE + 30,
    'week9-b-job-001',
    FALSE,
    NOW(),
    NOW()
FROM companies company
WHERE company.name = 'WEEK9 B DevPath Labs'
  AND NOT EXISTS (
      SELECT 1
      FROM job_postings job
      WHERE job.external_job_id = 'week9-b-job-001'
        AND job.is_deleted = FALSE
  );

-- B-19. JD 분석 태그
INSERT INTO job_skill_tags (
    job_posting_id,
    name,
    source,
    confidence_score,
    matched_keyword,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    job.job_posting_id,
    skill.name,
    'JD_RULE_BASED',
    skill.confidence_score,
    skill.matched_keyword,
    FALSE,
    NOW(),
    NOW()
FROM job_postings job
CROSS JOIN (
    VALUES
        ('Java', 0.95, 'java'),
        ('Spring Boot', 0.95, 'spring boot'),
        ('JPA', 0.95, 'jpa'),
        ('PostgreSQL', 0.95, 'postgresql'),
        ('Docker', 0.95, 'docker'),
        ('AWS', 0.95, 'aws')
) AS skill(name, confidence_score, matched_keyword)
WHERE job.external_job_id = 'week9-b-job-001'
  AND NOT EXISTS (
      SELECT 1
      FROM job_skill_tags tag
      WHERE tag.job_posting_id = job.job_posting_id
        AND tag.name = skill.name
        AND tag.is_deleted = FALSE
  );

-- B-20. Career Profile
INSERT INTO career_profiles (
    user_id,
    target_role,
    headline,
    summary,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    mentee.user_id,
    'Backend Developer',
    '문제 해결 중심의 백엔드 개발자',
    'Spring Boot 기반 API 설계와 JPA 데이터 모델링에 강점이 있습니다.',
    FALSE,
    NOW(),
    NOW()
FROM users mentee
WHERE mentee.email = 'week9.b.mentee@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM career_profiles profile
      WHERE profile.user_id = mentee.user_id
        AND profile.is_deleted = FALSE
  );

-- B-21. Profile Skill
INSERT INTO career_profile_skills (
    career_profile_id,
    name,
    level,
    self_reported,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    profile.career_profile_id,
    skill.name,
    skill.level,
    TRUE,
    FALSE,
    NOW(),
    NOW()
FROM career_profiles profile
JOIN users mentee ON mentee.user_id = profile.user_id
CROSS JOIN (
    VALUES
        ('Java', 'INTERMEDIATE'),
        ('Spring Boot', 'INTERMEDIATE'),
        ('JPA', 'INTERMEDIATE')
) AS skill(name, level)
WHERE mentee.email = 'week9.b.mentee@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM career_profile_skills cps
      WHERE cps.career_profile_id = profile.career_profile_id
        AND LOWER(cps.name) = LOWER(skill.name)
        AND cps.is_deleted = FALSE
  );

-- B-22. Career Profile Snapshot
INSERT INTO career_profile_snapshots (
    career_profile_id,
    snapshot_content,
    memo,
    created_at
)
SELECT
    profile.career_profile_id,
    'targetRole: Backend Developer
headline: 문제 해결 중심의 백엔드 개발자
summary: Spring Boot 기반 API 설계와 JPA 데이터 모델링에 강점이 있습니다.
skills: Java(INTERMEDIATE), Spring Boot(INTERMEDIATE), JPA(INTERMEDIATE)
proofCards: WEEK9 B PR 리뷰 통과#1
projects: DevPath(Backend Developer)',
    'WEEK9 B 백엔드 주니어 지원용 프로필 스냅샷',
    NOW()
FROM career_profiles profile
JOIN users mentee ON mentee.user_id = profile.user_id
WHERE mentee.email = 'week9.b.mentee@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM career_profile_snapshots snapshot
      WHERE snapshot.career_profile_id = profile.career_profile_id
        AND snapshot.memo = 'WEEK9 B 백엔드 주니어 지원용 프로필 스냅샷'
  );

-- B-23. Career Profile Version
INSERT INTO career_profile_versions (
    career_profile_id,
    career_profile_snapshot_id,
    version_number,
    description,
    version_content,
    created_at
)
SELECT
    profile.career_profile_id,
    snapshot.career_profile_snapshot_id,
    1,
    'WEEK9 B 백엔드 주니어 지원용 프로필 스냅샷',
    snapshot.snapshot_content,
    NOW()
FROM career_profiles profile
JOIN users mentee ON mentee.user_id = profile.user_id
JOIN career_profile_snapshots snapshot ON snapshot.career_profile_id = profile.career_profile_id
WHERE mentee.email = 'week9.b.mentee@devpath.com'
  AND snapshot.memo = 'WEEK9 B 백엔드 주니어 지원용 프로필 스냅샷'
  AND NOT EXISTS (
      SELECT 1
      FROM career_profile_versions version
      WHERE version.career_profile_id = profile.career_profile_id
        AND version.version_number = 1
  );

-- B-24. Sequence 보정
SELECT setval(pg_get_serial_sequence('users', 'user_id'), COALESCE((SELECT MAX(user_id) FROM users), 1));
SELECT setval(pg_get_serial_sequence('mentoring_posts', 'mentoring_post_id'), COALESCE((SELECT MAX(mentoring_post_id) FROM mentoring_posts), 1));
SELECT setval(pg_get_serial_sequence('mentoring_applications', 'mentoring_application_id'), COALESCE((SELECT MAX(mentoring_application_id) FROM mentoring_applications), 1));
SELECT setval(pg_get_serial_sequence('mentorings', 'mentoring_id'), COALESCE((SELECT MAX(mentoring_id) FROM mentorings), 1));
SELECT setval(pg_get_serial_sequence('mentoring_missions', 'mentoring_mission_id'), COALESCE((SELECT MAX(mentoring_mission_id) FROM mentoring_missions), 1));
SELECT setval(pg_get_serial_sequence('mentoring_materials', 'mentoring_material_id'), COALESCE((SELECT MAX(mentoring_material_id) FROM mentoring_materials), 1));
SELECT setval(pg_get_serial_sequence('mission_submissions', 'mission_submission_id'), COALESCE((SELECT MAX(mission_submission_id) FROM mission_submissions), 1));
SELECT setval(pg_get_serial_sequence('pull_request_submissions', 'pull_request_submission_id'), COALESCE((SELECT MAX(pull_request_submission_id) FROM pull_request_submissions), 1));
SELECT setval(pg_get_serial_sequence('pull_request_reviews', 'pull_request_review_id'), COALESCE((SELECT MAX(pull_request_review_id) FROM pull_request_reviews), 1));
SELECT setval(pg_get_serial_sequence('lounge_applications', 'lounge_application_id'), COALESCE((SELECT MAX(lounge_application_id) FROM lounge_applications), 1));
SELECT setval(pg_get_serial_sequence('application_messages', 'application_message_id'), COALESCE((SELECT MAX(application_message_id) FROM application_messages), 1));
SELECT setval(pg_get_serial_sequence('mentoring_questions', 'mentoring_question_id'), COALESCE((SELECT MAX(mentoring_question_id) FROM mentoring_questions), 1));
SELECT setval(pg_get_serial_sequence('mentoring_answers', 'mentoring_answer_id'), COALESCE((SELECT MAX(mentoring_answer_id) FROM mentoring_answers), 1));
SELECT setval(pg_get_serial_sequence('meeting_rooms', 'meeting_room_id'), COALESCE((SELECT MAX(meeting_room_id) FROM meeting_rooms), 1));
SELECT setval(pg_get_serial_sequence('voice_channels', 'voice_channel_id'), COALESCE((SELECT MAX(voice_channel_id) FROM voice_channels), 1));
SELECT setval(pg_get_serial_sequence('ai_code_reviews', 'ai_code_review_id'), COALESCE((SELECT MAX(ai_code_review_id) FROM ai_code_reviews), 1));
SELECT setval(pg_get_serial_sequence('ai_review_comments', 'ai_review_comment_id'), COALESCE((SELECT MAX(ai_review_comment_id) FROM ai_review_comments), 1));
SELECT setval(pg_get_serial_sequence('companies', 'company_id'), COALESCE((SELECT MAX(company_id) FROM companies), 1));
SELECT setval(pg_get_serial_sequence('job_postings', 'job_posting_id'), COALESCE((SELECT MAX(job_posting_id) FROM job_postings), 1));
SELECT setval(pg_get_serial_sequence('job_skill_tags', 'job_skill_tag_id'), COALESCE((SELECT MAX(job_skill_tag_id) FROM job_skill_tags), 1));
SELECT setval(pg_get_serial_sequence('career_profiles', 'career_profile_id'), COALESCE((SELECT MAX(career_profile_id) FROM career_profiles), 1));
SELECT setval(pg_get_serial_sequence('career_profile_skills', 'career_profile_skill_id'), COALESCE((SELECT MAX(career_profile_skill_id) FROM career_profile_skills), 1));
SELECT setval(pg_get_serial_sequence('career_profile_snapshots', 'career_profile_snapshot_id'), COALESCE((SELECT MAX(career_profile_snapshot_id) FROM career_profile_snapshots), 1));
SELECT setval(pg_get_serial_sequence('career_profile_versions', 'career_profile_version_id'), COALESCE((SELECT MAX(career_profile_version_id) FROM career_profile_versions), 1));
-- =============================================
-- TASK-22: Workspace 샘플 데이터
-- =============================================

DELETE FROM workspace_member wm
USING workspace w
WHERE wm.workspace_id = w.id
  AND wm.learner_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
  AND w.name NOT IN (
      '배달비 절약 플랫폼',
      '대용량 트래픽 커머스 서버',
      'Next.js 블로그 플랫폼 구축'
  );

DELETE FROM workspace_answers
WHERE workspace_question_id IN (
    SELECT workspace_question_id FROM workspace_questions
    WHERE workspace_id IN (
        SELECT id FROM workspace
        WHERE owner_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
          AND name IN ('포트폴리오 빌더 솔로', '멘토링 세션 워크스페이스', '공통 과제형 멘토링 워크스페이스', '팀 프로젝트형 멘토링 워크스페이스')
    )
);

DELETE FROM workspace_questions
WHERE workspace_id IN (
    SELECT id FROM workspace
    WHERE owner_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
      AND name IN ('포트폴리오 빌더 솔로', '멘토링 세션 워크스페이스', '공통 과제형 멘토링 워크스페이스', '팀 프로젝트형 멘토링 워크스페이스')
);

DELETE FROM qna_answers
WHERE question_id IN (
    SELECT question_id FROM qna_questions
    WHERE workspace_id IN (
        SELECT id FROM workspace
        WHERE owner_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
          AND name IN ('포트폴리오 빌더 솔로', '멘토링 세션 워크스페이스', '공통 과제형 멘토링 워크스페이스', '팀 프로젝트형 멘토링 워크스페이스')
    )
);

DELETE FROM qna_questions
WHERE workspace_id IN (
    SELECT id FROM workspace
    WHERE owner_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
      AND name IN ('포트폴리오 빌더 솔로', '멘토링 세션 워크스페이스', '공통 과제형 멘토링 워크스페이스', '팀 프로젝트형 멘토링 워크스페이스')
);

DELETE FROM workspace_notice_read
WHERE workspace_id IN (
    SELECT id FROM workspace
    WHERE owner_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
      AND name IN ('포트폴리오 빌더 솔로', '멘토링 세션 워크스페이스', '공통 과제형 멘토링 워크스페이스', '팀 프로젝트형 멘토링 워크스페이스')
);

DELETE FROM workspace_notice
WHERE workspace_id IN (
    SELECT id FROM workspace
    WHERE owner_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
      AND name IN ('포트폴리오 빌더 솔로', '멘토링 세션 워크스페이스', '공통 과제형 멘토링 워크스페이스', '팀 프로젝트형 멘토링 워크스페이스')
);

DELETE FROM voice_events
WHERE voice_channel_id IN (
    SELECT voice_channel_id FROM voice_channels
    WHERE workspace_id IN (
        SELECT id FROM workspace
        WHERE owner_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
          AND name IN ('포트폴리오 빌더 솔로', '멘토링 세션 워크스페이스', '공통 과제형 멘토링 워크스페이스', '팀 프로젝트형 멘토링 워크스페이스')
    )
);

DELETE FROM voice_participants
WHERE voice_channel_id IN (
    SELECT voice_channel_id FROM voice_channels
    WHERE workspace_id IN (
        SELECT id FROM workspace
        WHERE owner_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
          AND name IN ('포트폴리오 빌더 솔로', '멘토링 세션 워크스페이스', '공통 과제형 멘토링 워크스페이스', '팀 프로젝트형 멘토링 워크스페이스')
    )
);

DELETE FROM voice_channels
WHERE workspace_id IN (
    SELECT id FROM workspace
    WHERE owner_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
      AND name IN ('포트폴리오 빌더 솔로', '멘토링 세션 워크스페이스', '공통 과제형 멘토링 워크스페이스', '팀 프로젝트형 멘토링 워크스페이스')
);

DELETE FROM external_integration
WHERE workspace_id IN (
    SELECT id FROM workspace
    WHERE owner_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
      AND name IN ('포트폴리오 빌더 솔로', '멘토링 세션 워크스페이스', '공통 과제형 멘토링 워크스페이스', '팀 프로젝트형 멘토링 워크스페이스')
);

DELETE FROM meeting_note
WHERE workspace_id IN (
    SELECT id FROM workspace
    WHERE owner_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
      AND name IN ('포트폴리오 빌더 솔로', '멘토링 세션 워크스페이스', '공통 과제형 멘토링 워크스페이스', '팀 프로젝트형 멘토링 워크스페이스')
);

DELETE FROM workspace_doc
WHERE workspace_id IN (
    SELECT id FROM workspace
    WHERE owner_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
      AND name IN ('포트폴리오 빌더 솔로', '멘토링 세션 워크스페이스', '공통 과제형 멘토링 워크스페이스', '팀 프로젝트형 멘토링 워크스페이스')
);

DELETE FROM workspace_file
WHERE workspace_id IN (
    SELECT id FROM workspace
    WHERE owner_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
      AND name IN ('포트폴리오 빌더 솔로', '멘토링 세션 워크스페이스', '공통 과제형 멘토링 워크스페이스', '팀 프로젝트형 멘토링 워크스페이스')
);

DELETE FROM activity_log
WHERE workspace_id IN (
    SELECT id FROM workspace
    WHERE owner_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
      AND name IN ('포트폴리오 빌더 솔로', '멘토링 세션 워크스페이스', '공통 과제형 멘토링 워크스페이스', '팀 프로젝트형 멘토링 워크스페이스')
);

DELETE FROM calendar_event
WHERE workspace_id IN (
    SELECT id FROM workspace
    WHERE owner_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
      AND name IN ('포트폴리오 빌더 솔로', '멘토링 세션 워크스페이스', '공통 과제형 멘토링 워크스페이스', '팀 프로젝트형 멘토링 워크스페이스')
);

DELETE FROM milestone
WHERE workspace_id IN (
    SELECT id FROM workspace
    WHERE owner_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
      AND name IN ('포트폴리오 빌더 솔로', '멘토링 세션 워크스페이스', '공통 과제형 멘토링 워크스페이스', '팀 프로젝트형 멘토링 워크스페이스')
);

DELETE FROM workspace_task
WHERE workspace_id IN (
    SELECT id FROM workspace
    WHERE owner_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
      AND name IN ('포트폴리오 빌더 솔로', '멘토링 세션 워크스페이스', '공통 과제형 멘토링 워크스페이스', '팀 프로젝트형 멘토링 워크스페이스')
);

DELETE FROM workspace_member
WHERE workspace_id IN (
    SELECT id FROM workspace
    WHERE owner_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
      AND name IN ('포트폴리오 빌더 솔로', '멘토링 세션 워크스페이스', '공통 과제형 멘토링 워크스페이스', '팀 프로젝트형 멘토링 워크스페이스')
);

DELETE FROM workspace
WHERE owner_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
  AND name IN ('포트폴리오 빌더 솔로', '멘토링 세션 워크스페이스', '공통 과제형 멘토링 워크스페이스', '팀 프로젝트형 멘토링 워크스페이스');

INSERT INTO workspace (owner_id, name, description, type, status, is_deleted, created_at, updated_at)
SELECT
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    'DevPath 팀 워크스페이스',
    'DevPath 팀 협업을 위한 스쿼드 워크스페이스',
    'SQUAD',
    'ACTIVE',
    FALSE,
    '2026-03-23 14:00:00',
    '2026-03-23 14:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM workspace WHERE name = 'DevPath 팀 워크스페이스'
);

INSERT INTO workspace (owner_id, name, description, type, status, is_deleted, created_at, updated_at)
SELECT
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    '배달비 절약 플랫폼',
    '위치 기반 실시간 공동 구매 매칭 서비스 MVP 개발',
    'SQUAD',
    'ACTIVE',
    FALSE,
    '2026-03-23 15:00:00',
    '2026-03-23 15:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM workspace WHERE name = '배달비 절약 플랫폼'
);

INSERT INTO workspace (owner_id, name, description, type, status, is_deleted, created_at, updated_at)
SELECT
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    '대용량 트래픽 커머스 서버',
    '공통 과제형 멘토링으로 Spring Boot와 Redis를 활용한 선착순 쿠폰 시스템을 구현하는 워크스페이스',
    'MENTORING',
    'ACTIVE',
    FALSE,
    '2026-03-25 09:00:00',
    '2026-03-25 09:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM workspace WHERE name = '대용량 트래픽 커머스 서버'
);

INSERT INTO workspace (owner_id, name, description, type, status, is_deleted, created_at, updated_at)
SELECT
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    'Next.js 블로그 플랫폼 구축',
    '팀 프로젝트형 멘토링으로 역할을 나누어 Next.js 블로그 플랫폼을 완성하는 워크스페이스',
    'MENTORING',
    'ACTIVE',
    FALSE,
    '2026-03-26 09:00:00',
    '2026-03-26 09:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM workspace WHERE name = 'Next.js 블로그 플랫폼 구축'
);

-- workspace_member 샘플 데이터 (learner는 스쿼드 1개, 멘토링 2개만 연결)
INSERT INTO workspace_member (workspace_id, learner_id, joined_at)
SELECT
    (SELECT id FROM workspace WHERE name = '배달비 절약 플랫폼'),
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    '2026-03-23 14:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM workspace_member
    WHERE workspace_id = (SELECT id FROM workspace WHERE name = '배달비 절약 플랫폼')
      AND learner_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
);

INSERT INTO workspace_member (workspace_id, learner_id, joined_at)
SELECT
    (SELECT id FROM workspace WHERE name = '대용량 트래픽 커머스 서버'),
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    '2026-03-25 09:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM workspace_member
    WHERE workspace_id = (SELECT id FROM workspace WHERE name = '대용량 트래픽 커머스 서버')
      AND learner_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
);

INSERT INTO workspace_member (workspace_id, learner_id, joined_at)
SELECT
    (SELECT id FROM workspace WHERE name = 'Next.js 블로그 플랫폼 구축'),
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    '2026-03-26 09:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM workspace_member
    WHERE workspace_id = (SELECT id FROM workspace WHERE name = 'Next.js 블로그 플랫폼 구축')
      AND learner_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
);

DELETE FROM mentorings mentoring
USING mentoring_posts post
WHERE mentoring.mentoring_post_id = post.mentoring_post_id
  AND mentoring.mentee_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
  AND post.title NOT IN ('대용량 트래픽 커머스 서버', 'Next.js 블로그 플랫폼 구축');

DELETE FROM mentoring_applications application
USING mentoring_posts post
WHERE application.mentoring_post_id = post.mentoring_post_id
  AND application.applicant_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
  AND post.title NOT IN ('대용량 트래픽 커머스 서버', 'Next.js 블로그 플랫폼 구축');

DELETE FROM mentorings mentoring
USING mentoring_posts post
WHERE mentoring.mentoring_post_id = post.mentoring_post_id
  AND post.mentor_id = (SELECT user_id FROM users WHERE email = 'instructor@devpath.com')
  AND post.title = '스쿼드 런칭 팀 프로젝트 멘토링';

DELETE FROM mentoring_applications application
USING mentoring_posts post
WHERE application.mentoring_post_id = post.mentoring_post_id
  AND post.mentor_id = (SELECT user_id FROM users WHERE email = 'instructor@devpath.com')
  AND post.title = '스쿼드 런칭 팀 프로젝트 멘토링';

DELETE FROM mentoring_posts
WHERE mentor_id = (SELECT user_id FROM users WHERE email = 'instructor@devpath.com')
  AND title = '스쿼드 런칭 팀 프로젝트 멘토링';

INSERT INTO mentoring_posts (
    mentor_id,
    title,
    content,
    required_stacks,
    category,
    mentoring_type,
    duration_weeks,
    curriculum,
    deadline_at,
    current_participants,
    max_participants,
    view_count,
    status,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    mentor.user_id,
    '대용량 트래픽 커머스 서버',
    '실제 운영 환경과 유사한 트래픽 시나리오를 경험합니다. 선착순 쿠폰 발급, 재고 동시성 이슈 등을 해결해보는 백엔드 심화 과정입니다. 각자 동일한 과제를 수행하며 개별 피드백을 받습니다.',
    'Spring Boot,Redis,Kafka',
    'Backend',
    'study',
    4,
    E'요구사항 분석 및 ERD 설계, 아키텍처 리뷰\n회원/상품 기능 구현 및 단위 테스트 작성\n대용량 트래픽 처리를 위한 Redis/Kafka 도입\n부하 테스트 및 성능 최적화, 최종 발표',
    CURRENT_DATE + 14,
    5,
    10,
    0,
    'OPEN',
    FALSE,
    '2026-03-25 10:00:00',
    '2026-03-25 10:00:00'
FROM users mentor
WHERE mentor.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM mentoring_posts post
      WHERE post.title = '대용량 트래픽 커머스 서버'
        AND post.is_deleted = FALSE
  );

INSERT INTO mentoring_applications (
    mentoring_post_id,
    applicant_id,
    message,
    status,
    reject_reason,
    processed_at,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    post.mentoring_post_id,
    learner.user_id,
    '공통 과제형 멘토링으로 대용량 트래픽 과제를 수행하며 피드백을 받고 싶습니다.',
    'APPROVED',
    NULL,
    '2026-03-25 10:20:00',
    FALSE,
    '2026-03-25 10:15:00',
    '2026-03-25 10:20:00'
FROM mentoring_posts post
JOIN users learner ON learner.email = 'learner@devpath.com'
WHERE post.title = '대용량 트래픽 커머스 서버'
  AND NOT EXISTS (
      SELECT 1
      FROM mentoring_applications application
      WHERE application.mentoring_post_id = post.mentoring_post_id
        AND application.applicant_id = learner.user_id
  );

INSERT INTO mentorings (
    mentoring_post_id,
    mentor_id,
    mentee_id,
    status,
    started_at,
    ended_at,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    post.mentoring_post_id,
    mentor.user_id,
    learner.user_id,
    'ONGOING',
    '2026-03-25 11:00:00',
    NULL,
    FALSE,
    '2026-03-25 11:00:00',
    '2026-03-25 11:00:00'
FROM mentoring_posts post
JOIN users mentor ON mentor.email = 'instructor@devpath.com'
JOIN users learner ON learner.email = 'learner@devpath.com'
WHERE post.title = '대용량 트래픽 커머스 서버'
  AND NOT EXISTS (
      SELECT 1
      FROM mentorings mentoring
      WHERE mentoring.mentoring_post_id = post.mentoring_post_id
        AND mentoring.mentee_id = learner.user_id
  );

INSERT INTO mentoring_posts (
    mentor_id,
    title,
    content,
    required_stacks,
    category,
    mentoring_type,
    duration_weeks,
    curriculum,
    deadline_at,
    current_participants,
    max_participants,
    view_count,
    status,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    mentor.user_id,
    'Next.js 블로그 플랫폼 구축',
    '하나의 블로그 플랫폼을 팀원들과 역할을 나누어 기획부터 배포까지 완성합니다. SEO 최적화, 마크다운 파싱, 다크모드 등 모던 프론트엔드의 실무 스킬을 멘토와 함께 적용해봅니다.',
    'React,Next.js 14,Tailwind',
    'Frontend',
    'team',
    4,
    E'기획 리뷰 및 Next.js 14 App Router 뼈대 세팅\n각 파트별 기능 구현\n디자인 시스템 적용 및 다크모드 통합\nVercel 배포 및 성능 튜닝, 팀 회고',
    CURRENT_DATE + 2,
    3,
    4,
    0,
    'OPEN',
    FALSE,
    '2026-03-26 10:00:00',
    '2026-03-26 10:00:00'
FROM users mentor
WHERE mentor.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM mentoring_posts post
      WHERE post.title = 'Next.js 블로그 플랫폼 구축'
        AND post.is_deleted = FALSE
  );

INSERT INTO mentoring_applications (
    mentoring_post_id,
    applicant_id,
    message,
    status,
    reject_reason,
    processed_at,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    post.mentoring_post_id,
    learner.user_id,
    '팀 프로젝트형 멘토링으로 Next.js 블로그 플랫폼을 역할 분담해서 완성하고 싶습니다.',
    'APPROVED',
    NULL,
    '2026-03-26 10:20:00',
    FALSE,
    '2026-03-26 10:15:00',
    '2026-03-26 10:20:00'
FROM mentoring_posts post
JOIN users learner ON learner.email = 'learner@devpath.com'
WHERE post.title = 'Next.js 블로그 플랫폼 구축'
  AND NOT EXISTS (
      SELECT 1
      FROM mentoring_applications application
      WHERE application.mentoring_post_id = post.mentoring_post_id
        AND application.applicant_id = learner.user_id
        AND application.is_deleted = FALSE
  );

INSERT INTO mentorings (
    mentoring_post_id,
    mentor_id,
    mentee_id,
    status,
    started_at,
    ended_at,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    post.mentoring_post_id,
    mentor.user_id,
    learner.user_id,
    'ONGOING',
    '2026-03-26 11:00:00',
    NULL,
    FALSE,
    '2026-03-26 11:00:00',
    '2026-03-26 11:00:00'
FROM mentoring_posts post
JOIN users mentor ON mentor.email = 'instructor@devpath.com'
JOIN users learner ON learner.email = 'learner@devpath.com'
WHERE post.title = 'Next.js 블로그 플랫폼 구축'
  AND NOT EXISTS (
      SELECT 1
      FROM mentorings mentoring
      WHERE mentoring.mentoring_post_id = post.mentoring_post_id
        AND mentoring.mentee_id = learner.user_id
        AND mentoring.is_deleted = FALSE
  );

-- workspace_task 샘플 데이터
INSERT INTO workspace_task (workspace_id, title, description, status, priority, assignee_id, due_date, created_by_id, is_deleted, created_at, updated_at)
SELECT
    (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스'),
    '로그인 API 구현',
    'JWT 기반 로그인 및 토큰 발급 API 구현',
    'TODO',
    'HIGH',
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    '2026-06-01',
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    FALSE,
    '2026-03-23 14:00:00',
    '2026-03-23 14:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM workspace_task
    WHERE workspace_id = (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스')
      AND title = '로그인 API 구현'
);

INSERT INTO workspace_task (workspace_id, title, description, status, priority, assignee_id, due_date, created_by_id, is_deleted, created_at, updated_at)
SELECT
    (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스'),
    '칸반 보드 UI 설계',
    'React 기반 드래그앤드롭 칸반 보드 UI 설계 및 구현',
    'IN_PROGRESS',
    'MEDIUM',
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    '2026-06-10',
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    FALSE,
    '2026-03-24 09:00:00',
    '2026-03-24 09:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM workspace_task
    WHERE workspace_id = (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스')
      AND title = '칸반 보드 UI 설계'
);

INSERT INTO workspace_task (workspace_id, title, description, status, priority, assignee_id, due_date, created_by_id, is_deleted, created_at, updated_at)
SELECT
    (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스'),
    'ERD 다이어그램 작성',
    '전체 도메인 ERD 다이어그램 작성 및 리뷰',
    'DONE',
    'LOW',
    NULL,
    '2026-05-15',
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    FALSE,
    '2026-03-22 10:00:00',
    '2026-03-22 10:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM workspace_task
    WHERE workspace_id = (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스')
      AND title = 'ERD 다이어그램 작성'
);

-- milestone 샘플 데이터
INSERT INTO milestone (workspace_id, title, description, start_date, due_date, status, created_by_id, is_deleted, created_at, updated_at)
SELECT
    (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스'),
    'v1.0 MVP 릴리즈',
    '핵심 기능 완성 및 스테이징 환경 배포',
    '2026-05-01',
    '2026-06-30',
    'IN_PROGRESS',
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    FALSE,
    '2026-03-23 14:00:00',
    '2026-03-23 14:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM milestone
    WHERE workspace_id = (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스')
      AND title = 'v1.0 MVP 릴리즈'
);

INSERT INTO milestone (workspace_id, title, description, start_date, due_date, status, created_by_id, is_deleted, created_at, updated_at)
SELECT
    (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스'),
    '코드 리뷰 프로세스 정립',
    'PR 템플릿 및 리뷰 가이드라인 작성',
    '2026-04-01',
    '2026-04-30',
    'DONE',
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    FALSE,
    '2026-03-22 10:00:00',
    '2026-04-30 18:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM milestone
    WHERE workspace_id = (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스')
      AND title = '코드 리뷰 프로세스 정립'
);

-- calendar_event 샘플 데이터
INSERT INTO calendar_event (workspace_id, title, description, start_at, end_at, created_by_id, is_deleted, created_at, updated_at)
SELECT
    (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스'),
    '스프린트 킥오프 회의',
    '2주 스프린트 목표 설정 및 태스크 분배',
    '2026-06-02 10:00:00',
    '2026-06-02 11:00:00',
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    FALSE,
    '2026-03-23 14:00:00',
    '2026-03-23 14:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM calendar_event
    WHERE workspace_id = (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스')
      AND title = '스프린트 킥오프 회의'
);

INSERT INTO calendar_event (workspace_id, title, description, start_at, end_at, created_by_id, is_deleted, created_at, updated_at)
SELECT
    (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스'),
    '중간 데모',
    'v1.0 중간 진행 상황 공유 데모',
    '2026-06-16 14:00:00',
    '2026-06-16 15:00:00',
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    FALSE,
    '2026-03-24 09:00:00',
    '2026-03-24 09:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM calendar_event
    WHERE workspace_id = (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스')
      AND title = '중간 데모'
);

INSERT INTO calendar_event (workspace_id, title, description, start_at, end_at, created_by_id, is_deleted, created_at, updated_at)
SELECT
    (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스'),
    '스프린트 회고',
    '2주 스프린트 KPT 회고 미팅',
    '2026-06-30 16:00:00',
    '2026-06-30 17:00:00',
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    FALSE,
    '2026-03-25 09:00:00',
    '2026-03-25 09:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM calendar_event
    WHERE workspace_id = (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스')
      AND title = '스프린트 회고'
);

-- activity_log 샘플 데이터
INSERT INTO activity_log (workspace_id, actor_id, activity_type, description, created_at)
SELECT
    (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스'),
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    'MEMBER_JOINED',
    '학습자가 워크스페이스에 참여했습니다.',
    '2026-03-20 09:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM activity_log
    WHERE workspace_id = (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스')
      AND activity_type = 'MEMBER_JOINED'
);

INSERT INTO activity_log (workspace_id, actor_id, activity_type, description, created_at)
SELECT
    (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스'),
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    'TASK_CREATED',
    '태스크 "API 설계 완료"가 생성되었습니다.',
    '2026-03-21 10:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM activity_log
    WHERE workspace_id = (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스')
      AND activity_type = 'TASK_CREATED'
);

INSERT INTO activity_log (workspace_id, actor_id, activity_type, description, created_at)
SELECT
    (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스'),
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    'MILESTONE_CREATED',
    '마일스톤 "MVP 기능 구현 완료"가 생성되었습니다.',
    '2026-03-22 11:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM activity_log
    WHERE workspace_id = (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스')
      AND activity_type = 'MILESTONE_CREATED'
);

INSERT INTO activity_log (workspace_id, actor_id, activity_type, description, created_at)
SELECT
    (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스'),
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    'DOC_UPDATED',
    'ERD 문서가 업데이트되었습니다.',
    '2026-03-23 14:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM activity_log
    WHERE workspace_id = (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스')
      AND activity_type = 'DOC_UPDATED'
);

INSERT INTO activity_log (workspace_id, actor_id, activity_type, description, created_at)
SELECT
    (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스'),
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    'MEETING_NOTE_CREATED',
    '회의록 "스프린트 킥오프"가 생성되었습니다.',
    '2026-03-24 15:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM activity_log
    WHERE workspace_id = (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스')
      AND activity_type = 'MEETING_NOTE_CREATED'
);

-- showcase 샘플 데이터
INSERT INTO showcase (user_id, title, description, thumbnail_url, category, is_public, view_count, is_deleted, created_at, updated_at)
SELECT
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    'DevPath 학습 대시보드',
    'Spring Boot + React로 구현한 개발자 학습 경로 관리 플랫폼입니다.',
    NULL,
    'FULLSTACK',
    true,
    15,
    false,
    '2026-04-01 10:00:00',
    '2026-04-01 10:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM showcase WHERE title = 'DevPath 학습 대시보드'
);

INSERT INTO showcase (user_id, title, description, thumbnail_url, category, is_public, view_count, is_deleted, created_at, updated_at)
SELECT
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    'REST API 설계 모음집',
    'RESTful API 설계 원칙과 실제 구현 예시를 정리한 백엔드 쇼케이스입니다.',
    NULL,
    'BACKEND',
    true,
    8,
    false,
    '2026-04-05 14:00:00',
    '2026-04-05 14:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM showcase WHERE title = 'REST API 설계 모음집'
);

INSERT INTO showcase (user_id, title, description, thumbnail_url, category, is_public, view_count, is_deleted, created_at, updated_at)
SELECT
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    'React 컴포넌트 라이브러리',
    '재사용 가능한 React 컴포넌트를 Storybook으로 문서화한 프론트엔드 프로젝트입니다.',
    NULL,
    'FRONTEND',
    true,
    22,
    false,
    '2026-04-10 09:00:00',
    '2026-04-10 09:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM showcase WHERE title = 'React 컴포넌트 라이브러리'
);

-- showcase_link 샘플 데이터
INSERT INTO showcase_link (showcase_id, link_type, url)
SELECT
    (SELECT id FROM showcase WHERE title = 'DevPath 학습 대시보드'),
    'GITHUB',
    'https://github.com/example/devpath'
WHERE NOT EXISTS (
    SELECT 1 FROM showcase_link
    WHERE showcase_id = (SELECT id FROM showcase WHERE title = 'DevPath 학습 대시보드')
      AND link_type = 'GITHUB'
);

INSERT INTO showcase_link (showcase_id, link_type, url)
SELECT
    (SELECT id FROM showcase WHERE title = 'DevPath 학습 대시보드'),
    'DEMO',
    'https://devpath.example.com'
WHERE NOT EXISTS (
    SELECT 1 FROM showcase_link
    WHERE showcase_id = (SELECT id FROM showcase WHERE title = 'DevPath 학습 대시보드')
      AND link_type = 'DEMO'
);

-- showcase_comment 샘플 데이터
INSERT INTO showcase_comment (showcase_id, user_id, content, is_deleted, created_at, updated_at)
SELECT
    (SELECT id FROM showcase WHERE title = 'DevPath 학습 대시보드'),
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    '정말 잘 만든 프로젝트네요! 학습 경로 관리 기능이 인상적입니다.',
    false,
    '2026-04-02 11:00:00',
    '2026-04-02 11:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM showcase_comment
    WHERE showcase_id = (SELECT id FROM showcase WHERE title = 'DevPath 학습 대시보드')
      AND content = '정말 잘 만든 프로젝트네요! 학습 경로 관리 기능이 인상적입니다.'
);

INSERT INTO showcase_comment (showcase_id, user_id, content, is_deleted, created_at, updated_at)
SELECT
    (SELECT id FROM showcase WHERE title = 'REST API 설계 모음집'),
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    'API 설계 예시가 실무에서 바로 활용할 수 있을 것 같아요.',
    false,
    '2026-04-06 10:00:00',
    '2026-04-06 10:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM showcase_comment
    WHERE showcase_id = (SELECT id FROM showcase WHERE title = 'REST API 설계 모음집')
      AND content = 'API 설계 예시가 실무에서 바로 활용할 수 있을 것 같아요.'
);

-- showcase_like 샘플 데이터
INSERT INTO showcase_like (showcase_id, user_id, created_at)
SELECT
    (SELECT id FROM showcase WHERE title = 'DevPath 학습 대시보드'),
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    '2026-04-02 12:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM showcase_like
    WHERE showcase_id = (SELECT id FROM showcase WHERE title = 'DevPath 학습 대시보드')
      AND user_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
);

-- portfolio 샘플 데이터
INSERT INTO portfolio (user_id, title, bio, is_public, public_link_token, is_deleted, created_at, updated_at)
SELECT
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    '김하늘의 개발 포트폴리오',
    'Spring Boot와 React를 주로 사용하는 풀스택 개발자입니다.',
    false,
    NULL,
    false,
    '2026-04-01 09:00:00',
    '2026-04-01 09:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM portfolio
    WHERE user_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
      AND is_deleted = false
);

-- portfolio_item 샘플 데이터
INSERT INTO portfolio_item (portfolio_id, item_type, reference_id, sort_order, added_at)
SELECT
    (SELECT id FROM portfolio WHERE user_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com') AND is_deleted = false),
    'PROJECT',
    1,
    0,
    '2026-04-02 10:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM portfolio_item
    WHERE portfolio_id = (SELECT id FROM portfolio WHERE user_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com') AND is_deleted = false)
      AND item_type = 'PROJECT' AND reference_id = 1
);

INSERT INTO portfolio_item (portfolio_id, item_type, reference_id, sort_order, added_at)
SELECT
    (SELECT id FROM portfolio WHERE user_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com') AND is_deleted = false),
    'PROOF_CARD',
    1,
    1,
    '2026-04-02 11:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM portfolio_item
    WHERE portfolio_id = (SELECT id FROM portfolio WHERE user_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com') AND is_deleted = false)
      AND item_type = 'PROOF_CARD' AND reference_id = 1
);

-- portfolio_github_commit 샘플 데이터
INSERT INTO portfolio_github_commit (portfolio_id, repo_name, commit_message, commit_url, committed_at)
SELECT
    (SELECT id FROM portfolio WHERE user_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com') AND is_deleted = false),
    'devpath/backend',
    'feat: Workspace API 구현',
    'https://github.com/devpath/backend/commit/abc123',
    '2026-04-10 14:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM portfolio_github_commit
    WHERE portfolio_id = (SELECT id FROM portfolio WHERE user_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com') AND is_deleted = false)
      AND commit_url = 'https://github.com/devpath/backend/commit/abc123'
);

-- =============================================
-- 스쿼드 / 워크스페이스 문서 / 파일 / 회의록 샘플 데이터
-- =============================================

-- squads 샘플 데이터
INSERT INTO squads (name, description, is_archived, is_deleted, created_at, updated_at)
SELECT
    'DevPath 개발팀',
    'DevPath 서비스 개발을 위한 스쿼드',
    false,
    false,
    '2026-03-15 09:00:00',
    '2026-03-15 09:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM squads WHERE name = 'DevPath 개발팀'
);

INSERT INTO squads (name, description, is_archived, is_deleted, created_at, updated_at)
SELECT
    '포트폴리오 스터디',
    '포트폴리오 제작을 위한 스터디 스쿼드',
    false,
    false,
    '2026-03-20 10:00:00',
    '2026-03-20 10:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM squads WHERE name = '포트폴리오 스터디'
);

-- squad_members 샘플 데이터
INSERT INTO squad_members (squad_id, user_id, role, joined_at)
SELECT
    (SELECT squad_id FROM squads WHERE name = 'DevPath 개발팀'),
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    'LEADER',
    '2026-03-15 09:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM squad_members
    WHERE squad_id = (SELECT squad_id FROM squads WHERE name = 'DevPath 개발팀')
      AND user_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
);

INSERT INTO squad_members (squad_id, user_id, role, joined_at)
SELECT
    (SELECT squad_id FROM squads WHERE name = 'DevPath 개발팀'),
    (SELECT user_id FROM users WHERE email = 'frontend@devpath.com'),
    'MEMBER',
    '2026-03-16 10:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM squad_members
    WHERE squad_id = (SELECT squad_id FROM squads WHERE name = 'DevPath 개발팀')
      AND user_id = (SELECT user_id FROM users WHERE email = 'frontend@devpath.com')
);

INSERT INTO squad_members (squad_id, user_id, role, joined_at)
SELECT
    (SELECT squad_id FROM squads WHERE name = '포트폴리오 스터디'),
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    'LEADER',
    '2026-03-20 10:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM squad_members
    WHERE squad_id = (SELECT squad_id FROM squads WHERE name = '포트폴리오 스터디')
      AND user_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com')
);

-- squad_invitations 샘플 데이터
INSERT INTO squad_invitations (squad_id, inviter_id, invitee_id, status, created_at)
SELECT
    (SELECT squad_id FROM squads WHERE name = 'DevPath 개발팀'),
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    (SELECT user_id FROM users WHERE email = 'data@devpath.com'),
    'PENDING',
    '2026-03-17 11:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM squad_invitations
    WHERE squad_id = (SELECT squad_id FROM squads WHERE name = 'DevPath 개발팀')
      AND invitee_id = (SELECT user_id FROM users WHERE email = 'data@devpath.com')
);

-- workspace_file 샘플 데이터
INSERT INTO workspace_file (workspace_id, original_file_name, stored_file_name, file_path, file_size, content_type, item_type, storage_provider, uploaded_by_id, is_deleted, created_at)
SELECT
    (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스'),
    '요구사항_명세서.txt',
    'sample_requirements.txt',
    './uploads/workspace/1/sample_requirements.txt',
    1024,
    'text/plain',
    'FILE',
    'LOCAL',
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    false,
    '2026-03-24 10:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM workspace_file
    WHERE workspace_id = (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스')
      AND original_file_name = '요구사항_명세서.txt'
);

INSERT INTO workspace_file (workspace_id, original_file_name, stored_file_name, file_path, file_size, content_type, item_type, storage_provider, uploaded_by_id, is_deleted, created_at)
SELECT
    (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스'),
    '와이어프레임_v1.png',
    'sample_wireframe.png',
    './uploads/workspace/1/sample_wireframe.png',
    204800,
    'image/png',
    'FILE',
    'LOCAL',
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    false,
    '2026-03-25 14:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM workspace_file
    WHERE workspace_id = (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스')
      AND original_file_name = '와이어프레임_v1.png'
);

-- workspace_doc 샘플 데이터
INSERT INTO workspace_doc (workspace_id, doc_type, content, updated_by_id, created_at, updated_at)
SELECT
    (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스'),
    'ERD',
    'erDiagram
    USERS {
        bigint user_id PK
        varchar email
        varchar name
    }
    WORKSPACE {
        bigint id PK
        bigint owner_id FK
        varchar name
    }
    USERS ||--o{ WORKSPACE : owns',
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    '2026-03-26 09:00:00',
    '2026-03-26 09:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM workspace_doc
    WHERE workspace_id = (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스')
      AND doc_type = 'ERD'
);

INSERT INTO workspace_doc (workspace_id, doc_type, content, updated_by_id, created_at, updated_at)
SELECT
    (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스'),
    'API_SPEC',
    'openapi: 3.0.0
info:
  title: DevPath API
  version: 1.0.0
paths:
  /api/workspaces:
    get:
      summary: 워크스페이스 목록 조회',
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    '2026-03-26 10:00:00',
    '2026-03-26 10:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM workspace_doc
    WHERE workspace_id = (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스')
      AND doc_type = 'API_SPEC'
);

-- meeting_note 샘플 데이터
INSERT INTO meeting_note (workspace_id, title, content, created_by_id, is_deleted, created_at, updated_at)
SELECT
    (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스'),
    '프로젝트 킥오프 회의',
    '참석자: 전원
목표: MVP 기능 범위 확정
결정사항:
- 1차 스프린트: 로그인/회원가입, 워크스페이스 기본 기능
- 2차 스프린트: 칸반, 마일스톤
다음 회의: 2주 후',
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    false,
    '2026-03-23 15:00:00',
    '2026-03-23 15:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM meeting_note
    WHERE workspace_id = (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스')
      AND title = '프로젝트 킥오프 회의'
);

INSERT INTO meeting_note (workspace_id, title, content, created_by_id, is_deleted, created_at, updated_at)
SELECT
    (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스'),
    '스프린트 1 회고',
    '참석자: 전원
잘한 점: API 설계 빠른 완료, 팀원 간 소통 원활
개선점: 테스트 코드 작성 부족
다음 스프린트 목표: 칸반 보드 완성, 파일 업로드 기능 구현',
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    false,
    '2026-04-06 17:00:00',
    '2026-04-06 17:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM meeting_note
    WHERE workspace_id = (SELECT id FROM workspace WHERE name = 'DevPath 팀 워크스페이스')
      AND title = '스프린트 1 회고'
);

-- ============================================================
-- B. Mentoring / Workspace / PR Review / Meeting / Voice / Job / Resume seed
-- ============================================================

-- ------------------------------------------------------------
-- B-1. Users
-- password: devpath1234
-- ------------------------------------------------------------

INSERT INTO users (email, password, name, role_name, is_active, created_at, updated_at)
SELECT
    'b-learner-one@devpath.com',
    '$2a$10$xh6.EW/FRzJBWfxqpdXh2uTVoepPhUxQRUH5OEwk90IpYeKjegkj.',
    'B학습자일',
    'ROLE_LEARNER',
    TRUE,
    NOW(),
    NOW()
WHERE NOT EXISTS (
    SELECT 1 FROM users WHERE email = 'b-learner-one@devpath.com'
);

INSERT INTO users (email, password, name, role_name, is_active, created_at, updated_at)
SELECT
    'b-learner-two@devpath.com',
    '$2a$10$xh6.EW/FRzJBWfxqpdXh2uTVoepPhUxQRUH5OEwk90IpYeKjegkj.',
    'B학습자이',
    'ROLE_LEARNER',
    TRUE,
    NOW(),
    NOW()
WHERE NOT EXISTS (
    SELECT 1 FROM users WHERE email = 'b-learner-two@devpath.com'
);

INSERT INTO users (email, password, name, role_name, is_active, created_at, updated_at)
SELECT
    'b-mentor@devpath.com',
    '$2a$10$xh6.EW/FRzJBWfxqpdXh2uTVoepPhUxQRUH5OEwk90IpYeKjegkj.',
    'B멘토',
    'ROLE_INSTRUCTOR',
    TRUE,
    NOW(),
    NOW()
WHERE NOT EXISTS (
    SELECT 1 FROM users WHERE email = 'b-mentor@devpath.com'
);

-- ------------------------------------------------------------
-- B-2. Workspace / Workspace Member
-- ------------------------------------------------------------

INSERT INTO workspace (
    owner_id,
    name,
    description,
    type,
    status,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    owner.user_id,
    'B Swagger Squad Workspace',
    'B 담당 Swagger 시나리오 검증용 팀 워크스페이스입니다.',
    'SQUAD',
    'ACTIVE',
    FALSE,
    NOW(),
    NOW()
FROM users owner
WHERE owner.email = 'b-learner-one@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM workspace WHERE name = 'B Swagger Squad Workspace'
  );

INSERT INTO workspace_member (
    workspace_id,
    learner_id,
    joined_at
)
SELECT
    w.id,
    u.user_id,
    NOW()
FROM workspace w
JOIN users u ON u.email = 'b-learner-one@devpath.com'
WHERE w.name = 'B Swagger Squad Workspace'
  AND NOT EXISTS (
      SELECT 1
      FROM workspace_member wm
      WHERE wm.workspace_id = w.id
        AND wm.learner_id = u.user_id
  );

INSERT INTO workspace_member (
    workspace_id,
    learner_id,
    joined_at
)
SELECT
    w.id,
    u.user_id,
    NOW()
FROM workspace w
JOIN users u ON u.email = 'b-learner-two@devpath.com'
WHERE w.name = 'B Swagger Squad Workspace'
  AND NOT EXISTS (
      SELECT 1
      FROM workspace_member wm
      WHERE wm.workspace_id = w.id
        AND wm.learner_id = u.user_id
  );

-- ------------------------------------------------------------
-- B-3. Mentoring Post / Application / Ongoing Mentoring
-- ------------------------------------------------------------

INSERT INTO mentoring_posts (
    mentor_id,
    title,
    content,
    required_stacks,
    max_participants,
    status,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    mentor.user_id,
    'B Swagger 백엔드 멘토링',
    'PR 리뷰, 미션, 회의, Q&A 시나리오 검증용 멘토링 공고입니다.',
    'Java,Spring Boot,JPA,PostgreSQL',
    5,
    'OPEN',
    FALSE,
    NOW(),
    NOW()
FROM users mentor
WHERE mentor.email = 'b-mentor@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM mentoring_posts WHERE title = 'B Swagger 백엔드 멘토링'
  );

INSERT INTO mentoring_applications (
    mentoring_post_id,
    applicant_id,
    message,
    status,
    reject_reason,
    processed_at,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    post.mentoring_post_id,
    applicant.user_id,
    'B Swagger 시나리오 테스트를 위해 멘토링에 신청합니다.',
    'APPROVED',
    NULL,
    NOW(),
    FALSE,
    NOW(),
    NOW()
FROM mentoring_posts post
JOIN users applicant ON applicant.email = 'b-learner-one@devpath.com'
WHERE post.title = 'B Swagger 백엔드 멘토링'
  AND NOT EXISTS (
      SELECT 1
      FROM mentoring_applications ma
      WHERE ma.mentoring_post_id = post.mentoring_post_id
        AND ma.applicant_id = applicant.user_id
  );

INSERT INTO mentorings (
    mentoring_post_id,
    mentor_id,
    mentee_id,
    status,
    started_at,
    ended_at,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    post.mentoring_post_id,
    mentor.user_id,
    mentee.user_id,
    'ONGOING',
    NOW(),
    NULL,
    FALSE,
    NOW(),
    NOW()
FROM mentoring_posts post
JOIN users mentor ON mentor.email = 'b-mentor@devpath.com'
JOIN users mentee ON mentee.email = 'b-learner-one@devpath.com'
WHERE post.title = 'B Swagger 백엔드 멘토링'
  AND NOT EXISTS (
      SELECT 1
      FROM mentorings m
      WHERE m.mentoring_post_id = post.mentoring_post_id
        AND m.mentor_id = mentor.user_id
        AND m.mentee_id = mentee.user_id
        AND m.is_deleted = FALSE
  );

-- ------------------------------------------------------------
-- B-4. Mentoring Mission / Material
-- ------------------------------------------------------------

INSERT INTO mentoring_missions (
    mentoring_id,
    week_number,
    title,
    description,
    due_at,
    status,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    m.mentoring_id,
    1,
    'B 1주차 PR 리뷰 미션',
    '멘토링 Q&A, PR 제출, 코드 리뷰, 미션 Pass/Reject 흐름을 검증합니다.',
    NOW() + INTERVAL '7' DAY,
    'OPEN',
    FALSE,
    NOW(),
    NOW()
FROM mentorings m
JOIN mentoring_posts post ON post.mentoring_post_id = m.mentoring_post_id
WHERE post.title = 'B Swagger 백엔드 멘토링'
  AND NOT EXISTS (
      SELECT 1
      FROM mentoring_missions mm
      WHERE mm.mentoring_id = m.mentoring_id
        AND mm.week_number = 1
        AND mm.title = 'B 1주차 PR 리뷰 미션'
  );

INSERT INTO mentoring_materials (
    mentoring_mission_id,
    type,
    title,
    content,
    url,
    sort_order,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    mission.mentoring_mission_id,
    'TEXT',
    'B 1주차 가이드라인',
    'Controller는 Thin하게 유지하고, 검증과 상태 전이는 Service에서 처리합니다.',
    NULL,
    1,
    FALSE,
    NOW(),
    NOW()
FROM mentoring_missions mission
JOIN mentorings m ON m.mentoring_id = mission.mentoring_id
JOIN mentoring_posts post ON post.mentoring_post_id = m.mentoring_post_id
WHERE post.title = 'B Swagger 백엔드 멘토링'
  AND mission.title = 'B 1주차 PR 리뷰 미션'
  AND NOT EXISTS (
      SELECT 1
      FROM mentoring_materials material
      WHERE material.mentoring_mission_id = mission.mentoring_mission_id
        AND material.title = 'B 1주차 가이드라인'
  );

-- ------------------------------------------------------------
-- B-5. PR Submission seed
-- ------------------------------------------------------------

INSERT INTO mission_submissions (
    mentoring_mission_id,
    submitter_id,
    status,
    feedback,
    graded_at,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    mission.mentoring_mission_id,
    submitter.user_id,
    'SUBMITTED',
    NULL,
    NULL,
    FALSE,
    NOW(),
    NOW()
FROM mentoring_missions mission
JOIN mentorings m ON m.mentoring_id = mission.mentoring_id
JOIN mentoring_posts post ON post.mentoring_post_id = m.mentoring_post_id
JOIN users submitter ON submitter.email = 'b-learner-one@devpath.com'
WHERE post.title = 'B Swagger 백엔드 멘토링'
  AND mission.title = 'B 1주차 PR 리뷰 미션'
  AND NOT EXISTS (
      SELECT 1
      FROM mission_submissions ms
      WHERE ms.mentoring_mission_id = mission.mentoring_mission_id
        AND ms.submitter_id = submitter.user_id
        AND ms.is_deleted = FALSE
  );

INSERT INTO pull_request_submissions (
    mission_submission_id,
    pr_url,
    title,
    description,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    ms.mission_submission_id,
    'https://github.com/yongha03/DevPath/pull/9001',
    'B 1주차 멘토링 미션 PR',
    'B Swagger 테스트용 PR 제출 데이터입니다.',
    FALSE,
    NOW(),
    NOW()
FROM mission_submissions ms
JOIN mentoring_missions mission ON mission.mentoring_mission_id = ms.mentoring_mission_id
JOIN mentorings m ON m.mentoring_id = mission.mentoring_id
JOIN mentoring_posts post ON post.mentoring_post_id = m.mentoring_post_id
WHERE post.title = 'B Swagger 백엔드 멘토링'
  AND mission.title = 'B 1주차 PR 리뷰 미션'
  AND NOT EXISTS (
      SELECT 1
      FROM pull_request_submissions prs
      WHERE prs.mission_submission_id = ms.mission_submission_id
  );

-- ------------------------------------------------------------
-- B-6. Notification seed
-- ------------------------------------------------------------

INSERT INTO learner_notification (
    learner_id,
    type,
    message,
    is_read,
    created_at
)
SELECT
    learner.user_id,
    'SYSTEM',
    'B Swagger 알림 조회 테스트용 알림입니다.',
    FALSE,
    NOW()
FROM users learner
WHERE learner.email = 'b-learner-one@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM learner_notification ln
      WHERE ln.learner_id = learner.user_id
        AND ln.message = 'B Swagger 알림 조회 테스트용 알림입니다.'
  );

-- ------------------------------------------------------------
-- B-7. Meeting / Voice seed
-- ------------------------------------------------------------

INSERT INTO meeting_rooms (
    mentoring_id,
    host_id,
    title,
    meeting_url,
    recording_url,
    scheduled_at,
    started_at,
    ended_at,
    status,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    m.mentoring_id,
    mentor.user_id,
    'B Swagger 멘토링 회의방',
    'https://meet.devpath.local/b-swagger-mentoring',
    NULL,
    NOW() + INTERVAL '1' DAY,
    NOW(),
    NULL,
    'OPEN',
    FALSE,
    NOW(),
    NOW()
FROM mentorings m
JOIN mentoring_posts post ON post.mentoring_post_id = m.mentoring_post_id
JOIN users mentor ON mentor.email = 'b-mentor@devpath.com'
WHERE post.title = 'B Swagger 백엔드 멘토링'
  AND NOT EXISTS (
      SELECT 1
      FROM meeting_rooms mr
      WHERE mr.mentoring_id = m.mentoring_id
        AND mr.title = 'B Swagger 멘토링 회의방'
        AND mr.is_deleted = FALSE
  );

INSERT INTO voice_channels (
    workspace_id,
    creator_id,
    name,
    description,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    w.id,
    creator.user_id,
    'B Swagger 보이스 채널',
    'B Swagger 보이스 이벤트 테스트용 채널입니다.',
    FALSE,
    NOW(),
    NOW()
FROM workspace w
JOIN users creator ON creator.email = 'b-learner-one@devpath.com'
WHERE w.name = 'B Swagger Squad Workspace'
  AND NOT EXISTS (
      SELECT 1
      FROM voice_channels vc
      WHERE vc.workspace_id = w.id
        AND vc.name = 'B Swagger 보이스 채널'
        AND vc.is_deleted = FALSE
  );

-- ------------------------------------------------------------
-- B-8. Company / Job / Skill Tags seed
-- ------------------------------------------------------------

INSERT INTO companies (
    name,
    description,
    website_url,
    logo_url,
    industry,
    location,
    verification_status,
    verification_memo,
    verified_at,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    'DevPath Labs',
    'B Swagger 채용/시장 분석 테스트용 기업입니다.',
    'https://devpath.example.com',
    NULL,
    'Education Tech',
    'SEOUL',
    'VERIFIED',
    'B 시나리오 테스트용 인증 기업',
    NOW(),
    FALSE,
    NOW(),
    NOW()
WHERE NOT EXISTS (
    SELECT 1 FROM companies WHERE name = 'DevPath Labs'
);

INSERT INTO job_postings (
    company_id,
    title,
    job_role,
    description,
    required_skills,
    region,
    career_level,
    source_url,
    source,
    status,
    deadline,
    external_job_id,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    c.company_id,
    '주니어 백엔드 개발자',
    'BACKEND',
    'Spring Boot 기반 REST API와 JPA 도메인 설계를 담당합니다.',
    'Java, Spring Boot, JPA, PostgreSQL',
    '서울',
    'JUNIOR',
    'https://devpath.example.com/jobs/backend-junior',
    'INTERNAL',
    'OPEN',
    CURRENT_DATE + 30,
    'B-JOB-BACKEND-001',
    FALSE,
    NOW(),
    NOW()
FROM companies c
WHERE c.name = 'DevPath Labs'
  AND NOT EXISTS (
      SELECT 1
      FROM job_postings jp
      WHERE jp.external_job_id = 'B-JOB-BACKEND-001'
  );

INSERT INTO job_postings (
    company_id,
    title,
    job_role,
    description,
    required_skills,
    region,
    career_level,
    source_url,
    source,
    status,
    deadline,
    external_job_id,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    c.company_id,
    '풀스택 개발자 인턴',
    'FULLSTACK',
    'React와 Spring Boot를 활용해 학습 플랫폼 기능을 개발합니다.',
    'React, TypeScript, Java, Spring Boot',
    '경기',
    'INTERN',
    'https://devpath.example.com/jobs/fullstack-intern',
    'INTERNAL',
    'OPEN',
    CURRENT_DATE + 45,
    'B-JOB-FULLSTACK-001',
    FALSE,
    NOW(),
    NOW()
FROM companies c
WHERE c.name = 'DevPath Labs'
  AND NOT EXISTS (
      SELECT 1
      FROM job_postings jp
      WHERE jp.external_job_id = 'B-JOB-FULLSTACK-001'
  );

INSERT INTO job_skill_tags (
    job_posting_id,
    name,
    source,
    confidence_score,
    matched_keyword,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    jp.job_posting_id,
    skill.name,
    'JD_RULE_BASED',
    skill.confidence_score,
    skill.matched_keyword,
    FALSE,
    NOW(),
    NOW()
FROM job_postings jp
CROSS JOIN (
    VALUES
        ('Java', 0.95, 'Java'),
        ('Spring Boot', 0.98, 'Spring Boot'),
        ('JPA', 0.91, 'JPA')
) AS skill(name, confidence_score, matched_keyword)
WHERE jp.external_job_id = 'B-JOB-BACKEND-001'
  AND NOT EXISTS (
      SELECT 1
      FROM job_skill_tags tag
      WHERE tag.job_posting_id = jp.job_posting_id
        AND tag.name = skill.name
  );

INSERT INTO job_skill_tags (
    job_posting_id,
    name,
    source,
    confidence_score,
    matched_keyword,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    jp.job_posting_id,
    skill.name,
    'JD_RULE_BASED',
    skill.confidence_score,
    skill.matched_keyword,
    FALSE,
    NOW(),
    NOW()
FROM job_postings jp
CROSS JOIN (
    VALUES
        ('React', 0.93, 'React'),
        ('TypeScript', 0.9, 'TypeScript')
) AS skill(name, confidence_score, matched_keyword)
WHERE jp.external_job_id = 'B-JOB-FULLSTACK-001'
  AND NOT EXISTS (
      SELECT 1
      FROM job_skill_tags tag
      WHERE tag.job_posting_id = jp.job_posting_id
        AND tag.name = skill.name
  );

-- ------------------------------------------------------------
-- B-9. Career Profile / Proof Card link seed
-- ------------------------------------------------------------

INSERT INTO career_profiles (
    user_id,
    target_role,
    headline,
    summary,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    learner.user_id,
    'BACKEND',
    'Spring Boot 기반 주니어 백엔드 개발자',
    '멘토링 PR 리뷰와 학습 이력을 기반으로 백엔드 역량을 정리한 B 테스트 프로필입니다.',
    FALSE,
    NOW(),
    NOW()
FROM users learner
WHERE learner.email = 'b-learner-one@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM career_profiles cp
      WHERE cp.user_id = learner.user_id
        AND cp.target_role = 'BACKEND'
        AND cp.is_deleted = FALSE
  );

INSERT INTO career_profile_proof_cards (
    career_profile_id,
    proof_card_id,
    title,
    summary,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    cp.career_profile_id,
    9001,
    'B Swagger Proof Card',
    'B Swagger 시나리오 검증용 Proof Card 연결 샘플입니다.',
    FALSE,
    NOW(),
    NOW()
FROM career_profiles cp
JOIN users learner ON learner.user_id = cp.user_id
WHERE learner.email = 'b-learner-one@devpath.com'
  AND cp.target_role = 'BACKEND'
  AND NOT EXISTS (
      SELECT 1
      FROM career_profile_proof_cards cpc
      WHERE cpc.career_profile_id = cp.career_profile_id
        AND cpc.proof_card_id = 9001
        AND cpc.is_deleted = FALSE
  );
-- ------------------------------------------------------------
-- B-9a. Evaluation Swagger compatibility roadmap node
-- ------------------------------------------------------------

INSERT INTO roadmap_nodes (
    roadmap_id,
    title,
    content,
    node_type,
    sort_order
)
SELECT
    r.roadmap_id,
    'Security and JWT',
    'Build authentication and authorization flows with Spring Security and JWT.',
    'CONCEPT',
    COALESCE((SELECT MAX(rn.sort_order) FROM roadmap_nodes rn WHERE rn.roadmap_id = r.roadmap_id), 0) + 1
FROM roadmaps r
WHERE r.title IN ('Backend Master Roadmap', '백엔드')
  AND NOT EXISTS (
      SELECT 1
      FROM roadmap_nodes rn
      WHERE rn.roadmap_id = r.roadmap_id
        AND rn.title IN ('Security and JWT', 'Spring Security & JWT')
  );

-- ------------------------------------------------------------
-- B-10. Sequence correction
-- ------------------------------------------------------------


SELECT setval(pg_get_serial_sequence('users', 'user_id'), COALESCE((SELECT MAX(user_id) FROM users), 1));
SELECT setval(pg_get_serial_sequence('workspace', 'id'), COALESCE((SELECT MAX(id) FROM workspace), 1));
SELECT setval(pg_get_serial_sequence('workspace_member', 'id'), COALESCE((SELECT MAX(id) FROM workspace_member), 1));
SELECT setval(pg_get_serial_sequence('mentoring_posts', 'mentoring_post_id'), COALESCE((SELECT MAX(mentoring_post_id) FROM mentoring_posts), 1));
SELECT setval(pg_get_serial_sequence('mentoring_applications', 'mentoring_application_id'), COALESCE((SELECT MAX(mentoring_application_id) FROM mentoring_applications), 1));
SELECT setval(pg_get_serial_sequence('mentorings', 'mentoring_id'), COALESCE((SELECT MAX(mentoring_id) FROM mentorings), 1));
SELECT setval(pg_get_serial_sequence('mentoring_missions', 'mentoring_mission_id'), COALESCE((SELECT MAX(mentoring_mission_id) FROM mentoring_missions), 1));
SELECT setval(pg_get_serial_sequence('mentoring_materials', 'mentoring_material_id'), COALESCE((SELECT MAX(mentoring_material_id) FROM mentoring_materials), 1));
SELECT setval(pg_get_serial_sequence('mission_submissions', 'mission_submission_id'), COALESCE((SELECT MAX(mission_submission_id) FROM mission_submissions), 1));
SELECT setval(pg_get_serial_sequence('pull_request_submissions', 'pull_request_submission_id'), COALESCE((SELECT MAX(pull_request_submission_id) FROM pull_request_submissions), 1));
SELECT setval(pg_get_serial_sequence('learner_notification', 'id'), COALESCE((SELECT MAX(id) FROM learner_notification), 1));
SELECT setval(pg_get_serial_sequence('meeting_rooms', 'meeting_room_id'), COALESCE((SELECT MAX(meeting_room_id) FROM meeting_rooms), 1));
SELECT setval(pg_get_serial_sequence('voice_channels', 'voice_channel_id'), COALESCE((SELECT MAX(voice_channel_id) FROM voice_channels), 1));
SELECT setval(pg_get_serial_sequence('companies', 'company_id'), COALESCE((SELECT MAX(company_id) FROM companies), 1));
SELECT setval(pg_get_serial_sequence('job_postings', 'job_posting_id'), COALESCE((SELECT MAX(job_posting_id) FROM job_postings), 1));
SELECT setval(pg_get_serial_sequence('job_skill_tags', 'job_skill_tag_id'), COALESCE((SELECT MAX(job_skill_tag_id) FROM job_skill_tags), 1));
SELECT setval(pg_get_serial_sequence('career_profiles', 'career_profile_id'), COALESCE((SELECT MAX(career_profile_id) FROM career_profiles), 1));
SELECT setval(pg_get_serial_sequence('career_profile_proof_cards', 'career_profile_proof_card_id'), COALESCE((SELECT MAX(career_profile_proof_card_id) FROM career_profile_proof_cards), 1));
SELECT setval(pg_get_serial_sequence('qna_questions', 'question_id'), COALESCE((SELECT MAX(question_id) FROM qna_questions), 1));
SELECT setval(pg_get_serial_sequence('qna_answers', 'answer_id'), COALESCE((SELECT MAX(answer_id) FROM qna_answers), 1));

-- =========================================================
-- A SEED - Squad Member / Invite / Kanban / Portfolio PDF
-- =========================================================

-- 스쿼드 멤버 관리 테스트용 스쿼드
INSERT INTO squads (
    squad_id,
    name,
    description,
    is_archived,
    is_deleted,
    archived_at,
    created_at,
    updated_at
)
SELECT
    9001,
    'DevPath A Squad',
    '프로젝트/스쿼드/워크스페이스 A 기능 테스트용 스쿼드',
    FALSE,
    FALSE,
    NULL,
    NOW(),
    NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM squads
    WHERE squad_id = 9001
       OR name = 'DevPath A Squad'
);

-- LEADER / MEMBER 멤버십
INSERT INTO squad_members (
    squad_member_id,
    squad_id,
    user_id,
    role,
    joined_at,
    is_deleted,
    deleted_at
)
SELECT
    9001,
    9001,
    learner.user_id,
    'LEADER',
    NOW(),
    FALSE,
    NULL
FROM users learner
WHERE learner.email = 'learner@devpath.com'
  AND NOT EXISTS (
    SELECT 1
    FROM squad_members
    WHERE squad_member_id = 9001
       OR (squad_id = 9001 AND user_id = learner.user_id AND is_deleted = FALSE)
);

INSERT INTO squad_members (
    squad_member_id,
    squad_id,
    user_id,
    role,
    joined_at,
    is_deleted,
    deleted_at
)
SELECT
    9002,
    9001,
    member.user_id,
    'MEMBER',
    NOW(),
    FALSE,
    NULL
FROM users member
WHERE member.email = 'frontend@devpath.com'
  AND NOT EXISTS (
    SELECT 1
    FROM squad_members
    WHERE squad_member_id = 9002
       OR (squad_id = 9001 AND user_id = member.user_id AND is_deleted = FALSE)
);

INSERT INTO workspace (
    id,
    owner_id,
    name,
    description,
    type,
    status,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    9001,
    owner.user_id,
    'DevPath A Workspace',
    'Workspace seed for A/C Swagger scenarios.',
    'SQUAD',
    'ACTIVE',
    FALSE,
    NOW(),
    NOW()
FROM users owner
WHERE owner.email = 'learner@devpath.com'
  AND NOT EXISTS (
    SELECT 1
    FROM workspace
    WHERE id = 9001
       OR name = 'DevPath A Workspace'
);

-- 초대 목록 조회 테스트용 PENDING 초대
INSERT INTO squad_invitations (
    squad_invitation_id,
    squad_id,
    inviter_id,
    invitee_id,
    invite_email,
    message,
    invitation_token,
    expires_at,
    accepted_at,
    status,
    created_at
)
SELECT
    9001,
    9001,
    inviter.user_id,
    NULL,
    'invitee@example.com',
    'DevPath A Squad에 초대합니다.',
    'a-seed-invite-token-9001',
    NOW() + INTERVAL '7 days',
    NULL,
    'PENDING',
    NOW()
FROM users inviter
WHERE inviter.email = 'learner@devpath.com'
  AND NOT EXISTS (
    SELECT 1
    FROM squad_invitations
    WHERE squad_invitation_id = 9001
       OR invitation_token = 'a-seed-invite-token-9001'
);

-- 워크스페이스 태스크 테스트 데이터
INSERT INTO workspace_task (
    id,
    workspace_id,
    title,
    description,
    status,
    priority,
    assignee_id,
    due_date,
    created_by_id,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    9001,
    9001,
    'A Swagger 칸반 TODO',
    'GET /api/workspaces/{workspaceId}/tasks 테스트용 태스크',
    'TODO',
    'MEDIUM',
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    CURRENT_DATE + 3,
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    FALSE,
    NOW(),
    NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM workspace_task
    WHERE id = 9001
       OR (workspace_id = 9001 AND title = 'A Swagger 칸반 TODO' AND is_deleted = FALSE)
);

INSERT INTO workspace_task (
    id,
    workspace_id,
    title,
    description,
    status,
    priority,
    assignee_id,
    due_date,
    created_by_id,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    9002,
    9001,
    'A Swagger 칸반 진행 중',
    'PATCH /api/tasks/{taskId}/status 테스트용 태스크',
    'IN_PROGRESS',
    'HIGH',
    (SELECT user_id FROM users WHERE email = 'frontend@devpath.com'),
    CURRENT_DATE + 5,
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    FALSE,
    NOW(),
    NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM workspace_task
    WHERE id = 9002
       OR (workspace_id = 9001 AND title = 'A Swagger 칸반 진행 중' AND is_deleted = FALSE)
);

INSERT INTO workspace_task (
    id,
    workspace_id,
    title,
    description,
    status,
    priority,
    assignee_id,
    due_date,
    created_by_id,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    9003,
    9001,
    'A Swagger 칸반 완료',
    'PATCH /api/tasks/{taskId}/assignee 테스트용 태스크',
    'DONE',
    'LOW',
    NULL,
    CURRENT_DATE + 7,
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    FALSE,
    NOW(),
    NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM workspace_task
    WHERE id = 9003
       OR (workspace_id = 9001 AND title = 'A Swagger 칸반 완료' AND is_deleted = FALSE)
);

-- 포트폴리오 PDF 테스트용 포트폴리오
INSERT INTO portfolio (
    id,
    user_id,
    title,
    bio,
    public_link_token,
    is_public,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    9001,
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    'DevPath A Portfolio',
    'A 기능 테스트용 포트폴리오입니다.',
    'a-seed-public-token-9001',
    TRUE,
    FALSE,
    NOW(),
    NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM portfolio
    WHERE id = 9001
       OR public_link_token = 'a-seed-public-token-9001'
);

-- PDF 버전 조회 테스트용 COMPLETED 버전
INSERT INTO portfolio_pdf_version (
    portfolio_pdf_version_id,
    portfolio_id,
    version,
    status,
    file_path,
    file_url,
    created_at
)
SELECT
    9001,
    9001,
    1,
    'COMPLETED',
    '/uploads/portfolios/9001/portfolio-v1.pdf',
    '/uploads/portfolios/9001/portfolio-v1.pdf',
    NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM portfolio_pdf_version
    WHERE portfolio_pdf_version_id = 9001
       OR (portfolio_id = 9001 AND version = 1)
);

-- PDF 다운로드 이력 조회 테스트 데이터
INSERT INTO portfolio_pdf_download_history (
    portfolio_pdf_download_history_id,
    portfolio_id,
    portfolio_pdf_version_id,
    user_id,
    file_path,
    ip_address,
    downloaded_at
)
SELECT
    9001,
    9001,
    9001,
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    '/uploads/portfolios/9001/portfolio-v1.pdf',
    '127.0.0.1',
    NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM portfolio_pdf_download_history
    WHERE portfolio_pdf_download_history_id = 9001
);

-- =========================================================
-- A SEED sequence sync
-- =========================================================

SELECT setval(pg_get_serial_sequence('squads', 'squad_id'), COALESCE((SELECT MAX(squad_id) FROM squads), 1));
SELECT setval(pg_get_serial_sequence('squad_members', 'squad_member_id'), COALESCE((SELECT MAX(squad_member_id) FROM squad_members), 1));
SELECT setval(pg_get_serial_sequence('squad_invitations', 'squad_invitation_id'), COALESCE((SELECT MAX(squad_invitation_id) FROM squad_invitations), 1));
SELECT setval(pg_get_serial_sequence('workspace', 'id'), COALESCE((SELECT MAX(id) FROM workspace), 1));
SELECT setval(pg_get_serial_sequence('workspace_task', 'id'), COALESCE((SELECT MAX(id) FROM workspace_task), 1));
SELECT setval(pg_get_serial_sequence('portfolio', 'id'), COALESCE((SELECT MAX(id) FROM portfolio), 1));
SELECT setval(pg_get_serial_sequence('portfolio_pdf_version', 'portfolio_pdf_version_id'), COALESCE((SELECT MAX(portfolio_pdf_version_id) FROM portfolio_pdf_version), 1));
SELECT setval(pg_get_serial_sequence('portfolio_pdf_download_history', 'portfolio_pdf_download_history_id'), COALESCE((SELECT MAX(portfolio_pdf_download_history_id) FROM portfolio_pdf_download_history), 1));

-- =========================================================
-- C SEED - Workspace Notice / Integration / Admin Operation
-- =========================================================

INSERT INTO workspace_notice (
    id,
    workspace_id,
    title,
    content,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    9001,
    9001,
    'C Swagger workspace notice',
    'Seed notice for Workspace Notice detail, update, delete, and read APIs.',
    FALSE,
    NOW(),
    NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM workspace_notice
    WHERE id = 9001
       OR (workspace_id = 9001 AND title = 'C Swagger workspace notice' AND is_deleted = FALSE)
);

INSERT INTO workspace_notice (
    id,
    workspace_id,
    title,
    content,
    is_deleted,
    created_at,
    updated_at
)
SELECT
    9002,
    9001,
    'C Swagger unread workspace notice',
    'Seed notice that remains unread for unread list and count APIs.',
    FALSE,
    NOW(),
    NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM workspace_notice
    WHERE id = 9002
       OR (workspace_id = 9001 AND title = 'C Swagger unread workspace notice' AND is_deleted = FALSE)
);

INSERT INTO workspace_notice_read (
    id,
    workspace_id,
    notice_id,
    user_id,
    read_at
)
SELECT
    9001,
    9001,
    9001,
    (SELECT user_id FROM users WHERE email = 'learner@devpath.com'),
    NOW()
WHERE EXISTS (
    SELECT 1
    FROM workspace_notice
    WHERE id = 9001
)
AND NOT EXISTS (
    SELECT 1
    FROM workspace_notice_read
    WHERE id = 9001
       OR (notice_id = 9001 AND user_id = (SELECT user_id FROM users WHERE email = 'learner@devpath.com'))
);

INSERT INTO external_integration (
    id,
    workspace_id,
    provider,
    is_active,
    connected_at,
    created_at,
    updated_at
)
SELECT
    9001,
    9001,
    'GITHUB',
    FALSE,
    NULL,
    NOW(),
    NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM external_integration
    WHERE id = 9001
       OR (workspace_id = 9001 AND provider = 'GITHUB')
);

INSERT INTO external_integration (
    id,
    workspace_id,
    provider,
    is_active,
    connected_at,
    created_at,
    updated_at
)
SELECT
    9002,
    9001,
    'SLACK',
    FALSE,
    NULL,
    NOW(),
    NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM external_integration
    WHERE id = 9002
       OR (workspace_id = 9001 AND provider = 'SLACK')
);

INSERT INTO recommendation_settings (
    id,
    setting_key,
    setting_value,
    description,
    created_at,
    updated_at
)
SELECT
    9001,
    'algorithm.weight.recent_activity',
    '0.8',
    'Recent activity recommendation weight',
    NOW(),
    NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM recommendation_settings
    WHERE id = 9001
       OR setting_key = 'algorithm.weight.recent_activity'
);

INSERT INTO recommendation_settings (
    id,
    setting_key,
    setting_value,
    description,
    created_at,
    updated_at
)
SELECT
    9002,
    'algorithm.weight.skill_match',
    '0.9',
    'Skill match recommendation weight',
    NOW(),
    NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM recommendation_settings
    WHERE id = 9002
       OR setting_key = 'algorithm.weight.skill_match'
);

INSERT INTO experiment_results (
    id,
    experiment_id,
    experiment_name,
    metrics_json,
    status,
    created_at
)
SELECT
    9001,
    'EXP-C-9001',
    'C Swagger admin analytics experiment',
    '{"totalUsers": 15230, "weeklyActiveUsers": 4321, "averageRoadmapProgress": 42.8, "monthlyCompletedAssignments": 1830}',
    'COMPLETED',
    NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM experiment_results
    WHERE id = 9001
       OR experiment_id = 'EXP-C-9001'
);

-- =========================================================
-- C SEED sequence sync
-- =========================================================

SELECT setval(pg_get_serial_sequence('workspace_notice', 'id'), COALESCE((SELECT MAX(id) FROM workspace_notice), 1));
SELECT setval(pg_get_serial_sequence('workspace_notice_read', 'id'), COALESCE((SELECT MAX(id) FROM workspace_notice_read), 1));
SELECT setval(pg_get_serial_sequence('external_integration', 'id'), COALESCE((SELECT MAX(id) FROM external_integration), 1));
SELECT setval(pg_get_serial_sequence('recommendation_settings', 'id'), COALESCE((SELECT MAX(id) FROM recommendation_settings), 1));
SELECT setval(pg_get_serial_sequence('experiment_results', 'id'), COALESCE((SELECT MAX(id) FROM experiment_results), 1));

-- =========================================================
-- Dashboard recent learning seed for frontend@devpath.com
-- =========================================================

INSERT INTO course_sections (course_id, title, description, sort_order, is_published)
WITH react_dashboard_sections(section_title, section_description, sort_order) AS (
    VALUES
        ('Dashboard Foundations', 'Layout, card hierarchy, and data loading patterns for dashboard screens.', 1),
        ('Interactive Widgets', 'Charts, filters, and optimistic UI feedback for production dashboards.', 2)
)
SELECT
    c.course_id,
    seed.section_title,
    seed.section_description,
    seed.sort_order,
    TRUE
FROM react_dashboard_sections seed
JOIN courses c ON c.title = 'React Dashboard Sprint'
WHERE NOT EXISTS (
    SELECT 1
    FROM course_sections cs
    WHERE cs.course_id = c.course_id
      AND cs.sort_order = seed.sort_order
);

INSERT INTO lessons (
    section_id,
    title,
    description,
    lesson_type,
    video_url,
    video_asset_key,
    video_provider,
    thumbnail_url,
    duration_seconds,
    is_preview,
    is_published,
    sort_order
)
WITH react_dashboard_lessons(
    section_order,
    lesson_title,
    lesson_description,
    video_url,
    video_asset_key,
    duration_seconds,
    sort_order,
    is_preview
) AS (
    VALUES
        (1, 'Dashboard layout and data cards', 'Build a dashboard shell with responsive metric cards and loading states.', '/samples/sample-intro.mp4', 'assets/courses/react-dashboard/layout-data-cards.mp4', 960, 1, TRUE),
        (1, 'Enrollment API data binding', 'Connect enrollment data to recent-learning and progress widgets without hard-coded fallbacks.', '/samples/devpath_ocr.mp4', 'assets/courses/react-dashboard/enrollment-api-binding.mp4', 1020, 2, FALSE),
        (2, 'Chart filters and empty states', 'Design chart filters, empty states, and error states that keep dashboard data honest.', '/samples/devpath_ocr_ver2.mp4', 'assets/courses/react-dashboard/chart-filters-empty-states.mp4', 1140, 1, FALSE)
)
SELECT
    cs.section_id,
    seed.lesson_title,
    seed.lesson_description,
    'VIDEO',
    seed.video_url,
    seed.video_asset_key,
    'local',
    'https://images.unsplash.com/photo-1460925895917-afdab827c52f?auto=format&fit=crop&w=800&q=60',
    seed.duration_seconds,
    seed.is_preview,
    TRUE,
    seed.sort_order
FROM react_dashboard_lessons seed
JOIN courses c ON c.title = 'React Dashboard Sprint'
JOIN course_sections cs ON cs.course_id = c.course_id
                       AND cs.sort_order = seed.section_order
WHERE NOT EXISTS (
    SELECT 1
    FROM lessons l
    WHERE l.section_id = cs.section_id
      AND l.sort_order = seed.sort_order
);

INSERT INTO course_enrollments (
    user_id,
    course_id,
    status,
    enrolled_at,
    completed_at,
    progress_percentage,
    last_accessed_at
)
WITH frontend_dashboard_enrollment_seed(
    learner_email,
    course_title,
    status,
    enrolled_at,
    completed_at,
    progress_percentage,
    last_accessed_at
) AS (
    VALUES
        ('frontend@devpath.com', 'Spring Boot Intro', 'ACTIVE', TIMESTAMP '2026-05-18 09:00:00', CAST(NULL AS TIMESTAMP), 42, TIMESTAMP '2026-05-24 20:15:00'),
        ('frontend@devpath.com', 'React Dashboard Sprint', 'ACTIVE', TIMESTAMP '2026-05-20 09:00:00', CAST(NULL AS TIMESTAMP), 64, TIMESTAMP '2026-05-24 21:30:00')
)
SELECT
    u.user_id,
    c.course_id,
    seed.status,
    seed.enrolled_at,
    seed.completed_at,
    seed.progress_percentage,
    seed.last_accessed_at
FROM frontend_dashboard_enrollment_seed seed
JOIN users u ON u.email = seed.learner_email
JOIN courses c ON c.title = seed.course_title
WHERE NOT EXISTS (
    SELECT 1
    FROM course_enrollments ce
    WHERE ce.user_id = u.user_id
      AND ce.course_id = c.course_id
);

INSERT INTO lesson_progress (
    user_id,
    lesson_id,
    progress_percent,
    progress_seconds,
    default_playback_rate,
    is_pip_enabled,
    is_completed,
    last_watched_at,
    created_at,
    updated_at
)
WITH frontend_dashboard_progress_seed(
    learner_email,
    course_title,
    section_order,
    lesson_order,
    progress_percent,
    progress_seconds,
    default_playback_rate,
    is_pip_enabled,
    is_completed,
    last_watched_at
) AS (
    VALUES
        ('frontend@devpath.com', 'Spring Boot Intro', 1, 1, 100, 780, 1.25, TRUE, TRUE, TIMESTAMP '2026-05-22 20:15:00'),
        ('frontend@devpath.com', 'Spring Boot Intro', 1, 2, 42, 386, 1.25, FALSE, FALSE, TIMESTAMP '2026-05-24 20:15:00'),
        ('frontend@devpath.com', 'React Dashboard Sprint', 1, 1, 100, 960, 1.25, TRUE, TRUE, TIMESTAMP '2026-05-23 21:00:00'),
        ('frontend@devpath.com', 'React Dashboard Sprint', 1, 2, 64, 653, 1.25, FALSE, FALSE, TIMESTAMP '2026-05-24 21:30:00')
)
SELECT
    u.user_id,
    l.lesson_id,
    seed.progress_percent,
    seed.progress_seconds,
    seed.default_playback_rate,
    seed.is_pip_enabled,
    seed.is_completed,
    seed.last_watched_at,
    seed.last_watched_at,
    seed.last_watched_at
FROM frontend_dashboard_progress_seed seed
JOIN users u ON u.email = seed.learner_email
JOIN courses c ON c.title = seed.course_title
JOIN course_sections cs ON cs.course_id = c.course_id
                       AND cs.sort_order = seed.section_order
JOIN lessons l ON l.section_id = cs.section_id
              AND l.sort_order = seed.lesson_order
WHERE NOT EXISTS (
    SELECT 1
    FROM lesson_progress lp
    WHERE lp.user_id = u.user_id
      AND lp.lesson_id = l.lesson_id
);

-- =====================================================================
-- 공식 로드맵 이름 한글화 (직무별)
--   허브 카드 라벨(roadmap_hub_items.title, 직무별=한글)과 roadmaps.title(영문)이
--   불일치하던 문제를 해소: 로드맵 상세/어드민 '로드맵 기본정보'에서도 한글로 표시.
--   - 모든 노드/허브아이템 시딩(FK 연결) 이후 마지막에 실행 → title 기반 참조 무영향
--   - role-based 섹션만 대상 (skill-based는 허브도 영문이라 이미 일치, 기술명 영문 유지)
--   - ddl-auto: create 재부팅 시에도 시드 재실행되어 한글 이름이 유지됨 (멱등)
-- =====================================================================
UPDATE roadmaps r
SET title = hi.title
FROM roadmap_hub_items hi
JOIN roadmap_hub_sections s ON s.id = hi.section_id
WHERE hi.linked_roadmap_id = r.roadmap_id
  AND s.section_key = 'role-based'
  AND r.is_official = TRUE
  AND r.is_deleted = FALSE
  AND hi.title IS NOT NULL
  AND hi.title <> r.title;

-- 한글 상세 노드와 겹치는 이전 Swagger 호환 노드가 기존 DB에 남아 있으면 안전하게 제거한다.
DELETE FROM custom_roadmap_nodes crn
USING roadmap_nodes rn
JOIN roadmaps r ON r.roadmap_id = rn.roadmap_id
WHERE crn.original_node_id = rn.node_id
  AND r.title = '백엔드'
  AND rn.title = 'Security and JWT'
  AND EXISTS (
      SELECT 1
      FROM roadmap_nodes replacement
      WHERE replacement.roadmap_id = r.roadmap_id
        AND replacement.title = 'Spring Security & JWT'
  )
  AND NOT EXISTS (
      SELECT 1
      FROM custom_node_prerequisites cnp
      WHERE cnp.custom_node_id = crn.custom_node_id
         OR cnp.prerequisite_custom_node_id = crn.custom_node_id
  )
  AND NOT EXISTS (
      SELECT 1
      FROM learning_proofs proof
      WHERE proof.custom_node_id = crn.custom_node_id
  );

DELETE FROM roadmap_nodes rn
USING roadmaps r
WHERE rn.roadmap_id = r.roadmap_id
  AND r.title = '백엔드'
  AND rn.title = 'Security and JWT'
  AND EXISTS (
      SELECT 1
      FROM roadmap_nodes replacement
      WHERE replacement.roadmap_id = r.roadmap_id
        AND replacement.title = 'Spring Security & JWT'
  )
  AND NOT EXISTS (
      SELECT 1
      FROM custom_roadmap_nodes crn
      WHERE crn.original_node_id = rn.node_id
  );

-- =====================================================================
-- learner@devpath.com 시연용 로드맵 진행 상태 복구
--   공식 로드맵 제목 한글화 이후에도 최소 데모 진행 상태가 유지되도록 보정한다.
--   이미 사용자가 더 많이 완료한 상태는 되돌리지 않는다.
-- =====================================================================
WITH demo_roadmaps(roadmap_title, completed_until, in_progress_sort, seeded_at) AS (
    VALUES
        ('백엔드', 2, 3, TIMESTAMP '2026-03-29 18:00:00'),
        ('프론트엔드', 1, 2, TIMESTAMP '2026-04-03 18:00:00'),
        ('데브옵스', 1, 2, TIMESTAMP '2026-04-04 18:00:00'),
        ('AI 엔지니어', 1, 2, TIMESTAMP '2026-04-05 18:00:00'),
        ('데이터 엔지니어', 1, 2, TIMESTAMP '2026-04-06 18:00:00')
)
INSERT INTO custom_roadmaps (
    user_id, original_roadmap_id, title, progress_rate, is_builder_origin, created_at, updated_at
)
SELECT
    u.user_id,
    r.roadmap_id,
    r.title,
    0,
    FALSE,
    seed.seeded_at,
    seed.seeded_at
FROM demo_roadmaps seed
JOIN users u ON u.email = 'learner@devpath.com'
JOIN roadmaps r ON r.title = seed.roadmap_title
WHERE r.is_official = TRUE
  AND r.is_deleted = FALSE
ON CONFLICT ON CONSTRAINT uk_custom_roadmap_user_original
DO UPDATE SET
    title = EXCLUDED.title,
    is_builder_origin = FALSE,
    updated_at = EXCLUDED.updated_at;

WITH demo_roadmaps(roadmap_title, completed_until, in_progress_sort, seeded_at) AS (
    VALUES
        ('백엔드', 2, 3, TIMESTAMP '2026-03-29 18:00:00'),
        ('프론트엔드', 1, 2, TIMESTAMP '2026-04-03 18:00:00'),
        ('데브옵스', 1, 2, TIMESTAMP '2026-04-04 18:00:00'),
        ('AI 엔지니어', 1, 2, TIMESTAMP '2026-04-05 18:00:00'),
        ('데이터 엔지니어', 1, 2, TIMESTAMP '2026-04-06 18:00:00')
),
demo_nodes AS (
    SELECT
        cr.custom_roadmap_id,
        rn.node_id,
        rn.sort_order,
        CASE
            WHEN rn.sort_order <= seed.completed_until THEN 'COMPLETED'
            WHEN rn.sort_order = seed.in_progress_sort THEN 'IN_PROGRESS'
            ELSE 'NOT_STARTED'
        END AS seeded_status,
        CASE WHEN rn.sort_order <= seed.in_progress_sort THEN seed.seeded_at ELSE NULL END AS seeded_started_at,
        CASE WHEN rn.sort_order <= seed.completed_until THEN seed.seeded_at ELSE NULL END AS seeded_completed_at
    FROM demo_roadmaps seed
    JOIN users u ON u.email = 'learner@devpath.com'
    JOIN roadmaps r ON r.title = seed.roadmap_title
    JOIN custom_roadmaps cr ON cr.user_id = u.user_id AND cr.original_roadmap_id = r.roadmap_id
    JOIN roadmap_nodes rn ON rn.roadmap_id = r.roadmap_id
    WHERE rn.title <> 'Security and JWT'
)
INSERT INTO custom_roadmap_nodes (
    custom_roadmap_id, original_node_id, status, custom_sort_order, started_at, completed_at
)
SELECT
    dn.custom_roadmap_id,
    dn.node_id,
    dn.seeded_status,
    dn.sort_order,
    dn.seeded_started_at,
    dn.seeded_completed_at
FROM demo_nodes dn
WHERE NOT EXISTS (
    SELECT 1
    FROM custom_roadmap_nodes existing
    WHERE existing.custom_roadmap_id = dn.custom_roadmap_id
      AND existing.original_node_id = dn.node_id
);

WITH demo_roadmaps(roadmap_title, completed_until, in_progress_sort, seeded_at) AS (
    VALUES
        ('백엔드', 2, 3, TIMESTAMP '2026-03-29 18:00:00'),
        ('프론트엔드', 1, 2, TIMESTAMP '2026-04-03 18:00:00'),
        ('데브옵스', 1, 2, TIMESTAMP '2026-04-04 18:00:00'),
        ('AI 엔지니어', 1, 2, TIMESTAMP '2026-04-05 18:00:00'),
        ('데이터 엔지니어', 1, 2, TIMESTAMP '2026-04-06 18:00:00')
),
demo_nodes AS (
    SELECT
        crn.custom_node_id,
        CASE
            WHEN rn.sort_order <= seed.completed_until THEN 'COMPLETED'
            WHEN rn.sort_order = seed.in_progress_sort THEN 'IN_PROGRESS'
            ELSE 'NOT_STARTED'
        END AS seeded_status,
        CASE WHEN rn.sort_order <= seed.in_progress_sort THEN seed.seeded_at ELSE NULL END AS seeded_started_at,
        CASE WHEN rn.sort_order <= seed.completed_until THEN seed.seeded_at ELSE NULL END AS seeded_completed_at
    FROM demo_roadmaps seed
    JOIN users u ON u.email = 'learner@devpath.com'
    JOIN roadmaps r ON r.title = seed.roadmap_title
    JOIN custom_roadmaps cr ON cr.user_id = u.user_id AND cr.original_roadmap_id = r.roadmap_id
    JOIN roadmap_nodes rn ON rn.roadmap_id = r.roadmap_id
    JOIN custom_roadmap_nodes crn ON crn.custom_roadmap_id = cr.custom_roadmap_id
        AND crn.original_node_id = rn.node_id
    WHERE rn.title <> 'Security and JWT'
)
UPDATE custom_roadmap_nodes crn
SET
    status = CASE
        WHEN crn.status = 'COMPLETED' THEN crn.status
        ELSE dn.seeded_status
    END,
    started_at = COALESCE(crn.started_at, dn.seeded_started_at),
    completed_at = CASE
        WHEN crn.status = 'COMPLETED' THEN crn.completed_at
        ELSE COALESCE(crn.completed_at, dn.seeded_completed_at)
    END
FROM demo_nodes dn
WHERE crn.custom_node_id = dn.custom_node_id
  AND dn.seeded_status <> 'NOT_STARTED'
  AND crn.status <> 'COMPLETED';

WITH demo_roadmaps(roadmap_title, completed_until, in_progress_sort) AS (
    VALUES
        ('백엔드', 2, 3),
        ('프론트엔드', 1, 2),
        ('데브옵스', 1, 2),
        ('AI 엔지니어', 1, 2),
        ('데이터 엔지니어', 1, 2)
)
INSERT INTO user_tech_stacks (user_id, tag_id)
SELECT DISTINCT u.user_id, nrt.tag_id
FROM demo_roadmaps seed
JOIN users u ON u.email = 'learner@devpath.com'
JOIN roadmaps r ON r.title = seed.roadmap_title
JOIN roadmap_nodes rn ON rn.roadmap_id = r.roadmap_id
JOIN node_required_tags nrt ON nrt.node_id = rn.node_id
WHERE rn.sort_order <= seed.in_progress_sort
  AND NOT EXISTS (
      SELECT 1
      FROM user_tech_stacks existing
      WHERE existing.user_id = u.user_id
        AND existing.tag_id = nrt.tag_id
  );

WITH demo_roadmaps(roadmap_title, completed_until, in_progress_sort, seeded_at) AS (
    VALUES
        ('백엔드', 2, 3, TIMESTAMP '2026-03-29 18:00:00'),
        ('프론트엔드', 1, 2, TIMESTAMP '2026-04-03 18:00:00'),
        ('데브옵스', 1, 2, TIMESTAMP '2026-04-04 18:00:00'),
        ('AI 엔지니어', 1, 2, TIMESTAMP '2026-04-05 18:00:00'),
        ('데이터 엔지니어', 1, 2, TIMESTAMP '2026-04-06 18:00:00')
),
demo_nodes AS (
    SELECT
        u.user_id,
        rn.node_id,
        rn.sort_order,
        CASE
            WHEN rn.sort_order <= seed.completed_until THEN 'CLEARED'
            ELSE 'NOT_CLEARED'
        END AS clearance_status,
        CASE
            WHEN rn.sort_order <= seed.completed_until THEN 1.00
            ELSE 0.65
        END AS lesson_completion_rate,
        CASE WHEN rn.sort_order <= seed.completed_until THEN TRUE ELSE FALSE END AS completed,
        CASE WHEN rn.sort_order <= seed.completed_until THEN seed.seeded_at ELSE NULL END AS cleared_at,
        seed.seeded_at
    FROM demo_roadmaps seed
    JOIN users u ON u.email = 'learner@devpath.com'
    JOIN roadmaps r ON r.title = seed.roadmap_title
    JOIN roadmap_nodes rn ON rn.roadmap_id = r.roadmap_id
    WHERE rn.sort_order <= seed.in_progress_sort
      AND rn.title <> 'Security and JWT'
)
INSERT INTO node_clearances (
    user_id, node_id, clearance_status, lesson_completion_rate, required_tags_satisfied,
    missing_tag_count, lesson_completed, quiz_passed, assignment_passed, proof_eligible,
    cleared_at, last_calculated_at, created_at, updated_at
)
SELECT
    dn.user_id,
    dn.node_id,
    dn.clearance_status,
    dn.lesson_completion_rate,
    TRUE,
    0,
    dn.completed,
    dn.completed,
    dn.completed,
    dn.completed,
    dn.cleared_at,
    dn.seeded_at,
    dn.seeded_at,
    dn.seeded_at
FROM demo_nodes dn
ON CONFLICT ON CONSTRAINT uk_node_clearances_user_node
DO UPDATE SET
    clearance_status = CASE
        WHEN node_clearances.clearance_status = 'CLEARED' THEN node_clearances.clearance_status
        ELSE EXCLUDED.clearance_status
    END,
    lesson_completion_rate = GREATEST(node_clearances.lesson_completion_rate, EXCLUDED.lesson_completion_rate),
    required_tags_satisfied = TRUE,
    missing_tag_count = 0,
    lesson_completed = node_clearances.lesson_completed OR EXCLUDED.lesson_completed,
    quiz_passed = node_clearances.quiz_passed OR EXCLUDED.quiz_passed,
    assignment_passed = node_clearances.assignment_passed OR EXCLUDED.assignment_passed,
    proof_eligible = node_clearances.proof_eligible OR EXCLUDED.proof_eligible,
    cleared_at = COALESCE(node_clearances.cleared_at, EXCLUDED.cleared_at),
    last_calculated_at = GREATEST(node_clearances.last_calculated_at, EXCLUDED.last_calculated_at),
    updated_at = EXCLUDED.updated_at;

INSERT INTO proof_cards (
    user_id, node_id, node_clearance_id, title, description, proof_card_status,
    issued_at, created_at, updated_at
)
SELECT
    nc.user_id,
    nc.node_id,
    nc.node_clearance_id,
    rn.title || ' 수료',
    r.title || ' 로드맵의 "' || rn.title || '" 노드를 완료한 시연용 학습 증명입니다.',
    'ISSUED',
    COALESCE(nc.cleared_at, nc.updated_at, CURRENT_TIMESTAMP),
    COALESCE(nc.cleared_at, nc.updated_at, CURRENT_TIMESTAMP),
    COALESCE(nc.updated_at, nc.cleared_at, CURRENT_TIMESTAMP)
FROM node_clearances nc
JOIN users u ON u.user_id = nc.user_id AND u.email = 'learner@devpath.com'
JOIN roadmap_nodes rn ON rn.node_id = nc.node_id
JOIN roadmaps r ON r.roadmap_id = rn.roadmap_id
WHERE nc.clearance_status = 'CLEARED'
  AND r.title IN ('백엔드', '프론트엔드', '데브옵스', 'AI 엔지니어', '데이터 엔지니어')
ON CONFLICT (node_clearance_id) DO NOTHING;

INSERT INTO proof_card_tags (proof_card_id, tag_id, skill_evidence_type)
SELECT DISTINCT
    pc.proof_card_id,
    nrt.tag_id,
    'VERIFIED'
FROM proof_cards pc
JOIN users u ON u.user_id = pc.user_id AND u.email = 'learner@devpath.com'
JOIN node_required_tags nrt ON nrt.node_id = pc.node_id
WHERE NOT EXISTS (
    SELECT 1
    FROM proof_card_tags existing
    WHERE existing.proof_card_id = pc.proof_card_id
      AND existing.tag_id = nrt.tag_id
      AND existing.skill_evidence_type = 'VERIFIED'
);

UPDATE custom_roadmaps cr
SET
    progress_rate = progress.progress_rate,
    updated_at = progress.updated_at
FROM (
    SELECT
        crn.custom_roadmap_id,
        CASE
            WHEN COUNT(*) = 0 THEN 0
            ELSE (COUNT(*) FILTER (WHERE crn.status = 'COMPLETED') * 100 / COUNT(*))::integer
        END AS progress_rate,
        MAX(COALESCE(crn.completed_at, crn.started_at, cr.updated_at, cr.created_at)) AS updated_at
    FROM custom_roadmaps cr
    JOIN users u ON u.user_id = cr.user_id AND u.email = 'learner@devpath.com'
    JOIN custom_roadmap_nodes crn ON crn.custom_roadmap_id = cr.custom_roadmap_id
    WHERE cr.original_roadmap_id IS NOT NULL
    GROUP BY crn.custom_roadmap_id
) progress
WHERE cr.custom_roadmap_id = progress.custom_roadmap_id;

-- =====================================================================
-- 공식 로드맵 레인 구조 파생
-- - 노드는 (sort_order, lane_key)만 직접 저장하고, 나머지 레인 필드는 여기서 계산한다.
--     척추(lane_key 없음): branch_kind='SPINE',  anchor_node_id=NULL
--     분기(lane_key 있음): branch_kind='BRANCH', anchor_node_id=레인 시작 직전 척추
--     order_in_lane: 레인 안에서 sort_order 오름차순 0-based
-- - 강의 활동 노드([CATALOG] 퀴즈/과제)는 section_order를 직접 저장하므로 구조 파생 대상이 아니다.
-- - 모든 roadmap_nodes INSERT 이후 마지막에 실행되어야 한다. UPDATE만 있어 멱등.
-- - 전제: 한 로드맵의 분기 구역은 하나다(lane 식별자가 (roadmap_id, lane_key)).
--   현재 공식 로드맵은 전부 이 형태이며, 중첩/다구역 분기는 anchor_node_id를 직접 지정해 표현한다.
-- =====================================================================

-- 1) 구조 노드: 레인 종류와 레인 내 순서
WITH structural AS (
    SELECT
        rn.node_id,
        rn.lane_key,
        ROW_NUMBER() OVER (
            PARTITION BY rn.roadmap_id, COALESCE(rn.lane_key, -1)
            ORDER BY rn.sort_order, rn.node_id
        ) - 1 AS lane_position
    FROM roadmap_nodes rn
    JOIN roadmaps r ON r.roadmap_id = rn.roadmap_id
    WHERE rn.sort_order IS NOT NULL
      AND r.title NOT IN ('DevPath 공개 강의 평가 데이터', '__SYSTEM_AI_DYNAMIC_NODES__')
)
UPDATE roadmap_nodes rn
SET
    branch_kind = CASE WHEN structural.lane_key IS NULL THEN 'SPINE' ELSE 'BRANCH' END,
    order_in_lane = structural.lane_position
FROM structural
WHERE rn.node_id = structural.node_id;

-- 2) 분기 레인의 앵커: 레인 첫 노드보다 앞선 마지막 척추 노드를 레인 구성원 전체가 공유한다
WITH lane_start AS (
    SELECT
        rn.roadmap_id,
        rn.lane_key,
        MIN(rn.sort_order) AS first_sort_order
    FROM roadmap_nodes rn
    WHERE rn.branch_kind = 'BRANCH'
    GROUP BY rn.roadmap_id, rn.lane_key
),
lane_anchor AS (
    SELECT
        lane_start.roadmap_id,
        lane_start.lane_key,
        (
            SELECT spine.node_id
            FROM roadmap_nodes spine
            WHERE spine.roadmap_id = lane_start.roadmap_id
              AND spine.branch_kind = 'SPINE'
              AND spine.sort_order < lane_start.first_sort_order
            ORDER BY spine.sort_order DESC, spine.node_id DESC
            LIMIT 1
        ) AS anchor_node_id
    FROM lane_start
)
UPDATE roadmap_nodes rn
SET anchor_node_id = lane_anchor.anchor_node_id
FROM lane_anchor
WHERE rn.roadmap_id = lane_anchor.roadmap_id
  AND rn.lane_key = lane_anchor.lane_key
  AND rn.branch_kind = 'BRANCH';

-- 3) 시드가 직접 만든 커스텀 로드맵도 레인 모델로 맞춘다.
--    이 로드맵들은 분기 없이 척추 한 줄이므로 앵커와 갈래 번호는 없고 순번만 부여한다.
--    (복사·빌더로 만들어지는 커스텀 로드맵은 런타임이 레인을 채우므로 여기 대상이 아니다.)
WITH spine_order AS (
    SELECT
        crn.custom_node_id,
        ROW_NUMBER() OVER (
            PARTITION BY crn.custom_roadmap_id
            ORDER BY crn.custom_sort_order, crn.custom_node_id
        ) - 1 AS lane_position
    FROM custom_roadmap_nodes crn
    WHERE crn.branch_kind IS NULL
)
UPDATE custom_roadmap_nodes crn
SET
    branch_kind = 'SPINE',
    lane_key = NULL,
    anchor_node_id = NULL,
    order_in_lane = spine_order.lane_position
FROM spine_order
WHERE crn.custom_node_id = spine_order.custom_node_id;

-- =========================================================
-- 샘플 강의 썸네일 교체: 외부 스톡 이미지 대신 강의별 전용 이미지(frontend/public/images/courses)
-- =========================================================
UPDATE courses c
SET thumbnail_url = '/images/courses/' || t.slug || '.webp'
FROM (VALUES
    ('Docker & Kubernetes 운영 실전', 'docker-kubernetes-ops'),
    ('실무 Spring Boot 백엔드 입문', 'spring-boot-backend-intro'),
    ('Flutter로 MVP 앱 출시하기', 'flutter-mvp'),
    ('Next.js 14 제품 개발 실전', 'nextjs-14'),
    ('React 19 프론트엔드 실전 가이드', 'react-19'),
    ('개발자 이력서와 기술 면접 패키지', 'resume-interview'),
    ('SQL로 끝내는 데이터 분석 기본기', 'sql-data-analysis'),
    ('ChatGPT API와 RAG 서비스 만들기', 'chatgpt-rag'),
    ('로드맵 실전: 인터넷 & 웹 기초', 'roadmap-internet-web'),
    ('로드맵 실전: OS & 터미널', 'roadmap-os-terminal'),
    ('로드맵 실전: Java 기초', 'roadmap-java'),
    ('로드맵 실전: Git & 버전 관리', 'roadmap-git'),
    ('로드맵 실전: RDB & SQL', 'roadmap-rdb-sql'),
    ('로드맵 실전: REST API 설계', 'roadmap-rest-api'),
    ('로드맵 실전: Spring Boot & MVC', 'roadmap-spring-boot-mvc'),
    ('로드맵 실전: Spring Data JPA', 'roadmap-spring-data-jpa'),
    ('로드맵 실전: Redis 기초', 'roadmap-redis-basic'),
    ('로드맵 실전: Redis 심화', 'roadmap-redis-advanced'),
    ('로드맵 실전: JUnit5 & Mockito', 'roadmap-junit-mockito'),
    ('로드맵 실전: Spring Boot 테스트', 'roadmap-spring-boot-test'),
    ('로드맵 실전: Spring Security & JWT', 'roadmap-spring-security-jwt'),
    ('로드맵 실전: Docker & CI/CD', 'roadmap-docker-cicd'),
    ('로드맵 실전: SOLID & 디자인패턴', 'roadmap-solid-patterns'),
    ('로드맵 실전: 웹 보안 기초', 'roadmap-web-security'),
    ('로드맵 실전: 메시지 큐 & MSA', 'roadmap-mq-msa'),
    ('SOLID 원칙과 디자인 패턴 실전', 'solid-design-patterns'),
    ('OAuth2와 소셜 로그인 연동', 'oauth2-social-login'),
    ('Spring Security 필터 체인과 JWT 인증', 'spring-security-filter-jwt'),
    ('MockMvc와 Spring Boot 통합 테스트', 'mockmvc-integration-test'),
    ('JUnit5와 Mockito 단위 테스트', 'junit5-mockito-unit-test'),
    ('FetchType, N+1, QueryDSL 최적화', 'jpa-n-plus-one-querydsl'),
    ('JPA Entity 매핑과 JPQL 실전', 'jpa-entity-jpql'),
    ('Spring MVC 요청 처리와 3계층 구조', 'spring-mvc-layered'),
    ('Spring Boot DI/IoC와 Spring Bean 등록 흐름', 'spring-di-ioc-bean'),
    ('인터페이스, 제네릭, 컬렉션 실전', 'java-generic-collection'),
    ('Java OOP와 상속 설계', 'java-oop-inheritance'),
    ('Linux 메모리 관리와 I/O 관리', 'linux-memory-io'),
    ('Linux 프로세스와 스레드 관리', 'linux-process-thread'),
    ('OWASP, XSS, CSRF, SQL Injection, CORS', 'owasp-web-security'),
    ('Swagger와 REST API 문서화', 'swagger-rest-docs'),
    ('REST URI 설계와 HTTP 메서드', 'rest-uri-http-method'),
    ('Pull Request와 코드 리뷰 실무', 'pull-request-code-review'),
    ('Git 브랜치 전략과 GitFlow', 'git-branch-gitflow'),
    ('브라우저 요청 흐름과 HTTP 응답 구조', 'browser-http-flow'),
    ('DNS, 도메인, 웹 호스팅 입문', 'dns-domain-hosting'),
    ('HTTP 요청/응답, 메서드, 상태코드', 'http-request-response'),
    ('MSA API Gateway와 서비스 분리 기준', 'msa-api-gateway'),
    ('Kafka와 Kafka 토픽 흐름', 'kafka-topic-flow'),
    ('GitHub Actions와 CI/CD 자동화', 'github-actions-cicd'),
    ('Docker와 docker-compose 실전', 'docker-compose'),
    ('Redis Session, Pub/Sub, 분산 락', 'redis-session-pubsub-lock'),
    ('Redis 자료구조, TTL, Spring Cache', 'redis-ttl-spring-cache'),
    ('인덱스, 트랜잭션, PostgreSQL 성능 기본기', 'postgres-index-transaction'),
    ('SQL JOIN과 서브쿼리 패턴', 'sql-join-subquery')
) AS t(title, slug)
WHERE c.title = t.title;

-- =========================================================
-- 샘플 강의 내용 보강: 소개글, 상세 정보(추천 대상/선수 지식/학습 목표), 커리큘럼,
-- 섹션 퀴즈(5문항)와 실습 과제(루브릭 4개)
-- 강의는 제목으로 찾고, 아래 임시 테이블에 내용을 적재한 뒤 마지막 블록에서 한 번에 반영한다.
-- =========================================================
DROP TABLE IF EXISTS seed_course_content;
DROP TABLE IF EXISTS seed_course_info;
DROP TABLE IF EXISTS seed_course_curriculum;
DROP TABLE IF EXISTS seed_course_quiz;
DROP TABLE IF EXISTS seed_course_quiz_question;
DROP TABLE IF EXISTS seed_course_assignment;
DROP TABLE IF EXISTS seed_course_assignment_rubric;

CREATE TEMP TABLE seed_course_content (
    course_title VARCHAR(255) PRIMARY KEY,
    subtitle VARCHAR(255) NOT NULL,
    description TEXT NOT NULL
);

CREATE TEMP TABLE seed_course_info (
    course_title VARCHAR(255) NOT NULL,
    section_key VARCHAR(50) NOT NULL,
    item_order INTEGER NOT NULL,
    item_text VARCHAR(1000) NOT NULL
);

CREATE TEMP TABLE seed_course_curriculum (
    course_title VARCHAR(255) NOT NULL,
    section_order INTEGER NOT NULL,
    section_title VARCHAR(255) NOT NULL,
    section_description TEXT NOT NULL,
    lesson_order INTEGER NOT NULL,
    lesson_title VARCHAR(255) NOT NULL,
    lesson_description TEXT NOT NULL
);

CREATE TEMP TABLE seed_course_quiz (
    course_title VARCHAR(255) PRIMARY KEY,
    quiz_title VARCHAR(200) NOT NULL,
    quiz_description TEXT NOT NULL,
    lesson_title VARCHAR(255) NOT NULL,
    lesson_description TEXT NOT NULL
);

CREATE TEMP TABLE seed_course_quiz_question (
    course_title VARCHAR(255) NOT NULL,
    display_order INTEGER NOT NULL,
    question_text TEXT NOT NULL,
    explanation TEXT NOT NULL,
    correct_option INTEGER NOT NULL,
    option1 TEXT NOT NULL,
    option2 TEXT NOT NULL,
    option3 TEXT NOT NULL,
    option4 TEXT NOT NULL
);

CREATE TEMP TABLE seed_course_assignment (
    course_title VARCHAR(255) PRIMARY KEY,
    assignment_title VARCHAR(200) NOT NULL,
    assignment_description TEXT NOT NULL,
    submission_rule TEXT NOT NULL,
    lesson_title VARCHAR(255) NOT NULL,
    lesson_description TEXT NOT NULL
);

CREATE TEMP TABLE seed_course_assignment_rubric (
    course_title VARCHAR(255) NOT NULL,
    display_order INTEGER NOT NULL,
    criteria_name VARCHAR(100) NOT NULL,
    criteria_description TEXT NOT NULL,
    max_points INTEGER NOT NULL
);

INSERT INTO seed_course_content (course_title, subtitle, description) VALUES
('Docker & Kubernetes 운영 실전', '이미지 빌드부터 무중단 배포까지, 컨테이너 운영의 전 과정을 손으로 익힙니다',
'로컬에서는 잘 돌던 애플리케이션이 서버에만 올라가면 깨지는 문제, 배포할 때마다 몇 초씩 서비스가 끊기는 문제는 대부분 실행 환경과 배포 방식이 표준화되지 않아서 생깁니다. 이 강의는 Docker로 실행 환경을 이미지 하나에 담고, Kubernetes로 그 이미지를 안정적으로 운영하는 흐름을 처음부터 끝까지 따라갑니다.

첫 섹션에서는 멀티 스테이지 Dockerfile로 가벼운 이미지를 만들고, 레이어 캐시가 빌드 시간에 어떤 영향을 주는지 확인합니다. Docker Compose로 애플리케이션, 데이터베이스, 캐시를 한 번에 띄우며 컨테이너 네트워크와 볼륨이 어떻게 연결되는지도 정리합니다.

두 번째 섹션에서는 Deployment, Service, ConfigMap, Secret을 직접 작성하면서 롤링 업데이트와 readinessProbe가 어떻게 무중단 배포를 만드는지 살펴봅니다. 마지막 과제에서는 실제 서비스에 그대로 적용할 수 있는 수준의 배포 매니페스트를 완성합니다.'),
('실무 Spring Boot 백엔드 입문', '프로젝트 생성부터 JPA, JWT 로그인까지 백엔드 첫 API를 완성합니다',
'Spring Boot를 처음 접하면 어노테이션은 많고 동작 원리는 보이지 않아 막막하게 느껴집니다. 이 강의는 회원 API 하나를 끝까지 만들어 보면서 요청이 Controller, Service, Repository를 거쳐 데이터베이스까지 가는 길을 눈으로 확인하는 데 집중합니다.

첫 섹션에서는 프로젝트 구조와 개발 환경을 갖추고, REST API 요청이 계층별로 어떻게 나뉘어 처리되는지 정리합니다. 왜 Controller에는 비즈니스 로직을 두지 않는지, 왜 Entity를 그대로 응답하지 않는지 같은 실무 기준도 함께 다룹니다.

두 번째 섹션에서는 JPA Entity와 Repository를 설계하고, Spring Security와 JWT로 로그인과 인증 흐름을 붙입니다. 강의를 마치면 회원가입, 로그인, 내 정보 조회까지 동작하는 백엔드 프로젝트가 손에 남습니다.'),
('Flutter로 MVP 앱 출시하기', '위젯 설계부터 스토어 제출 준비까지, 아이디어를 3주 안에 앱으로 만듭니다',
'아이디어를 검증하려면 완벽한 앱보다 빠르게 출시할 수 있는 MVP가 필요합니다. Flutter는 코드 하나로 Android와 iOS를 함께 만들 수 있어 1인 개발자나 작은 팀이 MVP를 내기에 가장 효율적인 선택지 중 하나입니다.

첫 섹션에서는 위젯 트리와 상태 관리의 기본을 잡고, 화면 이동과 입력 폼 검증을 구현하며 앱의 뼈대를 만듭니다. 어떤 상태를 위젯 안에 두고 어떤 상태를 바깥으로 꺼내야 하는지 판단 기준을 함께 정리합니다.

두 번째 섹션에서는 REST API를 연동하고 네트워크 오류를 사용자에게 친절하게 보여 주는 방법, 앱 아이콘과 권한, 릴리스 빌드 설정까지 출시 직전에 꼭 챙겨야 할 항목을 다룹니다. 마지막 과제로 스토어 제출이 가능한 수준의 MVP 화면을 완성합니다.'),
('Next.js 14 제품 개발 실전', 'App Router, 서버 컴포넌트, 캐싱 전략으로 배포 가능한 제품을 만듭니다',
'Next.js 14의 App Router는 페이지를 만드는 방식뿐 아니라 데이터를 가져오고 캐싱하는 방식까지 크게 바꿨습니다. 예전 Pages Router 감각으로 접근하면 왜 데이터가 갱신되지 않는지, 왜 클라이언트 컴포넌트에서만 동작하는지 헷갈리기 쉽습니다.

첫 섹션에서는 라우팅과 레이아웃 구조를 설계하고, 서버 컴포넌트와 클라이언트 컴포넌트의 경계를 어디에 둘지, fetch 캐싱과 revalidate를 어떻게 조합할지 실제 화면을 만들며 정리합니다.

두 번째 섹션에서는 인증과 권한 처리, 이미지 최적화와 메타데이터 설정처럼 제품을 실제로 배포할 때 필요한 요소를 다룹니다. 마지막 과제에서는 예약 상세 페이지를 출시 체크리스트에 맞춰 완성합니다.'),
('React 19 프론트엔드 실전 가이드', '컴포넌트 경계 설계부터 Actions, 테스트까지 실무형 React 화면을 만듭니다',
'React 문법은 익숙한데 화면이 커질수록 상태가 꼬이고, 어디서 데이터를 불러와야 할지 매번 고민된다면 컴포넌트 경계를 설계하는 기준이 필요한 시점입니다. 이 강의는 대시보드 화면 하나를 만들며 실무에서 쓰는 판단 기준을 정리합니다.

첫 섹션에서는 상태를 어느 컴포넌트에 둘지 결정하는 방법, 서버 데이터와 화면 상태를 구분하는 방법, React 19의 Actions와 useActionState로 폼 제출과 대기 상태를 다루는 패턴을 익힙니다.

두 번째 섹션에서는 Tailwind 유틸리티를 일관되게 쓰는 규칙을 정하고, Playwright로 실제 사용자 흐름을 테스트해 화면 품질을 지키는 방법을 다룹니다. 마지막 과제로 테스트까지 갖춘 대시보드 화면을 완성합니다.'),
('개발자 이력서와 기술 면접 패키지', '프로젝트 경험을 성과로 바꾸는 이력서 작성법과 면접 답변 구조를 익힙니다',
'신입 개발자의 이력서가 서류에서 떨어지는 가장 흔한 이유는 실력이 부족해서가 아니라, 무엇을 했고 어떤 결과를 냈는지가 문장에 드러나지 않기 때문입니다. 이 강의는 이미 해 본 프로젝트를 채용 담당자가 읽고 싶어 하는 형태로 다시 쓰는 방법을 다룹니다.

첫 섹션에서는 경력이 없어도 프로젝트를 성과 중심으로 정리하는 법, STAR 구조로 경험을 문장화하는 법을 실제 문장을 고쳐 보며 익힙니다. 기술 스택 나열 대신 문제, 행동, 결과가 보이는 문장을 만드는 것이 목표입니다.

두 번째 섹션에서는 CS 질문과 프로젝트 질문에 답하는 구조, GitHub README와 배포 링크를 정리해 포트폴리오의 신뢰도를 높이는 방법을 다룹니다. 마지막 과제로 지원 포지션에 맞춘 이력서를 완성합니다.'),
('SQL로 끝내는 데이터 분석 기본기', 'SELECT부터 윈도우 함수, Pandas 리포트 자동화까지 실무 분석 흐름을 익힙니다',
'데이터 분석은 거창한 머신러닝보다 정확한 집계에서 시작합니다. 매출이 왜 줄었는지, 어떤 사용자가 다시 돌아오는지 같은 질문은 대부분 SQL 몇 줄과 깔끔한 표 하나로 답할 수 있습니다.

첫 섹션에서는 SELECT, JOIN, GROUP BY로 원하는 데이터를 정확히 뽑는 방법과, 윈도우 함수로 순위와 누적값, 전월 대비 변화를 계산하는 방법을 실제 매출 데이터로 연습합니다.

두 번째 섹션에서는 Pandas로 CSV를 정리하고 결측치를 처리한 뒤, 시각화에 바로 쓸 수 있는 집계 테이블을 만들어 반복되는 리포트를 자동화합니다. 마지막 과제로 매출과 리텐션을 함께 보여 주는 분석 리포트를 작성합니다.'),
('ChatGPT API와 RAG 서비스 만들기', 'LLM API 호출부터 문서 검색 기반 답변까지, 나만의 AI 어시스턴트를 만듭니다',
'LLM은 똑똑하지만 우리 회사 문서나 최신 정보는 모릅니다. 그래서 실제 서비스에서는 질문과 관련된 문서를 먼저 찾아 모델에 함께 전달하는 RAG(검색 증강 생성) 구조를 많이 사용합니다.

첫 섹션에서는 메시지 구조와 역할, 토큰과 비용, 응답 형식을 제어하는 프롬프트 작성법을 익히고, API를 호출해 응답을 안정적으로 처리하는 코드를 작성합니다.

두 번째 섹션에서는 문서를 청크로 나누고 임베딩을 저장한 뒤, 질문과 가까운 문서를 검색해 답변을 생성하는 파이프라인을 LangChain으로 연결합니다. 마지막 과제로 사내 문서에 답하는 Q&A 챗봇 프로토타입을 만듭니다.');

INSERT INTO seed_course_info (course_title, section_key, item_order, item_text) VALUES
('Docker & Kubernetes 운영 실전', 'TARGET_AUDIENCE', 0, 'Docker 명령어는 써 봤지만 운영 환경에 어떻게 올려야 할지 막막한 백엔드 개발자'),
('Docker & Kubernetes 운영 실전', 'TARGET_AUDIENCE', 1, '배포할 때마다 서비스가 잠깐씩 끊기는 문제를 해결하고 싶은 분'),
('Docker & Kubernetes 운영 실전', 'TARGET_AUDIENCE', 2, 'Kubernetes 매니페스트를 복사해서만 써 왔고 각 항목의 의미를 정확히 알고 싶은 분'),
('Docker & Kubernetes 운영 실전', 'PREREQUISITES', 0, '터미널에서 기본 Linux 명령어를 사용할 수 있으면 좋습니다.'),
('Docker & Kubernetes 운영 실전', 'PREREQUISITES', 1, '간단한 웹 애플리케이션을 직접 만들어 실행해 본 경험이 있으면 충분합니다.'),
('Docker & Kubernetes 운영 실전', 'OBJECTIVES', 0, '멀티 스테이지 Dockerfile로 작고 재현 가능한 이미지를 만들 수 있습니다.'),
('Docker & Kubernetes 운영 실전', 'OBJECTIVES', 1, 'Docker Compose로 애플리케이션과 DB, 캐시를 함께 띄우는 로컬 환경을 구성할 수 있습니다.'),
('Docker & Kubernetes 운영 실전', 'OBJECTIVES', 2, 'Deployment, Service, ConfigMap, Secret의 역할을 구분하고 직접 작성할 수 있습니다.'),
('Docker & Kubernetes 운영 실전', 'OBJECTIVES', 3, '롤링 업데이트와 readinessProbe로 무중단 배포를 설계할 수 있습니다.'),
('실무 Spring Boot 백엔드 입문', 'TARGET_AUDIENCE', 0, 'Java 문법은 알지만 Spring Boot로 API를 만들어 본 적이 없는 입문자'),
('실무 Spring Boot 백엔드 입문', 'TARGET_AUDIENCE', 1, '튜토리얼을 따라 했지만 계층 구조가 왜 필요한지 설명하기 어려운 분'),
('실무 Spring Boot 백엔드 입문', 'TARGET_AUDIENCE', 2, '포트폴리오용 백엔드 프로젝트를 처음 시작하려는 취업 준비생'),
('실무 Spring Boot 백엔드 입문', 'PREREQUISITES', 0, 'Java의 클래스, 인터페이스, 컬렉션을 사용할 수 있으면 좋습니다.'),
('실무 Spring Boot 백엔드 입문', 'PREREQUISITES', 1, 'HTTP 요청과 응답의 기본 개념을 알고 있으면 충분합니다.'),
('실무 Spring Boot 백엔드 입문', 'OBJECTIVES', 0, 'Controller, Service, Repository의 책임을 구분해 REST API를 설계할 수 있습니다.'),
('실무 Spring Boot 백엔드 입문', 'OBJECTIVES', 1, 'JPA Entity와 Repository로 회원 데이터를 저장하고 조회할 수 있습니다.'),
('실무 Spring Boot 백엔드 입문', 'OBJECTIVES', 2, '요청 DTO 검증과 공통 예외 처리로 일관된 API 응답을 만들 수 있습니다.'),
('실무 Spring Boot 백엔드 입문', 'OBJECTIVES', 3, 'Spring Security와 JWT로 로그인과 인증이 필요한 API를 구현할 수 있습니다.'),
('Flutter로 MVP 앱 출시하기', 'TARGET_AUDIENCE', 0, '아이디어를 빠르게 앱으로 만들어 검증하고 싶은 1인 개발자와 창업 준비생'),
('Flutter로 MVP 앱 출시하기', 'TARGET_AUDIENCE', 1, '웹 개발 경험은 있지만 모바일 앱은 처음인 개발자'),
('Flutter로 MVP 앱 출시하기', 'TARGET_AUDIENCE', 2, 'Android와 iOS를 하나의 코드로 함께 출시하고 싶은 분'),
('Flutter로 MVP 앱 출시하기', 'PREREQUISITES', 0, '변수, 함수, 클래스 같은 프로그래밍 기초를 알고 있으면 충분합니다. Dart는 강의에서 함께 익힙니다.'),
('Flutter로 MVP 앱 출시하기', 'PREREQUISITES', 1, 'Flutter SDK와 에뮬레이터 또는 실제 기기를 준비해 두면 실습이 수월합니다.'),
('Flutter로 MVP 앱 출시하기', 'OBJECTIVES', 0, '위젯 트리를 설계하고 상태를 어디에 둘지 판단할 수 있습니다.'),
('Flutter로 MVP 앱 출시하기', 'OBJECTIVES', 1, '라우팅과 입력 폼 검증으로 기본적인 앱 화면 흐름을 만들 수 있습니다.'),
('Flutter로 MVP 앱 출시하기', 'OBJECTIVES', 2, 'REST API를 연동하고 로딩과 오류 상태를 사용자에게 보여 줄 수 있습니다.'),
('Flutter로 MVP 앱 출시하기', 'OBJECTIVES', 3, '앱 아이콘, 권한, 릴리스 빌드를 설정해 스토어 제출을 준비할 수 있습니다.'),
('Next.js 14 제품 개발 실전', 'TARGET_AUDIENCE', 0, 'React는 익숙하지만 App Router와 서버 컴포넌트가 아직 낯선 프론트엔드 개발자'),
('Next.js 14 제품 개발 실전', 'TARGET_AUDIENCE', 1, '데이터가 왜 갱신되지 않는지 캐싱 동작 때문에 고생해 본 분'),
('Next.js 14 제품 개발 실전', 'TARGET_AUDIENCE', 2, '사이드 프로젝트를 실제 배포 가능한 제품 수준으로 끌어올리고 싶은 분'),
('Next.js 14 제품 개발 실전', 'PREREQUISITES', 0, 'React 컴포넌트, props, 상태 관리를 사용해 본 경험이 필요합니다.'),
('Next.js 14 제품 개발 실전', 'PREREQUISITES', 1, 'TypeScript 기본 타입 문법을 읽을 수 있으면 좋습니다.'),
('Next.js 14 제품 개발 실전', 'OBJECTIVES', 0, 'App Router의 라우팅, 레이아웃, 로딩과 에러 화면 구조를 설계할 수 있습니다.'),
('Next.js 14 제품 개발 실전', 'OBJECTIVES', 1, '서버 컴포넌트와 클라이언트 컴포넌트의 경계를 목적에 맞게 나눌 수 있습니다.'),
('Next.js 14 제품 개발 실전', 'OBJECTIVES', 2, 'fetch 캐싱과 revalidate를 조합해 데이터 신선도와 성능을 함께 관리할 수 있습니다.'),
('Next.js 14 제품 개발 실전', 'OBJECTIVES', 3, '인증, 이미지 최적화, 메타데이터를 갖춘 배포용 페이지를 완성할 수 있습니다.'),
('React 19 프론트엔드 실전 가이드', 'TARGET_AUDIENCE', 0, '화면이 커질수록 상태 관리가 꼬여 리팩터링이 두려운 React 개발자'),
('React 19 프론트엔드 실전 가이드', 'TARGET_AUDIENCE', 1, 'React 19의 Actions와 새 훅을 실무 코드에 적용해 보고 싶은 분'),
('React 19 프론트엔드 실전 가이드', 'TARGET_AUDIENCE', 2, 'E2E 테스트로 화면 품질을 지키는 습관을 들이고 싶은 분'),
('React 19 프론트엔드 실전 가이드', 'PREREQUISITES', 0, 'React 컴포넌트와 useState, useEffect를 사용해 본 경험이 필요합니다.'),
('React 19 프론트엔드 실전 가이드', 'PREREQUISITES', 1, 'TypeScript와 Tailwind CSS를 처음 보더라도 따라올 수 있도록 설명합니다.'),
('React 19 프론트엔드 실전 가이드', 'OBJECTIVES', 0, '상태를 둘 위치와 컴포넌트 경계를 근거를 들어 설계할 수 있습니다.'),
('React 19 프론트엔드 실전 가이드', 'OBJECTIVES', 1, 'Actions와 useActionState로 폼 제출과 대기, 오류 상태를 처리할 수 있습니다.'),
('React 19 프론트엔드 실전 가이드', 'OBJECTIVES', 2, 'Tailwind 유틸리티를 일관된 규칙으로 사용해 재사용 가능한 UI를 만들 수 있습니다.'),
('React 19 프론트엔드 실전 가이드', 'OBJECTIVES', 3, 'Playwright로 핵심 사용자 흐름을 자동으로 검증할 수 있습니다.'),
('개발자 이력서와 기술 면접 패키지', 'TARGET_AUDIENCE', 0, '서류 전형에서 계속 떨어져 이력서를 어떻게 고쳐야 할지 모르는 취업 준비생'),
('개발자 이력서와 기술 면접 패키지', 'TARGET_AUDIENCE', 1, '프로젝트 경험은 있지만 성과를 문장으로 표현하기 어려운 신입 개발자'),
('개발자 이력서와 기술 면접 패키지', 'TARGET_AUDIENCE', 2, '기술 면접에서 아는 내용도 조리 있게 답하지 못해 아쉬웠던 분'),
('개발자 이력서와 기술 면접 패키지', 'PREREQUISITES', 0, '팀 프로젝트나 개인 프로젝트를 하나 이상 진행해 본 경험이 있으면 좋습니다.'),
('개발자 이력서와 기술 면접 패키지', 'PREREQUISITES', 1, '현재 이력서 초안이나 GitHub 저장소를 준비해 오면 바로 고쳐 볼 수 있습니다.'),
('개발자 이력서와 기술 면접 패키지', 'OBJECTIVES', 0, '프로젝트 경험을 문제, 행동, 결과가 드러나는 성과 문장으로 바꿀 수 있습니다.'),
('개발자 이력서와 기술 면접 패키지', 'OBJECTIVES', 1, '지원 포지션의 요구 역량에 맞춰 이력서 항목의 우선순위를 정할 수 있습니다.'),
('개발자 이력서와 기술 면접 패키지', 'OBJECTIVES', 2, 'CS 질문과 프로젝트 질문에 결론부터 말하는 구조로 답변할 수 있습니다.'),
('개발자 이력서와 기술 면접 패키지', 'OBJECTIVES', 3, 'README와 배포 링크를 정리해 포트폴리오의 신뢰도를 높일 수 있습니다.'),
('SQL로 끝내는 데이터 분석 기본기', 'TARGET_AUDIENCE', 0, '엑셀로 하던 집계를 SQL로 옮기고 싶은 기획자, 마케터, 비전공자'),
('SQL로 끝내는 데이터 분석 기본기', 'TARGET_AUDIENCE', 1, '데이터 분석가 직무를 준비하며 실무형 쿼리를 연습하고 싶은 분'),
('SQL로 끝내는 데이터 분석 기본기', 'TARGET_AUDIENCE', 2, '매번 손으로 만들던 주간 리포트를 자동화하고 싶은 분'),
('SQL로 끝내는 데이터 분석 기본기', 'PREREQUISITES', 0, '별도 선수 지식은 필요 없습니다. 표 형태의 데이터를 다뤄 본 경험이면 충분합니다.'),
('SQL로 끝내는 데이터 분석 기본기', 'PREREQUISITES', 1, 'Pandas 실습을 위해 Python 실행 환경(Jupyter 등)을 준비하면 좋습니다.'),
('SQL로 끝내는 데이터 분석 기본기', 'OBJECTIVES', 0, 'SELECT, JOIN, GROUP BY로 질문에 맞는 데이터를 정확히 집계할 수 있습니다.'),
('SQL로 끝내는 데이터 분석 기본기', 'OBJECTIVES', 1, '윈도우 함수로 순위, 누적합, 전월 대비 변화량을 계산할 수 있습니다.'),
('SQL로 끝내는 데이터 분석 기본기', 'OBJECTIVES', 2, 'Pandas로 결측치와 이상값을 정리하고 분석용 테이블을 만들 수 있습니다.'),
('SQL로 끝내는 데이터 분석 기본기', 'OBJECTIVES', 3, '매출과 리텐션 지표를 담은 반복 리포트를 자동화할 수 있습니다.'),
('ChatGPT API와 RAG 서비스 만들기', 'TARGET_AUDIENCE', 0, 'LLM API를 서비스에 붙여 보고 싶은 백엔드, 풀스택 개발자'),
('ChatGPT API와 RAG 서비스 만들기', 'TARGET_AUDIENCE', 1, '사내 문서나 FAQ에 답하는 챗봇을 만들어야 하는 분'),
('ChatGPT API와 RAG 서비스 만들기', 'TARGET_AUDIENCE', 2, '모델이 엉뚱한 답을 지어내는 문제를 구조적으로 줄이고 싶은 분'),
('ChatGPT API와 RAG 서비스 만들기', 'PREREQUISITES', 0, 'Python 기본 문법과 함수, 딕셔너리 사용에 익숙하면 좋습니다.'),
('ChatGPT API와 RAG 서비스 만들기', 'PREREQUISITES', 1, 'REST API를 호출해 JSON 응답을 다뤄 본 경험이 있으면 충분합니다.'),
('ChatGPT API와 RAG 서비스 만들기', 'OBJECTIVES', 0, '메시지 역할과 토큰 구조를 이해하고 목적에 맞는 프롬프트를 작성할 수 있습니다.'),
('ChatGPT API와 RAG 서비스 만들기', 'OBJECTIVES', 1, 'LLM API 호출 결과를 검증하고 오류와 재시도를 처리할 수 있습니다.'),
('ChatGPT API와 RAG 서비스 만들기', 'OBJECTIVES', 2, '문서 청킹, 임베딩, 벡터 검색으로 관련 문서를 찾는 파이프라인을 만들 수 있습니다.'),
('ChatGPT API와 RAG 서비스 만들기', 'OBJECTIVES', 3, '검색 결과를 근거로 답변하는 RAG 챗봇을 구현하고 품질을 점검할 수 있습니다.');

INSERT INTO seed_course_quiz (course_title, quiz_title, quiz_description, lesson_title, lesson_description) VALUES
('Docker & Kubernetes 운영 실전', '컨테이너 운영 기초 점검 퀴즈', '이미지와 컨테이너, Dockerfile, Compose의 핵심 개념을 점검합니다.', '섹션 마무리 퀴즈: 이미지와 컨테이너 생명주기', '이미지 레이어, 컨테이너 생명주기, Compose 네트워크와 볼륨을 5문항으로 점검합니다.'),
('실무 Spring Boot 백엔드 입문', 'Spring Boot 계층 구조 점검 퀴즈', 'Controller, Service, Repository의 책임과 요청 처리 흐름을 점검합니다.', '섹션 마무리 퀴즈: Controller-Service-Repository 흐름', '계층별 책임, DTO 사용 이유, 트랜잭션 위치를 5문항으로 점검합니다.'),
('Flutter로 MVP 앱 출시하기', 'Flutter 위젯과 상태 점검 퀴즈', '위젯 트리, 상태 관리, 라우팅과 폼 검증의 핵심을 점검합니다.', '섹션 마무리 퀴즈: 위젯과 상태 흐름', 'StatelessWidget과 StatefulWidget, setState, 라우팅, 폼 검증을 5문항으로 점검합니다.'),
('Next.js 14 제품 개발 실전', 'App Router 데이터 흐름 점검 퀴즈', '레이아웃, 서버 컴포넌트, 캐싱과 revalidate 동작을 점검합니다.', '섹션 마무리 퀴즈: App Router 데이터 흐름', '라우팅 규칙, 서버와 클라이언트 컴포넌트의 경계, 캐싱 전략을 5문항으로 점검합니다.'),
('React 19 프론트엔드 실전 가이드', 'React 상태 설계 점검 퀴즈', '상태 배치, 파생 상태, Actions와 폼 처리 패턴을 점검합니다.', '섹션 마무리 퀴즈: 상태 설계 판단 기준', '상태를 둘 위치, 파생 값 계산, useActionState 사용법을 5문항으로 점검합니다.'),
('개발자 이력서와 기술 면접 패키지', '이력서 문장 점검 퀴즈', '성과 중심 문장, STAR 구조, 이력서 항목 우선순위를 점검합니다.', '섹션 마무리 퀴즈: 이력서 문장 점검', '좋은 이력서 문장과 아쉬운 문장을 구분하는 기준을 5문항으로 점검합니다.'),
('SQL로 끝내는 데이터 분석 기본기', '집계 쿼리 읽기 퀴즈', 'JOIN, GROUP BY, HAVING, 윈도우 함수의 동작을 점검합니다.', '섹션 마무리 퀴즈: 집계 쿼리 읽기', '쿼리 실행 순서와 집계 결과를 예측하는 문제 5문항으로 점검합니다.'),
('ChatGPT API와 RAG 서비스 만들기', '프롬프트와 토큰 관리 퀴즈', '메시지 역할, 토큰, temperature, 구조화 출력의 핵심을 점검합니다.', '섹션 마무리 퀴즈: 프롬프트와 토큰 관리', 'LLM API를 안정적으로 호출하기 위한 기본기를 5문항으로 점검합니다.');

INSERT INTO seed_course_quiz_question (course_title, display_order, question_text, explanation, correct_option, option1, option2, option3, option4) VALUES
('Docker & Kubernetes 운영 실전', 1, 'Docker 이미지와 컨테이너의 관계로 가장 올바른 설명은 무엇인가요?', '이미지는 읽기 전용 실행 템플릿이고, 컨테이너는 그 이미지 위에 쓰기 가능한 레이어를 얹어 실행한 인스턴스입니다.', 2, '컨테이너를 먼저 만들어야 이미지를 빌드할 수 있다', '이미지는 읽기 전용 템플릿이고 컨테이너는 이미지를 실행한 인스턴스다', '이미지와 컨테이너는 항상 같은 ID를 가진다', '컨테이너를 삭제하면 이미지도 함께 삭제된다'),
('Docker & Kubernetes 운영 실전', 2, 'Dockerfile에서 의존성 설치 단계를 소스 코드 복사보다 먼저 두는 주된 이유는 무엇인가요?', '변경이 적은 의존성 레이어를 앞에 두면 소스만 바뀌었을 때 캐시된 레이어를 재사용해 빌드 시간이 크게 줄어듭니다.', 3, '이미지 태그를 자동으로 붙이기 위해서', '컨테이너 실행 권한을 root로 고정하기 위해서', '소스만 바뀌었을 때 의존성 레이어 캐시를 재사용하기 위해서', 'Docker Hub 업로드 순서를 맞추기 위해서'),
('Docker & Kubernetes 운영 실전', 3, '멀티 스테이지 빌드를 사용하면 얻을 수 있는 가장 큰 이점은 무엇인가요?', '빌드 도구와 중간 산출물은 빌드 스테이지에 남기고, 실행에 필요한 결과물만 최종 이미지에 복사해 크기와 공격 면을 줄입니다.', 1, '빌드 도구를 제외한 실행 결과물만 담아 최종 이미지를 작게 만든다', '컨테이너 여러 개를 하나로 합쳐 실행한다', '이미지 빌드 없이 컨테이너를 바로 실행한다', '레지스트리 인증을 생략할 수 있다'),
('Docker & Kubernetes 운영 실전', 4, 'Docker Compose로 띄운 app 컨테이너가 db 컨테이너에 접속할 때 호스트 이름으로 가장 적절한 것은 무엇인가요?', 'Compose는 같은 네트워크 안에서 서비스 이름으로 DNS를 제공하므로 db라는 이름으로 접근합니다.', 4, 'localhost', '127.0.0.1', '호스트 PC의 공인 IP', 'compose 파일에 정의한 서비스 이름인 db'),
('Docker & Kubernetes 운영 실전', 5, '컨테이너를 삭제해도 데이터베이스 데이터를 유지하려면 어떻게 해야 하나요?', '컨테이너의 쓰기 레이어는 컨테이너와 함께 사라지므로, 데이터는 볼륨이나 바인드 마운트로 컨테이너 밖에 저장해야 합니다.', 2, '컨테이너를 재시작하지 않는다', '데이터 디렉터리를 볼륨으로 마운트한다', '이미지 태그를 latest로 고정한다', '컨테이너 이름을 고정한다'),
('실무 Spring Boot 백엔드 입문', 1, 'Controller 계층의 책임으로 가장 적절한 것은 무엇인가요?', 'Controller는 요청을 받아 검증하고 Service에 위임한 뒤 응답을 반환하는 역할에 집중하고, 비즈니스 규칙은 Service에 둡니다.', 3, '주문 금액 할인 정책을 계산한다', 'SQL을 직접 작성해 데이터를 조회한다', '요청을 검증하고 Service를 호출해 응답을 반환한다', '트랜잭션을 시작하고 커밋한다'),
('실무 Spring Boot 백엔드 입문', 2, 'API 응답에 Entity 대신 DTO를 사용하는 이유로 가장 거리가 먼 것은 무엇인가요?', 'DTO는 응답 형태를 고정하고 민감 정보 노출과 지연 로딩 문제를 막기 위해 씁니다. 데이터베이스 저장 속도와는 관계가 없습니다.', 4, '비밀번호 같은 민감 필드 노출을 막는다', 'Entity 구조가 바뀌어도 API 스펙을 유지한다', '지연 로딩 연관관계 직렬화 문제를 피한다', '데이터베이스 INSERT 속도가 빨라진다'),
('실무 Spring Boot 백엔드 입문', 3, '@Transactional을 붙이기에 가장 적절한 위치는 어디인가요?', '하나의 비즈니스 작업 단위가 Service 메서드이므로, 여러 Repository 호출을 하나의 트랜잭션으로 묶으려면 Service에 둡니다.', 2, 'Controller 클래스', '비즈니스 작업 단위를 담당하는 Service 메서드', '요청 DTO 클래스', 'application.yml 파일'),
('실무 Spring Boot 백엔드 입문', 4, '스프링이 생성자 주입을 권장하는 이유로 가장 적절한 것은 무엇인가요?', '생성자 주입은 의존성을 final로 고정해 불변성을 보장하고, 누락이 일찍 드러나며 테스트에서 직접 주입하기도 쉽습니다.', 1, '의존성을 final로 두어 불변성을 보장하고 테스트하기 쉽다', '필드 주입보다 런타임 성능이 항상 빠르다', '스프링 컨테이너 없이도 자동으로 빈이 생성된다', '순환 참조를 자동으로 해결해 준다'),
('실무 Spring Boot 백엔드 입문', 5, 'JWT 기반 인증에서 서버가 매 요청마다 확인하는 것으로 가장 적절한 것은 무엇인가요?', '서버는 세션 저장소를 조회하지 않고, 요청 헤더의 토큰 서명과 만료 시간을 검증해 사용자를 식별합니다.', 3, '서버 메모리에 저장된 세션 ID', '요청 바디에 담긴 비밀번호', '요청 헤더 토큰의 서명과 만료 시간', '클라이언트 IP 주소'),
('Flutter로 MVP 앱 출시하기', 1, 'StatefulWidget이 필요한 상황으로 가장 적절한 것은 무엇인가요?', '사용자 입력이나 시간에 따라 화면이 바뀌는 값을 위젯이 직접 보관해야 할 때 StatefulWidget을 사용합니다.', 2, '고정된 로고 이미지를 보여 줄 때', '버튼을 누를 때마다 바뀌는 카운터 값을 화면에 보여 줄 때', '앱 이름 텍스트를 표시할 때', '정적인 구분선을 그릴 때'),
('Flutter로 MVP 앱 출시하기', 2, 'setState를 호출하면 어떤 일이 일어나나요?', 'setState는 상태가 바뀌었음을 프레임워크에 알려 해당 위젯의 build 메서드를 다시 실행하게 합니다.', 1, '해당 위젯의 build가 다시 실행되어 화면이 갱신된다', '앱 전체가 재시작된다', '서버에 상태가 자동으로 저장된다', '이전 화면으로 이동한다'),
('Flutter로 MVP 앱 출시하기', 3, 'Navigator.push로 새 화면을 열었을 때 이전 화면으로 돌아가는 방법은 무엇인가요?', 'Navigator는 화면을 스택으로 관리하므로 pop을 호출하면 현재 화면을 제거하고 이전 화면이 다시 보입니다.', 4, '앱을 다시 실행한다', 'setState를 호출한다', 'MaterialApp을 새로 만든다', 'Navigator.pop을 호출한다'),
('Flutter로 MVP 앱 출시하기', 4, 'Form과 TextFormField로 입력값을 검증할 때 각 필드의 오류 메시지를 반환하는 곳은 어디인가요?', 'TextFormField의 validator 함수가 오류 문자열을 반환하면 해당 메시지가 필드 아래에 표시되고, null이면 통과입니다.', 3, 'initState', 'dispose', 'TextFormField의 validator', 'AppBar의 title'),
('Flutter로 MVP 앱 출시하기', 5, '비동기로 API 데이터를 불러와 로딩, 성공, 오류 상태를 화면에 나눠 보여 줄 때 자주 쓰는 위젯은 무엇인가요?', 'FutureBuilder는 Future의 진행 상태를 snapshot으로 제공해 로딩, 데이터, 오류 화면을 분기할 수 있게 해 줍니다.', 2, 'Container', 'FutureBuilder', 'Padding', 'Divider'),
('Next.js 14 제품 개발 실전', 1, 'App Router에서 여러 페이지가 공유하는 헤더와 사이드바를 두기에 가장 적절한 파일은 무엇인가요?', 'layout.tsx는 하위 경로가 바뀌어도 다시 마운트되지 않고 유지되므로 공통 UI를 두기에 적합합니다.', 3, 'page.tsx', 'loading.tsx', 'layout.tsx', 'not-found.tsx'),
('Next.js 14 제품 개발 실전', 2, '서버 컴포넌트에 대한 설명으로 올바른 것은 무엇인가요?', '서버 컴포넌트는 서버에서 렌더링되어 데이터베이스나 비밀 키에 직접 접근할 수 있지만, useState 같은 클라이언트 훅은 사용할 수 없습니다.', 1, '서버에서 실행되어 데이터를 직접 조회할 수 있지만 useState는 사용할 수 없다', '브라우저에서만 실행되어 이벤트 핸들러를 자유롭게 쓸 수 있다', '항상 클라이언트 번들에 포함된다', 'use client 지시어를 반드시 파일 맨 위에 적어야 한다'),
('Next.js 14 제품 개발 실전', 3, '버튼 클릭 이벤트와 useState가 필요한 컴포넌트는 어떻게 만들어야 하나요?', '상호작용이 필요한 컴포넌트는 파일 맨 위에 use client를 선언한 클라이언트 컴포넌트로 분리하고, 나머지는 서버 컴포넌트로 유지합니다.', 4, 'layout.tsx 안에 직접 작성한다', 'API 라우트로 옮긴다', 'next.config.js에 등록한다', 'use client를 선언한 클라이언트 컴포넌트로 분리한다'),
('Next.js 14 제품 개발 실전', 4, 'fetch에 next: { revalidate: 60 } 옵션을 주면 어떻게 동작하나요?', '응답을 캐시해 두고 60초가 지난 뒤 들어온 요청에서 다시 가져와 갱신하는 시간 기반 재검증입니다.', 2, '60번 요청할 때마다 캐시를 비운다', '캐시된 데이터를 쓰다가 60초가 지나면 다시 가져와 갱신한다', '요청을 60초 동안 막는다', '60초 안에 응답이 없으면 오류를 낸다'),
('Next.js 14 제품 개발 실전', 5, '이미지 최적화를 위해 Next.js에서 권장하는 방법은 무엇인가요?', 'next/image의 Image 컴포넌트는 크기 지정, 지연 로딩, 최적 포맷 변환을 자동으로 처리해 레이아웃 흔들림과 용량을 줄여 줍니다.', 3, 'img 태그에 원본 고해상도 이미지를 그대로 사용한다', '모든 이미지를 Base64로 인라인한다', 'next/image의 Image 컴포넌트를 사용한다', 'CSS background로만 이미지를 표시한다'),
('React 19 프론트엔드 실전 가이드', 1, '두 형제 컴포넌트가 같은 값을 보고 함께 변경해야 할 때 상태를 어디에 두는 것이 좋나요?', '공유가 필요한 상태는 두 컴포넌트의 가장 가까운 공통 부모로 끌어올려 props로 내려 주는 것이 기본 원칙입니다.', 2, '각 형제 컴포넌트에 같은 상태를 복사해 둔다', '가장 가까운 공통 부모 컴포넌트', '전역 변수', 'localStorage'),
('React 19 프론트엔드 실전 가이드', 2, '목록 배열과 검색어가 상태로 있을 때 필터링된 목록은 어떻게 다루는 것이 좋나요?', '기존 상태로 계산할 수 있는 값은 별도 상태로 두지 말고 렌더링 중에 계산해야 동기화 버그가 생기지 않습니다.', 4, 'useEffect로 필터링 결과를 별도 상태에 복사한다', '검색어가 바뀔 때마다 서버에 저장한다', 'ref에 저장해 둔다', '렌더링할 때 기존 상태로부터 계산한다'),
('React 19 프론트엔드 실전 가이드', 3, 'React 19의 useActionState가 주로 도와주는 일은 무엇인가요?', 'useActionState는 폼 액션의 결과 상태와 대기 여부를 함께 관리해 제출 중 표시와 오류 메시지 처리를 단순하게 만듭니다.', 1, '폼 액션의 결과 상태와 대기 여부를 함께 관리한다', '컴포넌트를 서버로 이동시킨다', 'CSS 클래스를 자동으로 생성한다', '라우팅 경로를 정의한다'),
('React 19 프론트엔드 실전 가이드', 4, '리스트를 렌더링할 때 key로 배열 인덱스를 쓰면 문제가 되는 경우는 언제인가요?', '항목이 삽입, 삭제, 정렬되면 인덱스가 바뀌어 React가 다른 항목의 상태를 재사용하게 되므로 고유 ID를 key로 써야 합니다.', 3, '항목이 절대 바뀌지 않는 정적 목록일 때', '항목 수가 10개 미만일 때', '항목이 삽입되거나 순서가 바뀔 때', 'TypeScript를 사용할 때'),
('React 19 프론트엔드 실전 가이드', 5, 'Playwright E2E 테스트에서 요소를 찾을 때 가장 권장되는 방식은 무엇인가요?', 'getByRole처럼 사용자가 인식하는 역할과 이름으로 찾으면 CSS 구조 변경에 덜 깨지고 접근성도 함께 점검됩니다.', 2, 'nth-child가 포함된 CSS 선택자', 'getByRole처럼 역할과 접근성 이름으로 찾기', '자동 생성된 클래스 이름', 'XPath 절대 경로'),
('개발자 이력서와 기술 면접 패키지', 1, '다음 중 성과가 가장 잘 드러나는 이력서 문장은 무엇인가요?', '무엇을 했는지와 함께 수치로 확인되는 결과가 들어가야 채용 담당자가 기여도를 판단할 수 있습니다.', 3, 'Spring Boot, JPA, Redis를 사용했습니다', '성실하게 프로젝트에 참여했습니다', '목록 조회 API에 캐시를 적용해 평균 응답 시간을 820ms에서 120ms로 줄였습니다', '백엔드 개발을 담당했습니다'),
('개발자 이력서와 기술 면접 패키지', 2, 'STAR 구조의 네 요소를 올바르게 나열한 것은 무엇인가요?', 'STAR는 상황(Situation), 과제(Task), 행동(Action), 결과(Result) 순서로 경험을 정리하는 방법입니다.', 1, '상황, 과제, 행동, 결과', '기술, 팀, 역할, 회고', '시작, 테스트, 분석, 리뷰', '스택, 타임라인, 아키텍처, 리소스'),
('개발자 이력서와 기술 면접 패키지', 3, '신입 이력서에서 프로젝트 항목을 배치하는 기준으로 가장 적절한 것은 무엇인가요?', '지원 포지션의 요구 역량과 가장 관련 있는 프로젝트를 위에 두어야 짧은 검토 시간 안에 적합성이 전달됩니다.', 4, '진행한 날짜가 오래된 순서', '참여 인원이 많은 순서', '사용한 기술 수가 많은 순서', '지원 포지션과 관련성이 높은 순서'),
('개발자 이력서와 기술 면접 패키지', 4, '기술 면접에서 모르는 질문을 받았을 때 가장 바람직한 태도는 무엇인가요?', '모르는 부분은 솔직히 인정하고, 알고 있는 관련 개념과 추론 과정을 말하면 문제 해결 방식을 보여 줄 수 있습니다.', 2, '아는 척하며 비슷한 용어로 길게 답한다', '모른다고 인정한 뒤 알고 있는 관련 개념과 추론 과정을 설명한다', '질문을 다음으로 넘겨 달라고 요청한다', '대답하지 않고 침묵한다'),
('개발자 이력서와 기술 면접 패키지', 5, '포트폴리오 GitHub README에 가장 먼저 들어가야 할 내용은 무엇인가요?', '처음 보는 사람이 프로젝트가 무엇을 해결하는지와 실행 결과를 바로 볼 수 있어야 하므로 한 줄 소개와 배포 링크, 화면을 먼저 둡니다.', 1, '프로젝트 한 줄 소개와 배포 링크, 주요 화면', '사용한 라이브러리 전체 버전 목록', '커밋 메시지 규칙', '라이선스 전문'),
('SQL로 끝내는 데이터 분석 기본기', 1, 'SQL 쿼리의 논리적 실행 순서로 올바른 것은 무엇인가요?', 'FROM과 WHERE로 대상 행을 고른 뒤 GROUP BY로 묶고 HAVING으로 그룹을 거른 다음 SELECT와 ORDER BY가 처리됩니다.', 2, 'SELECT, FROM, WHERE, GROUP BY, ORDER BY', 'FROM, WHERE, GROUP BY, HAVING, SELECT, ORDER BY', 'WHERE, FROM, SELECT, HAVING, GROUP BY', 'ORDER BY, SELECT, FROM, WHERE'),
('SQL로 끝내는 데이터 분석 기본기', 2, '주문이 한 건도 없는 고객까지 포함해 고객별 주문 수를 구하려면 어떤 JOIN을 써야 하나요?', 'LEFT JOIN은 왼쪽 테이블(고객)의 모든 행을 유지하므로 주문이 없는 고객도 결과에 남고, COUNT(주문 컬럼)는 0이 됩니다.', 3, 'INNER JOIN', 'CROSS JOIN', 'customers LEFT JOIN orders', 'orders INNER JOIN customers'),
('SQL로 끝내는 데이터 분석 기본기', 3, '카테고리별 매출 합계가 100만 원 이상인 카테고리만 남기려면 조건을 어디에 써야 하나요?', '집계 결과에 대한 조건은 그룹이 만들어진 뒤 적용되는 HAVING에 작성해야 합니다.', 4, 'WHERE SUM(amount) >= 1000000', 'ORDER BY SUM(amount) >= 1000000', 'SELECT 절 안의 IF', 'HAVING SUM(amount) >= 1000000'),
('SQL로 끝내는 데이터 분석 기본기', 4, 'ROW_NUMBER, RANK, DENSE_RANK 중 동점일 때 같은 순위를 주고 다음 순위를 건너뛰지 않는 함수는 무엇인가요?', 'DENSE_RANK는 동점에 같은 순위를 주고 다음 순위를 연속 번호로 이어 갑니다. RANK는 다음 순위를 건너뜁니다.', 1, 'DENSE_RANK', 'ROW_NUMBER', 'RANK', 'NTILE'),
('SQL로 끝내는 데이터 분석 기본기', 5, 'Pandas에서 결측치가 있는 행을 제거하는 메서드는 무엇인가요?', 'dropna는 결측치가 포함된 행이나 열을 제거하고, fillna는 결측치를 다른 값으로 채웁니다.', 3, 'fillna', 'groupby', 'dropna', 'merge'),
('ChatGPT API와 RAG 서비스 만들기', 1, 'Chat API 요청에서 system 메시지의 역할로 가장 적절한 것은 무엇인가요?', 'system 메시지는 모델의 역할, 말투, 지켜야 할 규칙처럼 대화 전체에 적용될 지침을 설정합니다.', 2, '사용자의 질문을 담는다', '모델의 역할과 응답 규칙 같은 전체 지침을 설정한다', '모델의 이전 답변을 저장한다', 'API 키를 전달한다'),
('ChatGPT API와 RAG 서비스 만들기', 2, '토큰에 대한 설명으로 올바른 것은 무엇인가요?', '모델은 텍스트를 토큰 단위로 처리하며, 입력과 출력 토큰 수가 비용과 컨텍스트 길이 제한에 함께 반영됩니다.', 4, '토큰은 항상 단어 하나와 정확히 같다', '출력 토큰만 비용에 포함된다', '컨텍스트 길이에는 제한이 없다', '입력과 출력 토큰 수가 비용과 컨텍스트 한도에 함께 반영된다'),
('ChatGPT API와 RAG 서비스 만들기', 3, 'temperature 값을 낮추면 응답이 어떻게 달라지나요?', 'temperature가 낮을수록 확률이 높은 토큰을 고르는 경향이 강해져 응답이 일관되고 예측 가능해집니다.', 1, '응답이 더 일관되고 예측 가능해진다', '응답이 더 길어진다', '모델이 더 많은 문서를 검색한다', '응답 속도가 항상 두 배 빨라진다'),
('ChatGPT API와 RAG 서비스 만들기', 4, '모델 응답을 프로그램에서 안정적으로 파싱하려면 어떻게 하는 것이 좋나요?', 'JSON 스키마 같은 구조화 출력을 요구하고, 받은 결과를 코드에서 검증해야 형식 오류를 안전하게 처리할 수 있습니다.', 3, '자연어 응답을 정규식으로 대충 잘라 쓴다', '응답 길이를 최대로 늘린다', '구조화 출력(JSON 스키마)을 요구하고 결과를 검증한다', 'temperature를 최대로 올린다'),
('ChatGPT API와 RAG 서비스 만들기', 5, 'RAG를 도입하는 가장 큰 이유는 무엇인가요?', 'RAG는 질문과 관련된 외부 문서를 검색해 근거로 함께 전달하므로 모델이 모르는 사내 정보에도 답할 수 있고 환각을 줄입니다.', 2, '모델 파라미터를 직접 수정하기 위해', '모델이 모르는 문서를 검색해 근거로 제공하기 위해', 'API 호출 비용을 0으로 만들기 위해', '응답 언어를 바꾸기 위해');

INSERT INTO seed_course_assignment (course_title, assignment_title, assignment_description, submission_rule, lesson_title, lesson_description) VALUES
('Docker & Kubernetes 운영 실전', '무중단 배포 매니페스트 작성',
'상황.
운영 중인 Spring Boot API 서버를 Kubernetes로 옮기려 합니다. 배포 중에도 요청이 끊기면 안 되고, DB 접속 정보는 이미지에 넣지 않아야 합니다.

요구사항.
1. 멀티 스테이지 Dockerfile로 애플리케이션 이미지를 빌드하세요.
2. replicas 2 이상인 Deployment와 이를 노출하는 Service를 작성하세요.
3. 일반 설정은 ConfigMap, DB 비밀번호는 Secret으로 분리해 환경 변수로 주입하세요.
4. RollingUpdate 전략(maxUnavailable 0)과 readinessProbe, livenessProbe를 설정하세요.
5. 새 버전 배포 중 요청이 끊기지 않는 것을 확인한 방법을 README에 적으세요.

제출물.
GitHub 저장소 URL과 README 요약. README에는 매니페스트 구조, 배포 명령어, 무중단 확인 결과를 포함하세요.',
'GitHub 저장소 URL을 제출하고, 텍스트 칸에 배포 명령어와 무중단 확인 결과를 요약하세요. 저장소에는 Dockerfile, k8s 매니페스트, README가 있어야 합니다.',
'실습 과제: 무중단 배포 매니페스트 작성', 'Deployment, Service, ConfigMap, Secret과 프로브를 갖춘 무중단 배포 매니페스트를 제출합니다.'),
('실무 Spring Boot 백엔드 입문', '회원 API와 JWT 로그인 완성',
'상황.
서비스의 첫 기능으로 회원가입과 로그인을 만들어야 합니다. 프론트엔드는 로그인 후 받은 토큰으로 내 정보를 조회합니다.

요구사항.
1. 회원가입 API(POST /api/users)를 만들고 이메일 중복과 입력값을 검증하세요.
2. 비밀번호는 BCrypt로 암호화해 저장하세요.
3. 로그인 API에서 JWT 액세스 토큰을 발급하세요.
4. 토큰이 있어야만 호출되는 내 정보 조회 API(GET /api/users/me)를 만드세요.
5. Controller, Service, Repository 책임을 분리하고 공통 예외 응답 형식을 정하세요.

제출물.
GitHub 저장소 URL과 API 호출 예시(요청, 응답)를 정리한 README.',
'GitHub 저장소 URL을 제출하세요. README에 API 목록, 실행 방법, 회원가입부터 내 정보 조회까지의 호출 예시를 포함하세요.',
'실습 과제: 회원 API와 JWT 로그인 완성', '회원가입, 로그인, 내 정보 조회 API를 JWT 인증과 함께 구현해 제출합니다.'),
('Flutter로 MVP 앱 출시하기', '스토어 제출용 MVP 화면 완성',
'상황.
할 일 관리 MVP 앱을 2주 안에 테스터에게 배포해야 합니다. 핵심 흐름만 완성도 있게 동작하면 됩니다.

요구사항.
1. 목록, 상세, 작성 화면 3개를 만들고 Navigator로 연결하세요.
2. 작성 화면은 Form과 validator로 빈 제목을 막으세요.
3. 목록 데이터는 REST API(또는 목업 API)에서 불러오고 로딩과 오류 상태를 보여 주세요.
4. 앱 아이콘과 앱 이름, 필요한 권한을 설정하세요.
5. 릴리스 빌드를 만들고 실행 화면을 캡처하세요.

제출물.
GitHub 저장소 URL과 주요 화면 캡처, 릴리스 빌드 확인 내용을 담은 README.',
'GitHub 저장소 URL을 제출하고, 화면 캡처 3장 이상을 README 또는 첨부 파일로 포함하세요.',
'실습 과제: 스토어 제출용 MVP 화면 완성', '목록, 상세, 작성 화면과 API 연동, 릴리스 빌드까지 갖춘 MVP 앱을 제출합니다.'),
('Next.js 14 제품 개발 실전', '예약 상세 페이지 출시 체크리스트',
'상황.
숙소 예약 서비스의 상세 페이지를 출시해야 합니다. 검색 노출과 첫 화면 속도가 중요하고, 예약 버튼은 로그인한 사용자만 사용할 수 있습니다.

요구사항.
1. /rooms/[id] 동적 경로에 상세 페이지를 만들고 서버 컴포넌트에서 데이터를 조회하세요.
2. 가격과 남은 객실 수는 revalidate 60초로, 숙소 소개는 정적으로 캐싱하세요.
3. 예약 버튼은 클라이언트 컴포넌트로 분리하고 비로그인 시 로그인 페이지로 보내세요.
4. next/image로 대표 이미지를 최적화하고 generateMetadata로 제목과 설명을 설정하세요.
5. loading.tsx와 not-found.tsx를 작성하세요.

제출물.
GitHub 저장소 URL, 배포 URL(선택), 출시 체크리스트를 정리한 README.',
'GitHub 저장소 URL을 제출하세요. 배포했다면 배포 URL도 함께 적고, README에 캐싱 전략을 선택한 이유를 적으세요.',
'실습 과제: 예약 상세 페이지 출시 체크리스트', '캐싱 전략, 인증, 이미지 최적화, 메타데이터를 갖춘 상세 페이지를 제출합니다.'),
('React 19 프론트엔드 실전 가이드', '테스트를 갖춘 대시보드 화면 완성',
'상황.
운영팀이 매일 보는 주문 대시보드를 새로 만들어야 합니다. 필터를 바꿔도 화면이 꼬이지 않아야 하고, 주요 흐름은 자동 테스트로 지켜야 합니다.

요구사항.
1. 요약 카드, 주문 목록, 상태 필터, 검색 입력으로 구성된 대시보드를 만드세요.
2. 필터링된 목록은 별도 상태 없이 렌더링 중에 계산하세요.
3. 주문 메모 저장 폼을 Actions와 useActionState로 구현하고 대기, 오류 상태를 표시하세요.
4. Tailwind로 카드와 표 스타일을 일관되게 작성하세요.
5. 필터 변경과 메모 저장 흐름을 Playwright 테스트 2개 이상으로 검증하세요.

제출물.
GitHub 저장소 URL과 테스트 실행 결과를 정리한 README.',
'GitHub 저장소 URL을 제출하세요. README에 컴포넌트 구조도와 상태 배치 이유, 테스트 실행 결과를 포함하세요.',
'실습 과제: 대시보드 화면 완성', '상태 설계와 Actions, Playwright 테스트를 갖춘 대시보드를 제출합니다.'),
('개발자 이력서와 기술 면접 패키지', '지원 포지션 맞춤 이력서 완성',
'상황.
실제로 지원하고 싶은 채용 공고 하나를 골라, 그 포지션에 맞춘 이력서를 완성합니다.

요구사항.
1. 지원할 채용 공고의 핵심 요구 역량 3가지를 정리하세요.
2. 요구 역량과 관련 있는 프로젝트를 2개 이상 골라 위쪽에 배치하세요.
3. 프로젝트마다 STAR 구조로 성과 문장을 3개 이상 작성하고, 가능하면 수치를 넣으세요.
4. 기술 스택은 사용 경험이 설명 가능한 것만 남기세요.
5. 예상 면접 질문 3개와 답변 요약을 함께 작성하세요.

제출물.
PDF 이력서 파일 또는 노션 등 공개 링크, 그리고 수정 전후 비교 요약.',
'이력서 PDF를 첨부하거나 공개 링크를 제출하세요. 텍스트 칸에는 채용 공고 요약과 수정 전후 비교를 적으세요.',
'실습 과제: 지원 포지션 맞춤 이력서 완성', '채용 공고에 맞춰 성과 문장과 면접 답변을 정리한 이력서를 제출합니다.'),
('SQL로 끝내는 데이터 분석 기본기', '매출 리텐션 리포트 작성',
'상황.
쇼핑몰 운영팀이 월별 매출 추이와 재구매 고객 비율을 매주 확인하고 싶어 합니다. 제공된 주문, 고객 샘플 데이터로 리포트를 만들어 주세요.

요구사항.
1. 월별 매출 합계와 전월 대비 증감률을 SQL 윈도우 함수로 계산하세요.
2. 카테고리별 매출 상위 3개 상품을 구하세요.
3. 첫 구매 월 기준으로 다음 달 재구매율(리텐션)을 계산하세요.
4. Pandas로 결측치와 이상값을 정리한 뒤 결과 테이블을 만드세요.
5. 결과를 바탕으로 운영팀에 전할 인사이트 3가지를 적으세요.

제출물.
SQL 파일과 노트북(또는 스크립트), 결과 요약 문서.',
'SQL과 노트북 파일을 zip으로 첨부하거나 GitHub 저장소 URL을 제출하세요. 텍스트 칸에는 인사이트 3가지를 요약하세요.',
'실습 과제: 매출 리텐션 리포트 작성', '월별 매출, 상위 상품, 리텐션을 계산한 분석 리포트를 제출합니다.'),
('ChatGPT API와 RAG 서비스 만들기', '사내 문서 Q&A 챗봇 프로토타입',
'상황.
사내 위키 문서 20여 개를 바탕으로 직원 질문에 답하는 챗봇이 필요합니다. 근거 없는 답변은 하지 않아야 합니다.

요구사항.
1. 문서를 적절한 크기로 청킹하고 임베딩을 벡터 저장소에 저장하세요.
2. 질문과 유사한 문서 상위 k개를 검색해 프롬프트에 근거로 넣으세요.
3. 근거 문서에 없는 내용은 모른다고 답하도록 system 메시지를 작성하세요.
4. 답변과 함께 참고한 문서 제목을 출처로 보여 주세요.
5. 질문 5개로 답변 품질을 점검하고, 잘못된 답변이 있었다면 원인과 개선 방법을 적으세요.

제출물.
GitHub 저장소 URL과 품질 점검 결과를 담은 README.',
'GitHub 저장소 URL을 제출하세요. API 키는 절대 커밋하지 말고, README에 청킹 기준과 품질 점검 결과를 정리하세요.',
'실습 과제: 사내 문서 Q&A 챗봇 프로토타입', '문서 검색과 출처 표시를 갖춘 RAG 챗봇 프로토타입을 제출합니다.');

INSERT INTO seed_course_assignment_rubric (course_title, display_order, criteria_name, criteria_description, max_points) VALUES
('Docker & Kubernetes 운영 실전', 1, '이미지 빌드 품질', '멀티 스테이지 빌드와 레이어 캐시를 고려해 작고 재현 가능한 이미지를 만들었습니다.', 20),
('Docker & Kubernetes 운영 실전', 2, '매니페스트 구성', 'Deployment, Service, ConfigMap, Secret이 역할에 맞게 분리되어 있습니다.', 30),
('Docker & Kubernetes 운영 실전', 3, '무중단 배포 설정', 'RollingUpdate 전략과 프로브 설정이 올바르고 무중단 확인 근거가 있습니다.', 35),
('Docker & Kubernetes 운영 실전', 4, '문서화', 'README만 보고도 배포와 검증을 재현할 수 있습니다.', 15),
('실무 Spring Boot 백엔드 입문', 1, '계층 분리', 'Controller, Service, Repository 책임이 명확하고 Entity를 직접 응답하지 않습니다.', 25),
('실무 Spring Boot 백엔드 입문', 2, '입력 검증과 예외 처리', '요청 검증과 중복 이메일 처리, 공통 오류 응답이 일관됩니다.', 25),
('실무 Spring Boot 백엔드 입문', 3, '인증 구현', '비밀번호 암호화와 JWT 발급, 인증 필터가 올바르게 동작합니다.', 35),
('실무 Spring Boot 백엔드 입문', 4, '문서화', '실행 방법과 API 호출 예시가 README에 정리되어 있습니다.', 15),
('Flutter로 MVP 앱 출시하기', 1, '화면 흐름', '목록, 상세, 작성 화면이 자연스럽게 연결됩니다.', 25),
('Flutter로 MVP 앱 출시하기', 2, '입력 검증과 상태 처리', '폼 검증과 로딩, 오류 상태가 사용자에게 명확히 보입니다.', 30),
('Flutter로 MVP 앱 출시하기', 3, 'API 연동', '데이터를 불러오고 실패 시 재시도나 안내가 가능합니다.', 25),
('Flutter로 MVP 앱 출시하기', 4, '출시 준비', '아이콘, 앱 이름, 권한, 릴리스 빌드 설정을 확인했습니다.', 20),
('Next.js 14 제품 개발 실전', 1, '렌더링 경계', '서버 컴포넌트와 클라이언트 컴포넌트가 목적에 맞게 분리되어 있습니다.', 30),
('Next.js 14 제품 개발 실전', 2, '캐싱 전략', '데이터 성격에 따라 정적 캐싱과 revalidate를 근거 있게 선택했습니다.', 30),
('Next.js 14 제품 개발 실전', 3, '인증과 예외 화면', '비로그인 처리, loading, not-found 화면이 갖춰져 있습니다.', 20),
('Next.js 14 제품 개발 실전', 4, '출시 품질', '이미지 최적화와 메타데이터가 설정되어 있습니다.', 20),
('React 19 프론트엔드 실전 가이드', 1, '상태 설계', '상태 위치가 적절하고 파생 값을 중복 상태로 두지 않았습니다.', 30),
('React 19 프론트엔드 실전 가이드', 2, '폼 처리', 'Actions와 useActionState로 대기, 오류 상태를 처리했습니다.', 25),
('React 19 프론트엔드 실전 가이드', 3, 'UI 일관성', 'Tailwind 스타일 규칙이 일관되고 반응형으로 동작합니다.', 20),
('React 19 프론트엔드 실전 가이드', 4, '테스트', '핵심 사용자 흐름을 검증하는 Playwright 테스트가 통과합니다.', 25),
('개발자 이력서와 기술 면접 패키지', 1, '포지션 적합성', '채용 공고의 요구 역량과 이력서 내용이 연결되어 있습니다.', 30),
('개발자 이력서와 기술 면접 패키지', 2, '성과 문장', 'STAR 구조와 수치로 기여와 결과가 드러납니다.', 35),
('개발자 이력서와 기술 면접 패키지', 3, '가독성', '핵심 정보가 한눈에 보이도록 구성과 분량이 정리되어 있습니다.', 15),
('개발자 이력서와 기술 면접 패키지', 4, '면접 준비', '예상 질문과 답변이 결론부터 말하는 구조로 정리되어 있습니다.', 20),
('SQL로 끝내는 데이터 분석 기본기', 1, '쿼리 정확성', '집계와 윈도우 함수 결과가 요구사항과 일치합니다.', 35),
('SQL로 끝내는 데이터 분석 기본기', 2, '데이터 정제', '결측치와 이상값을 처리한 기준이 명확합니다.', 20),
('SQL로 끝내는 데이터 분석 기본기', 3, '리텐션 계산', '첫 구매 월 기준 재구매율 계산 로직이 올바릅니다.', 25),
('SQL로 끝내는 데이터 분석 기본기', 4, '인사이트', '결과에서 근거 있는 인사이트를 도출했습니다.', 20),
('ChatGPT API와 RAG 서비스 만들기', 1, '검색 파이프라인', '청킹, 임베딩, 검색이 올바르게 연결되어 있습니다.', 30),
('ChatGPT API와 RAG 서비스 만들기', 2, '프롬프트 설계', '근거 밖 질문을 거절하고 출처를 표시하도록 설계했습니다.', 25),
('ChatGPT API와 RAG 서비스 만들기', 3, '품질 점검', '테스트 질문으로 답변을 점검하고 개선 방향을 제시했습니다.', 30),
('ChatGPT API와 RAG 서비스 만들기', 4, '보안과 문서화', 'API 키를 분리했고 README로 재현할 수 있습니다.', 15);

INSERT INTO seed_course_content (course_title, subtitle, description) VALUES
('로드맵 실전: 인터넷 & 웹 기초', '주소창에 URL을 입력한 순간부터 화면이 뜨기까지, 웹의 동작 원리를 한 흐름으로 잇습니다',
'백엔드든 프론트엔드든 모든 웹 개발은 브라우저와 서버가 주고받는 요청 하나에서 시작합니다. 그런데 DNS, TCP, HTTP, 호스팅 같은 개념을 따로따로 외우면 정작 장애가 났을 때 어디부터 봐야 할지 감이 오지 않습니다.

첫 섹션에서는 도메인이 DNS 조회를 거쳐 IP 주소로 바뀌고, TCP 연결과 TLS 핸드셰이크를 지나 HTTP 요청이 서버에 도착하기까지의 과정을 한 장의 지도로 정리합니다. 요청 메서드와 상태 코드, 헤더가 각각 무엇을 알려 주는지도 함께 익힙니다.

두 번째 섹션에서는 개발자 도구 Network 탭으로 실제 요청을 뜯어보고, 도메인을 연결해 웹 호스팅에 정적 페이지를 배포해 봅니다. 마지막 과제로 내가 배포한 페이지의 요청 흐름을 직접 추적해 문서로 남깁니다.'),
('로드맵 실전: OS & 터미널', '프로세스, 스레드, 메모리를 터미널 명령어로 직접 관찰하며 운영체제를 이해합니다',
'서버가 갑자기 느려지거나 메모리 부족으로 프로세스가 죽었을 때, 원인을 찾으려면 운영체제가 프로그램을 어떻게 실행하고 자원을 나누는지 알아야 합니다. 이 강의는 운영체제 이론을 터미널에서 바로 확인하는 방식으로 익힙니다.

첫 섹션에서는 프로세스와 스레드의 차이, 컨텍스트 스위칭, 가상 메모리와 페이지 폴트, 파일 디스크립터 같은 핵심 개념을 정리합니다. 개념마다 ps, top, free, lsof 같은 명령어로 실제 수치를 확인합니다.

두 번째 섹션에서는 셸 스크립트로 반복 작업을 자동화하고, 파일 권한과 프로세스 시그널을 다루며, CPU나 메모리가 튀는 프로세스를 찾아내는 장애 점검 시나리오를 따라갑니다. 마지막 과제로 서버 상태 점검 스크립트를 직접 만듭니다.'),
('로드맵 실전: Java 기초', '객체지향, 인터페이스, 제네릭, 컬렉션까지 백엔드 개발에 필요한 Java 기본기를 다집니다',
'Spring을 배우다 막히는 지점의 상당수는 사실 Java 기본기에서 옵니다. 인터페이스로 역할을 나누는 이유, 제네릭 타입이 컴파일 시점에 무엇을 막아 주는지, 컬렉션마다 성능이 어떻게 다른지 알면 프레임워크 코드도 훨씬 잘 읽힙니다.

첫 섹션에서는 클래스와 객체, 캡슐화, 상속과 다형성, 추상 클래스와 인터페이스의 차이를 예제 중심으로 정리합니다. 언제 상속 대신 조합을 써야 하는지도 함께 다룹니다.

두 번째 섹션에서는 제네릭과 List, Set, Map 컬렉션을 실무 코드처럼 사용해 보고, equals와 hashCode, 불변 객체, 예외 처리 같은 자주 실수하는 부분을 점검합니다. 마지막 과제로 도서 대여 도메인을 객체지향적으로 설계합니다.'),
('로드맵 실전: Git & 버전 관리', '커밋과 브랜치의 원리부터 PR 협업까지, 팀에서 바로 쓰는 Git 워크플로우를 익힙니다',
'혼자 할 때는 add, commit, push만 알아도 충분하지만 팀으로 일하는 순간 충돌, 잘못된 커밋, 꼬인 브랜치를 만나게 됩니다. Git이 변경 이력을 어떻게 저장하는지 이해하면 이런 상황에서도 당황하지 않고 되돌릴 수 있습니다.

첫 섹션에서는 작업 디렉터리, 스테이징 영역, 저장소의 세 영역과 커밋이 스냅샷으로 저장되는 원리를 정리합니다. 브랜치와 merge, rebase의 차이, GitFlow와 GitHub Flow 같은 브랜치 전략도 함께 살펴봅니다.

두 번째 섹션에서는 Pull Request로 리뷰를 주고받는 흐름, 충돌 해결, revert와 reset으로 실수를 되돌리는 방법을 실습합니다. 마지막 과제로 팀 브랜치 전략을 정하고 PR 회고를 작성합니다.'),
('로드맵 실전: RDB & SQL', '테이블 설계, JOIN, 인덱스, 트랜잭션까지 백엔드 개발자의 데이터베이스 기본기를 잡습니다',
'대부분의 백엔드 서비스는 관계형 데이터베이스에 핵심 데이터를 저장합니다. 테이블을 어떻게 나누고 어떤 인덱스를 거느냐에 따라 데이터 정합성과 조회 성능이 크게 달라집니다.

첫 섹션에서는 기본키와 외래키로 테이블 관계를 설계하는 방법, 정규화의 목적, INNER JOIN과 LEFT JOIN, 서브쿼리를 언제 쓰는지 예제로 정리합니다. 쿼리 결과를 머릿속으로 예측하는 연습도 함께 합니다.

두 번째 섹션에서는 인덱스가 조회를 빠르게 만드는 원리와 쓰기 비용, 실행 계획을 읽는 방법, 트랜잭션과 ACID, 격리 수준이 동시성 문제를 어떻게 막는지 다룹니다. 마지막 과제로 주문 도메인의 스키마와 핵심 쿼리를 설계합니다.'),
('로드맵 실전: REST API 설계', '자원 중심 URI, 올바른 메서드와 상태 코드, 문서화까지 협업하기 좋은 API를 설계합니다',
'API는 프론트엔드, 모바일, 다른 서비스가 함께 쓰는 약속입니다. 엔드포인트 이름이 제각각이고 실패해도 200을 돌려주는 API는 쓰는 쪽이 매번 코드를 열어 봐야 해서 협업 비용이 커집니다.

첫 섹션에서는 자원을 명사로 표현하는 URI 설계, GET, POST, PUT, PATCH, DELETE의 의미와 멱등성, 상황별로 알맞은 HTTP 상태 코드를 정리합니다.

두 번째 섹션에서는 페이지네이션과 필터링, 일관된 오류 응답 형식, 버전 관리 전략을 다루고 Swagger로 API 문서를 자동화합니다. 마지막 과제로 실제 서비스 하나의 API 명세를 설계하고 문서로 공개합니다.'),
('로드맵 실전: Spring Boot & MVC', 'DI와 빈 등록부터 MVC 요청 처리, 3계층 구조까지 Spring의 뼈대를 이해합니다',
'Spring Boot는 설정을 많이 대신해 주지만, 내부에서 무슨 일이 일어나는지 모르면 빈이 주입되지 않거나 요청이 엉뚱한 곳으로 갈 때 원인을 찾기 어렵습니다.

첫 섹션에서는 IoC 컨테이너가 빈을 만들고 의존성을 주입하는 과정, 컴포넌트 스캔과 설정 클래스, 빈 스코프를 정리합니다. 생성자 주입을 권장하는 이유도 코드로 확인합니다.

두 번째 섹션에서는 DispatcherServlet이 요청을 컨트롤러에 연결하는 흐름, 요청 파라미터와 바디 바인딩, 검증과 전역 예외 처리를 다루고 Controller, Service, Repository로 책임을 나눕니다. 마지막 과제로 게시판 API를 3계층 구조로 구현합니다.'),
('로드맵 실전: Spring Data JPA', 'Entity 매핑부터 연관관계, N+1 문제 해결까지 JPA를 실무 수준으로 다룹니다',
'JPA를 쓰면 SQL을 덜 쓰게 되지만, 영속성 컨텍스트와 지연 로딩을 이해하지 못하면 쿼리가 수십 번 나가거나 원하지 않는 업데이트가 발생합니다.

첫 섹션에서는 Entity와 테이블 매핑, 연관관계의 주인, 영속성 컨텍스트와 변경 감지, Spring Data JPA 메서드 쿼리와 JPQL 작성법을 정리합니다.

두 번째 섹션에서는 FetchType에 따른 로딩 차이, N+1 문제가 생기는 원리와 fetch join, EntityGraph, 배치 사이즈로 해결하는 방법, QueryDSL로 동적 쿼리를 작성하는 방법을 다룹니다. 마지막 과제로 실제 N+1 문제를 찾아 개선하고 쿼리 수 변화를 측정합니다.'),
('로드맵 실전: Redis 기초', 'Redis 자료구조와 TTL, Spring Cache로 조회 성능을 끌어올리는 캐시를 설계합니다',
'같은 데이터를 매번 데이터베이스에서 읽으면 트래픽이 늘수록 응답이 느려집니다. Redis는 메모리 기반 저장소라 자주 읽는 데이터를 캐시해 두기에 적합하고, 다양한 자료구조로 랭킹이나 카운터 같은 기능도 쉽게 만들 수 있습니다.

첫 섹션에서는 String, List, Set, Sorted Set, Hash 자료구조의 특징과 쓰임새, TTL로 데이터 수명을 관리하는 방법, 싱글 스레드 구조가 가지는 의미를 정리합니다.

두 번째 섹션에서는 Cache-Aside 패턴과 Spring Cache 추상화로 조회 API에 캐시를 적용하고, 캐시 무효화 시점과 캐시 스탬피드 같은 실무 문제를 다룹니다. 마지막 과제로 인기 게시글 API에 캐시를 적용하고 성능 변화를 측정합니다.');

INSERT INTO seed_course_info (course_title, section_key, item_order, item_text) VALUES
('로드맵 실전: 인터넷 & 웹 기초', 'TARGET_AUDIENCE', 0, '웹 개발을 막 시작해 브라우저와 서버가 어떻게 통신하는지 큰 그림이 필요한 입문자'),
('로드맵 실전: 인터넷 & 웹 기초', 'TARGET_AUDIENCE', 1, 'DNS, HTTP, 호스팅 용어는 들어 봤지만 서로 어떻게 연결되는지 설명하기 어려운 분'),
('로드맵 실전: 인터넷 & 웹 기초', 'TARGET_AUDIENCE', 2, '면접에서 URL 입력 후 일어나는 일을 조리 있게 답하고 싶은 취업 준비생'),
('로드맵 실전: 인터넷 & 웹 기초', 'PREREQUISITES', 0, '별도 선수 지식은 필요 없습니다. 브라우저와 터미널을 열 수 있으면 충분합니다.'),
('로드맵 실전: 인터넷 & 웹 기초', 'PREREQUISITES', 1, 'HTML 파일을 직접 만들어 본 경험이 있으면 배포 실습이 더 쉽습니다.'),
('로드맵 실전: 인터넷 & 웹 기초', 'OBJECTIVES', 0, 'URL 입력부터 화면 표시까지 DNS, TCP, TLS, HTTP 단계를 순서대로 설명할 수 있습니다.'),
('로드맵 실전: 인터넷 & 웹 기초', 'OBJECTIVES', 1, 'HTTP 메서드와 상태 코드, 주요 헤더의 의미를 구분할 수 있습니다.'),
('로드맵 실전: 인터넷 & 웹 기초', 'OBJECTIVES', 2, '개발자 도구 Network 탭으로 요청과 응답을 분석할 수 있습니다.'),
('로드맵 실전: 인터넷 & 웹 기초', 'OBJECTIVES', 3, '도메인을 연결해 정적 웹 페이지를 호스팅에 배포할 수 있습니다.'),
('로드맵 실전: OS & 터미널', 'TARGET_AUDIENCE', 0, '서버에 접속하면 무엇부터 확인해야 할지 막막한 백엔드 입문자'),
('로드맵 실전: OS & 터미널', 'TARGET_AUDIENCE', 1, '운영체제 이론을 시험용이 아니라 실무에서 쓰는 감각으로 익히고 싶은 분'),
('로드맵 실전: OS & 터미널', 'TARGET_AUDIENCE', 2, '반복되는 서버 작업을 셸 스크립트로 자동화하고 싶은 분'),
('로드맵 실전: OS & 터미널', 'PREREQUISITES', 0, '터미널을 열고 cd, ls 같은 기본 명령어를 입력해 본 경험이면 충분합니다.'),
('로드맵 실전: OS & 터미널', 'PREREQUISITES', 1, 'Linux 또는 macOS 환경(Windows는 WSL)을 준비하면 실습을 그대로 따라 할 수 있습니다.'),
('로드맵 실전: OS & 터미널', 'OBJECTIVES', 0, '프로세스와 스레드의 차이와 컨텍스트 스위칭 비용을 설명할 수 있습니다.'),
('로드맵 실전: OS & 터미널', 'OBJECTIVES', 1, '가상 메모리와 페이지 폴트, 파일 디스크립터 개념을 명령어로 확인할 수 있습니다.'),
('로드맵 실전: OS & 터미널', 'OBJECTIVES', 2, 'ps, top, free, lsof로 자원을 많이 쓰는 프로세스를 찾아낼 수 있습니다.'),
('로드맵 실전: OS & 터미널', 'OBJECTIVES', 3, '파일 권한과 시그널을 다루고 셸 스크립트로 점검 작업을 자동화할 수 있습니다.'),
('로드맵 실전: Java 기초', 'TARGET_AUDIENCE', 0, 'Java 문법은 배웠지만 객체지향 설계가 아직 어렵게 느껴지는 입문자'),
('로드맵 실전: Java 기초', 'TARGET_AUDIENCE', 1, 'Spring을 배우기 전에 Java 기본기를 탄탄히 다지고 싶은 분'),
('로드맵 실전: Java 기초', 'TARGET_AUDIENCE', 2, '코딩 테스트용 Java가 아니라 실무용 Java 코드 감각을 익히고 싶은 분'),
('로드맵 실전: Java 기초', 'PREREQUISITES', 0, '변수, 조건문, 반복문, 메서드 같은 프로그래밍 기초 문법을 알고 있으면 좋습니다.'),
('로드맵 실전: Java 기초', 'PREREQUISITES', 1, 'JDK 17 이상과 IntelliJ 같은 IDE를 준비하면 실습이 수월합니다.'),
('로드맵 실전: Java 기초', 'OBJECTIVES', 0, '캡슐화, 상속, 다형성을 활용해 역할이 분명한 클래스를 설계할 수 있습니다.'),
('로드맵 실전: Java 기초', 'OBJECTIVES', 1, '추상 클래스와 인터페이스를 상황에 맞게 선택할 수 있습니다.'),
('로드맵 실전: Java 기초', 'OBJECTIVES', 2, '제네릭과 List, Set, Map을 특성에 맞게 사용할 수 있습니다.'),
('로드맵 실전: Java 기초', 'OBJECTIVES', 3, 'equals와 hashCode, 불변 객체, 예외 처리를 올바르게 구현할 수 있습니다.'),
('로드맵 실전: Git & 버전 관리', 'TARGET_AUDIENCE', 0, 'add, commit, push만 알고 브랜치와 충돌 해결이 두려운 입문자'),
('로드맵 실전: Git & 버전 관리', 'TARGET_AUDIENCE', 1, '첫 팀 프로젝트를 앞두고 협업 규칙을 정해야 하는 분'),
('로드맵 실전: Git & 버전 관리', 'TARGET_AUDIENCE', 2, '잘못된 커밋을 되돌리다 더 꼬여 본 경험이 있는 분'),
('로드맵 실전: Git & 버전 관리', 'PREREQUISITES', 0, 'Git 설치와 GitHub 계정만 있으면 시작할 수 있습니다.'),
('로드맵 실전: Git & 버전 관리', 'PREREQUISITES', 1, '터미널 기본 명령어를 알면 실습을 더 빠르게 따라올 수 있습니다.'),
('로드맵 실전: Git & 버전 관리', 'OBJECTIVES', 0, '작업 디렉터리, 스테이징 영역, 저장소의 관계를 설명할 수 있습니다.'),
('로드맵 실전: Git & 버전 관리', 'OBJECTIVES', 1, 'merge와 rebase의 차이를 이해하고 상황에 맞게 선택할 수 있습니다.'),
('로드맵 실전: Git & 버전 관리', 'OBJECTIVES', 2, 'GitFlow 같은 브랜치 전략으로 팀 협업 규칙을 정할 수 있습니다.'),
('로드맵 실전: Git & 버전 관리', 'OBJECTIVES', 3, 'PR 리뷰, 충돌 해결, revert와 reset으로 협업 중 문제를 수습할 수 있습니다.'),
('로드맵 실전: RDB & SQL', 'TARGET_AUDIENCE', 0, 'SQL을 조금 써 봤지만 테이블 설계와 인덱스는 아직 자신 없는 백엔드 입문자'),
('로드맵 실전: RDB & SQL', 'TARGET_AUDIENCE', 1, 'JPA를 쓰기 전에 데이터베이스 기본기를 먼저 다지고 싶은 분'),
('로드맵 실전: RDB & SQL', 'TARGET_AUDIENCE', 2, '트랜잭션과 격리 수준을 면접에서 정확히 설명하고 싶은 분'),
('로드맵 실전: RDB & SQL', 'PREREQUISITES', 0, '별도 선수 지식은 필요 없습니다. 표 형태의 데이터를 다뤄 본 경험이면 충분합니다.'),
('로드맵 실전: RDB & SQL', 'PREREQUISITES', 1, 'PostgreSQL을 로컬이나 Docker로 실행할 수 있으면 실습이 수월합니다.'),
('로드맵 실전: RDB & SQL', 'OBJECTIVES', 0, '기본키와 외래키로 관계를 표현하고 정규화된 스키마를 설계할 수 있습니다.'),
('로드맵 실전: RDB & SQL', 'OBJECTIVES', 1, 'JOIN과 서브쿼리, 집계 함수로 원하는 데이터를 조회할 수 있습니다.'),
('로드맵 실전: RDB & SQL', 'OBJECTIVES', 2, '인덱스의 원리와 비용을 이해하고 실행 계획을 읽을 수 있습니다.'),
('로드맵 실전: RDB & SQL', 'OBJECTIVES', 3, '트랜잭션의 ACID와 격리 수준별 동시성 문제를 설명할 수 있습니다.'),
('로드맵 실전: REST API 설계', 'TARGET_AUDIENCE', 0, 'API를 만들 줄은 알지만 설계 기준이 매번 달라 고민되는 백엔드 개발자'),
('로드맵 실전: REST API 설계', 'TARGET_AUDIENCE', 1, '프론트엔드와 API 명세를 맞추는 과정에서 자주 부딪히는 분'),
('로드맵 실전: REST API 설계', 'TARGET_AUDIENCE', 2, 'Swagger로 API 문서를 자동화하고 싶은 분'),
('로드맵 실전: REST API 설계', 'PREREQUISITES', 0, 'HTTP 요청과 응답 구조를 알고 있으면 좋습니다.'),
('로드맵 실전: REST API 설계', 'PREREQUISITES', 1, '간단한 API를 하나 이상 만들어 본 경험이 있으면 충분합니다.'),
('로드맵 실전: REST API 설계', 'OBJECTIVES', 0, '자원 중심으로 일관된 URI를 설계할 수 있습니다.'),
('로드맵 실전: REST API 설계', 'OBJECTIVES', 1, 'HTTP 메서드의 의미와 멱등성을 고려해 엔드포인트를 정의할 수 있습니다.'),
('로드맵 실전: REST API 설계', 'OBJECTIVES', 2, '상황에 맞는 상태 코드와 일관된 오류 응답 형식을 정할 수 있습니다.'),
('로드맵 실전: REST API 설계', 'OBJECTIVES', 3, '페이지네이션, 버전 관리를 반영한 API를 Swagger로 문서화할 수 있습니다.'),
('로드맵 실전: Spring Boot & MVC', 'TARGET_AUDIENCE', 0, 'Spring Boot로 API를 만들어 봤지만 내부 동작이 궁금한 개발자'),
('로드맵 실전: Spring Boot & MVC', 'TARGET_AUDIENCE', 1, '빈 주입 오류나 순환 참조를 만나면 원인을 찾기 어려운 분'),
('로드맵 실전: Spring Boot & MVC', 'TARGET_AUDIENCE', 2, '계층 구조를 근거를 들어 설명하고 싶은 취업 준비생'),
('로드맵 실전: Spring Boot & MVC', 'PREREQUISITES', 0, 'Java 객체지향과 인터페이스를 이해하고 있으면 좋습니다.'),
('로드맵 실전: Spring Boot & MVC', 'PREREQUISITES', 1, 'HTTP와 REST API의 기본 개념을 알고 있으면 충분합니다.'),
('로드맵 실전: Spring Boot & MVC', 'OBJECTIVES', 0, 'IoC 컨테이너가 빈을 생성하고 의존성을 주입하는 과정을 설명할 수 있습니다.'),
('로드맵 실전: Spring Boot & MVC', 'OBJECTIVES', 1, '컴포넌트 스캔과 설정 클래스로 빈을 등록하고 스코프를 구분할 수 있습니다.'),
('로드맵 실전: Spring Boot & MVC', 'OBJECTIVES', 2, 'DispatcherServlet부터 컨트롤러까지 요청 처리 흐름을 설명할 수 있습니다.'),
('로드맵 실전: Spring Boot & MVC', 'OBJECTIVES', 3, '검증과 전역 예외 처리를 갖춘 3계층 API를 구현할 수 있습니다.'),
('로드맵 실전: Spring Data JPA', 'TARGET_AUDIENCE', 0, 'JPA로 CRUD는 만들지만 쿼리가 몇 번 나가는지 모르고 있던 개발자'),
('로드맵 실전: Spring Data JPA', 'TARGET_AUDIENCE', 1, 'N+1 문제를 들어는 봤지만 직접 찾아 해결해 본 적은 없는 분'),
('로드맵 실전: Spring Data JPA', 'TARGET_AUDIENCE', 2, '복잡한 검색 조건을 QueryDSL로 깔끔하게 작성하고 싶은 분'),
('로드맵 실전: Spring Data JPA', 'PREREQUISITES', 0, 'Spring Boot 기본 구조와 SQL JOIN을 알고 있으면 좋습니다.'),
('로드맵 실전: Spring Data JPA', 'PREREQUISITES', 1, 'Entity와 Repository로 간단한 CRUD를 만들어 본 경험이 있으면 충분합니다.'),
('로드맵 실전: Spring Data JPA', 'OBJECTIVES', 0, 'Entity와 연관관계를 매핑하고 연관관계의 주인을 올바르게 정할 수 있습니다.'),
('로드맵 실전: Spring Data JPA', 'OBJECTIVES', 1, '영속성 컨텍스트와 변경 감지의 동작을 설명할 수 있습니다.'),
('로드맵 실전: Spring Data JPA', 'OBJECTIVES', 2, 'N+1 문제를 찾아 fetch join, EntityGraph, 배치 사이즈로 해결할 수 있습니다.'),
('로드맵 실전: Spring Data JPA', 'OBJECTIVES', 3, 'JPQL과 QueryDSL로 동적 조회 쿼리를 작성할 수 있습니다.'),
('로드맵 실전: Redis 기초', 'TARGET_AUDIENCE', 0, '조회 API가 느려 캐시 도입을 고민하는 백엔드 개발자'),
('로드맵 실전: Redis 기초', 'TARGET_AUDIENCE', 1, 'Redis를 단순 키값 저장소로만 써 왔던 분'),
('로드맵 실전: Redis 기초', 'TARGET_AUDIENCE', 2, 'Spring Cache를 적용했지만 무효화 시점이 헷갈리는 분'),
('로드맵 실전: Redis 기초', 'PREREQUISITES', 0, 'Spring Boot로 간단한 조회 API를 만들어 본 경험이 있으면 좋습니다.'),
('로드맵 실전: Redis 기초', 'PREREQUISITES', 1, 'Docker로 Redis를 실행할 수 있으면 실습이 수월합니다.'),
('로드맵 실전: Redis 기초', 'OBJECTIVES', 0, 'Redis 자료구조별 특징을 이해하고 기능에 맞게 선택할 수 있습니다.'),
('로드맵 실전: Redis 기초', 'OBJECTIVES', 1, 'TTL로 데이터 수명을 관리하고 만료 정책을 설계할 수 있습니다.'),
('로드맵 실전: Redis 기초', 'OBJECTIVES', 2, 'Cache-Aside 패턴과 Spring Cache로 조회 API에 캐시를 적용할 수 있습니다.'),
('로드맵 실전: Redis 기초', 'OBJECTIVES', 3, '캐시 무효화와 캐시 스탬피드 같은 운영 문제에 대응할 수 있습니다.');

INSERT INTO seed_course_curriculum (course_title, section_order, section_title, section_description, lesson_order, lesson_title, lesson_description) VALUES
('로드맵 실전: 인터넷 & 웹 기초', 1, '요청이 서버에 닿기까지', 'URL 입력부터 서버 응답까지 네트워크 단계를 한 흐름으로 정리합니다.', 1, 'URL을 입력하면 일어나는 일: DNS부터 렌더링까지', '도메인 조회, TCP 연결, TLS, HTTP 요청과 응답, 렌더링으로 이어지는 전체 흐름을 한 장의 지도로 정리합니다.'),
('로드맵 실전: 인터넷 & 웹 기초', 1, '요청이 서버에 닿기까지', 'URL 입력부터 서버 응답까지 네트워크 단계를 한 흐름으로 정리합니다.', 2, 'HTTP 메서드, 상태 코드, 헤더 읽기', '요청 라인과 헤더, 바디 구조를 살펴보고 자주 쓰는 메서드와 상태 코드의 의미를 정리합니다.'),
('로드맵 실전: 인터넷 & 웹 기초', 2, '웹을 직접 관찰하고 배포하기', '개발자 도구로 요청을 분석하고 도메인을 연결해 페이지를 배포합니다.', 1, '개발자 도구 Network 탭으로 요청 분석하기', '실제 사이트의 요청을 열어 보며 캐시, 쿠키, 리다이렉트, 응답 시간을 확인하는 방법을 익힙니다.'),
('로드맵 실전: 인터넷 & 웹 기초', 2, '웹을 직접 관찰하고 배포하기', '개발자 도구로 요청을 분석하고 도메인을 연결해 페이지를 배포합니다.', 2, '도메인 연결과 정적 페이지 호스팅', 'DNS 레코드를 설정해 도메인을 연결하고 정적 페이지를 호스팅에 배포하는 과정을 따라갑니다.'),
('로드맵 실전: OS & 터미널', 1, '운영체제가 프로그램을 실행하는 방법', '프로세스, 스레드, 메모리, 파일 디스크립터를 명령어로 확인하며 정리합니다.', 1, '프로세스와 스레드, 컨텍스트 스위칭', '프로세스와 스레드의 메모리 구조 차이와 컨텍스트 스위칭 비용을 ps와 top으로 확인합니다.'),
('로드맵 실전: OS & 터미널', 1, '운영체제가 프로그램을 실행하는 방법', '프로세스, 스레드, 메모리, 파일 디스크립터를 명령어로 확인하며 정리합니다.', 2, '가상 메모리와 파일 디스크립터', '가상 메모리와 페이지 폴트, 열린 파일과 소켓을 free, vmstat, lsof로 관찰합니다.'),
('로드맵 실전: OS & 터미널', 2, '터미널로 서버 다루기', '셸 스크립트, 권한, 시그널을 다루고 장애 점검 흐름을 익힙니다.', 1, '셸 스크립트와 파일 권한', '파이프와 리다이렉션, 변수와 반복문으로 스크립트를 만들고 chmod로 권한을 관리합니다.'),
('로드맵 실전: OS & 터미널', 2, '터미널로 서버 다루기', '셸 스크립트, 권한, 시그널을 다루고 장애 점검 흐름을 익힙니다.', 2, '시그널과 장애 점검 시나리오', 'kill 시그널의 차이를 이해하고 CPU, 메모리, 디스크 문제를 순서대로 점검하는 시나리오를 따라갑니다.'),
('로드맵 실전: Java 기초', 1, '객체지향으로 생각하기', '클래스 설계, 상속과 다형성, 인터페이스의 역할을 정리합니다.', 1, '클래스와 캡슐화, 상속과 다형성', '필드를 감추고 메서드로 행동을 드러내는 캡슐화와, 상속과 다형성으로 확장 가능한 코드를 만드는 방법을 다룹니다.'),
('로드맵 실전: Java 기초', 1, '객체지향으로 생각하기', '클래스 설계, 상속과 다형성, 인터페이스의 역할을 정리합니다.', 2, '추상 클래스와 인터페이스, 상속 대신 조합', '추상 클래스와 인터페이스의 차이, 상속의 한계와 조합을 선택하는 기준을 예제로 비교합니다.'),
('로드맵 실전: Java 기초', 2, '실무에서 자주 쓰는 Java', '제네릭, 컬렉션, equals와 hashCode, 예외 처리를 실무 코드로 익힙니다.', 1, '제네릭과 컬렉션 프레임워크', 'List, Set, Map의 구현체별 특징과 시간 복잡도, 제네릭으로 타입 안정성을 확보하는 방법을 정리합니다.'),
('로드맵 실전: Java 기초', 2, '실무에서 자주 쓰는 Java', '제네릭, 컬렉션, equals와 hashCode, 예외 처리를 실무 코드로 익힙니다.', 2, 'equals와 hashCode, 불변 객체, 예외 처리', 'HashSet에서 객체가 중복 저장되는 이유와 불변 객체의 장점, 체크 예외와 언체크 예외의 사용 기준을 다룹니다.'),
('로드맵 실전: Git & 버전 관리', 1, 'Git이 변경을 기록하는 방식', '세 영역과 커밋 구조, 브랜치와 병합 전략을 정리합니다.', 1, '작업 디렉터리, 스테이징, 커밋의 구조', '변경이 스테이징을 거쳐 커밋 스냅샷으로 저장되는 과정을 따라가며 좋은 커밋 단위를 정합니다.'),
('로드맵 실전: Git & 버전 관리', 1, 'Git이 변경을 기록하는 방식', '세 영역과 커밋 구조, 브랜치와 병합 전략을 정리합니다.', 2, '브랜치, merge와 rebase, 브랜치 전략', 'merge와 rebase가 이력을 어떻게 다르게 남기는지 비교하고 GitFlow와 GitHub Flow를 살펴봅니다.'),
('로드맵 실전: Git & 버전 관리', 2, '팀으로 일하는 Git', 'PR 리뷰와 충돌 해결, 실수 되돌리기를 실습합니다.', 1, 'Pull Request와 코드 리뷰 흐름', 'PR을 작게 나누는 방법, 리뷰 코멘트를 주고받는 방법, 승인 후 병합까지의 흐름을 익힙니다.'),
('로드맵 실전: Git & 버전 관리', 2, '팀으로 일하는 Git', 'PR 리뷰와 충돌 해결, 실수 되돌리기를 실습합니다.', 2, '충돌 해결과 revert, reset으로 되돌리기', '충돌이 생기는 원리와 해결 절차, 공유된 커밋은 revert로, 로컬 커밋은 reset으로 되돌리는 기준을 다룹니다.'),
('로드맵 실전: RDB & SQL', 1, '관계형 데이터 모델과 SQL', '테이블 관계 설계와 JOIN, 서브쿼리를 정리합니다.', 1, '테이블 관계 설계와 정규화', '기본키와 외래키로 1:N, N:M 관계를 표현하고 정규화로 중복과 이상 현상을 줄이는 방법을 다룹니다.'),
('로드맵 실전: RDB & SQL', 1, '관계형 데이터 모델과 SQL', '테이블 관계 설계와 JOIN, 서브쿼리를 정리합니다.', 2, 'JOIN과 서브쿼리, 집계 쿼리', 'INNER JOIN과 LEFT JOIN의 결과 차이, 서브쿼리와 GROUP BY, HAVING을 예제로 연습합니다.'),
('로드맵 실전: RDB & SQL', 2, '성능과 정합성 지키기', '인덱스와 실행 계획, 트랜잭션과 격리 수준을 다룹니다.', 1, '인덱스 원리와 실행 계획 읽기', 'B-Tree 인덱스가 조회를 빠르게 하는 원리와 쓰기 비용, EXPLAIN으로 실행 계획을 읽는 방법을 정리합니다.'),
('로드맵 실전: RDB & SQL', 2, '성능과 정합성 지키기', '인덱스와 실행 계획, 트랜잭션과 격리 수준을 다룹니다.', 2, '트랜잭션과 격리 수준', 'ACID의 의미와 더티 리드, 반복 불가능한 읽기, 팬텀 리드를 격리 수준별로 비교합니다.'),
('로드맵 실전: REST API 설계', 1, 'REST 설계 원칙', 'URI, 메서드, 상태 코드를 일관된 기준으로 정리합니다.', 1, '자원 중심 URI 설계', '동사 대신 명사로 자원을 표현하고 계층 관계와 복수형 규칙을 정해 일관된 URI를 만드는 방법을 다룹니다.'),
('로드맵 실전: REST API 설계', 1, 'REST 설계 원칙', 'URI, 메서드, 상태 코드를 일관된 기준으로 정리합니다.', 2, 'HTTP 메서드, 멱등성, 상태 코드', 'PUT과 PATCH의 차이, 멱등성의 의미, 200, 201, 204, 400, 401, 403, 404, 409를 고르는 기준을 정리합니다.'),
('로드맵 실전: REST API 설계', 2, '협업하기 좋은 API 만들기', '페이지네이션, 오류 응답, 버전 관리와 문서화를 다룹니다.', 1, '페이지네이션, 오류 응답, 버전 관리', '오프셋과 커서 페이지네이션, 일관된 오류 응답 바디, URI와 헤더 버전 관리의 장단점을 비교합니다.'),
('로드맵 실전: REST API 설계', 2, '협업하기 좋은 API 만들기', '페이지네이션, 오류 응답, 버전 관리와 문서화를 다룹니다.', 2, 'Swagger로 API 문서 자동화', 'OpenAPI 명세와 Swagger UI로 요청, 응답 예시가 포함된 문서를 자동으로 만드는 방법을 익힙니다.'),
('로드맵 실전: Spring Boot & MVC', 1, '스프링 컨테이너와 빈', 'IoC와 DI, 빈 등록과 스코프를 정리합니다.', 1, 'IoC 컨테이너와 의존성 주입', '객체 생성과 의존성 연결을 컨테이너에 맡기는 이유와 생성자 주입 방식을 코드로 확인합니다.'),
('로드맵 실전: Spring Boot & MVC', 1, '스프링 컨테이너와 빈', 'IoC와 DI, 빈 등록과 스코프를 정리합니다.', 2, '컴포넌트 스캔, 설정 클래스, 빈 스코프', '@Component와 @Bean 등록 방식의 차이, 싱글톤과 프로토타입 스코프, 자동 설정의 원리를 다룹니다.'),
('로드맵 실전: Spring Boot & MVC', 2, 'MVC 요청 처리와 계층 구조', '요청 처리 흐름과 3계층 책임 분리를 익힙니다.', 1, 'DispatcherServlet과 요청 매핑', '요청이 DispatcherServlet, 핸들러 매핑, 컨트롤러, 메시지 컨버터를 거쳐 응답이 되는 과정을 따라갑니다.'),
('로드맵 실전: Spring Boot & MVC', 2, 'MVC 요청 처리와 계층 구조', '요청 처리 흐름과 3계층 책임 분리를 익힙니다.', 2, '검증, 전역 예외 처리, 3계층 구조', '@Valid 검증과 @RestControllerAdvice 예외 처리를 적용하고 Controller, Service, Repository 책임을 나눕니다.'),
('로드맵 실전: Spring Data JPA', 1, 'JPA의 동작 원리', 'Entity 매핑, 연관관계, 영속성 컨텍스트를 정리합니다.', 1, 'Entity 매핑과 연관관계의 주인', '@Entity와 컬럼 매핑, 단방향과 양방향 연관관계, 외래키를 가진 쪽이 주인이 되는 이유를 다룹니다.'),
('로드맵 실전: Spring Data JPA', 1, 'JPA의 동작 원리', 'Entity 매핑, 연관관계, 영속성 컨텍스트를 정리합니다.', 2, '영속성 컨텍스트와 변경 감지, JPQL', '1차 캐시와 쓰기 지연, 변경 감지로 UPDATE가 나가는 원리와 메서드 쿼리, JPQL 작성법을 정리합니다.'),
('로드맵 실전: Spring Data JPA', 2, '성능 문제 찾고 해결하기', '지연 로딩과 N+1, QueryDSL 동적 쿼리를 다룹니다.', 1, 'FetchType과 N+1 문제 해결', '지연 로딩과 즉시 로딩의 차이, N+1이 생기는 원리, fetch join과 EntityGraph, 배치 사이즈 적용법을 비교합니다.'),
('로드맵 실전: Spring Data JPA', 2, '성능 문제 찾고 해결하기', '지연 로딩과 N+1, QueryDSL 동적 쿼리를 다룹니다.', 2, 'QueryDSL로 동적 쿼리 작성하기', '검색 조건이 선택적으로 들어오는 목록 조회를 QueryDSL과 BooleanExpression으로 깔끔하게 구현합니다.'),
('로드맵 실전: Redis 기초', 1, 'Redis 자료구조와 TTL', '자료구조별 쓰임새와 데이터 수명 관리를 정리합니다.', 1, 'Redis 자료구조 5가지와 쓰임새', 'String, List, Set, Sorted Set, Hash를 카운터, 최근 목록, 중복 제거, 랭킹, 객체 저장 예제로 익힙니다.'),
('로드맵 실전: Redis 기초', 1, 'Redis 자료구조와 TTL', '자료구조별 쓰임새와 데이터 수명 관리를 정리합니다.', 2, 'TTL과 만료 정책, 싱글 스레드 구조', 'EXPIRE와 TTL로 데이터 수명을 관리하고, 싱글 스레드 구조에서 오래 걸리는 명령이 위험한 이유를 다룹니다.'),
('로드맵 실전: Redis 기초', 2, '캐시로 성능 올리기', 'Spring Cache 적용과 캐시 운영 문제를 다룹니다.', 1, 'Cache-Aside 패턴과 Spring Cache', '@Cacheable, @CacheEvict로 조회 API에 캐시를 적용하고 직렬화와 키 설계를 정리합니다.'),
('로드맵 실전: Redis 기초', 2, '캐시로 성능 올리기', 'Spring Cache 적용과 캐시 운영 문제를 다룹니다.', 2, '캐시 무효화와 캐시 스탬피드 대응', '데이터 변경 시 캐시를 비우는 시점, 동시에 만료된 키로 요청이 몰리는 스탬피드 대응 전략을 다룹니다.');

INSERT INTO seed_course_quiz (course_title, quiz_title, quiz_description, lesson_title, lesson_description) VALUES
('로드맵 실전: 인터넷 & 웹 기초', '웹 요청 흐름 점검 퀴즈', 'DNS, TCP, HTTP, 상태 코드의 핵심 개념을 점검합니다.', '섹션 퀴즈: 요청이 서버에 닿기까지', 'URL 입력부터 응답까지의 단계와 HTTP 기본 개념을 5문항으로 점검합니다.'),
('로드맵 실전: OS & 터미널', '운영체제 핵심 개념 퀴즈', '프로세스, 스레드, 메모리, 파일 디스크립터를 점검합니다.', '섹션 퀴즈: 운영체제가 프로그램을 실행하는 방법', '프로세스와 스레드, 가상 메모리, 명령어 사용법을 5문항으로 점검합니다.'),
('로드맵 실전: Java 기초', '객체지향 기초 점검 퀴즈', '캡슐화, 상속, 다형성, 인터페이스의 핵심을 점검합니다.', '섹션 퀴즈: 객체지향으로 생각하기', '객체지향 개념과 Java 문법의 연결을 5문항으로 점검합니다.'),
('로드맵 실전: Git & 버전 관리', 'Git 협업 흐름 점검 퀴즈', '세 영역, 커밋, 브랜치와 병합 전략을 점검합니다.', '섹션 마무리 퀴즈: Git 협업 흐름 점검', 'Git의 기록 방식과 브랜치 전략을 5문항으로 점검합니다.'),
('로드맵 실전: RDB & SQL', '관계형 모델과 SQL 점검 퀴즈', '키와 관계, 정규화, JOIN과 집계의 핵심을 점검합니다.', '섹션 퀴즈: 관계형 데이터 모델과 SQL', '테이블 설계와 쿼리 결과 예측을 5문항으로 점검합니다.'),
('로드맵 실전: REST API 설계', 'REST 설계 원칙 점검 퀴즈', 'URI 설계, HTTP 메서드, 멱등성, 상태 코드를 점검합니다.', '섹션 퀴즈: REST 설계 원칙', '일관된 API를 만들기 위한 설계 기준을 5문항으로 점검합니다.'),
('로드맵 실전: Spring Boot & MVC', '스프링 컨테이너 점검 퀴즈', 'IoC, DI, 빈 등록과 스코프의 핵심을 점검합니다.', '섹션 퀴즈: 스프링 컨테이너와 빈', '스프링이 객체를 만들고 연결하는 방식을 5문항으로 점검합니다.'),
('로드맵 실전: Spring Data JPA', 'JPA 동작 원리 점검 퀴즈', '연관관계 매핑, 영속성 컨텍스트, 변경 감지를 점검합니다.', '섹션 퀴즈: JPA의 동작 원리', 'JPA가 SQL을 만들어 내는 원리를 5문항으로 점검합니다.'),
('로드맵 실전: Redis 기초', 'Redis 자료구조와 TTL 퀴즈', '자료구조별 쓰임새와 TTL, 싱글 스레드 구조를 점검합니다.', '섹션 퀴즈: Redis 자료구조와 TTL', '기능에 맞는 Redis 자료구조 선택을 5문항으로 점검합니다.');

INSERT INTO seed_course_quiz_question (course_title, display_order, question_text, explanation, correct_option, option1, option2, option3, option4) VALUES
('로드맵 실전: 인터넷 & 웹 기초', 1, '브라우저가 www.example.com에 처음 접속할 때 가장 먼저 필요한 작업은 무엇인가요?', '서버에 연결하려면 IP 주소가 필요하므로, 먼저 DNS 조회로 도메인을 IP 주소로 바꿉니다.', 3, 'HTML 파싱', 'HTTP 응답 캐싱', 'DNS 조회로 도메인의 IP 주소 찾기', '쿠키 삭제'),
('로드맵 실전: 인터넷 & 웹 기초', 2, 'HTTPS가 HTTP와 비교해 추가로 제공하는 것은 무엇인가요?', 'HTTPS는 TLS로 통신을 암호화하고 인증서로 서버의 신원을 확인해 도청과 위조를 막습니다.', 1, 'TLS를 통한 암호화와 서버 인증', '더 짧은 URL', '서버 없는 통신', '자동 캐싱'),
('로드맵 실전: 인터넷 & 웹 기초', 3, '요청한 페이지가 서버에 존재하지 않을 때 응답 상태 코드로 알맞은 것은 무엇인가요?', '404 Not Found는 요청한 자원을 찾을 수 없음을 뜻합니다. 500은 서버 내부 오류입니다.', 4, '200', '301', '500', '404'),
('로드맵 실전: 인터넷 & 웹 기초', 4, '서버의 데이터를 조회만 하고 변경하지 않는 요청에 사용하는 메서드는 무엇인가요?', 'GET은 자원을 조회하는 안전한 메서드로, 서버 상태를 바꾸지 않는 것이 원칙입니다.', 2, 'POST', 'GET', 'DELETE', 'PATCH'),
('로드맵 실전: 인터넷 & 웹 기초', 5, 'DNS에서 도메인을 IPv4 주소에 직접 연결하는 레코드 타입은 무엇인가요?', 'A 레코드는 도메인을 IPv4 주소에 연결하고, CNAME은 다른 도메인 이름을 가리킵니다.', 3, 'MX', 'TXT', 'A', 'NS'),
('로드맵 실전: OS & 터미널', 1, '같은 프로세스 안의 스레드들이 공유하는 것은 무엇인가요?', '스레드는 각자 스택과 레지스터를 가지지만 코드, 데이터, 힙 영역은 프로세스 안에서 공유합니다.', 2, '각자의 스택 영역', '힙과 데이터 영역', '프로그램 카운터', 'CPU 레지스터 값'),
('로드맵 실전: OS & 터미널', 2, '컨텍스트 스위칭에 대한 설명으로 올바른 것은 무엇인가요?', 'CPU가 실행 대상을 바꿀 때 현재 상태를 저장하고 다음 대상의 상태를 복원해야 하므로 비용이 발생합니다.', 4, '비용이 전혀 들지 않는다', '디스크 용량을 늘리는 작업이다', '프로세스를 영구 종료하는 작업이다', '실행 중인 작업의 상태를 저장하고 다른 작업의 상태를 복원한다'),
('로드맵 실전: OS & 터미널', 3, '실시간으로 CPU와 메모리 사용량이 높은 프로세스를 확인할 때 쓰는 명령어는 무엇인가요?', 'top은 프로세스별 CPU, 메모리 사용량을 실시간으로 갱신해 보여 줍니다.', 1, 'top', 'cd', 'mkdir', 'echo'),
('로드맵 실전: OS & 터미널', 4, '파일 권한 rwxr-x---를 숫자로 표현하면 무엇인가요?', '소유자 rwx는 4+2+1=7, 그룹 r-x는 4+1=5, 기타 ---는 0이므로 750입니다.', 3, '777', '644', '750', '700'),
('로드맵 실전: OS & 터미널', 5, 'kill -9(SIGKILL)과 kill -15(SIGTERM)의 차이로 올바른 것은 무엇인가요?', 'SIGTERM은 프로세스가 정리 작업 후 종료할 기회를 주고, SIGKILL은 즉시 강제 종료하므로 정리 작업이 실행되지 않습니다.', 2, '둘 다 완전히 같다', 'SIGTERM은 정상 종료 기회를 주고 SIGKILL은 즉시 강제 종료한다', 'SIGKILL이 더 안전한 종료 방법이다', 'SIGTERM은 프로세스를 일시 정지만 한다'),
('로드맵 실전: Java 기초', 1, '캡슐화의 목적으로 가장 적절한 것은 무엇인가요?', '캡슐화는 내부 상태를 감추고 정해진 메서드로만 변경하게 해 객체가 잘못된 상태가 되는 것을 막습니다.', 3, '클래스 개수를 줄이기 위해', '모든 필드를 public으로 공개하기 위해', '내부 상태를 감추고 메서드로만 변경하게 하기 위해', '상속을 금지하기 위해'),
('로드맵 실전: Java 기초', 2, '부모 타입 변수로 자식 객체를 참조해 같은 메서드 호출이 객체마다 다르게 동작하는 것을 무엇이라 하나요?', '다형성은 같은 타입의 메시지에 실제 객체가 각자 다르게 응답하는 성질로, 재정의된 메서드가 호출됩니다.', 1, '다형성', '캡슐화', '추상화 해제', '오버로딩'),
('로드맵 실전: Java 기초', 3, '인터페이스에 대한 설명으로 올바른 것은 무엇인가요?', '클래스는 하나만 상속할 수 있지만 인터페이스는 여러 개 구현할 수 있어 역할을 나눠 정의하기 좋습니다.', 4, '인스턴스 필드를 자유롭게 가질 수 있다', '한 클래스는 인터페이스를 하나만 구현할 수 있다', '생성자를 정의해야 한다', '한 클래스가 여러 인터페이스를 구현할 수 있다'),
('로드맵 실전: Java 기초', 4, '메서드 오버라이딩과 오버로딩의 차이로 올바른 것은 무엇인가요?', '오버라이딩은 부모의 메서드를 같은 시그니처로 재정의하는 것이고, 오버로딩은 같은 이름에 매개변수를 다르게 정의하는 것입니다.', 2, '둘은 같은 개념이다', '오버라이딩은 상속받은 메서드를 재정의하고, 오버로딩은 매개변수가 다른 같은 이름의 메서드를 정의한다', '오버로딩은 반드시 상속 관계에서만 가능하다', '오버라이딩은 반환 타입만 바꾸는 것이다'),
('로드맵 실전: Java 기초', 5, '상속보다 조합을 우선 고려하라는 조언의 이유로 가장 적절한 것은 무엇인가요?', '상속은 부모 구현에 강하게 묶여 변경이 자식에 전파되지만, 조합은 필요한 기능을 가진 객체를 필드로 두어 결합도를 낮춥니다.', 3, '조합이 문법적으로 더 짧아서', '상속은 Java에서 지원하지 않아서', '상속은 부모 구현에 강하게 결합되어 변경에 취약해서', '조합을 쓰면 인터페이스가 필요 없어서'),
('로드맵 실전: Git & 버전 관리', 1, 'git add 명령어의 역할은 무엇인가요?', 'git add는 작업 디렉터리의 변경을 스테이징 영역에 올려 다음 커밋에 포함될 내용을 고릅니다.', 2, '원격 저장소로 업로드한다', '변경을 스테이징 영역에 올린다', '새 브랜치를 만든다', '커밋을 삭제한다'),
('로드맵 실전: Git & 버전 관리', 2, 'Git 커밋에 대한 설명으로 올바른 것은 무엇인가요?', '커밋은 특정 시점의 프로젝트 스냅샷과 부모 커밋 정보를 담아, 이력을 따라가 이전 상태로 돌아갈 수 있게 합니다.', 1, '특정 시점의 스냅샷과 부모 커밋 정보를 저장한다', '변경된 줄 번호만 저장한다', '원격 저장소에만 존재한다', '한 번 만들면 브랜치를 바꿀 수 없다'),
('로드맵 실전: Git & 버전 관리', 3, 'rebase의 특징으로 올바른 것은 무엇인가요?', 'rebase는 내 커밋을 대상 브랜치 끝으로 다시 적용해 이력을 일직선으로 만들지만 커밋 해시가 바뀌므로 공유된 브랜치에서는 주의해야 합니다.', 4, '병합 커밋을 항상 새로 만든다', '원격 저장소를 삭제한다', '커밋 해시가 절대 바뀌지 않는다', '커밋을 다시 적용해 이력을 일직선으로 만들고 해시가 바뀐다'),
('로드맵 실전: Git & 버전 관리', 4, 'GitFlow에서 운영 중인 버전의 긴급 버그를 수정할 때 사용하는 브랜치는 무엇인가요?', 'hotfix 브랜치는 main에서 분기해 긴급 수정을 하고 main과 develop에 함께 병합합니다.', 3, 'feature', 'release', 'hotfix', 'gh-pages'),
('로드맵 실전: Git & 버전 관리', 5, '이미 원격에 푸시해 팀원이 받은 커밋을 되돌릴 때 안전한 방법은 무엇인가요?', 'revert는 되돌리는 새 커밋을 만들어 이력을 보존하므로 공유된 커밋에도 안전합니다. reset 후 강제 푸시는 팀원 이력을 꼬이게 합니다.', 1, 'git revert로 되돌리는 커밋을 만든다', 'git reset --hard 후 강제 푸시한다', '저장소를 삭제하고 다시 만든다', '.git 폴더를 지운다'),
('로드맵 실전: RDB & SQL', 1, '외래키(Foreign Key)의 역할로 가장 적절한 것은 무엇인가요?', '외래키는 다른 테이블의 기본키를 참조해 존재하지 않는 값이 들어가지 않도록 참조 무결성을 지킵니다.', 2, '테이블의 조회 속도를 항상 높인다', '다른 테이블의 키를 참조해 참조 무결성을 보장한다', '중복 행을 자동으로 삭제한다', '컬럼의 기본값을 정한다'),
('로드맵 실전: RDB & SQL', 2, '정규화의 주된 목적은 무엇인가요?', '정규화는 데이터 중복을 줄여 삽입, 수정, 삭제 이상 현상을 막는 것이 목적입니다.', 3, '테이블 수를 최소화하기 위해', '모든 조회를 JOIN 없이 하기 위해', '중복을 줄여 이상 현상을 방지하기 위해', '인덱스를 자동 생성하기 위해'),
('로드맵 실전: RDB & SQL', 3, 'students 5명, 그중 수강 신청한 학생 3명이 enrollments에 있을 때 students LEFT JOIN enrollments 결과의 학생 수는 몇 명인가요?', 'LEFT JOIN은 왼쪽 테이블의 모든 행을 유지하므로 신청하지 않은 학생 2명도 NULL과 함께 포함되어 5명입니다(학생당 신청이 1건일 때).', 4, '3명', '2명', '0명', '5명'),
('로드맵 실전: RDB & SQL', 4, 'COUNT(*)와 COUNT(컬럼)의 차이로 올바른 것은 무엇인가요?', 'COUNT(*)는 모든 행을 세고, COUNT(컬럼)은 해당 컬럼이 NULL이 아닌 행만 셉니다.', 1, 'COUNT(컬럼)은 NULL 값을 제외하고 센다', '둘은 항상 같은 값을 반환한다', 'COUNT(*)는 NULL 행을 제외한다', 'COUNT(컬럼)은 중복을 자동 제거한다'),
('로드맵 실전: RDB & SQL', 5, '서브쿼리 결과에 해당하는 값이 존재하는지만 확인할 때 효율적으로 쓰는 키워드는 무엇인가요?', 'EXISTS는 조건을 만족하는 행이 하나라도 있으면 바로 참을 반환하므로 존재 여부 확인에 적합합니다.', 2, 'DISTINCT', 'EXISTS', 'UNION', 'LIMIT'),
('로드맵 실전: REST API 설계', 1, 'REST 원칙에 가장 잘 맞는 URI는 무엇인가요?', '자원은 명사 복수형으로 표현하고 행위는 HTTP 메서드로 나타내므로 GET /users/10/orders가 적절합니다.', 3, 'GET /getUserOrders?id=10', 'POST /users/10/getOrders', 'GET /users/10/orders', 'GET /user_orders_list/10'),
('로드맵 실전: REST API 설계', 2, '다음 중 멱등성을 가지지 않는 메서드는 무엇인가요?', '같은 요청을 여러 번 보내도 결과가 같으면 멱등입니다. POST는 호출할 때마다 새 자원이 생길 수 있어 멱등이 아닙니다.', 4, 'GET', 'PUT', 'DELETE', 'POST'),
('로드맵 실전: REST API 설계', 3, '새 회원을 성공적으로 생성했을 때 가장 적절한 상태 코드는 무엇인가요?', '201 Created는 새 자원이 생성되었음을 뜻하며, 보통 Location 헤더로 생성된 자원 위치를 알려 줍니다.', 1, '201 Created', '200 OK', '204 No Content', '202 Accepted'),
('로드맵 실전: REST API 설계', 4, '로그인은 했지만 해당 자원에 접근할 권한이 없을 때 알맞은 상태 코드는 무엇인가요?', '401은 인증되지 않은 상태, 403은 인증은 됐지만 권한이 없는 상태를 뜻합니다.', 2, '401 Unauthorized', '403 Forbidden', '404 Not Found', '400 Bad Request'),
('로드맵 실전: REST API 설계', 5, 'PUT과 PATCH의 차이로 올바른 것은 무엇인가요?', 'PUT은 자원 전체를 요청 내용으로 교체하고, PATCH는 전달한 필드만 부분 수정합니다.', 3, 'PUT은 조회, PATCH는 삭제에 쓴다', '둘은 완전히 같다', 'PUT은 자원 전체를 교체하고 PATCH는 일부만 수정한다', 'PATCH는 새 자원 생성에만 쓴다'),
('로드맵 실전: Spring Boot & MVC', 1, 'IoC(제어의 역전)를 가장 잘 설명한 것은 무엇인가요?', 'IoC는 객체 생성과 의존성 연결 같은 제어권을 개발자 코드가 아니라 스프링 컨테이너가 가지는 것을 말합니다.', 2, '개발자가 모든 객체를 new로 직접 만든다', '객체 생성과 연결의 제어권을 컨테이너가 가진다', '메서드 호출 순서를 거꾸로 바꾼다', '예외를 상위로 던지지 않는다'),
('로드맵 실전: Spring Boot & MVC', 2, '스프링 빈의 기본 스코프는 무엇인가요?', '별도 설정이 없으면 빈은 싱글톤으로 컨테이너당 하나의 인스턴스만 생성되어 공유됩니다.', 1, 'singleton', 'prototype', 'request', 'session'),
('로드맵 실전: Spring Boot & MVC', 3, '싱글톤 빈에 요청마다 바뀌는 값을 인스턴스 필드로 저장하면 어떤 문제가 생기나요?', '싱글톤 빈은 여러 요청 스레드가 공유하므로 상태를 필드에 저장하면 다른 요청의 값과 섞이는 동시성 문제가 생깁니다.', 4, '빈이 생성되지 않는다', '컴파일 오류가 발생한다', '요청마다 새 빈이 만들어진다', '여러 요청이 같은 필드를 공유해 값이 섞인다'),
('로드맵 실전: Spring Boot & MVC', 4, '외부 라이브러리 클래스를 빈으로 등록할 때 주로 쓰는 방법은 무엇인가요?', '소스를 수정할 수 없는 외부 클래스는 @Configuration 클래스의 @Bean 메서드로 직접 생성해 등록합니다.', 3, '라이브러리 소스에 @Component를 직접 붙인다', 'application.yml에 클래스 이름만 적는다', '@Configuration 클래스에서 @Bean 메서드로 등록한다', '@Autowired를 클래스에 붙인다'),
('로드맵 실전: Spring Boot & MVC', 5, '같은 타입의 빈이 두 개 이상일 때 주입 대상을 지정하는 방법으로 알맞은 것은 무엇인가요?', '같은 타입 빈이 여러 개면 @Qualifier로 이름을 지정하거나 @Primary로 기본 빈을 정해 모호함을 해결합니다.', 2, '@Transactional', '@Qualifier 또는 @Primary', '@RequestMapping', '@Value'),
('로드맵 실전: Spring Data JPA', 1, '양방향 연관관계에서 연관관계의 주인이 되는 쪽은 어디인가요?', '외래키를 관리하는 쪽, 즉 외래키가 있는 테이블에 매핑된 엔티티가 주인이며 mappedBy가 없는 쪽입니다.', 3, 'mappedBy를 선언한 쪽', '항상 부모 엔티티', '외래키를 가진 테이블에 매핑된 엔티티', '먼저 생성된 엔티티'),
('로드맵 실전: Spring Data JPA', 2, '트랜잭션 안에서 조회한 엔티티의 필드 값을 바꾸면 어떻게 되나요?', '영속 상태 엔티티는 변경 감지 대상이라 커밋 시점에 스냅샷과 비교해 UPDATE 쿼리가 자동으로 실행됩니다.', 1, '커밋 시점에 변경 감지로 UPDATE가 실행된다', 'save를 호출하지 않으면 절대 반영되지 않는다', '즉시 DELETE 후 INSERT된다', '예외가 발생한다'),
('로드맵 실전: Spring Data JPA', 3, '같은 트랜잭션에서 같은 id로 엔티티를 두 번 조회하면 어떻게 되나요?', '처음 조회한 엔티티는 1차 캐시에 저장되므로 두 번째 조회는 SQL 없이 같은 인스턴스를 반환합니다.', 4, '항상 SELECT가 두 번 실행된다', '두 번째 조회에서 예외가 난다', '서로 다른 인스턴스가 반환된다', '1차 캐시에서 같은 인스턴스를 반환한다'),
('로드맵 실전: Spring Data JPA', 4, 'Spring Data JPA에서 메서드 이름 findByEmail이 하는 일은 무엇인가요?', '메서드 이름 규칙을 해석해 email 필드로 조건을 거는 조회 쿼리를 자동으로 만들어 줍니다.', 2, 'email 컬럼을 삭제한다', 'email 조건으로 조회하는 쿼리를 자동 생성한다', 'email 인덱스를 만든다', '모든 행을 email 순으로 정렬한다'),
('로드맵 실전: Spring Data JPA', 5, 'JPQL에 대한 설명으로 올바른 것은 무엇인가요?', 'JPQL은 테이블이 아니라 엔티티와 필드를 대상으로 작성하는 객체 지향 쿼리로, 실행 시 SQL로 변환됩니다.', 3, '데이터베이스 테이블 이름을 그대로 써야 한다', 'DB 종류마다 문법이 완전히 다르다', '엔티티와 필드를 대상으로 작성하고 SQL로 변환된다', 'INSERT 문만 지원한다'),
('로드맵 실전: Redis 기초', 1, '점수 기준 실시간 랭킹을 구현하기에 가장 적합한 Redis 자료구조는 무엇인가요?', 'Sorted Set은 멤버마다 점수를 가지고 자동 정렬되므로 ZADD, ZREVRANGE로 랭킹을 쉽게 만들 수 있습니다.', 4, 'String', 'List', 'Hash', 'Sorted Set'),
('로드맵 실전: Redis 기초', 2, '중복 없이 오늘 방문한 사용자 ID를 모으기에 적합한 자료구조는 무엇인가요?', 'Set은 중복을 허용하지 않으므로 같은 사용자가 여러 번 방문해도 한 번만 저장됩니다.', 2, 'List', 'Set', 'String', 'Stream'),
('로드맵 실전: Redis 기초', 3, 'TTL이 지난 키는 어떻게 되나요?', 'TTL이 만료된 키는 자동으로 삭제되어 더 이상 조회되지 않습니다.', 1, '자동으로 만료되어 조회되지 않는다', '디스크로 옮겨진다', '값이 0으로 바뀐다', '수동으로 지울 때까지 유지된다'),
('로드맵 실전: Redis 기초', 4, 'Redis가 싱글 스레드로 명령을 처리한다는 것의 의미로 올바른 것은 무엇인가요?', '명령이 순서대로 하나씩 실행되므로 각 명령은 원자적이지만, KEYS처럼 오래 걸리는 명령은 다른 요청을 모두 막습니다.', 3, '동시에 한 명의 클라이언트만 접속할 수 있다', '모든 명령이 디스크에 먼저 기록된다', '명령이 순차 실행되어 오래 걸리는 명령이 전체를 막을 수 있다', '멀티 코어를 자동으로 모두 사용한다'),
('로드맵 실전: Redis 기초', 5, 'Cache-Aside 패턴의 조회 흐름으로 올바른 것은 무엇인가요?', '먼저 캐시를 확인하고 없으면 DB에서 읽은 뒤 캐시에 저장해, 다음 조회부터는 캐시에서 응답합니다.', 2, '항상 DB만 조회한다', '캐시를 먼저 확인하고 없으면 DB에서 읽어 캐시에 저장한다', 'DB에 쓰기 전에 캐시를 항상 비운다', '캐시와 DB를 동시에 조회해 빠른 쪽을 쓴다');

INSERT INTO seed_course_assignment (course_title, assignment_title, assignment_description, submission_rule, lesson_title, lesson_description) VALUES
('로드맵 실전: 인터넷 & 웹 기초', '내 페이지의 요청 흐름 추적하기',
'상황.
직접 만든 자기소개 페이지를 도메인에 연결해 배포하고, 누군가 주소를 입력했을 때 어떤 일이 일어나는지 단계별로 설명해야 합니다.

요구사항.
1. 간단한 HTML 페이지를 만들어 정적 호스팅(GitHub Pages 등)에 배포하세요.
2. 가능하다면 도메인을 연결하고 사용한 DNS 레코드를 정리하세요.
3. nslookup 또는 dig로 도메인의 IP 주소를 조회한 결과를 남기세요.
4. 개발자 도구 Network 탭에서 문서 요청 하나를 골라 메서드, 상태 코드, 주요 헤더를 설명하세요.
5. URL 입력부터 화면 표시까지의 단계를 자신의 말로 정리하세요.

제출물.
배포 URL과 분석 문서(마크다운 또는 PDF).',
'배포 URL을 제출하고, 분석 문서를 첨부하거나 텍스트로 붙여 넣으세요. 캡처 이미지가 있으면 함께 첨부하세요.',
'실습 과제: 내 페이지의 요청 흐름 추적하기', '직접 배포한 페이지의 DNS 조회와 HTTP 요청을 분석해 문서로 제출합니다.'),
('로드맵 실전: OS & 터미널', '서버 상태 점검 스크립트 만들기',
'상황.
운영 중인 서버가 가끔 느려진다는 제보가 들어옵니다. 당번 개발자가 한 번에 상태를 확인할 수 있는 점검 스크립트가 필요합니다.

요구사항.
1. CPU 사용률 상위 5개 프로세스를 출력하세요.
2. 메모리 사용량과 스왑 사용량을 출력하세요.
3. 디스크 사용률이 80%를 넘는 파티션이 있으면 경고 문구를 출력하세요.
4. 특정 포트(예: 8080)를 사용 중인 프로세스를 확인하세요.
5. 결과를 날짜가 포함된 로그 파일로 저장하고, 실행 권한을 설정하세요.

제출물.
스크립트 파일과 실행 결과 예시, 각 명령어를 고른 이유를 정리한 README.',
'스크립트 파일(.sh)을 첨부하거나 GitHub 저장소 URL을 제출하세요. 텍스트 칸에 실행 결과 예시를 붙여 넣으세요.',
'실습 과제: 서버 상태 점검 스크립트 만들기', 'CPU, 메모리, 디스크, 포트를 한 번에 점검하는 셸 스크립트를 제출합니다.'),
('로드맵 실전: Java 기초', '도서 대여 도메인 객체지향 설계',
'상황.
작은 도서관의 대여 시스템을 콘솔 프로그램으로 만들려 합니다. 기능보다 객체 설계가 핵심입니다.

요구사항.
1. 도서, 회원, 대여 기록 클래스를 설계하고 필드는 private으로 감추세요.
2. 일반 회원과 우수 회원의 대여 가능 권수를 다형성으로 구현하세요.
3. 연체료 정책을 인터페이스로 분리하고 두 가지 이상의 구현체를 만드세요.
4. 도서 목록은 List, 회원 조회는 Map을 사용하고 선택 이유를 적으세요.
5. 대여 불가 상황은 의미 있는 예외로 처리하세요.

제출물.
GitHub 저장소 URL과 클래스 다이어그램 또는 설계 설명이 담긴 README.',
'GitHub 저장소 URL을 제출하세요. README에 클래스 관계와 인터페이스를 분리한 이유를 설명하세요.',
'실습 과제: 도서 대여 도메인 객체지향 설계', '캡슐화, 다형성, 인터페이스, 컬렉션을 활용한 도서 대여 프로그램을 제출합니다.'),
('로드맵 실전: Git & 버전 관리', 'Git 브랜치 전략과 PR 회고',
'상황.
3명이 함께하는 사이드 프로젝트를 시작합니다. 첫 주에 브랜치 규칙을 정하고 실제 PR 흐름을 한 번 돌려 봐야 합니다.

요구사항.
1. main, develop, feature 브랜치를 포함한 브랜치 전략과 이름 규칙을 정하세요.
2. 기능 브랜치 두 개를 만들어 각각 PR을 올리고 리뷰 코멘트를 남기세요.
3. 의도적으로 충돌을 만들고 해결한 과정을 기록하세요.
4. 잘못된 커밋 하나를 revert로 되돌리세요.
5. 커밋 메시지 규칙과 PR 템플릿을 저장소에 추가하세요.

제출물.
GitHub 저장소 URL과 PR 링크, 협업 과정을 정리한 회고 문서.',
'GitHub 저장소 URL을 제출하고, 텍스트 칸에 PR 링크와 회고 요약을 적으세요.',
'실습 과제: Git 브랜치 전략과 PR 회고', '브랜치 전략, PR 리뷰, 충돌 해결, revert 과정을 담은 저장소와 회고를 제출합니다.'),
('로드맵 실전: RDB & SQL', '주문 도메인 스키마와 핵심 쿼리 설계',
'상황.
작은 쇼핑몰의 회원, 상품, 주문, 주문 상품 데이터를 저장할 데이터베이스를 설계해야 합니다.

요구사항.
1. 회원, 상품, 주문, 주문상품 테이블을 설계하고 기본키와 외래키를 정의하세요.
2. 회원별 총 주문 금액, 상품별 판매 수량을 구하는 쿼리를 작성하세요.
3. 한 번도 주문하지 않은 회원을 조회하는 쿼리를 작성하세요.
4. 자주 쓰일 조회 조건에 인덱스를 추가하고 EXPLAIN 결과를 비교하세요.
5. 주문 생성 시 재고 차감을 하나의 트랜잭션으로 묶는 SQL 흐름을 작성하세요.

제출물.
DDL과 쿼리가 담긴 SQL 파일, ERD 이미지, 설계 이유를 정리한 문서.',
'SQL 파일과 ERD를 zip으로 첨부하거나 GitHub 저장소 URL을 제출하세요. 텍스트 칸에 인덱스 전후 비교를 요약하세요.',
'실습 과제: 주문 도메인 스키마와 핵심 쿼리 설계', '주문 도메인의 스키마, 집계 쿼리, 인덱스, 트랜잭션을 설계해 제출합니다.'),
('로드맵 실전: REST API 설계', '서비스 API 명세 설계와 문서화',
'상황.
스터디 모집 서비스를 새로 만듭니다. 프론트엔드 개발자가 바로 작업할 수 있도록 API 명세를 먼저 확정해야 합니다.

요구사항.
1. 스터디, 참여 신청, 댓글 자원에 대한 엔드포인트를 설계하세요.
2. 각 엔드포인트에 알맞은 메서드와 성공, 실패 상태 코드를 정하세요.
3. 목록 조회에 페이지네이션과 필터 파라미터를 설계하세요.
4. 공통 오류 응답 형식을 정의하세요.
5. Swagger(OpenAPI)로 명세를 작성하고 요청, 응답 예시를 포함하세요.

제출물.
OpenAPI 명세 파일 또는 Swagger UI가 동작하는 저장소, 설계 근거 문서.',
'OpenAPI 파일을 첨부하거나 GitHub 저장소 URL을 제출하세요. 텍스트 칸에 설계 원칙 3가지를 요약하세요.',
'실습 과제: 서비스 API 명세 설계와 문서화', '자원, 메서드, 상태 코드, 오류 형식을 갖춘 API 명세를 Swagger로 제출합니다.'),
('로드맵 실전: Spring Boot & MVC', '3계층 구조 게시판 API 구현',
'상황.
사내 공지 게시판 API를 만들어야 합니다. 나중에 다른 개발자가 이어서 작업하기 쉽도록 구조를 깔끔하게 나누는 것이 중요합니다.

요구사항.
1. 게시글 등록, 목록, 상세, 수정, 삭제 API를 구현하세요.
2. Controller, Service, Repository로 책임을 나누고 생성자 주입을 사용하세요.
3. 요청 DTO에 @Valid 검증을 적용하세요.
4. @RestControllerAdvice로 존재하지 않는 게시글, 검증 실패 오류를 일관된 형식으로 응답하세요.
5. 요청이 컨트롤러에 도달하기까지의 흐름을 README에 그림이나 글로 설명하세요.

제출물.
GitHub 저장소 URL과 API 목록, 요청 처리 흐름을 정리한 README.',
'GitHub 저장소 URL을 제출하세요. README에 계층별 책임과 예외 응답 예시를 포함하세요.',
'실습 과제: 3계층 구조 게시판 API 구현', '검증과 전역 예외 처리를 갖춘 게시판 API를 3계층 구조로 제출합니다.'),
('로드맵 실전: Spring Data JPA', 'N+1 문제 찾고 개선하기',
'상황.
게시글 목록 API가 게시글 수가 늘수록 느려집니다. 로그를 보니 게시글마다 작성자와 댓글 조회 쿼리가 따로 나가고 있습니다.

요구사항.
1. 게시글, 회원, 댓글 엔티티와 연관관계를 매핑하세요(모두 지연 로딩).
2. 목록 조회 시 N+1이 발생하는 것을 SQL 로그로 확인하세요.
3. fetch join, EntityGraph, 배치 사이즈 중 두 가지 이상으로 개선하세요.
4. 개선 전후 쿼리 수를 비교하고, 컬렉션 fetch join과 페이징을 함께 쓸 때의 주의점을 정리하세요.
5. 작성자 이름, 기간 조건이 선택적으로 들어오는 검색을 QueryDSL로 구현하세요.

제출물.
GitHub 저장소 URL과 개선 전후 비교를 담은 README.',
'GitHub 저장소 URL을 제출하세요. README에 개선 전후 SQL 로그와 쿼리 수 비교를 포함하세요.',
'실습 과제: N+1 문제 찾고 개선하기', 'N+1 문제를 재현하고 두 가지 이상의 방법으로 개선한 결과를 제출합니다.'),
('로드맵 실전: Redis 기초', '인기 게시글 API에 캐시 적용하기',
'상황.
메인 화면의 인기 게시글 API가 트래픽의 절반을 차지해 DB 부하가 큽니다. 캐시를 도입해 응답 속도와 DB 부하를 줄여야 합니다.

요구사항.
1. Redis를 연동하고 인기 게시글 조회에 @Cacheable을 적용하세요.
2. 게시글 수정, 삭제 시 캐시가 무효화되도록 하세요.
3. 캐시 TTL을 정하고 그 근거를 적으세요.
4. 조회수 랭킹을 Sorted Set으로 구현하세요.
5. 캐시 적용 전후 평균 응답 시간을 측정해 비교하세요.

제출물.
GitHub 저장소 URL과 측정 결과, 캐시 설계 설명이 담긴 README.',
'GitHub 저장소 URL을 제출하세요. README에 캐시 키 설계, TTL 근거, 전후 응답 시간 비교를 포함하세요.',
'실습 과제: 인기 게시글 API에 캐시 적용하기', 'Spring Cache와 Redis로 조회 API에 캐시를 적용하고 성능 변화를 제출합니다.');

INSERT INTO seed_course_assignment_rubric (course_title, display_order, criteria_name, criteria_description, max_points) VALUES
('로드맵 실전: 인터넷 & 웹 기초', 1, '배포 완료', '페이지가 공개 URL에서 정상적으로 열립니다.', 20),
('로드맵 실전: 인터넷 & 웹 기초', 2, 'DNS 이해', 'DNS 조회 결과와 레코드 설정을 올바르게 설명했습니다.', 25),
('로드맵 실전: 인터넷 & 웹 기초', 3, 'HTTP 분석', '메서드, 상태 코드, 헤더를 실제 요청에 근거해 설명했습니다.', 30),
('로드맵 실전: 인터넷 & 웹 기초', 4, '전체 흐름 정리', 'URL 입력부터 화면 표시까지 단계를 빠짐없이 정리했습니다.', 25),
('로드맵 실전: OS & 터미널', 1, '점검 항목 완성도', 'CPU, 메모리, 디스크, 포트 점검이 모두 동작합니다.', 35),
('로드맵 실전: OS & 터미널', 2, '명령어 이해', '각 명령어 출력의 의미와 선택 이유를 설명했습니다.', 25),
('로드맵 실전: OS & 터미널', 3, '스크립트 품질', '변수, 조건문, 로그 저장이 읽기 쉽게 작성되어 있습니다.', 25),
('로드맵 실전: OS & 터미널', 4, '권한과 실행', '실행 권한 설정과 실행 결과 예시가 있습니다.', 15),
('로드맵 실전: Java 기초', 1, '캡슐화', '필드를 감추고 의미 있는 메서드로 상태를 변경합니다.', 25),
('로드맵 실전: Java 기초', 2, '다형성과 인터페이스', '회원 등급과 연체료 정책이 다형성과 인터페이스로 분리되어 있습니다.', 35),
('로드맵 실전: Java 기초', 3, '컬렉션 활용', '목적에 맞는 컬렉션을 선택하고 이유를 설명했습니다.', 20),
('로드맵 실전: Java 기초', 4, '예외 처리', '대여 불가 상황을 의미 있는 예외로 처리했습니다.', 20),
('로드맵 실전: Git & 버전 관리', 1, '브랜치 전략', '브랜치 종류와 이름 규칙이 명확하고 실제로 지켜졌습니다.', 25),
('로드맵 실전: Git & 버전 관리', 2, 'PR과 리뷰', 'PR 설명과 리뷰 코멘트가 구체적입니다.', 30),
('로드맵 실전: Git & 버전 관리', 3, '충돌 해결과 되돌리기', '충돌 해결과 revert 과정이 기록되어 있습니다.', 25),
('로드맵 실전: Git & 버전 관리', 4, '회고', '협업 과정에서 배운 점과 개선점을 정리했습니다.', 20),
('로드맵 실전: RDB & SQL', 1, '스키마 설계', '키와 관계가 올바르고 정규화가 적절합니다.', 30),
('로드맵 실전: RDB & SQL', 2, '쿼리 정확성', '집계와 JOIN 쿼리 결과가 요구사항과 일치합니다.', 30),
('로드맵 실전: RDB & SQL', 3, '인덱스 설계', '인덱스 선택 근거와 실행 계획 비교가 있습니다.', 20),
('로드맵 실전: RDB & SQL', 4, '트랜잭션', '재고 차감과 주문 생성을 하나의 작업 단위로 묶었습니다.', 20),
('로드맵 실전: REST API 설계', 1, 'URI와 메서드', '자원 중심 URI와 알맞은 메서드를 일관되게 사용했습니다.', 30),
('로드맵 실전: REST API 설계', 2, '상태 코드와 오류 형식', '상황별 상태 코드와 공통 오류 응답이 정의되어 있습니다.', 25),
('로드맵 실전: REST API 설계', 3, '목록 조회 설계', '페이지네이션과 필터가 실사용에 맞게 설계되어 있습니다.', 20),
('로드맵 실전: REST API 설계', 4, '문서화', 'Swagger 명세에 요청, 응답 예시가 포함되어 있습니다.', 25),
('로드맵 실전: Spring Boot & MVC', 1, '계층 분리', '계층별 책임이 명확하고 생성자 주입을 사용했습니다.', 30),
('로드맵 실전: Spring Boot & MVC', 2, 'API 완성도', 'CRUD API가 모두 정상 동작합니다.', 25),
('로드맵 실전: Spring Boot & MVC', 3, '검증과 예외 처리', '입력 검증과 전역 예외 처리가 일관된 형식으로 응답합니다.', 25),
('로드맵 실전: Spring Boot & MVC', 4, '흐름 설명', '요청 처리 흐름을 정확히 설명했습니다.', 20),
('로드맵 실전: Spring Data JPA', 1, '엔티티 매핑', '연관관계와 지연 로딩이 올바르게 매핑되어 있습니다.', 20),
('로드맵 실전: Spring Data JPA', 2, 'N+1 재현과 분석', 'SQL 로그로 문제를 재현하고 원인을 설명했습니다.', 25),
('로드맵 실전: Spring Data JPA', 3, '개선과 측정', '두 가지 이상 방법으로 개선하고 쿼리 수 변화를 측정했습니다.', 35),
('로드맵 실전: Spring Data JPA', 4, '동적 쿼리', 'QueryDSL로 선택 조건 검색을 구현했습니다.', 20),
('로드맵 실전: Redis 기초', 1, '캐시 적용', '조회 캐시와 무효화가 올바르게 동작합니다.', 35),
('로드맵 실전: Redis 기초', 2, '캐시 설계', '캐시 키와 TTL을 근거 있게 설계했습니다.', 20),
('로드맵 실전: Redis 기초', 3, '랭킹 구현', 'Sorted Set으로 조회수 랭킹을 구현했습니다.', 20),
('로드맵 실전: Redis 기초', 4, '성능 측정', '전후 응답 시간을 측정하고 결과를 해석했습니다.', 25);

INSERT INTO seed_course_content (course_title, subtitle, description) VALUES
('로드맵 실전: Redis 심화', '세션 공유, Pub/Sub, 분산 락, 고가용성까지 Redis를 운영 수준으로 다룹니다',
'서버를 여러 대로 늘리는 순간 로그인 세션 공유, 서버 간 메시지 전달, 동시에 들어온 요청의 중복 처리 같은 새로운 문제가 생깁니다. Redis는 이런 분산 환경 문제를 해결하는 데 가장 많이 쓰이는 도구 중 하나입니다.

첫 섹션에서는 Spring Session으로 여러 서버가 세션을 공유하는 방법, Pub/Sub으로 서버 간 이벤트를 전달하는 방법과 그 한계, Redis Streams와의 차이를 정리합니다.

두 번째 섹션에서는 SETNX와 Redisson으로 분산 락을 구현해 재고 차감 같은 동시성 문제를 막고, Replication과 Sentinel, Cluster로 Redis 자체의 장애에 대비하는 구조를 살펴봅니다. 마지막 과제로 선착순 쿠폰 발급 기능을 분산 락으로 안전하게 구현합니다.'),
('로드맵 실전: JUnit5 & Mockito', '좋은 단위 테스트의 기준부터 Mockito 활용까지, 리팩터링이 두렵지 않은 코드를 만듭니다',
'테스트 코드가 없으면 작은 수정에도 어디가 깨질지 몰라 배포가 두려워집니다. 반대로 테스트가 있어도 구현 세부에 너무 묶여 있으면 리팩터링할 때마다 테스트를 고쳐야 합니다.

첫 섹션에서는 JUnit5의 기본 구조와 생명주기, 단언문 작성법, given-when-then 패턴으로 읽기 쉬운 테스트를 만드는 방법, 파라미터화 테스트로 경계값을 검증하는 방법을 익힙니다.

두 번째 섹션에서는 Mockito로 외부 의존성을 대체하는 방법, stub과 verify의 차이, BDDMockito 스타일, 목을 과하게 쓰면 생기는 문제를 다룹니다. 마지막 과제로 주문 서비스의 핵심 로직을 단위 테스트로 보호합니다.'),
('로드맵 실전: Spring Boot 테스트', '슬라이스 테스트, MockMvc, 통합 테스트로 계층별 테스트 전략을 세웁니다',
'Spring Boot 애플리케이션을 테스트할 때 모든 테스트를 @SpringBootTest로 작성하면 느리고, 단위 테스트만으로는 설정이나 계층 간 연결 오류를 잡지 못합니다. 계층별로 알맞은 테스트 도구를 고르는 기준이 필요합니다.

첫 섹션에서는 @WebMvcTest와 MockMvc로 컨트롤러의 요청, 응답, 검증을 테스트하고, @DataJpaTest로 리포지토리 쿼리를 검증하는 슬라이스 테스트를 다룹니다.

두 번째 섹션에서는 @SpringBootTest로 실제 흐름을 검증하는 통합 테스트, Testcontainers로 실제 데이터베이스를 띄우는 방법, 테스트 데이터 격리와 커버리지 측정을 다룹니다. 마지막 과제로 API 하나에 대한 계층별 테스트 세트를 완성합니다.'),
('로드맵 실전: Spring Security & JWT', '필터 체인의 동작 원리부터 JWT 인증, 소셜 로그인까지 인증과 인가를 설계합니다',
'Spring Security는 설정 몇 줄로 많은 것을 해 주지만, 필터 체인이 어떻게 동작하는지 모르면 401과 403이 왜 나는지, 토큰이 왜 인식되지 않는지 찾기 어렵습니다.

첫 섹션에서는 인증과 인가의 차이, SecurityFilterChain과 필터 순서, SecurityContext에 인증 정보가 저장되는 과정, 비밀번호 암호화를 정리합니다.

두 번째 섹션에서는 JWT 액세스 토큰과 리프레시 토큰 설계, 커스텀 인증 필터 구현, 인증 실패와 권한 부족 응답 처리, OAuth2 소셜 로그인 연동을 다룹니다. 마지막 과제로 JWT 기반 인증과 역할별 권한 제어를 갖춘 API를 완성합니다.'),
('로드맵 실전: Docker & CI/CD', '컨테이너 이미지와 GitHub Actions로 테스트부터 배포까지 자동화 파이프라인을 만듭니다',
'수동 배포는 실수를 부르고, 배포가 무서워지면 릴리스 주기도 길어집니다. 코드를 푸시하면 테스트와 빌드, 배포가 자동으로 이어지는 파이프라인을 만들면 팀이 훨씬 자주, 안전하게 배포할 수 있습니다.

첫 섹션에서는 Dockerfile 작성과 이미지 최적화, docker-compose로 애플리케이션과 DB를 함께 구성하는 방법, 이미지를 레지스트리에 올리는 흐름을 정리합니다.

두 번째 섹션에서는 GitHub Actions 워크플로 문법, 테스트와 빌드 자동화, 시크릿 관리, AWS EC2에 컨테이너를 배포하고 헬스 체크로 배포 결과를 확인하는 방법을 다룹니다. 마지막 과제로 푸시만으로 배포까지 이어지는 파이프라인을 구축합니다.'),
('로드맵 실전: SOLID & 디자인패턴', '변경에 강한 코드를 만드는 SOLID 원칙과 실무에서 자주 쓰는 디자인 패턴을 익힙니다',
'처음에는 잘 돌아가던 코드도 요구사항이 바뀔 때마다 if 문이 늘고, 한 곳을 고치면 다른 곳이 깨지기 시작합니다. SOLID 원칙과 디자인 패턴은 이런 변경 비용을 줄이기 위한 검증된 설계 도구입니다.

첫 섹션에서는 단일 책임, 개방 폐쇄, 리스코프 치환, 인터페이스 분리, 의존 역전 원칙을 위반 사례와 개선 코드로 비교합니다. 원칙을 외우기보다 왜 그렇게 나누는지 이해하는 데 집중합니다.

두 번째 섹션에서는 Strategy, Factory, Singleton, Template Method, Decorator 패턴을 실무 예제로 다루고, 스프링 프레임워크 안에서 이 패턴들이 어떻게 쓰이는지 확인합니다. 마지막 과제로 할인 정책 코드를 원칙과 패턴으로 리팩터링합니다.'),
('로드맵 실전: 웹 보안 기초', 'HTTPS와 인증부터 XSS, CSRF, SQL Injection, CORS까지 웹 보안의 기본 방어선을 세웁니다',
'보안 사고는 대부분 화려한 해킹 기법이 아니라 입력값을 검증하지 않거나, 출력값을 그대로 렌더링하거나, 설정을 잘못한 기본적인 실수에서 시작합니다. OWASP Top 10에 오르는 취약점 상당수가 이 범주에 속합니다.

첫 섹션에서는 HTTPS와 인증서, 쿠키 보안 속성, 세션과 토큰 인증의 보안 고려사항을 정리하고 OWASP Top 10의 주요 항목을 살펴봅니다.

두 번째 섹션에서는 XSS, CSRF, SQL Injection이 실제로 어떻게 공격에 쓰이는지 취약한 예제로 확인하고 방어 코드를 작성합니다. CORS 정책이 무엇을 막고 무엇을 막지 않는지도 함께 다룹니다. 마지막 과제로 취약한 게시판을 점검하고 보안 패치를 적용합니다.'),
('로드맵 실전: 메시지 큐 & MSA', 'Kafka 메시지 흐름과 서비스 분리 기준, API Gateway로 MSA의 핵심 구조를 이해합니다',
'서비스가 커지면 하나의 애플리케이션을 여러 서비스로 나누는 MSA를 고민하게 됩니다. 하지만 기준 없이 나누면 서비스 간 호출이 거미줄처럼 얽히고, 한 서비스 장애가 전체로 번집니다.

첫 섹션에서는 동기 호출과 비동기 메시징의 차이, Kafka의 토픽, 파티션, 컨슈머 그룹, 오프셋 개념, 메시지 순서와 중복 처리를 정리합니다.

두 번째 섹션에서는 도메인 경계로 서비스를 나누는 기준, 서비스별 데이터 소유, API Gateway의 역할, 분산 트랜잭션을 Saga 패턴과 이벤트로 다루는 방법을 살펴봅니다. 마지막 과제로 주문과 결제 서비스를 이벤트로 연결하는 구조를 설계합니다.');

INSERT INTO seed_course_info (course_title, section_key, item_order, item_text) VALUES
('로드맵 실전: Redis 심화', 'TARGET_AUDIENCE', 0, '서버를 여러 대로 늘리며 세션 공유와 동시성 문제를 마주한 백엔드 개발자'),
('로드맵 실전: Redis 심화', 'TARGET_AUDIENCE', 1, '선착순, 재고 차감처럼 중복 처리가 치명적인 기능을 구현해야 하는 분'),
('로드맵 실전: Redis 심화', 'TARGET_AUDIENCE', 2, 'Redis 장애에 대비한 고가용성 구성을 이해하고 싶은 분'),
('로드맵 실전: Redis 심화', 'PREREQUISITES', 0, 'Redis 자료구조와 TTL, Spring Boot 기본을 알고 있어야 합니다.'),
('로드맵 실전: Redis 심화', 'PREREQUISITES', 1, '스레드와 동시성 문제의 기본 개념을 알고 있으면 좋습니다.'),
('로드맵 실전: Redis 심화', 'OBJECTIVES', 0, 'Spring Session과 Redis로 여러 서버가 세션을 공유하게 만들 수 있습니다.'),
('로드맵 실전: Redis 심화', 'OBJECTIVES', 1, 'Pub/Sub과 Streams의 차이를 이해하고 용도에 맞게 선택할 수 있습니다.'),
('로드맵 실전: Redis 심화', 'OBJECTIVES', 2, '분산 락으로 동시 요청의 중복 처리를 막을 수 있습니다.'),
('로드맵 실전: Redis 심화', 'OBJECTIVES', 3, 'Replication, Sentinel, Cluster 구성의 차이와 장애 대응 방식을 설명할 수 있습니다.'),
('로드맵 실전: JUnit5 & Mockito', 'TARGET_AUDIENCE', 0, '테스트 코드를 써야 한다는 건 알지만 무엇을 어떻게 테스트할지 모르는 개발자'),
('로드맵 실전: JUnit5 & Mockito', 'TARGET_AUDIENCE', 1, '리팩터링할 때마다 테스트가 줄줄이 깨져 지친 분'),
('로드맵 실전: JUnit5 & Mockito', 'TARGET_AUDIENCE', 2, 'Mockito의 stub과 verify를 언제 써야 할지 헷갈리는 분'),
('로드맵 실전: JUnit5 & Mockito', 'PREREQUISITES', 0, 'Java 문법과 인터페이스, 의존성 주입 개념을 알고 있어야 합니다.'),
('로드맵 실전: JUnit5 & Mockito', 'PREREQUISITES', 1, 'Gradle 또는 Maven으로 프로젝트를 실행해 본 경험이 있으면 좋습니다.'),
('로드맵 실전: JUnit5 & Mockito', 'OBJECTIVES', 0, 'given-when-then 구조로 읽기 쉬운 단위 테스트를 작성할 수 있습니다.'),
('로드맵 실전: JUnit5 & Mockito', 'OBJECTIVES', 1, '파라미터화 테스트로 경계값과 예외 상황을 효율적으로 검증할 수 있습니다.'),
('로드맵 실전: JUnit5 & Mockito', 'OBJECTIVES', 2, 'Mockito로 외부 의존성을 대체하고 stub과 verify를 구분해 사용할 수 있습니다.'),
('로드맵 실전: JUnit5 & Mockito', 'OBJECTIVES', 3, '구현 세부가 아닌 동작을 검증해 리팩터링에 강한 테스트를 만들 수 있습니다.'),
('로드맵 실전: Spring Boot 테스트', 'TARGET_AUDIENCE', 0, '모든 테스트를 @SpringBootTest로 작성해 테스트가 느려진 개발자'),
('로드맵 실전: Spring Boot 테스트', 'TARGET_AUDIENCE', 1, '컨트롤러와 리포지토리를 각각 어떻게 테스트해야 할지 궁금한 분'),
('로드맵 실전: Spring Boot 테스트', 'TARGET_AUDIENCE', 2, '실제 DB와 비슷한 환경에서 통합 테스트를 하고 싶은 분'),
('로드맵 실전: Spring Boot 테스트', 'PREREQUISITES', 0, 'JUnit5 단위 테스트를 작성해 본 경험이 있어야 합니다.'),
('로드맵 실전: Spring Boot 테스트', 'PREREQUISITES', 1, 'Spring MVC와 JPA로 API를 만들어 본 경험이 있으면 좋습니다.'),
('로드맵 실전: Spring Boot 테스트', 'OBJECTIVES', 0, '@WebMvcTest와 MockMvc로 컨트롤러의 요청, 응답, 검증을 테스트할 수 있습니다.'),
('로드맵 실전: Spring Boot 테스트', 'OBJECTIVES', 1, '@DataJpaTest로 리포지토리 쿼리를 검증할 수 있습니다.'),
('로드맵 실전: Spring Boot 테스트', 'OBJECTIVES', 2, '@SpringBootTest와 Testcontainers로 실제 흐름을 통합 테스트할 수 있습니다.'),
('로드맵 실전: Spring Boot 테스트', 'OBJECTIVES', 3, '테스트 데이터를 격리하고 커버리지를 측정해 테스트 전략을 세울 수 있습니다.'),
('로드맵 실전: Spring Security & JWT', 'TARGET_AUDIENCE', 0, '로그인 기능을 붙였지만 Spring Security 동작은 블랙박스처럼 느껴지는 개발자'),
('로드맵 실전: Spring Security & JWT', 'TARGET_AUDIENCE', 1, 'JWT 인증을 직접 설계하고 리프레시 토큰까지 다뤄 보고 싶은 분'),
('로드맵 실전: Spring Security & JWT', 'TARGET_AUDIENCE', 2, '소셜 로그인을 서비스에 연동해야 하는 분'),
('로드맵 실전: Spring Security & JWT', 'PREREQUISITES', 0, 'Spring Boot와 MVC 구조, 필터의 개념을 알고 있어야 합니다.'),
('로드맵 실전: Spring Security & JWT', 'PREREQUISITES', 1, 'HTTP 헤더와 쿠키, 세션의 기본 개념을 알고 있으면 좋습니다.'),
('로드맵 실전: Spring Security & JWT', 'OBJECTIVES', 0, 'SecurityFilterChain과 필터 순서, 인증 정보 저장 과정을 설명할 수 있습니다.'),
('로드맵 실전: Spring Security & JWT', 'OBJECTIVES', 1, 'JWT 인증 필터를 구현하고 액세스, 리프레시 토큰을 설계할 수 있습니다.'),
('로드맵 실전: Spring Security & JWT', 'OBJECTIVES', 2, '인증 실패와 권한 부족을 구분해 일관된 오류 응답을 보낼 수 있습니다.'),
('로드맵 실전: Spring Security & JWT', 'OBJECTIVES', 3, 'OAuth2 소셜 로그인을 연동하고 서비스 회원과 연결할 수 있습니다.'),
('로드맵 실전: Docker & CI/CD', 'TARGET_AUDIENCE', 0, '아직 서버에 직접 접속해 수동으로 배포하고 있는 개발자'),
('로드맵 실전: Docker & CI/CD', 'TARGET_AUDIENCE', 1, 'GitHub Actions로 테스트와 배포를 자동화하고 싶은 분'),
('로드맵 실전: Docker & CI/CD', 'TARGET_AUDIENCE', 2, '포트폴리오 프로젝트에 실제 배포 파이프라인을 갖추고 싶은 취업 준비생'),
('로드맵 실전: Docker & CI/CD', 'PREREQUISITES', 0, 'Git과 GitHub 사용법, 터미널 기본 명령어를 알고 있어야 합니다.'),
('로드맵 실전: Docker & CI/CD', 'PREREQUISITES', 1, '배포할 간단한 웹 애플리케이션이 있으면 실습이 수월합니다.'),
('로드맵 실전: Docker & CI/CD', 'OBJECTIVES', 0, 'Dockerfile로 애플리케이션 이미지를 만들고 크기를 최적화할 수 있습니다.'),
('로드맵 실전: Docker & CI/CD', 'OBJECTIVES', 1, 'docker-compose로 애플리케이션과 DB를 함께 구성할 수 있습니다.'),
('로드맵 실전: Docker & CI/CD', 'OBJECTIVES', 2, 'GitHub Actions로 테스트와 이미지 빌드를 자동화하고 시크릿을 안전하게 관리할 수 있습니다.'),
('로드맵 실전: Docker & CI/CD', 'OBJECTIVES', 3, 'EC2에 컨테이너를 자동 배포하고 헬스 체크로 결과를 검증할 수 있습니다.'),
('로드맵 실전: SOLID & 디자인패턴', 'TARGET_AUDIENCE', 0, '기능은 만들 수 있지만 요구사항이 바뀔 때마다 코드가 무너지는 개발자'),
('로드맵 실전: SOLID & 디자인패턴', 'TARGET_AUDIENCE', 1, '코드 리뷰에서 설계 관련 피드백을 자주 받는 분'),
('로드맵 실전: SOLID & 디자인패턴', 'TARGET_AUDIENCE', 2, '디자인 패턴을 외웠지만 언제 써야 할지 모르는 분'),
('로드맵 실전: SOLID & 디자인패턴', 'PREREQUISITES', 0, 'Java 객체지향 문법과 인터페이스를 이해하고 있어야 합니다.'),
('로드맵 실전: SOLID & 디자인패턴', 'PREREQUISITES', 1, '수백 줄 이상의 코드를 직접 작성해 본 경험이 있으면 좋습니다.'),
('로드맵 실전: SOLID & 디자인패턴', 'OBJECTIVES', 0, 'SOLID 다섯 원칙을 위반 사례와 함께 설명할 수 있습니다.'),
('로드맵 실전: SOLID & 디자인패턴', 'OBJECTIVES', 1, '조건문이 늘어나는 코드를 Strategy 패턴으로 개선할 수 있습니다.'),
('로드맵 실전: SOLID & 디자인패턴', 'OBJECTIVES', 2, 'Factory, Singleton, Template Method, Decorator를 상황에 맞게 적용할 수 있습니다.'),
('로드맵 실전: SOLID & 디자인패턴', 'OBJECTIVES', 3, '스프링 안에서 쓰이는 패턴을 찾아 설계 의도를 설명할 수 있습니다.'),
('로드맵 실전: 웹 보안 기초', 'TARGET_AUDIENCE', 0, '서비스를 배포하기 전에 기본 보안 점검을 하고 싶은 웹 개발자'),
('로드맵 실전: 웹 보안 기초', 'TARGET_AUDIENCE', 1, 'XSS, CSRF, CORS 용어가 헷갈려 정확히 정리하고 싶은 분'),
('로드맵 실전: 웹 보안 기초', 'TARGET_AUDIENCE', 2, '보안 관련 면접 질문에 대비하고 싶은 취업 준비생'),
('로드맵 실전: 웹 보안 기초', 'PREREQUISITES', 0, 'HTTP 요청과 응답, 쿠키와 세션의 기본 개념을 알고 있어야 합니다.'),
('로드맵 실전: 웹 보안 기초', 'PREREQUISITES', 1, '간단한 웹 애플리케이션을 만들어 본 경험이 있으면 좋습니다.'),
('로드맵 실전: 웹 보안 기초', 'OBJECTIVES', 0, 'HTTPS와 쿠키 보안 속성으로 전송 구간과 세션을 보호할 수 있습니다.'),
('로드맵 실전: 웹 보안 기초', 'OBJECTIVES', 1, 'XSS와 CSRF의 공격 원리를 이해하고 방어 코드를 적용할 수 있습니다.'),
('로드맵 실전: 웹 보안 기초', 'OBJECTIVES', 2, 'Prepared Statement로 SQL Injection을 방어할 수 있습니다.'),
('로드맵 실전: 웹 보안 기초', 'OBJECTIVES', 3, 'CORS 정책의 역할과 한계를 이해하고 올바르게 설정할 수 있습니다.'),
('로드맵 실전: 메시지 큐 & MSA', 'TARGET_AUDIENCE', 0, '모놀리식 서비스를 운영하며 서비스 분리를 고민하는 백엔드 개발자'),
('로드맵 실전: 메시지 큐 & MSA', 'TARGET_AUDIENCE', 1, 'Kafka를 도입했지만 파티션과 컨슈머 그룹 개념이 헷갈리는 분'),
('로드맵 실전: 메시지 큐 & MSA', 'TARGET_AUDIENCE', 2, '분산 환경의 데이터 정합성 문제를 이해하고 싶은 분'),
('로드맵 실전: 메시지 큐 & MSA', 'PREREQUISITES', 0, 'Spring Boot로 REST API를 만들어 본 경험이 있어야 합니다.'),
('로드맵 실전: 메시지 큐 & MSA', 'PREREQUISITES', 1, '트랜잭션과 Docker 기본 사용법을 알고 있으면 좋습니다.'),
('로드맵 실전: 메시지 큐 & MSA', 'OBJECTIVES', 0, '동기 호출과 비동기 메시징의 장단점을 비교할 수 있습니다.'),
('로드맵 실전: 메시지 큐 & MSA', 'OBJECTIVES', 1, 'Kafka의 토픽, 파티션, 컨슈머 그룹, 오프셋을 설명할 수 있습니다.'),
('로드맵 실전: 메시지 큐 & MSA', 'OBJECTIVES', 2, '도메인 경계와 데이터 소유를 기준으로 서비스를 나눌 수 있습니다.'),
('로드맵 실전: 메시지 큐 & MSA', 'OBJECTIVES', 3, 'API Gateway와 Saga 패턴으로 서비스 간 흐름을 설계할 수 있습니다.');

INSERT INTO seed_course_curriculum (course_title, section_order, section_title, section_description, lesson_order, lesson_title, lesson_description) VALUES
('로드맵 실전: Redis 심화', 1, '분산 환경에서 Redis 쓰기', '세션 공유와 서버 간 메시지 전달을 다룹니다.', 1, 'Spring Session으로 세션 공유하기', '서버가 여러 대일 때 세션이 사라지는 이유와 Redis에 세션을 저장해 공유하는 구성을 따라갑니다.'),
('로드맵 실전: Redis 심화', 1, '분산 환경에서 Redis 쓰기', '세션 공유와 서버 간 메시지 전달을 다룹니다.', 2, 'Pub/Sub과 Streams로 이벤트 전달하기', 'Pub/Sub으로 서버 간 알림을 전달하고, 메시지가 저장되지 않는 한계를 Streams로 보완하는 방법을 비교합니다.'),
('로드맵 실전: Redis 심화', 2, '동시성과 고가용성', '분산 락과 Redis 장애 대비 구조를 다룹니다.', 1, '분산 락으로 동시성 문제 해결하기', 'SETNX와 만료 시간, Redisson 락으로 재고 차감의 중복 처리를 막고 락 해제 실패 시나리오를 점검합니다.'),
('로드맵 실전: Redis 심화', 2, '동시성과 고가용성', '분산 락과 Redis 장애 대비 구조를 다룹니다.', 2, 'Replication, Sentinel, Cluster 구성', '복제와 자동 장애 조치, 샤딩 구성의 차이를 정리하고 운영 환경에서 고를 기준을 다룹니다.'),
('로드맵 실전: JUnit5 & Mockito', 1, '좋은 단위 테스트의 기준', 'JUnit5 구조와 읽기 쉬운 테스트 작성법을 익힙니다.', 1, 'JUnit5 구조와 given-when-then', '테스트 생명주기와 단언문, given-when-then으로 의도가 드러나는 테스트를 작성하는 방법을 다룹니다.'),
('로드맵 실전: JUnit5 & Mockito', 1, '좋은 단위 테스트의 기준', 'JUnit5 구조와 읽기 쉬운 테스트 작성법을 익힙니다.', 2, '파라미터화 테스트와 예외 검증', '@ParameterizedTest로 경계값을 한 번에 검증하고 assertThrows로 예외 상황을 테스트합니다.'),
('로드맵 실전: JUnit5 & Mockito', 2, 'Mockito로 의존성 다루기', '목 객체로 협력 객체를 대체하고 검증하는 방법을 익힙니다.', 1, 'Mock, Stub, Verify의 차이', '@Mock과 @InjectMocks로 테스트 대상을 구성하고, 반환값을 정하는 stub과 호출을 확인하는 verify를 구분합니다.'),
('로드맵 실전: JUnit5 & Mockito', 2, 'Mockito로 의존성 다루기', '목 객체로 협력 객체를 대체하고 검증하는 방법을 익힙니다.', 2, 'BDDMockito와 과도한 목 사용 피하기', 'BDD 스타일로 테스트를 읽기 쉽게 만들고, 구현 세부에 묶인 테스트가 리팩터링을 방해하는 사례를 살펴봅니다.'),
('로드맵 실전: Spring Boot 테스트', 1, '슬라이스 테스트', '컨트롤러와 리포지토리를 필요한 빈만 띄워 테스트합니다.', 1, '@WebMvcTest와 MockMvc로 컨트롤러 테스트', '요청 파라미터, JSON 바디, 검증 실패, 상태 코드를 MockMvc로 검증하는 방법을 다룹니다.'),
('로드맵 실전: Spring Boot 테스트', 1, '슬라이스 테스트', '컨트롤러와 리포지토리를 필요한 빈만 띄워 테스트합니다.', 2, '@DataJpaTest로 리포지토리 테스트', '임베디드 또는 실제 DB로 쿼리 메서드와 JPQL 결과를 검증하고 트랜잭션 롤백 동작을 확인합니다.'),
('로드맵 실전: Spring Boot 테스트', 2, '통합 테스트와 테스트 전략', '전체 흐름 테스트와 테스트 환경 구성을 다룹니다.', 1, '@SpringBootTest와 Testcontainers', '실제 애플리케이션 컨텍스트와 컨테이너 DB로 API 전체 흐름을 검증하는 통합 테스트를 작성합니다.'),
('로드맵 실전: Spring Boot 테스트', 2, '통합 테스트와 테스트 전략', '전체 흐름 테스트와 테스트 환경 구성을 다룹니다.', 2, '테스트 데이터 격리와 커버리지 측정', '테스트 간 데이터 간섭을 막는 방법과 JaCoCo로 커버리지를 측정해 테스트 전략을 점검합니다.'),
('로드맵 실전: Spring Security & JWT', 1, 'Spring Security 동작 원리', '필터 체인과 인증 정보 저장 과정을 정리합니다.', 1, '인증과 인가, SecurityFilterChain', '인증과 인가의 차이, 요청이 필터 체인을 통과하는 순서, 설정 클래스로 접근 규칙을 정하는 방법을 다룹니다.'),
('로드맵 실전: Spring Security & JWT', 1, 'Spring Security 동작 원리', '필터 체인과 인증 정보 저장 과정을 정리합니다.', 2, 'SecurityContext와 비밀번호 암호화', '인증 결과가 SecurityContext에 저장되는 과정과 BCrypt로 비밀번호를 안전하게 저장하는 방법을 정리합니다.'),
('로드맵 실전: Spring Security & JWT', 2, 'JWT와 소셜 로그인', '토큰 인증과 OAuth2 연동을 구현합니다.', 1, 'JWT 인증 필터와 리프레시 토큰', '토큰을 검증하는 커스텀 필터를 만들고, 액세스 토큰 만료 시 리프레시 토큰으로 재발급하는 흐름을 설계합니다.'),
('로드맵 실전: Spring Security & JWT', 2, 'JWT와 소셜 로그인', '토큰 인증과 OAuth2 연동을 구현합니다.', 2, 'OAuth2 소셜 로그인과 예외 응답', 'OAuth2 로그인 흐름을 연동하고, 인증 실패와 권한 부족을 EntryPoint와 AccessDeniedHandler로 처리합니다.'),
('로드맵 실전: Docker & CI/CD', 1, '컨테이너로 실행 환경 통일하기', 'Dockerfile과 docker-compose로 환경을 구성합니다.', 1, 'Dockerfile 작성과 이미지 최적화', '멀티 스테이지 빌드와 레이어 캐시, .dockerignore로 빌드 속도와 이미지 크기를 줄이는 방법을 다룹니다.'),
('로드맵 실전: Docker & CI/CD', 1, '컨테이너로 실행 환경 통일하기', 'Dockerfile과 docker-compose로 환경을 구성합니다.', 2, 'docker-compose와 이미지 레지스트리', '애플리케이션과 DB를 compose로 함께 띄우고, 이미지를 레지스트리에 태그와 함께 올리는 흐름을 익힙니다.'),
('로드맵 실전: Docker & CI/CD', 2, '자동화 파이프라인 만들기', 'GitHub Actions로 테스트부터 배포까지 자동화합니다.', 1, 'GitHub Actions로 테스트와 빌드 자동화', '워크플로 트리거와 잡, 스텝 구조를 이해하고 푸시마다 테스트와 이미지 빌드가 실행되게 만듭니다.'),
('로드맵 실전: Docker & CI/CD', 2, '자동화 파이프라인 만들기', 'GitHub Actions로 테스트부터 배포까지 자동화합니다.', 2, '시크릿 관리와 EC2 자동 배포', '저장소 시크릿으로 접속 정보를 관리하고, EC2에 새 이미지를 배포한 뒤 헬스 체크로 결과를 확인합니다.'),
('로드맵 실전: SOLID & 디자인패턴', 1, 'SOLID 원칙', '다섯 가지 설계 원칙을 위반 사례와 개선 코드로 비교합니다.', 1, '단일 책임 원칙과 개방 폐쇄 원칙', '변경 이유가 여러 개인 클래스를 나누고, 새 기능을 추가할 때 기존 코드를 고치지 않는 구조를 만듭니다.'),
('로드맵 실전: SOLID & 디자인패턴', 1, 'SOLID 원칙', '다섯 가지 설계 원칙을 위반 사례와 개선 코드로 비교합니다.', 2, 'LSP, ISP, DIP로 의존 관계 정리하기', '하위 타입이 상위 타입을 대체할 수 있어야 하는 이유, 인터페이스를 작게 나누는 이유, 추상화에 의존하는 방법을 다룹니다.'),
('로드맵 실전: SOLID & 디자인패턴', 2, '실무 디자인 패턴', '자주 쓰는 패턴을 실무 예제와 스프링 코드로 익힙니다.', 1, 'Strategy, Factory, Singleton 패턴', '조건문을 전략 객체로 바꾸고, 객체 생성을 팩토리로 모으며, 싱글톤의 주의점을 정리합니다.'),
('로드맵 실전: SOLID & 디자인패턴', 2, '실무 디자인 패턴', '자주 쓰는 패턴을 실무 예제와 스프링 코드로 익힙니다.', 2, 'Template Method, Decorator와 스프링 속 패턴', '공통 흐름을 템플릿으로 고정하고 기능을 덧붙이는 데코레이터를 구현한 뒤, 스프링에서 쓰이는 사례를 찾아봅니다.'),
('로드맵 실전: 웹 보안 기초', 1, '안전한 통신과 인증', 'HTTPS, 쿠키 보안, OWASP Top 10을 정리합니다.', 1, 'HTTPS와 쿠키 보안 속성', 'TLS 인증서의 역할과 Secure, HttpOnly, SameSite 쿠키 속성이 막아 주는 공격을 정리합니다.'),
('로드맵 실전: 웹 보안 기초', 1, '안전한 통신과 인증', 'HTTPS, 쿠키 보안, OWASP Top 10을 정리합니다.', 2, 'OWASP Top 10 한눈에 보기', '접근 제어 실패, 인젝션, 보안 설정 오류 등 자주 발생하는 취약점의 유형과 사례를 살펴봅니다.'),
('로드맵 실전: 웹 보안 기초', 2, '주요 공격과 방어', 'XSS, CSRF, SQL Injection, CORS를 취약 예제로 확인합니다.', 1, 'XSS와 CSRF 공격과 방어', '스크립트 삽입과 요청 위조가 일어나는 과정을 재현하고 출력 이스케이프, CSP, CSRF 토큰으로 방어합니다.'),
('로드맵 실전: 웹 보안 기초', 2, '주요 공격과 방어', 'XSS, CSRF, SQL Injection, CORS를 취약 예제로 확인합니다.', 2, 'SQL Injection과 CORS 정책', '문자열 연결 쿼리의 위험과 Prepared Statement 방어, CORS가 브라우저에서만 적용되는 이유를 정리합니다.'),
('로드맵 실전: 메시지 큐 & MSA', 1, '메시지 큐와 Kafka', '비동기 메시징과 Kafka의 핵심 구조를 정리합니다.', 1, '동기 호출과 비동기 메시징', '서비스 간 직접 호출의 장애 전파 문제와 메시지 큐로 결합도를 낮추는 구조를 비교합니다.'),
('로드맵 실전: 메시지 큐 & MSA', 1, '메시지 큐와 Kafka', '비동기 메시징과 Kafka의 핵심 구조를 정리합니다.', 2, 'Kafka 토픽, 파티션, 컨슈머 그룹', '파티션으로 처리량을 늘리는 원리, 컨슈머 그룹과 오프셋, 메시지 순서와 중복 처리 전략을 다룹니다.'),
('로드맵 실전: 메시지 큐 & MSA', 2, 'MSA 설계', '서비스 분리 기준과 서비스 간 흐름 관리를 다룹니다.', 1, '서비스 분리 기준과 데이터 소유', '도메인 경계로 서비스를 나누고 각 서비스가 자기 데이터를 소유해야 하는 이유를 사례로 정리합니다.'),
('로드맵 실전: 메시지 큐 & MSA', 2, 'MSA 설계', '서비스 분리 기준과 서비스 간 흐름 관리를 다룹니다.', 2, 'API Gateway와 Saga 패턴', '인증, 라우팅을 담당하는 게이트웨이와 보상 트랜잭션으로 분산 작업을 마무리하는 Saga 패턴을 다룹니다.');

INSERT INTO seed_course_quiz (course_title, quiz_title, quiz_description, lesson_title, lesson_description) VALUES
('로드맵 실전: Redis 심화', '분산 환경 Redis 점검 퀴즈', '세션 공유, Pub/Sub, Streams, 분산 락의 핵심을 점검합니다.', '섹션 퀴즈: 분산 환경에서 Redis 쓰기', '여러 서버 환경에서 Redis를 쓰는 방법을 5문항으로 점검합니다.'),
('로드맵 실전: JUnit5 & Mockito', '단위 테스트 기본기 퀴즈', 'JUnit5 구조, 단언, 파라미터화 테스트의 핵심을 점검합니다.', '섹션 퀴즈: 좋은 단위 테스트의 기준', '읽기 쉽고 믿을 수 있는 테스트의 조건을 5문항으로 점검합니다.'),
('로드맵 실전: Spring Boot 테스트', '슬라이스 테스트 점검 퀴즈', '@WebMvcTest, MockMvc, @DataJpaTest의 특징을 점검합니다.', '섹션 퀴즈: 슬라이스 테스트', '계층별 테스트 어노테이션의 차이를 5문항으로 점검합니다.'),
('로드맵 실전: Spring Security & JWT', 'Spring Security 동작 원리 퀴즈', '인증과 인가, 필터 체인, 비밀번호 암호화를 점검합니다.', '섹션 퀴즈: Spring Security 동작 원리', '보안 필터 체인의 동작을 5문항으로 점검합니다.'),
('로드맵 실전: Docker & CI/CD', '컨테이너 환경 구성 퀴즈', 'Dockerfile, 이미지 최적화, docker-compose의 핵심을 점검합니다.', '섹션 퀴즈: 컨테이너로 실행 환경 통일하기', '이미지 빌드와 컨테이너 구성을 5문항으로 점검합니다.'),
('로드맵 실전: SOLID & 디자인패턴', 'SOLID 원칙 점검 퀴즈', '다섯 가지 설계 원칙의 의미와 적용 사례를 점검합니다.', '섹션 퀴즈: SOLID 원칙', '원칙 위반 사례를 찾아내는 문제 5문항으로 점검합니다.'),
('로드맵 실전: 웹 보안 기초', '안전한 통신과 인증 퀴즈', 'HTTPS, 쿠키 보안 속성, OWASP Top 10의 핵심을 점검합니다.', '섹션 퀴즈: 안전한 통신과 인증', '기본 보안 설정을 5문항으로 점검합니다.'),
('로드맵 실전: 메시지 큐 & MSA', '메시지 큐와 Kafka 퀴즈', '비동기 메시징과 Kafka의 구조를 점검합니다.', '섹션 퀴즈: 메시지 큐와 Kafka', '토픽, 파티션, 컨슈머 그룹 개념을 5문항으로 점검합니다.');

INSERT INTO seed_course_quiz_question (course_title, display_order, question_text, explanation, correct_option, option1, option2, option3, option4) VALUES
('로드맵 실전: Redis 심화', 1, '서버 두 대가 로드 밸런서 뒤에 있을 때 로그인 상태가 자주 풀리는 원인으로 가장 가능성이 높은 것은 무엇인가요?', '세션을 각 서버 메모리에 저장하면 다른 서버로 요청이 가는 순간 세션을 찾지 못하므로, Redis 같은 공유 저장소가 필요합니다.', 2, '쿠키 이름이 너무 길어서', '세션이 각 서버 메모리에만 저장되어 서로 공유되지 않아서', 'HTTPS를 사용해서', '데이터베이스 인덱스가 없어서'),
('로드맵 실전: Redis 심화', 2, 'Redis Pub/Sub의 특징으로 올바른 것은 무엇인가요?', 'Pub/Sub은 메시지를 저장하지 않으므로 발행 시점에 구독 중이 아닌 클라이언트는 메시지를 받을 수 없습니다.', 4, '메시지가 디스크에 영구 저장된다', '구독자가 나중에 접속해도 지난 메시지를 모두 받는다', '메시지마다 처리 확인(ACK)을 보낸다', '발행 시점에 구독 중인 클라이언트에게만 전달되고 저장되지 않는다'),
('로드맵 실전: Redis 심화', 3, 'Redis Streams가 Pub/Sub보다 유리한 상황은 무엇인가요?', 'Streams는 메시지를 로그로 저장하고 컨슈머 그룹과 ACK를 지원하므로, 유실 없이 처리해야 하는 이벤트에 적합합니다.', 1, '메시지 유실 없이 처리 여부를 추적해야 할 때', '메시지를 절대 저장하면 안 될 때', '단순히 키 하나에 값을 저장할 때', '랭킹을 계산할 때'),
('로드맵 실전: Redis 심화', 4, 'SET key value NX PX 3000 명령으로 락을 잡을 때 만료 시간을 함께 주는 이유는 무엇인가요?', '락을 잡은 서버가 해제 전에 죽어도 만료 시간이 지나면 락이 풀려 다른 요청이 영원히 막히는 데드락을 피할 수 있습니다.', 3, '명령 속도를 높이기 위해', '락을 여러 서버가 동시에 잡게 하기 위해', '락을 가진 서버가 죽어도 락이 영원히 남지 않게 하기 위해', '값을 암호화하기 위해'),
('로드맵 실전: Redis 심화', 5, '락을 해제할 때 내 락인지 확인한 뒤 삭제해야 하는 이유는 무엇인가요?', '내 락이 만료된 뒤 다른 요청이 새 락을 잡았을 수 있으므로, 값(소유자 식별자)을 확인하지 않고 지우면 남의 락을 해제하게 됩니다.', 2, 'DEL 명령이 느리기 때문에', '만료 후 다른 요청이 잡은 락을 실수로 해제할 수 있기 때문에', 'Redis가 삭제를 지원하지 않기 때문에', '락 키 이름이 자동으로 바뀌기 때문에'),
('로드맵 실전: JUnit5 & Mockito', 1, 'given-when-then 구조에서 when 단계에 들어가야 하는 것은 무엇인가요?', 'given은 준비, when은 테스트 대상 행동 실행, then은 결과 검증입니다. when에는 검증하려는 동작 하나만 둡니다.', 3, '테스트 데이터 준비', '결과값 단언', '테스트 대상 메서드 호출', '목 객체 선언'),
('로드맵 실전: JUnit5 & Mockito', 2, '@BeforeEach가 붙은 메서드는 언제 실행되나요?', '@BeforeEach는 각 테스트 메서드가 실행되기 직전마다 실행되어 테스트마다 깨끗한 상태를 준비합니다.', 1, '각 테스트 메서드 실행 전마다', '테스트 클래스 전체에서 한 번만', '모든 테스트가 끝난 뒤 한 번', '실패한 테스트 뒤에만'),
('로드맵 실전: JUnit5 & Mockito', 3, '여러 입력값으로 같은 검증을 반복할 때 가장 알맞은 기능은 무엇인가요?', '@ParameterizedTest와 @ValueSource, @CsvSource를 쓰면 같은 테스트를 여러 입력값으로 실행할 수 있습니다.', 4, '@Disabled', '@Order', '@Timeout', '@ParameterizedTest'),
('로드맵 실전: JUnit5 & Mockito', 4, '음수 금액을 입금하면 예외가 발생하는지 검증하는 올바른 방법은 무엇인가요?', 'assertThrows는 실행 코드가 지정한 예외를 던지는지 검증하고, 던져진 예외를 반환해 메시지까지 확인할 수 있습니다.', 2, 'try-catch 없이 호출만 한다', 'assertThrows로 예외 타입을 검증한다', 'assertEquals(null, 결과)를 쓴다', '예외를 로그로만 출력한다'),
('로드맵 실전: JUnit5 & Mockito', 5, '좋은 단위 테스트의 특징으로 가장 거리가 먼 것은 무엇인가요?', '좋은 단위 테스트는 빠르고, 독립적이며, 반복 가능해야 합니다. 실행 순서에 따라 결과가 달라지면 신뢰할 수 없습니다.', 3, '빠르게 실행된다', '다른 테스트와 독립적이다', '실행 순서에 따라 결과가 달라진다', '언제 실행해도 같은 결과가 나온다'),
('로드맵 실전: Spring Boot 테스트', 1, '@WebMvcTest의 특징으로 올바른 것은 무엇인가요?', '@WebMvcTest는 컨트롤러, 필터, 메시지 컨버터 같은 MVC 관련 빈만 로드하므로 Service 등은 @MockBean으로 대체해야 합니다.', 2, '모든 빈을 로드한다', 'MVC 관련 빈만 로드해 Service는 목으로 대체해야 한다', '실제 서버 포트를 반드시 연다', 'JPA 리포지토리를 자동으로 로드한다'),
('로드맵 실전: Spring Boot 테스트', 2, 'MockMvc로 응답 상태가 201인지 검증하는 코드로 알맞은 것은 무엇인가요?', 'andExpect(status().isCreated())는 응답 상태 코드가 201 Created인지 검증합니다.', 1, 'andExpect(status().isCreated())', 'andExpect(status().isOk())', 'andDo(print())', 'andReturn()'),
('로드맵 실전: Spring Boot 테스트', 3, '@DataJpaTest의 기본 동작으로 올바른 것은 무엇인가요?', '@DataJpaTest는 JPA 관련 빈만 로드하고 각 테스트를 트랜잭션으로 감싸 끝나면 롤백합니다.', 4, '테스트 후 데이터를 커밋한다', '웹 계층까지 모두 로드한다', '트랜잭션을 사용하지 않는다', 'JPA 관련 빈만 로드하고 테스트마다 롤백한다'),
('로드맵 실전: Spring Boot 테스트', 4, '요청 바디 검증 실패 시 400이 반환되는지 테스트하려면 어떤 테스트가 가장 효율적인가요?', '검증과 상태 코드는 웹 계층의 책임이므로 @WebMvcTest와 MockMvc로 빠르게 검증하는 것이 효율적입니다.', 3, 'Testcontainers를 쓴 통합 테스트', '@DataJpaTest', '@WebMvcTest와 MockMvc', '수동 테스트'),
('로드맵 실전: Spring Boot 테스트', 5, '@MockBean의 역할로 올바른 것은 무엇인가요?', '@MockBean은 스프링 컨텍스트의 빈을 Mockito 목으로 등록하거나 교체해, 슬라이스 테스트에서 의존 빈을 대체합니다.', 2, '실제 빈을 두 개 등록한다', '스프링 컨텍스트의 빈을 목 객체로 등록하거나 교체한다', '테스트를 비활성화한다', '데이터베이스를 초기화한다'),
('로드맵 실전: Spring Security & JWT', 1, '인증(Authentication)과 인가(Authorization)의 차이로 올바른 것은 무엇인가요?', '인증은 사용자가 누구인지 확인하는 과정이고, 인가는 확인된 사용자가 특정 자원에 접근할 권한이 있는지 판단하는 과정입니다.', 1, '인증은 누구인지 확인하고, 인가는 권한이 있는지 판단한다', '둘은 같은 개념이다', '인가가 항상 인증보다 먼저 일어난다', '인증은 서버, 인가는 브라우저에서만 일어난다'),
('로드맵 실전: Spring Security & JWT', 2, 'Spring Security가 요청을 처리하는 기본 단위는 무엇인가요?', 'Spring Security는 서블릿 필터 체인으로 동작하며 요청은 정해진 순서의 보안 필터들을 차례로 통과합니다.', 3, '컨트롤러 메서드', 'JPA 리포지토리', '서블릿 필터 체인', 'application.yml'),
('로드맵 실전: Spring Security & JWT', 3, '인증에 성공한 사용자 정보는 기본적으로 어디에 저장되나요?', '인증 결과 Authentication 객체는 SecurityContextHolder의 SecurityContext에 저장되어 이후 코드에서 조회할 수 있습니다.', 2, 'HTTP 응답 바디', 'SecurityContextHolder의 SecurityContext', '데이터베이스 users 테이블', '브라우저 로컬 스토리지'),
('로드맵 실전: Spring Security & JWT', 4, '비밀번호를 저장할 때 BCrypt 같은 해시 함수를 쓰는 이유는 무엇인가요?', '단방향 해시와 솔트로 저장하면 DB가 유출되어도 원래 비밀번호를 알아내기 어렵습니다.', 4, '나중에 비밀번호를 복호화해 보여 주기 위해', '비밀번호 길이를 줄이기 위해', '로그인 속도를 빠르게 하기 위해', 'DB가 유출되어도 원래 비밀번호를 알기 어렵게 하기 위해'),
('로드맵 실전: Spring Security & JWT', 5, '로그인하지 않은 사용자가 보호된 API를 호출했을 때 기본적으로 처리하는 컴포넌트는 무엇인가요?', '인증되지 않은 요청은 AuthenticationEntryPoint가 401 응답을 만들고, 권한 부족은 AccessDeniedHandler가 403을 만듭니다.', 1, 'AuthenticationEntryPoint', 'AccessDeniedHandler', 'PasswordEncoder', 'UserDetailsService'),
('로드맵 실전: Docker & CI/CD', 1, '.dockerignore 파일의 역할은 무엇인가요?', '.dockerignore에 적힌 파일은 빌드 컨텍스트에서 제외되어 빌드 속도가 빨라지고 불필요한 파일이 이미지에 들어가지 않습니다.', 3, '컨테이너 포트를 지정한다', '환경 변수를 정의한다', '빌드 컨텍스트에서 불필요한 파일을 제외한다', '이미지 태그를 정한다'),
('로드맵 실전: Docker & CI/CD', 2, 'Dockerfile의 CMD와 RUN의 차이로 올바른 것은 무엇인가요?', 'RUN은 이미지를 빌드할 때 실행되어 레이어를 만들고, CMD는 컨테이너가 시작될 때 실행할 기본 명령을 지정합니다.', 2, '둘 다 빌드 시점에 실행된다', 'RUN은 빌드 시점, CMD는 컨테이너 시작 시점에 실행된다', 'CMD는 여러 번 써도 모두 실행된다', 'RUN은 컨테이너 시작 시점에 실행된다'),
('로드맵 실전: Docker & CI/CD', 3, 'docker-compose에서 app 서비스가 db 서비스보다 나중에 시작되도록 지정하는 키는 무엇인가요?', 'depends_on은 서비스 시작 순서를 지정합니다. DB가 실제로 준비됐는지까지 보장하려면 healthcheck 조건을 함께 씁니다.', 4, 'ports', 'volumes', 'image', 'depends_on'),
('로드맵 실전: Docker & CI/CD', 4, '컨테이너의 8080 포트를 호스트의 80 포트로 노출하는 옵션은 무엇인가요?', '-p 호스트포트:컨테이너포트 형식이므로 -p 80:8080이 맞습니다.', 1, '-p 80:8080', '-p 8080:80', '-v 80:8080', '-e 80=8080'),
('로드맵 실전: Docker & CI/CD', 5, '이미지 태그로 latest만 사용하는 것의 문제점은 무엇인가요?', 'latest는 계속 덮어써지므로 어떤 버전이 배포됐는지 추적하기 어렵고 롤백도 힘듭니다. 커밋 해시나 버전 태그를 함께 붙이는 것이 좋습니다.', 3, '이미지 크기가 커진다', '빌드가 실패한다', '어떤 버전이 배포됐는지 추적하고 롤백하기 어렵다', '컨테이너가 실행되지 않는다'),
('로드맵 실전: SOLID & 디자인패턴', 1, '한 클래스가 주문 계산, 이메일 발송, 로그 저장을 모두 담당한다면 어떤 원칙을 위반하나요?', '단일 책임 원칙은 클래스가 변경될 이유를 하나만 가져야 한다는 원칙입니다. 세 가지 책임은 서로 다른 이유로 바뀝니다.', 1, '단일 책임 원칙', '리스코프 치환 원칙', '인터페이스 분리 원칙', '의존 역전 원칙'),
('로드맵 실전: SOLID & 디자인패턴', 2, '새 결제 수단을 추가할 때마다 기존 switch 문을 수정해야 한다면 어떤 원칙을 지키지 못한 것인가요?', '개방 폐쇄 원칙은 확장에는 열려 있고 수정에는 닫혀 있어야 한다는 원칙으로, 새 구현체를 추가하는 방식으로 개선할 수 있습니다.', 3, '단일 책임 원칙', '인터페이스 분리 원칙', '개방 폐쇄 원칙', '리스코프 치환 원칙'),
('로드맵 실전: SOLID & 디자인패턴', 3, '정사각형 클래스가 직사각형을 상속했는데 너비만 바꾸면 높이도 함께 바뀌어 기존 코드가 깨진다면 어떤 원칙 위반인가요?', '리스코프 치환 원칙은 하위 타입이 상위 타입의 약속을 깨지 않고 대체될 수 있어야 한다는 원칙입니다.', 2, '개방 폐쇄 원칙', '리스코프 치환 원칙', '단일 책임 원칙', '의존 역전 원칙'),
('로드맵 실전: SOLID & 디자인패턴', 4, '프린터 기능만 필요한 클래스가 스캔, 팩스 메서드까지 있는 큰 인터페이스를 구현해야 한다면 어떤 원칙 위반인가요?', '인터페이스 분리 원칙은 클라이언트가 쓰지 않는 메서드에 의존하지 않도록 인터페이스를 작게 나누라는 원칙입니다.', 4, '단일 책임 원칙', '개방 폐쇄 원칙', '의존 역전 원칙', '인터페이스 분리 원칙'),
('로드맵 실전: SOLID & 디자인패턴', 5, '의존 역전 원칙을 지키는 코드로 가장 적절한 것은 무엇인가요?', '상위 모듈이 구체 클래스가 아닌 추상화(인터페이스)에 의존하고 구현체는 외부에서 주입받아야 합니다.', 2, 'OrderService 안에서 new MySqlOrderRepository()를 직접 생성한다', 'OrderService가 OrderRepository 인터페이스에 의존하고 구현체를 주입받는다', '모든 클래스를 static 메서드로 만든다', '구현 클래스 이름을 문자열로 비교한다'),
('로드맵 실전: 웹 보안 기초', 1, '쿠키에 HttpOnly 속성을 설정하면 어떤 효과가 있나요?', 'HttpOnly 쿠키는 JavaScript의 document.cookie로 읽을 수 없어 XSS로 세션 쿠키를 탈취하는 공격을 줄여 줍니다.', 2, 'HTTPS에서만 전송된다', 'JavaScript에서 쿠키를 읽을 수 없게 된다', '다른 도메인으로도 전송된다', '쿠키 만료 시간이 무한대가 된다'),
('로드맵 실전: 웹 보안 기초', 2, '쿠키의 Secure 속성이 하는 일은 무엇인가요?', 'Secure 속성이 있으면 쿠키는 HTTPS 연결에서만 전송되어 평문 통신 구간에서의 탈취를 막습니다.', 3, '쿠키 값을 자동 암호화한다', '같은 사이트 요청에서만 전송한다', 'HTTPS 연결에서만 쿠키를 전송한다', '쿠키 크기를 줄인다'),
('로드맵 실전: 웹 보안 기초', 3, 'SameSite=Strict 쿠키가 주로 방어하는 공격은 무엇인가요?', 'SameSite 속성은 다른 사이트에서 시작된 요청에 쿠키를 보내지 않게 해 CSRF 공격을 줄입니다.', 1, 'CSRF', 'SQL Injection', 'DDoS', '무차별 대입 공격'),
('로드맵 실전: 웹 보안 기초', 4, 'HTTPS 통신에서 인증서의 역할로 가장 적절한 것은 무엇인가요?', '인증서는 신뢰할 수 있는 기관이 서버의 신원과 공개키를 보증해, 브라우저가 진짜 서버와 통신하는지 확인할 수 있게 합니다.', 4, '서버의 CPU 사용량을 줄인다', '쿠키를 저장한다', '모든 요청을 캐싱한다', '서버의 신원과 공개키를 신뢰 기관이 보증한다'),
('로드맵 실전: 웹 보안 기초', 5, '일반 사용자가 URL의 id만 바꿔 다른 사람의 주문 내역을 볼 수 있다면 OWASP의 어떤 항목에 해당하나요?', '인증된 사용자가 자기 것이 아닌 자원에 접근할 수 있다면 접근 제어 실패(Broken Access Control)에 해당합니다.', 2, '암호화 실패', '접근 제어 실패', '취약한 구성 요소 사용', '로깅 및 모니터링 실패'),
('로드맵 실전: 메시지 큐 & MSA', 1, '주문 서비스가 결제, 알림, 포인트 서비스를 모두 동기로 호출할 때 생길 수 있는 문제는 무엇인가요?', '동기 호출에서는 하위 서비스 하나가 느리거나 죽으면 주문 요청 전체가 느려지거나 실패하는 장애 전파가 일어납니다.', 3, '메시지가 중복 저장된다', '데이터베이스가 필요 없어진다', '한 서비스 장애가 주문 요청 전체로 전파된다', '서비스 간 결합도가 낮아진다'),
('로드맵 실전: 메시지 큐 & MSA', 2, 'Kafka에서 처리량을 늘리기 위해 토픽을 나누는 단위는 무엇인가요?', '토픽은 여러 파티션으로 나뉘고, 파티션 단위로 병렬 처리되므로 파티션 수가 처리량의 상한에 영향을 줍니다.', 1, '파티션', '오프셋', '브로커 이름', '헤더'),
('로드맵 실전: 메시지 큐 & MSA', 3, '같은 컨슈머 그룹에 속한 컨슈머들은 메시지를 어떻게 나눠 받나요?', '한 파티션은 그룹 안에서 하나의 컨슈머에만 할당되므로, 그룹은 파티션을 나눠 맡아 메시지를 한 번씩 처리합니다.', 4, '모든 컨슈머가 모든 메시지를 받는다', '가장 먼저 접속한 컨슈머만 받는다', '메시지를 무작위로 버린다', '파티션을 나눠 맡아 각 메시지를 그룹 안에서 한 번씩 처리한다'),
('로드맵 실전: 메시지 큐 & MSA', 4, 'Kafka에서 메시지 순서가 보장되는 범위는 어디인가요?', 'Kafka는 하나의 파티션 안에서만 순서를 보장합니다. 같은 주문의 이벤트는 같은 키로 보내 같은 파티션에 넣어야 합니다.', 2, '토픽 전체', '하나의 파티션 안', '클러스터 전체', '순서는 전혀 보장되지 않는다'),
('로드맵 실전: 메시지 큐 & MSA', 5, '네트워크 재시도로 같은 메시지가 두 번 처리될 수 있을 때 컨슈머가 갖춰야 할 성질은 무엇인가요?', '같은 메시지를 여러 번 처리해도 결과가 같도록 멱등하게 만들면, 메시지 중복 전달이 일어나도 데이터가 어긋나지 않습니다.', 3, '무상태성', '싱글톤', '멱등성', '비동기성');

INSERT INTO seed_course_assignment (course_title, assignment_title, assignment_description, submission_rule, lesson_title, lesson_description) VALUES
('로드맵 실전: Redis 심화', '선착순 쿠폰 발급 분산 락 구현',
'상황.
오픈 이벤트로 선착순 100명에게 쿠폰을 발급합니다. 서버는 3대이고, 오픈 순간 수천 건의 요청이 동시에 들어옵니다.

요구사항.
1. 락 없이 구현했을 때 100장보다 많이 발급되는 문제를 동시성 테스트로 재현하세요.
2. Redis 분산 락(SETNX 또는 Redisson)으로 중복 발급을 막으세요.
3. 락 획득 대기 시간과 만료 시간을 정하고 근거를 적으세요.
4. 같은 사용자가 두 번 발급받지 못하도록 Set으로 중복 요청을 걸러 내세요.
5. 락 방식과 Redis INCR 원자 연산 방식을 비교해 장단점을 정리하세요.

제출물.
GitHub 저장소 URL과 동시성 테스트 결과를 담은 README.',
'GitHub 저장소 URL을 제출하세요. README에 락 적용 전후 발급 수 비교와 방식별 장단점을 정리하세요.',
'실습 과제: 선착순 쿠폰 발급 분산 락 구현', '동시 요청에서도 정확히 100장만 발급되도록 분산 락을 적용한 결과를 제출합니다.'),
('로드맵 실전: JUnit5 & Mockito', '주문 서비스 단위 테스트 작성',
'상황.
주문 서비스에는 재고 확인, 할인 계산, 결제 요청, 알림 발송 로직이 섞여 있습니다. 리팩터링 전에 핵심 동작을 테스트로 고정해야 합니다.

요구사항.
1. 정상 주문, 재고 부족, 결제 실패 시나리오를 각각 테스트하세요.
2. 결제 클라이언트와 알림 발송기는 Mockito로 대체하세요.
3. 할인 금액 계산은 @ParameterizedTest로 경계값을 검증하세요.
4. 결제 실패 시 알림이 발송되지 않는지 verify로 확인하세요.
5. 모든 테스트를 given-when-then 구조로 작성하고 이름만 보고도 의도를 알 수 있게 하세요.

제출물.
GitHub 저장소 URL과 테스트 실행 결과.',
'GitHub 저장소 URL을 제출하세요. 텍스트 칸에 테스트 목록과 실행 결과 요약을 붙여 넣으세요.',
'실습 과제: 주문 서비스 단위 테스트 작성', '목 객체와 파라미터화 테스트로 주문 서비스 핵심 로직을 보호하는 테스트를 제출합니다.'),
('로드맵 실전: Spring Boot 테스트', '회원 API 계층별 테스트 세트',
'상황.
회원 가입과 조회 API에 테스트가 하나도 없습니다. 계층별로 알맞은 테스트를 작성해 빠르면서도 믿을 수 있는 테스트 세트를 만드세요.

요구사항.
1. @WebMvcTest로 가입 요청 검증 실패(400)와 성공(201)을 테스트하세요.
2. @DataJpaTest로 이메일 조회 쿼리와 중복 확인을 테스트하세요.
3. @SpringBootTest로 가입부터 조회까지 전체 흐름을 테스트하세요.
4. 가능하면 Testcontainers로 실제 PostgreSQL을 사용하세요.
5. JaCoCo 커버리지 결과를 첨부하고, 각 테스트 유형을 선택한 이유를 정리하세요.

제출물.
GitHub 저장소 URL과 테스트 전략 문서.',
'GitHub 저장소 URL을 제출하세요. README에 테스트 유형별 목적과 실행 시간, 커버리지 결과를 포함하세요.',
'실습 과제: 회원 API 계층별 테스트 세트', '슬라이스 테스트와 통합 테스트로 구성된 회원 API 테스트 세트를 제출합니다.'),
('로드맵 실전: Spring Security & JWT', 'JWT 인증과 역할별 권한 제어 API',
'상황.
학습 플랫폼의 API를 만들고 있습니다. 학습자는 강의를 조회하고, 강사는 강의를 등록하며, 관리자는 모든 사용자를 관리합니다.

요구사항.
1. 로그인 시 액세스 토큰과 리프레시 토큰을 발급하세요.
2. 요청 헤더의 토큰을 검증하는 커스텀 필터를 구현하세요.
3. 학습자, 강사, 관리자 역할에 따라 API 접근을 제어하세요.
4. 인증 실패는 401, 권한 부족은 403으로 일관된 JSON 오류를 응답하세요.
5. 리프레시 토큰으로 액세스 토큰을 재발급하는 API를 만들고, 토큰 탈취에 대비한 방안을 적으세요.

제출물.
GitHub 저장소 URL과 인증 흐름도, 역할별 접근 표를 담은 README.',
'GitHub 저장소 URL을 제출하세요. README에 토큰 만료 시간 설정 근거와 역할별 접근 권한 표를 포함하세요.',
'실습 과제: JWT 인증과 역할별 권한 제어 API', '토큰 발급, 검증, 재발급과 역할별 권한 제어를 갖춘 API를 제출합니다.'),
('로드맵 실전: Docker & CI/CD', '푸시부터 배포까지 CI/CD 파이프라인 구축',
'상황.
팀 프로젝트를 매번 수동으로 배포하다 설정 실수로 장애가 났습니다. main 브랜치에 병합하면 자동으로 배포되는 파이프라인이 필요합니다.

요구사항.
1. 애플리케이션 Dockerfile과 로컬 개발용 docker-compose 파일을 작성하세요.
2. PR이 올라오면 테스트가 자동 실행되는 워크플로를 만드세요.
3. main 병합 시 이미지를 빌드해 커밋 해시 태그로 레지스트리에 올리세요.
4. 서버 접속 정보는 저장소 시크릿으로 관리하고 EC2에 새 이미지를 배포하세요.
5. 배포 후 헬스 체크가 실패하면 워크플로가 실패하도록 만드세요.

제출물.
GitHub 저장소 URL과 워크플로 실행 기록, 파이프라인 구조 설명.',
'GitHub 저장소 URL을 제출하세요. 텍스트 칸에 성공한 워크플로 실행 링크와 파이프라인 단계 요약을 적으세요.',
'실습 과제: 푸시부터 배포까지 CI/CD 파이프라인 구축', '테스트, 이미지 빌드, 자동 배포, 헬스 체크를 갖춘 파이프라인을 제출합니다.'),
('로드맵 실전: SOLID & 디자인패턴', '할인 정책 코드 리팩터링',
'상황.
쇼핑몰의 할인 계산 코드가 회원 등급, 쿠폰, 이벤트 조건이 얽힌 300줄짜리 if 문으로 되어 있습니다. 매 분기 새 할인 정책이 추가됩니다.

요구사항.
1. 제공된 레거시 코드(또는 직접 만든 비슷한 코드)에서 원칙 위반 지점을 3곳 이상 찾아 설명하세요.
2. 할인 정책을 Strategy 패턴으로 분리하세요.
3. 정책 객체 생성은 Factory로 모으세요.
4. 새 할인 정책 하나를 추가할 때 기존 코드를 수정하지 않아도 됨을 보여 주세요.
5. 리팩터링 전후 동작이 같음을 테스트로 증명하세요.

제출물.
GitHub 저장소 URL과 리팩터링 전후 비교 문서.',
'GitHub 저장소 URL을 제출하세요. README에 위반 원칙 분석, 적용한 패턴, 전후 클래스 구조를 정리하세요.',
'실습 과제: 할인 정책 코드 리팩터링', 'SOLID 원칙과 Strategy, Factory 패턴으로 할인 로직을 리팩터링해 제출합니다.'),
('로드맵 실전: 웹 보안 기초', '취약한 게시판 보안 점검과 패치',
'상황.
급하게 만든 게시판이 곧 공개됩니다. 공개 전에 기본 보안 점검을 하고 발견한 취약점을 고쳐야 합니다.

요구사항.
1. 게시글 본문에 스크립트를 넣어 XSS가 발생하는지 확인하고 출력 이스케이프로 막으세요.
2. 검색 기능의 문자열 연결 쿼리를 Prepared Statement로 바꾸세요.
3. 글 삭제 요청에 CSRF 방어(토큰 또는 SameSite 쿠키)를 적용하세요.
4. 다른 사용자의 글을 수정할 수 없도록 권한 검사를 추가하세요.
5. 세션 쿠키에 HttpOnly, Secure, SameSite를 설정하고 CORS 허용 출처를 최소화하세요.

제출물.
취약점별 재현 방법, 원인, 패치 내용을 정리한 보안 점검 보고서와 코드 저장소.',
'GitHub 저장소 URL을 제출하고, 보안 점검 보고서를 첨부하거나 텍스트로 붙여 넣으세요.',
'실습 과제: 취약한 게시판 보안 점검과 패치', 'XSS, SQL Injection, CSRF, 접근 제어 취약점을 찾아 패치한 결과를 제출합니다.'),
('로드맵 실전: 메시지 큐 & MSA', '주문-결제 이벤트 기반 구조 설계',
'상황.
모놀리식 쇼핑몰에서 주문과 결제를 별도 서비스로 분리하려 합니다. 결제가 실패하면 주문도 취소되어야 합니다.

요구사항.
1. 주문, 결제, 재고 서비스의 경계와 각 서비스가 소유할 데이터를 정의하세요.
2. 주문 생성부터 결제 완료까지 주고받을 이벤트와 토픽을 설계하세요.
3. 결제 실패 시 주문 취소와 재고 복구가 일어나는 Saga 흐름을 그리세요.
4. 이벤트 중복 수신에 대비한 멱등 처리 방법을 적으세요.
5. 가능하면 Kafka와 두 개의 서비스로 이벤트 발행, 구독을 구현해 보세요.

제출물.
아키텍처 다이어그램과 이벤트 명세가 담긴 설계 문서(구현 저장소는 선택).',
'설계 문서(PDF 또는 마크다운)를 첨부하거나 저장소 URL을 제출하세요. 텍스트 칸에 Saga 흐름을 요약하세요.',
'실습 과제: 주문-결제 이벤트 기반 구조 설계', '서비스 경계, 이벤트 명세, Saga 보상 흐름을 담은 MSA 설계를 제출합니다.');

INSERT INTO seed_course_assignment_rubric (course_title, display_order, criteria_name, criteria_description, max_points) VALUES
('로드맵 실전: Redis 심화', 1, '문제 재현', '락 없이 초과 발급되는 문제를 테스트로 재현했습니다.', 20),
('로드맵 실전: Redis 심화', 2, '분산 락 구현', '락 획득, 해제, 만료 처리가 올바르게 구현되어 있습니다.', 35),
('로드맵 실전: Redis 심화', 3, '중복 요청 처리', '같은 사용자의 중복 발급을 막았습니다.', 20),
('로드맵 실전: Redis 심화', 4, '방식 비교', '락과 원자 연산 방식의 장단점을 근거 있게 비교했습니다.', 25),
('로드맵 실전: JUnit5 & Mockito', 1, '시나리오 커버리지', '정상, 재고 부족, 결제 실패 시나리오를 모두 검증했습니다.', 30),
('로드맵 실전: JUnit5 & Mockito', 2, '목 활용', '외부 의존성을 목으로 대체하고 stub과 verify를 적절히 사용했습니다.', 25),
('로드맵 실전: JUnit5 & Mockito', 3, '경계값 검증', '파라미터화 테스트로 할인 경계값을 검증했습니다.', 20),
('로드맵 실전: JUnit5 & Mockito', 4, '가독성', '테스트 이름과 구조만으로 의도가 드러납니다.', 25),
('로드맵 실전: Spring Boot 테스트', 1, '웹 계층 테스트', 'MockMvc로 요청 검증과 상태 코드를 테스트했습니다.', 25),
('로드맵 실전: Spring Boot 테스트', 2, '리포지토리 테스트', '@DataJpaTest로 쿼리 결과를 검증했습니다.', 20),
('로드맵 실전: Spring Boot 테스트', 3, '통합 테스트', '전체 흐름을 통합 테스트로 검증했습니다.', 30),
('로드맵 실전: Spring Boot 테스트', 4, '테스트 전략', '테스트 유형 선택 근거와 커버리지를 정리했습니다.', 25),
('로드맵 실전: Spring Security & JWT', 1, '토큰 발급과 검증', '액세스, 리프레시 토큰 발급과 필터 검증이 동작합니다.', 35),
('로드맵 실전: Spring Security & JWT', 2, '권한 제어', '역할별 접근 규칙이 올바르게 적용되어 있습니다.', 25),
('로드맵 실전: Spring Security & JWT', 3, '오류 응답', '401과 403이 구분되어 일관된 형식으로 응답합니다.', 20),
('로드맵 실전: Spring Security & JWT', 4, '보안 고려', '토큰 만료와 탈취 대비 방안을 근거 있게 설명했습니다.', 20),
('로드맵 실전: Docker & CI/CD', 1, '컨테이너 구성', 'Dockerfile과 compose 파일이 재현 가능하게 작성되어 있습니다.', 20),
('로드맵 실전: Docker & CI/CD', 2, 'CI 자동화', 'PR마다 테스트가 자동 실행됩니다.', 25),
('로드맵 실전: Docker & CI/CD', 3, 'CD 자동화', '병합 시 이미지 빌드와 배포가 자동으로 이어집니다.', 35),
('로드맵 실전: Docker & CI/CD', 4, '안전성', '시크릿 관리와 헬스 체크로 배포 실패를 감지합니다.', 20),
('로드맵 실전: SOLID & 디자인패턴', 1, '문제 분석', '원칙 위반 지점을 정확히 찾아 설명했습니다.', 25),
('로드맵 실전: SOLID & 디자인패턴', 2, '패턴 적용', 'Strategy와 Factory가 목적에 맞게 적용되어 있습니다.', 30),
('로드맵 실전: SOLID & 디자인패턴', 3, '확장성', '새 정책 추가 시 기존 코드를 수정하지 않습니다.', 25),
('로드맵 실전: SOLID & 디자인패턴', 4, '동작 보존', '리팩터링 전후 동작이 같음을 테스트로 증명했습니다.', 20),
('로드맵 실전: 웹 보안 기초', 1, '취약점 재현', '각 취약점을 재현하고 원인을 설명했습니다.', 25),
('로드맵 실전: 웹 보안 기초', 2, 'XSS와 SQL Injection 방어', '출력 이스케이프와 Prepared Statement를 올바르게 적용했습니다.', 30),
('로드맵 실전: 웹 보안 기초', 3, 'CSRF와 접근 제어', 'CSRF 방어와 작성자 권한 검사를 적용했습니다.', 25),
('로드맵 실전: 웹 보안 기초', 4, '보안 설정', '쿠키 속성과 CORS 설정을 최소 권한으로 구성했습니다.', 20),
('로드맵 실전: 메시지 큐 & MSA', 1, '서비스 경계', '서비스 경계와 데이터 소유가 명확합니다.', 25),
('로드맵 실전: 메시지 큐 & MSA', 2, '이벤트 설계', '이벤트와 토픽, 메시지 키가 흐름에 맞게 설계되어 있습니다.', 25),
('로드맵 실전: 메시지 큐 & MSA', 3, 'Saga 흐름', '실패 시 보상 트랜잭션 흐름이 빠짐없이 정의되어 있습니다.', 30),
('로드맵 실전: 메시지 큐 & MSA', 4, '멱등 처리', '중복 이벤트에 대한 처리 방법이 구체적입니다.', 20);

INSERT INTO seed_course_content (course_title, subtitle, description) VALUES
('SOLID 원칙과 디자인 패턴 실전', '레거시 코드를 직접 고치며 원칙과 패턴을 언제, 왜 써야 하는지 체득합니다',
'SOLID 원칙과 디자인 패턴을 이론으로 외우는 것과 실제 코드에 적용하는 것은 전혀 다른 일입니다. 패턴을 과하게 쓰면 오히려 코드가 복잡해지고, 원칙을 기계적으로 지키면 클래스만 늘어납니다.

첫 섹션에서는 실무에서 자주 보이는 냄새나는 코드, 즉 거대한 서비스 클래스, 타입별 분기, 구체 클래스에 묶인 의존성을 찾아내고 어떤 원칙이 깨졌는지 진단하는 연습을 합니다.

두 번째 섹션에서는 진단 결과에 따라 Strategy, Template Method, Decorator, Observer 패턴을 골라 단계적으로 리팩터링합니다. 테스트로 동작을 고정한 상태에서 조금씩 구조를 바꾸는 안전한 리팩터링 절차도 함께 익힙니다. 마지막 과제로 알림 발송 모듈을 확장 가능한 구조로 바꿉니다.'),
('OAuth2와 소셜 로그인 연동', 'Google, Kakao, Naver 로그인을 Spring Security OAuth2 Client로 연동하고 서비스 회원과 연결합니다',
'소셜 로그인은 사용자에게는 버튼 하나지만, 개발자에게는 인가 코드, 액세스 토큰, 사용자 정보 조회, 회원 연결까지 여러 단계가 숨어 있습니다. 흐름을 이해하지 못한 채 설정만 복사하면 redirect_uri 불일치 같은 오류에서 오래 헤매게 됩니다.

첫 섹션에서는 OAuth2의 역할(리소스 소유자, 클라이언트, 인가 서버, 리소스 서버)과 Authorization Code 흐름, state 파라미터와 PKCE가 막아 주는 공격을 정리합니다.

두 번째 섹션에서는 Spring Security OAuth2 Client로 Google, Kakao, Naver를 연동하고, 제공자마다 다른 사용자 정보 응답을 하나의 형식으로 맞춘 뒤 서비스 회원과 연결하고 JWT를 발급하는 흐름을 구현합니다. 마지막 과제로 소셜 로그인 2종을 연동한 로그인 기능을 완성합니다.'),
('Spring Security 필터 체인과 JWT 인증', '필터 체인을 한 단계씩 따라가며 JWT 인증 필터를 직접 설계하고 디버깅합니다',
'Spring Security 오류의 대부분은 요청이 어떤 필터를 어떤 순서로 지나가는지 모르는 데서 생깁니다. 토큰을 넣었는데도 401이 나거나, 허용한 경로인데도 막힌다면 필터 체인을 직접 들여다볼 차례입니다.

첫 섹션에서는 DelegatingFilterProxy와 FilterChainProxy, SecurityFilterChain의 관계, 주요 보안 필터의 순서와 역할, 디버그 로그로 요청 경로를 추적하는 방법을 정리합니다.

두 번째 섹션에서는 OncePerRequestFilter로 JWT 인증 필터를 구현하고 필터 체인 안의 위치를 정한 뒤, 토큰 만료와 서명 오류, 인증 실패와 권한 부족을 구분해 응답하는 방법을 다룹니다. 마지막 과제로 JWT 인증 필터와 예외 처리를 갖춘 보안 설정을 완성합니다.'),
('MockMvc와 Spring Boot 통합 테스트', 'MockMvc로 API의 요청과 응답 계약을 검증하고 통합 테스트로 실제 흐름을 지킵니다',
'API는 프론트엔드와의 약속입니다. 응답 필드 이름이 하나 바뀌거나 상태 코드가 달라지면 화면이 깨지는데, 이런 변화는 단위 테스트로는 잘 잡히지 않습니다.

첫 섹션에서는 MockMvc로 요청을 만들고 JSON 응답을 jsonPath로 검증하는 방법, 검증 실패와 예외 응답 형식, 인증이 필요한 API를 @WithMockUser로 테스트하는 방법을 다룹니다.

두 번째 섹션에서는 @SpringBootTest로 컨트롤러부터 데이터베이스까지 실제 흐름을 검증하고, 테스트 데이터 준비와 정리 전략, 외부 API 호출을 대체하는 방법, 느린 테스트를 줄이는 컨텍스트 캐싱을 다룹니다. 마지막 과제로 게시판 API의 계약 테스트와 통합 테스트를 작성합니다.'),
('JUnit5와 Mockito 단위 테스트', '테스트 더블의 종류와 Mockito 고급 기능까지, 협력 객체가 많은 코드를 테스트하는 방법을 익힙니다',
'외부 API, 메일 발송, 결제처럼 협력 객체가 많은 서비스 코드는 테스트를 작성하기 어렵습니다. 테스트 더블을 제대로 쓰면 이런 코드도 빠르고 안정적으로 검증할 수 있습니다.

첫 섹션에서는 Dummy, Stub, Spy, Mock, Fake의 차이와 용도, JUnit5의 중첩 테스트와 테스트 이름 표기, AssertJ로 읽기 쉬운 단언을 작성하는 방법을 정리합니다.

두 번째 섹션에서는 ArgumentCaptor로 전달된 인자를 검증하고, 예외를 던지는 stub, 호출 순서 검증, Spy의 주의점을 다룹니다. 테스트하기 어려운 코드를 테스트하기 쉬운 구조로 바꾸는 방법도 함께 살펴봅니다. 마지막 과제로 회원 가입 서비스를 테스트 더블로 검증합니다.'),
('FetchType, N+1, QueryDSL 최적화', '쿼리 로그를 읽고 N+1과 느린 조회를 찾아내 QueryDSL과 페치 전략으로 최적화합니다',
'JPA 성능 문제는 코드만 봐서는 잘 보이지 않습니다. 실제로 몇 개의 쿼리가 나가는지, 어떤 쿼리가 느린지 로그로 확인하는 습관이 최적화의 출발점입니다.

첫 섹션에서는 쿼리 로그와 실행 시간 측정 도구를 설정하고, 즉시 로딩이 위험한 이유, 지연 로딩 프록시의 동작, N+1이 발생하는 여러 패턴(목록 조회, 직렬화, 반복문 접근)을 재현합니다.

두 번째 섹션에서는 fetch join과 페이징의 충돌, 배치 사이즈, DTO 직접 조회, QueryDSL 프로젝션과 동적 조건, 카운트 쿼리 분리 같은 최적화 기법을 상황별로 비교합니다. 마지막 과제로 느린 목록 API를 측정하고 개선합니다.'),
('JPA Entity 매핑과 JPQL 실전', '도메인을 Entity로 옮기는 매핑 전략과 JPQL 작성법을 실전 예제로 익힙니다',
'좋은 Entity 설계는 테이블 구조를 그대로 옮기는 것이 아니라 도메인 규칙을 객체에 담는 일입니다. 매핑을 잘못하면 불필요한 쿼리와 예상치 못한 변경이 따라옵니다.

첫 섹션에서는 기본키 생성 전략, 값 타입(@Embeddable), Enum 매핑, 일대다와 다대일, 다대다를 중간 엔티티로 푸는 방법, cascade와 orphanRemoval의 사용 기준을 정리합니다.

두 번째 섹션에서는 JPQL의 기본 문법과 파라미터 바인딩, 조인과 페치 조인의 차이, 벌크 연산과 영속성 컨텍스트 불일치 문제, 네이티브 쿼리를 써야 하는 경우를 다룹니다. 마지막 과제로 수강 신청 도메인을 Entity로 설계하고 핵심 조회를 JPQL로 작성합니다.'),
('Spring MVC 요청 처리와 3계층 구조', 'DispatcherServlet 내부 흐름을 따라가며 책임이 분명한 3계층 API를 설계합니다',
'컨트롤러에 비즈니스 로직이 쌓이고, 서비스가 HTTP 요청 객체를 직접 다루기 시작하면 코드는 금세 테스트하기 어렵고 고치기 힘들어집니다. 요청이 어떻게 처리되는지 알면 각 계층에 무엇을 둬야 할지도 분명해집니다.

첫 섹션에서는 DispatcherServlet, HandlerMapping, HandlerAdapter, ArgumentResolver, HttpMessageConverter가 요청을 처리하는 순서와, 인터셉터와 필터의 차이를 정리합니다.

두 번째 섹션에서는 Controller, Service, Repository의 책임과 DTO 변환 위치, 트랜잭션 경계, 예외를 계층별로 다루는 방법을 정하고 실제 API에 적용합니다. 마지막 과제로 책임이 섞인 레거시 컨트롤러를 3계층 구조로 분리합니다.'),
('Spring Boot DI/IoC와 Spring Bean 등록 흐름', '애플리케이션이 시작될 때 빈이 만들어지고 연결되는 과정을 처음부터 끝까지 따라갑니다',
'Spring Boot 애플리케이션을 실행하면 수백 개의 빈이 만들어지고 서로 연결됩니다. 이 과정을 이해하면 빈 주입 실패, 순환 참조, 설정이 적용되지 않는 문제를 빠르게 해결할 수 있습니다.

첫 섹션에서는 의존성 주입 방식 세 가지와 생성자 주입의 장점, 컴포넌트 스캔 범위, @Configuration과 @Bean의 프록시 동작, 같은 타입 빈 충돌을 해결하는 방법을 정리합니다.

두 번째 섹션에서는 빈 생명주기와 초기화, 소멸 콜백, 빈 스코프, 조건부 빈 등록과 자동 설정이 동작하는 원리, 프로파일별 설정 분리를 다룹니다. 마지막 과제로 결제 수단을 프로파일과 조건에 따라 바꿔 끼우는 구조를 만듭니다.');

INSERT INTO seed_course_info (course_title, section_key, item_order, item_text) VALUES
('SOLID 원칙과 디자인 패턴 실전', 'TARGET_AUDIENCE', 0, '원칙과 패턴 이름은 알지만 실제 코드에 적용해 본 경험이 부족한 개발자'),
('SOLID 원칙과 디자인 패턴 실전', 'TARGET_AUDIENCE', 1, '레거시 코드를 안전하게 리팩터링하는 절차를 배우고 싶은 분'),
('SOLID 원칙과 디자인 패턴 실전', 'TARGET_AUDIENCE', 2, '패턴을 과하게 적용해 코드가 더 복잡해진 경험이 있는 분'),
('SOLID 원칙과 디자인 패턴 실전', 'PREREQUISITES', 0, 'Java 인터페이스와 다형성을 이해하고 있어야 합니다.'),
('SOLID 원칙과 디자인 패턴 실전', 'PREREQUISITES', 1, 'JUnit으로 간단한 테스트를 작성할 수 있으면 리팩터링 실습이 수월합니다.'),
('SOLID 원칙과 디자인 패턴 실전', 'OBJECTIVES', 0, '코드 냄새를 보고 어떤 설계 원칙이 깨졌는지 진단할 수 있습니다.'),
('SOLID 원칙과 디자인 패턴 실전', 'OBJECTIVES', 1, '상황에 맞는 패턴을 고르고 과도한 적용을 피할 수 있습니다.'),
('SOLID 원칙과 디자인 패턴 실전', 'OBJECTIVES', 2, 'Template Method, Decorator, Observer 패턴을 실무 코드에 적용할 수 있습니다.'),
('SOLID 원칙과 디자인 패턴 실전', 'OBJECTIVES', 3, '테스트로 동작을 고정한 뒤 단계적으로 리팩터링할 수 있습니다.'),
('OAuth2와 소셜 로그인 연동', 'TARGET_AUDIENCE', 0, '서비스에 Google, Kakao, Naver 로그인을 붙여야 하는 백엔드 개발자'),
('OAuth2와 소셜 로그인 연동', 'TARGET_AUDIENCE', 1, 'OAuth2 흐름을 그림으로 설명하기 어려운 분'),
('OAuth2와 소셜 로그인 연동', 'TARGET_AUDIENCE', 2, '소셜 로그인과 자체 JWT 인증을 함께 쓰는 구조가 궁금한 분'),
('OAuth2와 소셜 로그인 연동', 'PREREQUISITES', 0, 'Spring Security 기본 설정과 필터 체인 개념을 알고 있어야 합니다.'),
('OAuth2와 소셜 로그인 연동', 'PREREQUISITES', 1, '각 소셜 제공자의 개발자 콘솔에서 앱을 등록할 수 있는 계정이 필요합니다.'),
('OAuth2와 소셜 로그인 연동', 'OBJECTIVES', 0, 'Authorization Code 흐름과 각 역할을 순서대로 설명할 수 있습니다.'),
('OAuth2와 소셜 로그인 연동', 'OBJECTIVES', 1, 'state와 PKCE가 막아 주는 공격을 이해하고 설정할 수 있습니다.'),
('OAuth2와 소셜 로그인 연동', 'OBJECTIVES', 2, '제공자별 사용자 정보를 공통 형식으로 변환해 회원과 연결할 수 있습니다.'),
('OAuth2와 소셜 로그인 연동', 'OBJECTIVES', 3, '소셜 로그인 성공 후 서비스 JWT를 발급하는 흐름을 구현할 수 있습니다.'),
('Spring Security 필터 체인과 JWT 인증', 'TARGET_AUDIENCE', 0, 'Spring Security 설정은 했지만 401, 403 원인을 찾느라 시간을 쓰는 개발자'),
('Spring Security 필터 체인과 JWT 인증', 'TARGET_AUDIENCE', 1, 'JWT 인증 필터를 직접 설계해 보고 싶은 분'),
('Spring Security 필터 체인과 JWT 인증', 'TARGET_AUDIENCE', 2, '보안 설정을 디버깅하는 방법을 익히고 싶은 분'),
('Spring Security 필터 체인과 JWT 인증', 'PREREQUISITES', 0, 'Spring Boot와 서블릿 필터의 기본 개념을 알고 있어야 합니다.'),
('Spring Security 필터 체인과 JWT 인증', 'PREREQUISITES', 1, 'JWT의 구조(헤더, 페이로드, 서명)를 들어 본 적이 있으면 좋습니다.'),
('Spring Security 필터 체인과 JWT 인증', 'OBJECTIVES', 0, 'FilterChainProxy와 SecurityFilterChain의 관계를 설명할 수 있습니다.'),
('Spring Security 필터 체인과 JWT 인증', 'OBJECTIVES', 1, '디버그 로그로 요청이 거치는 보안 필터를 추적할 수 있습니다.'),
('Spring Security 필터 체인과 JWT 인증', 'OBJECTIVES', 2, 'OncePerRequestFilter로 JWT 인증 필터를 구현하고 위치를 정할 수 있습니다.'),
('Spring Security 필터 체인과 JWT 인증', 'OBJECTIVES', 3, '토큰 오류와 권한 부족을 구분해 일관된 응답을 보낼 수 있습니다.'),
('MockMvc와 Spring Boot 통합 테스트', 'TARGET_AUDIENCE', 0, 'API 응답이 바뀌어 프론트엔드가 깨진 경험이 있는 백엔드 개발자'),
('MockMvc와 Spring Boot 통합 테스트', 'TARGET_AUDIENCE', 1, '인증이 필요한 API를 어떻게 테스트할지 막막한 분'),
('MockMvc와 Spring Boot 통합 테스트', 'TARGET_AUDIENCE', 2, '통합 테스트가 느려서 고민인 분'),
('MockMvc와 Spring Boot 통합 테스트', 'PREREQUISITES', 0, 'JUnit5로 단위 테스트를 작성해 본 경험이 있어야 합니다.'),
('MockMvc와 Spring Boot 통합 테스트', 'PREREQUISITES', 1, 'Spring MVC로 REST API를 만들어 본 경험이 필요합니다.'),
('MockMvc와 Spring Boot 통합 테스트', 'OBJECTIVES', 0, 'MockMvc와 jsonPath로 응답 구조와 값을 검증할 수 있습니다.'),
('MockMvc와 Spring Boot 통합 테스트', 'OBJECTIVES', 1, '@WithMockUser 등으로 인증이 필요한 API를 테스트할 수 있습니다.'),
('MockMvc와 Spring Boot 통합 테스트', 'OBJECTIVES', 2, '@SpringBootTest로 실제 흐름을 검증하고 테스트 데이터를 관리할 수 있습니다.'),
('MockMvc와 Spring Boot 통합 테스트', 'OBJECTIVES', 3, '컨텍스트 캐싱을 이해하고 통합 테스트 실행 시간을 줄일 수 있습니다.'),
('JUnit5와 Mockito 단위 테스트', 'TARGET_AUDIENCE', 0, '외부 연동이 많은 서비스 코드를 테스트하기 어려운 개발자'),
('JUnit5와 Mockito 단위 테스트', 'TARGET_AUDIENCE', 1, 'Mock과 Stub, Spy의 차이를 정확히 알고 싶은 분'),
('JUnit5와 Mockito 단위 테스트', 'TARGET_AUDIENCE', 2, '테스트하기 쉬운 코드 구조를 고민하는 분'),
('JUnit5와 Mockito 단위 테스트', 'PREREQUISITES', 0, 'JUnit 테스트를 실행해 본 경험이 있으면 좋습니다.'),
('JUnit5와 Mockito 단위 테스트', 'PREREQUISITES', 1, 'Java 인터페이스와 의존성 주입을 이해하고 있어야 합니다.'),
('JUnit5와 Mockito 단위 테스트', 'OBJECTIVES', 0, '테스트 더블 다섯 종류의 차이와 용도를 설명할 수 있습니다.'),
('JUnit5와 Mockito 단위 테스트', 'OBJECTIVES', 1, 'AssertJ와 중첩 테스트로 읽기 쉬운 테스트를 작성할 수 있습니다.'),
('JUnit5와 Mockito 단위 테스트', 'OBJECTIVES', 2, 'ArgumentCaptor와 호출 순서 검증으로 협력 관계를 테스트할 수 있습니다.'),
('JUnit5와 Mockito 단위 테스트', 'OBJECTIVES', 3, '테스트하기 어려운 코드를 테스트하기 쉬운 구조로 바꿀 수 있습니다.'),
('FetchType, N+1, QueryDSL 최적화', 'TARGET_AUDIENCE', 0, 'JPA 목록 API가 느려 원인을 찾고 있는 백엔드 개발자'),
('FetchType, N+1, QueryDSL 최적화', 'TARGET_AUDIENCE', 1, 'fetch join과 페이징을 함께 쓰다 경고를 본 적이 있는 분'),
('FetchType, N+1, QueryDSL 최적화', 'TARGET_AUDIENCE', 2, 'QueryDSL로 복잡한 조회를 최적화하고 싶은 분'),
('FetchType, N+1, QueryDSL 최적화', 'PREREQUISITES', 0, 'JPA 연관관계 매핑과 영속성 컨텍스트를 이해하고 있어야 합니다.'),
('FetchType, N+1, QueryDSL 최적화', 'PREREQUISITES', 1, 'SQL JOIN과 실행 계획의 기본을 알고 있으면 좋습니다.'),
('FetchType, N+1, QueryDSL 최적화', 'OBJECTIVES', 0, '쿼리 로그와 실행 시간을 측정해 성능 문제를 찾아낼 수 있습니다.'),
('FetchType, N+1, QueryDSL 최적화', 'OBJECTIVES', 1, 'N+1이 발생하는 여러 패턴을 재현하고 설명할 수 있습니다.'),
('FetchType, N+1, QueryDSL 최적화', 'OBJECTIVES', 2, 'fetch join, 배치 사이즈, DTO 조회를 상황에 맞게 선택할 수 있습니다.'),
('FetchType, N+1, QueryDSL 최적화', 'OBJECTIVES', 3, 'QueryDSL 프로젝션과 카운트 쿼리 분리로 페이징 조회를 최적화할 수 있습니다.'),
('JPA Entity 매핑과 JPQL 실전', 'TARGET_AUDIENCE', 0, '테이블 구조를 그대로 Entity로 옮겨 온 JPA 입문자'),
('JPA Entity 매핑과 JPQL 실전', 'TARGET_AUDIENCE', 1, 'cascade와 orphanRemoval을 언제 써야 할지 헷갈리는 분'),
('JPA Entity 매핑과 JPQL 실전', 'TARGET_AUDIENCE', 2, 'JPQL과 네이티브 쿼리의 사용 기준을 정하고 싶은 분'),
('JPA Entity 매핑과 JPQL 실전', 'PREREQUISITES', 0, 'Spring Boot와 SQL 기본 문법을 알고 있어야 합니다.'),
('JPA Entity 매핑과 JPQL 실전', 'PREREQUISITES', 1, '간단한 JPA CRUD를 만들어 본 경험이 있으면 좋습니다.'),
('JPA Entity 매핑과 JPQL 실전', 'OBJECTIVES', 0, '기본키 전략과 값 타입, Enum 매핑을 목적에 맞게 선택할 수 있습니다.'),
('JPA Entity 매핑과 JPQL 실전', 'OBJECTIVES', 1, '다대다 관계를 중간 엔티티로 풀어 설계할 수 있습니다.'),
('JPA Entity 매핑과 JPQL 실전', 'OBJECTIVES', 2, 'cascade와 orphanRemoval을 안전하게 사용할 수 있습니다.'),
('JPA Entity 매핑과 JPQL 실전', 'OBJECTIVES', 3, 'JPQL 조인, 페치 조인, 벌크 연산을 올바르게 작성할 수 있습니다.'),
('Spring MVC 요청 처리와 3계층 구조', 'TARGET_AUDIENCE', 0, '컨트롤러가 점점 비대해져 고민인 백엔드 개발자'),
('Spring MVC 요청 처리와 3계층 구조', 'TARGET_AUDIENCE', 1, '필터와 인터셉터, ArgumentResolver의 차이를 알고 싶은 분'),
('Spring MVC 요청 처리와 3계층 구조', 'TARGET_AUDIENCE', 2, 'DTO 변환과 트랜잭션 경계를 어디에 둘지 기준이 필요한 분'),
('Spring MVC 요청 처리와 3계층 구조', 'PREREQUISITES', 0, 'Spring Boot로 간단한 API를 만들어 본 경험이 있어야 합니다.'),
('Spring MVC 요청 처리와 3계층 구조', 'PREREQUISITES', 1, 'HTTP 요청 구조와 JSON 형식을 알고 있으면 좋습니다.'),
('Spring MVC 요청 처리와 3계층 구조', 'OBJECTIVES', 0, 'DispatcherServlet 내부의 요청 처리 순서를 설명할 수 있습니다.'),
('Spring MVC 요청 처리와 3계층 구조', 'OBJECTIVES', 1, '필터와 인터셉터를 용도에 맞게 선택할 수 있습니다.'),
('Spring MVC 요청 처리와 3계층 구조', 'OBJECTIVES', 2, '계층별 책임과 DTO 변환, 트랜잭션 경계를 정할 수 있습니다.'),
('Spring MVC 요청 처리와 3계층 구조', 'OBJECTIVES', 3, '책임이 섞인 코드를 3계층 구조로 분리할 수 있습니다.'),
('Spring Boot DI/IoC와 Spring Bean 등록 흐름', 'TARGET_AUDIENCE', 0, '빈 주입 오류나 순환 참조를 만나면 원인을 찾기 어려운 개발자'),
('Spring Boot DI/IoC와 Spring Bean 등록 흐름', 'TARGET_AUDIENCE', 1, 'Spring Boot 자동 설정이 어떻게 동작하는지 궁금한 분'),
('Spring Boot DI/IoC와 Spring Bean 등록 흐름', 'TARGET_AUDIENCE', 2, '환경별로 다른 빈을 쓰는 구조를 설계하고 싶은 분'),
('Spring Boot DI/IoC와 Spring Bean 등록 흐름', 'PREREQUISITES', 0, 'Java 인터페이스와 Spring Boot 기본 구조를 알고 있어야 합니다.'),
('Spring Boot DI/IoC와 Spring Bean 등록 흐름', 'PREREQUISITES', 1, '어노테이션 기반 설정을 사용해 본 경험이 있으면 좋습니다.'),
('Spring Boot DI/IoC와 Spring Bean 등록 흐름', 'OBJECTIVES', 0, '주입 방식별 차이를 이해하고 생성자 주입을 적용할 수 있습니다.'),
('Spring Boot DI/IoC와 Spring Bean 등록 흐름', 'OBJECTIVES', 1, '@Configuration의 프록시 동작과 빈 충돌 해결 방법을 설명할 수 있습니다.'),
('Spring Boot DI/IoC와 Spring Bean 등록 흐름', 'OBJECTIVES', 2, '빈 생명주기 콜백과 스코프를 상황에 맞게 사용할 수 있습니다.'),
('Spring Boot DI/IoC와 Spring Bean 등록 흐름', 'OBJECTIVES', 3, '조건부 빈 등록과 프로파일로 환경별 구성을 분리할 수 있습니다.');

INSERT INTO seed_course_curriculum (course_title, section_order, section_title, section_description, lesson_order, lesson_title, lesson_description) VALUES
('SOLID 원칙과 디자인 패턴 실전', 1, '코드 냄새 진단하기', '레거시 코드에서 원칙 위반을 찾아내는 연습을 합니다.', 1, '거대한 서비스 클래스와 타입별 분기', '여러 책임이 섞인 서비스와 instanceof, switch 분기가 늘어나는 코드를 보고 어떤 원칙이 깨졌는지 진단합니다.'),
('SOLID 원칙과 디자인 패턴 실전', 1, '코드 냄새 진단하기', '레거시 코드에서 원칙 위반을 찾아내는 연습을 합니다.', 2, '구체 클래스 의존과 테스트하기 어려운 코드', 'new로 직접 만든 의존성과 static 호출 때문에 테스트가 어려운 코드를 의존 역전으로 풀어냅니다.'),
('SOLID 원칙과 디자인 패턴 실전', 2, '패턴으로 리팩터링하기', '진단 결과에 맞는 패턴으로 단계적으로 리팩터링합니다.', 1, 'Strategy와 Template Method로 분기 제거하기', '동작이 달라지는 부분은 전략으로, 흐름이 같은 부분은 템플릿으로 고정해 분기를 없앱니다.'),
('SOLID 원칙과 디자인 패턴 실전', 2, '패턴으로 리팩터링하기', '진단 결과에 맞는 패턴으로 단계적으로 리팩터링합니다.', 2, 'Decorator와 Observer, 안전한 리팩터링 절차', '기능을 덧붙이는 데코레이터와 이벤트로 결합을 끊는 옵저버를 적용하고, 테스트로 동작을 지키며 바꾸는 절차를 익힙니다.'),
('OAuth2와 소셜 로그인 연동', 1, 'OAuth2 흐름 이해하기', '역할과 인가 코드 흐름, 보안 파라미터를 정리합니다.', 1, 'OAuth2의 네 가지 역할과 Authorization Code 흐름', '사용자, 클라이언트, 인가 서버, 리소스 서버가 인가 코드와 토큰을 주고받는 과정을 순서대로 따라갑니다.'),
('OAuth2와 소셜 로그인 연동', 1, 'OAuth2 흐름 이해하기', '역할과 인가 코드 흐름, 보안 파라미터를 정리합니다.', 2, 'state, PKCE, redirect_uri 검증', 'CSRF와 인가 코드 탈취를 막는 state와 PKCE, redirect_uri 불일치 오류의 원인을 정리합니다.'),
('OAuth2와 소셜 로그인 연동', 2, '소셜 로그인 구현하기', 'Spring Security OAuth2 Client로 제공자를 연동합니다.', 1, 'Google, Kakao, Naver 클라이언트 등록과 설정', '제공자별 앱 등록과 application.yml 설정, 국내 제공자를 위한 provider 설정을 직접 작성합니다.'),
('OAuth2와 소셜 로그인 연동', 2, '소셜 로그인 구현하기', 'Spring Security OAuth2 Client로 제공자를 연동합니다.', 2, '사용자 정보 통합과 회원 연결, JWT 발급', 'OAuth2UserService에서 제공자별 응답을 공통 형식으로 바꾸고 회원과 연결한 뒤 성공 핸들러에서 JWT를 발급합니다.'),
('Spring Security 필터 체인과 JWT 인증', 1, '필터 체인 해부하기', '보안 필터의 구조와 순서를 추적합니다.', 1, 'DelegatingFilterProxy와 FilterChainProxy', '서블릿 컨테이너와 스프링 빈 사이를 잇는 필터 위임 구조와 여러 SecurityFilterChain이 선택되는 방식을 다룹니다.'),
('Spring Security 필터 체인과 JWT 인증', 1, '필터 체인 해부하기', '보안 필터의 구조와 순서를 추적합니다.', 2, '주요 보안 필터 순서와 디버그 로그', '인증, 예외 변환, 인가 필터의 순서와 역할을 정리하고 디버그 로그로 요청이 막히는 지점을 찾습니다.'),
('Spring Security 필터 체인과 JWT 인증', 2, 'JWT 인증 필터 설계', 'JWT 필터를 직접 구현하고 예외를 처리합니다.', 1, 'OncePerRequestFilter로 JWT 필터 구현', '헤더에서 토큰을 꺼내 검증하고 Authentication을 만들어 SecurityContext에 저장하는 필터를 작성합니다.'),
('Spring Security 필터 체인과 JWT 인증', 2, 'JWT 인증 필터 설계', 'JWT 필터를 직접 구현하고 예외를 처리합니다.', 2, '토큰 오류와 인증, 인가 예외 응답', '만료, 서명 오류, 형식 오류를 구분하고 EntryPoint와 AccessDeniedHandler로 일관된 JSON 응답을 만듭니다.'),
('MockMvc와 Spring Boot 통합 테스트', 1, 'MockMvc로 API 계약 검증', '요청과 응답 구조, 인증이 필요한 API를 테스트합니다.', 1, 'MockMvc 요청 구성과 jsonPath 검증', '경로 변수, 쿼리 파라미터, JSON 바디를 담은 요청을 만들고 jsonPath로 응답 필드를 검증합니다.'),
('MockMvc와 Spring Boot 통합 테스트', 1, 'MockMvc로 API 계약 검증', '요청과 응답 구조, 인증이 필요한 API를 테스트합니다.', 2, '검증 실패, 예외 응답, 인증 API 테스트', '400과 404 응답 형식을 검증하고 @WithMockUser로 역할별 접근을 테스트합니다.'),
('MockMvc와 Spring Boot 통합 테스트', 2, '통합 테스트 운영하기', '실제 흐름 검증과 테스트 속도 관리를 다룹니다.', 1, '@SpringBootTest로 전체 흐름 검증', '컨트롤러부터 데이터베이스까지 실제 빈으로 흐름을 검증하고 외부 API는 목 서버로 대체합니다.'),
('MockMvc와 Spring Boot 통합 테스트', 2, '통합 테스트 운영하기', '실제 흐름 검증과 테스트 속도 관리를 다룹니다.', 2, '테스트 데이터 관리와 컨텍스트 캐싱', '테스트 간 데이터 격리 전략과, 설정 차이로 컨텍스트가 매번 새로 뜨는 문제를 줄이는 방법을 다룹니다.'),
('JUnit5와 Mockito 단위 테스트', 1, '테스트 더블과 읽기 쉬운 테스트', '테스트 더블 종류와 단언 작성법을 정리합니다.', 1, 'Dummy, Stub, Spy, Mock, Fake 구분하기', '같은 협력 객체를 다섯 가지 테스트 더블로 대체해 보며 각각을 언제 쓰는지 비교합니다.'),
('JUnit5와 Mockito 단위 테스트', 1, '테스트 더블과 읽기 쉬운 테스트', '테스트 더블 종류와 단언 작성법을 정리합니다.', 2, '@Nested, @DisplayName, AssertJ', '중첩 테스트로 상황별 테스트를 묶고 AssertJ의 체이닝 단언으로 읽기 쉬운 테스트를 작성합니다.'),
('JUnit5와 Mockito 단위 테스트', 2, 'Mockito 고급 활용', '인자 검증, 예외 stub, 테스트하기 쉬운 구조를 다룹니다.', 1, 'ArgumentCaptor와 호출 순서 검증', '협력 객체에 전달된 인자를 캡처해 검증하고, InOrder로 호출 순서를 확인합니다.'),
('JUnit5와 Mockito 단위 테스트', 2, 'Mockito 고급 활용', '인자 검증, 예외 stub, 테스트하기 쉬운 구조를 다룹니다.', 2, '예외 stub, Spy 주의점, 테스트하기 쉬운 설계', 'thenThrow로 실패 상황을 만들고, Spy를 남용하면 생기는 문제와 시간, 난수 같은 의존성을 분리하는 방법을 다룹니다.'),
('FetchType, N+1, QueryDSL 최적화', 1, '성능 문제 찾아내기', '쿼리 로그와 N+1 패턴을 재현합니다.', 1, '쿼리 로그 설정과 실행 시간 측정', 'SQL 로그와 바인딩 파라미터, 쿼리 수와 실행 시간을 확인하는 도구를 설정하고 기준선을 측정합니다.'),
('FetchType, N+1, QueryDSL 최적화', 1, '성능 문제 찾아내기', '쿼리 로그와 N+1 패턴을 재현합니다.', 2, '즉시 로딩의 위험과 N+1 발생 패턴', '즉시 로딩이 JPQL에서 N+1을 만드는 이유, 직렬화와 반복문에서 지연 로딩이 터지는 패턴을 재현합니다.'),
('FetchType, N+1, QueryDSL 최적화', 2, '상황별 최적화 기법', '페치 전략과 QueryDSL로 조회를 최적화합니다.', 1, 'fetch join과 페이징, 배치 사이즈', '컬렉션 fetch join과 페이징이 함께 쓰일 때 메모리 페이징이 일어나는 문제와 배치 사이즈로 푸는 방법을 비교합니다.'),
('FetchType, N+1, QueryDSL 최적화', 2, '상황별 최적화 기법', '페치 전략과 QueryDSL로 조회를 최적화합니다.', 2, 'QueryDSL 프로젝션과 카운트 쿼리 분리', '필요한 컬럼만 DTO로 조회하고, 페이징 카운트 쿼리를 분리해 목록 API를 빠르게 만듭니다.'),
('JPA Entity 매핑과 JPQL 실전', 1, 'Entity 매핑 전략', '키 전략, 값 타입, 연관관계 설계를 다룹니다.', 1, '기본키 전략, 값 타입, Enum 매핑', 'IDENTITY와 SEQUENCE의 차이, @Embeddable로 의미 있는 값 묶기, Enum은 STRING으로 저장해야 하는 이유를 정리합니다.'),
('JPA Entity 매핑과 JPQL 실전', 1, 'Entity 매핑 전략', '키 전략, 값 타입, 연관관계 설계를 다룹니다.', 2, '다대다 풀기와 cascade, orphanRemoval', '@ManyToMany 대신 중간 엔티티를 쓰는 이유와 생명주기를 함께하는 자식에만 cascade를 적용하는 기준을 다룹니다.'),
('JPA Entity 매핑과 JPQL 실전', 2, 'JPQL 실전', 'JPQL 작성법과 주의할 점을 다룹니다.', 1, 'JPQL 기본 문법과 조인, 페치 조인', '파라미터 바인딩, 내부와 외부 조인, 엔티티를 함께 가져오는 페치 조인의 차이를 예제로 정리합니다.'),
('JPA Entity 매핑과 JPQL 실전', 2, 'JPQL 실전', 'JPQL 작성법과 주의할 점을 다룹니다.', 2, '벌크 연산과 네이티브 쿼리', '벌크 UPDATE 후 영속성 컨텍스트와 DB가 어긋나는 문제, 네이티브 쿼리를 써야 하는 경우와 주의점을 다룹니다.'),
('Spring MVC 요청 처리와 3계층 구조', 1, 'MVC 내부 동작', '요청이 컨트롤러에 도달하기까지의 구성 요소를 따라갑니다.', 1, 'DispatcherServlet, HandlerMapping, HandlerAdapter', '요청 URL로 핸들러를 찾고 실행하는 과정과 각 구성 요소의 역할을 순서대로 정리합니다.'),
('Spring MVC 요청 처리와 3계층 구조', 1, 'MVC 내부 동작', '요청이 컨트롤러에 도달하기까지의 구성 요소를 따라갑니다.', 2, 'ArgumentResolver, MessageConverter, 필터와 인터셉터', '파라미터가 객체로 바인딩되고 JSON으로 변환되는 과정, 필터와 인터셉터의 실행 위치 차이를 다룹니다.'),
('Spring MVC 요청 처리와 3계층 구조', 2, '책임이 분명한 계층 설계', '계층별 책임과 경계를 정하고 적용합니다.', 1, '계층별 책임과 DTO 변환 위치', 'Controller는 요청과 응답, Service는 비즈니스 규칙, Repository는 데이터 접근을 맡도록 경계를 정하고 DTO 변환 위치를 결정합니다.'),
('Spring MVC 요청 처리와 3계층 구조', 2, '책임이 분명한 계층 설계', '계층별 책임과 경계를 정하고 적용합니다.', 2, '트랜잭션 경계와 계층별 예외 처리', '트랜잭션을 서비스에 두는 이유와 도메인 예외를 HTTP 응답으로 바꾸는 전역 예외 처리를 정리합니다.'),
('Spring Boot DI/IoC와 Spring Bean 등록 흐름', 1, '빈 등록과 의존성 주입', '주입 방식과 빈 등록 방법, 충돌 해결을 정리합니다.', 1, '주입 방식 세 가지와 컴포넌트 스캔', '생성자, 세터, 필드 주입의 차이와 컴포넌트 스캔 범위가 결정되는 방식을 다룹니다.'),
('Spring Boot DI/IoC와 Spring Bean 등록 흐름', 1, '빈 등록과 의존성 주입', '주입 방식과 빈 등록 방법, 충돌 해결을 정리합니다.', 2, '@Configuration 프록시와 빈 충돌 해결', '@Bean 메서드를 여러 번 호출해도 같은 빈이 반환되는 이유와 @Primary, @Qualifier로 충돌을 해결하는 방법을 다룹니다.'),
('Spring Boot DI/IoC와 Spring Bean 등록 흐름', 2, '빈 생명주기와 자동 설정', '빈 생명주기, 스코프, 조건부 등록을 다룹니다.', 1, '빈 생명주기 콜백과 스코프', '@PostConstruct, @PreDestroy로 초기화와 정리를 처리하고 싱글톤과 프로토타입, 요청 스코프를 비교합니다.'),
('Spring Boot DI/IoC와 Spring Bean 등록 흐름', 2, '빈 생명주기와 자동 설정', '빈 생명주기, 스코프, 조건부 등록을 다룹니다.', 2, '조건부 빈 등록, 자동 설정, 프로파일', '@ConditionalOnProperty 같은 조건부 등록과 자동 설정이 적용되는 원리, 프로파일별 설정 분리를 다룹니다.');

INSERT INTO seed_course_quiz (course_title, quiz_title, quiz_description, lesson_title, lesson_description) VALUES
('SOLID 원칙과 디자인 패턴 실전', '코드 냄새 진단 퀴즈', '레거시 코드에서 원칙 위반과 개선 방향을 찾는 능력을 점검합니다.', '섹션 퀴즈: 코드 냄새 진단하기', '코드 냄새와 알맞은 개선 방법을 연결하는 문제 5문항입니다.'),
('OAuth2와 소셜 로그인 연동', 'OAuth2 흐름 점검 퀴즈', '역할, 인가 코드 흐름, state와 PKCE를 점검합니다.', '섹션 퀴즈: OAuth2 흐름 이해하기', 'OAuth2 인가 코드 흐름과 보안 장치를 5문항으로 점검합니다.'),
('Spring Security 필터 체인과 JWT 인증', '필터 체인 구조 점검 퀴즈', '필터 위임 구조와 보안 필터 순서를 점검합니다.', '섹션 퀴즈: 필터 체인 해부하기', '요청이 보안 필터를 통과하는 과정을 5문항으로 점검합니다.'),
('MockMvc와 Spring Boot 통합 테스트', 'MockMvc 계약 검증 퀴즈', 'MockMvc 요청 구성, jsonPath, 인증 테스트를 점검합니다.', '섹션 퀴즈: MockMvc로 API 계약 검증', 'API 응답을 검증하는 방법을 5문항으로 점검합니다.'),
('JUnit5와 Mockito 단위 테스트', '테스트 더블 점검 퀴즈', '테스트 더블 종류와 JUnit5, AssertJ 활용을 점검합니다.', '섹션 퀴즈: 테스트 더블과 읽기 쉬운 테스트', '상황에 맞는 테스트 더블을 고르는 문제 5문항입니다.'),
('FetchType, N+1, QueryDSL 최적화', 'N+1 진단 퀴즈', '로딩 전략과 N+1 발생 패턴을 점검합니다.', '섹션 퀴즈: 성능 문제 찾아내기', '쿼리 수를 예측하고 원인을 찾는 문제 5문항입니다.'),
('JPA Entity 매핑과 JPQL 실전', 'Entity 매핑 전략 퀴즈', '키 전략, 값 타입, Enum, cascade 사용 기준을 점검합니다.', '섹션 퀴즈: Entity 매핑 전략', '매핑 선택의 근거를 묻는 문제 5문항입니다.'),
('Spring MVC 요청 처리와 3계층 구조', 'MVC 내부 동작 퀴즈', 'DispatcherServlet과 주변 구성 요소의 역할을 점검합니다.', '섹션 퀴즈: MVC 내부 동작', '요청 처리 순서와 구성 요소의 역할을 5문항으로 점검합니다.'),
('Spring Boot DI/IoC와 Spring Bean 등록 흐름', '빈 등록과 주입 퀴즈', '주입 방식, 컴포넌트 스캔, @Configuration 동작을 점검합니다.', '섹션 퀴즈: 빈 등록과 의존성 주입', '빈이 만들어지고 연결되는 방식을 5문항으로 점검합니다.');

INSERT INTO seed_course_quiz_question (course_title, display_order, question_text, explanation, correct_option, option1, option2, option3, option4) VALUES
('SOLID 원칙과 디자인 패턴 실전', 1, '결제 타입마다 if (type == CARD) ... else if (type == KAKAO) ...가 서비스 곳곳에 반복될 때 가장 알맞은 개선 방향은 무엇인가요?', '타입별로 달라지는 동작을 공통 인터페이스의 구현체로 분리하면 분기가 사라지고 새 타입은 구현체 추가만으로 대응할 수 있습니다.', 3, '분기를 하나의 거대한 유틸 클래스로 옮긴다', 'type 값을 정수로 바꾼다', '타입별 동작을 공통 인터페이스 구현체로 분리한다', '주석으로 분기 의미를 설명한다'),
('SOLID 원칙과 디자인 패턴 실전', 2, '서비스가 내부에서 new SmtpMailSender()를 직접 만들어 테스트에서 실제 메일이 발송된다면 무엇이 문제인가요?', '구체 클래스를 직접 생성하면 의존성을 바꿀 수 없어 테스트가 어렵습니다. 인터페이스에 의존하고 주입받도록 바꾸면 테스트 더블로 대체할 수 있습니다.', 1, '구체 클래스에 직접 의존해 대체할 수 없다', '메일 서버가 느리다', '클래스 이름이 길다', '메서드가 public이다'),
('SOLID 원칙과 디자인 패턴 실전', 3, '여러 보고서 생성기가 데이터 조회, 가공, 출력의 순서는 같고 가공 방식만 다를 때 알맞은 패턴은 무엇인가요?', 'Template Method는 상위 클래스가 처리 순서를 고정하고 달라지는 단계만 하위 클래스가 구현하게 합니다.', 2, 'Singleton', 'Template Method', 'Builder', 'Adapter'),
('SOLID 원칙과 디자인 패턴 실전', 4, '기존 알림 발송 기능을 수정하지 않고 로깅과 재시도 기능을 덧붙이려 할 때 알맞은 패턴은 무엇인가요?', 'Decorator는 같은 인터페이스를 구현한 객체로 원래 객체를 감싸 기능을 덧붙이므로 기존 코드를 수정하지 않아도 됩니다.', 4, 'Factory Method', 'Facade', 'Prototype', 'Decorator'),
('SOLID 원칙과 디자인 패턴 실전', 5, '안전한 리팩터링 절차로 가장 적절한 것은 무엇인가요?', '현재 동작을 테스트로 고정한 뒤 작은 단위로 구조를 바꾸고 매번 테스트를 실행해야 동작이 바뀌지 않았음을 보장할 수 있습니다.', 1, '테스트로 동작을 고정한 뒤 작은 단위로 바꾸며 매번 테스트를 실행한다', '한 번에 전체 구조를 새로 작성한다', '테스트는 리팩터링이 끝난 뒤 작성한다', '운영 환경에서 직접 확인한다'),
('OAuth2와 소셜 로그인 연동', 1, 'Authorization Code 흐름에서 사용자가 로그인과 동의를 마친 뒤 클라이언트가 처음 받는 것은 무엇인가요?', '인가 서버는 redirect_uri로 인가 코드를 전달하고, 클라이언트는 이 코드를 백엔드에서 액세스 토큰으로 교환합니다.', 2, '액세스 토큰', '인가 코드', '사용자 비밀번호', '리프레시 토큰'),
('OAuth2와 소셜 로그인 연동', 2, '인가 코드를 액세스 토큰으로 교환하는 요청을 브라우저가 아니라 서버에서 하는 이유는 무엇인가요?', '토큰 교환에는 client_secret이 필요하므로 이를 노출하지 않으려면 서버에서 요청해야 합니다.', 3, '브라우저는 POST 요청을 보낼 수 없어서', '응답이 HTML이라서', 'client_secret을 브라우저에 노출하지 않기 위해서', '인가 코드가 만료되지 않게 하려고'),
('OAuth2와 소셜 로그인 연동', 3, 'state 파라미터가 막아 주는 공격은 무엇인가요?', 'state는 요청과 콜백을 연결하는 임의값으로, 공격자가 자신의 인가 코드로 피해자를 로그인시키는 CSRF 공격을 막습니다.', 1, '로그인 CSRF 공격', 'SQL Injection', '서비스 거부 공격', '비밀번호 무차별 대입'),
('OAuth2와 소셜 로그인 연동', 4, 'PKCE에 대한 설명으로 올바른 것은 무엇인가요?', 'PKCE는 클라이언트가 만든 code_verifier의 해시를 먼저 보내고, 토큰 교환 때 원본을 제출해 가로챈 인가 코드만으로는 토큰을 받지 못하게 합니다.', 4, '토큰 유효 기간을 늘리는 기능이다', '사용자 정보를 암호화해 저장한다', '소셜 제공자 목록을 관리한다', 'code_verifier로 가로챈 인가 코드의 토큰 교환을 막는다'),
('OAuth2와 소셜 로그인 연동', 5, '로그인 시도 시 redirect_uri mismatch 오류가 나는 가장 흔한 원인은 무엇인가요?', '요청한 redirect_uri가 제공자 콘솔에 등록한 주소와 스킴, 포트, 경로까지 정확히 일치해야 합니다.', 2, '사용자 비밀번호가 틀려서', '등록한 리다이렉트 주소와 요청 주소가 정확히 일치하지 않아서', '액세스 토큰이 만료되어서', '서버 시간이 맞지 않아서'),
('Spring Security 필터 체인과 JWT 인증', 1, 'DelegatingFilterProxy의 역할로 올바른 것은 무엇인가요?', '서블릿 컨테이너에 등록된 필터로서, 실제 처리를 스프링 컨테이너의 빈(FilterChainProxy)에 위임하는 다리 역할을 합니다.', 3, 'JWT를 발급한다', '비밀번호를 암호화한다', '서블릿 필터 요청을 스프링 빈인 FilterChainProxy에 위임한다', '컨트롤러를 생성한다'),
('Spring Security 필터 체인과 JWT 인증', 2, 'SecurityFilterChain이 여러 개 등록되어 있을 때 요청에 적용되는 체인은 어떻게 결정되나요?', 'FilterChainProxy는 등록된 순서대로 각 체인의 요청 매처를 확인해 처음으로 일치하는 체인 하나만 적용합니다.', 1, '요청과 처음 일치하는 체인 하나가 적용된다', '모든 체인이 순서대로 적용된다', '가장 마지막에 등록된 체인이 항상 적용된다', '무작위로 선택된다'),
('Spring Security 필터 체인과 JWT 인증', 3, '인증 과정에서 발생한 AuthenticationException을 401 응답으로 바꾸는 필터는 무엇인가요?', 'ExceptionTranslationFilter는 뒤쪽 필터에서 발생한 인증, 인가 예외를 잡아 EntryPoint나 AccessDeniedHandler로 넘깁니다.', 2, 'CsrfFilter', 'ExceptionTranslationFilter', 'CorsFilter', 'LogoutFilter'),
('Spring Security 필터 체인과 JWT 인증', 4, '허용했다고 생각한 경로에서 403이 계속 난다면 먼저 확인할 것으로 가장 알맞은 것은 무엇인가요?', '디버그 로그로 실제 적용된 필터와 규칙을 확인하면 경로 매칭 순서 문제나 CSRF 차단처럼 원인이 바로 드러납니다.', 4, '데이터베이스 인덱스', 'JVM 메모리 설정', '프론트엔드 CSS', '보안 디버그 로그로 적용된 체인과 규칙, CSRF 차단 여부'),
('Spring Security 필터 체인과 JWT 인증', 5, 'authorizeHttpRequests에서 규칙 순서가 중요한 이유는 무엇인가요?', '규칙은 위에서부터 차례로 검사해 처음 일치한 규칙이 적용되므로, anyRequest 같은 넓은 규칙을 먼저 쓰면 아래 규칙이 무시됩니다.', 3, '아래쪽 규칙이 항상 우선하기 때문에', '규칙이 많으면 서버가 느려지기 때문에', '위에서부터 처음 일치한 규칙이 적용되기 때문에', '순서는 중요하지 않다'),
('MockMvc와 Spring Boot 통합 테스트', 1, '응답 JSON의 data.title 값이 공지사항인지 검증하는 코드로 알맞은 것은 무엇인가요?', 'jsonPath는 JSON 경로 표현식으로 응답 필드를 찾아 값을 검증합니다.', 2, 'andExpect(status().isOk())', 'andExpect(jsonPath("$.data.title").value("공지사항"))', 'andExpect(content().contentType("text/html"))', 'andDo(print())'),
('MockMvc와 Spring Boot 통합 테스트', 2, 'MockMvc로 JSON 바디를 담은 POST 요청을 보낼 때 꼭 지정해야 하는 것은 무엇인가요?', '서버가 바디를 JSON으로 해석하려면 contentType을 application/json으로 지정하고 직렬화한 문자열을 content로 넣어야 합니다.', 1, 'contentType(MediaType.APPLICATION_JSON)과 content', 'cookie', 'locale', 'sessionAttr'),
('MockMvc와 Spring Boot 통합 테스트', 3, '@WithMockUser(roles = "ADMIN")의 역할은 무엇인가요?', '테스트 실행 동안 ADMIN 역할을 가진 가짜 인증 사용자를 SecurityContext에 넣어 권한이 필요한 API를 테스트할 수 있게 합니다.', 4, '실제 관리자 계정을 DB에 생성한다', '보안 설정을 비활성화한다', 'JWT를 발급한다', 'ADMIN 역할의 가짜 인증 사용자를 SecurityContext에 넣는다'),
('MockMvc와 Spring Boot 통합 테스트', 4, '존재하지 않는 게시글을 조회했을 때 오류 응답 형식까지 검증해야 하는 이유는 무엇인가요?', '프론트엔드는 오류 응답의 코드와 메시지 필드를 읽어 화면을 그리므로, 오류 형식도 API 계약의 일부입니다.', 3, '상태 코드는 항상 200이기 때문에', '오류는 프론트엔드에서 무시되기 때문에', '오류 응답 형식도 클라이언트가 의존하는 API 계약이기 때문에', '테스트 커버리지 숫자를 높이기 위해서'),
('MockMvc와 Spring Boot 통합 테스트', 5, '@WebMvcTest에서 컨트롤러가 의존하는 서비스를 대체하는 일반적인 방법은 무엇인가요?', '@WebMvcTest는 서비스 빈을 로드하지 않으므로 @MockBean으로 등록해 원하는 반환값을 지정합니다.', 2, '서비스를 new로 직접 생성한다', '@MockBean으로 목 빈을 등록한다', '@SpringBootTest로 바꾼다', '서비스 클래스를 삭제한다'),
('JUnit5와 Mockito 단위 테스트', 1, '정해진 값만 반환하도록 미리 설정해 두고 호출 여부는 검증하지 않는 테스트 더블은 무엇인가요?', 'Stub은 미리 정한 응답을 돌려주는 데 집중하고, Mock은 호출 자체를 검증하는 데 집중합니다.', 1, 'Stub', 'Mock', 'Dummy', 'Spy'),
('JUnit5와 Mockito 단위 테스트', 2, '메서드 시그니처를 채우기 위해 전달만 하고 실제로 사용되지 않는 객체는 무엇인가요?', 'Dummy는 매개변수를 채우기 위해서만 존재하며 테스트 안에서 실제로 사용되지 않습니다.', 3, 'Fake', 'Mock', 'Dummy', 'Stub'),
('JUnit5와 Mockito 단위 테스트', 3, '실제 데이터베이스 대신 HashMap으로 동작하는 간단한 저장소 구현체는 어떤 테스트 더블인가요?', 'Fake는 실제처럼 동작하지만 단순화된 구현으로, 메모리 저장소가 대표적인 예입니다.', 4, 'Dummy', 'Stub', 'Spy', 'Fake'),
('JUnit5와 Mockito 단위 테스트', 4, '@Nested를 사용하는 주된 이유는 무엇인가요?', '@Nested는 같은 상황에 속한 테스트를 내부 클래스로 묶어 상황별 구조를 드러내고 공통 준비 코드를 공유하게 해 줍니다.', 2, '테스트를 병렬로 실행하기 위해', '상황별로 관련 테스트를 묶어 구조를 드러내기 위해', '테스트를 비활성화하기 위해', '테스트 실행 순서를 무작위로 하기 위해'),
('JUnit5와 Mockito 단위 테스트', 5, 'AssertJ의 assertThat(list).hasSize(3).contains("a")와 같은 체이닝 단언의 장점은 무엇인가요?', '체이닝 단언은 문장처럼 읽혀 의도가 잘 드러나고, 실패 시 어떤 조건이 어긋났는지 자세한 메시지를 보여 줍니다.', 3, '테스트가 컴파일 없이 실행된다', '예외를 자동으로 무시한다', '읽기 쉽고 실패 메시지가 구체적이다', '목 객체를 자동 생성한다'),
('FetchType, N+1, QueryDSL 최적화', 1, '팀 10개를 조회한 뒤 각 팀의 멤버 컬렉션에 접근하면 지연 로딩 기준으로 총 몇 번의 쿼리가 실행되나요?', '팀 목록 조회 1번과 팀마다 멤버를 조회하는 10번이 더해져 총 11번, 즉 1+N 쿼리가 실행됩니다.', 2, '1번', '11번', '2번', '10번'),
('FetchType, N+1, QueryDSL 최적화', 2, '@ManyToOne에 즉시 로딩(EAGER)을 설정하면 JPQL 목록 조회에서 어떤 일이 생길 수 있나요?', 'JPQL은 먼저 SQL 그대로 엔티티를 조회한 뒤, 즉시 로딩 설정을 보고 연관 엔티티를 각각 추가 조회하므로 N+1이 생깁니다.', 1, '연관 엔티티를 위해 추가 쿼리가 N번 실행될 수 있다', '항상 JOIN 한 번으로 해결된다', '연관 엔티티가 조회되지 않는다', '컴파일 오류가 발생한다'),
('FetchType, N+1, QueryDSL 최적화', 3, 'Entity를 그대로 JSON으로 응답할 때 N+1이 생기는 이유는 무엇인가요?', '직렬화 과정에서 getter로 지연 로딩 연관관계에 접근하면 그때마다 추가 쿼리가 실행됩니다.', 4, 'JSON 변환이 느려서', '컨트롤러가 트랜잭션을 시작해서', '응답 크기가 커서', '직렬화 중 지연 로딩 연관관계에 접근해 추가 쿼리가 실행되어서'),
('FetchType, N+1, QueryDSL 최적화', 4, '지연 로딩된 연관 엔티티 필드에는 처음에 무엇이 들어 있나요?', '지연 로딩 필드에는 실제 엔티티 대신 프록시 객체가 들어 있고, 실제 데이터에 접근하는 순간 쿼리가 실행됩니다.', 3, 'null', '빈 리스트', '실제 엔티티를 대신하는 프록시 객체', '엔티티의 id 문자열'),
('FetchType, N+1, QueryDSL 최적화', 5, '트랜잭션이 끝난 뒤 지연 로딩 프록시에 접근하면 어떤 일이 생기나요?', '영속성 컨텍스트가 닫힌 뒤에는 프록시를 초기화할 수 없어 LazyInitializationException이 발생합니다.', 2, '자동으로 새 트랜잭션이 열린다', 'LazyInitializationException이 발생한다', '빈 값이 반환된다', '캐시된 값이 반환된다'),
('JPA Entity 매핑과 JPQL 실전', 1, 'Enum을 @Enumerated(EnumType.ORDINAL)로 저장하면 생기는 위험은 무엇인가요?', 'ORDINAL은 순서 번호를 저장하므로 Enum 중간에 값을 추가하면 기존 데이터의 의미가 뒤바뀝니다. STRING 저장이 안전합니다.', 3, '저장 공간이 너무 많이 든다', '조회가 불가능하다', 'Enum 순서가 바뀌면 기존 데이터의 의미가 달라진다', '대소문자를 구분하지 못한다'),
('JPA Entity 매핑과 JPQL 실전', 2, '주소의 도시, 거리, 우편번호를 하나의 의미 있는 값으로 묶어 여러 엔티티에서 재사용하려면 무엇을 쓰나요?', '@Embeddable 값 타입으로 묶고 엔티티에서 @Embedded로 사용하면 의미가 분명해지고 재사용할 수 있습니다.', 1, '@Embeddable 값 타입', '별도 엔티티와 @OneToMany', '문자열 하나로 합쳐 저장', '@Transient 필드'),
('JPA Entity 매핑과 JPQL 실전', 3, '학생과 강의의 다대다 관계에 신청일, 상태 같은 정보가 필요할 때 알맞은 설계는 무엇인가요?', '@ManyToMany의 연결 테이블에는 추가 컬럼을 둘 수 없으므로 수강 신청 같은 중간 엔티티를 만들어 일대다, 다대일로 풉니다.', 4, '@ManyToMany를 그대로 사용한다', '학생 테이블에 강의 id를 콤마로 저장한다', '두 엔티티에 서로의 id 리스트를 저장한다', '수강 신청 중간 엔티티를 만들어 일대다, 다대일로 푼다'),
('JPA Entity 매핑과 JPQL 실전', 4, 'cascade = CascadeType.ALL을 적용하기에 가장 알맞은 관계는 무엇인가요?', 'cascade는 생명주기를 완전히 함께하는 소유 관계에만 써야 합니다. 주문과 주문 상품이 대표적입니다.', 2, '여러 게시글이 공유하는 카테고리', '주문과 그 주문에만 속한 주문 상품', '여러 주문이 참조하는 회원', '여러 강의가 참조하는 강사'),
('JPA Entity 매핑과 JPQL 실전', 5, 'orphanRemoval = true를 설정하면 어떤 일이 일어나나요?', '부모 컬렉션에서 제거된 자식 엔티티는 고아로 판단되어 자동으로 DELETE됩니다.', 1, '부모 컬렉션에서 빠진 자식 엔티티가 자동으로 삭제된다', '부모가 저장될 때 자식이 복제된다', '자식이 다른 부모로 자동 이동한다', '삭제 쿼리가 절대 실행되지 않는다'),
('Spring MVC 요청 처리와 3계층 구조', 1, '요청 URL에 맞는 컨트롤러 메서드를 찾는 구성 요소는 무엇인가요?', 'HandlerMapping은 요청 정보로 처리할 핸들러를 찾고, HandlerAdapter가 그 핸들러를 실행합니다.', 2, 'ViewResolver', 'HandlerMapping', 'MessageConverter', 'DataSource'),
('Spring MVC 요청 처리와 3계층 구조', 2, '@RequestBody로 받은 JSON을 자바 객체로 바꿔 주는 구성 요소는 무엇인가요?', 'HttpMessageConverter(예: Jackson 기반 컨버터)가 요청 바디를 객체로, 반환 객체를 JSON으로 변환합니다.', 4, 'HandlerMapping', 'Filter', 'ViewResolver', 'HttpMessageConverter'),
('Spring MVC 요청 처리와 3계층 구조', 3, '로그인한 사용자 객체를 컨트롤러 파라미터로 바로 받게 해 주는 확장 지점은 무엇인가요?', 'HandlerMethodArgumentResolver를 구현하면 원하는 타입의 파라미터를 직접 만들어 컨트롤러에 주입할 수 있습니다.', 1, 'HandlerMethodArgumentResolver', 'ViewResolver', 'CommandLineRunner', 'BeanPostProcessor'),
('Spring MVC 요청 처리와 3계층 구조', 4, '필터와 인터셉터의 차이로 올바른 것은 무엇인가요?', '필터는 서블릿 컨테이너 수준에서 DispatcherServlet 앞에서 동작하고, 인터셉터는 스프링 MVC 안에서 컨트롤러 호출 전후에 동작합니다.', 3, '둘은 완전히 같은 위치에서 실행된다', '인터셉터가 DispatcherServlet보다 먼저 실행된다', '필터는 DispatcherServlet 앞, 인터셉터는 컨트롤러 호출 전후에 동작한다', '필터는 스프링 빈을 절대 사용할 수 없다'),
('Spring MVC 요청 처리와 3계층 구조', 5, '@ResponseBody가 붙은 메서드의 반환값은 어떻게 처리되나요?', '뷰를 찾지 않고 MessageConverter가 반환 객체를 직렬화해 HTTP 응답 바디에 바로 씁니다.', 2, 'ViewResolver가 같은 이름의 HTML 파일을 찾는다', 'MessageConverter가 직렬화해 응답 바디에 쓴다', '세션에 저장된다', '데이터베이스에 저장된다'),
('Spring Boot DI/IoC와 Spring Bean 등록 흐름', 1, '필드 주입(@Autowired 필드)의 단점으로 가장 적절한 것은 무엇인가요?', '필드 주입은 final을 쓸 수 없고, 스프링 없이 객체를 만들 때 의존성을 넣을 방법이 없어 테스트가 어렵습니다.', 3, '코드가 너무 길어진다', '컴파일이 느려진다', 'final을 쓸 수 없고 스프링 없이 테스트하기 어렵다', '빈이 두 번 생성된다'),
('Spring Boot DI/IoC와 Spring Bean 등록 흐름', 2, '@SpringBootApplication이 있는 클래스의 패키지 위치가 중요한 이유는 무엇인가요?', '컴포넌트 스캔은 기본적으로 해당 클래스의 패키지와 하위 패키지만 대상으로 하므로, 바깥 패키지의 빈은 등록되지 않습니다.', 1, '그 패키지와 하위 패키지만 컴포넌트 스캔 대상이 되기 때문에', '패키지 이름이 애플리케이션 이름이 되기 때문에', '그 위치에만 application.yml을 둘 수 있기 때문에', '위치는 아무 영향이 없다'),
('Spring Boot DI/IoC와 Spring Bean 등록 흐름', 3, '@Configuration 클래스 안에서 @Bean 메서드를 두 번 호출해도 같은 인스턴스가 반환되는 이유는 무엇인가요?', '@Configuration 클래스는 CGLIB 프록시로 감싸져 @Bean 메서드 호출을 가로채고, 이미 등록된 빈이 있으면 그것을 반환합니다.', 4, '메서드가 static이기 때문에', 'JVM이 결과를 캐시하기 때문에', '@Bean 메서드는 한 번만 호출할 수 있기 때문에', '설정 클래스가 프록시로 감싸져 등록된 빈을 반환하기 때문에'),
('Spring Boot DI/IoC와 Spring Bean 등록 흐름', 4, '두 빈이 생성자에서 서로를 주입받으면 애플리케이션 시작 시 어떤 일이 생기나요?', '생성자 주입에서는 서로가 먼저 만들어져야 하므로 순환 참조 오류로 시작에 실패합니다. 설계를 바꿔 의존 방향을 한쪽으로 정리해야 합니다.', 2, '자동으로 하나가 지연 생성된다', '순환 참조 오류로 시작에 실패한다', '둘 중 하나가 null로 주입된다', '아무 문제 없이 시작된다'),
('Spring Boot DI/IoC와 Spring Bean 등록 흐름', 5, '같은 인터페이스 구현체가 여러 개일 때 모두 주입받아 사용하려면 어떻게 하나요?', 'List나 Map 타입으로 주입받으면 해당 타입의 모든 빈이 들어와 전략 선택 등에 활용할 수 있습니다.', 3, '@Primary를 모든 빈에 붙인다', '구현체를 하나만 남긴다', 'List<인터페이스> 또는 Map<String, 인터페이스>로 주입받는다', '@Lazy를 붙인다');

INSERT INTO seed_course_assignment (course_title, assignment_title, assignment_description, submission_rule, lesson_title, lesson_description) VALUES
('SOLID 원칙과 디자인 패턴 실전', '알림 발송 모듈 확장 가능한 구조로 리팩터링',
'상황.
서비스의 알림 발송 모듈이 이메일, SMS, 푸시를 하나의 클래스에서 분기로 처리합니다. 다음 분기에 카카오 알림톡과 재시도, 발송 로그 기능이 추가될 예정입니다.

요구사항.
1. 현재 구조의 코드 냄새를 3가지 이상 찾아 어떤 원칙 위반인지 설명하세요.
2. 리팩터링 전에 현재 동작을 고정하는 테스트를 작성하세요.
3. 채널별 발송을 공통 인터페이스 구현체로 분리하세요.
4. 재시도와 발송 로그는 Decorator로 덧붙이세요.
5. 알림톡 채널을 추가할 때 기존 코드 변경이 없음을 보여 주세요.

제출물.
GitHub 저장소 URL과 리팩터링 단계별 커밋, 전후 구조를 비교한 README.',
'GitHub 저장소 URL을 제출하세요. 리팩터링은 단계별 커밋으로 나누고 README에 각 단계의 의도를 적으세요.',
'실습 과제: 알림 발송 모듈 리팩터링', '테스트로 동작을 지키며 알림 모듈을 패턴 기반 구조로 바꾼 결과를 제출합니다.'),
('OAuth2와 소셜 로그인 연동', '소셜 로그인 2종 연동과 회원 연결',
'상황.
신규 서비스에 Google과 Kakao 로그인을 붙여야 합니다. 소셜 로그인 후에도 서비스 API는 자체 JWT로 인증합니다.

요구사항.
1. Google, Kakao(또는 Naver) 두 제공자를 Spring Security OAuth2 Client로 연동하세요.
2. 제공자별 사용자 정보를 공통 형식으로 변환하세요.
3. 처음 로그인한 사용자는 회원으로 가입시키고, 같은 이메일의 기존 회원 처리 정책을 정하세요.
4. 로그인 성공 시 서비스 JWT를 발급해 프론트엔드에 전달하세요.
5. 클라이언트 비밀 값은 환경 변수로 분리하고 저장소에 올리지 마세요.

제출물.
GitHub 저장소 URL과 로그인 흐름도, 회원 연결 정책을 설명한 README.',
'GitHub 저장소 URL을 제출하세요. 비밀 값이 커밋되지 않았는지 확인하고, README에 로그인 흐름도와 계정 연결 정책을 포함하세요.',
'실습 과제: 소셜 로그인 2종 연동과 회원 연결', '두 제공자의 소셜 로그인과 회원 연결, JWT 발급을 구현해 제출합니다.'),
('Spring Security 필터 체인과 JWT 인증', 'JWT 인증 필터와 보안 예외 처리 완성',
'상황.
API 서버에 JWT 인증을 직접 구현해야 합니다. 프론트엔드는 토큰 만료와 권한 부족을 구분해 다른 화면을 보여 줘야 합니다.

요구사항.
1. OncePerRequestFilter를 상속한 JWT 인증 필터를 구현하세요.
2. 필터를 UsernamePasswordAuthenticationFilter 앞에 배치하고 이유를 설명하세요.
3. 공개 경로, 로그인 사용자 경로, 관리자 경로 규칙을 설정하세요.
4. 토큰 만료, 서명 오류, 권한 부족을 서로 다른 오류 코드로 응답하세요.
5. 보안 디버그 로그로 요청이 거친 필터 목록을 캡처하세요.

제출물.
GitHub 저장소 URL과 필터 체인 구조, 오류 코드 표를 정리한 README.',
'GitHub 저장소 URL을 제출하세요. README에 오류 코드 표와 디버그 로그 캡처를 포함하세요.',
'실습 과제: JWT 인증 필터와 보안 예외 처리', '직접 구현한 JWT 필터와 상황별 보안 예외 응답을 제출합니다.'),
('MockMvc와 Spring Boot 통합 테스트', '게시판 API 계약 테스트와 통합 테스트',
'상황.
게시판 API의 응답 형식이 자주 바뀌어 프론트엔드가 여러 번 깨졌습니다. 응답 계약을 테스트로 고정하고 실제 흐름도 검증해야 합니다.

요구사항.
1. 게시글 목록, 상세, 작성 API의 응답 필드를 jsonPath로 검증하세요.
2. 검증 실패와 존재하지 않는 게시글의 오류 응답 형식을 검증하세요.
3. 작성 API는 로그인 사용자만 호출할 수 있음을 테스트하세요.
4. @SpringBootTest로 작성부터 조회까지 실제 흐름을 테스트하세요.
5. 테스트 간 데이터가 섞이지 않도록 격리 전략을 적용하세요.

제출물.
GitHub 저장소 URL과 테스트 목록, 실행 시간을 정리한 README.',
'GitHub 저장소 URL을 제출하세요. README에 계약 테스트와 통합 테스트의 역할 차이를 설명하세요.',
'실습 과제: 게시판 API 계약 테스트와 통합 테스트', 'MockMvc 계약 테스트와 통합 테스트로 게시판 API를 보호한 결과를 제출합니다.'),
('JUnit5와 Mockito 단위 테스트', '회원 가입 서비스 테스트 더블 검증',
'상황.
회원 가입 서비스는 중복 확인, 비밀번호 암호화, 저장, 환영 메일 발송, 가입 이벤트 발행을 순서대로 처리합니다.

요구사항.
1. 저장소는 Fake(메모리 구현), 메일 발송기와 이벤트 발행기는 Mock으로 대체하세요.
2. 가입 성공 시 메일 발송기에 전달된 이메일 주소를 ArgumentCaptor로 검증하세요.
3. 저장이 메일 발송보다 먼저 일어나는지 호출 순서를 검증하세요.
4. 메일 발송이 실패해도 가입은 완료되는지 예외 stub으로 테스트하세요.
5. 현재 시간에 의존하는 코드를 Clock 주입으로 바꿔 테스트 가능하게 만드세요.

제출물.
GitHub 저장소 URL과 테스트 더블 선택 이유를 정리한 README.',
'GitHub 저장소 URL을 제출하세요. README에 협력 객체별로 고른 테스트 더블과 그 이유를 표로 정리하세요.',
'실습 과제: 회원 가입 서비스 테스트 더블 검증', '여러 테스트 더블로 회원 가입 서비스의 협력 관계를 검증해 제출합니다.'),
('FetchType, N+1, QueryDSL 최적화', '느린 목록 API 측정과 최적화',
'상황.
강의 목록 API가 강사, 태그, 리뷰 수를 함께 보여 주는데 응답이 2초 이상 걸립니다. 페이징과 검색 조건도 지원해야 합니다.

요구사항.
1. 쿼리 로그와 실행 시간을 측정해 기준선을 기록하세요.
2. N+1이 발생하는 지점을 모두 찾아 원인을 설명하세요.
3. 다대일은 fetch join, 컬렉션은 배치 사이즈 또는 별도 조회로 해결하세요.
4. QueryDSL로 검색 조건과 DTO 프로젝션, 카운트 쿼리 분리를 구현하세요.
5. 개선 전후 쿼리 수와 응답 시간을 표로 비교하세요.

제출물.
GitHub 저장소 URL과 측정 결과 보고서.',
'GitHub 저장소 URL을 제출하세요. README에 개선 단계별 쿼리 수와 응답 시간을 표로 정리하세요.',
'실습 과제: 느린 목록 API 측정과 최적화', 'N+1을 찾아 해결하고 QueryDSL로 목록 조회를 최적화한 결과를 제출합니다.'),
('JPA Entity 매핑과 JPQL 실전', '수강 신청 도메인 Entity 설계',
'상황.
온라인 강의 플랫폼의 수강 신청 기능을 JPA로 설계합니다. 학생은 여러 강의를 신청하고, 신청에는 신청일과 상태가 있습니다.

요구사항.
1. 학생, 강의, 수강 신청 엔티티를 설계하고 다대다를 중간 엔티티로 푸세요.
2. 신청 상태는 Enum STRING으로, 강의 기간은 @Embeddable 값 타입으로 매핑하세요.
3. cascade와 orphanRemoval을 적용할 관계와 적용하지 않을 관계를 구분하고 이유를 적으세요.
4. 특정 학생의 신청 강의 목록을 페치 조인 JPQL로 조회하세요.
5. 기간이 지난 신청을 한 번에 만료 처리하는 벌크 연산을 작성하고 영속성 컨텍스트 처리 방법을 적으세요.

제출물.
GitHub 저장소 URL과 엔티티 관계도, 매핑 결정 이유를 담은 README.',
'GitHub 저장소 URL을 제출하세요. README에 엔티티 관계도와 매핑 결정 근거를 포함하세요.',
'실습 과제: 수강 신청 도메인 Entity 설계', '중간 엔티티, 값 타입, JPQL, 벌크 연산을 활용한 수강 신청 도메인을 제출합니다.'),
('Spring MVC 요청 처리와 3계층 구조', '레거시 컨트롤러 3계층 분리',
'상황.
주문 컨트롤러 하나에 요청 파싱, 재고 확인, 금액 계산, SQL 실행, 응답 생성이 모두 들어 있습니다.

요구사항.
1. 레거시 컨트롤러(직접 작성한 예제 가능)의 문제점을 정리하세요.
2. Controller, Service, Repository로 책임을 분리하고 DTO 변환 위치를 정하세요.
3. 트랜잭션을 서비스 계층에 두고 그 이유를 설명하세요.
4. 로그인 사용자를 ArgumentResolver로 주입받도록 바꾸세요.
5. 요청 처리 시간을 기록하는 인터셉터를 추가하고, 필터가 아닌 인터셉터를 고른 이유를 적으세요.

제출물.
GitHub 저장소 URL과 전후 구조 비교를 담은 README.',
'GitHub 저장소 URL을 제출하세요. README에 분리 전후 클래스 구조와 계층별 책임을 표로 정리하세요.',
'실습 과제: 레거시 컨트롤러 3계층 분리', '책임이 섞인 컨트롤러를 3계층 구조로 분리하고 MVC 확장 지점을 적용해 제출합니다.'),
('Spring Boot DI/IoC와 Spring Bean 등록 흐름', '환경별 결제 수단 빈 구성',
'상황.
결제 기능을 개발 환경에서는 가짜 결제로, 운영 환경에서는 실제 PG 연동으로 동작시켜야 합니다. 결제 수단은 앞으로 더 늘어납니다.

요구사항.
1. 결제 인터페이스와 카드, 간편결제 구현체를 만드세요.
2. 프로파일에 따라 가짜 결제와 실제 결제 빈이 바뀌도록 구성하세요.
3. 설정값에 따라 특정 결제 수단을 켜고 끄는 조건부 빈을 만드세요.
4. 모든 결제 수단을 Map으로 주입받아 요청 타입에 맞게 선택하세요.
5. 초기화 시 PG 연결을 확인하는 생명주기 콜백을 추가하세요.

제출물.
GitHub 저장소 URL과 빈 구성 다이어그램, 프로파일별 동작 설명을 담은 README.',
'GitHub 저장소 URL을 제출하세요. README에 프로파일과 설정값 조합별로 등록되는 빈 목록을 표로 정리하세요.',
'실습 과제: 환경별 결제 수단 빈 구성', '프로파일, 조건부 등록, 컬렉션 주입으로 결제 수단을 구성한 결과를 제출합니다.');

INSERT INTO seed_course_assignment_rubric (course_title, display_order, criteria_name, criteria_description, max_points) VALUES
('SOLID 원칙과 디자인 패턴 실전', 1, '문제 진단', '코드 냄새와 원칙 위반을 구체적으로 설명했습니다.', 20),
('SOLID 원칙과 디자인 패턴 실전', 2, '안전한 리팩터링', '테스트로 동작을 고정하고 단계별로 커밋했습니다.', 30),
('SOLID 원칙과 디자인 패턴 실전', 3, '패턴 적용', '채널 분리와 Decorator가 목적에 맞게 적용되어 있습니다.', 30),
('SOLID 원칙과 디자인 패턴 실전', 4, '확장성 검증', '새 채널 추가 시 기존 코드 변경이 없음을 보여 줬습니다.', 20),
('OAuth2와 소셜 로그인 연동', 1, '제공자 연동', '두 제공자의 로그인이 정상 동작합니다.', 30),
('OAuth2와 소셜 로그인 연동', 2, '사용자 정보 통합', '제공자별 응답을 공통 형식으로 변환했습니다.', 25),
('OAuth2와 소셜 로그인 연동', 3, '회원 연결과 JWT', '회원 가입, 연결 정책과 JWT 발급이 구현되어 있습니다.', 30),
('OAuth2와 소셜 로그인 연동', 4, '비밀 값 관리', '클라이언트 비밀 값이 저장소에 노출되지 않았습니다.', 15),
('Spring Security 필터 체인과 JWT 인증', 1, '필터 구현', 'JWT 필터가 토큰을 검증하고 인증 정보를 저장합니다.', 35),
('Spring Security 필터 체인과 JWT 인증', 2, '필터 위치와 규칙', '필터 위치와 경로별 접근 규칙이 올바르게 설정되어 있습니다.', 25),
('Spring Security 필터 체인과 JWT 인증', 3, '예외 응답', '토큰 오류와 권한 부족을 구분해 응답합니다.', 25),
('Spring Security 필터 체인과 JWT 인증', 4, '디버깅 근거', '디버그 로그로 필터 흐름을 확인한 근거가 있습니다.', 15),
('MockMvc와 Spring Boot 통합 테스트', 1, '응답 계약 검증', '정상 응답 필드를 빠짐없이 검증했습니다.', 30),
('MockMvc와 Spring Boot 통합 테스트', 2, '오류와 인증 테스트', '오류 응답 형식과 인증 조건을 검증했습니다.', 25),
('MockMvc와 Spring Boot 통합 테스트', 3, '통합 테스트', '실제 흐름을 통합 테스트로 검증했습니다.', 25),
('MockMvc와 Spring Boot 통합 테스트', 4, '데이터 격리', '테스트 간 데이터 간섭이 없도록 구성했습니다.', 20),
('JUnit5와 Mockito 단위 테스트', 1, '테스트 더블 선택', '협력 객체마다 알맞은 테스트 더블을 골랐습니다.', 25),
('JUnit5와 Mockito 단위 테스트', 2, '상호작용 검증', 'ArgumentCaptor와 호출 순서 검증이 올바릅니다.', 25),
('JUnit5와 Mockito 단위 테스트', 3, '실패 시나리오', '메일 발송 실패 상황을 예외 stub으로 검증했습니다.', 25),
('JUnit5와 Mockito 단위 테스트', 4, '테스트 가능한 설계', '시간 의존성을 분리해 테스트 가능하게 만들었습니다.', 25),
('FetchType, N+1, QueryDSL 최적화', 1, '측정과 진단', '기준선을 측정하고 N+1 지점을 모두 찾았습니다.', 25),
('FetchType, N+1, QueryDSL 최적화', 2, '로딩 전략 개선', '관계 유형에 맞는 해결 방법을 적용했습니다.', 30),
('FetchType, N+1, QueryDSL 최적화', 3, 'QueryDSL 최적화', '동적 조건, DTO 프로젝션, 카운트 분리를 구현했습니다.', 25),
('FetchType, N+1, QueryDSL 최적화', 4, '결과 비교', '전후 쿼리 수와 응답 시간을 비교해 해석했습니다.', 20),
('JPA Entity 매핑과 JPQL 실전', 1, '엔티티 설계', '중간 엔티티와 값 타입, Enum 매핑이 적절합니다.', 30),
('JPA Entity 매핑과 JPQL 실전', 2, '생명주기 관리', 'cascade와 orphanRemoval 적용 기준이 명확합니다.', 20),
('JPA Entity 매핑과 JPQL 실전', 3, 'JPQL 조회', '페치 조인 JPQL이 올바르게 동작합니다.', 25),
('JPA Entity 매핑과 JPQL 실전', 4, '벌크 연산', '벌크 연산 후 영속성 컨텍스트 처리까지 고려했습니다.', 25),
('Spring MVC 요청 처리와 3계층 구조', 1, '문제 분석', '레거시 코드의 문제점을 구체적으로 정리했습니다.', 15),
('Spring MVC 요청 처리와 3계층 구조', 2, '계층 분리', '계층별 책임과 DTO 변환, 트랜잭션 위치가 적절합니다.', 40),
('Spring MVC 요청 처리와 3계층 구조', 3, 'MVC 확장 지점', 'ArgumentResolver와 인터셉터를 목적에 맞게 적용했습니다.', 25),
('Spring MVC 요청 처리와 3계층 구조', 4, '문서화', '전후 구조와 선택 이유를 README로 설명했습니다.', 20),
('Spring Boot DI/IoC와 Spring Bean 등록 흐름', 1, '인터페이스 설계', '결제 인터페이스와 구현체가 역할에 맞게 나뉘어 있습니다.', 20),
('Spring Boot DI/IoC와 Spring Bean 등록 흐름', 2, '환경별 구성', '프로파일과 조건부 등록이 의도대로 동작합니다.', 30),
('Spring Boot DI/IoC와 Spring Bean 등록 흐름', 3, '컬렉션 주입', 'Map 주입으로 결제 수단을 선택합니다.', 25),
('Spring Boot DI/IoC와 Spring Bean 등록 흐름', 4, '생명주기와 문서화', '초기화 콜백과 빈 구성 설명이 정리되어 있습니다.', 25);

INSERT INTO seed_course_content (course_title, subtitle, description) VALUES
('인터페이스, 제네릭, 컬렉션 실전', '타입 안전한 코드와 상황에 맞는 자료구조 선택으로 Java 실무 감각을 키웁니다',
'Java로 실무 코드를 작성하면 인터페이스, 제네릭, 컬렉션을 하루에도 수십 번 사용합니다. 그런데 ArrayList와 LinkedList 중 무엇을 써야 하는지, 제네릭 와일드카드는 언제 필요한지 물으면 막히는 경우가 많습니다.

첫 섹션에서는 인터페이스로 역할을 정의하고 구현을 바꿔 끼우는 방법, default 메서드와 함수형 인터페이스, 제네릭 클래스와 메서드, 타입 소거와 와일드카드(extends, super)의 의미를 정리합니다.

두 번째 섹션에서는 List, Set, Map 구현체의 내부 구조와 시간 복잡도, HashMap이 해시 충돌을 다루는 방식, Comparable과 Comparator로 정렬하는 방법, 스트림으로 컬렉션을 가공하는 패턴을 다룹니다. 마지막 과제로 상품 재고 관리 모듈을 타입 안전하게 구현합니다.'),
('Java OOP와 상속 설계', '상속을 언제 쓰고 언제 피해야 하는지, 객체지향 설계의 판단 기준을 익힙니다',
'상속은 코드 재사용을 위한 가장 쉬운 방법처럼 보이지만, 잘못 쓰면 부모 클래스 하나를 고칠 때마다 여러 자식 클래스가 깨지는 구조가 됩니다. 이 강의는 상속의 장점과 함정을 함께 보며 객체지향 설계의 판단 기준을 세웁니다.

첫 섹션에서는 객체의 책임과 메시지, 캡슐화로 불변식을 지키는 방법, 상속과 메서드 재정의, super 호출, 추상 클래스로 공통 흐름을 정의하는 방법을 정리합니다.

두 번째 섹션에서는 상속이 캡슐화를 깨뜨리는 사례, 상속 대신 조합과 위임으로 설계하는 방법, is-a 관계를 판단하는 기준, final로 확장을 제한하는 이유를 다룹니다. 마지막 과제로 결제 수단 계층을 상속과 조합 두 가지 방식으로 설계해 비교합니다.'),
('Linux 메모리 관리와 I/O 관리', '가상 메모리, 페이지 캐시, 파일 I/O를 이해하고 메모리, 디스크 문제를 진단합니다',
'서버가 메모리 부족으로 죽거나 디스크 I/O 때문에 응답이 느려질 때, free나 iostat 출력을 정확히 읽을 줄 알면 원인을 훨씬 빨리 찾을 수 있습니다. 이 강의는 Linux가 메모리와 I/O를 관리하는 방식을 명령어 출력과 연결해 이해합니다.

첫 섹션에서는 가상 메모리와 페이지, 페이지 폴트, 스왑, 페이지 캐시와 버퍼, OOM Killer의 동작을 정리하고 free, vmstat, /proc/meminfo로 실제 상태를 읽습니다.

두 번째 섹션에서는 파일 디스크립터와 시스템 콜, 블로킹과 논블로킹 I/O, I/O 멀티플렉싱(select, epoll)의 개념, iostat과 iotop으로 디스크 병목을 찾는 방법을 다룹니다. 마지막 과제로 메모리, I/O 문제 상황을 재현하고 진단 보고서를 작성합니다.'),
('Linux 프로세스와 스레드 관리', 'fork와 exec, 시그널, 스케줄링, 스레드까지 리눅스 실행 단위를 터미널에서 관찰합니다',
'애플리케이션이 멈추거나 CPU를 100% 쓰는 상황에서 어떤 프로세스와 스레드가 문제인지 찾아내는 능력은 백엔드 개발자에게 꼭 필요합니다. 이 강의는 리눅스가 프로그램을 실행하고 관리하는 방식을 직접 관찰하며 익힙니다.

첫 섹션에서는 프로세스 생성(fork, exec)과 부모 자식 관계, 프로세스 상태, 좀비와 고아 프로세스, 시그널과 종료 처리를 ps, pstree, kill로 확인합니다.

두 번째 섹션에서는 스레드와 프로세스의 차이, 스케줄링과 nice 값, 컨텍스트 스위칭 측정, top -H로 CPU를 많이 쓰는 스레드를 찾는 방법, systemd로 서비스를 관리하는 방법을 다룹니다. 마지막 과제로 CPU를 점유하는 스레드를 찾아내는 장애 분석을 수행합니다.'),
('OWASP, XSS, CSRF, SQL Injection, CORS', '대표 웹 취약점을 직접 공격해 보고 방어 코드를 작성하며 보안 감각을 기릅니다',
'웹 보안은 이론으로만 배우면 실제 코드에서 어디가 위험한지 감이 오지 않습니다. 이 강의는 의도적으로 취약하게 만든 예제 애플리케이션을 직접 공격해 보고, 같은 코드를 안전하게 고치는 방식으로 진행합니다.

첫 섹션에서는 OWASP Top 10의 흐름을 살펴본 뒤 저장형, 반사형, DOM 기반 XSS와 CSRF를 재현하고, 출력 인코딩, CSP, CSRF 토큰, SameSite 쿠키로 방어합니다.

두 번째 섹션에서는 SQL Injection으로 로그인을 우회하거나 데이터를 빼내는 과정을 재현한 뒤 Prepared Statement와 ORM 사용 시 주의점을 다루고, CORS의 동작 원리와 잘못된 설정이 만드는 위험을 정리합니다. 마지막 과제로 취약점 점검 체크리스트를 만들어 내 프로젝트를 점검합니다.'),
('Swagger와 REST API 문서화', 'springdoc-openapi로 코드와 함께 살아 있는 API 문서를 만들고 협업에 활용합니다',
'API 문서를 위키에 따로 적으면 코드가 바뀌어도 문서는 그대로 남아 금세 틀린 문서가 됩니다. 코드에서 문서를 생성하면 구현과 문서가 항상 함께 움직입니다.

첫 섹션에서는 OpenAPI 명세의 구조, springdoc-openapi 설정, @Operation, @Parameter, @Schema로 설명과 예시를 다는 방법, 공통 응답과 오류 응답을 문서에 표현하는 방법을 정리합니다.

두 번째 섹션에서는 JWT 인증 헤더를 Swagger UI에서 테스트하는 설정, API 그룹 분리, 운영 환경에서 문서 노출을 제한하는 방법, 명세 파일로 프론트엔드 타입과 목 서버를 생성하는 협업 흐름을 다룹니다. 마지막 과제로 기존 API에 완성도 있는 문서를 붙입니다.'),
('REST URI 설계와 HTTP 메서드', '자원 모델링부터 메서드와 상태 코드 선택까지, 헷갈리는 API 설계 사례를 정리합니다',
'API 설계에서 가장 자주 고민하는 것은 이 동작을 어떤 URI와 메서드로 표현할지입니다. 로그인, 좋아요, 결제 취소처럼 CRUD에 딱 맞지 않는 동작을 만나면 팀마다 제각각의 이름이 생깁니다.

첫 섹션에서는 자원을 식별하고 계층을 표현하는 URI 규칙, 컬렉션과 단일 자원, 하위 자원과 쿼리 파라미터의 구분, 동사처럼 보이는 동작을 자원으로 모델링하는 방법을 다룹니다.

두 번째 섹션에서는 HTTP 메서드의 안전성과 멱등성, PUT과 PATCH, POST의 선택 기준, 조건부 요청과 낙관적 잠금, 상황별 상태 코드 선택을 사례 중심으로 정리합니다. 마지막 과제로 헷갈리는 동작이 많은 서비스의 API를 설계하고 근거를 문서화합니다.'),
('Pull Request와 코드 리뷰 실무', '리뷰하기 좋은 PR을 만들고, 팀이 함께 성장하는 코드 리뷰 문화를 익힙니다',
'코드 리뷰는 버그를 잡는 도구이기도 하지만, 팀이 같은 기준으로 코드를 쓰게 만드는 가장 좋은 방법입니다. 하지만 수천 줄짜리 PR이나 감정이 실린 코멘트는 리뷰를 형식적인 절차로 만들어 버립니다.

첫 섹션에서는 PR을 작게 나누는 기준, 리뷰어가 맥락을 빠르게 파악할 수 있는 PR 설명 작성법, 셀프 리뷰 체크리스트, 커밋을 정리하는 방법을 다룹니다.

두 번째 섹션에서는 리뷰어가 무엇을 우선적으로 봐야 하는지, 근거와 제안이 담긴 코멘트를 쓰는 방법, 의견이 갈릴 때 합의하는 방법, 리뷰 규칙과 자동화(CI, 린트)로 리뷰 부담을 줄이는 방법을 정리합니다. 마지막 과제로 실제 PR을 올리고 상호 리뷰를 진행합니다.'),
('Git 브랜치 전략과 GitFlow', 'GitFlow, GitHub Flow, 트렁크 기반 개발을 비교하고 팀에 맞는 브랜치 전략을 정합니다',
'브랜치 전략은 정답이 하나가 아닙니다. 배포 주기, 팀 규모, 운영 중인 버전 수에 따라 알맞은 전략이 달라집니다. 전략 없이 각자 브랜치를 만들면 병합 충돌과 배포 사고가 반복됩니다.

첫 섹션에서는 브랜치의 실체인 커밋 포인터, fast-forward와 3-way 병합, merge, squash, rebase 병합 방식의 차이와 이력에 남는 모습을 비교합니다.

두 번째 섹션에서는 GitFlow의 main, develop, feature, release, hotfix 흐름을 실습하고, GitHub Flow와 트렁크 기반 개발과 비교해 팀 상황에 맞는 전략을 고르는 기준, 브랜치 보호 규칙과 버전 태그 관리를 다룹니다. 마지막 과제로 릴리스와 핫픽스 시나리오를 GitFlow로 재현합니다.'),
('브라우저 요청 흐름과 HTTP 응답 구조', '브라우저가 요청을 보내고 응답을 받아 화면을 그리기까지, 백엔드 관점에서 해부합니다',
'백엔드 개발자가 브라우저 동작을 알아야 하는 이유는 분명합니다. 캐시 헤더 하나, 쿠키 속성 하나, 리다이렉트 하나가 화면 속도와 로그인 유지, 보안에 직접 영향을 주기 때문입니다.

첫 섹션에서는 브라우저가 URL을 해석하고 연결을 재사용하는 방식, HTTP/1.1과 HTTP/2의 차이, 요청 헤더(쿠키, Accept, Authorization)와 응답 구조(상태 줄, 헤더, 바디)를 정리합니다.

두 번째 섹션에서는 Cache-Control과 ETag로 캐시를 제어하는 방법, 리다이렉트와 쿠키 설정 응답, 압축과 Content-Type, 브라우저가 응답을 받아 렌더링하기까지의 과정과 백엔드가 성능에 기여할 수 있는 지점을 다룹니다. 마지막 과제로 API 응답 헤더를 설계하고 개발자 도구로 효과를 검증합니다.');

INSERT INTO seed_course_info (course_title, section_key, item_order, item_text) VALUES
('인터페이스, 제네릭, 컬렉션 실전', 'TARGET_AUDIENCE', 0, 'Java 문법은 익혔지만 컬렉션 선택과 제네릭이 아직 감으로만 느껴지는 입문자'),
('인터페이스, 제네릭, 컬렉션 실전', 'TARGET_AUDIENCE', 1, '와일드카드 문법을 보면 머리가 아파지는 분'),
('인터페이스, 제네릭, 컬렉션 실전', 'TARGET_AUDIENCE', 2, '자료구조 선택 이유를 면접에서 설명하고 싶은 취업 준비생'),
('인터페이스, 제네릭, 컬렉션 실전', 'PREREQUISITES', 0, 'Java 클래스와 객체, 상속의 기본 문법을 알고 있어야 합니다.'),
('인터페이스, 제네릭, 컬렉션 실전', 'PREREQUISITES', 1, '배열과 반복문으로 간단한 프로그램을 만들어 본 경험이 있으면 좋습니다.'),
('인터페이스, 제네릭, 컬렉션 실전', 'OBJECTIVES', 0, '인터페이스로 역할을 정의하고 구현을 교체하는 코드를 작성할 수 있습니다.'),
('인터페이스, 제네릭, 컬렉션 실전', 'OBJECTIVES', 1, '제네릭 클래스와 메서드, 와일드카드를 의도에 맞게 사용할 수 있습니다.'),
('인터페이스, 제네릭, 컬렉션 실전', 'OBJECTIVES', 2, '컬렉션 구현체의 내부 구조와 시간 복잡도를 비교해 선택할 수 있습니다.'),
('인터페이스, 제네릭, 컬렉션 실전', 'OBJECTIVES', 3, 'Comparator와 스트림으로 컬렉션을 정렬하고 가공할 수 있습니다.'),
('Java OOP와 상속 설계', 'TARGET_AUDIENCE', 0, '상속으로 코드를 재사용하다 구조가 꼬인 경험이 있는 개발자'),
('Java OOP와 상속 설계', 'TARGET_AUDIENCE', 1, '객체지향을 문법이 아니라 설계 관점에서 이해하고 싶은 입문자'),
('Java OOP와 상속 설계', 'TARGET_AUDIENCE', 2, '조합과 위임이 왜 권장되는지 궁금한 분'),
('Java OOP와 상속 설계', 'PREREQUISITES', 0, 'Java 클래스, 생성자, 메서드 문법을 알고 있어야 합니다.'),
('Java OOP와 상속 설계', 'PREREQUISITES', 1, '간단한 클래스 여러 개로 프로그램을 만들어 본 경험이 있으면 좋습니다.'),
('Java OOP와 상속 설계', 'OBJECTIVES', 0, '객체의 책임을 정하고 캡슐화로 불변식을 지킬 수 있습니다.'),
('Java OOP와 상속 설계', 'OBJECTIVES', 1, '상속과 재정의, 추상 클래스로 공통 흐름을 설계할 수 있습니다.'),
('Java OOP와 상속 설계', 'OBJECTIVES', 2, '상속이 캡슐화를 깨뜨리는 사례를 알아보고 피할 수 있습니다.'),
('Java OOP와 상속 설계', 'OBJECTIVES', 3, '조합과 위임으로 유연한 구조를 설계할 수 있습니다.'),
('Linux 메모리 관리와 I/O 관리', 'TARGET_AUDIENCE', 0, '서버 메모리 부족이나 디스크 지연을 진단해야 하는 백엔드 개발자'),
('Linux 메모리 관리와 I/O 관리', 'TARGET_AUDIENCE', 1, 'free 출력의 buff/cache를 보고 메모리가 부족하다고 오해한 적이 있는 분'),
('Linux 메모리 관리와 I/O 관리', 'TARGET_AUDIENCE', 2, 'epoll과 논블로킹 I/O의 개념을 정리하고 싶은 분'),
('Linux 메모리 관리와 I/O 관리', 'PREREQUISITES', 0, 'Linux 터미널 기본 명령어를 사용할 수 있어야 합니다.'),
('Linux 메모리 관리와 I/O 관리', 'PREREQUISITES', 1, '프로세스와 스레드의 기본 개념을 알고 있으면 좋습니다.'),
('Linux 메모리 관리와 I/O 관리', 'OBJECTIVES', 0, '가상 메모리, 페이지 폴트, 스왑의 관계를 설명할 수 있습니다.'),
('Linux 메모리 관리와 I/O 관리', 'OBJECTIVES', 1, 'free와 vmstat 출력을 정확히 읽고 메모리 상태를 판단할 수 있습니다.'),
('Linux 메모리 관리와 I/O 관리', 'OBJECTIVES', 2, '블로킹, 논블로킹, I/O 멀티플렉싱의 차이를 설명할 수 있습니다.'),
('Linux 메모리 관리와 I/O 관리', 'OBJECTIVES', 3, 'iostat과 iotop으로 디스크 병목을 찾아낼 수 있습니다.'),
('Linux 프로세스와 스레드 관리', 'TARGET_AUDIENCE', 0, '애플리케이션이 CPU를 과도하게 쓸 때 원인을 찾아야 하는 백엔드 개발자'),
('Linux 프로세스와 스레드 관리', 'TARGET_AUDIENCE', 1, '좀비 프로세스와 시그널 개념을 실습으로 익히고 싶은 분'),
('Linux 프로세스와 스레드 관리', 'TARGET_AUDIENCE', 2, 'systemd로 서비스를 등록하고 관리해야 하는 분'),
('Linux 프로세스와 스레드 관리', 'PREREQUISITES', 0, 'Linux 터미널 기본 명령어를 사용할 수 있어야 합니다.'),
('Linux 프로세스와 스레드 관리', 'PREREQUISITES', 1, 'Linux 또는 WSL 실습 환경을 준비하면 좋습니다.'),
('Linux 프로세스와 스레드 관리', 'OBJECTIVES', 0, 'fork와 exec로 프로세스가 만들어지는 과정을 설명할 수 있습니다.'),
('Linux 프로세스와 스레드 관리', 'OBJECTIVES', 1, '프로세스 상태와 좀비, 고아 프로세스를 구분하고 처리할 수 있습니다.'),
('Linux 프로세스와 스레드 관리', 'OBJECTIVES', 2, '시그널과 nice 값으로 프로세스를 제어할 수 있습니다.'),
('Linux 프로세스와 스레드 관리', 'OBJECTIVES', 3, 'top -H와 스레드 덤프로 CPU를 점유하는 스레드를 찾아낼 수 있습니다.'),
('OWASP, XSS, CSRF, SQL Injection, CORS', 'TARGET_AUDIENCE', 0, '내 서비스가 기본 공격에 안전한지 직접 점검하고 싶은 웹 개발자'),
('OWASP, XSS, CSRF, SQL Injection, CORS', 'TARGET_AUDIENCE', 1, '보안 취약점을 이론이 아니라 실습으로 이해하고 싶은 분'),
('OWASP, XSS, CSRF, SQL Injection, CORS', 'TARGET_AUDIENCE', 2, 'CORS 오류를 만나면 일단 모두 허용해 왔던 분'),
('OWASP, XSS, CSRF, SQL Injection, CORS', 'PREREQUISITES', 0, 'HTTP와 쿠키, HTML과 JavaScript 기본을 알고 있어야 합니다.'),
('OWASP, XSS, CSRF, SQL Injection, CORS', 'PREREQUISITES', 1, 'SQL SELECT 문을 읽을 수 있으면 좋습니다.'),
('OWASP, XSS, CSRF, SQL Injection, CORS', 'OBJECTIVES', 0, '저장형, 반사형, DOM 기반 XSS를 구분하고 방어할 수 있습니다.'),
('OWASP, XSS, CSRF, SQL Injection, CORS', 'OBJECTIVES', 1, 'CSRF 공격 원리를 이해하고 토큰과 SameSite로 방어할 수 있습니다.'),
('OWASP, XSS, CSRF, SQL Injection, CORS', 'OBJECTIVES', 2, 'SQL Injection을 재현하고 Prepared Statement로 막을 수 있습니다.'),
('OWASP, XSS, CSRF, SQL Injection, CORS', 'OBJECTIVES', 3, 'CORS의 동작 원리와 안전한 설정 기준을 설명할 수 있습니다.'),
('Swagger와 REST API 문서화', 'TARGET_AUDIENCE', 0, 'API 문서를 따로 관리하다 코드와 어긋나 곤란했던 백엔드 개발자'),
('Swagger와 REST API 문서화', 'TARGET_AUDIENCE', 1, '프론트엔드와 API 협업 속도를 높이고 싶은 분'),
('Swagger와 REST API 문서화', 'TARGET_AUDIENCE', 2, 'Swagger UI에서 인증이 필요한 API를 테스트하고 싶은 분'),
('Swagger와 REST API 문서화', 'PREREQUISITES', 0, 'Spring Boot로 REST API를 만들어 본 경험이 있어야 합니다.'),
('Swagger와 REST API 문서화', 'PREREQUISITES', 1, 'JSON과 HTTP 상태 코드의 기본을 알고 있으면 좋습니다.'),
('Swagger와 REST API 문서화', 'OBJECTIVES', 0, 'OpenAPI 명세의 구조를 이해하고 springdoc을 설정할 수 있습니다.'),
('Swagger와 REST API 문서화', 'OBJECTIVES', 1, '어노테이션으로 설명, 예시, 오류 응답을 문서에 표현할 수 있습니다.'),
('Swagger와 REST API 문서화', 'OBJECTIVES', 2, 'JWT 인증 설정과 API 그룹 분리, 노출 제한을 구성할 수 있습니다.'),
('Swagger와 REST API 문서화', 'OBJECTIVES', 3, '명세 파일로 클라이언트 타입과 목 서버를 생성해 협업에 활용할 수 있습니다.'),
('REST URI 설계와 HTTP 메서드', 'TARGET_AUDIENCE', 0, 'CRUD로 표현하기 어려운 동작의 API 이름을 매번 고민하는 개발자'),
('REST URI 설계와 HTTP 메서드', 'TARGET_AUDIENCE', 1, '팀의 API 설계 규칙을 정해야 하는 분'),
('REST URI 설계와 HTTP 메서드', 'TARGET_AUDIENCE', 2, '멱등성과 동시 수정 문제를 API 설계로 풀고 싶은 분'),
('REST URI 설계와 HTTP 메서드', 'PREREQUISITES', 0, 'HTTP 메서드와 상태 코드의 기본을 알고 있어야 합니다.'),
('REST URI 설계와 HTTP 메서드', 'PREREQUISITES', 1, 'REST API를 직접 만들어 본 경험이 있으면 좋습니다.'),
('REST URI 설계와 HTTP 메서드', 'OBJECTIVES', 0, '자원과 하위 자원, 쿼리 파라미터를 구분해 URI를 설계할 수 있습니다.'),
('REST URI 설계와 HTTP 메서드', 'OBJECTIVES', 1, '동사처럼 보이는 동작을 자원으로 모델링할 수 있습니다.'),
('REST URI 설계와 HTTP 메서드', 'OBJECTIVES', 2, '안전성과 멱등성을 고려해 메서드를 선택할 수 있습니다.'),
('REST URI 설계와 HTTP 메서드', 'OBJECTIVES', 3, 'ETag와 조건부 요청으로 동시 수정 충돌을 처리할 수 있습니다.'),
('Pull Request와 코드 리뷰 실무', 'TARGET_AUDIENCE', 0, '첫 팀 프로젝트에서 코드 리뷰를 어떻게 해야 할지 막막한 개발자'),
('Pull Request와 코드 리뷰 실무', 'TARGET_AUDIENCE', 1, 'PR이 너무 커서 리뷰가 늘 늦어지는 팀'),
('Pull Request와 코드 리뷰 실무', 'TARGET_AUDIENCE', 2, '리뷰 코멘트가 상처가 될까 봐 망설여지는 분'),
('Pull Request와 코드 리뷰 실무', 'PREREQUISITES', 0, 'Git 브랜치와 커밋, GitHub 사용법을 알고 있어야 합니다.'),
('Pull Request와 코드 리뷰 실무', 'PREREQUISITES', 1, '함께 리뷰를 주고받을 동료가 있으면 실습 효과가 큽니다.'),
('Pull Request와 코드 리뷰 실무', 'OBJECTIVES', 0, '리뷰하기 좋은 크기로 PR을 나누고 설명을 작성할 수 있습니다.'),
('Pull Request와 코드 리뷰 실무', 'OBJECTIVES', 1, '셀프 리뷰와 커밋 정리로 리뷰어의 부담을 줄일 수 있습니다.'),
('Pull Request와 코드 리뷰 실무', 'OBJECTIVES', 2, '근거와 제안이 담긴 리뷰 코멘트를 작성할 수 있습니다.'),
('Pull Request와 코드 리뷰 실무', 'OBJECTIVES', 3, '리뷰 규칙과 자동화로 팀의 리뷰 문화를 만들 수 있습니다.'),
('Git 브랜치 전략과 GitFlow', 'TARGET_AUDIENCE', 0, '팀의 브랜치 전략을 정해야 하는 개발자와 리드'),
('Git 브랜치 전략과 GitFlow', 'TARGET_AUDIENCE', 1, 'merge, squash, rebase 병합의 차이가 헷갈리는 분'),
('Git 브랜치 전략과 GitFlow', 'TARGET_AUDIENCE', 2, '릴리스와 핫픽스를 동시에 관리해야 하는 분'),
('Git 브랜치 전략과 GitFlow', 'PREREQUISITES', 0, 'Git 기본 명령어(commit, branch, merge)를 사용할 수 있어야 합니다.'),
('Git 브랜치 전략과 GitFlow', 'PREREQUISITES', 1, 'GitHub 저장소를 만들고 푸시해 본 경험이 있으면 좋습니다.'),
('Git 브랜치 전략과 GitFlow', 'OBJECTIVES', 0, 'fast-forward와 3-way 병합이 일어나는 조건을 설명할 수 있습니다.'),
('Git 브랜치 전략과 GitFlow', 'OBJECTIVES', 1, 'merge, squash, rebase 병합의 이력 차이를 비교할 수 있습니다.'),
('Git 브랜치 전략과 GitFlow', 'OBJECTIVES', 2, 'GitFlow의 릴리스와 핫픽스 흐름을 실행할 수 있습니다.'),
('Git 브랜치 전략과 GitFlow', 'OBJECTIVES', 3, '팀 상황에 맞는 브랜치 전략과 보호 규칙을 정할 수 있습니다.'),
('브라우저 요청 흐름과 HTTP 응답 구조', 'TARGET_AUDIENCE', 0, '캐시와 쿠키 설정을 근거 있게 정하고 싶은 백엔드 개발자'),
('브라우저 요청 흐름과 HTTP 응답 구조', 'TARGET_AUDIENCE', 1, '브라우저에서 생기는 문제를 서버 관점에서 분석하고 싶은 분'),
('브라우저 요청 흐름과 HTTP 응답 구조', 'TARGET_AUDIENCE', 2, 'HTTP/2와 연결 재사용의 차이를 알고 싶은 분'),
('브라우저 요청 흐름과 HTTP 응답 구조', 'PREREQUISITES', 0, 'HTTP 요청과 응답의 기본 구조를 알고 있으면 좋습니다.'),
('브라우저 요청 흐름과 HTTP 응답 구조', 'PREREQUISITES', 1, '브라우저 개발자 도구를 열어 본 경험이면 충분합니다.'),
('브라우저 요청 흐름과 HTTP 응답 구조', 'OBJECTIVES', 0, 'HTTP/1.1과 HTTP/2의 연결 방식 차이를 설명할 수 있습니다.'),
('브라우저 요청 흐름과 HTTP 응답 구조', 'OBJECTIVES', 1, '요청과 응답 헤더가 브라우저 동작에 주는 영향을 설명할 수 있습니다.'),
('브라우저 요청 흐름과 HTTP 응답 구조', 'OBJECTIVES', 2, 'Cache-Control과 ETag로 캐시 전략을 설계할 수 있습니다.'),
('브라우저 요청 흐름과 HTTP 응답 구조', 'OBJECTIVES', 3, '리다이렉트, 쿠키, 압축 응답을 올바르게 구성할 수 있습니다.');

INSERT INTO seed_course_curriculum (course_title, section_order, section_title, section_description, lesson_order, lesson_title, lesson_description) VALUES
('인터페이스, 제네릭, 컬렉션 실전', 1, '인터페이스와 제네릭', '역할 정의와 타입 안전한 코드를 정리합니다.', 1, '인터페이스로 역할 정의하기', '인터페이스로 역할을 정의하고 구현을 교체하는 방법, default 메서드와 함수형 인터페이스를 다룹니다.'),
('인터페이스, 제네릭, 컬렉션 실전', 1, '인터페이스와 제네릭', '역할 정의와 타입 안전한 코드를 정리합니다.', 2, '제네릭과 와일드카드', '제네릭 클래스와 메서드, 타입 소거, extends와 super 와일드카드를 언제 쓰는지 예제로 정리합니다.'),
('인터페이스, 제네릭, 컬렉션 실전', 2, '컬렉션 제대로 쓰기', '컬렉션 구현체의 내부와 정렬, 가공 방법을 다룹니다.', 1, 'List, Set, Map 구현체 비교', 'ArrayList와 LinkedList, HashSet과 TreeSet, HashMap과 LinkedHashMap의 내부 구조와 시간 복잡도를 비교합니다.'),
('인터페이스, 제네릭, 컬렉션 실전', 2, '컬렉션 제대로 쓰기', '컬렉션 구현체의 내부와 정렬, 가공 방법을 다룹니다.', 2, '정렬과 스트림으로 컬렉션 가공하기', 'Comparable과 Comparator로 정렬하고, 스트림의 filter, map, groupingBy로 데이터를 가공합니다.'),
('Java OOP와 상속 설계', 1, '객체와 상속의 기본', '책임, 캡슐화, 상속과 추상 클래스를 정리합니다.', 1, '객체의 책임과 캡슐화', '데이터가 아니라 책임 중심으로 객체를 설계하고, 캡슐화로 객체의 불변식을 지키는 방법을 다룹니다.'),
('Java OOP와 상속 설계', 1, '객체와 상속의 기본', '책임, 캡슐화, 상속과 추상 클래스를 정리합니다.', 2, '상속, 재정의, 추상 클래스', '메서드 재정의와 super 호출, 추상 클래스로 공통 흐름을 정의하는 방법을 예제로 익힙니다.'),
('Java OOP와 상속 설계', 2, '상속의 함정과 대안', '상속이 깨지는 사례와 조합, 위임을 다룹니다.', 1, '상속이 캡슐화를 깨뜨리는 사례', '부모 구현이 바뀌어 자식이 깨지는 사례와 is-a 관계를 잘못 판단한 설계를 분석합니다.'),
('Java OOP와 상속 설계', 2, '상속의 함정과 대안', '상속이 깨지는 사례와 조합, 위임을 다룹니다.', 2, '조합과 위임, final로 확장 제한하기', '상속 구조를 조합과 위임으로 바꾸고, 확장을 의도하지 않은 클래스에 final을 붙이는 이유를 정리합니다.'),
('Linux 메모리 관리와 I/O 관리', 1, '메모리 관리', '가상 메모리와 캐시, OOM을 명령어로 확인합니다.', 1, '가상 메모리, 페이지 폴트, 스왑', '프로세스마다 독립된 주소 공간을 갖는 원리와 페이지 폴트, 스왑이 성능에 주는 영향을 정리합니다.'),
('Linux 메모리 관리와 I/O 관리', 1, '메모리 관리', '가상 메모리와 캐시, OOM을 명령어로 확인합니다.', 2, '페이지 캐시와 OOM Killer, free 읽기', 'buff/cache와 available의 의미, OOM Killer가 프로세스를 고르는 기준을 free와 dmesg로 확인합니다.'),
('Linux 메모리 관리와 I/O 관리', 2, 'I/O 관리', '파일 I/O와 I/O 모델, 디스크 병목 진단을 다룹니다.', 1, '파일 디스크립터와 I/O 모델', '시스템 콜과 파일 디스크립터, 블로킹과 논블로킹, select와 epoll의 차이를 정리합니다.'),
('Linux 메모리 관리와 I/O 관리', 2, 'I/O 관리', '파일 I/O와 I/O 모델, 디스크 병목 진단을 다룹니다.', 2, 'iostat, iotop으로 디스크 병목 찾기', 'await, util 같은 지표를 읽고 디스크를 많이 쓰는 프로세스를 찾아내는 절차를 따라갑니다.'),
('Linux 프로세스와 스레드 관리', 1, '프로세스의 일생', '프로세스 생성, 상태, 시그널을 관찰합니다.', 1, 'fork, exec와 프로세스 상태', '프로세스가 복제되고 새 프로그램으로 바뀌는 과정과 R, S, D, Z 상태를 ps와 pstree로 확인합니다.'),
('Linux 프로세스와 스레드 관리', 1, '프로세스의 일생', '프로세스 생성, 상태, 시그널을 관찰합니다.', 2, '좀비, 고아 프로세스와 시그널', '부모가 자식을 회수하지 않을 때 생기는 좀비와 고아 프로세스, SIGTERM과 SIGKILL 처리를 다룹니다.'),
('Linux 프로세스와 스레드 관리', 2, '스레드와 스케줄링', '스레드 관찰과 스케줄링, 서비스 관리를 다룹니다.', 1, '스레드와 스케줄링, nice 값', '스레드가 프로세스 자원을 공유하는 방식, 스케줄러와 nice 값으로 우선순위를 조정하는 방법을 정리합니다.'),
('Linux 프로세스와 스레드 관리', 2, '스레드와 스케줄링', '스레드 관찰과 스케줄링, 서비스 관리를 다룹니다.', 2, 'CPU 점유 스레드 찾기와 systemd', 'top -H로 스레드 ID를 찾고 스레드 덤프와 대조하는 방법, systemd로 서비스를 등록하고 재시작하는 방법을 다룹니다.'),
('OWASP, XSS, CSRF, SQL Injection, CORS', 1, '브라우저를 노리는 공격', 'XSS와 CSRF를 재현하고 방어합니다.', 1, 'OWASP Top 10과 XSS 세 가지 유형', '저장형, 반사형, DOM 기반 XSS를 취약한 예제로 재현하고 출력 인코딩과 CSP로 방어합니다.'),
('OWASP, XSS, CSRF, SQL Injection, CORS', 1, '브라우저를 노리는 공격', 'XSS와 CSRF를 재현하고 방어합니다.', 2, 'CSRF 재현과 토큰, SameSite 방어', '로그인된 사용자의 쿠키를 악용하는 요청 위조를 재현하고 CSRF 토큰과 SameSite 쿠키로 막습니다.'),
('OWASP, XSS, CSRF, SQL Injection, CORS', 2, '서버와 설정을 노리는 공격', 'SQL Injection과 CORS 설정 문제를 다룹니다.', 1, 'SQL Injection 재현과 방어', '로그인 우회와 UNION 기반 데이터 탈취를 재현하고 Prepared Statement와 ORM 사용 시 주의점을 정리합니다.'),
('OWASP, XSS, CSRF, SQL Injection, CORS', 2, '서버와 설정을 노리는 공격', 'SQL Injection과 CORS 설정 문제를 다룹니다.', 2, 'CORS 동작 원리와 잘못된 설정', '단순 요청과 프리플라이트 요청, 자격 증명을 포함한 요청에서 와일드카드 출처가 위험한 이유를 다룹니다.'),
('Swagger와 REST API 문서화', 1, '코드로 문서 만들기', 'OpenAPI 구조와 springdoc 어노테이션을 다룹니다.', 1, 'OpenAPI 명세 구조와 springdoc 설정', 'paths, components, schemas로 이뤄진 명세 구조와 springdoc-openapi 기본 설정을 정리합니다.'),
('Swagger와 REST API 문서화', 1, '코드로 문서 만들기', 'OpenAPI 구조와 springdoc 어노테이션을 다룹니다.', 2, '@Operation, @Schema로 설명과 예시 달기', '엔드포인트 설명, 파라미터, 요청과 응답 예시, 공통 오류 응답을 문서에 표현합니다.'),
('Swagger와 REST API 문서화', 2, '문서를 협업에 활용하기', '인증, 그룹, 노출 제한과 협업 흐름을 다룹니다.', 1, 'JWT 인증 설정과 API 그룹 분리', 'Swagger UI에서 Bearer 토큰으로 테스트하는 설정과 관리자, 사용자 API 그룹 분리를 다룹니다.'),
('Swagger와 REST API 문서화', 2, '문서를 협업에 활용하기', '인증, 그룹, 노출 제한과 협업 흐름을 다룹니다.', 2, '운영 노출 제한과 명세 기반 협업', '운영 환경에서 문서를 숨기는 방법과 명세 파일로 프론트엔드 타입, 목 서버를 생성하는 흐름을 정리합니다.'),
('REST URI 설계와 HTTP 메서드', 1, '자원 모델링', 'URI 규칙과 동작을 자원으로 표현하는 방법을 다룹니다.', 1, 'URI 규칙과 하위 자원, 쿼리 파라미터', '컬렉션과 단일 자원, 하위 자원 경로와 필터링용 쿼리 파라미터를 구분하는 기준을 정리합니다.'),
('REST URI 설계와 HTTP 메서드', 1, '자원 모델링', 'URI 규칙과 동작을 자원으로 표현하는 방법을 다룹니다.', 2, '동사처럼 보이는 동작을 자원으로 바꾸기', '로그인, 좋아요, 결제 취소 같은 동작을 세션, 좋아요, 취소 요청 자원으로 모델링하는 사례를 다룹니다.'),
('REST URI 설계와 HTTP 메서드', 2, '메서드와 상태 코드 선택', '메서드 성질과 동시 수정, 상태 코드를 사례로 정리합니다.', 1, '안전성, 멱등성과 메서드 선택', 'PUT, PATCH, POST를 고르는 기준과 재시도 가능한 API를 만들기 위한 멱등 키 설계를 다룹니다.'),
('REST URI 설계와 HTTP 메서드', 2, '메서드와 상태 코드 선택', '메서드 성질과 동시 수정, 상태 코드를 사례로 정리합니다.', 2, '조건부 요청과 상황별 상태 코드', 'ETag와 If-Match로 동시 수정 충돌을 막고 409, 412, 422 같은 상태 코드를 고르는 기준을 정리합니다.'),
('Pull Request와 코드 리뷰 실무', 1, '리뷰하기 좋은 PR 만들기', 'PR 크기, 설명, 셀프 리뷰를 다룹니다.', 1, 'PR을 작게 나누는 기준', '기능, 리팩터링, 포맷 변경을 분리하고 리뷰 가능한 크기로 PR을 나누는 기준을 정리합니다.'),
('Pull Request와 코드 리뷰 실무', 1, '리뷰하기 좋은 PR 만들기', 'PR 크기, 설명, 셀프 리뷰를 다룹니다.', 2, 'PR 설명 작성과 셀프 리뷰', '변경 이유, 변경 내용, 테스트 방법, 확인 요청 사항을 담은 PR 설명과 셀프 리뷰 체크리스트를 만듭니다.'),
('Pull Request와 코드 리뷰 실무', 2, '함께 성장하는 코드 리뷰', '리뷰 우선순위와 코멘트 작성, 합의 과정을 다룹니다.', 1, '리뷰 우선순위와 좋은 코멘트', '설계와 정확성을 먼저 보고 스타일은 도구에 맡기는 우선순위, 근거와 대안을 담은 코멘트 작성법을 다룹니다.'),
('Pull Request와 코드 리뷰 실무', 2, '함께 성장하는 코드 리뷰', '리뷰 우선순위와 코멘트 작성, 합의 과정을 다룹니다.', 2, '의견 조율과 리뷰 자동화', '의견이 갈릴 때 합의하는 방법과 CI, 린트, PR 템플릿으로 리뷰 부담을 줄이는 방법을 정리합니다.'),
('Git 브랜치 전략과 GitFlow', 1, '병합 방식 이해하기', '브랜치 구조와 병합 방식별 이력 차이를 비교합니다.', 1, '브랜치의 실체와 fast-forward, 3-way 병합', '브랜치가 커밋을 가리키는 포인터라는 점과 병합 방식이 결정되는 조건을 그림과 명령어로 확인합니다.'),
('Git 브랜치 전략과 GitFlow', 1, '병합 방식 이해하기', '브랜치 구조와 병합 방식별 이력 차이를 비교합니다.', 2, 'merge, squash, rebase 병합 비교', '세 가지 병합 방식이 이력에 남기는 모습과 각각을 선택하는 기준을 비교합니다.'),
('Git 브랜치 전략과 GitFlow', 2, '팀 브랜치 전략', 'GitFlow와 대안 전략, 보호 규칙을 다룹니다.', 1, 'GitFlow 릴리스와 핫픽스 흐름', 'develop에서 release를 분기해 안정화하고, 운영 장애는 hotfix로 처리해 양쪽에 병합하는 흐름을 실습합니다.'),
('Git 브랜치 전략과 GitFlow', 2, '팀 브랜치 전략', 'GitFlow와 대안 전략, 보호 규칙을 다룹니다.', 2, 'GitHub Flow, 트렁크 기반 개발과 보호 규칙', '배포 주기와 팀 규모에 따라 전략을 고르는 기준, 브랜치 보호 규칙과 버전 태그 관리를 정리합니다.'),
('브라우저 요청 흐름과 HTTP 응답 구조', 1, '요청이 만들어지는 과정', '브라우저의 연결 방식과 요청, 응답 구조를 정리합니다.', 1, '브라우저의 연결 재사용과 HTTP/2', 'Keep-Alive와 연결 재사용, HTTP/2의 멀티플렉싱이 페이지 로딩에 주는 영향을 정리합니다.'),
('브라우저 요청 흐름과 HTTP 응답 구조', 1, '요청이 만들어지는 과정', '브라우저의 연결 방식과 요청, 응답 구조를 정리합니다.', 2, '요청 헤더와 응답 구조 해부', 'Cookie, Accept, Authorization 같은 요청 헤더와 상태 줄, 응답 헤더, 바디의 구조를 실제 요청으로 확인합니다.'),
('브라우저 요청 흐름과 HTTP 응답 구조', 2, '응답이 화면이 되기까지', '캐시, 리다이렉트, 쿠키, 렌더링을 백엔드 관점에서 다룹니다.', 1, 'Cache-Control과 ETag로 캐시 제어', 'max-age, no-cache, no-store의 차이와 ETag 기반 재검증으로 304 응답을 만드는 방법을 정리합니다.'),
('브라우저 요청 흐름과 HTTP 응답 구조', 2, '응답이 화면이 되기까지', '캐시, 리다이렉트, 쿠키, 렌더링을 백엔드 관점에서 다룹니다.', 2, '리다이렉트, 쿠키 설정, 압축과 렌더링', '301과 302, Set-Cookie 속성, gzip 압축과 Content-Type이 브라우저 렌더링에 주는 영향을 다룹니다.');

INSERT INTO seed_course_quiz (course_title, quiz_title, quiz_description, lesson_title, lesson_description) VALUES
('인터페이스, 제네릭, 컬렉션 실전', '인터페이스와 제네릭 퀴즈', '인터페이스 활용과 제네릭, 와일드카드를 점검합니다.', '섹션 퀴즈: 인터페이스와 제네릭', '타입 안전한 코드 작성법을 5문항으로 점검합니다.'),
('Java OOP와 상속 설계', '객체와 상속 기본 퀴즈', '책임, 캡슐화, 재정의, 추상 클래스를 점검합니다.', '섹션 퀴즈: 객체와 상속의 기본', '상속 문법과 설계 개념을 5문항으로 점검합니다.'),
('Linux 메모리 관리와 I/O 관리', '메모리 관리 점검 퀴즈', '가상 메모리, 페이지 캐시, OOM, free 출력 해석을 점검합니다.', '섹션 퀴즈: 메모리 관리', '메모리 상태를 바르게 해석하는 능력을 5문항으로 점검합니다.'),
('Linux 프로세스와 스레드 관리', '프로세스의 일생 퀴즈', 'fork와 exec, 프로세스 상태, 좀비와 시그널을 점검합니다.', '섹션 퀴즈: 프로세스의 일생', '프로세스 생성과 종료 과정을 5문항으로 점검합니다.'),
('OWASP, XSS, CSRF, SQL Injection, CORS', '브라우저 공격 방어 퀴즈', 'XSS와 CSRF의 원리와 방어법을 점검합니다.', '섹션 퀴즈: 브라우저를 노리는 공격', '공격 시나리오와 방어 수단을 연결하는 문제 5문항입니다.'),
('Swagger와 REST API 문서화', 'OpenAPI 문서화 퀴즈', 'OpenAPI 구조와 springdoc 어노테이션을 점검합니다.', '섹션 퀴즈: 코드로 문서 만들기', '코드 기반 API 문서화 방법을 5문항으로 점검합니다.'),
('REST URI 설계와 HTTP 메서드', '자원 모델링 퀴즈', 'URI 규칙과 동작을 자원으로 표현하는 방법을 점검합니다.', '섹션 퀴즈: 자원 모델링', '헷갈리는 동작의 URI 설계를 5문항으로 점검합니다.'),
('Pull Request와 코드 리뷰 실무', '리뷰하기 좋은 PR 퀴즈', 'PR 크기, 설명, 셀프 리뷰의 기준을 점검합니다.', '섹션 퀴즈: 리뷰하기 좋은 PR 만들기', '좋은 PR의 조건을 5문항으로 점검합니다.'),
('Git 브랜치 전략과 GitFlow', '병합 방식 점검 퀴즈', 'fast-forward, 3-way, squash, rebase 병합을 점검합니다.', '섹션 퀴즈: 병합 방식 이해하기', '병합 방식별 이력 차이를 5문항으로 점검합니다.'),
('브라우저 요청 흐름과 HTTP 응답 구조', '요청과 응답 구조 퀴즈', '연결 재사용, HTTP/2, 요청과 응답 헤더를 점검합니다.', '섹션 퀴즈: 요청이 만들어지는 과정', '브라우저 요청 구조를 5문항으로 점검합니다.');

INSERT INTO seed_course_quiz_question (course_title, display_order, question_text, explanation, correct_option, option1, option2, option3, option4) VALUES
('인터페이스, 제네릭, 컬렉션 실전', 1, '변수 타입을 ArrayList<String> 대신 List<String>으로 선언하는 이유로 가장 적절한 것은 무엇인가요?', '인터페이스 타입으로 선언하면 사용하는 코드를 바꾸지 않고 구현체를 LinkedList 등으로 교체할 수 있습니다.', 2, 'ArrayList가 곧 사라질 예정이라서', '사용 코드를 바꾸지 않고 구현체를 교체할 수 있어서', '실행 속도가 항상 빨라서', '메모리를 절반만 사용해서'),
('인터페이스, 제네릭, 컬렉션 실전', 2, '제네릭을 사용했을 때 얻는 가장 큰 이점은 무엇인가요?', '제네릭은 잘못된 타입이 들어가는 것을 컴파일 시점에 막고, 꺼낼 때 형변환을 하지 않아도 되게 합니다.', 1, '컴파일 시점에 타입 오류를 잡고 형변환을 줄인다', '런타임에 타입 정보를 더 많이 남긴다', '모든 타입을 Object로 바꾼다', '컬렉션 크기를 자동으로 늘린다'),
('인터페이스, 제네릭, 컬렉션 실전', 3, 'List<? extends Number> 타입의 리스트에 대한 설명으로 올바른 것은 무엇인가요?', 'extends 와일드카드는 읽기 전용에 가깝습니다. 원소를 Number로 꺼낼 수는 있지만 정확한 타입을 모르므로 null 외에는 추가할 수 없습니다.', 4, 'Integer를 자유롭게 추가할 수 있다', 'Number의 상위 타입만 담긴다', 'String도 담을 수 있다', '원소를 Number로 읽을 수 있지만 새 원소는 추가할 수 없다'),
('인터페이스, 제네릭, 컬렉션 실전', 4, '런타임에 List<String>과 List<Integer>를 구분할 수 없는 이유는 무엇인가요?', '제네릭 타입 정보는 컴파일 후 지워지는 타입 소거 때문에 런타임에는 둘 다 List로만 남습니다.', 3, '두 리스트가 같은 메모리를 공유해서', 'JVM이 제네릭을 지원하지 않아서', '타입 소거로 런타임에는 제네릭 타입 정보가 사라져서', '리스트가 비어 있어서'),
('인터페이스, 제네릭, 컬렉션 실전', 5, '함수형 인터페이스의 조건으로 올바른 것은 무엇인가요?', '함수형 인터페이스는 추상 메서드가 정확히 하나여야 하며, 그래서 람다로 구현할 수 있습니다. default 메서드는 여러 개 있어도 됩니다.', 2, 'default 메서드가 하나도 없어야 한다', '추상 메서드가 정확히 하나여야 한다', '반드시 제네릭이어야 한다', '클래스에서만 선언할 수 있다'),
('Java OOP와 상속 설계', 1, '은행 계좌 객체의 잔액이 음수가 되지 않도록 보장하는 가장 좋은 방법은 무엇인가요?', '잔액 필드를 감추고 출금 메서드 안에서 규칙을 검사하면 어떤 경로로도 잘못된 상태가 될 수 없습니다.', 3, '잔액 필드를 public으로 두고 사용하는 쪽에서 검사한다', '잔액에 setter를 열어 둔다', '잔액을 감추고 출금 메서드 안에서 규칙을 검사한다', '주석으로 음수 금지를 적어 둔다'),
('Java OOP와 상속 설계', 2, '자식 클래스에서 부모 메서드를 재정의하면서 부모의 원래 동작도 실행하고 싶을 때 쓰는 키워드는 무엇인가요?', 'super.메서드()로 부모의 구현을 호출한 뒤 자식만의 동작을 덧붙일 수 있습니다.', 1, 'super', 'this', 'static', 'final'),
('Java OOP와 상속 설계', 3, '추상 클래스가 인터페이스보다 적합한 상황은 무엇인가요?', '여러 하위 클래스가 공유하는 상태(필드)나 공통 구현, 고정된 처리 흐름이 있을 때 추상 클래스가 적합합니다.', 4, '서로 관련 없는 클래스들이 같은 기능을 가질 때', '다중 구현이 필요할 때', '람다로 구현하고 싶을 때', '하위 클래스들이 공통 상태와 처리 흐름을 공유할 때'),
('Java OOP와 상속 설계', 4, '메서드 재정의(오버라이딩) 시 지켜야 할 규칙으로 올바른 것은 무엇인가요?', '재정의 메서드는 부모보다 접근 범위를 좁힐 수 없습니다. 이름과 매개변수는 같아야 하며 @Override로 실수를 막을 수 있습니다.', 2, '접근 제어자를 부모보다 좁게 바꿀 수 있다', '접근 범위를 부모보다 좁힐 수 없다', '매개변수 개수를 바꿔도 재정의가 된다', 'static 메서드도 재정의된다'),
('Java OOP와 상속 설계', 5, '자동차와 엔진의 관계를 표현하는 방법으로 가장 적절한 것은 무엇인가요?', '자동차는 엔진이 아니라 엔진을 가지는 관계(has-a)이므로 상속이 아니라 필드로 포함하는 조합이 맞습니다.', 1, '자동차가 엔진을 필드로 가지는 조합', '자동차가 엔진을 상속', '엔진이 자동차를 상속', '둘을 하나의 클래스로 합침'),
('Linux 메모리 관리와 I/O 관리', 1, 'free 명령에서 free 값은 작지만 available 값이 충분히 크다면 어떻게 해석해야 하나요?', 'Linux는 남는 메모리를 페이지 캐시로 활용하며, 필요하면 캐시를 비워 쓸 수 있으므로 available이 실제로 쓸 수 있는 양에 가깝습니다.', 2, '메모리가 곧 바닥나므로 즉시 증설해야 한다', '캐시로 쓰이는 메모리가 많을 뿐 실제로 쓸 수 있는 메모리는 충분하다', '스왑이 고장 났다', 'free 명령이 잘못된 값을 보여 준다'),
('Linux 메모리 관리와 I/O 관리', 2, '접근하려는 페이지가 물리 메모리에 없어 디스크에서 읽어 와야 하는 상황을 무엇이라 하나요?', '메이저 페이지 폴트는 페이지를 디스크에서 읽어 와야 하는 경우로, 비용이 크며 많아지면 성능이 크게 떨어집니다.', 4, '컨텍스트 스위칭', '데드락', '캐시 히트', '메이저 페이지 폴트'),
('Linux 메모리 관리와 I/O 관리', 3, '스왑 사용량이 계속 늘고 si, so 값이 높게 유지된다면 어떤 상황인가요?', '스왑 인, 아웃이 계속 일어나면 물리 메모리가 부족해 디스크와 메모리 사이를 오가는 상황으로 응답이 크게 느려집니다.', 1, '물리 메모리가 부족해 디스크와 메모리 사이 교환이 잦다', '디스크가 너무 빠르다', 'CPU가 놀고 있다', '네트워크 대역폭이 부족하다'),
('Linux 메모리 관리와 I/O 관리', 4, 'OOM Killer가 동작했는지 확인할 때 가장 먼저 볼 곳은 어디인가요?', 'OOM Killer가 프로세스를 종료하면 커널 로그에 기록되므로 dmesg나 journalctl -k에서 확인할 수 있습니다.', 3, '애플리케이션 접속 로그', 'crontab 설정', 'dmesg 같은 커널 로그', '/etc/hosts 파일'),
('Linux 메모리 관리와 I/O 관리', 5, '각 프로세스가 독립된 가상 주소 공간을 가져서 얻는 이점은 무엇인가요?', '가상 주소 공간 덕분에 프로세스끼리 메모리를 침범하지 못하고, 각자 연속된 메모리를 쓰는 것처럼 프로그래밍할 수 있습니다.', 2, '모든 프로세스가 같은 변수를 공유한다', '다른 프로세스의 메모리를 침범할 수 없고 연속된 공간처럼 쓸 수 있다', '디스크를 쓰지 않아도 된다', 'CPU 캐시가 필요 없어진다'),
('Linux 프로세스와 스레드 관리', 1, 'fork() 호출 직후의 상태로 올바른 것은 무엇인가요?', 'fork는 현재 프로세스를 복제해 자식 프로세스를 만들고, 부모와 자식은 같은 코드의 다음 줄부터 각자 실행됩니다.', 3, '부모 프로세스가 종료된다', '새 프로그램이 즉시 실행된다', '부모를 복제한 자식 프로세스가 생겨 둘 다 다음 코드부터 실행된다', '스레드가 하나 추가된다'),
('Linux 프로세스와 스레드 관리', 2, 'exec 계열 함수의 역할은 무엇인가요?', 'exec는 현재 프로세스의 메모리 이미지를 새 프로그램으로 교체합니다. PID는 그대로 유지됩니다.', 1, '현재 프로세스를 새 프로그램으로 교체한다', '프로세스를 복제한다', '프로세스를 종료한다', '프로세스 우선순위를 바꾼다'),
('Linux 프로세스와 스레드 관리', 3, 'ps 출력에서 상태가 Z로 표시되는 프로세스는 무엇인가요?', '좀비 프로세스는 이미 종료했지만 부모가 종료 상태를 회수(wait)하지 않아 프로세스 테이블에 남아 있는 상태입니다.', 4, '실행 중인 프로세스', '디스크 I/O를 기다리는 프로세스', '일시 정지된 프로세스', '종료했지만 부모가 회수하지 않은 좀비 프로세스'),
('Linux 프로세스와 스레드 관리', 4, '좀비 프로세스를 정리하는 올바른 방법은 무엇인가요?', '좀비는 이미 죽은 상태라 kill로 지울 수 없습니다. 부모가 wait로 회수하거나, 부모를 종료해 init이 입양 후 회수하게 해야 합니다.', 2, '좀비 프로세스에 kill -9를 보낸다', '부모 프로세스가 회수하게 하거나 부모를 종료한다', '서버 디스크를 비운다', '좀비의 nice 값을 낮춘다'),
('Linux 프로세스와 스레드 관리', 5, '애플리케이션이 SIGTERM을 받았을 때 바람직한 동작은 무엇인가요?', 'SIGTERM은 정상 종료 요청이므로 처리 중인 요청을 마무리하고 자원을 정리한 뒤 종료하는 그레이스풀 셧다운을 해야 합니다.', 1, '처리 중인 작업을 마무리하고 자원을 정리한 뒤 종료한다', '신호를 무시하고 계속 실행한다', '즉시 모든 작업을 버리고 종료한다', '자식 프로세스를 더 만든다'),
('OWASP, XSS, CSRF, SQL Injection, CORS', 1, '게시글 본문에 저장된 스크립트가 다른 사용자가 글을 볼 때마다 실행되는 공격은 무엇인가요?', '악성 스크립트가 서버에 저장되어 조회하는 모든 사용자에게 실행되는 것은 저장형 XSS입니다.', 2, '반사형 XSS', '저장형 XSS', 'CSRF', 'SQL Injection'),
('OWASP, XSS, CSRF, SQL Injection, CORS', 2, 'XSS를 막는 가장 기본적인 방법은 무엇인가요?', '사용자 입력을 HTML에 출력할 때 특수문자를 인코딩하면 스크립트가 코드가 아닌 문자로 표시됩니다.', 3, '모든 요청을 POST로 바꾼다', 'HTTPS를 적용한다', '출력할 때 HTML 특수문자를 인코딩한다', '비밀번호를 해시로 저장한다'),
('OWASP, XSS, CSRF, SQL Injection, CORS', 3, 'Content-Security-Policy 헤더가 XSS 피해를 줄이는 방식은 무엇인가요?', 'CSP는 허용한 출처의 스크립트만 실행되게 하고 인라인 스크립트를 막아, 주입된 스크립트가 실행되기 어렵게 만듭니다.', 1, '허용된 출처의 스크립트만 실행되도록 제한한다', '쿠키를 암호화한다', '서버 요청 수를 제한한다', 'SQL 쿼리를 검사한다'),
('OWASP, XSS, CSRF, SQL Injection, CORS', 4, 'CSRF 공격이 성립하는 핵심 조건은 무엇인가요?', '브라우저가 다른 사이트에서 시작된 요청에도 대상 사이트의 쿠키를 자동으로 붙여 보내기 때문에, 사용자 의도와 무관한 요청이 인증된 채로 처리됩니다.', 4, '서버가 SQL을 문자열로 만든다', '비밀번호가 짧다', '서버가 HTTP를 사용한다', '브라우저가 다른 사이트에서 시작된 요청에도 쿠키를 자동으로 보낸다'),
('OWASP, XSS, CSRF, SQL Injection, CORS', 5, 'CSRF 토큰이 공격을 막을 수 있는 이유는 무엇인가요?', '공격 사이트는 대상 사이트의 페이지에 담긴 토큰 값을 읽을 수 없으므로, 토큰이 필요한 요청을 위조할 수 없습니다.', 2, '토큰이 쿠키를 삭제하기 때문에', '공격자 사이트가 대상 사이트 페이지의 토큰 값을 알 수 없기 때문에', '토큰이 요청을 암호화하기 때문에', '토큰이 서버 포트를 바꾸기 때문에'),
('Swagger와 REST API 문서화', 1, '코드에서 API 문서를 생성하는 방식의 가장 큰 장점은 무엇인가요?', '문서가 코드에서 만들어지므로 구현이 바뀌면 문서도 함께 바뀌어 문서와 코드가 어긋나지 않습니다.', 1, '구현이 바뀌면 문서도 함께 바뀌어 어긋나지 않는다', '문서를 작성할 필요가 전혀 없다', 'API 성능이 좋아진다', '보안 취약점이 사라진다'),
('Swagger와 REST API 문서화', 2, 'OpenAPI 명세에서 여러 API가 함께 쓰는 요청, 응답 모델을 정의하는 곳은 어디인가요?', '공통 모델은 components.schemas에 정의하고 각 API에서 참조해 중복을 줄입니다.', 3, 'info', 'servers', 'components.schemas', 'tags'),
('Swagger와 REST API 문서화', 3, 'DTO 필드에 설명과 예시 값을 표시하려면 어떤 어노테이션을 쓰나요?', '@Schema의 description, example 속성으로 필드 설명과 예시를 문서에 표시합니다.', 2, '@Operation', '@Schema', '@Tag', '@Hidden'),
('Swagger와 REST API 문서화', 4, '컨트롤러 메서드에 API 요약과 상세 설명을 다는 어노테이션은 무엇인가요?', '@Operation의 summary와 description으로 엔드포인트 단위 설명을 작성합니다.', 4, '@Schema', '@Parameter', '@ApiResponse만 단독 사용', '@Operation'),
('Swagger와 REST API 문서화', 5, '문서에 성공 응답만 있고 오류 응답이 없으면 생기는 문제는 무엇인가요?', '클라이언트는 오류 형식을 알아야 화면을 처리할 수 있으므로, 오류 응답이 없으면 실제 연동 시 코드를 열어 보거나 직접 호출해 봐야 합니다.', 3, '서버가 시작되지 않는다', '성공 응답이 표시되지 않는다', '클라이언트가 오류 처리 방법을 문서에서 알 수 없다', 'Swagger UI가 느려진다'),
('REST URI 설계와 HTTP 메서드', 1, '특정 회원의 주문 목록을 표현하는 URI로 가장 적절한 것은 무엇인가요?', '주문이 회원에 종속된 하위 자원이라면 /members/{id}/orders처럼 계층으로 표현합니다.', 2, '/getMemberOrders/{id}', '/members/{id}/orders', '/orders/member/list/{id}/get', '/memberorders?action=list&id={id}'),
('REST URI 설계와 HTTP 메서드', 2, '상품 목록을 가격순으로 정렬하고 카테고리로 거르는 조건은 어디에 두는 것이 좋나요?', '정렬과 필터는 자원을 식별하는 것이 아니라 표현 방식을 바꾸는 조건이므로 쿼리 파라미터가 적합합니다.', 1, '쿼리 파라미터 (/products?category=book&sort=price)', '경로 (/products/book/price)', '요청 바디', '응답 헤더'),
('REST URI 설계와 HTTP 메서드', 3, '게시글 좋아요 기능을 자원 중심으로 설계한 것으로 가장 적절한 것은 무엇인가요?', '좋아요를 게시글의 하위 자원으로 보고 생성은 PUT 또는 POST, 취소는 DELETE로 표현하면 동사 URI 없이 동작을 나타낼 수 있습니다.', 4, 'POST /posts/{id}/doLike', 'GET /likePost?id={id}', 'POST /posts/like/{id}/true', 'PUT /posts/{id}/likes/me 와 DELETE /posts/{id}/likes/me'),
('REST URI 설계와 HTTP 메서드', 4, '로그인을 자원 관점으로 표현할 때 자주 쓰는 방식은 무엇인가요?', '로그인은 인증 세션(또는 토큰)을 새로 만드는 것으로 보고 POST /sessions나 POST /auth/tokens처럼 표현합니다.', 3, 'GET /login?id=..&pw=..', 'PUT /users/login', 'POST /sessions (세션이나 토큰 생성)', 'DELETE /users'),
('REST URI 설계와 HTTP 메서드', 5, 'URI에 자원 이름을 쓸 때 일반적인 규칙으로 올바른 것은 무엇인가요?', '컬렉션 자원은 복수형 명사를 쓰고, 단어 구분은 소문자와 하이픈을 쓰는 것이 일반적입니다.', 2, '동사 원형과 대문자를 쓴다', '복수형 명사와 소문자, 하이픈을 쓴다', '파일 확장자를 붙인다', '언더스코어와 대문자를 섞는다'),
('Pull Request와 코드 리뷰 실무', 1, '리뷰하기 좋은 PR의 특징으로 가장 적절한 것은 무엇인가요?', '하나의 목적에 집중한 작은 PR은 리뷰어가 맥락을 빠르게 이해하고 문제를 정확히 찾을 수 있게 합니다.', 3, '여러 기능을 한 번에 모아 수천 줄로 올린다', '설명 없이 코드만 올린다', '하나의 목적에 집중한 작은 단위로 올린다', '포맷 변경과 기능 변경을 섞는다'),
('Pull Request와 코드 리뷰 실무', 2, 'PR 설명에 가장 먼저 들어가야 할 내용은 무엇인가요?', '리뷰어는 왜 이 변경이 필요한지 알아야 코드의 판단을 평가할 수 있으므로 변경 이유와 배경이 먼저입니다.', 1, '이 변경이 필요한 이유와 배경', '작성자의 근무 시간', '사용한 IDE 이름', '커밋 해시 목록'),
('Pull Request와 코드 리뷰 실무', 3, '기능 구현 중 대규모 코드 포맷 변경이 필요해졌다면 어떻게 하는 것이 좋나요?', '포맷 변경을 별도 PR이나 커밋으로 분리하면 리뷰어가 실제 기능 변경에 집중할 수 있습니다.', 2, '기능 PR에 함께 섞어 올린다', '포맷 변경을 별도 PR이나 커밋으로 분리한다', '포맷 변경은 리뷰 없이 바로 병합한다', '포맷 도구 사용을 금지한다'),
('Pull Request와 코드 리뷰 실무', 4, 'PR을 올리기 전 셀프 리뷰의 목적으로 가장 적절한 것은 무엇인가요?', '셀프 리뷰로 디버그 코드, 오타, 빠진 테스트 같은 기본 실수를 먼저 걸러 내면 리뷰어가 중요한 문제에 집중할 수 있습니다.', 4, '리뷰어 없이 혼자 병합하기 위해', 'PR 크기를 늘리기 위해', '커밋 수를 늘리기 위해', '기본 실수를 먼저 걸러 리뷰어가 중요한 부분에 집중하게 하기 위해'),
('Pull Request와 코드 리뷰 실무', 5, '리뷰 후 수정 커밋이 여러 개 쌓였을 때 병합 전 정리 방법으로 알맞은 것은 무엇인가요?', '팀 규칙에 따라 squash 병합이나 의미 단위 커밋 정리로 이력을 깔끔하게 남길 수 있습니다.', 1, '팀 규칙에 따라 squash 병합하거나 의미 단위로 커밋을 정리한다', '수정 커밋을 모두 삭제하고 리뷰 내용을 버린다', '새 저장소로 옮긴다', '정리 없이 강제 푸시로 원격 이력을 지운다'),
('Git 브랜치 전략과 GitFlow', 1, 'main에서 분기한 뒤 main에 새 커밋이 없는 상태로 feature를 병합하면 어떤 병합이 일어나나요?', '대상 브랜치가 분기 이후 진행되지 않았다면 포인터만 앞으로 옮기는 fast-forward 병합이 일어납니다.', 2, '3-way 병합', 'fast-forward 병합', '충돌 병합', 'cherry-pick'),
('Git 브랜치 전략과 GitFlow', 2, '두 브랜치가 각자 새 커밋을 가진 상태에서 merge하면 어떻게 되나요?', '공통 조상과 두 브랜치 끝을 비교하는 3-way 병합이 일어나고, 두 부모를 가진 병합 커밋이 만들어집니다.', 3, '포인터만 이동한다', '한쪽 커밋이 삭제된다', '3-way 병합으로 병합 커밋이 만들어진다', '자동으로 rebase된다'),
('Git 브랜치 전략과 GitFlow', 3, 'squash 병합의 특징으로 올바른 것은 무엇인가요?', 'squash 병합은 브랜치의 여러 커밋을 하나로 합쳐 대상 브랜치에 남기므로 이력은 깔끔하지만 세부 커밋 기록은 사라집니다.', 1, '여러 커밋을 하나로 합쳐 대상 브랜치에 남긴다', '모든 커밋을 그대로 보존하고 병합 커밋을 추가한다', '커밋을 원격에서만 합친다', '충돌이 절대 생기지 않는다'),
('Git 브랜치 전략과 GitFlow', 4, 'Git에서 브랜치의 실체는 무엇인가요?', '브랜치는 특정 커밋을 가리키는 가벼운 포인터이며, 새 커밋을 만들면 포인터가 그 커밋으로 이동합니다.', 4, '파일 전체를 복사한 폴더', '원격 서버의 별도 저장소', '커밋 메시지 목록 파일', '특정 커밋을 가리키는 포인터'),
('Git 브랜치 전략과 GitFlow', 5, '공유 브랜치의 이력을 rebase로 바꾼 뒤 강제 푸시하면 생기는 문제는 무엇인가요?', '커밋 해시가 바뀌어 이미 그 브랜치를 받은 팀원의 이력과 어긋나, 중복 커밋이나 충돌을 일으킵니다.', 2, '저장소 용량이 줄어든다', '팀원의 로컬 이력과 어긋나 중복 커밋과 충돌이 생긴다', '태그가 자동 생성된다', '아무 문제도 없다'),
('브라우저 요청 흐름과 HTTP 응답 구조', 1, 'HTTP Keep-Alive(지속 연결)의 효과는 무엇인가요?', '하나의 TCP 연결로 여러 요청을 보내 매번 연결을 새로 맺는 비용(핸드셰이크)을 줄입니다.', 3, '응답 바디를 압축한다', '요청을 암호화한다', '하나의 연결로 여러 요청을 보내 연결 비용을 줄인다', '쿠키를 자동 삭제한다'),
('브라우저 요청 흐름과 HTTP 응답 구조', 2, 'HTTP/2가 HTTP/1.1과 비교해 가진 대표적인 특징은 무엇인가요?', 'HTTP/2는 하나의 연결에서 여러 요청과 응답을 동시에 주고받는 멀티플렉싱과 헤더 압축을 지원합니다.', 1, '하나의 연결에서 여러 요청을 동시에 처리하는 멀티플렉싱', '텍스트 기반 프로토콜로 회귀', '쿠키 사용 금지', '요청마다 새 연결 필수'),
('브라우저 요청 흐름과 HTTP 응답 구조', 3, '클라이언트가 JSON 응답을 원한다는 뜻을 서버에 전하는 요청 헤더는 무엇인가요?', 'Accept 헤더는 클라이언트가 받을 수 있는 응답 형식을 알립니다. Content-Type은 보내는 바디의 형식입니다.', 4, 'Content-Length', 'Host', 'Referer', 'Accept: application/json'),
('브라우저 요청 흐름과 HTTP 응답 구조', 4, 'HTTP 응답의 첫 줄(상태 줄)에 들어 있는 정보는 무엇인가요?', '상태 줄에는 HTTP 버전, 상태 코드, 상태 메시지가 들어 있습니다. 예: HTTP/1.1 200 OK', 2, '요청 URL과 메서드', 'HTTP 버전, 상태 코드, 상태 메시지', '쿠키 목록', '응답 바디 길이만'),
('브라우저 요청 흐름과 HTTP 응답 구조', 5, '브라우저가 같은 도메인으로 요청할 때 로그인 쿠키를 자동으로 보내는 헤더는 무엇인가요?', '브라우저는 저장된 쿠키 중 조건이 맞는 것을 Cookie 요청 헤더에 담아 자동으로 보냅니다.', 1, 'Cookie', 'Set-Cookie', 'Authorization', 'Origin');

INSERT INTO seed_course_assignment (course_title, assignment_title, assignment_description, submission_rule, lesson_title, lesson_description) VALUES
('인터페이스, 제네릭, 컬렉션 실전', '상품 재고 관리 모듈 구현',
'상황.
작은 온라인 매장의 재고 관리 모듈을 만들어야 합니다. 상품 종류가 계속 늘어나고, 다양한 기준으로 조회와 정렬이 필요합니다.

요구사항.
1. 재고 저장소를 인터페이스로 정의하고 메모리 구현체를 만드세요.
2. 상품 타입에 상관없이 재사용할 수 있는 제네릭 Repository를 설계하세요.
3. 상품 코드로 빠르게 찾기 위한 Map, 카테고리별 중복 없는 목록을 위한 Set을 사용하세요.
4. 가격순, 재고순 정렬을 Comparator로 구현하세요.
5. 스트림으로 카테고리별 재고 합계를 계산하세요.

제출물.
GitHub 저장소 URL과 자료구조 선택 이유를 정리한 README.',
'GitHub 저장소 URL을 제출하세요. README에 각 컬렉션을 고른 이유와 시간 복잡도를 정리하세요.',
'실습 과제: 상품 재고 관리 모듈 구현', '인터페이스, 제네릭, 컬렉션을 활용한 재고 관리 모듈을 제출합니다.'),
('Java OOP와 상속 설계', '결제 수단 계층 상속과 조합 비교 설계',
'상황.
쇼핑몰의 결제 수단(카드, 계좌이체, 포인트)을 객체로 설계해야 합니다. 일부 결제 수단에는 할인, 적립 같은 부가 기능이 붙습니다.

요구사항.
1. 상속만 사용해 결제 수단 계층을 설계하세요.
2. 같은 요구사항을 조합과 위임으로 다시 설계하세요.
3. 할인과 적립을 함께 적용하는 결제를 두 설계에서 각각 구현하세요.
4. 새 부가 기능이 추가될 때 두 설계의 변경 범위를 비교하세요.
5. 객체의 불변식(예: 결제 금액은 0보다 커야 함)을 캡슐화로 보장하세요.

제출물.
GitHub 저장소 URL과 두 설계의 장단점 비교 문서.',
'GitHub 저장소 URL을 제출하세요. README에 두 설계의 클래스 구조와 변경 범위 비교를 표로 정리하세요.',
'실습 과제: 결제 수단 상속과 조합 비교 설계', '같은 요구사항을 상속과 조합으로 설계하고 비교한 결과를 제출합니다.'),
('Linux 메모리 관리와 I/O 관리', '메모리, I/O 문제 재현과 진단 보고서',
'상황.
운영 서버에서 메모리 사용량 경고와 디스크 지연 알림이 번갈아 발생합니다. 실제와 비슷한 상황을 재현해 진단 절차를 정리해야 합니다.

요구사항.
1. 메모리를 계속 할당하는 프로그램이나 stress 도구로 메모리 부족 상황을 만드세요.
2. free, vmstat으로 메모리와 스왑 변화를 기록하고 해석하세요.
3. 대용량 파일 쓰기로 디스크 부하를 만들고 iostat, iotop으로 원인 프로세스를 찾으세요.
4. 페이지 캐시가 파일 읽기 속도에 주는 영향을 측정하세요.
5. 상황별 진단 순서를 체크리스트로 정리하세요.

제출물.
명령어 출력과 해석이 담긴 진단 보고서.',
'진단 보고서(마크다운 또는 PDF)를 첨부하세요. 명령어 출력은 핵심 부분만 발췌하고 해석을 함께 적으세요.',
'실습 과제: 메모리, I/O 문제 재현과 진단', '메모리 부족과 디스크 병목을 재현하고 진단 절차를 정리한 보고서를 제출합니다.'),
('Linux 프로세스와 스레드 관리', 'CPU 점유 스레드 장애 분석',
'상황.
Java 애플리케이션 서버의 CPU 사용률이 갑자기 100%가 되었습니다. 어떤 코드가 원인인지 찾아야 합니다.

요구사항.
1. 무한 루프 스레드를 포함한 간단한 애플리케이션을 만들어 상황을 재현하세요.
2. top과 top -H로 CPU를 점유한 프로세스와 스레드 ID를 찾으세요.
3. 스레드 ID를 16진수로 바꿔 스레드 덤프에서 해당 스레드의 코드 위치를 찾으세요.
4. SIGTERM으로 그레이스풀 종료가 되는지 확인하세요.
5. 애플리케이션을 systemd 서비스로 등록하고 비정상 종료 시 자동 재시작되게 설정하세요.

제출물.
분석 과정과 명령어 출력, systemd 설정 파일을 담은 보고서.',
'분석 보고서를 첨부하거나 텍스트로 붙여 넣으세요. systemd 유닛 파일 내용도 함께 포함하세요.',
'실습 과제: CPU 점유 스레드 장애 분석', 'CPU를 점유하는 스레드를 찾아 코드 위치까지 추적한 분석 보고서를 제출합니다.'),
('OWASP, XSS, CSRF, SQL Injection, CORS', '내 프로젝트 보안 점검 체크리스트',
'상황.
지금까지 만든 개인 프로젝트를 공개하기 전에 기본 보안 점검을 해야 합니다.

요구사항.
1. XSS, CSRF, SQL Injection, CORS, 접근 제어 항목을 포함한 점검 체크리스트를 만드세요.
2. 체크리스트로 자신의 프로젝트(또는 제공된 예제)를 점검하고 결과를 기록하세요.
3. 발견한 취약점 중 2개 이상을 재현 방법과 함께 정리하세요.
4. 발견한 취약점을 수정하고 수정 전후 코드를 비교하세요.
5. 앞으로 개발할 때 지킬 보안 규칙 5가지를 정리하세요.

제출물.
점검 체크리스트, 점검 결과, 수정 내역이 담긴 보고서와 코드 저장소.',
'보고서를 첨부하고 수정 코드가 있는 저장소 URL을 제출하세요. 실제 서비스나 타인의 사이트를 공격하지 마세요.',
'실습 과제: 내 프로젝트 보안 점검 체크리스트', '보안 체크리스트로 프로젝트를 점검하고 취약점을 수정한 결과를 제출합니다.'),
('Swagger와 REST API 문서화', '기존 API에 완성도 있는 문서 붙이기',
'상황.
문서 없이 운영되던 API 서버에 프론트엔드 팀이 새로 합류했습니다. 문서만 보고 연동할 수 있는 수준의 Swagger 문서가 필요합니다.

요구사항.
1. springdoc-openapi를 설정하고 API를 기능별 태그로 묶으세요.
2. 모든 엔드포인트에 요약, 설명, 파라미터 설명을 다세요.
3. 요청과 응답 DTO 필드에 설명과 예시를 다세요.
4. 성공 응답과 함께 400, 401, 404 오류 응답 형식을 문서에 표시하세요.
5. JWT 인증 설정을 추가하고 운영 프로파일에서는 문서가 노출되지 않게 하세요.

제출물.
GitHub 저장소 URL과 Swagger UI 화면 캡처.',
'GitHub 저장소 URL을 제출하고, Swagger UI 캡처를 첨부하세요. 텍스트 칸에 문서화 규칙을 요약하세요.',
'실습 과제: 기존 API에 완성도 있는 문서 붙이기', '설명, 예시, 오류 응답, 인증 설정을 갖춘 API 문서를 제출합니다.'),
('REST URI 설계와 HTTP 메서드', '헷갈리는 동작이 많은 서비스 API 설계',
'상황.
중고 거래 서비스의 API를 설계합니다. 찜하기, 예약하기, 거래 완료, 끌어올리기, 신고하기처럼 CRUD로 딱 떨어지지 않는 동작이 많습니다.

요구사항.
1. 상품, 찜, 예약, 거래, 신고 자원을 정의하세요.
2. 각 동작을 자원 중심 URI와 알맞은 메서드로 표현하세요.
3. 같은 결제 요청이 두 번 들어와도 안전하도록 멱등 키를 설계하세요.
4. 두 사람이 동시에 상품을 수정하는 상황을 ETag와 조건부 요청으로 처리하세요.
5. 상황별 상태 코드와 그 근거를 표로 정리하세요.

제출물.
API 설계 문서(OpenAPI 파일 또는 마크다운 표).',
'설계 문서를 첨부하거나 저장소 URL을 제출하세요. 텍스트 칸에 가장 고민했던 설계 결정 2가지를 적으세요.',
'실습 과제: 헷갈리는 동작이 많은 서비스 API 설계', 'CRUD로 표현하기 어려운 동작을 자원 중심으로 설계한 API 문서를 제출합니다.'),
('Pull Request와 코드 리뷰 실무', '실제 PR 올리기와 상호 리뷰',
'상황.
동료(또는 스터디원)와 함께 작은 기능을 개발하며 PR과 리뷰를 직접 주고받아 봅니다.

요구사항.
1. 저장소에 PR 템플릿과 리뷰 규칙 문서를 추가하세요.
2. 하나의 목적에 집중한 PR을 2개 이상 올리고 템플릿에 맞춰 설명을 작성하세요.
3. 동료의 PR에 근거와 제안이 담긴 리뷰 코멘트를 5개 이상 남기세요.
4. 받은 리뷰를 반영하고, 반영하지 않은 의견에는 이유를 답하세요.
5. CI에서 테스트와 린트가 자동으로 실행되도록 설정하세요.

제출물.
저장소 URL, PR 링크, 리뷰 과정 회고.',
'저장소 URL을 제출하고, 텍스트 칸에 PR 링크와 리뷰를 주고받으며 배운 점을 정리하세요.',
'실습 과제: 실제 PR 올리기와 상호 리뷰', 'PR 템플릿, 상호 리뷰, CI 설정을 포함한 협업 결과를 제출합니다.'),
('Git 브랜치 전략과 GitFlow', '릴리스와 핫픽스 시나리오 재현',
'상황.
버전 1.0이 운영 중인 상태에서 1.1 기능을 개발하던 중 운영 장애가 발생했습니다. GitFlow로 이 상황을 처리해야 합니다.

요구사항.
1. main, develop 브랜치를 만들고 v1.0 태그를 붙이세요.
2. feature 브랜치 두 개를 develop에 병합하세요(하나는 merge, 하나는 squash).
3. release/1.1 브랜치를 만들어 버전 정보를 수정하고 안정화하세요.
4. 그 사이 hotfix/1.0.1 브랜치로 운영 장애를 수정해 main과 develop에 모두 반영하고 태그를 붙이세요.
5. 최종 이력 그래프를 캡처하고, 팀에 GitHub Flow가 더 맞는 경우를 정리하세요.

제출물.
저장소 URL과 이력 그래프 캡처, 전략 비교 문서.',
'저장소 URL을 제출하고, git log --graph 출력 또는 캡처를 첨부하세요.',
'실습 과제: 릴리스와 핫픽스 시나리오 재현', 'GitFlow로 릴리스와 핫픽스를 동시에 처리한 이력과 전략 비교를 제출합니다.'),
('브라우저 요청 흐름과 HTTP 응답 구조', 'API 응답 헤더 설계와 효과 검증',
'상황.
서비스의 정적 파일과 API 응답에 캐시 정책이 없어 재방문할 때마다 모든 리소스를 다시 받고 있습니다.

요구사항.
1. 정적 파일(해시 포함 파일명)에 긴 max-age와 immutable을 설정하세요.
2. 자주 바뀌지 않는 API 응답에 ETag를 적용해 304 응답이 오도록 하세요.
3. 개인 정보가 담긴 응답에는 캐시가 저장되지 않도록 설정하세요.
4. 로그인 쿠키에 HttpOnly, Secure, SameSite를 설정하세요.
5. 개발자 도구에서 적용 전후 전송량과 응답 상태를 비교하세요.

제출물.
설정 코드와 적용 전후 비교 캡처, 헤더 설계 이유를 정리한 문서.',
'GitHub 저장소 URL을 제출하고, 적용 전후 Network 탭 캡처를 첨부하세요.',
'실습 과제: API 응답 헤더 설계와 효과 검증', '캐시와 쿠키 헤더를 설계하고 개발자 도구로 효과를 검증한 결과를 제출합니다.');

INSERT INTO seed_course_assignment_rubric (course_title, display_order, criteria_name, criteria_description, max_points) VALUES
('인터페이스, 제네릭, 컬렉션 실전', 1, '인터페이스 설계', '저장소 역할을 인터페이스로 분리했습니다.', 20),
('인터페이스, 제네릭, 컬렉션 실전', 2, '제네릭 활용', '타입 안전한 제네릭 Repository를 구현했습니다.', 30),
('인터페이스, 제네릭, 컬렉션 실전', 3, '컬렉션 선택', '목적에 맞는 컬렉션을 근거 있게 선택했습니다.', 25),
('인터페이스, 제네릭, 컬렉션 실전', 4, '정렬과 집계', 'Comparator와 스트림을 올바르게 사용했습니다.', 25),
('Java OOP와 상속 설계', 1, '상속 설계', '상속 기반 설계가 요구사항을 충족합니다.', 20),
('Java OOP와 상속 설계', 2, '조합 설계', '조합과 위임으로 같은 요구사항을 구현했습니다.', 30),
('Java OOP와 상속 설계', 3, '비교 분석', '변경 범위와 장단점을 근거 있게 비교했습니다.', 30),
('Java OOP와 상속 설계', 4, '캡슐화', '객체의 불변식을 캡슐화로 보장했습니다.', 20),
('Linux 메모리 관리와 I/O 관리', 1, '상황 재현', '메모리 부족과 디스크 부하를 재현했습니다.', 20),
('Linux 메모리 관리와 I/O 관리', 2, '메모리 해석', 'free, vmstat 출력을 정확히 해석했습니다.', 30),
('Linux 메모리 관리와 I/O 관리', 3, 'I/O 진단', '디스크 병목 원인 프로세스를 찾아냈습니다.', 30),
('Linux 메모리 관리와 I/O 관리', 4, '진단 절차', '재사용 가능한 진단 체크리스트를 정리했습니다.', 20),
('Linux 프로세스와 스레드 관리', 1, '원인 스레드 추적', 'top -H와 스레드 덤프로 원인 코드를 찾았습니다.', 40),
('Linux 프로세스와 스레드 관리', 2, '분석 과정', '명령어 출력과 해석이 논리적으로 이어집니다.', 25),
('Linux 프로세스와 스레드 관리', 3, '종료 처리', '시그널에 따른 종료 동작을 확인했습니다.', 15),
('Linux 프로세스와 스레드 관리', 4, '서비스 관리', 'systemd 등록과 자동 재시작을 설정했습니다.', 20),
('OWASP, XSS, CSRF, SQL Injection, CORS', 1, '체크리스트', '주요 취약점을 포괄하는 점검 항목을 만들었습니다.', 20),
('OWASP, XSS, CSRF, SQL Injection, CORS', 2, '취약점 재현', '발견한 취약점을 재현 방법과 함께 설명했습니다.', 25),
('OWASP, XSS, CSRF, SQL Injection, CORS', 3, '수정', '취약점을 올바른 방어 기법으로 수정했습니다.', 35),
('OWASP, XSS, CSRF, SQL Injection, CORS', 4, '보안 규칙', '실천 가능한 보안 규칙을 정리했습니다.', 20),
('Swagger와 REST API 문서화', 1, '문서 구성', '태그와 엔드포인트 설명이 체계적으로 정리되어 있습니다.', 25),
('Swagger와 REST API 문서화', 2, '모델 설명과 예시', 'DTO 필드 설명과 예시가 충분합니다.', 25),
('Swagger와 REST API 문서화', 3, '오류 응답', '주요 오류 응답 형식이 문서에 표시되어 있습니다.', 25),
('Swagger와 REST API 문서화', 4, '인증과 노출 제한', 'JWT 인증 설정과 운영 노출 제한을 적용했습니다.', 25),
('REST URI 설계와 HTTP 메서드', 1, '자원 모델링', '동작을 자원으로 일관되게 모델링했습니다.', 30),
('REST URI 설계와 HTTP 메서드', 2, '메서드 선택', '안전성과 멱등성을 고려해 메서드를 선택했습니다.', 25),
('REST URI 설계와 HTTP 메서드', 3, '동시성과 재시도', '멱등 키와 조건부 요청을 설계했습니다.', 25),
('REST URI 설계와 HTTP 메서드', 4, '상태 코드', '상황별 상태 코드를 근거 있게 정리했습니다.', 20),
('Pull Request와 코드 리뷰 실무', 1, 'PR 품질', 'PR이 작고 설명이 충실합니다.', 30),
('Pull Request와 코드 리뷰 실무', 2, '리뷰 코멘트', '근거와 대안이 담긴 리뷰 코멘트를 남겼습니다.', 30),
('Pull Request와 코드 리뷰 실무', 3, '피드백 반영', '리뷰를 반영하거나 반영하지 않은 이유를 설명했습니다.', 20),
('Pull Request와 코드 리뷰 실무', 4, '자동화', 'CI와 템플릿으로 리뷰 흐름을 갖췄습니다.', 20),
('Git 브랜치 전략과 GitFlow', 1, '브랜치 운용', 'feature, release, hotfix 브랜치가 규칙대로 운용되었습니다.', 35),
('Git 브랜치 전략과 GitFlow', 2, '병합 방식', 'merge와 squash 병합 결과의 차이를 확인했습니다.', 20),
('Git 브랜치 전략과 GitFlow', 3, '태그와 이력', '버전 태그와 이력 그래프가 시나리오와 일치합니다.', 25),
('Git 브랜치 전략과 GitFlow', 4, '전략 비교', '팀 상황별 전략 선택 기준을 정리했습니다.', 20),
('브라우저 요청 흐름과 HTTP 응답 구조', 1, '캐시 정책', '리소스 성격에 맞는 캐시 정책을 설정했습니다.', 35),
('브라우저 요청 흐름과 HTTP 응답 구조', 2, '재검증', 'ETag로 304 응답을 확인했습니다.', 20),
('브라우저 요청 흐름과 HTTP 응답 구조', 3, '쿠키 보안', '쿠키 보안 속성을 올바르게 설정했습니다.', 20),
('브라우저 요청 흐름과 HTTP 응답 구조', 4, '효과 검증', '전후 전송량과 상태 코드를 비교했습니다.', 25);

INSERT INTO seed_course_content (course_title, subtitle, description) VALUES
('DNS, 도메인, 웹 호스팅 입문', '도메인을 사고 DNS를 설정해 내 서비스를 세상에 공개하는 과정을 처음부터 따라갑니다',
'서비스를 만들었다면 이제 사람들이 기억하기 쉬운 주소로 접속할 수 있게 해야 합니다. 도메인을 구입하고 DNS 레코드를 설정해 서버와 연결하는 과정은 생각보다 단순하지만, 원리를 모르면 설정이 반영되지 않을 때 무엇을 기다리고 무엇을 고쳐야 할지 알 수 없습니다.

첫 섹션에서는 도메인 이름의 구조, 루트와 TLD, 권한 있는 네임서버로 이어지는 DNS 조회 과정, 캐시와 TTL, A, CNAME, MX, TXT 레코드의 쓰임새를 정리합니다.

두 번째 섹션에서는 정적 호스팅과 가상 서버(VPS), 클라우드 호스팅의 차이를 비교하고, 도메인을 서버에 연결해 HTTPS 인증서를 발급하는 과정을 실습합니다. 마지막 과제로 내 도메인에 웹 페이지와 이메일 설정을 연결합니다.'),
('HTTP 요청/응답, 메서드, 상태코드', 'HTTP 메시지를 한 줄씩 읽으며 클라이언트와 서버가 대화하는 규칙을 정확히 익힙니다',
'HTTP는 웹 개발의 공용어입니다. 메서드와 상태 코드를 정확히 쓰면 API를 처음 보는 사람도 동작을 예측할 수 있고, 장애가 났을 때 로그 한 줄만으로 원인을 짐작할 수 있습니다.

첫 섹션에서는 요청 라인, 헤더, 바디로 이루어진 HTTP 메시지 구조, GET, POST, PUT, PATCH, DELETE의 의미와 안전성, 멱등성, curl로 요청을 직접 만들어 보내는 방법을 다룹니다.

두 번째 섹션에서는 1xx부터 5xx까지 상태 코드 계열의 의미, 자주 헷갈리는 코드(401과 403, 400과 422, 301과 302)의 구분, Content-Type과 인코딩, 상태 코드로 오류를 진단하는 방법을 정리합니다. 마지막 과제로 공개 API를 curl로 호출하며 HTTP 메시지를 분석합니다.'),
('MSA API Gateway와 서비스 분리 기준', '어디서 서비스를 나눌지 판단하는 기준과 API Gateway의 역할을 실전 사례로 정리합니다',
'MSA의 가장 어려운 질문은 기술이 아니라 어디서 나눌 것인가입니다. 기준 없이 테이블 단위나 팀 단위로 쪼개면, 기능 하나를 바꿀 때마다 여러 서비스를 함께 배포해야 하는 분산 모놀리스가 됩니다.

첫 섹션에서는 모놀리스와 MSA의 장단점, 도메인 주도 설계의 바운디드 컨텍스트, 변경 빈도와 데이터 소유, 트랜잭션 경계로 서비스 분리 지점을 찾는 방법을 사례 중심으로 다룹니다.

두 번째 섹션에서는 API Gateway가 맡는 라우팅, 인증, 요청 제한, 응답 조합 역할과 Spring Cloud Gateway 구성, 서비스 디스커버리, 장애 격리를 위한 서킷 브레이커와 타임아웃 설정을 정리합니다. 마지막 과제로 모놀리스 서비스의 분리 계획과 게이트웨이 라우팅을 설계합니다.'),
('Kafka와 Kafka 토픽 흐름', '프로듀서부터 컨슈머까지 메시지가 흐르는 길을 따라가며 Kafka를 실무 수준으로 이해합니다',
'Kafka는 대용량 이벤트를 안정적으로 전달하는 데 널리 쓰이지만, 파티션 수나 컨슈머 설정을 잘못 정하면 메시지 순서가 뒤섞이거나 같은 메시지를 두 번 처리하는 문제가 생깁니다.

첫 섹션에서는 브로커, 토픽, 파티션, 복제본의 구조와 프로듀서가 메시지 키로 파티션을 고르는 방식, acks 설정과 재시도, 멱등 프로듀서를 정리합니다.

두 번째 섹션에서는 컨슈머 그룹과 리밸런싱, 오프셋 커밋 시점에 따른 유실과 중복, 처리 실패 메시지를 위한 재시도 토픽과 DLT, Spring Kafka로 프로듀서와 컨슈머를 구현하는 방법을 다룹니다. 마지막 과제로 주문 이벤트 파이프라인을 만들고 장애 상황을 실험합니다.'),
('GitHub Actions와 CI/CD 자동화', '워크플로 문법부터 캐시, 매트릭스, 배포 자동화까지 GitHub Actions를 실무에 맞게 다룹니다',
'GitHub Actions는 저장소 안에서 바로 CI/CD를 구성할 수 있어 많은 팀이 선택합니다. 하지만 워크플로가 커지면 실행 시간이 길어지고, 시크릿 관리와 배포 실패 처리가 복잡해집니다.

첫 섹션에서는 워크플로, 잡, 스텝, 러너의 구조와 트리거 이벤트, 의존성 캐시로 빌드 시간을 줄이는 방법, 매트릭스로 여러 버전을 동시에 테스트하는 방법, 잡 간 아티팩트 전달을 정리합니다.

두 번째 섹션에서는 환경별 시크릿과 승인 절차, Docker 이미지 빌드와 푸시, EC2에 SSH 또는 배포 도구로 배포하는 방법, 배포 후 헬스 체크와 실패 시 롤백 전략, 재사용 가능한 워크플로를 다룹니다. 마지막 과제로 스테이징과 운영 환경을 나눈 배포 파이프라인을 구축합니다.'),
('Docker와 docker-compose 실전', '내 서비스를 컨테이너로 만들고 compose로 개발 환경 전체를 한 번에 띄웁니다',
'새 팀원이 합류할 때마다 개발 환경 설정에 하루를 쓰고 있다면 Docker와 docker-compose가 해답이 될 수 있습니다. 데이터베이스, 캐시, 애플리케이션을 명령어 하나로 똑같이 띄울 수 있기 때문입니다.

첫 섹션에서는 이미지와 컨테이너, 레이어, Dockerfile 주요 명령어, 이미지 크기를 줄이는 방법, 컨테이너 로그와 셸 접속으로 문제를 확인하는 방법을 정리합니다.

두 번째 섹션에서는 compose 파일로 애플리케이션, PostgreSQL, Redis를 함께 구성하고, 네트워크와 볼륨, 환경 변수 파일, 헬스 체크와 시작 순서, 개발용과 운영용 설정 분리를 다룹니다. 마지막 과제로 팀원이 명령어 하나로 실행할 수 있는 개발 환경을 만듭니다.'),
('Redis Session, Pub/Sub, 분산 락', '여러 서버가 함께 동작할 때 필요한 세션 공유, 실시간 메시지, 동시성 제어를 Redis로 구현합니다',
'애플리케이션 서버가 한 대일 때는 문제없던 기능이 서버를 늘리는 순간 깨지기 시작합니다. 로그인이 풀리고, 실시간 알림이 일부 사용자에게만 가고, 같은 주문이 두 번 처리됩니다.

첫 섹션에서는 스티키 세션과 세션 저장소 공유 방식을 비교하고 Spring Session Redis를 적용한 뒤, Pub/Sub으로 여러 서버의 웹소켓 연결에 실시간 메시지를 전달하는 구조를 만듭니다.

두 번째 섹션에서는 동시성 문제가 생기는 원리, 데이터베이스 락과 분산 락의 차이, Redisson의 락 획득 대기와 임대 시간, 락 범위를 정하는 기준을 다룹니다. 마지막 과제로 여러 서버 환경의 실시간 알림과 중복 주문 방지를 구현합니다.'),
('Redis 자료구조, TTL, Spring Cache', '자료구조별 명령어와 TTL 전략, Spring Cache 설정까지 Redis 캐시를 깊이 있게 다룹니다',
'캐시는 적용하는 것보다 운영하는 것이 더 어렵습니다. 어떤 데이터를 얼마나 오래 둘지, 데이터가 바뀌면 언제 지울지, 캐시가 한꺼번에 만료되면 어떻게 될지를 미리 설계해야 합니다.

첫 섹션에서는 String, Hash, List, Set, Sorted Set의 대표 명령어와 시간 복잡도, 키 이름 규칙, TTL 설정과 만료 이벤트, 메모리 정책(maxmemory-policy)을 정리합니다.

두 번째 섹션에서는 Spring Cache의 @Cacheable, @CachePut, @CacheEvict 동작과 캐시별 TTL 설정, 직렬화 방식 선택, 캐시 관통과 스탬피드를 막는 방법, 캐시 적중률 모니터링을 다룹니다. 마지막 과제로 상품 상세 API에 캐시를 설계하고 적중률을 측정합니다.'),
('인덱스, 트랜잭션, PostgreSQL 성능 기본기', '실행 계획을 읽고 인덱스를 설계하며, 트랜잭션과 잠금으로 정합성을 지키는 법을 익힙니다',
'쿼리가 느려지면 일단 인덱스를 추가하고 보는 경우가 많지만, 잘못된 인덱스는 쓰기 성능만 떨어뜨리고 조회는 빨라지지 않습니다. PostgreSQL이 쿼리를 어떻게 실행하는지 읽을 수 있어야 올바른 처방을 내릴 수 있습니다.

첫 섹션에서는 EXPLAIN ANALYZE로 실행 계획을 읽는 방법, Seq Scan과 Index Scan, Index Only Scan의 차이, 복합 인덱스의 컬럼 순서, 부분 인덱스와 표현식 인덱스를 다룹니다.

두 번째 섹션에서는 트랜잭션 격리 수준과 PostgreSQL의 MVCC, 행 잠금과 SELECT FOR UPDATE, 데드락이 생기는 원리와 예방, VACUUM이 필요한 이유를 정리합니다. 마지막 과제로 느린 쿼리를 진단해 개선하고 동시 수정 문제를 해결합니다.'),
('SQL JOIN과 서브쿼리 패턴', 'JOIN과 서브쿼리를 자유롭게 조합해 실무에서 자주 나오는 조회 문제를 풀어냅니다',
'실무에서 받는 데이터 요청은 대부분 여러 테이블을 엮어야 답할 수 있습니다. 어떤 JOIN을 쓰느냐에 따라 행이 사라지거나 중복되고, 서브쿼리를 어디에 두느냐에 따라 결과와 성능이 달라집니다.

첫 섹션에서는 INNER, LEFT, RIGHT, FULL OUTER, CROSS, SELF JOIN의 결과 차이를 벤 다이어그램이 아닌 실제 행으로 확인하고, JOIN 조건과 WHERE 조건의 위치에 따라 결과가 달라지는 함정을 다룹니다.

두 번째 섹션에서는 스칼라, 인라인 뷰, WHERE 절 서브쿼리와 상관 서브쿼리, EXISTS와 IN, CTE(WITH)로 복잡한 쿼리를 읽기 쉽게 나누는 방법, 그룹별 최신 행 구하기 같은 실무 패턴을 정리합니다. 마지막 과제로 실무형 조회 요청 10개를 SQL로 해결합니다.');

INSERT INTO seed_course_info (course_title, section_key, item_order, item_text) VALUES
('DNS, 도메인, 웹 호스팅 입문', 'TARGET_AUDIENCE', 0, '만든 서비스를 내 도메인으로 공개해 보고 싶은 입문 개발자'),
('DNS, 도메인, 웹 호스팅 입문', 'TARGET_AUDIENCE', 1, 'DNS 설정을 바꿨는데 반영이 안 되어 당황해 본 분'),
('DNS, 도메인, 웹 호스팅 입문', 'TARGET_AUDIENCE', 2, '호스팅 종류가 많아 무엇을 골라야 할지 모르는 분'),
('DNS, 도메인, 웹 호스팅 입문', 'PREREQUISITES', 0, '별도 선수 지식은 필요 없습니다. 브라우저와 터미널을 열 수 있으면 충분합니다.'),
('DNS, 도메인, 웹 호스팅 입문', 'PREREQUISITES', 1, '실습용 도메인을 구입하면 더 실감 나게 따라올 수 있습니다(무료 대안도 안내합니다).'),
('DNS, 도메인, 웹 호스팅 입문', 'OBJECTIVES', 0, '루트부터 권한 있는 네임서버까지 DNS 조회 과정을 설명할 수 있습니다.'),
('DNS, 도메인, 웹 호스팅 입문', 'OBJECTIVES', 1, 'A, CNAME, MX, TXT 레코드를 목적에 맞게 설정할 수 있습니다.'),
('DNS, 도메인, 웹 호스팅 입문', 'OBJECTIVES', 2, 'TTL과 캐시 때문에 설정 반영이 늦어지는 이유를 설명할 수 있습니다.'),
('DNS, 도메인, 웹 호스팅 입문', 'OBJECTIVES', 3, '호스팅 종류를 비교해 고르고 HTTPS 인증서를 발급할 수 있습니다.'),
('HTTP 요청/응답, 메서드, 상태코드', 'TARGET_AUDIENCE', 0, 'HTTP를 처음 체계적으로 배우는 웹 개발 입문자'),
('HTTP 요청/응답, 메서드, 상태코드', 'TARGET_AUDIENCE', 1, '상태 코드를 200과 500만 쓰고 있었던 분'),
('HTTP 요청/응답, 메서드, 상태코드', 'TARGET_AUDIENCE', 2, 'curl로 API를 직접 호출하며 디버깅하고 싶은 분'),
('HTTP 요청/응답, 메서드, 상태코드', 'PREREQUISITES', 0, '별도 선수 지식은 필요 없습니다. 웹 브라우저 사용 경험이면 충분합니다.'),
('HTTP 요청/응답, 메서드, 상태코드', 'PREREQUISITES', 1, '터미널에서 curl 명령을 실행할 수 있는 환경을 준비하면 좋습니다.'),
('HTTP 요청/응답, 메서드, 상태코드', 'OBJECTIVES', 0, 'HTTP 요청과 응답 메시지 구조를 읽고 직접 작성할 수 있습니다.'),
('HTTP 요청/응답, 메서드, 상태코드', 'OBJECTIVES', 1, '메서드별 의미와 안전성, 멱등성을 구분할 수 있습니다.'),
('HTTP 요청/응답, 메서드, 상태코드', 'OBJECTIVES', 2, '헷갈리는 상태 코드를 상황에 맞게 구분해 사용할 수 있습니다.'),
('HTTP 요청/응답, 메서드, 상태코드', 'OBJECTIVES', 3, 'curl과 상태 코드로 API 문제를 진단할 수 있습니다.'),
('MSA API Gateway와 서비스 분리 기준', 'TARGET_AUDIENCE', 0, '모놀리스를 MSA로 전환할지 고민 중인 백엔드 개발자와 리드'),
('MSA API Gateway와 서비스 분리 기준', 'TARGET_AUDIENCE', 1, '서비스를 나눴는데 오히려 배포가 더 어려워진 팀'),
('MSA API Gateway와 서비스 분리 기준', 'TARGET_AUDIENCE', 2, 'API Gateway의 역할을 정확히 이해하고 싶은 분'),
('MSA API Gateway와 서비스 분리 기준', 'PREREQUISITES', 0, 'Spring Boot로 REST API를 개발해 본 경험이 있어야 합니다.'),
('MSA API Gateway와 서비스 분리 기준', 'PREREQUISITES', 1, '트랜잭션과 HTTP 통신의 기본을 알고 있으면 좋습니다.'),
('MSA API Gateway와 서비스 분리 기준', 'OBJECTIVES', 0, '모놀리스와 MSA의 장단점을 상황에 맞게 비교할 수 있습니다.'),
('MSA API Gateway와 서비스 분리 기준', 'OBJECTIVES', 1, '바운디드 컨텍스트와 데이터 소유로 서비스 분리 지점을 찾을 수 있습니다.'),
('MSA API Gateway와 서비스 분리 기준', 'OBJECTIVES', 2, 'API Gateway의 라우팅, 인증, 요청 제한을 구성할 수 있습니다.'),
('MSA API Gateway와 서비스 분리 기준', 'OBJECTIVES', 3, '서킷 브레이커와 타임아웃으로 장애 전파를 막을 수 있습니다.'),
('Kafka와 Kafka 토픽 흐름', 'TARGET_AUDIENCE', 0, 'Kafka를 도입했거나 도입을 앞둔 백엔드 개발자'),
('Kafka와 Kafka 토픽 흐름', 'TARGET_AUDIENCE', 1, '메시지 중복 처리나 순서 문제로 고생한 분'),
('Kafka와 Kafka 토픽 흐름', 'TARGET_AUDIENCE', 2, 'Spring Kafka 설정값의 의미를 정확히 알고 싶은 분'),
('Kafka와 Kafka 토픽 흐름', 'PREREQUISITES', 0, 'Spring Boot 애플리케이션을 만들어 본 경험이 있어야 합니다.'),
('Kafka와 Kafka 토픽 흐름', 'PREREQUISITES', 1, 'Docker로 Kafka를 실행할 수 있으면 실습이 수월합니다.'),
('Kafka와 Kafka 토픽 흐름', 'OBJECTIVES', 0, '브로커, 토픽, 파티션, 복제본의 구조를 설명할 수 있습니다.'),
('Kafka와 Kafka 토픽 흐름', 'OBJECTIVES', 1, 'acks와 멱등 프로듀서로 메시지 유실과 중복을 줄일 수 있습니다.'),
('Kafka와 Kafka 토픽 흐름', 'OBJECTIVES', 2, '오프셋 커밋 시점에 따른 처리 보장을 이해하고 설정할 수 있습니다.'),
('Kafka와 Kafka 토픽 흐름', 'OBJECTIVES', 3, '재시도 토픽과 DLT로 실패 메시지를 처리할 수 있습니다.'),
('GitHub Actions와 CI/CD 자동화', 'TARGET_AUDIENCE', 0, 'GitHub Actions 워크플로가 느리고 복잡해져 정리가 필요한 개발자'),
('GitHub Actions와 CI/CD 자동화', 'TARGET_AUDIENCE', 1, '스테이징과 운영 배포를 안전하게 나누고 싶은 팀'),
('GitHub Actions와 CI/CD 자동화', 'TARGET_AUDIENCE', 2, '배포 실패 시 자동 롤백을 구성하고 싶은 분'),
('GitHub Actions와 CI/CD 자동화', 'PREREQUISITES', 0, 'Git과 GitHub, YAML 문법의 기본을 알고 있어야 합니다.'),
('GitHub Actions와 CI/CD 자동화', 'PREREQUISITES', 1, 'Docker 이미지 빌드 경험이 있으면 배포 실습이 수월합니다.'),
('GitHub Actions와 CI/CD 자동화', 'OBJECTIVES', 0, '워크플로 구조와 트리거를 이해하고 목적에 맞게 구성할 수 있습니다.'),
('GitHub Actions와 CI/CD 자동화', 'OBJECTIVES', 1, '캐시와 매트릭스로 CI 시간을 줄이고 여러 환경을 검증할 수 있습니다.'),
('GitHub Actions와 CI/CD 자동화', 'OBJECTIVES', 2, '환경별 시크릿과 승인 절차로 안전하게 배포할 수 있습니다.'),
('GitHub Actions와 CI/CD 자동화', 'OBJECTIVES', 3, '헬스 체크와 롤백 전략을 갖춘 배포 파이프라인을 만들 수 있습니다.'),
('Docker와 docker-compose 실전', 'TARGET_AUDIENCE', 0, '개발 환경 설정에 매번 시간을 쓰는 팀'),
('Docker와 docker-compose 실전', 'TARGET_AUDIENCE', 1, 'Docker를 처음 실무에 도입하려는 개발자'),
('Docker와 docker-compose 실전', 'TARGET_AUDIENCE', 2, '컨테이너가 바로 죽거나 DB에 연결되지 않아 헤맨 경험이 있는 분'),
('Docker와 docker-compose 실전', 'PREREQUISITES', 0, '터미널 기본 명령어와 간단한 웹 애플리케이션 실행 경험이 있으면 좋습니다.'),
('Docker와 docker-compose 실전', 'PREREQUISITES', 1, 'Docker Desktop 또는 Docker Engine을 설치해 두면 바로 실습할 수 있습니다.'),
('Docker와 docker-compose 실전', 'OBJECTIVES', 0, '이미지와 컨테이너, 레이어의 관계를 설명할 수 있습니다.'),
('Docker와 docker-compose 실전', 'OBJECTIVES', 1, 'Dockerfile로 작고 빠르게 빌드되는 이미지를 만들 수 있습니다.'),
('Docker와 docker-compose 실전', 'OBJECTIVES', 2, 'compose로 애플리케이션, DB, 캐시를 함께 구성할 수 있습니다.'),
('Docker와 docker-compose 실전', 'OBJECTIVES', 3, '헬스 체크와 환경별 설정 분리로 안정적인 개발 환경을 만들 수 있습니다.'),
('Redis Session, Pub/Sub, 분산 락', 'TARGET_AUDIENCE', 0, '서버 증설 후 로그인 유지와 실시간 알림 문제를 겪는 백엔드 개발자'),
('Redis Session, Pub/Sub, 분산 락', 'TARGET_AUDIENCE', 1, '중복 주문, 중복 결제 같은 동시성 버그를 막아야 하는 분'),
('Redis Session, Pub/Sub, 분산 락', 'TARGET_AUDIENCE', 2, '웹소켓 서버를 여러 대로 늘려야 하는 분'),
('Redis Session, Pub/Sub, 분산 락', 'PREREQUISITES', 0, 'Redis 기본 자료구조와 Spring Boot를 알고 있어야 합니다.'),
('Redis Session, Pub/Sub, 분산 락', 'PREREQUISITES', 1, '세션과 쿠키, 스레드 동시성 개념을 알고 있으면 좋습니다.'),
('Redis Session, Pub/Sub, 분산 락', 'OBJECTIVES', 0, '스티키 세션과 세션 저장소 공유의 장단점을 비교할 수 있습니다.'),
('Redis Session, Pub/Sub, 분산 락', 'OBJECTIVES', 1, 'Pub/Sub으로 여러 서버의 웹소켓 사용자에게 메시지를 전달할 수 있습니다.'),
('Redis Session, Pub/Sub, 분산 락', 'OBJECTIVES', 2, 'DB 락과 분산 락의 차이를 이해하고 상황에 맞게 선택할 수 있습니다.'),
('Redis Session, Pub/Sub, 분산 락', 'OBJECTIVES', 3, 'Redisson 락의 대기 시간과 임대 시간을 근거 있게 설정할 수 있습니다.'),
('Redis 자료구조, TTL, Spring Cache', 'TARGET_AUDIENCE', 0, '캐시를 적용했지만 데이터 불일치나 적중률 문제를 겪는 개발자'),
('Redis 자료구조, TTL, Spring Cache', 'TARGET_AUDIENCE', 1, 'Redis 명령어와 시간 복잡도를 정리하고 싶은 분'),
('Redis 자료구조, TTL, Spring Cache', 'TARGET_AUDIENCE', 2, '캐시 TTL을 감으로 정해 왔던 분'),
('Redis 자료구조, TTL, Spring Cache', 'PREREQUISITES', 0, 'Spring Boot로 조회 API를 만들어 본 경험이 있어야 합니다.'),
('Redis 자료구조, TTL, Spring Cache', 'PREREQUISITES', 1, 'Redis를 Docker로 실행할 수 있으면 좋습니다.'),
('Redis 자료구조, TTL, Spring Cache', 'OBJECTIVES', 0, '자료구조별 대표 명령어와 시간 복잡도를 알고 선택할 수 있습니다.'),
('Redis 자료구조, TTL, Spring Cache', 'OBJECTIVES', 1, '키 이름 규칙과 TTL, 메모리 정책을 설계할 수 있습니다.'),
('Redis 자료구조, TTL, Spring Cache', 'OBJECTIVES', 2, 'Spring Cache 어노테이션과 캐시별 TTL, 직렬화를 설정할 수 있습니다.'),
('Redis 자료구조, TTL, Spring Cache', 'OBJECTIVES', 3, '캐시 관통과 스탬피드를 막고 적중률을 측정할 수 있습니다.'),
('인덱스, 트랜잭션, PostgreSQL 성능 기본기', 'TARGET_AUDIENCE', 0, '느린 쿼리를 만나면 인덱스부터 추가해 왔던 백엔드 개발자'),
('인덱스, 트랜잭션, PostgreSQL 성능 기본기', 'TARGET_AUDIENCE', 1, 'PostgreSQL 실행 계획을 읽는 법을 배우고 싶은 분'),
('인덱스, 트랜잭션, PostgreSQL 성능 기본기', 'TARGET_AUDIENCE', 2, '동시 수정과 데드락 문제를 겪은 분'),
('인덱스, 트랜잭션, PostgreSQL 성능 기본기', 'PREREQUISITES', 0, 'SQL SELECT, JOIN, GROUP BY를 사용할 수 있어야 합니다.'),
('인덱스, 트랜잭션, PostgreSQL 성능 기본기', 'PREREQUISITES', 1, 'PostgreSQL을 로컬이나 Docker로 실행할 수 있으면 좋습니다.'),
('인덱스, 트랜잭션, PostgreSQL 성능 기본기', 'OBJECTIVES', 0, 'EXPLAIN ANALYZE로 실행 계획과 병목을 읽을 수 있습니다.'),
('인덱스, 트랜잭션, PostgreSQL 성능 기본기', 'OBJECTIVES', 1, '복합, 부분, 표현식 인덱스를 쿼리에 맞게 설계할 수 있습니다.'),
('인덱스, 트랜잭션, PostgreSQL 성능 기본기', 'OBJECTIVES', 2, 'MVCC와 격리 수준, 행 잠금의 동작을 설명할 수 있습니다.'),
('인덱스, 트랜잭션, PostgreSQL 성능 기본기', 'OBJECTIVES', 3, '데드락을 예방하고 동시 수정 문제를 해결할 수 있습니다.'),
('SQL JOIN과 서브쿼리 패턴', 'TARGET_AUDIENCE', 0, 'JOIN 결과가 예상과 달라 자주 당황하는 입문자'),
('SQL JOIN과 서브쿼리 패턴', 'TARGET_AUDIENCE', 1, '복잡한 데이터 요청을 SQL 한 번으로 풀고 싶은 개발자와 분석가'),
('SQL JOIN과 서브쿼리 패턴', 'TARGET_AUDIENCE', 2, 'SQL 코딩 테스트를 준비하는 분'),
('SQL JOIN과 서브쿼리 패턴', 'PREREQUISITES', 0, 'SELECT, WHERE, GROUP BY 기본 문법을 알고 있으면 좋습니다.'),
('SQL JOIN과 서브쿼리 패턴', 'PREREQUISITES', 1, '실습용 PostgreSQL 또는 MySQL 환경을 준비하면 바로 따라올 수 있습니다.'),
('SQL JOIN과 서브쿼리 패턴', 'OBJECTIVES', 0, 'JOIN 종류별 결과 행을 정확히 예측할 수 있습니다.'),
('SQL JOIN과 서브쿼리 패턴', 'OBJECTIVES', 1, 'ON 조건과 WHERE 조건의 차이로 생기는 함정을 피할 수 있습니다.'),
('SQL JOIN과 서브쿼리 패턴', 'OBJECTIVES', 2, '상관 서브쿼리, EXISTS, CTE를 상황에 맞게 사용할 수 있습니다.'),
('SQL JOIN과 서브쿼리 패턴', 'OBJECTIVES', 3, '그룹별 최신 행, 누락 데이터 찾기 같은 실무 패턴을 작성할 수 있습니다.');

INSERT INTO seed_course_curriculum (course_title, section_order, section_title, section_description, lesson_order, lesson_title, lesson_description) VALUES
('DNS, 도메인, 웹 호스팅 입문', 1, 'DNS와 도메인의 원리', '도메인 구조와 DNS 조회, 레코드를 정리합니다.', 1, '도메인 구조와 DNS 조회 과정', '루트, TLD, 권한 있는 네임서버로 이어지는 조회 과정과 리졸버, 캐시의 역할을 dig로 확인합니다.'),
('DNS, 도메인, 웹 호스팅 입문', 1, 'DNS와 도메인의 원리', '도메인 구조와 DNS 조회, 레코드를 정리합니다.', 2, 'DNS 레코드 종류와 TTL', 'A, AAAA, CNAME, MX, TXT 레코드의 쓰임새와 TTL이 설정 반영 시간에 주는 영향을 정리합니다.'),
('DNS, 도메인, 웹 호스팅 입문', 2, '내 서비스 공개하기', '호스팅을 고르고 도메인과 HTTPS를 연결합니다.', 1, '호스팅 종류 비교와 선택', '정적 호스팅, VPS, 클라우드, PaaS의 차이와 비용, 운영 부담을 비교해 서비스에 맞게 고릅니다.'),
('DNS, 도메인, 웹 호스팅 입문', 2, '내 서비스 공개하기', '호스팅을 고르고 도메인과 HTTPS를 연결합니다.', 2, '도메인 연결과 HTTPS 인증서 발급', '도메인을 서버에 연결하고 Let''s Encrypt로 무료 인증서를 발급해 HTTPS를 적용합니다.'),
('HTTP 요청/응답, 메서드, 상태코드', 1, 'HTTP 메시지와 메서드', '메시지 구조와 메서드의 성질을 익힙니다.', 1, 'HTTP 메시지 구조와 curl 실습', '요청 라인, 헤더, 빈 줄, 바디로 이루어진 메시지를 curl -v로 직접 보내고 읽어 봅니다.'),
('HTTP 요청/응답, 메서드, 상태코드', 1, 'HTTP 메시지와 메서드', '메시지 구조와 메서드의 성질을 익힙니다.', 2, '메서드의 의미와 안전성, 멱등성', 'GET, POST, PUT, PATCH, DELETE의 의미와 재시도해도 안전한 메서드를 구분하는 기준을 정리합니다.'),
('HTTP 요청/응답, 메서드, 상태코드', 2, '상태 코드로 대화하기', '상태 코드 계열과 헷갈리는 코드를 정리합니다.', 1, '상태 코드 계열과 대표 코드', '1xx부터 5xx까지 계열의 의미와 200, 201, 204, 301, 304, 400, 404, 500, 503의 쓰임새를 정리합니다.'),
('HTTP 요청/응답, 메서드, 상태코드', 2, '상태 코드로 대화하기', '상태 코드 계열과 헷갈리는 코드를 정리합니다.', 2, '헷갈리는 상태 코드와 오류 진단', '401과 403, 400과 422, 301과 302를 구분하고 상태 코드와 헤더로 문제 원인을 좁혀 가는 방법을 다룹니다.'),
('MSA API Gateway와 서비스 분리 기준', 1, '서비스를 나누는 기준', 'MSA의 장단점과 서비스 분리 지점을 찾는 방법을 다룹니다.', 1, '모놀리스와 MSA, 분산 모놀리스', '모놀리스와 MSA의 장단점, 잘못 나눠 생기는 분산 모놀리스의 증상을 사례로 살펴봅니다.'),
('MSA API Gateway와 서비스 분리 기준', 1, '서비스를 나누는 기준', 'MSA의 장단점과 서비스 분리 지점을 찾는 방법을 다룹니다.', 2, '바운디드 컨텍스트와 데이터 소유', '도메인 언어와 변경 빈도, 데이터 소유, 트랜잭션 경계로 서비스 분리 지점을 찾는 방법을 정리합니다.'),
('MSA API Gateway와 서비스 분리 기준', 2, 'API Gateway와 장애 격리', '게이트웨이 구성과 장애 전파 방지 기법을 다룹니다.', 1, 'API Gateway의 역할과 구성', '라우팅, 인증, 요청 제한, 응답 조합 역할과 Spring Cloud Gateway 라우트, 필터 구성을 다룹니다.'),
('MSA API Gateway와 서비스 분리 기준', 2, 'API Gateway와 장애 격리', '게이트웨이 구성과 장애 전파 방지 기법을 다룹니다.', 2, '서비스 디스커버리와 서킷 브레이커', '서비스 위치를 찾는 디스커버리와 타임아웃, 재시도, 서킷 브레이커로 장애 전파를 막는 방법을 정리합니다.'),
('Kafka와 Kafka 토픽 흐름', 1, '프로듀서와 토픽', 'Kafka 구조와 메시지 발행 설정을 정리합니다.', 1, '브로커, 토픽, 파티션, 복제본', '메시지가 파티션 로그에 쌓이는 구조와 리더, 팔로워 복제본, ISR의 의미를 정리합니다.'),
('Kafka와 Kafka 토픽 흐름', 1, '프로듀서와 토픽', 'Kafka 구조와 메시지 발행 설정을 정리합니다.', 2, '메시지 키, acks, 멱등 프로듀서', '키로 파티션이 정해지는 방식, acks 설정별 유실 가능성, 멱등 프로듀서가 중복을 막는 원리를 다룹니다.'),
('Kafka와 Kafka 토픽 흐름', 2, '컨슈머와 실패 처리', '컨슈머 그룹과 오프셋, 실패 메시지 처리를 다룹니다.', 1, '컨슈머 그룹, 리밸런싱, 오프셋 커밋', '그룹 내 파티션 할당과 리밸런싱, 커밋 시점에 따른 최소 한 번과 최대 한 번 처리를 비교합니다.'),
('Kafka와 Kafka 토픽 흐름', 2, '컨슈머와 실패 처리', '컨슈머 그룹과 오프셋, 실패 메시지 처리를 다룹니다.', 2, '재시도 토픽과 DLT, Spring Kafka', 'Spring Kafka로 프로듀서와 컨슈머를 만들고, 처리 실패 메시지를 재시도 토픽과 DLT로 보내는 구성을 다룹니다.'),
('GitHub Actions와 CI/CD 자동화', 1, 'CI 워크플로 다듬기', '워크플로 구조와 빌드 최적화를 다룹니다.', 1, '워크플로 구조와 트리거', '워크플로, 잡, 스텝, 러너의 관계와 push, pull_request, workflow_dispatch 트리거를 정리합니다.'),
('GitHub Actions와 CI/CD 자동화', 1, 'CI 워크플로 다듬기', '워크플로 구조와 빌드 최적화를 다룹니다.', 2, '캐시, 매트릭스, 아티팩트', '의존성 캐시로 빌드 시간을 줄이고, 매트릭스로 여러 버전을 테스트하며, 잡 간에 빌드 결과를 전달합니다.'),
('GitHub Actions와 CI/CD 자동화', 2, '안전한 배포 자동화', '환경별 배포와 실패 대응을 다룹니다.', 1, '환경별 시크릿과 승인 절차', 'environment로 스테이징과 운영을 나누고 운영 배포 전 승인을 받도록 구성합니다.'),
('GitHub Actions와 CI/CD 자동화', 2, '안전한 배포 자동화', '환경별 배포와 실패 대응을 다룹니다.', 2, '이미지 배포, 헬스 체크, 롤백', '이미지를 빌드해 서버에 배포하고 헬스 체크 실패 시 이전 버전으로 되돌리는 흐름과 재사용 워크플로를 다룹니다.'),
('Docker와 docker-compose 실전', 1, '이미지와 컨테이너', 'Dockerfile 작성과 컨테이너 디버깅을 다룹니다.', 1, '이미지, 레이어, Dockerfile 명령어', 'FROM, COPY, RUN, CMD, ENTRYPOINT의 역할과 레이어 캐시를 고려한 명령어 순서를 정리합니다.'),
('Docker와 docker-compose 실전', 1, '이미지와 컨테이너', 'Dockerfile 작성과 컨테이너 디버깅을 다룹니다.', 2, '이미지 경량화와 컨테이너 디버깅', '경량 베이스 이미지와 멀티 스테이지 빌드로 크기를 줄이고, logs와 exec로 컨테이너 문제를 확인합니다.'),
('Docker와 docker-compose 실전', 2, 'compose로 개발 환경 구성', '여러 컨테이너를 함께 구성하고 운영합니다.', 1, '애플리케이션, PostgreSQL, Redis 함께 띄우기', 'compose 파일로 서비스를 정의하고 네트워크와 볼륨, 환경 변수 파일을 구성합니다.'),
('Docker와 docker-compose 실전', 2, 'compose로 개발 환경 구성', '여러 컨테이너를 함께 구성하고 운영합니다.', 2, '헬스 체크, 시작 순서, 환경별 설정', 'DB가 준비된 뒤 애플리케이션이 시작되도록 헬스 체크를 걸고, override 파일로 개발과 운영 설정을 나눕니다.'),
('Redis Session, Pub/Sub, 분산 락', 1, '여러 서버에서 상태 공유하기', '세션 공유와 실시간 메시지 전달을 구현합니다.', 1, '스티키 세션 대 세션 저장소 공유', '스티키 세션의 한계와 Spring Session Redis로 세션을 공유하는 구성, 세션 직렬화 주의점을 다룹니다.'),
('Redis Session, Pub/Sub, 분산 락', 1, '여러 서버에서 상태 공유하기', '세션 공유와 실시간 메시지 전달을 구현합니다.', 2, 'Pub/Sub으로 여러 웹소켓 서버에 메시지 전달', '사용자가 서로 다른 서버에 연결되어 있어도 Pub/Sub으로 모든 서버에 메시지를 퍼뜨리는 구조를 만듭니다.'),
('Redis Session, Pub/Sub, 분산 락', 2, '동시성 제어', '동시성 문제의 원리와 분산 락을 다룹니다.', 1, '동시성 문제와 DB 락, 분산 락', '경쟁 상태가 생기는 원리와 비관적 락, 낙관적 락, 분산 락을 각각 언제 쓰는지 비교합니다.'),
('Redis Session, Pub/Sub, 분산 락', 2, '동시성 제어', '동시성 문제의 원리와 분산 락을 다룹니다.', 2, 'Redisson 락 대기 시간과 임대 시간', '락 획득 대기, 임대 시간, 워치독 동작을 이해하고 트랜잭션과 락 범위를 맞추는 기준을 정리합니다.'),
('Redis 자료구조, TTL, Spring Cache', 1, 'Redis 명령어와 데이터 수명', '자료구조별 명령어와 TTL, 메모리 정책을 정리합니다.', 1, '자료구조별 명령어와 시간 복잡도', '자주 쓰는 명령어의 시간 복잡도와 KEYS 대신 SCAN을 써야 하는 이유, 키 이름 규칙을 정리합니다.'),
('Redis 자료구조, TTL, Spring Cache', 1, 'Redis 명령어와 데이터 수명', '자료구조별 명령어와 TTL, 메모리 정책을 정리합니다.', 2, 'TTL 전략과 메모리 정책', '데이터 성격별 TTL 결정 기준과 메모리가 가득 찼을 때 키를 내보내는 maxmemory-policy를 다룹니다.'),
('Redis 자료구조, TTL, Spring Cache', 2, 'Spring Cache 운영', '캐시 어노테이션과 운영 문제를 다룹니다.', 1, '@Cacheable, @CachePut, @CacheEvict와 캐시별 TTL', '세 어노테이션의 동작 차이와 RedisCacheManager로 캐시마다 TTL과 직렬화 방식을 지정하는 방법을 다룹니다.'),
('Redis 자료구조, TTL, Spring Cache', 2, 'Spring Cache 운영', '캐시 어노테이션과 운영 문제를 다룹니다.', 2, '캐시 관통, 스탬피드, 적중률 모니터링', '없는 데이터 조회가 DB로 몰리는 관통, 동시 만료로 생기는 스탬피드를 막고 적중률을 측정합니다.'),
('인덱스, 트랜잭션, PostgreSQL 성능 기본기', 1, '실행 계획과 인덱스', '실행 계획을 읽고 인덱스를 설계합니다.', 1, 'EXPLAIN ANALYZE로 실행 계획 읽기', 'Seq Scan, Index Scan, Bitmap Scan과 예상 행 수, 실제 시간을 읽고 병목 노드를 찾는 방법을 다룹니다.'),
('인덱스, 트랜잭션, PostgreSQL 성능 기본기', 1, '실행 계획과 인덱스', '실행 계획을 읽고 인덱스를 설계합니다.', 2, '복합, 부분, 표현식 인덱스 설계', '복합 인덱스의 컬럼 순서, 조건이 정해진 행만 담는 부분 인덱스, 함수 결과에 거는 표현식 인덱스를 다룹니다.'),
('인덱스, 트랜잭션, PostgreSQL 성능 기본기', 2, '트랜잭션과 잠금', 'MVCC와 잠금, 데드락을 다룹니다.', 1, 'MVCC와 격리 수준', 'PostgreSQL이 행 버전으로 읽기와 쓰기를 분리하는 방식과 Read Committed, Repeatable Read의 차이를 정리합니다.'),
('인덱스, 트랜잭션, PostgreSQL 성능 기본기', 2, '트랜잭션과 잠금', 'MVCC와 잠금, 데드락을 다룹니다.', 2, '행 잠금, 데드락, VACUUM', 'SELECT FOR UPDATE로 동시 수정을 막는 방법, 데드락이 생기는 순서와 예방, 죽은 행을 정리하는 VACUUM을 다룹니다.'),
('SQL JOIN과 서브쿼리 패턴', 1, 'JOIN 완전 정복', 'JOIN 종류별 결과와 조건 위치의 함정을 다룹니다.', 1, 'JOIN 종류별 결과 행 확인하기', 'INNER, LEFT, FULL OUTER, CROSS, SELF JOIN의 결과를 실제 행으로 확인하고 행이 늘거나 사라지는 이유를 정리합니다.'),
('SQL JOIN과 서브쿼리 패턴', 1, 'JOIN 완전 정복', 'JOIN 종류별 결과와 조건 위치의 함정을 다룹니다.', 2, 'ON 조건과 WHERE 조건의 함정', 'LEFT JOIN에서 오른쪽 테이블 조건을 WHERE에 두면 INNER JOIN처럼 동작하는 이유와 올바른 작성법을 다룹니다.'),
('SQL JOIN과 서브쿼리 패턴', 2, '서브쿼리와 실무 패턴', '서브쿼리 종류와 CTE, 실무 조회 패턴을 다룹니다.', 1, '서브쿼리 종류와 EXISTS, IN', '스칼라, 인라인 뷰, 상관 서브쿼리와 EXISTS, IN, NOT IN과 NULL 함정을 정리합니다.'),
('SQL JOIN과 서브쿼리 패턴', 2, '서브쿼리와 실무 패턴', '서브쿼리 종류와 CTE, 실무 조회 패턴을 다룹니다.', 2, 'CTE와 그룹별 최신 행 패턴', 'WITH로 복잡한 쿼리를 단계별로 나누고, 그룹별 최신 행이나 누락 데이터 찾기 같은 실무 패턴을 작성합니다.');

INSERT INTO seed_course_quiz (course_title, quiz_title, quiz_description, lesson_title, lesson_description) VALUES
('DNS, 도메인, 웹 호스팅 입문', 'DNS와 도메인 원리 퀴즈', '도메인 구조, DNS 조회 과정, 레코드와 TTL을 점검합니다.', '섹션 퀴즈: DNS와 도메인의 원리', 'DNS가 동작하는 방식을 5문항으로 점검합니다.'),
('HTTP 요청/응답, 메서드, 상태코드', 'HTTP 메시지와 메서드 퀴즈', '메시지 구조, 메서드의 의미와 성질을 점검합니다.', '섹션 퀴즈: HTTP 메시지와 메서드', 'HTTP 메시지를 읽고 메서드를 구분하는 문제 5문항입니다.'),
('MSA API Gateway와 서비스 분리 기준', '서비스 분리 기준 퀴즈', 'MSA의 장단점과 서비스 경계 판단 기준을 점검합니다.', '섹션 퀴즈: 서비스를 나누는 기준', '서비스 경계를 판단하는 문제 5문항입니다.'),
('Kafka와 Kafka 토픽 흐름', '프로듀서와 토픽 퀴즈', '파티션 구조, 메시지 키, acks, 멱등 프로듀서를 점검합니다.', '섹션 퀴즈: 프로듀서와 토픽', '메시지가 안전하게 저장되는 원리를 5문항으로 점검합니다.'),
('GitHub Actions와 CI/CD 자동화', 'CI 워크플로 퀴즈', '워크플로 구조, 트리거, 캐시와 매트릭스를 점검합니다.', '섹션 퀴즈: CI 워크플로 다듬기', '효율적인 CI 구성을 5문항으로 점검합니다.'),
('Docker와 docker-compose 실전', '이미지와 컨테이너 퀴즈', 'Dockerfile 명령어, 레이어, 경량화, 디버깅을 점검합니다.', '섹션 퀴즈: 이미지와 컨테이너', '이미지 빌드와 컨테이너 운영 기초를 5문항으로 점검합니다.'),
('Redis Session, Pub/Sub, 분산 락', '서버 간 상태 공유 퀴즈', '세션 공유 방식과 Pub/Sub 기반 메시지 전달을 점검합니다.', '섹션 퀴즈: 여러 서버에서 상태 공유하기', '분산 환경의 상태 공유를 5문항으로 점검합니다.'),
('Redis 자료구조, TTL, Spring Cache', 'Redis 명령어와 TTL 퀴즈', '명령어 시간 복잡도, 키 설계, TTL, 메모리 정책을 점검합니다.', '섹션 퀴즈: Redis 명령어와 데이터 수명', 'Redis를 안전하게 쓰는 기준을 5문항으로 점검합니다.'),
('인덱스, 트랜잭션, PostgreSQL 성능 기본기', '실행 계획과 인덱스 퀴즈', '실행 계획 해석과 인덱스 설계 원칙을 점검합니다.', '섹션 퀴즈: 실행 계획과 인덱스', '인덱스가 쓰이는 조건을 5문항으로 점검합니다.'),
('SQL JOIN과 서브쿼리 패턴', 'JOIN 결과 예측 퀴즈', 'JOIN 종류별 결과와 조건 위치의 차이를 점검합니다.', '섹션 퀴즈: JOIN 완전 정복', 'JOIN 결과 행을 예측하는 문제 5문항입니다.');

INSERT INTO seed_course_quiz_question (course_title, display_order, question_text, explanation, correct_option, option1, option2, option3, option4) VALUES
('DNS, 도메인, 웹 호스팅 입문', 1, 'blog.example.com에서 com은 무엇에 해당하나요?', '도메인은 오른쪽부터 루트, 최상위 도메인(TLD), 2차 도메인 순으로 읽으며 com은 최상위 도메인입니다.', 2, '서브도메인', '최상위 도메인(TLD)', '호스트 이름', '포트 번호'),
('DNS, 도메인, 웹 호스팅 입문', 2, 'www.example.com을 example.com과 같은 서버로 보내고 싶을 때 www에 설정하기 알맞은 레코드는 무엇인가요?', 'CNAME은 도메인을 다른 도메인 이름의 별칭으로 지정해, 대상의 IP가 바뀌어도 함께 따라갑니다.', 3, 'MX', 'TXT', 'CNAME', 'NS'),
('DNS, 도메인, 웹 호스팅 입문', 3, '도메인의 메일을 받을 서버를 지정하는 레코드는 무엇인가요?', 'MX 레코드는 해당 도메인으로 오는 메일을 처리할 메일 서버와 우선순위를 지정합니다.', 1, 'MX', 'A', 'CNAME', 'AAAA'),
('DNS, 도메인, 웹 호스팅 입문', 4, 'A 레코드의 IP를 바꿨는데 일부 사용자는 여전히 예전 서버로 접속한다면 가장 가능성 높은 이유는 무엇인가요?', '리졸버와 브라우저가 이전 응답을 TTL 동안 캐시하므로, TTL이 지나기 전까지는 예전 IP로 접속할 수 있습니다.', 4, '서버가 꺼져 있어서', 'HTTPS 인증서가 만료되어서', '도메인이 삭제되어서', '이전 레코드가 TTL 동안 캐시되어 있어서'),
('DNS, 도메인, 웹 호스팅 입문', 5, '도메인 소유를 증명하거나 SPF 같은 메일 인증 정보를 등록할 때 쓰는 레코드는 무엇인가요?', 'TXT 레코드에는 임의의 텍스트를 담을 수 있어 도메인 소유 확인 값이나 SPF, DKIM 정보를 등록하는 데 쓰입니다.', 2, 'A', 'TXT', 'CNAME', 'PTR'),
('HTTP 요청/응답, 메서드, 상태코드', 1, 'HTTP 요청 메시지에서 헤더와 바디를 구분하는 것은 무엇인가요?', '헤더 영역이 끝나면 빈 줄(CRLF) 하나가 오고 그 뒤부터 바디가 시작됩니다.', 3, '세미콜론', '콜론', '빈 줄 하나', '중괄호'),
('HTTP 요청/응답, 메서드, 상태코드', 2, 'HTTP 요청 라인에 들어 있는 정보로 올바른 것은 무엇인가요?', '요청 라인은 메서드, 요청 대상(경로), HTTP 버전으로 구성됩니다. 예: GET /users HTTP/1.1', 1, '메서드, 요청 경로, HTTP 버전', '상태 코드와 메시지', '쿠키와 세션', '응답 바디 길이'),
('HTTP 요청/응답, 메서드, 상태코드', 3, '다음 중 안전한(Safe) 메서드는 무엇인가요?', '안전한 메서드는 서버 상태를 변경하지 않는 메서드로 GET, HEAD, OPTIONS가 해당합니다.', 4, 'POST', 'DELETE', 'PATCH', 'HEAD'),
('HTTP 요청/응답, 메서드, 상태코드', 4, '같은 DELETE /posts/3 요청을 두 번 보냈을 때에 대한 설명으로 올바른 것은 무엇인가요?', 'DELETE는 멱등이므로 여러 번 보내도 서버의 최종 상태(3번 글이 없음)는 같습니다. 응답 코드는 달라질 수 있습니다.', 2, '두 번째 요청에서 다른 글이 삭제된다', '서버의 최종 상태는 같다', '글이 두 번 삭제되어 복구된다', 'DELETE는 한 번만 보낼 수 있다'),
('HTTP 요청/응답, 메서드, 상태코드', 5, 'curl로 요청과 응답 헤더를 모두 확인하려면 어떤 옵션을 쓰나요?', '-v(verbose) 옵션은 보낸 요청 헤더와 받은 응답 헤더를 모두 출력합니다.', 1, '-v', '-o', '-s', '-L'),
('MSA API Gateway와 서비스 분리 기준', 1, '분산 모놀리스의 대표 증상은 무엇인가요?', '서비스를 나눴지만 강하게 결합되어 있어 기능 하나를 바꿀 때 여러 서비스를 함께 수정하고 배포해야 한다면 분산 모놀리스입니다.', 3, '서비스마다 독립적으로 배포된다', '각 서비스가 자기 DB를 가진다', '기능 하나를 바꿀 때 여러 서비스를 함께 배포해야 한다', '서비스 간 통신이 비동기다'),
('MSA API Gateway와 서비스 분리 기준', 2, 'MSA에서 서비스마다 자기 데이터베이스를 소유해야 하는 이유는 무엇인가요?', 'DB를 공유하면 스키마 변경이 다른 서비스에 영향을 줘 독립 배포가 불가능해지므로, 각 서비스가 자기 데이터를 소유해야 합니다.', 1, '스키마 변경이 다른 서비스에 영향을 주지 않아 독립적으로 배포할 수 있어서', 'DB 비용이 줄어들어서', 'JOIN이 더 쉬워져서', '트랜잭션 처리가 단순해져서'),
('MSA API Gateway와 서비스 분리 기준', 3, '서비스 분리 지점을 찾을 때 좋은 신호로 가장 적절한 것은 무엇인가요?', '같은 단어가 다른 의미로 쓰이는 경계, 변경 이유와 빈도가 다른 영역은 바운디드 컨텍스트를 나누기 좋은 지점입니다.', 4, '테이블 수가 많은 곳', '개발자 이름이 다른 곳', '코드 줄 수가 많은 곳', '용어의 의미와 변경 이유가 달라지는 경계'),
('MSA API Gateway와 서비스 분리 기준', 4, 'MSA가 모놀리스보다 불리한 점은 무엇인가요?', '서비스가 나뉘면 네트워크 호출, 분산 트랜잭션, 모니터링과 배포 인프라 등 운영 복잡도가 크게 늘어납니다.', 2, '독립 배포가 어렵다', '네트워크 통신과 운영 복잡도가 늘어난다', '기술 스택을 서비스별로 고를 수 없다', '장애 격리가 불가능하다'),
('MSA API Gateway와 서비스 분리 기준', 5, '팀 규모가 작고 도메인이 아직 자주 바뀌는 초기 서비스에 가장 알맞은 선택은 무엇인가요?', '도메인 경계가 불분명한 초기에는 모듈화된 모놀리스로 시작해 경계가 분명해진 뒤 필요한 부분만 분리하는 것이 안전합니다.', 3, '처음부터 서비스 20개로 나눈다', '테이블마다 서비스를 하나씩 만든다', '모듈화된 모놀리스로 시작해 경계가 분명해지면 분리한다', '모든 기능을 서버리스 함수로 나눈다'),
('Kafka와 Kafka 토픽 흐름', 1, '프로듀서가 메시지 키를 지정하면 어떤 효과가 있나요?', '같은 키의 메시지는 같은 파티션으로 가므로 해당 키 안에서는 순서가 보장됩니다.', 2, '메시지가 암호화된다', '같은 키의 메시지가 같은 파티션으로 가 순서가 보장된다', '메시지가 모든 파티션에 복제된다', '메시지가 즉시 삭제된다'),
('Kafka와 Kafka 토픽 흐름', 2, 'acks=all 설정의 의미는 무엇인가요?', 'acks=all이면 리더와 동기화된 모든 복제본(ISR)이 메시지를 저장해야 성공 응답을 보내 유실 가능성이 가장 낮습니다.', 4, '응답을 기다리지 않는다', '리더만 저장하면 성공으로 본다', '컨슈머가 읽어야 성공으로 본다', '동기화된 모든 복제본이 저장해야 성공으로 본다'),
('Kafka와 Kafka 토픽 흐름', 3, '멱등 프로듀서(enable.idempotence=true)가 막아 주는 문제는 무엇인가요?', '네트워크 오류로 재전송이 일어나도 브로커가 시퀀스 번호로 중복을 걸러 같은 메시지가 두 번 저장되지 않습니다.', 1, '재전송으로 같은 메시지가 중복 저장되는 문제', '컨슈머가 느린 문제', '토픽이 삭제되는 문제', '디스크가 가득 차는 문제'),
('Kafka와 Kafka 토픽 흐름', 4, '복제 계수(replication factor)를 3으로 설정했을 때의 효과는 무엇인가요?', '각 파티션이 서로 다른 브로커 3곳에 복제되어 일부 브로커가 죽어도 데이터를 잃지 않고 서비스할 수 있습니다.', 3, '처리량이 정확히 3배가 된다', '메시지가 3번 전달된다', '파티션이 3개의 브로커에 복제되어 장애에 대비한다', '컨슈머가 3개로 고정된다'),
('Kafka와 Kafka 토픽 흐름', 5, '토픽의 파티션 수를 정할 때 고려해야 할 것으로 가장 적절한 것은 무엇인가요?', '한 그룹의 컨슈머 병렬도는 파티션 수를 넘을 수 없으므로 목표 처리량과 컨슈머 수를 고려해 정합니다. 파티션은 늘릴 수는 있어도 줄이기 어렵습니다.', 2, '파티션은 많을수록 무조건 좋다', '목표 처리량과 컨슈머 병렬도를 고려한다', '항상 1개로 둔다', '브로커 수와 같으면 된다'),
('GitHub Actions와 CI/CD 자동화', 1, 'GitHub Actions에서 같은 워크플로의 잡들은 기본적으로 어떻게 실행되나요?', '잡은 기본적으로 병렬로 실행되며, needs로 의존 관계를 지정하면 순서대로 실행됩니다.', 3, '항상 순서대로 실행된다', '하나만 실행된다', '기본은 병렬이고 needs로 순서를 지정한다', '무작위 순서로 하나씩 실행된다'),
('GitHub Actions와 CI/CD 자동화', 2, 'actions/cache로 Gradle 의존성을 캐시할 때 key에 빌드 파일 해시를 넣는 이유는 무엇인가요?', '의존성 정의가 바뀌면 해시가 바뀌어 새 캐시를 만들고, 바뀌지 않으면 기존 캐시를 재사용하기 위해서입니다.', 1, '의존성 정의가 바뀌었을 때만 캐시를 새로 만들기 위해', '캐시를 매번 삭제하기 위해', '시크릿을 암호화하기 위해', '러너 OS를 선택하기 위해'),
('GitHub Actions와 CI/CD 자동화', 3, 'Java 17과 21에서 각각 테스트를 돌리고 싶을 때 쓰는 기능은 무엇인가요?', 'strategy.matrix에 버전 목록을 지정하면 각 조합마다 잡이 만들어져 병렬로 실행됩니다.', 4, 'concurrency', 'workflow_dispatch', 'environment', 'strategy.matrix'),
('GitHub Actions와 CI/CD 자동화', 4, '빌드 잡에서 만든 jar 파일을 배포 잡에서 사용하려면 어떻게 하나요?', '잡마다 새 러너에서 실행되므로 upload-artifact로 올리고 download-artifact로 받아 전달합니다.', 2, '같은 폴더에 있으니 그대로 쓴다', 'upload-artifact와 download-artifact로 전달한다', '환경 변수에 jar 내용을 넣는다', '커밋에 jar를 포함한다'),
('GitHub Actions와 CI/CD 자동화', 5, '수동으로 버튼을 눌러 워크플로를 실행하게 하려면 어떤 트리거를 쓰나요?', 'workflow_dispatch 트리거를 추가하면 Actions 화면에서 수동 실행 버튼과 입력값을 사용할 수 있습니다.', 1, 'workflow_dispatch', 'push', 'schedule', 'pull_request'),
('Docker와 docker-compose 실전', 1, 'ENTRYPOINT와 CMD를 함께 쓸 때 CMD의 역할은 무엇인가요?', 'ENTRYPOINT가 실행할 명령을 고정하고, CMD는 그 명령의 기본 인자를 제공하며 docker run 인자로 덮어쓸 수 있습니다.', 2, 'ENTRYPOINT를 무시하게 만든다', 'ENTRYPOINT에 전달할 기본 인자를 제공한다', '빌드 시점에 실행된다', '환경 변수를 정의한다'),
('Docker와 docker-compose 실전', 2, 'COPY . . 명령을 Dockerfile 앞부분에 두면 생기는 문제는 무엇인가요?', '소스가 조금만 바뀌어도 이 레이어부터 캐시가 깨져 이후 의존성 설치까지 매번 다시 실행되어 빌드가 느려집니다.', 3, '이미지가 실행되지 않는다', '파일이 복사되지 않는다', '소스 변경마다 이후 레이어 캐시가 깨져 빌드가 느려진다', '컨테이너 포트가 닫힌다'),
('Docker와 docker-compose 실전', 3, '실행 중인 컨테이너 안에서 셸을 열어 상태를 확인하는 명령어는 무엇인가요?', 'docker exec -it 컨테이너 sh(또는 bash)로 실행 중인 컨테이너에 접속해 파일이나 프로세스를 확인할 수 있습니다.', 1, 'docker exec -it 컨테이너 sh', 'docker build', 'docker pull', 'docker tag'),
('Docker와 docker-compose 실전', 4, '컨테이너가 시작하자마자 종료될 때 원인을 확인하는 첫 단계로 알맞은 것은 무엇인가요?', '종료된 컨테이너도 로그가 남으므로 docker logs로 애플리케이션이 출력한 오류를 먼저 확인합니다.', 4, '이미지를 삭제한다', 'Docker를 재설치한다', '포트를 바꾼다', 'docker logs로 출력된 오류를 확인한다'),
('Docker와 docker-compose 실전', 5, 'alpine이나 distroless 같은 경량 베이스 이미지를 쓰는 이유로 가장 적절한 것은 무엇인가요?', '불필요한 패키지가 적어 이미지가 작고, 공격에 쓰일 수 있는 도구가 줄어 보안상으로도 유리합니다.', 3, '컨테이너가 GPU를 쓰게 하려고', '빌드 명령이 필요 없어서', '이미지가 작고 보안 공격 면이 줄어서', '로그가 자동 저장되어서'),
('Redis Session, Pub/Sub, 분산 락', 1, '스티키 세션의 한계로 가장 적절한 것은 무엇인가요?', '사용자가 특정 서버에 고정되므로 그 서버가 죽으면 세션이 사라지고, 부하가 고르게 분산되지 않을 수 있습니다.', 2, '세션을 전혀 저장할 수 없다', '서버가 죽으면 그 서버에 묶인 사용자의 세션이 사라진다', '쿠키를 사용할 수 없다', 'HTTPS를 쓸 수 없다'),
('Redis Session, Pub/Sub, 분산 락', 2, 'Spring Session Redis를 적용하면 세션 데이터는 어디에 저장되나요?', '세션이 각 서버 메모리가 아니라 Redis에 저장되므로 어느 서버로 요청이 가도 같은 세션을 읽을 수 있습니다.', 1, 'Redis', '각 서버의 메모리', '브라우저 로컬 스토리지', '로드 밸런서'),
('Redis Session, Pub/Sub, 분산 락', 3, '세션에 저장하는 객체가 갖춰야 할 조건으로 올바른 것은 무엇인가요?', '세션은 Redis에 저장되기 위해 직렬화되어야 하므로 직렬화 가능한 객체만 넣고, 클래스 변경 시 호환성도 고려해야 합니다.', 4, '반드시 싱글톤이어야 한다', '스프링 빈이어야 한다', 'final 클래스여야 한다', '직렬화가 가능해야 한다'),
('Redis Session, Pub/Sub, 분산 락', 4, '사용자 A는 서버 1, 사용자 B는 서버 2에 웹소켓으로 연결되어 있을 때 A의 메시지를 B에게 전달하는 방법으로 알맞은 것은 무엇인가요?', '서버 1이 Redis 채널에 발행하면 구독 중인 모든 서버가 받아 자기 서버에 연결된 사용자에게 전달합니다.', 3, '서버 1이 B의 웹소켓에 직접 연결한다', 'A가 서버 2로 재접속한다', '서버 1이 Redis 채널에 발행하고 서버 2가 구독해 B에게 전달한다', '메시지를 DB에 저장하고 B가 새로고침한다'),
('Redis Session, Pub/Sub, 분산 락', 5, 'Redis Pub/Sub으로 알림을 보낼 때 서버가 잠시 재시작되는 동안 발행된 메시지는 어떻게 되나요?', 'Pub/Sub은 메시지를 보관하지 않으므로 구독하지 않던 동안 발행된 메시지는 받을 수 없습니다. 유실되면 안 되는 메시지는 Streams나 DB를 함께 써야 합니다.', 2, '재시작 후 자동으로 모두 받는다', '구독하지 않던 동안의 메시지는 유실된다', 'Redis가 디스크에 저장해 둔다', '다른 서버가 대신 저장한다'),
('Redis 자료구조, TTL, Spring Cache', 1, '운영 환경에서 KEYS * 대신 SCAN을 써야 하는 이유는 무엇인가요?', 'KEYS는 모든 키를 한 번에 훑는 O(N) 명령이라 싱글 스레드 Redis 전체를 멈추게 할 수 있고, SCAN은 커서로 나눠 조회합니다.', 3, 'KEYS는 결과가 부정확해서', 'SCAN이 키를 정렬해 줘서', 'KEYS가 Redis 전체를 오래 막을 수 있어서', 'SCAN만 패턴 검색을 지원해서'),
('Redis 자료구조, TTL, Spring Cache', 2, 'Sorted Set에 멤버를 추가하는 ZADD의 시간 복잡도는 무엇인가요?', 'Sorted Set은 정렬된 구조(스킵 리스트)를 유지하므로 추가와 삭제는 O(log N)입니다.', 2, 'O(1)', 'O(log N)', 'O(N)', 'O(N²)'),
('Redis 자료구조, TTL, Spring Cache', 3, 'Redis 키 이름 규칙으로 흔히 쓰는 방식은 무엇인가요?', '콜론으로 계층을 나누는 product:123:detail 같은 규칙은 키의 용도를 드러내고 패턴 검색과 관리에 도움이 됩니다.', 1, 'product:123:detail처럼 콜론으로 계층을 나눈다', '무작위 UUID만 사용한다', '공백을 넣어 구분한다', '모든 키를 한 단어로 짓는다'),
('Redis 자료구조, TTL, Spring Cache', 4, 'maxmemory-policy를 allkeys-lru로 설정하면 메모리가 가득 찼을 때 어떻게 되나요?', 'allkeys-lru는 모든 키 중 가장 오랫동안 사용되지 않은 키부터 내보내 새 데이터를 위한 공간을 만듭니다.', 4, '모든 쓰기 요청을 거부한다', 'TTL이 있는 키만 삭제한다', '무작위로 키를 지운다', '가장 오래 사용되지 않은 키부터 내보낸다'),
('Redis 자료구조, TTL, Spring Cache', 5, '같은 시각에 대량으로 저장한 캐시가 같은 TTL로 동시에 만료되는 문제를 줄이는 방법은 무엇인가요?', 'TTL에 무작위 값(지터)을 더하면 만료 시점이 흩어져 한꺼번에 DB로 요청이 몰리는 것을 줄일 수 있습니다.', 3, 'TTL을 모두 0으로 둔다', '캐시를 사용하지 않는다', 'TTL에 무작위 값을 더해 만료 시점을 분산한다', 'TTL을 모두 같은 값으로 고정한다'),
('인덱스, 트랜잭션, PostgreSQL 성능 기본기', 1, 'EXPLAIN과 EXPLAIN ANALYZE의 차이로 올바른 것은 무엇인가요?', 'EXPLAIN은 예상 실행 계획만 보여 주고, EXPLAIN ANALYZE는 쿼리를 실제로 실행해 실제 시간과 행 수를 함께 보여 줍니다.', 2, '둘은 완전히 같다', 'ANALYZE는 쿼리를 실제로 실행해 실제 시간과 행 수를 보여 준다', 'EXPLAIN만 실제로 쿼리를 실행한다', 'ANALYZE는 인덱스를 자동 생성한다'),
('인덱스, 트랜잭션, PostgreSQL 성능 기본기', 2, '(user_id, created_at) 복합 인덱스가 있을 때 효율적으로 사용되기 어려운 조건은 무엇인가요?', '복합 인덱스는 앞쪽 컬럼부터 정렬되어 있으므로 첫 컬럼 없이 created_at만으로 조회하면 인덱스를 효율적으로 쓰기 어렵습니다.', 4, 'WHERE user_id = 1', 'WHERE user_id = 1 AND created_at > 어제', 'WHERE user_id = 1 ORDER BY created_at', 'WHERE created_at > 어제 (user_id 조건 없음)'),
('인덱스, 트랜잭션, PostgreSQL 성능 기본기', 3, 'WHERE lower(email) = ? 조회를 빠르게 하려면 어떤 인덱스가 알맞나요?', '컬럼에 함수를 적용한 조건은 일반 인덱스를 쓰지 못하므로 lower(email)에 대한 표현식 인덱스를 만들어야 합니다.', 1, 'lower(email)에 대한 표현식 인덱스', 'email 일반 인덱스', 'id 기본키 인덱스', '인덱스가 필요 없다'),
('인덱스, 트랜잭션, PostgreSQL 성능 기본기', 4, '전체 주문 중 처리 대기 상태인 주문만 자주 조회한다면 어떤 인덱스가 효율적인가요?', 'WHERE status = PENDING 조건을 가진 부분 인덱스는 해당 행만 담아 크기가 작고 조회가 빠릅니다.', 3, '모든 컬럼에 인덱스를 건다', '인덱스를 모두 지운다', '처리 대기 상태 행만 담는 부분 인덱스', '주문 금액 컬럼 인덱스'),
('인덱스, 트랜잭션, PostgreSQL 성능 기본기', 5, '인덱스가 있는데도 실행 계획에 Seq Scan이 나오는 이유로 가능한 것은 무엇인가요?', '조건에 맞는 행이 테이블의 큰 비율을 차지하면 인덱스를 거쳐 여러 번 읽는 것보다 순차 스캔이 더 싸다고 판단할 수 있습니다.', 2, 'PostgreSQL이 인덱스를 지원하지 않아서', '조건에 맞는 행이 많아 순차 스캔이 더 싸다고 판단해서', '인덱스가 너무 작아서', 'EXPLAIN 결과가 항상 틀려서'),
('SQL JOIN과 서브쿼리 패턴', 1, '고객 3명, 주문 4건(고객 A 2건, 고객 B 2건, 고객 C 0건)일 때 customers INNER JOIN orders 결과의 행 수는 몇 개인가요?', 'INNER JOIN은 양쪽에 짝이 있는 행만 남기므로 A의 2건과 B의 2건, 총 4행이 됩니다.', 3, '3행', '5행', '4행', '12행'),
('SQL JOIN과 서브쿼리 패턴', 2, '같은 데이터에서 customers LEFT JOIN orders 결과의 행 수는 몇 개인가요?', 'LEFT JOIN은 짝이 있는 4행에 더해, 주문이 없는 고객 C도 NULL과 함께 한 행으로 남아 총 5행입니다.', 2, '4행', '5행', '3행', '7행'),
('SQL JOIN과 서브쿼리 패턴', 3, 'LEFT JOIN 후 WHERE orders.status = PAID 조건을 걸면 어떤 일이 생기나요?', '주문이 없는 고객은 status가 NULL이라 WHERE에서 걸러지므로, 결과적으로 INNER JOIN처럼 동작합니다. 조건은 ON 절에 둬야 합니다.', 1, '주문이 없는 고객이 사라져 INNER JOIN처럼 동작한다', '모든 고객이 그대로 남는다', '문법 오류가 발생한다', '주문이 없는 고객만 남는다'),
('SQL JOIN과 서브쿼리 패턴', 4, '직원 테이블에서 각 직원과 그 직원의 관리자 이름을 함께 조회하려면 어떤 JOIN을 쓰나요?', '같은 테이블을 별칭 두 개로 나눠 manager_id와 id를 연결하는 SELF JOIN을 사용합니다.', 4, 'CROSS JOIN', 'FULL OUTER JOIN', 'NATURAL JOIN', 'SELF JOIN'),
('SQL JOIN과 서브쿼리 패턴', 5, '3행 테이블과 4행 테이블을 CROSS JOIN하면 결과는 몇 행인가요?', 'CROSS JOIN은 모든 조합(카티션 곱)을 만들므로 3 x 4 = 12행입니다.', 3, '7행', '4행', '12행', '3행');

INSERT INTO seed_course_assignment (course_title, assignment_title, assignment_description, submission_rule, lesson_title, lesson_description) VALUES
('DNS, 도메인, 웹 호스팅 입문', '내 도메인에 웹 페이지와 메일 연결하기',
'상황.
개인 포트폴리오 사이트를 내 도메인으로 공개하고, 같은 도메인으로 메일도 받고 싶습니다.

요구사항.
1. 도메인을 준비하고(무료 서브도메인 서비스도 가능) 호스팅을 선택한 이유를 적으세요.
2. 루트 도메인에는 A 레코드, www에는 CNAME을 설정하세요.
3. HTTPS 인증서를 발급해 적용하고, HTTP 요청이 HTTPS로 이동하게 하세요.
4. 메일 수신을 위한 MX 레코드(또는 메일 포워딩)를 설정하세요.
5. dig로 각 레코드를 조회한 결과와 TTL 설정 이유를 정리하세요.

제출물.
사이트 URL과 DNS 설정 내역, 조회 결과를 정리한 문서.',
'사이트 URL을 제출하고, 텍스트 칸에 DNS 레코드 표와 dig 조회 결과를 붙여 넣으세요.',
'실습 과제: 내 도메인에 웹 페이지와 메일 연결하기', '도메인, DNS 레코드, HTTPS, 메일 설정을 직접 구성한 결과를 제출합니다.'),
('HTTP 요청/응답, 메서드, 상태코드', '공개 API로 HTTP 메시지 분석하기',
'상황.
처음 보는 공개 API(예: JSONPlaceholder)를 문서와 curl만으로 분석해 동작을 설명해야 합니다.

요구사항.
1. GET, POST, PUT, PATCH, DELETE 요청을 curl로 각각 보내 보세요.
2. 각 요청의 요청 라인, 주요 헤더, 바디를 정리하세요.
3. 각 응답의 상태 코드와 주요 응답 헤더의 의미를 설명하세요.
4. 존재하지 않는 자원, 잘못된 바디 등으로 오류 응답을 일부러 받아 보고 분석하세요.
5. 같은 PUT 요청을 두 번 보내 멱등성을 확인하세요.

제출물.
curl 명령과 응답, 분석 내용을 정리한 문서.',
'분석 문서를 첨부하거나 텍스트로 붙여 넣으세요. 각 요청마다 명령어, 응답 요약, 해석을 함께 적으세요.',
'실습 과제: 공개 API로 HTTP 메시지 분석하기', 'curl로 메서드별 요청을 보내고 응답과 상태 코드를 분석한 결과를 제출합니다.'),
('MSA API Gateway와 서비스 분리 기준', '모놀리스 분리 계획과 게이트웨이 라우팅 설계',
'상황.
온라인 강의 플랫폼(회원, 강의, 수강, 결제, 알림 기능)을 모놀리스로 운영 중입니다. 결제 장애가 전체 서비스를 멈추는 일이 반복되어 분리를 검토합니다.

요구사항.
1. 현재 기능을 바운디드 컨텍스트로 나누고 각 경계의 근거를 적으세요.
2. 가장 먼저 분리할 서비스 하나를 고르고 그 이유를 설명하세요.
3. 분리 후 서비스별 데이터 소유와 서비스 간 통신 방식을 정하세요.
4. API Gateway의 라우팅 규칙과 인증 처리 위치를 설계하세요.
5. 결제 서비스 장애 시 다른 기능을 보호할 타임아웃과 서킷 브레이커 설정을 제안하세요.

제출물.
아키텍처 다이어그램과 분리 계획 문서(게이트웨이 설정 예시 포함).',
'설계 문서를 첨부하세요. 텍스트 칸에 첫 분리 대상과 선택 이유를 요약하세요.',
'실습 과제: 모놀리스 분리 계획과 게이트웨이 설계', '서비스 경계, 분리 순서, 게이트웨이 라우팅, 장애 격리 방안을 담은 설계를 제출합니다.'),
('Kafka와 Kafka 토픽 흐름', '주문 이벤트 파이프라인과 장애 실험',
'상황.
주문이 생성되면 재고 차감과 알림 발송이 이벤트로 처리되어야 합니다. 일시적인 오류가 나도 이벤트를 잃으면 안 됩니다.

요구사항.
1. Docker로 Kafka를 띄우고 주문 이벤트 토픽(파티션 3개)을 만드세요.
2. 주문 ID를 키로 이벤트를 발행하는 프로듀서를 Spring Kafka로 구현하세요.
3. 재고, 알림 컨슈머를 서로 다른 컨슈머 그룹으로 구현하세요.
4. 처리 중 예외가 나면 재시도 후 DLT로 보내도록 설정하세요.
5. 컨슈머를 하나 더 띄워 리밸런싱을 관찰하고, 같은 이벤트를 두 번 받아도 안전하도록 멱등 처리하세요.

제출물.
GitHub 저장소 URL과 실험 결과 보고서.',
'GitHub 저장소 URL을 제출하세요. README에 토픽 설계, 실패 처리 흐름, 리밸런싱 관찰 결과를 정리하세요.',
'실습 과제: 주문 이벤트 파이프라인과 장애 실험', 'Kafka 이벤트 파이프라인을 만들고 재시도, DLT, 리밸런싱을 실험한 결과를 제출합니다.'),
('GitHub Actions와 CI/CD 자동화', '스테이징과 운영을 나눈 배포 파이프라인',
'상황.
지금은 main에 병합하면 바로 운영에 배포됩니다. 스테이징에서 먼저 확인하고 승인 후 운영에 배포하는 흐름으로 바꿔야 합니다.

요구사항.
1. PR에서는 캐시를 적용한 테스트와 빌드만 실행하세요.
2. main 병합 시 이미지를 빌드해 스테이징에 자동 배포하세요.
3. 운영 배포는 environment 승인 후에만 진행되게 하세요.
4. 배포 후 헬스 체크가 실패하면 이전 이미지로 롤백하세요.
5. 공통 배포 단계를 재사용 가능한 워크플로로 분리하세요.

제출물.
GitHub 저장소 URL과 워크플로 실행 기록, 파이프라인 다이어그램.',
'GitHub 저장소 URL을 제출하세요. 텍스트 칸에 스테이징 배포 성공 실행 링크와 롤백 테스트 결과를 적으세요.',
'실습 과제: 스테이징과 운영을 나눈 배포 파이프라인', '환경별 배포, 승인, 롤백을 갖춘 GitHub Actions 파이프라인을 제출합니다.'),
('Docker와 docker-compose 실전', '명령어 하나로 뜨는 팀 개발 환경',
'상황.
새 팀원이 합류할 때마다 PostgreSQL, Redis 설치와 설정에 반나절씩 걸립니다. docker compose up 한 번으로 개발 환경이 뜨게 만들어야 합니다.

요구사항.
1. 애플리케이션 Dockerfile을 멀티 스테이지로 작성하고 이미지 크기를 기록하세요.
2. compose로 애플리케이션, PostgreSQL, Redis를 정의하세요.
3. DB 데이터는 볼륨으로 유지하고 초기 스키마가 자동으로 들어가게 하세요.
4. DB 헬스 체크 후 애플리케이션이 시작되게 하세요.
5. 비밀번호 등은 .env 파일로 분리하고 예시 파일만 저장소에 올리세요.

제출물.
GitHub 저장소 URL과 실행 방법, 구성 설명을 담은 README.',
'GitHub 저장소 URL을 제출하세요. README에 실행 명령, 서비스 구성도, 문제 해결 팁을 포함하세요.',
'실습 과제: 명령어 하나로 뜨는 팀 개발 환경', 'compose로 애플리케이션, DB, 캐시를 한 번에 띄우는 개발 환경을 제출합니다.'),
('Redis Session, Pub/Sub, 분산 락', '멀티 서버 실시간 알림과 중복 주문 방지',
'상황.
애플리케이션 서버를 2대로 늘렸더니 로그인이 풀리고, 실시간 알림이 일부 사용자에게만 전달되며, 버튼을 연타하면 주문이 두 번 생깁니다.

요구사항.
1. 서버 2대를 띄우고 Spring Session Redis로 세션을 공유하세요.
2. 웹소켓 알림을 Redis Pub/Sub으로 모든 서버에 전달하세요.
3. 같은 사용자의 주문 요청이 동시에 들어오면 한 건만 처리되도록 분산 락을 적용하세요.
4. 락 대기 시간과 임대 시간을 정하고 트랜잭션과의 순서를 설명하세요.
5. 서버 한 대를 내렸을 때 세션과 알림이 어떻게 동작하는지 확인하세요.

제출물.
GitHub 저장소 URL과 실험 결과를 담은 README.',
'GitHub 저장소 URL을 제출하세요. README에 서버 2대 실행 방법과 동시 요청 테스트 결과를 포함하세요.',
'실습 과제: 멀티 서버 실시간 알림과 중복 주문 방지', '세션 공유, Pub/Sub 알림, 분산 락을 여러 서버 환경에서 구현한 결과를 제출합니다.'),
('Redis 자료구조, TTL, Spring Cache', '상품 상세 API 캐시 설계와 적중률 측정',
'상황.
상품 상세 API는 조회가 매우 많고, 가격과 재고는 자주 바뀌지만 상품 설명은 거의 바뀌지 않습니다.

요구사항.
1. 자주 바뀌는 데이터와 거의 바뀌지 않는 데이터를 나눠 캐시 단위를 설계하세요.
2. 캐시마다 다른 TTL을 RedisCacheManager로 설정하세요.
3. 상품 수정 시 @CacheEvict 또는 @CachePut으로 캐시를 갱신하세요.
4. 존재하지 않는 상품 조회가 DB로 몰리지 않도록 처리하세요.
5. 부하 테스트로 캐시 적중률과 응답 시간을 측정하세요.

제출물.
GitHub 저장소 URL과 캐시 설계표, 측정 결과.',
'GitHub 저장소 URL을 제출하세요. README에 캐시 키, TTL, 갱신 시점 설계표와 적중률 측정 결과를 포함하세요.',
'실습 과제: 상품 상세 API 캐시 설계와 적중률 측정', '데이터 성격별 캐시 설계와 적중률 측정 결과를 제출합니다.'),
('인덱스, 트랜잭션, PostgreSQL 성능 기본기', '느린 쿼리 진단과 동시 수정 문제 해결',
'상황.
주문 내역 조회가 데이터가 쌓일수록 느려지고, 재고 차감 과정에서 가끔 재고가 음수가 되는 문제가 보고되었습니다.

요구사항.
1. 샘플 데이터 100만 건 이상을 만들고 느린 조회 쿼리 3개를 EXPLAIN ANALYZE로 분석하세요.
2. 쿼리별로 알맞은 인덱스(복합, 부분, 표현식 중)를 설계하고 개선 결과를 비교하세요.
3. 인덱스 추가가 쓰기 성능에 주는 영향을 측정하세요.
4. 두 세션에서 동시에 재고를 차감해 문제를 재현하고 SELECT FOR UPDATE로 해결하세요.
5. 데드락이 생기는 상황을 재현하고 예방 방법을 정리하세요.

제출물.
SQL 스크립트와 실행 계획 비교, 동시성 실험 결과를 담은 보고서.',
'SQL 스크립트와 보고서를 첨부하거나 저장소 URL을 제출하세요. 실행 계획은 개선 전후를 함께 보여 주세요.',
'실습 과제: 느린 쿼리 진단과 동시 수정 문제 해결', '실행 계획으로 인덱스를 설계하고 잠금으로 동시성 문제를 해결한 결과를 제출합니다.'),
('SQL JOIN과 서브쿼리 패턴', '실무형 조회 요청 10개 해결하기',
'상황.
쇼핑몰 운영팀에서 데이터 요청 10건이 들어왔습니다. 고객, 주문, 주문상품, 상품, 카테고리 테이블로 답해야 합니다.

요구사항.
1. 한 번도 주문하지 않은 고객 목록을 구하세요.
2. 고객별 가장 최근 주문 한 건을 구하세요.
3. 카테고리별 매출 1위 상품을 구하세요.
4. 평균 주문 금액보다 큰 주문만 구하세요.
5. 이 밖에 실무형 요청 6개를 직접 정하거나 제공된 목록에서 골라 SQL로 해결하세요. 문제마다 JOIN과 서브쿼리 중 무엇을 썼는지, 다른 방법과 비교한 결과를 적으세요.

제출물.
문제별 SQL과 결과 예시, 풀이 설명.',
'SQL 파일을 첨부하거나 저장소 URL을 제출하세요. 문제마다 사용한 패턴과 대안 비교를 짧게 적으세요.',
'실습 과제: 실무형 조회 요청 10개 해결하기', 'JOIN, 서브쿼리, CTE를 활용해 실무형 조회 요청을 해결한 결과를 제출합니다.');

INSERT INTO seed_course_assignment_rubric (course_title, display_order, criteria_name, criteria_description, max_points) VALUES
('DNS, 도메인, 웹 호스팅 입문', 1, '도메인 연결', '루트와 www 도메인이 모두 정상 접속됩니다.', 30),
('DNS, 도메인, 웹 호스팅 입문', 2, 'HTTPS 적용', '인증서가 적용되고 HTTP가 HTTPS로 이동합니다.', 25),
('DNS, 도메인, 웹 호스팅 입문', 3, '레코드 이해', '각 레코드의 역할과 TTL 설정 이유를 설명했습니다.', 25),
('DNS, 도메인, 웹 호스팅 입문', 4, '메일 설정', 'MX 레코드 또는 메일 포워딩이 동작합니다.', 20),
('HTTP 요청/응답, 메서드, 상태코드', 1, '요청 작성', '메서드별 요청을 올바르게 작성했습니다.', 25),
('HTTP 요청/응답, 메서드, 상태코드', 2, '메시지 분석', '요청과 응답의 구조를 정확히 설명했습니다.', 30),
('HTTP 요청/응답, 메서드, 상태코드', 3, '오류 분석', '오류 응답의 상태 코드와 원인을 해석했습니다.', 25),
('HTTP 요청/응답, 메서드, 상태코드', 4, '멱등성 확인', '멱등성을 실험으로 확인하고 설명했습니다.', 20),
('MSA API Gateway와 서비스 분리 기준', 1, '경계 설정', '바운디드 컨텍스트와 경계 근거가 타당합니다.', 30),
('MSA API Gateway와 서비스 분리 기준', 2, '분리 전략', '분리 순서와 데이터 소유, 통신 방식이 현실적입니다.', 25),
('MSA API Gateway와 서비스 분리 기준', 3, '게이트웨이 설계', '라우팅과 인증 처리 위치가 명확합니다.', 25),
('MSA API Gateway와 서비스 분리 기준', 4, '장애 격리', '타임아웃과 서킷 브레이커 설정을 근거 있게 제안했습니다.', 20),
('Kafka와 Kafka 토픽 흐름', 1, '파이프라인 구현', '키 기반 발행과 그룹별 소비가 동작합니다.', 30),
('Kafka와 Kafka 토픽 흐름', 2, '실패 처리', '재시도와 DLT 흐름이 올바르게 구성되어 있습니다.', 25),
('Kafka와 Kafka 토픽 흐름', 3, '멱등 처리', '중복 이벤트를 안전하게 처리합니다.', 25),
('Kafka와 Kafka 토픽 흐름', 4, '실험과 해석', '리밸런싱 등 실험 결과를 해석했습니다.', 20),
('GitHub Actions와 CI/CD 자동화', 1, 'CI 최적화', '캐시를 적용한 테스트와 빌드가 동작합니다.', 20),
('GitHub Actions와 CI/CD 자동화', 2, '환경별 배포', '스테이징 자동 배포와 운영 승인 배포가 분리되어 있습니다.', 35),
('GitHub Actions와 CI/CD 자동화', 3, '롤백', '헬스 체크 실패 시 롤백이 동작합니다.', 25),
('GitHub Actions와 CI/CD 자동화', 4, '재사용성', '공통 단계를 재사용 워크플로로 분리했습니다.', 20),
('Docker와 docker-compose 실전', 1, '이미지 품질', '멀티 스테이지 빌드로 이미지를 최적화했습니다.', 20),
('Docker와 docker-compose 실전', 2, 'compose 구성', '서비스, 네트워크, 볼륨이 올바르게 구성되어 있습니다.', 30),
('Docker와 docker-compose 실전', 3, '안정성', '헬스 체크와 시작 순서로 안정적으로 기동됩니다.', 25),
('Docker와 docker-compose 실전', 4, '설정 관리', '비밀 값이 분리되어 있고 README로 재현할 수 있습니다.', 25),
('Redis Session, Pub/Sub, 분산 락', 1, '세션 공유', '서버를 바꿔도 로그인 상태가 유지됩니다.', 25),
('Redis Session, Pub/Sub, 분산 락', 2, '실시간 알림', '어느 서버에 연결된 사용자에게도 알림이 전달됩니다.', 25),
('Redis Session, Pub/Sub, 분산 락', 3, '중복 방지', '동시 요청에서 주문이 한 건만 처리됩니다.', 30),
('Redis Session, Pub/Sub, 분산 락', 4, '설계 근거', '락 시간과 트랜잭션 순서를 근거 있게 설명했습니다.', 20),
('Redis 자료구조, TTL, Spring Cache', 1, '캐시 단위 설계', '데이터 성격에 따라 캐시를 나눴습니다.', 25),
('Redis 자료구조, TTL, Spring Cache', 2, 'TTL과 갱신', '캐시별 TTL과 갱신 시점이 적절합니다.', 30),
('Redis 자료구조, TTL, Spring Cache', 3, '관통 방지', '없는 데이터 조회가 DB로 몰리지 않습니다.', 20),
('Redis 자료구조, TTL, Spring Cache', 4, '측정', '적중률과 응답 시간을 측정해 해석했습니다.', 25),
('인덱스, 트랜잭션, PostgreSQL 성능 기본기', 1, '실행 계획 분석', '느린 쿼리의 병목을 실행 계획으로 찾았습니다.', 25),
('인덱스, 트랜잭션, PostgreSQL 성능 기본기', 2, '인덱스 설계', '쿼리에 맞는 인덱스를 설계하고 효과를 비교했습니다.', 30),
('인덱스, 트랜잭션, PostgreSQL 성능 기본기', 3, '동시성 해결', '재고 동시 차감 문제를 재현하고 해결했습니다.', 25),
('인덱스, 트랜잭션, PostgreSQL 성능 기본기', 4, '데드락 이해', '데드락 상황과 예방 방법을 정리했습니다.', 20),
('SQL JOIN과 서브쿼리 패턴', 1, '정확성', '문제마다 결과가 요구사항과 일치합니다.', 40),
('SQL JOIN과 서브쿼리 패턴', 2, '패턴 활용', 'JOIN, 서브쿼리, CTE를 상황에 맞게 사용했습니다.', 25),
('SQL JOIN과 서브쿼리 패턴', 3, '대안 비교', '다른 풀이와 비교해 장단점을 설명했습니다.', 20),
('SQL JOIN과 서브쿼리 패턴', 4, '가독성', '쿼리가 읽기 쉽게 정리되어 있습니다.', 15);

-- 소개글
UPDATE courses c
SET subtitle = s.subtitle,
    description = s.description,
    updated_at = NOW()
FROM seed_course_content s
WHERE c.title = s.course_title;

-- 상세 정보: 강의에 상세 항목이 하나도 없을 때만 넣는다(강사가 편집한 내용은 보존).
INSERT INTO course_info_section_items (
    course_id, section_key, section_title, section_order, item_order, item_text
)
SELECT
    c.course_id,
    i.section_key,
    CASE i.section_key
        WHEN 'TARGET_AUDIENCE' THEN '이런 분들께 추천합니다'
        WHEN 'PREREQUISITES' THEN '수강 전 알아두면 좋습니다'
        ELSE '이 강의를 끝내면'
    END,
    CASE i.section_key
        WHEN 'TARGET_AUDIENCE' THEN 0
        WHEN 'PREREQUISITES' THEN 1
        ELSE 2
    END,
    i.item_order,
    i.item_text
FROM seed_course_info i
JOIN courses c ON c.title = i.course_title
WHERE NOT EXISTS (
    SELECT 1 FROM course_info_section_items e WHERE e.course_id = c.course_id
);

-- 커리큘럼: 섹션 순번, 레슨 순번 기준으로 제목과 설명을 바꾼다.
UPDATE course_sections cs
SET title = x.section_title,
    description = x.section_description
FROM (
    SELECT DISTINCT course_title, section_order, section_title, section_description
    FROM seed_course_curriculum
) x
JOIN courses c ON c.title = x.course_title
WHERE cs.course_id = c.course_id
  AND cs.sort_order = x.section_order;

UPDATE lessons l
SET title = x.lesson_title,
    description = x.lesson_description
FROM seed_course_curriculum x
JOIN courses c ON c.title = x.course_title
JOIN course_sections cs ON cs.course_id = c.course_id AND cs.sort_order = x.section_order
WHERE l.section_id = cs.section_id
  AND l.sort_order = x.lesson_order;

-- 퀴즈와 과제: 첫 섹션 끝에 퀴즈 레슨, 마지막 섹션 끝에 과제 레슨을 둔다.
-- 이미 퀴즈/과제 레슨이 있는 강의는 레슨을 새로 만들지 않고 문항과 루브릭만 교체한다.
DO $$
DECLARE
    r RECORD;
    q RECORD;
    v_eval_roadmap_id BIGINT;
    v_course_id BIGINT;
    v_section_id BIGINT;
    v_lesson_id BIGINT;
    v_node_id BIGINT;
    v_quiz_id BIGINT;
    v_question_id BIGINT;
    v_assignment_id BIGINT;
BEGIN
    SELECT roadmap_id INTO v_eval_roadmap_id
    FROM roadmaps
    WHERE title = 'DevPath 공개 강의 평가 데이터'
    ORDER BY roadmap_id
    LIMIT 1;

    IF v_eval_roadmap_id IS NULL THEN
        RETURN;
    END IF;

    FOR r IN SELECT * FROM seed_course_quiz ORDER BY course_title LOOP
        SELECT course_id INTO v_course_id
        FROM courses WHERE title = r.course_title ORDER BY course_id LIMIT 1;
        CONTINUE WHEN v_course_id IS NULL;

        SELECT l.lesson_id, l.quiz_node_id INTO v_lesson_id, v_node_id
        FROM lessons l
        JOIN course_sections cs ON cs.section_id = l.section_id
        WHERE cs.course_id = v_course_id AND l.quiz_node_id IS NOT NULL
        ORDER BY cs.sort_order, l.sort_order
        LIMIT 1;

        IF v_lesson_id IS NULL THEN
            SELECT section_id INTO v_section_id
            FROM course_sections WHERE course_id = v_course_id
            ORDER BY sort_order, section_id
            LIMIT 1;
            CONTINUE WHEN v_section_id IS NULL;

            INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, section_order)
            VALUES (v_eval_roadmap_id, r.lesson_title, r.lesson_description, 'COURSE_QUIZ', 0, r.course_title, 1)
            RETURNING node_id INTO v_node_id;

            INSERT INTO lessons (
                section_id, title, description, lesson_type, duration_seconds,
                is_preview, is_published, sort_order, quiz_node_id
            )
            SELECT v_section_id, r.lesson_title, r.lesson_description, 'READING', 300,
                   FALSE, TRUE, COALESCE(MAX(sort_order), 0) + 1, v_node_id
            FROM lessons WHERE section_id = v_section_id;

            INSERT INTO course_node_mappings (course_id, node_id, created_at)
            VALUES (v_course_id, v_node_id, NOW());
        ELSE
            UPDATE lessons
            SET title = r.lesson_title, description = r.lesson_description
            WHERE lesson_id = v_lesson_id;
        END IF;

        SELECT quiz_id INTO v_quiz_id
        FROM quizzes
        WHERE node_id = v_node_id AND is_deleted = FALSE
        ORDER BY created_at DESC NULLS LAST, quiz_id DESC
        LIMIT 1;

        IF v_quiz_id IS NULL THEN
            INSERT INTO quizzes (
                node_id, title, description, quiz_type, total_score, pass_score,
                time_limit_minutes, is_published, is_active, expose_answer,
                expose_explanation, is_deleted, created_at, updated_at
            )
            VALUES (
                v_node_id, r.quiz_title, r.quiz_description, 'MANUAL', 0, 60,
                10, TRUE, TRUE, TRUE, TRUE, FALSE, NOW(), NOW()
            )
            RETURNING quiz_id INTO v_quiz_id;
        END IF;

        IF EXISTS (
            SELECT 1
            FROM seed_course_quiz_question sq
            WHERE sq.course_title = r.course_title
              AND NOT EXISTS (
                  SELECT 1 FROM quiz_questions qq
                  WHERE qq.quiz_id = v_quiz_id
                    AND qq.is_deleted = FALSE
                    AND qq.question_text = sq.question_text
              )
        ) THEN
            UPDATE quiz_question_options
            SET is_deleted = TRUE, updated_at = NOW()
            WHERE is_deleted = FALSE
              AND question_id IN (
                  SELECT question_id FROM quiz_questions
                  WHERE quiz_id = v_quiz_id AND is_deleted = FALSE
              );

            UPDATE quiz_questions
            SET is_deleted = TRUE, updated_at = NOW()
            WHERE quiz_id = v_quiz_id AND is_deleted = FALSE;

            FOR q IN
                SELECT * FROM seed_course_quiz_question
                WHERE course_title = r.course_title
                ORDER BY display_order
            LOOP
                INSERT INTO quiz_questions (
                    quiz_id, question_type, question_text, explanation, points,
                    display_order, is_deleted, created_at, updated_at
                )
                VALUES (
                    v_quiz_id, 'MULTIPLE_CHOICE', q.question_text, q.explanation, 20,
                    q.display_order, FALSE, NOW(), NOW()
                )
                RETURNING question_id INTO v_question_id;

                INSERT INTO quiz_question_options (
                    question_id, option_text, is_correct, display_order, is_deleted, created_at, updated_at
                )
                SELECT v_question_id, o.option_text, o.idx = q.correct_option, o.idx - 1, FALSE, NOW(), NOW()
                FROM unnest(ARRAY[q.option1, q.option2, q.option3, q.option4])
                     WITH ORDINALITY AS o(option_text, idx);
            END LOOP;
        END IF;

        UPDATE quizzes
        SET title = r.quiz_title,
            description = r.quiz_description,
            quiz_type = 'MANUAL',
            total_score = (
                SELECT COALESCE(SUM(points), 0) FROM quiz_questions
                WHERE quiz_id = v_quiz_id AND is_deleted = FALSE
            ),
            pass_score = 60,
            time_limit_minutes = 10,
            is_published = TRUE,
            is_active = TRUE,
            expose_answer = TRUE,
            expose_explanation = TRUE,
            updated_at = NOW()
        WHERE quiz_id = v_quiz_id;
    END LOOP;

    FOR r IN SELECT * FROM seed_course_assignment ORDER BY course_title LOOP
        SELECT course_id INTO v_course_id
        FROM courses WHERE title = r.course_title ORDER BY course_id LIMIT 1;
        CONTINUE WHEN v_course_id IS NULL;

        SELECT l.lesson_id, l.assignment_node_id INTO v_lesson_id, v_node_id
        FROM lessons l
        JOIN course_sections cs ON cs.section_id = l.section_id
        WHERE cs.course_id = v_course_id AND l.assignment_node_id IS NOT NULL
        ORDER BY cs.sort_order DESC, l.sort_order DESC
        LIMIT 1;

        IF v_lesson_id IS NULL THEN
            SELECT section_id INTO v_section_id
            FROM course_sections WHERE course_id = v_course_id
            ORDER BY sort_order DESC, section_id DESC
            LIMIT 1;
            CONTINUE WHEN v_section_id IS NULL;

            INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, section_order)
            VALUES (v_eval_roadmap_id, r.lesson_title, r.lesson_description, 'COURSE_ASSIGNMENT', 0, r.course_title, 2)
            RETURNING node_id INTO v_node_id;

            INSERT INTO lessons (
                section_id, title, description, lesson_type, duration_seconds,
                is_preview, is_published, sort_order, assignment_node_id
            )
            SELECT v_section_id, r.lesson_title, r.lesson_description, 'CODING', 900,
                   FALSE, TRUE, COALESCE(MAX(sort_order), 0) + 1, v_node_id
            FROM lessons WHERE section_id = v_section_id;

            INSERT INTO course_node_mappings (course_id, node_id, created_at)
            VALUES (v_course_id, v_node_id, NOW());
        ELSE
            UPDATE lessons
            SET title = r.lesson_title, description = r.lesson_description
            WHERE lesson_id = v_lesson_id;
        END IF;

        SELECT assignment_id INTO v_assignment_id
        FROM assignments
        WHERE node_id = v_node_id AND is_deleted = FALSE
        ORDER BY created_at DESC NULLS LAST, assignment_id DESC
        LIMIT 1;

        IF v_assignment_id IS NULL THEN
            INSERT INTO assignments (
                node_id, title, description, submission_type, total_score, pass_score,
                readme_required, test_required, lint_required, is_published, is_active,
                allow_late_submission, is_deleted, created_at, updated_at
            )
            VALUES (
                v_node_id, r.assignment_title, r.assignment_description, 'MULTIPLE', 100, 70,
                FALSE, FALSE, FALSE, TRUE, TRUE,
                TRUE, FALSE, NOW(), NOW()
            )
            RETURNING assignment_id INTO v_assignment_id;
        END IF;

        UPDATE assignments
        SET title = r.assignment_title,
            description = r.assignment_description,
            submission_type = 'MULTIPLE',
            due_at = NULL,
            allowed_file_formats = 'md,pdf,zip',
            submission_rule_description = r.submission_rule,
            total_score = 100,
            pass_score = 70,
            is_published = TRUE,
            is_active = TRUE,
            allow_late_submission = TRUE,
            ai_review_enabled = TRUE,
            allow_text_submission = TRUE,
            allow_file_submission = TRUE,
            allow_url_submission = TRUE,
            updated_at = NOW()
        WHERE assignment_id = v_assignment_id;

        IF EXISTS (
            SELECT 1
            FROM seed_course_assignment_rubric sr
            WHERE sr.course_title = r.course_title
              AND NOT EXISTS (
                  SELECT 1 FROM assignment_rubrics ar
                  WHERE ar.assignment_id = v_assignment_id
                    AND ar.is_deleted = FALSE
                    AND ar.criteria_name = sr.criteria_name
              )
        ) THEN
            UPDATE assignment_rubrics
            SET is_deleted = TRUE, updated_at = NOW()
            WHERE assignment_id = v_assignment_id AND is_deleted = FALSE;

            INSERT INTO assignment_rubrics (
                assignment_id, criteria_name, criteria_description,
                max_points, display_order, is_deleted, created_at, updated_at
            )
            SELECT v_assignment_id, sr.criteria_name, sr.criteria_description,
                   sr.max_points, sr.display_order, FALSE, NOW(), NOW()
            FROM seed_course_assignment_rubric sr
            WHERE sr.course_title = r.course_title;
        END IF;
    END LOOP;
END $$;

DROP TABLE seed_course_content;
DROP TABLE seed_course_info;
DROP TABLE seed_course_curriculum;
DROP TABLE seed_course_quiz;
DROP TABLE seed_course_quiz_question;
DROP TABLE seed_course_assignment;
DROP TABLE seed_course_assignment_rubric;
