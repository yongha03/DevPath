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
    '$2a$10$xh6.EW/FRzJBWfxqpdXh2uTVoepPhUxQRUH5OEwk90IpYeKjegkj.',
    'Learner Kim',
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
    'Instructor Hong',
    'ROLE_INSTRUCTOR',
    TRUE,
    NOW(),
    NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM users
    WHERE email = 'instructor@devpath.com'
);

INSERT INTO users (email, password, name, role_name, is_active, created_at, updated_at)
SELECT
    'admin@devpath.com',
    '$2a$10$xh6.EW/FRzJBWfxqpdXh2uTVoepPhUxQRUH5OEwk90IpYeKjegkj.',
    'Admin Park',
    'ROLE_ADMIN',
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
WHERE email IN ('learner@devpath.com', 'instructor@devpath.com', 'admin@devpath.com');

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
    'Hong Backend Lab',
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
    'DevPath Admin',
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
    channel_name = 'Hong Backend Lab',
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
    channel_name = 'DevPath Admin',
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
    'Security and JWT',
    'Build authentication and authorization flows with Spring Security and JWT.',
    'CONCEPT',
    5
FROM roadmaps r
WHERE r.title = 'Backend Master Roadmap'
  AND NOT EXISTS (
      SELECT 1
      FROM roadmap_nodes
      WHERE roadmap_id = r.roadmap_id
        AND title = 'Security and JWT'
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

INSERT INTO prerequisites (node_id, pre_node_id)
SELECT n2.node_id, n1.node_id
FROM roadmap_nodes n1, roadmap_nodes n2
WHERE n1.title = 'Java Basics'
  AND n2.title = 'HTTP Fundamentals'
  AND NOT EXISTS (
      SELECT 1
      FROM prerequisites p
      WHERE p.node_id = n2.node_id
        AND p.pre_node_id = n1.node_id
  );

INSERT INTO prerequisites (node_id, pre_node_id)
SELECT n2.node_id, n1.node_id
FROM roadmap_nodes n1, roadmap_nodes n2
WHERE n1.title = 'HTTP Fundamentals'
  AND n2.title = 'Spring Boot Basics'
  AND NOT EXISTS (
      SELECT 1
      FROM prerequisites p
      WHERE p.node_id = n2.node_id
        AND p.pre_node_id = n1.node_id
  );

INSERT INTO prerequisites (node_id, pre_node_id)
SELECT n2.node_id, n1.node_id
FROM roadmap_nodes n1, roadmap_nodes n2
WHERE n1.title = 'Spring Boot Basics'
  AND n2.title = 'Spring Data JPA'
  AND NOT EXISTS (
      SELECT 1
      FROM prerequisites p
      WHERE p.node_id = n2.node_id
        AND p.pre_node_id = n1.node_id
  );

INSERT INTO prerequisites (node_id, pre_node_id)
SELECT n2.node_id, n1.node_id
FROM roadmap_nodes n1, roadmap_nodes n2
WHERE n1.title = 'Spring Data JPA'
  AND n2.title = 'Security and JWT'
  AND NOT EXISTS (
      SELECT 1
      FROM prerequisites p
      WHERE p.node_id = n2.node_id
        AND p.pre_node_id = n1.node_id
  );

INSERT INTO prerequisites (node_id, pre_node_id)
SELECT n2.node_id, n1.node_id
FROM roadmap_nodes n1, roadmap_nodes n2
WHERE n1.title = 'Security and JWT'
  AND n2.title = 'Docker Deployment Basics'
  AND NOT EXISTS (
      SELECT 1
      FROM prerequisites p
      WHERE p.node_id = n2.node_id
        AND p.pre_node_id = n1.node_id
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
       'Restricted Learner', 'ROLE_LEARNER', FALSE, 'RESTRICTED',
       '2026-02-01 00:00:00', '2026-02-15 00:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM users WHERE email = 'restricted-user@devpath.com'
);

INSERT INTO users (
    email, password, name, role_name, is_active, account_status, created_at, updated_at
)
SELECT 'deactivated-user@devpath.com',
       '$2a$10$RcdWJBwl.kuttYmqm/BN..6aZKeLNlq9DiNFHbZgZxfTzzNDD33o2',
       'Deactivated Learner', 'ROLE_LEARNER', FALSE, 'DEACTIVATED',
       '2026-02-01 00:00:00', '2026-02-16 00:00:00'
WHERE NOT EXISTS (
    SELECT 1 FROM users WHERE email = 'deactivated-user@devpath.com'
);

INSERT INTO users (
    email, password, name, role_name, is_active, account_status, created_at, updated_at
)
SELECT 'withdrawn-user@devpath.com',
       '$2a$10$RcdWJBwl.kuttYmqm/BN..6aZKeLNlq9DiNFHbZgZxfTzzNDD33o2',
       'Withdrawn Learner', 'ROLE_LEARNER', FALSE, 'WITHDRAWN',
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
    'Learner Park',
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
    'Learner Lee',
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
INSERT INTO project (name, description, status, is_deleted, created_at)
SELECT
    'DevPath Team Workspace',
    'DevPath 팀 협업 워크스페이스용 프로젝트. 역할 배정, 멘토링, Proof 제출 테스트용 데이터',
    'IN_PROGRESS',
    FALSE,
    '2026-03-23 14:00:00'
WHERE NOT EXISTS (
    SELECT 1
    FROM project
    WHERE name = 'DevPath Team Workspace'
      AND is_deleted = FALSE
);

INSERT INTO project (name, description, status, is_deleted, created_at)
SELECT
    'Portfolio Builder Squad',
    '포트폴리오 제작 중심의 준비중 프로젝트. 초대 거절/멘토링 승인 시나리오 테스트용 데이터',
    'PREPARING',
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
    'Learner Choi',
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

-- 18단계: node_completion_rules, node_recommendations, node_required_tags, prerequisites
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

DELETE FROM prerequisites
WHERE node_id IN (
    SELECT node_id FROM roadmap_nodes
    WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap')
) OR pre_node_id IN (
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

-- 22단계: roadmap_nodes 삭제 (모든 자식 정리 완료)
DELETE FROM roadmap_nodes
WHERE roadmap_id = (SELECT roadmap_id FROM roadmaps WHERE title = 'Backend Master Roadmap');

-- 척추 노드 (branch_group = NULL)
INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, branch_group)
SELECT r.roadmap_id, '인터넷 & 웹 기초',
       'HTTP/HTTPS 동작 방식, DNS 조회 원리, 도메인과 호스팅 개념을 이해하고 브라우저가 서버와 통신하는 전체 흐름을 학습합니다.',
       'CONCEPT', 1, 'HTTP/HTTPS,DNS 작동원리,도메인,호스팅,브라우저', NULL
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, branch_group)
SELECT r.roadmap_id, 'OS & 터미널',
       'Linux/Unix 운영체제 기본 명령어, 파일 시스템, 프로세스·스레드 관리, 메모리·I/O 관리 원리를 학습합니다.',
       'CONCEPT', 2, 'Terminal 사용법,프로세스 관리,스레드와 동시성,메모리 관리,I/O 관리', NULL
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, branch_group)
SELECT r.roadmap_id, 'Java 기초',
       '변수/자료형, 제어문, 클래스·객체, 상속·다형성·캡슐화를 학습하고 Java로 기본 프로그램을 작성할 수 있습니다.',
       'CONCEPT', 3, 'OOP,클래스와 객체,상속,인터페이스,제네릭,컬렉션 프레임워크', NULL
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, branch_group)
SELECT r.roadmap_id, 'Git & 버전 관리',
       'Git init/add/commit/branch/merge/rebase를 익히고 GitHub Pull Request 기반의 협업 워크플로우를 학습합니다.',
       'PRACTICE', 4, 'Git 기초,브랜치 전략,GitFlow,Pull Request,코드 리뷰', NULL
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, branch_group)
SELECT r.roadmap_id, 'RDB & SQL',
       '관계형 데이터베이스 구조, 정규화, SELECT/JOIN/서브쿼리/집계함수를 학습하고 트랜잭션(ACID)의 원리를 이해합니다.',
       'CONCEPT', 5, 'SQL CRUD,JOIN,서브쿼리,인덱스,트랜잭션,ACID,PostgreSQL', NULL
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, branch_group)
SELECT r.roadmap_id, 'REST API 설계',
       'REST 원칙, URI 명사형 설계, HTTP 메서드 활용, 상태코드 전략, Swagger(OpenAPI 3.0) 문서화를 학습합니다.',
       'CONCEPT', 6, 'REST 원칙,URI 설계,HTTP 메서드,상태코드,Swagger,OpenAPI', NULL
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, branch_group)
SELECT r.roadmap_id, 'Spring Boot & MVC',
       'Auto-configuration, @Bean/@Component, DispatcherServlet, Controller-Service-Repository 3계층 구조를 학습합니다.',
       'CONCEPT', 7, 'DI/IoC,@Bean,Auto-configuration,DispatcherServlet,3계층 구조', NULL
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, branch_group)
SELECT r.roadmap_id, 'Spring Data JPA',
       'Entity 설계, Repository 패턴, JPQL, FetchType(LAZY/EAGER), N+1 문제 해결 방법을 학습합니다.',
       'CONCEPT', 8, 'Entity 매핑,Repository,JPQL,FetchType,N+1 해결,QueryDSL', NULL
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

-- 분기 노드 (sort 9-10, 좌: Redis, 우: 테스트)
INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, branch_group)
SELECT r.roadmap_id, 'Redis 기초',
       'Redis 자료구조(String/Hash/List/Set/ZSet), TTL 설정, Spring Cache(@Cacheable) 연동을 학습합니다.',
       'PRACTICE', 9, 'String/Hash/List/Set/ZSet,TTL,Spring Cache,@Cacheable', 1
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, branch_group)
SELECT r.roadmap_id, 'Redis 심화',
       'Session 저장, JWT 블랙리스트 관리, Pub/Sub 메시지, 분산 락(Redisson)을 학습합니다.',
       'PRACTICE', 10, 'Session 저장,JWT 블랙리스트,Pub/Sub,분산 락,Redisson', 1
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, branch_group)
SELECT r.roadmap_id, 'JUnit5 & Mockito',
       '@Test, @BeforeEach, Mock/Spy 객체, verify 검증을 활용한 단위 테스트 작성법을 학습합니다.',
       'PRACTICE', 9, '@Test,@BeforeEach,Mock/Spy,verify,assertThat,BDD', 2
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, branch_group)
SELECT r.roadmap_id, 'Spring Boot 테스트',
       '@SpringBootTest, @WebMvcTest, MockMvc, TestRestTemplate를 활용한 통합 테스트 작성법을 학습합니다.',
       'PRACTICE', 10, '@SpringBootTest,@WebMvcTest,MockMvc,TestRestTemplate,JaCoCo', 2
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

-- 척추 뒷부분 (sort 11-15, branch_group = NULL)
INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, branch_group)
SELECT r.roadmap_id, 'Spring Security & JWT',
       'SecurityFilterChain, Access/Refresh Token 구조, OncePerRequestFilter, OAuth2 소셜 로그인을 학습합니다.',
       'CONCEPT', 11, 'SecurityFilterChain,JWT 구조,Access/Refresh Token,OAuth2,소셜 로그인', NULL
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, branch_group)
SELECT r.roadmap_id, 'Docker & CI/CD',
       'Dockerfile 작성, docker-compose 설정, GitHub Actions를 활용한 자동 빌드·테스트·배포 파이프라인을 구축합니다.',
       'PRACTICE', 12, 'Dockerfile,docker-compose,GitHub Actions,CI/CD 파이프라인,AWS EC2', NULL
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, branch_group)
SELECT r.roadmap_id, 'SOLID & 디자인패턴',
       'SOLID 5원칙을 이해하고 GoF 디자인 패턴(Singleton/Factory/Strategy/Observer/Builder)을 코드에 적용합니다.',
       'CONCEPT', 13, 'SRP,OCP,LSP,ISP,DIP,Singleton,Factory,Strategy,Observer', NULL
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, branch_group)
SELECT r.roadmap_id, '웹 보안 기초',
       'OWASP Top 10 취약점을 이해하고 XSS/CSRF/SQL Injection 방어, HTTPS/TLS 설정을 학습합니다.',
       'CONCEPT', 14, 'OWASP Top 10,XSS,CSRF,SQL Injection,HTTPS/TLS,CORS,Rate Limiting', NULL
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, branch_group)
SELECT r.roadmap_id, '메시지 큐 & MSA',
       'Kafka Topic/Producer/Consumer와 MSA 서비스 분리 기준, API Gateway 패턴을 학습합니다.',
       'CONCEPT', 15, 'Kafka,Topic/Partition,Producer/Consumer,MSA,API Gateway,서비스 분리', NULL
FROM roadmaps r WHERE r.title = 'Backend Master Roadmap';

-- learner@devpath.com 커스텀 로드맵 재생성
INSERT INTO custom_roadmaps (user_id, original_roadmap_id, title, progress_rate, created_at, updated_at)
SELECT u.user_id, r.roadmap_id, r.title, 0,
       TIMESTAMP '2026-03-28 10:00:00', TIMESTAMP '2026-03-28 10:00:00'
FROM users u
JOIN roadmaps r ON r.title = 'Backend Master Roadmap'
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM custom_roadmaps cr
      WHERE cr.user_id = u.user_id AND cr.original_roadmap_id = r.roadmap_id
  );

INSERT INTO custom_roadmap_nodes (custom_roadmap_id, original_node_id, status, custom_sort_order, is_branch, branch_from_node_id, branch_type, started_at, completed_at)
SELECT cr.custom_roadmap_id,
       rn.node_id,
       CASE
           WHEN rn.sort_order <= 2 THEN 'COMPLETED'
           WHEN rn.sort_order = 3  THEN 'IN_PROGRESS'
           ELSE 'NOT_STARTED'
       END,
       rn.sort_order,
       false,
       NULL,
       NULL,
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

-- learner 커스텀 로드맵 순차 prerequisite 체인 (n+1번 노드는 n번 노드를 선행으로 가짐)
INSERT INTO custom_node_prerequisites (custom_roadmap_id, custom_node_id, prerequisite_custom_node_id)
SELECT cr.custom_roadmap_id, n_cur.custom_node_id, n_pre.custom_node_id
FROM custom_roadmaps cr
JOIN users u ON u.user_id = cr.user_id
JOIN roadmaps r ON r.roadmap_id = cr.original_roadmap_id
JOIN custom_roadmap_nodes n_cur ON n_cur.custom_roadmap_id = cr.custom_roadmap_id
JOIN roadmap_nodes rn_cur ON rn_cur.node_id = n_cur.original_node_id
JOIN roadmap_nodes rn_pre ON rn_pre.roadmap_id = r.roadmap_id AND rn_pre.sort_order = rn_cur.sort_order - 1
JOIN custom_roadmap_nodes n_pre ON n_pre.custom_roadmap_id = cr.custom_roadmap_id AND n_pre.original_node_id = rn_pre.node_id
WHERE u.email = 'learner@devpath.com'
  AND r.title = 'Backend Master Roadmap'
  AND rn_cur.sort_order > 1
  AND rn_cur.title NOT LIKE '[TEST]%'
  AND NOT EXISTS (
      SELECT 1 FROM custom_node_prerequisites cnp
      WHERE cnp.custom_roadmap_id = cr.custom_roadmap_id
        AND cnp.custom_node_id = n_cur.custom_node_id
        AND cnp.prerequisite_custom_node_id = n_pre.custom_node_id
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
    '김소연',
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
    'Frontend Craft',
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
    'AI Data Lab',
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
        ('React 19 프론트엔드 실전 가이드', 2, 3, '실습 과제: 대시보드 화면 완성', '필터, 카드, 차트를 포함한 대시보드 화면을 제출합니다.', 'CODING', NULL, 900, FALSE),
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

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order, sub_topics, branch_group)
WITH activity_nodes(course_title, section_order, activity_kind, node_title, node_content, sort_order) AS (
    VALUES
        ('실무 Spring Boot 백엔드 입문', 1, 'QUIZ', '[CATALOG] 실무 Spring Boot 백엔드 입문 - 1 QUIZ', 'Spring Boot 계층 구조와 요청 흐름을 확인하는 퀴즈입니다.', 1001),
        ('실무 Spring Boot 백엔드 입문', 2, 'ASSIGNMENT', '[CATALOG] 실무 Spring Boot 백엔드 입문 - 2 ASSIGNMENT', '회원 API와 JWT 로그인 흐름을 완성하는 과제입니다.', 1002),
        ('Docker & Kubernetes 운영 실전', 1, 'QUIZ', '[CATALOG] Docker & Kubernetes 운영 실전 - 1 QUIZ', '이미지, 컨테이너, Compose 실행 흐름을 확인하는 퀴즈입니다.', 1011),
        ('Docker & Kubernetes 운영 실전', 2, 'ASSIGNMENT', '[CATALOG] Docker & Kubernetes 운영 실전 - 2 ASSIGNMENT', 'Kubernetes 배포 매니페스트를 작성하는 과제입니다.', 1012),
        ('React 19 프론트엔드 실전 가이드', 1, 'QUIZ', '[CATALOG] React 19 프론트엔드 실전 가이드 - 1 QUIZ', 'React 상태 설계와 컴포넌트 경계를 확인하는 퀴즈입니다.', 1021),
        ('React 19 프론트엔드 실전 가이드', 2, 'ASSIGNMENT', '[CATALOG] React 19 프론트엔드 실전 가이드 - 2 ASSIGNMENT', '대시보드 화면과 테스트 흐름을 완성하는 과제입니다.', 1022),
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
                         AND rn.branch_group = cs.sort_order
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
                           AND rn.branch_group = cs.sort_order
                           AND rn.node_type = 'QUIZ'
      WHERE cs.section_id = l.section_id
  );

UPDATE lessons l
SET assignment_node_id = (
    SELECT rn.node_id
    FROM course_sections cs
    JOIN courses c ON c.course_id = cs.course_id
    JOIN roadmap_nodes rn ON rn.sub_topics = c.title
                         AND rn.branch_group = cs.sort_order
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
                           AND rn.branch_group = cs.sort_order
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
