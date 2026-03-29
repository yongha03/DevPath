-- OCR schema backfill for environments that already have ocr_results rows.
ALTER TABLE ocr_results
    ADD COLUMN IF NOT EXISTS source_image_url VARCHAR(500);

ALTER TABLE ocr_results
    ADD COLUMN IF NOT EXISTS status VARCHAR(30);

ALTER TABLE ocr_results
    ADD COLUMN IF NOT EXISTS searchable_normalized_text TEXT;

ALTER TABLE ocr_results
    ADD COLUMN IF NOT EXISTS timestamp_mappings TEXT;

ALTER TABLE ocr_results
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP;

-- Fill defaults before tightening the new non-null columns.
UPDATE ocr_results
SET source_image_url = COALESCE(source_image_url, '')
WHERE source_image_url IS NULL;

UPDATE ocr_results
SET status = COALESCE(status, 'REQUESTED')
WHERE status IS NULL;

UPDATE ocr_results
SET searchable_normalized_text = COALESCE(searchable_normalized_text, LOWER(REGEXP_REPLACE(TRIM(extracted_text), '\s+', ' ', 'g')))
WHERE searchable_normalized_text IS NULL
  AND extracted_text IS NOT NULL;

UPDATE ocr_results
SET timestamp_mappings = COALESCE(
    timestamp_mappings,
    '[{"second":' || COALESCE(frame_timestamp_second, 0) || ',"text":"' ||
    REPLACE(REPLACE(REPLACE(COALESCE(extracted_text, ''), E'\\', E'\\\\'), '"', E'\\"'), E'\n', ' ') ||
    '"}]'
)
WHERE timestamp_mappings IS NULL;

UPDATE ocr_results
SET updated_at = COALESCE(updated_at, created_at, NOW())
WHERE updated_at IS NULL;

ALTER TABLE ocr_results
    ALTER COLUMN source_image_url SET DEFAULT '';

ALTER TABLE ocr_results
    ALTER COLUMN source_image_url SET NOT NULL;

ALTER TABLE ocr_results
    ALTER COLUMN status SET DEFAULT 'REQUESTED';

ALTER TABLE ocr_results
    ALTER COLUMN status SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_ocr_results_user_lesson_frame
    ON ocr_results (user_id, lesson_id, frame_timestamp_second);

-- Recommendation support columns for history, warning, and supplement tracking.
ALTER TABLE recommendation_histories
    ADD COLUMN IF NOT EXISTS recommendation_id BIGINT;

ALTER TABLE recommendation_histories
    ADD COLUMN IF NOT EXISTS node_id BIGINT;

ALTER TABLE recommendation_histories
    ADD COLUMN IF NOT EXISTS action_type VARCHAR(30);

UPDATE recommendation_histories
SET action_type = COALESCE(action_type, 'GENERATED')
WHERE action_type IS NULL;

ALTER TABLE recommendation_histories
    ALTER COLUMN action_type SET DEFAULT 'GENERATED';

ALTER TABLE recommendation_histories
    ALTER COLUMN action_type SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_recommendation_histories_user_created_at
    ON recommendation_histories (user_id, created_at);

CREATE INDEX IF NOT EXISTS idx_recommendation_histories_user_recommendation_id
    ON recommendation_histories (user_id, recommendation_id);

CREATE INDEX IF NOT EXISTS idx_recommendation_histories_user_node_id
    ON recommendation_histories (user_id, node_id);

ALTER TABLE risk_warnings
    ADD COLUMN IF NOT EXISTS risk_level VARCHAR(20);

ALTER TABLE risk_warnings
    ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMP;

UPDATE risk_warnings
SET risk_level = COALESCE(risk_level, 'MEDIUM')
WHERE risk_level IS NULL;

UPDATE risk_warnings
SET acknowledged_at = COALESCE(acknowledged_at, created_at)
WHERE is_acknowledged = TRUE
  AND acknowledged_at IS NULL;

ALTER TABLE risk_warnings
    ALTER COLUMN risk_level SET DEFAULT 'MEDIUM';

ALTER TABLE risk_warnings
    ALTER COLUMN risk_level SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_risk_warnings_user_created_at
    ON risk_warnings (user_id, created_at);

CREATE INDEX IF NOT EXISTS idx_risk_warnings_user_acknowledged
    ON risk_warnings (user_id, is_acknowledged, created_at);

CREATE INDEX IF NOT EXISTS idx_risk_warnings_user_node_id
    ON risk_warnings (user_id, node_id);

ALTER TABLE supplement_recommendations
    ADD COLUMN IF NOT EXISTS priority INTEGER;

ALTER TABLE supplement_recommendations
    ADD COLUMN IF NOT EXISTS coverage_percent DOUBLE PRECISION;

ALTER TABLE supplement_recommendations
    ADD COLUMN IF NOT EXISTS missing_tag_count INTEGER;

ALTER TABLE supplement_recommendations
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP;

UPDATE supplement_recommendations
SET updated_at = COALESCE(updated_at, created_at, NOW())
WHERE updated_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_supplement_recommendations_user_created_at
    ON supplement_recommendations (user_id, created_at);

CREATE INDEX IF NOT EXISTS idx_supplement_recommendations_user_node_created_at
    ON supplement_recommendations (user_id, node_id, created_at);

ALTER TABLE user_profiles
    ADD COLUMN IF NOT EXISTS is_public BOOLEAN NOT NULL DEFAULT TRUE;

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

INSERT INTO users (email, password, name, role_name, is_active, created_at, updated_at)
SELECT
    'learner@devpath.com',
    '$2a$10$RcdWJBwl.kuttYmqm/BN..6aZKeLNlq9DiNFHbZgZxfTzzNDD33o2',
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
    '$2a$10$RcdWJBwl.kuttYmqm/BN..6aZKeLNlq9DiNFHbZgZxfTzzNDD33o2',
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
    '$2a$10$RcdWJBwl.kuttYmqm/BN..6aZKeLNlq9DiNFHbZgZxfTzzNDD33o2',
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
SET password = '$2a$10$RcdWJBwl.kuttYmqm/BN..6aZKeLNlq9DiNFHbZgZxfTzzNDD33o2'
WHERE email IN ('learner@devpath.com', 'instructor@devpath.com', 'admin@devpath.com');

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
    '/images/profiles/instructor-hong.png',
    'Hong Backend Lab',
    'Spring Boot? ?ㅻТ 諛깆뿏???ㅺ퀎瑜?以묒떖?쇰줈 媛뺤쓽?섎뒗 媛뺤궗?낅땲??',
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
    '/images/profiles/admin-park.png',
    'DevPath Admin',
    '肄섑뀗痢?寃?섏? ?쒓렇 嫄곕쾭?뚯뒪瑜??대떦?⑸땲??',
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

INSERT INTO tags (name, category, is_official)
SELECT 'Java', 'Backend', TRUE
WHERE NOT EXISTS (
    SELECT 1
    FROM tags
    WHERE name = 'Java'
);

INSERT INTO tags (name, category, is_official)
SELECT 'Spring Boot', 'Backend', TRUE
WHERE NOT EXISTS (
    SELECT 1
    FROM tags
    WHERE name = 'Spring Boot'
);

INSERT INTO tags (name, category, is_official)
SELECT 'JPA', 'Backend', TRUE
WHERE NOT EXISTS (
    SELECT 1
    FROM tags
    WHERE name = 'JPA'
);

INSERT INTO tags (name, category, is_official)
SELECT 'Spring Security', 'Backend', TRUE
WHERE NOT EXISTS (
    SELECT 1
    FROM tags
    WHERE name = 'Spring Security'
);

INSERT INTO tags (name, category, is_official)
SELECT 'HTTP', 'Backend', TRUE
WHERE NOT EXISTS (
    SELECT 1
    FROM tags
    WHERE name = 'HTTP'
);

INSERT INTO tags (name, category, is_official)
SELECT 'PostgreSQL', 'Database', TRUE
WHERE NOT EXISTS (
    SELECT 1
    FROM tags
    WHERE name = 'PostgreSQL'
);

INSERT INTO tags (name, category, is_official)
SELECT 'Redis', 'Database', TRUE
WHERE NOT EXISTS (
    SELECT 1
    FROM tags
    WHERE name = 'Redis'
);

INSERT INTO tags (name, category, is_official)
SELECT 'Docker', 'DevOps', TRUE
WHERE NOT EXISTS (
    SELECT 1
    FROM tags
    WHERE name = 'Docker'
);

INSERT INTO tags (name, category, is_official)
SELECT 'React', 'Frontend', TRUE
WHERE NOT EXISTS (
    SELECT 1
    FROM tags
    WHERE name = 'React'
);

INSERT INTO tags (name, category, is_official)
SELECT 'TypeScript', 'Frontend', TRUE
WHERE NOT EXISTS (
    SELECT 1
    FROM tags
    WHERE name = 'TypeScript'
);

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
    '/images/courses/spring-boot.png',
    '/videos/trailers/spring-boot.mp4',
    'assets/courses/trailers/spring-boot.mp4',
    95,
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
    '/images/courses/jpa.png',
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

INSERT INTO tags (name, category, is_official)
SELECT 'JWT', 'Backend', TRUE
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
    'Offline security special event',
    'Join the offline Spring Security special lecture and Q&A session.',
    TRUE,
    0,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP,
    TIMESTAMP '2099-12-31 23:59:59',
    'March offline special lecture',
    'https://devpath.com/events/security-special',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
FROM courses c
WHERE c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1
      FROM course_announcements ca
      WHERE ca.course_id = c.course_id
        AND ca.title = 'Offline security special event'
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
    'Course material update',
    'The latest Spring Boot Intro materials and examples have been updated.',
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
        AND ca.title = 'Course material update'
  );

INSERT INTO qna_question_templates
    (template_type, name, description, guide_example, sort_order, is_active, created_at, updated_at)
SELECT 'DEBUGGING', '버그/에러 질문', '에러 로그와 재현 조건을 중심으로 질문하는 템플릿입니다.',
       '에러 로그, 재현 단계, 기대 결과, 실제 결과를 순서대로 적어주세요.', 1, TRUE, NOW(), NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM qna_question_templates
    WHERE template_type = 'DEBUGGING'
);

INSERT INTO qna_question_templates
    (template_type, name, description, guide_example, sort_order, is_active, created_at, updated_at)
SELECT 'IMPLEMENTATION', '구현 질문', '기능 구현 방식이나 설계 방향을 묻는 템플릿입니다.',
       '현재 구조, 목표 기능, 고민 중인 선택지를 함께 적어주세요.', 2, TRUE, NOW(), NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM qna_question_templates
    WHERE template_type = 'IMPLEMENTATION'
);

INSERT INTO qna_question_templates
    (template_type, name, description, guide_example, sort_order, is_active, created_at, updated_at)
SELECT 'CODE_REVIEW', '코드 리뷰 질문', '작성한 코드에 대한 개선점이나 리팩토링 의견을 받는 템플릿입니다.',
       '핵심 코드, 현재 우려사항, 성능/보안/가독성 관점을 함께 적어주세요.', 3, TRUE, NOW(), NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM qna_question_templates
    WHERE template_type = 'CODE_REVIEW'
);

INSERT INTO qna_question_templates
    (template_type, name, description, guide_example, sort_order, is_active, created_at, updated_at)
SELECT 'CAREER', '커리어 질문', '취업, 포트폴리오, 이직, 기술 선택 관련 질문 템플릿입니다.',
       '현재 상황, 목표 포지션, 보유 경험, 고민 포인트를 적어주세요.', 4, TRUE, NOW(), NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM qna_question_templates
    WHERE template_type = 'CAREER'
);

INSERT INTO qna_question_templates
    (template_type, name, description, guide_example, sort_order, is_active, created_at, updated_at)
SELECT 'STUDY', '학습 질문', '학습 순서나 개념 이해를 묻는 템플릿입니다.',
       '현재 이해한 내용과 막히는 지점을 함께 적어주세요.', 5, TRUE, NOW(), NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM qna_question_templates
    WHERE template_type = 'STUDY'
);

INSERT INTO qna_question_templates
    (template_type, name, description, guide_example, sort_order, is_active, created_at, updated_at)
SELECT 'PROJECT', '프로젝트 질문', '프로젝트 구조, 협업, 배포, 운영 관련 질문 템플릿입니다.',
       '프로젝트 배경, 현재 구조, 발생 중인 문제를 적어주세요.', 6, TRUE, NOW(), NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM qna_question_templates
    WHERE template_type = 'PROJECT'
);

-- ===========================
-- B 담당 샘플 데이터
-- ===========================

-- [1] review (5건)
INSERT INTO review (course_id, learner_id, rating, content, status, is_hidden, is_deleted, issue_tags_raw, created_at, updated_at)
SELECT c.course_id, u.user_id, 5, '강의 내용이 너무 좋아요! 핵심 개념을 쉽게 설명해줘서 많은 도움이 되었습니다.', 'ANSWERED', FALSE, FALSE, NULL, '2026-01-20 00:00:00', '2026-01-20 00:00:00'
FROM courses c, users u
WHERE c.title = 'Spring Boot Intro' AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM review r WHERE r.content = '강의 내용이 너무 좋아요! 핵심 개념을 쉽게 설명해줘서 많은 도움이 되었습니다.');

INSERT INTO review (course_id, learner_id, rating, content, status, is_hidden, is_deleted, issue_tags_raw, created_at, updated_at)
SELECT c.course_id, u.user_id, 4, 'JPA 실전 패턴이 정말 유용했습니다. 다만 QueryDSL 부분이 조금 더 상세했으면 좋겠어요.', 'UNANSWERED', FALSE, FALSE, NULL, '2026-01-22 00:00:00', '2026-01-22 00:00:00'
FROM courses c, users u
WHERE c.title = 'JPA Practical Design' AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM review r WHERE r.content = 'JPA 실전 패턴이 정말 유용했습니다. 다만 QueryDSL 부분이 조금 더 상세했으면 좋겠어요.');

INSERT INTO review (course_id, learner_id, rating, content, status, is_hidden, is_deleted, issue_tags_raw, created_at, updated_at)
SELECT c.course_id, u.user_id, 3, '설명은 이해하기 쉬우나 실습 예제가 좀 더 다양했으면 좋겠습니다.', 'ANSWERED', FALSE, FALSE, NULL, '2026-01-25 00:00:00', '2026-01-25 00:00:00'
FROM courses c, users u
WHERE c.title = 'Spring Boot Intro' AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM review r WHERE r.content = '설명은 이해하기 쉬우나 실습 예제가 좀 더 다양했으면 좋겠습니다.');

INSERT INTO review (course_id, learner_id, rating, content, status, is_hidden, is_deleted, issue_tags_raw, created_at, updated_at)
SELECT c.course_id, u.user_id, 5, 'N+1 문제 해결 방법을 실제 프로젝트에 바로 적용할 수 있었습니다. 강력 추천합니다!', 'UNANSWERED', FALSE, FALSE, NULL, '2026-01-28 00:00:00', '2026-01-28 00:00:00'
FROM courses c, users u
WHERE c.title = 'JPA Practical Design' AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM review r WHERE r.content = 'N+1 문제 해결 방법을 실제 프로젝트에 바로 적용할 수 있었습니다. 강력 추천합니다!');

INSERT INTO review (course_id, learner_id, rating, content, status, is_hidden, is_deleted, issue_tags_raw, created_at, updated_at)
SELECT c.course_id, u.user_id, 2, '강의 내용은 좋지만 설명 속도가 너무 빨라서 따라가기 어려웠습니다.', 'UNSATISFIED', FALSE, FALSE, NULL, '2026-02-01 00:00:00', '2026-02-01 00:00:00'
FROM courses c, users u
WHERE c.title = 'Spring Boot Intro' AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM review r WHERE r.content = '강의 내용은 좋지만 설명 속도가 너무 빨라서 따라가기 어려웠습니다.');

-- [2] review_reply (3건)
INSERT INTO review_reply (review_id, instructor_id, content, is_deleted, created_at, updated_at)
SELECT r.id, u.user_id, '소중한 리뷰 감사합니다! 앞으로도 더 좋은 강의로 보답하겠습니다. 궁금한 점은 언제든지 질문해 주세요.', FALSE, '2026-01-21 00:00:00', '2026-01-21 00:00:00'
FROM review r, users u
WHERE r.content = '강의 내용이 너무 좋아요! 핵심 개념을 쉽게 설명해줘서 많은 도움이 되었습니다.'
  AND u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM review_reply rr WHERE rr.review_id = r.id AND rr.instructor_id = u.user_id);

INSERT INTO review_reply (review_id, instructor_id, content, is_deleted, created_at, updated_at)
SELECT r.id, u.user_id, '피드백 감사합니다. 말씀하신 실습 예제 부분을 보완하여 곧 업데이트하겠습니다. 다음 업데이트를 기대해 주세요!', FALSE, '2026-01-26 00:00:00', '2026-01-26 00:00:00'
FROM review r, users u
WHERE r.content = '설명은 이해하기 쉬우나 실습 예제가 좀 더 다양했으면 좋겠습니다.'
  AND u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM review_reply rr WHERE rr.review_id = r.id AND rr.instructor_id = u.user_id);

INSERT INTO review_reply (review_id, instructor_id, content, is_deleted, created_at, updated_at)
SELECT r.id, u.user_id, '강의 속도에 대한 솔직한 피드백 감사드립니다. 설명 속도를 조절한 개정판을 준비 중입니다. 불편을 드려 죄송합니다.', FALSE, '2026-02-02 00:00:00', '2026-02-02 00:00:00'
FROM review r, users u
WHERE r.content = '강의 내용은 좋지만 설명 속도가 너무 빨라서 따라가기 어려웠습니다.'
  AND u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM review_reply rr WHERE rr.review_id = r.id AND rr.instructor_id = u.user_id);

-- [3] review_template (3건)
INSERT INTO review_template (instructor_id, title, content, is_deleted, created_at, updated_at)
SELECT u.user_id, '감사 인사', '수강해 주셔서 진심으로 감사드립니다. 좋은 리뷰는 강의를 더욱 발전시키는 큰 원동력이 됩니다. 앞으로도 최고의 강의로 보답하겠습니다!', FALSE, '2026-01-15 00:00:00', '2026-01-15 00:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM review_template rt WHERE rt.title = '감사 인사' AND rt.instructor_id = u.user_id);

INSERT INTO review_template (instructor_id, title, content, is_deleted, created_at, updated_at)
SELECT u.user_id, '개선 약속', '소중한 피드백 감사합니다. 말씀해 주신 부분을 꼼꼼히 검토하여 더 나은 강의로 업데이트하겠습니다. 지속적인 관심과 응원 부탁드립니다.', FALSE, '2026-01-15 00:00:00', '2026-01-15 00:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM review_template rt WHERE rt.title = '개선 약속' AND rt.instructor_id = u.user_id);

INSERT INTO review_template (instructor_id, title, content, is_deleted, created_at, updated_at)
SELECT u.user_id, '질문 유도', '강의를 수강해 주셔서 감사합니다. 학습 중 궁금한 점이 있으시면 Q&A 게시판을 통해 질문해 주세요. 최대한 빠르게 답변드리겠습니다!', FALSE, '2026-01-15 00:00:00', '2026-01-15 00:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM review_template rt WHERE rt.title = '질문 유도' AND rt.instructor_id = u.user_id);

-- [4] refund_request (3건)
INSERT INTO refund_request (learner_id, course_id, reason, status, is_deleted, requested_at, processed_at)
SELECT u.user_id, c.course_id, '강의 품질 불만족', 'PENDING', FALSE, '2026-02-05 00:00:00', NULL
FROM users u, courses c
WHERE u.email = 'learner@devpath.com' AND c.title = 'Spring Boot Intro'
  AND NOT EXISTS (SELECT 1 FROM refund_request rr WHERE rr.reason = '강의 품질 불만족' AND rr.learner_id = u.user_id AND rr.course_id = c.course_id);

INSERT INTO refund_request (learner_id, course_id, reason, status, is_deleted, requested_at, processed_at)
SELECT u.user_id, c.course_id, '중복 수강', 'APPROVED', FALSE, '2026-02-08 00:00:00', '2026-02-10 00:00:00'
FROM users u, courses c
WHERE u.email = 'learner@devpath.com' AND c.title = 'JPA Practical Design'
  AND NOT EXISTS (SELECT 1 FROM refund_request rr WHERE rr.reason = '중복 수강' AND rr.learner_id = u.user_id AND rr.course_id = c.course_id);

INSERT INTO refund_request (learner_id, course_id, reason, status, is_deleted, requested_at, processed_at)
SELECT u.user_id, c.course_id, '개인 사정', 'REJECTED', FALSE, '2026-02-12 00:00:00', '2026-02-13 00:00:00'
FROM users u, courses c
WHERE u.email = 'learner@devpath.com' AND c.title = 'Spring Boot Intro'
  AND NOT EXISTS (SELECT 1 FROM refund_request rr WHERE rr.reason = '개인 사정' AND rr.learner_id = u.user_id AND rr.course_id = c.course_id);

-- [5] settlement (3건)
INSERT INTO settlement (instructor_id, amount, status, is_deleted, settled_at, created_at)
SELECT u.user_id, 690000, 'COMPLETED', FALSE, '2026-01-31 00:00:00', '2026-01-31 00:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM settlement s WHERE s.instructor_id = u.user_id AND s.amount = 690000 AND s.created_at = '2026-01-31 00:00:00');

INSERT INTO settlement (instructor_id, amount, status, is_deleted, settled_at, created_at)
SELECT u.user_id, 385000, 'PENDING', FALSE, NULL, '2026-02-15 00:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM settlement s WHERE s.instructor_id = u.user_id AND s.amount = 385000 AND s.created_at = '2026-02-15 00:00:00');

INSERT INTO settlement (instructor_id, amount, status, is_deleted, settled_at, created_at)
SELECT u.user_id, 1980000, 'HELD', FALSE, NULL, '2026-02-28 00:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM settlement s WHERE s.instructor_id = u.user_id AND s.amount = 1980000 AND s.created_at = '2026-02-28 00:00:00');

-- [6] coupon (2건)
INSERT INTO coupon (instructor_id, coupon_code, discount_type, discount_value, target_course_id, max_usage_count, usage_count, expires_at, is_deleted, created_at)
SELECT u.user_id, 'HELLO2026', 'RATE', 30, NULL, 100, 45, '2026-02-28 23:59:59', FALSE, '2026-01-20 00:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM coupon c WHERE c.coupon_code = 'HELLO2026');

INSERT INTO coupon (instructor_id, coupon_code, discount_type, discount_value, target_course_id, max_usage_count, usage_count, expires_at, is_deleted, created_at)
SELECT u.user_id, 'JAVA_LAUNCH', 'FIXED', 15000, c.course_id, 200, 82, '2026-03-15 23:59:59', FALSE, '2026-01-20 00:00:00'
FROM users u, courses c
WHERE u.email = 'instructor@devpath.com' AND c.title = 'Spring Boot Intro'
  AND NOT EXISTS (SELECT 1 FROM coupon cp WHERE cp.coupon_code = 'JAVA_LAUNCH');

-- [7] promotion (2건)
INSERT INTO promotion (instructor_id, course_id, promotion_type, discount_rate, start_at, end_at, is_active, is_deleted, created_at)
SELECT u.user_id, c.course_id, 'TIMESALE', 20, '2026-02-01 00:00:00', '2026-02-07 23:59:59', TRUE, FALSE, '2026-01-30 00:00:00'
FROM users u, courses c
WHERE u.email = 'instructor@devpath.com' AND c.title = 'Spring Boot Intro'
  AND NOT EXISTS (SELECT 1 FROM promotion p WHERE p.course_id = c.course_id AND p.promotion_type = 'TIMESALE' AND p.start_at = '2026-02-01 00:00:00');

INSERT INTO promotion (instructor_id, course_id, promotion_type, discount_rate, start_at, end_at, is_active, is_deleted, created_at)
SELECT u.user_id, c.course_id, 'GENERAL', 15, '2026-02-15 00:00:00', '2026-03-15 23:59:59', TRUE, FALSE, '2026-02-10 00:00:00'
FROM users u, courses c
WHERE u.email = 'instructor@devpath.com' AND c.title = 'JPA Practical Design'
  AND NOT EXISTS (SELECT 1 FROM promotion p WHERE p.course_id = c.course_id AND p.promotion_type = 'GENERAL' AND p.start_at = '2026-02-15 00:00:00');

-- [8] notice (3건)
INSERT INTO notice (author_id, title, content, is_pinned, is_deleted, created_at, updated_at)
SELECT u.user_id, '서비스 점검 안내', '안녕하세요, DevPath입니다. 서비스 품질 향상을 위해 2026년 2월 15일 오전 2시부터 4시까지 서비스 점검이 진행됩니다. 점검 시간 동안에는 강의 수강 및 Q&A 이용이 일시적으로 제한될 수 있습니다. 이용에 불편을 드려 죄송합니다.', TRUE, FALSE, '2026-02-10 00:00:00', '2026-02-10 00:00:00'
FROM users u
WHERE u.email = 'admin@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM notice n WHERE n.title = '서비스 점검 안내');

INSERT INTO notice (author_id, title, content, is_pinned, is_deleted, created_at, updated_at)
SELECT u.user_id, '개인정보처리방침 개정 안내', '개인정보 보호법 개정에 따라 DevPath의 개인정보처리방침이 2026년 3월 1일부로 변경됩니다. 주요 변경 내용은 수집 항목 일부 조정 및 보유 기간 명확화입니다. 변경된 방침은 서비스 하단에서 확인하실 수 있습니다.', FALSE, FALSE, '2026-02-20 00:00:00', '2026-02-20 00:00:00'
FROM users u
WHERE u.email = 'admin@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM notice n WHERE n.title = '개인정보처리방침 개정 안내');

INSERT INTO notice (author_id, title, content, is_pinned, is_deleted, created_at, updated_at)
SELECT u.user_id, '신규 기능 출시 안내', 'DevPath에 새로운 기능이 추가되었습니다! 이번 업데이트에서는 강사 채널 구독 기능, 쿠폰 적용 기능, AI 기반 학습 경로 추천 기능이 출시되었습니다. 새로운 기능을 통해 더욱 효율적인 학습 경험을 즐겨보세요.', FALSE, FALSE, '2026-03-01 00:00:00', '2026-03-01 00:00:00'
FROM users u
WHERE u.email = 'admin@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM notice n WHERE n.title = '신규 기능 출시 안내');

-- [9] admin_role (3건)
INSERT INTO admin_role (role_name, description, is_deleted, created_at, updated_at)
SELECT 'SUPER_ADMIN', '모든 시스템 기능에 대한 최고 권한을 보유하며 사용자 권한 관리, 시스템 설정 변경, 데이터 접근 전반을 담당합니다.', FALSE, '2026-01-01 00:00:00', '2026-01-01 00:00:00'
WHERE NOT EXISTS (SELECT 1 FROM admin_role ar WHERE ar.role_name = 'SUPER_ADMIN');

INSERT INTO admin_role (role_name, description, is_deleted, created_at, updated_at)
SELECT 'CONTENT_MANAGER', '강의 콘텐츠 검수, 승인, 반려 및 태그 거버넌스를 담당합니다. 사용자 데이터 접근 권한은 없습니다.', FALSE, '2026-01-01 00:00:00', '2026-01-01 00:00:00'
WHERE NOT EXISTS (SELECT 1 FROM admin_role ar WHERE ar.role_name = 'CONTENT_MANAGER');

INSERT INTO admin_role (role_name, description, is_deleted, created_at, updated_at)
SELECT 'CS_MANAGER', '환불 요청 처리, 사용자 문의 응대 및 신고 콘텐츠 모니터링을 담당합니다.', FALSE, '2026-01-01 00:00:00', '2026-01-01 00:00:00'
WHERE NOT EXISTS (SELECT 1 FROM admin_role ar WHERE ar.role_name = 'CS_MANAGER');

-- [10] instructor_post (5건)
INSERT INTO instructor_post (instructor_id, title, content, post_type, like_count, comment_count, is_deleted, created_at, updated_at)
SELECT u.user_id, '[공지] 수강생 여러분께 드리는 안내', '안녕하세요, 강사입니다. 이번 달부터 매주 토요일 오후 2시에 라이브 Q&A 세션을 진행합니다. 수강생 여러분의 많은 참여 바랍니다!', 'NOTICE', 0, 0, FALSE, '2026-01-15 00:00:00', '2026-01-15 00:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM instructor_post ip WHERE ip.title = '[공지] 수강생 여러분께 드리는 안내');

INSERT INTO instructor_post (instructor_id, title, content, post_type, like_count, comment_count, is_deleted, created_at, updated_at)
SELECT u.user_id, 'Spring Boot와 JPA를 함께 사용할 때 주의할 점', 'Spring Boot 프로젝트에서 JPA를 사용할 때 가장 흔히 겪는 문제는 N+1 문제입니다. FetchType.LAZY를 기본으로 설정하고, 필요한 경우 fetch join을 활용하는 습관을 들이세요. 오늘도 즐거운 학습 되세요!', 'GENERAL', 0, 0, FALSE, '2026-01-20 00:00:00', '2026-01-20 00:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM instructor_post ip WHERE ip.title = 'Spring Boot와 JPA를 함께 사용할 때 주의할 점');

INSERT INTO instructor_post (instructor_id, title, content, post_type, like_count, comment_count, is_deleted, created_at, updated_at)
SELECT u.user_id, '백엔드 개발자가 꼭 알아야 할 HTTP 상태 코드 정리', '200 OK, 201 Created, 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found, 500 Internal Server Error... REST API 설계에서 자주 사용되는 HTTP 상태 코드를 정리해 보았습니다. 실무에서 적절한 상태 코드를 반환하는 것이 얼마나 중요한지 느껴보세요.', 'GENERAL', 0, 0, FALSE, '2026-01-25 00:00:00', '2026-01-25 00:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM instructor_post ip WHERE ip.title = '백엔드 개발자가 꼭 알아야 할 HTTP 상태 코드 정리');

INSERT INTO instructor_post (instructor_id, title, content, post_type, like_count, comment_count, is_deleted, created_at, updated_at)
SELECT u.user_id, 'Docker 컨테이너로 개발 환경 통일하기', '팀 프로젝트에서 "내 컴퓨터에서는 되는데..."라는 말, 이제는 하지 마세요. Docker Compose로 개발 환경을 코드로 관리하면 팀원 모두가 동일한 환경에서 개발할 수 있습니다. Spring Boot + PostgreSQL Docker Compose 설정 방법을 공유합니다.', 'GENERAL', 0, 0, FALSE, '2026-02-03 00:00:00', '2026-02-03 00:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM instructor_post ip WHERE ip.title = 'Docker 컨테이너로 개발 환경 통일하기');

INSERT INTO instructor_post (instructor_id, title, content, post_type, like_count, comment_count, is_deleted, created_at, updated_at)
SELECT u.user_id, 'JWT 인증 구현 시 보안을 위해 반드시 지켜야 할 사항', 'JWT를 구현할 때 Refresh Token은 반드시 HttpOnly Cookie에 저장하세요. Access Token은 만료 시간을 짧게(15분~1시간) 설정하고, 민감한 정보는 절대 Payload에 포함하지 마세요. 보안은 처음부터 올바르게 설계해야 합니다.', 'GENERAL', 0, 0, FALSE, '2026-02-10 00:00:00', '2026-02-10 00:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM instructor_post ip WHERE ip.title = 'JWT 인증 구현 시 보안을 위해 반드시 지켜야 할 사항');

-- [11] instructor_comment (5건)
INSERT INTO instructor_comment (post_id, author_id, parent_comment_id, content, like_count, is_deleted, created_at)
SELECT ip.id, u.user_id, NULL, '라이브 Q&A 세션 정말 기대됩니다! 꼭 참여하겠습니다.', 0, FALSE, '2026-01-16 00:00:00'
FROM instructor_post ip, users u
WHERE ip.title = '[공지] 수강생 여러분께 드리는 안내' AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM instructor_comment ic WHERE ic.post_id = ip.id AND ic.content = '라이브 Q&A 세션 정말 기대됩니다! 꼭 참여하겠습니다.');

INSERT INTO instructor_comment (post_id, author_id, parent_comment_id, content, like_count, is_deleted, created_at)
SELECT ip.id, u.user_id, NULL, '강사님 덕분에 N+1 문제를 드디어 이해했어요. fetch join 예시가 정말 도움이 됐습니다!', 0, FALSE, '2026-01-21 00:00:00'
FROM instructor_post ip, users u
WHERE ip.title = 'Spring Boot와 JPA를 함께 사용할 때 주의할 점' AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM instructor_comment ic WHERE ic.post_id = ip.id AND ic.content = '강사님 덕분에 N+1 문제를 드디어 이해했어요. fetch join 예시가 정말 도움이 됐습니다!');

INSERT INTO instructor_comment (post_id, author_id, parent_comment_id, content, like_count, is_deleted, created_at)
SELECT ip.id, u.user_id, NULL, 'HTTP 상태 코드 정리 감사합니다. 면접 준비할 때 자주 참고하겠습니다!', 0, FALSE, '2026-01-26 00:00:00'
FROM instructor_post ip, users u
WHERE ip.title = '백엔드 개발자가 꼭 알아야 할 HTTP 상태 코드 정리' AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM instructor_comment ic WHERE ic.post_id = ip.id AND ic.content = 'HTTP 상태 코드 정리 감사합니다. 면접 준비할 때 자주 참고하겠습니다!');

INSERT INTO instructor_comment (post_id, author_id, parent_comment_id, content, like_count, is_deleted, created_at)
SELECT ip.id, u.user_id, NULL, 'Docker Compose 예시 코드도 공유해 주시면 좋겠어요! 개인 프로젝트에 적용해보고 싶습니다.', 0, FALSE, '2026-02-04 00:00:00'
FROM instructor_post ip, users u
WHERE ip.title = 'Docker 컨테이너로 개발 환경 통일하기' AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM instructor_comment ic WHERE ic.post_id = ip.id AND ic.content = 'Docker Compose 예시 코드도 공유해 주시면 좋겠어요! 개인 프로젝트에 적용해보고 싶습니다.');

INSERT INTO instructor_comment (post_id, author_id, parent_comment_id, content, like_count, is_deleted, created_at)
SELECT ip.id, u.user_id, NULL, 'JWT Refresh Token을 HttpOnly Cookie에 저장하는 방법을 다음 강의에서 자세히 다뤄주시면 좋겠습니다!', 0, FALSE, '2026-02-11 00:00:00'
FROM instructor_post ip, users u
WHERE ip.title = 'JWT 인증 구현 시 보안을 위해 반드시 지켜야 할 사항' AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM instructor_comment ic WHERE ic.post_id = ip.id AND ic.content = 'JWT Refresh Token을 HttpOnly Cookie에 저장하는 방법을 다음 강의에서 자세히 다뤄주시면 좋겠습니다!');

-- qna_questions (qna_answer_draft 외래키 참조용)
INSERT INTO qna_questions (user_id, template_type, difficulty, title, content, adopted_answer_id, course_id, lecture_timestamp, qna_status, view_count, is_deleted, created_at, updated_at)
SELECT u.user_id, 'DEBUGGING', 'EASY', 'Spring Boot 실행 시 BeanCreationException이 발생합니다', '스프링 부트 애플리케이션을 실행하면 BeanCreationException: Error creating bean with name 오류가 발생합니다. 의존성 주입 설정은 맞게 한 것 같은데 어디서 문제가 생기는 걸까요?', NULL, c.course_id, NULL, 'UNANSWERED', 0, FALSE, '2026-02-05 00:00:00', '2026-02-05 00:00:00'
FROM users u, courses c
WHERE u.email = 'learner@devpath.com' AND c.title = 'Spring Boot Intro'
  AND NOT EXISTS (SELECT 1 FROM qna_questions q WHERE q.title = 'Spring Boot 실행 시 BeanCreationException이 발생합니다');

INSERT INTO qna_questions (user_id, template_type, difficulty, title, content, adopted_answer_id, course_id, lecture_timestamp, qna_status, view_count, is_deleted, created_at, updated_at)
SELECT u.user_id, 'IMPLEMENTATION', 'MEDIUM', 'JPA 연관관계 설정 시 무한 루프 문제', 'JPA에서 양방향 연관관계를 설정하면 toString()이나 JSON 직렬화 시 무한 루프가 발생합니다. @JsonIgnore나 @JsonManagedReference 중 어떤 방식을 쓰는 것이 더 좋을까요?', NULL, c.course_id, NULL, 'UNANSWERED', 0, FALSE, '2026-02-08 00:00:00', '2026-02-08 00:00:00'
FROM users u, courses c
WHERE u.email = 'learner@devpath.com' AND c.title = 'JPA Practical Design'
  AND NOT EXISTS (SELECT 1 FROM qna_questions q WHERE q.title = 'JPA 연관관계 설정 시 무한 루프 문제');

-- [12] qna_answer_draft (2건)
INSERT INTO qna_answer_draft (question_id, instructor_id, draft_content, is_deleted, saved_at, updated_at)
SELECT q.question_id, u.user_id, 'BeanCreationException은 주로 순환 의존성이나 빈 등록 실패로 발생합니다. @Component, @Service 어노테이션이 누락되지 않았는지 확인하시고, 생성자 주입을 사용하는 경우 순환 참조가 없는지 점검해보세요. 스택 트레이스에서 Caused by 부분을 자세히 보시면 정확한 원인을 찾으실 수 있습니다.', FALSE, '2026-02-06 00:00:00', '2026-02-06 00:00:00'
FROM qna_questions q, users u
WHERE q.title = 'Spring Boot 실행 시 BeanCreationException이 발생합니다' AND u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM qna_answer_draft d WHERE d.question_id = q.question_id AND d.instructor_id = u.user_id);

INSERT INTO qna_answer_draft (question_id, instructor_id, draft_content, is_deleted, saved_at, updated_at)
SELECT q.question_id, u.user_id, '양방향 연관관계에서의 무한 루프는 DTO 변환으로 가장 깔끔하게 해결할 수 있습니다. Entity를 직접 반환하지 말고 ResponseDTO로 변환하면 직렬화 시 무한 루프 자체가 발생하지 않습니다. 꼭 Entity를 직렬화해야 한다면 @JsonIgnore보다 @JsonManagedReference/@JsonBackReference 조합을 권장합니다.', FALSE, '2026-02-09 00:00:00', '2026-02-09 00:00:00'
FROM qna_questions q, users u
WHERE q.title = 'JPA 연관관계 설정 시 무한 루프 문제' AND u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM qna_answer_draft d WHERE d.question_id = q.question_id AND d.instructor_id = u.user_id);

-- [13] qna_template (3건)
INSERT INTO qna_template (instructor_id, title, content, is_deleted, created_at, updated_at)
SELECT u.user_id, '환경설정 공통 답변', '환경설정 관련 문제는 대부분 의존성 버전 충돌, 포트 충돌, 또는 application.properties 설정 오류에서 발생합니다. 먼저 pom.xml 또는 build.gradle의 의존성 버전을 확인하시고, 공식 문서에서 권장하는 버전 조합을 사용하고 있는지 체크해 보세요.', FALSE, '2026-01-10 00:00:00', '2026-01-10 00:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM qna_template qt WHERE qt.title = '환경설정 공통 답변' AND qt.instructor_id = u.user_id);

INSERT INTO qna_template (instructor_id, title, content, is_deleted, created_at, updated_at)
SELECT u.user_id, 'N+1 문제 공통 답변', 'N+1 문제는 JPA에서 매우 자주 발생하는 성능 이슈입니다. 해결 방법으로는 1) JPQL fetch join 사용, 2) @EntityGraph 활용, 3) Batch Size 설정이 있습니다. 연관 엔티티를 자주 함께 조회한다면 fetch join을 기본으로 사용하고, 단순 지연 로딩이 필요한 경우에는 BatchSize로 쿼리 수를 최적화하세요.', FALSE, '2026-01-10 00:00:00', '2026-01-10 00:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM qna_template qt WHERE qt.title = 'N+1 문제 공통 답변' AND qt.instructor_id = u.user_id);

INSERT INTO qna_template (instructor_id, title, content, is_deleted, created_at, updated_at)
SELECT u.user_id, '에러 해결 가이드', '에러를 해결할 때는 다음 순서로 접근해 보세요: 1) 에러 메시지의 핵심 키워드를 그대로 검색, 2) 스택 트레이스에서 내 코드가 포함된 첫 번째 줄 확인, 3) 최근 변경한 코드 롤백 후 재현 여부 확인, 4) 공식 문서 및 GitHub Issues 참고. 에러 메시지 전체를 공유해 주시면 더 빠르게 도움드릴 수 있습니다.', FALSE, '2026-01-10 00:00:00', '2026-01-10 00:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM qna_template qt WHERE qt.title = '에러 해결 가이드' AND qt.instructor_id = u.user_id);
-- 스터디 그룹
INSERT INTO study_group (name, description, status, max_members, is_deleted, created_at)
SELECT 'Spring Boot 마스터 스터디', '매주 주말 온라인으로 진행하는 백엔드 스터디입니다.', 'RECRUITING', 6, false, CURRENT_TIMESTAMP
    WHERE NOT EXISTS (SELECT 1 FROM study_group WHERE name = 'Spring Boot 마스터 스터디');

INSERT INTO study_group (name, description, status, max_members, is_deleted, created_at)
SELECT 'React 클론 코딩 스터디', 'React와 Tailwind를 활용한 프론트엔드 집중 스터디', 'IN_PROGRESS', 4, false, CURRENT_TIMESTAMP
    WHERE NOT EXISTS (SELECT 1 FROM study_group WHERE name = 'React 클론 코딩 스터디');

-- 스터디 그룹 멤버 (가정: COMMON BASE의 learner_id 1, 2 존재)
-- (study_group ID 1과 2가 존재한다고 가정)
INSERT INTO study_group_member (group_id, learner_id, join_status, joined_at)
SELECT 1, 1, 'APPROVED', CURRENT_TIMESTAMP
    WHERE NOT EXISTS (SELECT 1 FROM study_group_member WHERE group_id = 1 AND learner_id = 1);

INSERT INTO study_group_member (group_id, learner_id, join_status, joined_at)
SELECT 1, 2, 'PENDING', NULL
    WHERE NOT EXISTS (SELECT 1 FROM study_group_member WHERE group_id = 1 AND learner_id = 2);

INSERT INTO study_group_member (group_id, learner_id, join_status, joined_at)
SELECT 2, 1, 'APPROVED', CURRENT_TIMESTAMP
    WHERE NOT EXISTS (SELECT 1 FROM study_group_member WHERE group_id = 2 AND learner_id = 1);

-- 플래너 목표
INSERT INTO learner_goal (learner_id, goal_type, target_value, is_active)
SELECT 1, 'WEEKLY_NODE_CLEAR', 3, true
    WHERE NOT EXISTS (SELECT 1 FROM learner_goal WHERE learner_id = 1 AND goal_type = 'WEEKLY_NODE_CLEAR');

INSERT INTO learner_goal (learner_id, goal_type, target_value, is_active)
SELECT 2, 'WEEKLY_STUDY_TIME', 10, true
    WHERE NOT EXISTS (SELECT 1 FROM learner_goal WHERE learner_id = 2 AND goal_type = 'WEEKLY_STUDY_TIME');

-- 스트릭 (잔디) - Unique 제약조건 방어
INSERT INTO streak (learner_id, current_streak, longest_streak, last_study_date)
SELECT 1, 5, 14, CURRENT_DATE - INTERVAL '1 day'
WHERE NOT EXISTS (SELECT 1 FROM streak WHERE learner_id = 1);

INSERT INTO streak (learner_id, current_streak, longest_streak, last_study_date)
SELECT 2, 0, 7, CURRENT_DATE - INTERVAL '3 day'
WHERE NOT EXISTS (SELECT 1 FROM streak WHERE learner_id = 2);

-- 프로젝트
INSERT INTO project (name, description, status, is_deleted, created_at)
SELECT 'DevPath 클론 코딩', 'React와 Spring Boot를 활용한 플랫폼 개발', 'PREPARING', false, CURRENT_TIMESTAMP
    WHERE NOT EXISTS (SELECT 1 FROM project WHERE name = 'DevPath 클론 코딩');

INSERT INTO project (name, description, status, is_deleted, created_at)
SELECT 'AI 챗봇 서비스', 'OpenAI API를 활용한 맞춤형 멘토링 챗봇', 'IN_PROGRESS', false, CURRENT_TIMESTAMP
    WHERE NOT EXISTS (SELECT 1 FROM project WHERE name = 'AI 챗봇 서비스');

-- 프로젝트 아이디어 게시판
INSERT INTO project_idea_post (author_id, title, content, status, is_deleted, created_at)
SELECT 1, 'Spring Boot 기반 커머스 API 만들 분?', '백엔드 위주로 진행할 예정입니다.', 'PUBLISHED', false, CURRENT_TIMESTAMP
    WHERE NOT EXISTS (SELECT 1 FROM project_idea_post WHERE title = 'Spring Boot 기반 커머스 API 만들 분?');

-- ========================================
-- PostgreSQL Sequence 보정 처리 (매우 중요)
-- 명시적으로 ID를 넣거나 더미 데이터를 삽입한 후, 시퀀스를 동기화해 주어야 이후 POST 요청 시 ID 중복 에러가 나지 않습니다.
-- ========================================
SELECT setval('study_group_id_seq', (SELECT COALESCE(MAX(id), 1) FROM study_group));
SELECT setval('study_group_member_id_seq', (SELECT COALESCE(MAX(id), 1) FROM study_group_member));
SELECT setval('learner_goal_id_seq', (SELECT COALESCE(MAX(id), 1) FROM learner_goal));
SELECT setval('streak_id_seq', (SELECT COALESCE(MAX(id), 1) FROM streak));
SELECT setval('project_id_seq', (SELECT COALESCE(MAX(id), 1) FROM project));
SELECT setval('project_idea_post_id_seq', (SELECT COALESCE(MAX(id), 1) FROM project_idea_post));
-- ==========================================
-- [추가분] 누락된 C 파트 심화 도메인 더미 데이터 (실제 엔티티 구조 100% 반영)
-- ==========================================

-- 1. 스터디 매칭 (Study Match) - requester_id, receiver_id, node_id 사용
INSERT INTO study_match (requester_id, receiver_id, node_id, status, created_at)
SELECT 1, 2, 101, 'ACCEPTED', CURRENT_TIMESTAMP
    WHERE NOT EXISTS (SELECT 1 FROM study_match WHERE requester_id = 1 AND receiver_id = 2 AND node_id = 101);

-- 2. 플래너: 주간 플랜 (Weekly Plan) - plan_content 사용
INSERT INTO weekly_plan (learner_id, plan_content, status, created_at)
SELECT 1, '이번 주 목표: Spring Security 인증 필터 완벽 이해 및 적용', 'IN_PROGRESS', CURRENT_TIMESTAMP
    WHERE NOT EXISTS (SELECT 1 FROM weekly_plan WHERE learner_id = 1);

-- 3. 프로젝트: 모집 역할 (Project Role)
INSERT INTO project_role (project_id, role_type, required_count)
SELECT 1, 'BACKEND', 2
    WHERE NOT EXISTS (SELECT 1 FROM project_role WHERE project_id = 1 AND role_type = 'BACKEND');

INSERT INTO project_role (project_id, role_type, required_count)
SELECT 1, 'FRONTEND', 2
    WHERE NOT EXISTS (SELECT 1 FROM project_role WHERE project_id = 1 AND role_type = 'FRONTEND');

-- 4. 프로젝트: 참여 팀원 (Project Member)
INSERT INTO project_member (project_id, learner_id, role_type, joined_at)
SELECT 1, 1, 'LEADER', CURRENT_TIMESTAMP
    WHERE NOT EXISTS (SELECT 1 FROM project_member WHERE project_id = 1 AND learner_id = 1);

-- 5. 프로젝트: 초대 내역 (Project Invitation)
INSERT INTO project_invitation (project_id, inviter_id, invitee_id, status, created_at)
SELECT 1, 1, 3, 'PENDING', CURRENT_TIMESTAMP
    WHERE NOT EXISTS (SELECT 1 FROM project_invitation WHERE project_id = 1 AND invitee_id = 3);

-- 6. 멘토링: 지원 내역 (Mentoring Application)
INSERT INTO mentoring_application (project_id, mentor_id, message, status, created_at)
SELECT 1, 5, '백엔드 아키텍처 리뷰 부탁드립니다!', 'PENDING', CURRENT_TIMESTAMP
    WHERE NOT EXISTS (SELECT 1 FROM mentoring_application WHERE project_id = 1 AND mentor_id = 5);

-- 7. 학습 증명: 제출 내역 (Project Proof Submission)
INSERT INTO project_proof_submission (project_id, submitter_id, proof_card_ref_id, submitted_at)
SELECT 1, 1, 'PROOF-2026-ABC123X', CURRENT_TIMESTAMP
    WHERE NOT EXISTS (SELECT 1 FROM project_proof_submission WHERE project_id = 1 AND submitter_id = 1);

-- 8. 알림 (Learner Notification)
INSERT INTO learner_notification (learner_id, type, message, is_read, created_at)
SELECT 1, 'STUDY_GROUP', '새로운 스터디 팀원이 매칭되었습니다!', false, CURRENT_TIMESTAMP
    WHERE NOT EXISTS (SELECT 1 FROM learner_notification WHERE learner_id = 1 AND type = 'STUDY_GROUP');

-- 9. 대시보드 스냅샷 (Dashboard Snapshot) - completed_nodes 사용
INSERT INTO dashboard_snapshot (learner_id, snapshot_date, total_study_hours, completed_nodes)
SELECT 1, CURRENT_DATE, 45, 12
    WHERE NOT EXISTS (SELECT 1 FROM dashboard_snapshot WHERE learner_id = 1 AND snapshot_date = CURRENT_DATE);

-- ========================================
-- 10. A SEED
-- Learning Automation / Proof / History / Recommendation / Analytics
-- owner: A
-- ========================================

-- quiz / assignment parent seed
INSERT INTO quizzes (
    quiz_id,
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
) VALUES
(10901, 1, 'Java Basics 핵심 퀴즈', 'Java Basics 노드 학습 확인용 퀴즈입니다.', 'MANUAL', 10, TRUE, TRUE, TRUE, TRUE, FALSE, NOW() - INTERVAL '7 day', NOW() - INTERVAL '7 day'),
(10902, 2, 'HTTP Fundamentals 핵심 퀴즈', 'HTTP Fundamentals 노드 학습 확인용 퀴즈입니다.', 'MANUAL', 10, TRUE, TRUE, TRUE, TRUE, FALSE, NOW() - INTERVAL '7 day', NOW() - INTERVAL '7 day');

INSERT INTO assignments (
    assignment_id,
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
) VALUES
(11901, 1, 'Java Basics 실습 과제', '기본 문법과 객체지향 기초를 정리하는 과제입니다.', 'URL', NOW() - INTERVAL '4 day', NULL, TRUE, FALSE, FALSE, 'GitHub 저장소 URL을 제출합니다.', 100, TRUE, TRUE, TRUE, FALSE, NOW() - INTERVAL '7 day', NOW() - INTERVAL '7 day'),
(11902, 2, 'HTTP Fundamentals 정리 과제', 'HTTP 메서드와 상태 코드를 정리하는 과제입니다.', 'URL', NOW() - INTERVAL '1 day', NULL, TRUE, FALSE, FALSE, 'GitHub 저장소 URL을 제출합니다.', 100, TRUE, TRUE, TRUE, FALSE, NOW() - INTERVAL '7 day', NOW() - INTERVAL '7 day');

-- lesson_progress 완료/미완료
INSERT INTO lesson_progress (
    progress_id,
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
) VALUES
(10001, 1, 1, 100, 780, 1.0, FALSE, TRUE, NOW() - INTERVAL '5 day', NOW() - INTERVAL '7 day', NOW() - INTERVAL '5 day'),
(10002, 1, 2, 65, 598, 1.25, TRUE, FALSE, NOW() - INTERVAL '2 day', NOW() - INTERVAL '6 day', NOW() - INTERVAL '2 day'),
(10003, 2, 1, 100, 780, 1.0, FALSE, TRUE, NOW() - INTERVAL '3 day', NOW() - INTERVAL '8 day', NOW() - INTERVAL '3 day'),
(10004, 2, 3, 40, 440, 1.0, FALSE, FALSE, NOW() - INTERVAL '1 day', NOW() - INTERVAL '4 day', NOW() - INTERVAL '1 day');

-- quiz_attempts 통과/실패
INSERT INTO quiz_attempts (
    attempt_id,
    quiz_id,
    learner_id,
    score,
    max_score,
    started_at,
    completed_at,
    time_spent_seconds,
    is_passed,
    attempt_number,
    created_at,
    updated_at,
    is_deleted
) VALUES
(11001, 10901, 1, 9, 10, NOW() - INTERVAL '5 day' - INTERVAL '10 minute', NOW() - INTERVAL '5 day', 600, TRUE, 1, NOW() - INTERVAL '5 day', NOW() - INTERVAL '5 day', FALSE),
(11002, 10902, 1, 4, 10, NOW() - INTERVAL '2 day' - INTERVAL '8 minute', NOW() - INTERVAL '2 day', 480, FALSE, 1, NOW() - INTERVAL '2 day', NOW() - INTERVAL '2 day', FALSE),
(11003, 10901, 2, 8, 10, NOW() - INTERVAL '3 day' - INTERVAL '9 minute', NOW() - INTERVAL '3 day', 540, TRUE, 1, NOW() - INTERVAL '3 day', NOW() - INTERVAL '3 day', FALSE);

-- assignment_submissions 제출/미제출/통과
INSERT INTO assignment_submissions (
    submission_id,
    assignment_id,
    learner_id,
    submission_status,
    submission_url,
    is_late,
    submitted_at,
    graded_at,
    total_score,
    readme_passed,
    test_passed,
    lint_passed,
    file_format_passed,
    created_at,
    updated_at,
    is_deleted
) VALUES
(12001, 11901, 1, 'GRADED', 'https://github.com/example/devpath-assignment-1', FALSE, NOW() - INTERVAL '5 day', NOW() - INTERVAL '4 day', 95, TRUE, TRUE, TRUE, TRUE, NOW() - INTERVAL '5 day', NOW() - INTERVAL '4 day', FALSE),
(12002, 11902, 1, 'SUBMITTED', 'https://github.com/example/devpath-assignment-2', FALSE, NOW() - INTERVAL '2 day', NULL, NULL, NULL, NULL, NULL, NULL, NOW() - INTERVAL '2 day', NOW() - INTERVAL '2 day', FALSE),
(12003, 11901, 2, 'GRADED', 'https://github.com/example/devpath-assignment-3', FALSE, NOW() - INTERVAL '3 day', NOW() - INTERVAL '2 day', 82, TRUE, TRUE, FALSE, TRUE, NOW() - INTERVAL '3 day', NOW() - INTERVAL '2 day', FALSE);

-- til / timestamp_note
INSERT INTO timestamp_notes (
    note_id,
    user_id,
    lesson_id,
    timestamp_second,
    content,
    created_at,
    updated_at,
    is_deleted
) VALUES
(13001, 1, 1, 120, 'DI와 IoC 차이를 다시 정리했다.', NOW() - INTERVAL '6 day', NOW() - INTERVAL '6 day', FALSE),
(13002, 1, 2, 420, 'Bean lifecycle callback 흐름을 다시 봤다.', NOW() - INTERVAL '5 day', NOW() - INTERVAL '5 day', FALSE),
(13003, 2, 3, 300, '연관관계 매핑 전략 비교 포인트를 메모했다.', NOW() - INTERVAL '4 day', NOW() - INTERVAL '4 day', FALSE);

INSERT INTO til_drafts (
    til_id,
    user_id,
    lesson_id,
    title,
    content,
    status,
    published_url,
    created_at,
    updated_at,
    is_deleted
) VALUES
(14001, 1, 1, 'Spring IoC와 DI 정리', 'DI, IoC, BeanContainer 흐름을 정리했다.', 'PUBLISHED', 'https://velog.io/@devpath/ioc-di', NOW() - INTERVAL '5 day', NOW() - INTERVAL '5 day', FALSE),
(14002, 1, 2, 'Bean 생명주기 정리', 'Bean 생성과 소멸 콜백 시점을 정리했다.', 'DRAFT', NULL, NOW() - INTERVAL '2 day', NOW() - INTERVAL '2 day', FALSE),
(14003, 2, 3, 'JPA 연관관계 매핑 메모', '일대다와 다대일 매핑 차이를 정리했다.', 'PUBLISHED', 'https://velog.io/@devpath/jpa-mapping', NOW() - INTERVAL '3 day', NOW() - INTERVAL '3 day', FALSE);

-- supplement_recommendation
INSERT INTO supplement_recommendations (
    recommendation_id,
    user_id,
    node_id,
    reason,
    priority,
    coverage_percent,
    missing_tag_count,
    status,
    created_at,
    updated_at
) VALUES
(15001, 1, 2, 'HTTP 기초 보강이 필요해 추천이 생성되었습니다.', 90, 52.0, 2, 'PENDING', NOW() - INTERVAL '2 day', NOW() - INTERVAL '2 day'),
(15002, 1, 3, 'Spring Boot 기본기 보강 추천이 승인되었습니다.', 85, 71.0, 1, 'APPROVED', NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 day'),
(15003, 2, 2, 'HTTP 요청/응답 흐름 복습 추천이 생성되었습니다.', 80, 58.0, 2, 'PENDING', NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 day');

-- node_clearance / reason
INSERT INTO node_clearances (
    node_clearance_id,
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
) VALUES
(16001, 1, 1, 'CLEARED', 100.00, TRUE, 0, TRUE, TRUE, TRUE, TRUE, NOW() - INTERVAL '4 day', NOW() - INTERVAL '4 day', NOW() - INTERVAL '4 day', NOW() - INTERVAL '4 day'),
(16002, 1, 2, 'NOT_CLEARED', 65.00, FALSE, 1, FALSE, FALSE, FALSE, FALSE, NULL, NOW() - INTERVAL '2 day', NOW() - INTERVAL '2 day', NOW() - INTERVAL '2 day'),
(16003, 2, 1, 'CLEARED', 100.00, TRUE, 0, TRUE, TRUE, TRUE, TRUE, NOW() - INTERVAL '3 day', NOW() - INTERVAL '3 day', NOW() - INTERVAL '3 day', NOW() - INTERVAL '3 day');

INSERT INTO node_clearance_reasons (
    node_clearance_reason_id,
    node_clearance_id,
    reason_type,
    is_satisfied,
    detail_message,
    created_at
) VALUES
(16101, 16001, 'LESSON_COMPLETION', TRUE, '레슨 완강률: 100.00%', NOW() - INTERVAL '4 day'),
(16102, 16001, 'REQUIRED_TAGS', TRUE, '필수 태그를 모두 보유하고 있습니다.', NOW() - INTERVAL '4 day'),
(16103, 16001, 'QUIZ_PASS', TRUE, '퀴즈 조건을 만족했습니다.', NOW() - INTERVAL '4 day'),
(16104, 16001, 'ASSIGNMENT_PASS', TRUE, '과제 조건을 만족했습니다.', NOW() - INTERVAL '4 day'),
(16105, 16001, 'PROOF_ELIGIBLE', TRUE, 'Proof Card 발급 가능 상태입니다.', NOW() - INTERVAL '4 day'),
(16106, 16002, 'LESSON_COMPLETION', FALSE, '레슨 완강률: 65.00%', NOW() - INTERVAL '2 day'),
(16107, 16002, 'MISSING_TAGS', FALSE, 'HTTP', NOW() - INTERVAL '2 day'),
(16108, 16002, 'PROOF_ELIGIBLE', FALSE, 'Proof Card 발급 조건이 아직 충족되지 않았습니다.', NOW() - INTERVAL '2 day');

-- proof_card / certificate / share / download_history
INSERT INTO proof_cards (
    proof_card_id,
    user_id,
    node_id,
    node_clearance_id,
    title,
    description,
    proof_card_status,
    issued_at,
    created_at,
    updated_at
) VALUES
(17001, 1, 1, 16001, 'Java Basics Proof Card', 'Java Basics 노드의 학습 완료 및 검증 조건 충족 결과를 증명합니다.', 'ISSUED', NOW() - INTERVAL '4 day', NOW() - INTERVAL '4 day', NOW() - INTERVAL '4 day'),
(17002, 2, 1, 16003, 'Java Basics Proof Card', 'Java Basics 노드의 학습 완료 및 검증 조건 충족 결과를 증명합니다.', 'ISSUED', NOW() - INTERVAL '3 day', NOW() - INTERVAL '3 day', NOW() - INTERVAL '3 day');

INSERT INTO proof_card_tags (
    proof_card_tag_id,
    proof_card_id,
    tag_id,
    skill_evidence_type
) VALUES
(17101, 17001, 1, 'VERIFIED'),
(17102, 17001, 2, 'HELD'),
(17103, 17002, 1, 'VERIFIED');

INSERT INTO proof_card_shares (
    proof_card_share_id,
    proof_card_id,
    share_token,
    share_status,
    expires_at,
    access_count,
    created_at,
    updated_at
) VALUES
(17201, 17001, 'proof-share-token-17001', 'ACTIVE', NOW() + INTERVAL '30 day', 7, NOW() - INTERVAL '3 day', NOW() - INTERVAL '1 day'),
(17202, 17002, 'proof-share-token-17002', 'ACTIVE', NOW() + INTERVAL '15 day', 2, NOW() - INTERVAL '2 day', NOW() - INTERVAL '1 day');

INSERT INTO certificates (
    certificate_id,
    proof_card_id,
    certificate_number,
    certificate_status,
    issued_at,
    pdf_file_name,
    pdf_generated_at,
    last_downloaded_at,
    created_at,
    updated_at
) VALUES
(17301, 17001, 'CERT-20260329-A001', 'PDF_READY', NOW() - INTERVAL '3 day', 'certificate-CERT-20260329-A001.pdf', NOW() - INTERVAL '3 day', NOW() - INTERVAL '2 day', NOW() - INTERVAL '3 day', NOW() - INTERVAL '2 day'),
(17302, 17002, 'CERT-20260329-A002', 'ISSUED', NOW() - INTERVAL '2 day', NULL, NULL, NULL, NOW() - INTERVAL '2 day', NOW() - INTERVAL '2 day');

INSERT INTO certificate_download_histories (
    certificate_download_history_id,
    certificate_id,
    downloaded_by,
    download_reason,
    downloaded_at
) VALUES
(17401, 17301, 1, '포트폴리오 제출', NOW() - INTERVAL '2 day'),
(17402, 17301, 1, '이력 정리', NOW() - INTERVAL '1 day');

-- learning_history_share_link
INSERT INTO learning_history_share_links (
    learning_history_share_link_id,
    user_id,
    share_token,
    title,
    expires_at,
    access_count,
    is_active,
    created_at,
    updated_at
) VALUES
(17501, 1, 'history-share-token-17501', 'Learner Kim 학습 이력', NOW() + INTERVAL '30 day', 5, TRUE, NOW() - INTERVAL '2 day', NOW() - INTERVAL '1 day');

-- recommendation_change 샘플
INSERT INTO recommendation_changes (
    recommendation_change_id,
    user_id,
    node_id,
    source_recommendation_id,
    reason,
    context_summary,
    change_status,
    decision_status,
    suggested_at,
    applied_at,
    ignored_at,
    created_at,
    updated_at
) VALUES
(18001, 1, 2, 15001, '부족 태그와 최근 학습 기록을 반영한 추천입니다.', 'tilCount=2, weaknessSignal=true, warningCount=1, historyCount=1', 'SUGGESTED', 'UNDECIDED', NOW() - INTERVAL '1 day', NULL, NULL, NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 day'),
(18002, 1, 3, 15002, '퀴즈 실패 이력을 반영해 후속 노드 추천을 조정했습니다.', 'tilCount=2, weaknessSignal=true, warningCount=1, historyCount=2', 'APPLIED', 'APPLIED', NOW() - INTERVAL '12 hour', NOW() - INTERVAL '6 hour', NULL, NOW() - INTERVAL '12 hour', NOW() - INTERVAL '6 hour'),
(18003, 2, 2, 15003, '보강 추천 우선순위를 조정한 제안입니다.', 'tilCount=1, weaknessSignal=false, warningCount=0, historyCount=0', 'IGNORED', 'IGNORED', NOW() - INTERVAL '10 hour', NULL, NOW() - INTERVAL '4 hour', NOW() - INTERVAL '10 hour', NOW() - INTERVAL '4 hour');

-- learning_rule / metric_sample
INSERT INTO learning_automation_rules (
    learning_automation_rule_id,
    rule_key,
    rule_name,
    description,
    rule_value,
    priority,
    rule_status,
    created_at,
    updated_at
) VALUES
(19001, 'PROOF_CARD_AUTO_ISSUE', 'Proof Card 자동 발급', '노드 클리어 시 Proof Card를 자동 발급합니다.', 'true', 100, 'ENABLED', NOW() - INTERVAL '7 day', NOW() - INTERVAL '7 day'),
(19002, 'PROOF_CARD_MANUAL_ISSUE', 'Proof Card 수동 발급', '수동 발급 API 허용 여부입니다.', 'true', 90, 'ENABLED', NOW() - INTERVAL '7 day', NOW() - INTERVAL '7 day'),
(19003, 'RECOMMENDATION_CHANGE_ENABLED', '추천 변경 활성화', '추천 변경 제안 기능 활성화 여부입니다.', 'true', 80, 'ENABLED', NOW() - INTERVAL '7 day', NOW() - INTERVAL '7 day'),
(19004, 'RECOMMENDATION_CHANGE_MAX_LIMIT', '추천 변경 최대 개수', '추천 변경 제안 최대 개수입니다.', '5', 70, 'ENABLED', NOW() - INTERVAL '7 day', NOW() - INTERVAL '7 day'),
(19005, 'SUPPLEMENT_RECOMMENDATION_ENABLED', '보강 추천 활성화', '보강 추천 생성 기능 활성화 여부입니다.', 'true', 60, 'ENABLED', NOW() - INTERVAL '7 day', NOW() - INTERVAL '7 day');

INSERT INTO automation_monitor_snapshots (
    automation_monitor_snapshot_id,
    monitor_key,
    monitor_status,
    snapshot_value,
    snapshot_message,
    measured_at,
    created_at
) VALUES
(19101, 'PROOF_CARD_AUTO_ISSUE', 'HEALTHY', 1.0, '자동 발급 룰이 활성화되어 있습니다.', NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 day'),
(19102, 'PROOF_CARD_MANUAL_ISSUE', 'HEALTHY', 1.0, '수동 발급 룰이 활성화되어 있습니다.', NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 day'),
(19103, 'RECOMMENDATION_CHANGE_ENABLED', 'HEALTHY', 1.0, '추천 변경 룰이 활성화되어 있습니다.', NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 day'),
(19104, 'SUPPLEMENT_RECOMMENDATION_ENABLED', 'HEALTHY', 1.0, '보강 추천 룰이 활성화되어 있습니다.', NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 day');

INSERT INTO learning_metric_samples (
    learning_metric_sample_id,
    metric_type,
    metric_label,
    metric_value,
    sampled_at,
    created_at
) VALUES
(19201, 'OVERVIEW', 'clearanceRate', 87.50, NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 day'),
(19202, 'COMPLETION_RATE', 'roadmapCompletionRate', 42.80, NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 day'),
(19203, 'AVERAGE_WATCH_TIME', 'averageLearningDurationSeconds', 1380.00, NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 day'),
(19204, 'QUIZ_STATS', 'quizQualityScore', 79.40, NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 day');

-- 시퀀스 보정
SELECT setval(pg_get_serial_sequence('quizzes', 'quiz_id'), COALESCE((SELECT MAX(quiz_id) FROM quizzes), 1), true);
SELECT setval(pg_get_serial_sequence('assignments', 'assignment_id'), COALESCE((SELECT MAX(assignment_id) FROM assignments), 1), true);
SELECT setval(pg_get_serial_sequence('lesson_progress', 'progress_id'), COALESCE((SELECT MAX(progress_id) FROM lesson_progress), 1), true);
SELECT setval(pg_get_serial_sequence('quiz_attempts', 'attempt_id'), COALESCE((SELECT MAX(attempt_id) FROM quiz_attempts), 1), true);
SELECT setval(pg_get_serial_sequence('assignment_submissions', 'submission_id'), COALESCE((SELECT MAX(submission_id) FROM assignment_submissions), 1), true);
SELECT setval(pg_get_serial_sequence('timestamp_notes', 'note_id'), COALESCE((SELECT MAX(note_id) FROM timestamp_notes), 1), true);
SELECT setval(pg_get_serial_sequence('til_drafts', 'til_id'), COALESCE((SELECT MAX(til_id) FROM til_drafts), 1), true);
SELECT setval(pg_get_serial_sequence('supplement_recommendations', 'recommendation_id'), COALESCE((SELECT MAX(recommendation_id) FROM supplement_recommendations), 1), true);
SELECT setval(pg_get_serial_sequence('node_clearances', 'node_clearance_id'), COALESCE((SELECT MAX(node_clearance_id) FROM node_clearances), 1), true);
SELECT setval(pg_get_serial_sequence('node_clearance_reasons', 'node_clearance_reason_id'), COALESCE((SELECT MAX(node_clearance_reason_id) FROM node_clearance_reasons), 1), true);
SELECT setval(pg_get_serial_sequence('proof_cards', 'proof_card_id'), COALESCE((SELECT MAX(proof_card_id) FROM proof_cards), 1), true);
SELECT setval(pg_get_serial_sequence('proof_card_tags', 'proof_card_tag_id'), COALESCE((SELECT MAX(proof_card_tag_id) FROM proof_card_tags), 1), true);
SELECT setval(pg_get_serial_sequence('proof_card_shares', 'proof_card_share_id'), COALESCE((SELECT MAX(proof_card_share_id) FROM proof_card_shares), 1), true);
SELECT setval(pg_get_serial_sequence('certificates', 'certificate_id'), COALESCE((SELECT MAX(certificate_id) FROM certificates), 1), true);
SELECT setval(pg_get_serial_sequence('certificate_download_histories', 'certificate_download_history_id'), COALESCE((SELECT MAX(certificate_download_history_id) FROM certificate_download_histories), 1), true);
SELECT setval(pg_get_serial_sequence('learning_history_share_links', 'learning_history_share_link_id'), COALESCE((SELECT MAX(learning_history_share_link_id) FROM learning_history_share_links), 1), true);
SELECT setval(pg_get_serial_sequence('recommendation_changes', 'recommendation_change_id'), COALESCE((SELECT MAX(recommendation_change_id) FROM recommendation_changes), 1), true);
SELECT setval(pg_get_serial_sequence('learning_automation_rules', 'learning_automation_rule_id'), COALESCE((SELECT MAX(learning_automation_rule_id) FROM learning_automation_rules), 1), true);
SELECT setval(pg_get_serial_sequence('automation_monitor_snapshots', 'automation_monitor_snapshot_id'), COALESCE((SELECT MAX(automation_monitor_snapshot_id) FROM automation_monitor_snapshots), 1), true);
SELECT setval(pg_get_serial_sequence('learning_metric_samples', 'learning_metric_sample_id'), COALESCE((SELECT MAX(learning_metric_sample_id) FROM learning_metric_samples), 1), true);
