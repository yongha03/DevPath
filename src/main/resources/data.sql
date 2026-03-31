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
    'Spring Boot?? ????????썹땟戮녹???????????⑥쥓???汝뷴젆?????關???꾨き??熬곥룊??????????????ル늉??????汝뷴젆??녷뉩??읂?????ル늉??筌?類?域뱀옓堉??????戮?Ĳ??',
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
    '?????밸븶????????棺堉?뤃????? ????⑤슢堉?繹먮냱踰 ?饔낅챷維??????쑩??????????????꿔꺂??????',
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
SELECT 'DEBUGGING', 'Debugging question',
       'Use this template when you need help identifying the root cause of an error or failure.',
       'Explain the error message, when it happens, and what you already checked before asking.',
       1, TRUE, NOW(), NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM qna_question_templates
    WHERE template_type = 'DEBUGGING'
);

INSERT INTO qna_question_templates
    (template_type, name, description, guide_example, sort_order, is_active, created_at, updated_at)
SELECT 'IMPLEMENTATION', 'Implementation question',
       'Use this template when you are building a feature and need guidance on structure or approach.',
       'Describe the feature you are trying to build, the current design, and the exact part that blocks you.',
       2, TRUE, NOW(), NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM qna_question_templates
    WHERE template_type = 'IMPLEMENTATION'
);

INSERT INTO qna_question_templates
    (template_type, name, description, guide_example, sort_order, is_active, created_at, updated_at)
SELECT 'CODE_REVIEW', 'Code review question',
       'Use this template when you want feedback on code quality, readability, or tradeoffs.',
       'Share the relevant code, the expected behavior, and what kind of feedback you want most.',
       3, TRUE, NOW(), NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM qna_question_templates
    WHERE template_type = 'CODE_REVIEW'
);

INSERT INTO qna_question_templates
    (template_type, name, description, guide_example, sort_order, is_active, created_at, updated_at)
SELECT 'CAREER', 'Career question',
       'Use this template when you need advice on learning path, portfolio direction, or role preparation.',
       'Explain your current level, target role, and the decision you are trying to make next.',
       4, TRUE, NOW(), NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM qna_question_templates
    WHERE template_type = 'CAREER'
);

INSERT INTO qna_question_templates
    (template_type, name, description, guide_example, sort_order, is_active, created_at, updated_at)
SELECT 'STUDY', 'Study question',
       'Use this template when you want help planning what to study next or how to review effectively.',
       'Describe the topic, what you already understand, and what kind of study plan you want.',
       5, TRUE, NOW(), NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM qna_question_templates
    WHERE template_type = 'STUDY'
);

INSERT INTO qna_question_templates
    (template_type, name, description, guide_example, sort_order, is_active, created_at, updated_at)
SELECT 'PROJECT', 'Project question',
       'Use this template when you need help scoping, structuring, or improving a project idea or build.',
       'Explain the project goal, current progress, and the specific decision or risk you want reviewed.',
       6, TRUE, NOW(), NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM qna_question_templates
    WHERE template_type = 'PROJECT'
);

-- ===========================

-- ========================================
-- B SECTION START
-- ========================================

-- [B-01] review / review_reply / review_report / review_template
INSERT INTO review (
    course_id, learner_id, rating, content, status, is_hidden, is_deleted, issue_tags_raw, created_at, updated_at
)
SELECT c.course_id, u.user_id, 5,
       'Examples were practical and the explanation flow was very clear.',
       'ANSWERED', FALSE, FALSE, 'clear-examples,good-pacing',
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
       'The topic itself is useful, but I needed slower pacing around entity mapping and fetch strategy.',
       'UNANSWERED', FALSE, FALSE, 'too-fast,needs-more-diagrams',
       '2026-02-12 14:00:00', '2026-02-12 14:00:00'
FROM users u, courses c
WHERE u.email = 'learner@devpath.com'
  AND c.title = 'JPA Practical Design'
  AND NOT EXISTS (
      SELECT 1 FROM review r
      WHERE r.course_id = c.course_id AND r.learner_id = u.user_id
  );

INSERT INTO review_reply (
    review_id, instructor_id, content, is_deleted, created_at, updated_at
)
SELECT r.id, iu.user_id,
       'Thanks for the feedback. I will add more mapping diagrams and a slower walkthrough in the next update.',
       FALSE, '2026-02-10 12:00:00', '2026-02-10 12:00:00'
FROM review r, users iu, courses c
WHERE iu.email = 'instructor@devpath.com'
  AND c.title = 'Spring Boot Intro'
  AND r.course_id = c.course_id
  AND NOT EXISTS (
      SELECT 1 FROM review_reply rr WHERE rr.review_id = r.id AND rr.is_deleted = FALSE
  );

INSERT INTO review_report (
    review_id, reporter_id, reason, is_resolved, resolved_by, resolved_at, created_at, updated_at
)
SELECT r.id, au.user_id,
       'Contains vague wording and should be reviewed before public exposure.',
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
SELECT iu.user_id, 'Thanks and follow-up',
       'Thanks for leaving a detailed review. I will reflect your feedback in the next revision.',
       FALSE, '2026-02-01 00:00:00', '2026-02-01 00:00:00'
FROM users iu
WHERE iu.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM review_template rt
      WHERE rt.instructor_id = iu.user_id AND rt.title = 'Thanks and follow-up'
  );

INSERT INTO review_template (
    instructor_id, title, content, is_deleted, created_at, updated_at
)
SELECT iu.user_id, 'Issue acknowledged',
       'I reproduced the issue and added it to the revision queue. I will update the course notes as well.',
       FALSE, '2026-02-02 00:00:00', '2026-02-02 00:00:00'
FROM users iu
WHERE iu.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM review_template rt
      WHERE rt.instructor_id = iu.user_id AND rt.title = 'Issue acknowledged'
  );

-- [B-02] qna_questions / qna_answers / qna_answer_draft / qna_template
INSERT INTO qna_questions (
    user_id, template_type, difficulty, title, content, adopted_answer_id,
    course_id, lecture_timestamp, qna_status, view_count, is_deleted, created_at, updated_at
)
SELECT u.user_id, 'DEBUGGING', 'EASY',
       'BeanCreationException during startup',
       'Spring Boot startup fails with BeanCreationException. Which bean should I inspect first and how do I narrow the cause?',
       NULL, c.course_id, NULL, 'ANSWERED', 3, FALSE, '2026-02-05 00:00:00', '2026-02-06 00:00:00'
FROM users u, courses c
WHERE u.email = 'learner@devpath.com'
  AND c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1 FROM qna_questions q WHERE q.title = 'BeanCreationException during startup'
  );

INSERT INTO qna_questions (
    user_id, template_type, difficulty, title, content, adopted_answer_id,
    course_id, lecture_timestamp, qna_status, view_count, is_deleted, created_at, updated_at
)
SELECT u.user_id, 'IMPLEMENTATION', 'MEDIUM',
       'How to avoid JPA infinite recursion',
       'My entity graph loops when I serialize it to JSON. What is the safest way to stop recursive references?',
       NULL, c.course_id, '00:12:44', 'UNANSWERED', 5, FALSE, '2026-02-08 00:00:00', '2026-02-09 00:00:00'
FROM users u, courses c
WHERE u.email = 'learner@devpath.com'
  AND c.title = 'JPA Practical Design'
  AND NOT EXISTS (
      SELECT 1 FROM qna_questions q WHERE q.title = 'How to avoid JPA infinite recursion'
  );

INSERT INTO qna_answers (
    question_id, user_id, content, is_adopted, is_deleted, created_at, updated_at
)
SELECT q.question_id, iu.user_id,
       'Start from the root cause in the stack trace, then check configuration classes, component scanning, and constructor dependencies.',
       FALSE, FALSE, '2026-02-06 09:00:00', '2026-02-06 09:00:00'
FROM qna_questions q, users iu
WHERE q.title = 'BeanCreationException during startup'
  AND iu.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM qna_answers a WHERE a.question_id = q.question_id AND a.is_deleted = FALSE
  );

INSERT INTO qna_answer_draft (
    question_id, instructor_id, draft_content, is_deleted, saved_at, updated_at
)
SELECT q.question_id, iu.user_id,
       'Prefer response DTOs for API output, and use reference annotations only when you must serialize the entity graph directly.',
       FALSE, '2026-02-09 00:00:00', '2026-02-09 00:00:00'
FROM qna_questions q, users iu
WHERE q.title = 'How to avoid JPA infinite recursion'
  AND iu.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM qna_answer_draft d
      WHERE d.question_id = q.question_id AND d.instructor_id = iu.user_id AND d.is_deleted = FALSE
  );

INSERT INTO qna_template (
    instructor_id, title, content, is_deleted, created_at, updated_at
)
SELECT iu.user_id, 'Debugging startup errors',
       'Check stack trace order, configuration classes, environment variables, and recent dependency changes first.',
       FALSE, '2026-01-10 00:00:00', '2026-01-10 00:00:00'
FROM users iu
WHERE iu.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM qna_template qt
      WHERE qt.instructor_id = iu.user_id AND qt.title = 'Debugging startup errors'
  );

INSERT INTO qna_template (
    instructor_id, title, content, is_deleted, created_at, updated_at
)
SELECT iu.user_id, 'N+1 review checklist',
       'Compare repository query count, fetch strategy, and entity graph usage before changing domain structure.',
       FALSE, '2026-01-10 00:00:00', '2026-01-10 00:00:00'
FROM users iu
WHERE iu.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM qna_template qt
      WHERE qt.instructor_id = iu.user_id AND qt.title = 'N+1 review checklist'
  );

-- [B-03] instructor_post / instructor_comment / likes
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

-- [B-04] coupon / promotion / conversion_stat
INSERT INTO coupon (
    instructor_id, coupon_code, discount_type, discount_value, target_course_id,
    max_usage_count, usage_count, expires_at, is_deleted, created_at
)
SELECT iu.user_id, 'BSPRING10', 'RATE', 10, c.course_id,
       100, 0, '2026-12-31 23:59:59', FALSE, '2026-02-15 00:00:00'
FROM users iu, courses c
WHERE iu.email = 'instructor@devpath.com'
  AND c.title = 'Spring Boot Intro'
  AND NOT EXISTS (
      SELECT 1 FROM coupon cp WHERE cp.coupon_code = 'BSPRING10'
  );

INSERT INTO promotion (
    instructor_id, course_id, promotion_type, discount_rate, start_at, end_at,
    is_active, is_deleted, created_at
)
SELECT iu.user_id, c.course_id, 'TIME_SALE', 15,
       '2026-02-20 00:00:00', '2026-02-28 23:59:59',
       TRUE, FALSE, '2026-02-20 00:00:00'
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

-- [B-05] refund_request / refund_review / settlement / settlement_hold
INSERT INTO settlement (
    instructor_id, amount, status, is_deleted, settled_at, created_at
)
SELECT iu.user_id, 250000, 'PENDING', FALSE, NULL, '2026-02-25 00:00:00'
FROM users iu
WHERE iu.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM settlement s
      WHERE s.instructor_id = iu.user_id AND s.amount = 250000 AND s.status = 'PENDING'
  );

INSERT INTO settlement (
    instructor_id, amount, status, is_deleted, settled_at, created_at
)
SELECT iu.user_id, 50000, 'HELD', FALSE, NULL, '2026-02-24 00:00:00'
FROM users iu
WHERE iu.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1 FROM settlement s
      WHERE s.instructor_id = iu.user_id AND s.amount = 50000 AND s.status = 'HELD'
  );

INSERT INTO settlement_hold (
    settlement_id, admin_id, reason, held_at
)
SELECT s.id, au.user_id, 'Refund dispute review in progress', '2026-02-24 10:00:00'
FROM settlement s, users au
WHERE s.status = 'HELD'
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

-- [B-06] restricted / deactivated / withdrawn accounts
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

-- [B-07] notice / admin_role / admin_permission / account_log
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

-- [B-08] instructor_notification / dm_room / dm_message
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
