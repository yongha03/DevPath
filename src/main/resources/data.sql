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
    'Spring Boot?? ?????熬곣뫖利?????????고뀘??β뼯猷??嚥싳쉶瑗??꾧틡?????Β????醫딆┫?????β뼯爰귨㎘???醫딆┫?뺢껴?귟떋?????뉖뤁??',
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
    '??ш끽維???????嚥▲굧????? ???곌떽?깆쓦 ?꿸쑨????臾먮?????????????嶺뚮ㅎ????',
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
SELECT 'DEBUGGING', '?類?????????癲ル슣??袁ｋ즵', '??????棺??짆??? ?????釉뚰???쨨??濚욌꼬?댄꺍????⑥??癲ル슣??袁ｋ즵??嚥▲꺂痢??????뭇?繹먮냱??????덊렡.',
       '??????棺??짆?? ??????影?됀? ??れ삀?? ?濡ろ뜏??? ???源놁졆 ?濡ろ뜏???醫듽걫???筌?留???????ㅼ굡?醫덉뜏??????', 1, TRUE, NOW(), NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM qna_question_templates
    WHERE template_type = 'DEBUGGING'
);

INSERT INTO qna_question_templates
    (template_type, name, description, guide_example, sort_order, is_active, created_at, updated_at)
SELECT 'IMPLEMENTATION', '????열野?癲ル슣??袁ｋ즵', '??れ삀???????열野??袁⑸젻泳?????????됰텑???袁⑸젻泳?떑?????醫됲뀷???????뭇?繹먮냱??????덊렡.',
       '??ш끽維??????깼?? 癲ル슢?꾤땟?룹춻???れ삀??? ??關履? 濚욌꼬?댄꺍?????ャ뀕?얜ŉ異?堉온????影?얠맽 ???ㅼ굡?醫덉뜏??????', 2, TRUE, NOW(), NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM qna_question_templates
    WHERE template_type = 'IMPLEMENTATION'
);

INSERT INTO qna_question_templates
    (template_type, name, description, guide_example, sort_order, is_active, created_at, updated_at)
SELECT 'CODE_REVIEW', '?熬곣뫀????域밸Ŧ留??癲ル슣??袁ｋ즵', '????????熬곣뫀??????????좊즵獒뺣돀????????域밸Ŧ肉????ル늉??????듬쐥???袁⑸즵????????뭇?繹먮냱??????덊렡.',
       '??????熬곣뫀??? ??ш끽維?????ㅻ깹????? ?濚밸Ŧ援앲짆??怨뚮옖???눀???좊읈?????좊렰 ???굿???獄???影?얠맽 ???ㅼ굡?醫덉뜏??????', 3, TRUE, NOW(), NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM qna_question_templates
    WHERE template_type = 'CODE_REVIEW'
);

INSERT INTO qna_question_templates
    (template_type, name, description, guide_example, sort_order, is_active, created_at, updated_at)
SELECT 'CAREER', '??節뗪콪???癲ル슣??袁ｋ즵', '???爾쏉쫯? ????????? ???⑤챷?? ??れ삀??????ャ뀕?????굿??癲ル슣??袁ｋ즵 ?????뭇?繹먮냱??????덊렡.',
       '??ш끽維???????? 癲ル슢?꾤땟?룹춻?????? ?怨뚮옖??? ?濡ろ뜑??? ??關履? ????嶺? ???ㅼ굡?醫덉뜏??????', 4, TRUE, NOW(), NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM qna_question_templates
    WHERE template_type = 'CAREER'
);

INSERT INTO qna_question_templates
    (template_type, name, description, guide_example, sort_order, is_active, created_at, updated_at)
SELECT 'STUDY', '????? 癲ル슣??袁ｋ즵', '????? ??筌?留????좊즵獒????熬곣뫂?????醫됲뀷???????뭇?繹먮냱??????덊렡.',
       '??ш끽維????熬곣뫂??????⑤챶裕??癲ル슢??쭕???癲ル슣?????獄???影?얠맽 ???ㅼ굡?醫덉뜏??????', 5, TRUE, NOW(), NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM qna_question_templates
    WHERE template_type = 'STUDY'
);

INSERT INTO qna_question_templates
    (template_type, name, description, guide_example, sort_order, is_active, created_at, updated_at)
SELECT 'PROJECT', '??ш끽維곩ㅇ???됰씭肄?癲ル슣??袁ｋ즵', '??ш끽維곩ㅇ???됰씭肄?????깼?? ?????? ?袁⑸즲???? ???⑤㈇猿 ???굿??癲ル슣??袁ｋ즵 ?????뭇?繹먮냱??????덊렡.',
       '??ш끽維곩ㅇ???됰씭肄??袁⑸즲??㏓き? ??ш끽維??????깼?? ?袁⑸즵獒뺣뎾??濚욌꼬?댄꺍?????뽮덫?影?뽧걫????ㅼ굡?醫덉뜏??????', 6, TRUE, NOW(), NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM qna_question_templates
    WHERE template_type = 'PROJECT'
);

-- ===========================

-- A SEED START
-- ???덈? ???吏??+ Proof Card + ???덈? ?????+ ?怨뺣뾼???곌떠???+ ???덈? ?釉뚯뫒??
-- =====================================================

-- A scenario base
INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order)
SELECT r.roadmap_id, 'A Swagger Clear Node', 'A ?熬곣뫗??Swagger ?롪틵?嶺뚯빘鍮?????????筌뤾퍓援???낅퉵??', 'CONCEPT', 101
FROM roadmaps r
WHERE r.title = 'Backend Master Roadmap'
  AND NOT EXISTS (
      SELECT 1
      FROM roadmap_nodes n
      WHERE n.roadmap_id = r.roadmap_id
        AND n.title = 'A Swagger Clear Node'
  );

INSERT INTO roadmap_nodes (roadmap_id, title, content, node_type, sort_order)
SELECT r.roadmap_id, 'A Swagger Gap Node', 'A ?熬곣뫗??Swagger ?롪틵?嶺뚯빘鍮??亦껋꼶梨멨칰짰逾????筌뤾퍓援???낅퉵??', 'PRACTICE', 102
FROM roadmaps r
WHERE r.title = 'Backend Master Roadmap'
  AND NOT EXISTS (
      SELECT 1
      FROM roadmap_nodes n
      WHERE n.roadmap_id = r.roadmap_id
        AND n.title = 'A Swagger Gap Node'
  );

INSERT INTO node_completion_rules (node_id, criteria_type, criteria_value, created_at, updated_at)
SELECT n.node_id, 'LESSON_QUIZ_ASSIGNMENT', 'lesson,quiz,assignment', NOW() - INTERVAL '8' DAY, NOW() - INTERVAL '8' DAY
FROM roadmap_nodes n
WHERE n.title = 'A Swagger Clear Node'
  AND NOT EXISTS (
      SELECT 1
      FROM node_completion_rules r
      WHERE r.node_id = n.node_id
  );

INSERT INTO node_completion_rules (node_id, criteria_type, criteria_value, created_at, updated_at)
SELECT n.node_id, 'LESSON_QUIZ_ASSIGNMENT', 'lesson,quiz,assignment', NOW() - INTERVAL '8' DAY, NOW() - INTERVAL '8' DAY
FROM roadmap_nodes n
WHERE n.title = 'A Swagger Gap Node'
  AND NOT EXISTS (
      SELECT 1
      FROM node_completion_rules r
      WHERE r.node_id = n.node_id
  );

INSERT INTO node_required_tags (node_id, tag_id)
SELECT n.node_id, t.tag_id
FROM roadmap_nodes n, tags t
WHERE n.title = 'A Swagger Clear Node'
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
WHERE n.title = 'A Swagger Gap Node'
  AND t.name = 'Spring Security'
  AND NOT EXISTS (
      SELECT 1
      FROM node_required_tags req
      WHERE req.node_id = n.node_id
        AND req.tag_id = t.tag_id
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
    'A Java Proof Course',
    'A Swagger proof validation course',
    'Course for validating the cleared node to proof-card flow.',
    '/images/courses/a-java-proof.png',
    'https://cdn.devpath.com/courses/a-java-proof.mp4',
    'asset-a-java-proof',
    1800,
    0.00,
    0.00,
    'KRW',
    'BEGINNER',
    'ko',
    TRUE,
    'PUBLISHED',
    NOW() - INTERVAL '10' DAY
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM courses c
      WHERE c.title = 'A Java Proof Course'
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
    'A Gap Recovery Course',
    'A Swagger recovery validation course',
    'Course for validating the uncleared node recovery flow.',
    '/images/courses/a-gap-recovery.png',
    'https://cdn.devpath.com/courses/a-gap-recovery.mp4',
    'asset-a-gap-recovery',
    2100,
    0.00,
    0.00,
    'KRW',
    'BEGINNER',
    'ko',
    TRUE,
    'PUBLISHED',
    NOW() - INTERVAL '9' DAY
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM courses c
      WHERE c.title = 'A Gap Recovery Course'
  );

INSERT INTO course_sections (course_id, title, description, sort_order, is_published)
SELECT c.course_id, 'A Clear Section', 'Section for the cleared-node Swagger validation flow.', 1, TRUE
FROM courses c
WHERE c.title = 'A Java Proof Course'
  AND NOT EXISTS (
      SELECT 1
      FROM course_sections cs
      WHERE cs.course_id = c.course_id
        AND cs.sort_order = 1
  );

INSERT INTO course_sections (course_id, title, description, sort_order, is_published)
SELECT c.course_id, 'A Gap Section', 'Section for the uncleared-node Swagger validation flow.', 1, TRUE
FROM courses c
WHERE c.title = 'A Gap Recovery Course'
  AND NOT EXISTS (
      SELECT 1
      FROM course_sections cs
      WHERE cs.course_id = c.course_id
        AND cs.sort_order = 1
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
    'A Clear Lesson',
    '???????筌뤾퍓援???熬곣뫁?????곕?',
    'VIDEO',
    'https://cdn.devpath.com/lessons/a-clear-lesson.mp4',
    'asset-a-clear-lesson',
    'MUX',
    '/images/lessons/a-clear-lesson.png',
    900,
    FALSE,
    TRUE,
    1
FROM course_sections cs
JOIN courses c ON c.course_id = cs.course_id
WHERE c.title = 'A Java Proof Course'
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
    'A Gap Lesson',
    '亦껋꼶梨멨칰짰逾????筌뤾퍓援??亦껋꼶梨??쒕쇀????곕?',
    'VIDEO',
    'https://cdn.devpath.com/lessons/a-gap-lesson.mp4',
    'asset-a-gap-lesson',
    'MUX',
    '/images/lessons/a-gap-lesson.png',
    900,
    FALSE,
    TRUE,
    1
FROM course_sections cs
JOIN courses c ON c.course_id = cs.course_id
WHERE c.title = 'A Gap Recovery Course'
  AND cs.sort_order = 1
  AND NOT EXISTS (
      SELECT 1
      FROM lessons l
      WHERE l.section_id = cs.section_id
        AND l.sort_order = 1
  );

INSERT INTO course_node_mappings (course_id, node_id, created_at)
SELECT c.course_id, n.node_id, NOW() - INTERVAL '8' DAY
FROM courses c, roadmap_nodes n
WHERE c.title = 'A Java Proof Course'
  AND n.title = 'A Swagger Clear Node'
  AND NOT EXISTS (
      SELECT 1
      FROM course_node_mappings m
      WHERE m.course_id = c.course_id
        AND m.node_id = n.node_id
  );

INSERT INTO course_node_mappings (course_id, node_id, created_at)
SELECT c.course_id, n.node_id, NOW() - INTERVAL '8' DAY
FROM courses c, roadmap_nodes n
WHERE c.title = 'A Gap Recovery Course'
  AND n.title = 'A Swagger Gap Node'
  AND NOT EXISTS (
      SELECT 1
      FROM course_node_mappings m
      WHERE m.course_id = c.course_id
        AND m.node_id = n.node_id
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
SELECT u.user_id, c.course_id, 'COMPLETED', NOW() - INTERVAL '7' DAY, NOW() - INTERVAL '2' DAY, 100, NOW() - INTERVAL '1' DAY
FROM users u, courses c
WHERE u.email = 'learner@devpath.com'
  AND c.title = 'A Java Proof Course'
  AND NOT EXISTS (
      SELECT 1
      FROM course_enrollments e
      WHERE e.user_id = u.user_id
        AND e.course_id = c.course_id
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
SELECT u.user_id, c.course_id, 'ACTIVE', NOW() - INTERVAL '7' DAY, NULL, 40, NOW() - INTERVAL '5' HOUR
FROM users u, courses c
WHERE u.email = 'learner@devpath.com'
  AND c.title = 'A Gap Recovery Course'
  AND NOT EXISTS (
      SELECT 1
      FROM course_enrollments e
      WHERE e.user_id = u.user_id
        AND e.course_id = c.course_id
  );

-- 1. lesson_progress
-- ?熬곣뫁??亦껋꼶梨??쒕쇀???댟??怨룸츩
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
SELECT u.user_id, l.lesson_id, 100, 900, 1.0, FALSE, TRUE, NOW() - INTERVAL '2' DAY, NOW() - INTERVAL '7' DAY, NOW() - INTERVAL '2' DAY
FROM users u, lessons l
WHERE u.email = 'learner@devpath.com'
  AND l.title = 'A Clear Lesson'
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
SELECT u.user_id, l.lesson_id, 40, 360, 1.25, FALSE, FALSE, NOW() - INTERVAL '5' HOUR, NOW() - INTERVAL '6' DAY, NOW() - INTERVAL '5' HOUR
FROM users u, lessons l
WHERE u.email = 'learner@devpath.com'
  AND l.title = 'A Gap Lesson'
  AND NOT EXISTS (
      SELECT 1
      FROM lesson_progress lp
      WHERE lp.user_id = u.user_id
        AND lp.lesson_id = l.lesson_id
  );

-- 2. quiz_attempt ???裕?quiz_submission
-- ???沅????덉넮 ??댟??怨룸츩
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
SELECT n.node_id, 'A Clear Node Quiz', 'A Clear Node ???沅??롪틵?嶺뚯빘鍮????怨멥궛???낅퉵??', 'MANUAL', 10, TRUE, TRUE, TRUE, TRUE, FALSE, NOW() - INTERVAL '7' DAY, NOW() - INTERVAL '7' DAY
FROM roadmap_nodes n
WHERE n.title = 'A Swagger Clear Node'
  AND NOT EXISTS (
      SELECT 1
      FROM quizzes q
      WHERE q.node_id = n.node_id
        AND q.title = 'A Clear Node Quiz'
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
SELECT n.node_id, 'A Gap Node Quiz', 'A Gap Node ???덉넮 ?롪틵?嶺뚯빘鍮????怨멥궛???낅퉵??', 'MANUAL', 10, TRUE, TRUE, TRUE, TRUE, FALSE, NOW() - INTERVAL '7' DAY, NOW() - INTERVAL '7' DAY
FROM roadmap_nodes n
WHERE n.title = 'A Swagger Gap Node'
  AND NOT EXISTS (
      SELECT 1
      FROM quizzes q
      WHERE q.node_id = n.node_id
        AND q.title = 'A Gap Node Quiz'
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
    created_at,
    updated_at,
    is_deleted
)
SELECT q.quiz_id, u.user_id, 9, 10, NOW() - INTERVAL '2' DAY - INTERVAL '10' MINUTE, NOW() - INTERVAL '2' DAY, 600, TRUE, 1, NOW() - INTERVAL '2' DAY, NOW() - INTERVAL '2' DAY, FALSE
FROM quizzes q, users u
WHERE q.title = 'A Clear Node Quiz'
  AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM quiz_attempts qa
      WHERE qa.quiz_id = q.quiz_id
        AND qa.learner_id = u.user_id
        AND qa.attempt_number = 1
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
    created_at,
    updated_at,
    is_deleted
)
SELECT q.quiz_id, u.user_id, 4, 10, NOW() - INTERVAL '1' DAY - INTERVAL '8' MINUTE, NOW() - INTERVAL '1' DAY, 480, FALSE, 1, NOW() - INTERVAL '1' DAY, NOW() - INTERVAL '1' DAY, FALSE
FROM quizzes q, users u
WHERE q.title = 'A Gap Node Quiz'
  AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM quiz_attempts qa
      WHERE qa.quiz_id = q.quiz_id
        AND qa.learner_id = u.user_id
        AND qa.attempt_number = 1
  );

-- 3. submission
-- ??戮깅?亦껋꼶梨?節뉖퉲????沅???댟??怨룸츩
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
SELECT n.node_id, 'A Clear Assignment', 'Proof Card ?꾩룇裕???띠럾?????댟??怨룸츩 ?롪틵?嶺뚯빘鍮????λ닔????낅퉵??', 'URL', NOW() + INTERVAL '3' DAY, NULL, TRUE, TRUE, FALSE, 'GitHub ??????URL????戮깅??紐껊퉵??', 100, TRUE, TRUE, TRUE, FALSE, NOW() - INTERVAL '7' DAY, NOW() - INTERVAL '7' DAY
FROM roadmap_nodes n
WHERE n.title = 'A Swagger Clear Node'
  AND NOT EXISTS (
      SELECT 1
      FROM assignments a
      WHERE a.node_id = n.node_id
        AND a.title = 'A Clear Assignment'
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
SELECT n.node_id, 'A Failed Assignment', '??戮깅???嶺?亦껋꼶梨??Β???댟??怨룸츩 ?롪틵?嶺뚯빘鍮????λ닔????낅퉵??', 'URL', NOW() + INTERVAL '3' DAY, NULL, TRUE, TRUE, TRUE, 'GitHub ??????URL????戮깅??紐껊퉵??', 100, TRUE, TRUE, TRUE, FALSE, NOW() - INTERVAL '7' DAY, NOW() - INTERVAL '7' DAY
FROM roadmap_nodes n
WHERE n.title = 'A Swagger Gap Node'
  AND NOT EXISTS (
      SELECT 1
      FROM assignments a
      WHERE a.node_id = n.node_id
        AND a.title = 'A Failed Assignment'
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
SELECT n.node_id, 'A Missing Assignment', '亦껋꼶梨?節뉖퉲???댟??怨룸츩 ?롪틵?嶺뚯빘鍮????λ닔????낅퉵??', 'URL', NOW() + INTERVAL '4' DAY, NULL, FALSE, FALSE, FALSE, 'GitHub ??????URL????戮깅??紐껊퉵??', 100, TRUE, TRUE, TRUE, FALSE, NOW() - INTERVAL '7' DAY, NOW() - INTERVAL '7' DAY
FROM roadmap_nodes n
WHERE n.title = 'A Swagger Gap Node'
  AND NOT EXISTS (
      SELECT 1
      FROM assignments a
      WHERE a.node_id = n.node_id
        AND a.title = 'A Missing Assignment'
  );

INSERT INTO assignment_submissions (
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
)
SELECT a.assignment_id, u.user_id, 'GRADED', 'https://github.com/example/a-clear-assignment', FALSE, NOW() - INTERVAL '2' DAY, NOW() - INTERVAL '1' DAY, 95, TRUE, TRUE, TRUE, TRUE, NOW() - INTERVAL '2' DAY, NOW() - INTERVAL '1' DAY, FALSE
FROM assignments a, users u
WHERE a.title = 'A Clear Assignment'
  AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM assignment_submissions s
      WHERE s.assignment_id = a.assignment_id
        AND s.learner_id = u.user_id
  );

INSERT INTO assignment_submissions (
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
)
SELECT a.assignment_id, u.user_id, 'GRADED', 'https://github.com/example/a-failed-assignment', FALSE, NOW() - INTERVAL '1' DAY, NOW() - INTERVAL '12' HOUR, 0, FALSE, FALSE, FALSE, TRUE, NOW() - INTERVAL '1' DAY, NOW() - INTERVAL '12' HOUR, FALSE
FROM assignments a, users u
WHERE a.title = 'A Failed Assignment'
  AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM assignment_submissions s
      WHERE s.assignment_id = a.assignment_id
        AND s.learner_id = u.user_id
  );

-- 4. til / timestamp_note
INSERT INTO timestamp_notes (
    user_id,
    lesson_id,
    timestamp_second,
    content,
    created_at,
    updated_at,
    is_deleted
)
SELECT u.user_id, l.lesson_id, 120, 'A Clear Lesson?????Proof ?브퀗?쀦뤃?????곕뻣 ?筌먦끉逾???덈펲.', NOW() - INTERVAL '2' DAY, NOW() - INTERVAL '2' DAY, FALSE
FROM users u, lessons l
WHERE u.email = 'learner@devpath.com'
  AND l.title = 'A Clear Lesson'
  AND NOT EXISTS (
      SELECT 1
      FROM timestamp_notes tn
      WHERE tn.user_id = u.user_id
        AND tn.lesson_id = l.lesson_id
        AND tn.timestamp_second = 120
  );

INSERT INTO timestamp_notes (
    user_id,
    lesson_id,
    timestamp_second,
    content,
    created_at,
    updated_at,
    is_deleted
)
SELECT u.user_id, l.lesson_id, 240, 'A Gap Lesson???????伊쇿퐲???蹂μ쟽?? ??λ닔????⑤객臾??嶺뚮∥?????덈펲.', NOW() - INTERVAL '1' DAY, NOW() - INTERVAL '1' DAY, FALSE
FROM users u, lessons l
WHERE u.email = 'learner@devpath.com'
  AND l.title = 'A Gap Lesson'
  AND NOT EXISTS (
      SELECT 1
      FROM timestamp_notes tn
      WHERE tn.user_id = u.user_id
        AND tn.lesson_id = l.lesson_id
        AND tn.timestamp_second = 240
  );

INSERT INTO til_drafts (
    user_id,
    lesson_id,
    title,
    content,
    status,
    published_url,
    created_at,
    updated_at,
    is_deleted
)
SELECT u.user_id, l.lesson_id, 'A Clear Node TIL', 'NodeClearance?? Proof Card ?꾩룇裕???브퀗?쀦뤃???筌먲퐘遊???덈펲.', 'PUBLISHED', 'https://velog.io/@devpath/a-clear-proof', NOW() - INTERVAL '2' DAY, NOW() - INTERVAL '2' DAY, FALSE
FROM users u, lessons l
WHERE u.email = 'learner@devpath.com'
  AND l.title = 'A Clear Lesson'
  AND NOT EXISTS (
      SELECT 1
      FROM til_drafts td
      WHERE td.user_id = u.user_id
        AND td.title = 'A Clear Node TIL'
  );

INSERT INTO til_drafts (
    user_id,
    lesson_id,
    title,
    content,
    status,
    published_url,
    created_at,
    updated_at,
    is_deleted
)
SELECT u.user_id, l.lesson_id, 'A Gap Node TIL', '?遊붋????蹂μ쟽?? ??λ닔??亦껋꼶梨??Β????逾???筌먲퐘遊???덈펲.', 'DRAFT', NULL, NOW() - INTERVAL '1' DAY, NOW() - INTERVAL '1' DAY, FALSE
FROM users u, lessons l
WHERE u.email = 'learner@devpath.com'
  AND l.title = 'A Gap Lesson'
  AND NOT EXISTS (
      SELECT 1
      FROM til_drafts td
      WHERE td.user_id = u.user_id
        AND td.title = 'A Gap Node TIL'
  );

-- 5. supplement_recommendation
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
SELECT u.user_id, n.node_id, 'Spring Security ??蹂μ쟽?띠럾? ?遊붋?브퀗?꿴뜮??곌랜??????덈????怨뺣뾼???紐껊퉵??', 95, 35.00, 1, 'PENDING', NOW() - INTERVAL '12' HOUR, NOW() - INTERVAL '12' HOUR
FROM users u, roadmap_nodes n
WHERE u.email = 'learner@devpath.com'
  AND n.title = 'A Swagger Gap Node'
  AND NOT EXISTS (
      SELECT 1
      FROM supplement_recommendations sr
      WHERE sr.user_id = u.user_id
        AND sr.node_id = n.node_id
  );

-- 6. proof_card / certificate / share_link / download_history
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
SELECT u.user_id, n.node_id, 'CLEARED', 100.00, TRUE, 0, TRUE, TRUE, TRUE, TRUE, NOW() - INTERVAL '1' DAY, NOW() - INTERVAL '1' DAY, NOW() - INTERVAL '1' DAY, NOW() - INTERVAL '1' DAY
FROM users u, roadmap_nodes n
WHERE u.email = 'learner@devpath.com'
  AND n.title = 'A Swagger Clear Node'
  AND NOT EXISTS (
      SELECT 1
      FROM node_clearances nc
      WHERE nc.user_id = u.user_id
        AND nc.node_id = n.node_id
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
SELECT u.user_id, n.node_id, 'NOT_CLEARED', 0.00, FALSE, 1, FALSE, FALSE, FALSE, FALSE, NULL, NOW() - INTERVAL '12' HOUR, NOW() - INTERVAL '12' HOUR, NOW() - INTERVAL '12' HOUR
FROM users u, roadmap_nodes n
WHERE u.email = 'learner@devpath.com'
  AND n.title = 'A Swagger Gap Node'
  AND NOT EXISTS (
      SELECT 1
      FROM node_clearances nc
      WHERE nc.user_id = u.user_id
        AND nc.node_id = n.node_id
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
SELECT u.user_id, n.node_id, nc.node_clearance_id, 'A Clear Node Proof Card', 'A Clear Node??NodeClearance?? Proof ?꾩룇裕???띠럾?????⑤객臾??嶺뚯빘鍮뽳㎖??紐껊퉵??', 'ISSUED', NOW() - INTERVAL '1' DAY, NOW() - INTERVAL '1' DAY, NOW() - INTERVAL '1' DAY
FROM users u
JOIN roadmap_nodes n ON n.title = 'A Swagger Clear Node'
JOIN node_clearances nc ON nc.user_id = u.user_id AND nc.node_id = n.node_id
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM proof_cards pc
      WHERE pc.user_id = u.user_id
        AND pc.node_id = n.node_id
  );

INSERT INTO proof_card_tags (
    proof_card_id,
    tag_id,
    skill_evidence_type
)
SELECT pc.proof_card_id, t.tag_id, 'VERIFIED'
FROM proof_cards pc
JOIN roadmap_nodes n ON n.node_id = pc.node_id,
     tags t
WHERE n.title = 'A Swagger Clear Node'
  AND t.name = 'Java'
  AND NOT EXISTS (
      SELECT 1
      FROM proof_card_tags pt
      WHERE pt.proof_card_id = pc.proof_card_id
        AND pt.tag_id = t.tag_id
        AND pt.skill_evidence_type = 'VERIFIED'
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
SELECT pc.proof_card_id, 'proof-share-token-a-21101', 'ACTIVE', NOW() + INTERVAL '30' DAY, 3, NOW() - INTERVAL '1' DAY, NOW() - INTERVAL '6' HOUR
FROM proof_cards pc
JOIN roadmap_nodes n ON n.node_id = pc.node_id
WHERE n.title = 'A Swagger Clear Node'
  AND NOT EXISTS (
      SELECT 1
      FROM proof_card_shares ps
      WHERE ps.share_token = 'proof-share-token-a-21101'
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
SELECT pc.proof_card_id, 'CERT-20260330-A1001', 'PDF_READY', NOW() - INTERVAL '1' DAY, 'certificate-CERT-20260330-A1001.pdf', NOW() - INTERVAL '1' DAY, NOW() - INTERVAL '12' HOUR, NOW() - INTERVAL '1' DAY, NOW() - INTERVAL '12' HOUR
FROM proof_cards pc
JOIN roadmap_nodes n ON n.node_id = pc.node_id
WHERE n.title = 'A Swagger Clear Node'
  AND NOT EXISTS (
      SELECT 1
      FROM certificates c
      WHERE c.proof_card_id = pc.proof_card_id
  );

INSERT INTO certificate_download_histories (
    certificate_id,
    downloaded_by,
    download_reason,
    downloaded_at
)
SELECT c.certificate_id, u.user_id, 'A Swagger certificate download', NOW() - INTERVAL '12' HOUR
FROM certificates c, users u
WHERE c.certificate_number = 'CERT-20260330-A1001'
  AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM certificate_download_histories h
      WHERE h.certificate_id = c.certificate_id
        AND h.download_reason = 'A Swagger certificate download'
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
SELECT u.user_id, 'history-share-token-a-21151', 'A Swagger Learning History', NOW() + INTERVAL '14' DAY, 1, TRUE, NOW() - INTERVAL '8' HOUR, NOW() - INTERVAL '8' HOUR
FROM users u
WHERE u.email = 'learner@devpath.com'
  AND NOT EXISTS (
      SELECT 1
      FROM learning_history_share_links l
      WHERE l.share_token = 'history-share-token-a-21151'
  );

-- 7. learning_rule / metric_sample
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
SELECT 'A_SWAGGER_HISTORY_REFRESH', 'A Swagger History Refresh', 'A ?熬곣뫗???롪틵?嶺뚯빘鍮????戮?뎽 ?猷고????덈펲.', 'true', 40, 'ENABLED', NOW() - INTERVAL '2' DAY, NOW() - INTERVAL '2' DAY
WHERE NOT EXISTS (
    SELECT 1
    FROM learning_automation_rules r
    WHERE r.rule_key = 'A_SWAGGER_HISTORY_REFRESH'
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
SELECT 'A_SWAGGER_PROOF_LOCK', 'A Swagger Proof Lock', 'A ?熬곣뫗???롪틵?嶺뚯빘鍮?????????猷고????덈펲.', 'false', 30, 'DISABLED', NOW() - INTERVAL '2' DAY, NOW() - INTERVAL '2' DAY
WHERE NOT EXISTS (
    SELECT 1
    FROM learning_automation_rules r
    WHERE r.rule_key = 'A_SWAGGER_PROOF_LOCK'
);

INSERT INTO learning_metric_samples (
    metric_type,
    metric_label,
    metric_value,
    sampled_at,
    created_at
)
SELECT 'OVERVIEW', 'aSwaggerClearanceRate', 50.00, NOW() - INTERVAL '6' HOUR, NOW() - INTERVAL '6' HOUR
WHERE NOT EXISTS (
    SELECT 1
    FROM learning_metric_samples s
    WHERE s.metric_label = 'aSwaggerClearanceRate'
);

INSERT INTO learning_metric_samples (
    metric_type,
    metric_label,
    metric_value,
    sampled_at,
    created_at
)
SELECT 'QUIZ_STATS', 'aSwaggerQuizQuality', 65.00, NOW() - INTERVAL '6' HOUR, NOW() - INTERVAL '6' HOUR
WHERE NOT EXISTS (
    SELECT 1
    FROM learning_metric_samples s
    WHERE s.metric_label = 'aSwaggerQuizQuality'
);

-- =========================================================

-- A SEED END
-- =====================================================


-- =====================================================
-- B SECTION: instructor, review, refund, marketing, qna
-- anchored on COMMON BASE users and courses
-- =====================================================

-- [1] review
INSERT INTO review (course_id, learner_id, rating, content, status, is_hidden, is_deleted, issue_tags_raw, created_at, updated_at)
SELECT c.course_id, u.user_id, 5, 'The Spring Boot intro course was easy to follow and the examples were practical.', 'ANSWERED', FALSE, FALSE, NULL, '2026-01-20 00:00:00', '2026-01-20 00:00:00'
FROM courses c, users u
WHERE c.title = 'Spring Boot Intro' AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM review r WHERE r.content = 'The Spring Boot intro course was easy to follow and the examples were practical.');

INSERT INTO review (course_id, learner_id, rating, content, status, is_hidden, is_deleted, issue_tags_raw, created_at, updated_at)
SELECT c.course_id, u.user_id, 4, 'The JPA design material was useful, but I want one more QueryDSL example for filtering.', 'UNANSWERED', FALSE, FALSE, NULL, '2026-01-22 00:00:00', '2026-01-22 00:00:00'
FROM courses c, users u
WHERE c.title = 'JPA Practical Design' AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM review r WHERE r.content = 'The JPA design material was useful, but I want one more QueryDSL example for filtering.');

INSERT INTO review (course_id, learner_id, rating, content, status, is_hidden, is_deleted, issue_tags_raw, created_at, updated_at)
SELECT c.course_id, u.user_id, 3, 'I understood the deployment chapter, but a slower walkthrough would help beginners.', 'ANSWERED', FALSE, FALSE, NULL, '2026-01-25 00:00:00', '2026-01-25 00:00:00'
FROM courses c, users u
WHERE c.title = 'Spring Boot Intro' AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM review r WHERE r.content = 'I understood the deployment chapter, but a slower walkthrough would help beginners.');

INSERT INTO review (course_id, learner_id, rating, content, status, is_hidden, is_deleted, issue_tags_raw, created_at, updated_at)
SELECT c.course_id, u.user_id, 5, 'The N plus one explanation was strong. A side by side query comparison would make it even better.', 'UNANSWERED', FALSE, FALSE, NULL, '2026-01-28 00:00:00', '2026-01-28 00:00:00'
FROM courses c, users u
WHERE c.title = 'JPA Practical Design' AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM review r WHERE r.content = 'The N plus one explanation was strong. A side by side query comparison would make it even better.');

INSERT INTO review (course_id, learner_id, rating, content, status, is_hidden, is_deleted, issue_tags_raw, created_at, updated_at)
SELECT c.course_id, u.user_id, 2, 'The pace felt fast for the security section and I had trouble matching the code to the lecture.', 'UNSATISFIED', FALSE, FALSE, NULL, '2026-02-01 00:00:00', '2026-02-01 00:00:00'
FROM courses c, users u
WHERE c.title = 'Spring Boot Intro' AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM review r WHERE r.content = 'The pace felt fast for the security section and I had trouble matching the code to the lecture.');

-- [2] review_reply
INSERT INTO review_reply (review_id, instructor_id, content, is_deleted, created_at, updated_at)
SELECT r.id, u.user_id, 'Thanks for the detailed feedback. I will add one more guided example and update the lecture notes.', FALSE, '2026-01-21 00:00:00', '2026-01-21 00:00:00'
FROM review r, users u
WHERE r.content = 'The Spring Boot intro course was easy to follow and the examples were practical.'
  AND u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM review_reply rr WHERE rr.review_id = r.id AND rr.instructor_id = u.user_id);

INSERT INTO review_reply (review_id, instructor_id, content, is_deleted, created_at, updated_at)
SELECT r.id, u.user_id, 'I will add a shorter beginner path for this topic and link the revised notes in the next update.', FALSE, '2026-01-26 00:00:00', '2026-01-26 00:00:00'
FROM review r, users u
WHERE r.content = 'I understood the deployment chapter, but a slower walkthrough would help beginners.'
  AND u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM review_reply rr WHERE rr.review_id = r.id AND rr.instructor_id = u.user_id);

INSERT INTO review_reply (review_id, instructor_id, content, is_deleted, created_at, updated_at)
SELECT r.id, u.user_id, 'I reviewed the section and will break the security setup into smaller steps with a checklist.', FALSE, '2026-02-02 00:00:00', '2026-02-02 00:00:00'
FROM review r, users u
WHERE r.content = 'The pace felt fast for the security section and I had trouble matching the code to the lecture.'
  AND u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM review_reply rr WHERE rr.review_id = r.id AND rr.instructor_id = u.user_id);

-- [3] review_template
INSERT INTO review_template (instructor_id, title, content, is_deleted, created_at, updated_at)
SELECT u.user_id, 'Quick acknowledgment', 'Thanks for the review. I checked the issue and will follow up with a concrete fix or guide.', FALSE, '2026-01-15 00:00:00', '2026-01-15 00:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM review_template rt WHERE rt.title = 'Quick acknowledgment' AND rt.instructor_id = u.user_id);

INSERT INTO review_template (instructor_id, title, content, is_deleted, created_at, updated_at)
SELECT u.user_id, 'Ask for reproduction steps', 'Please share the exact steps, environment, and expected result so I can reproduce the problem quickly.', FALSE, '2026-01-15 00:00:00', '2026-01-15 00:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM review_template rt WHERE rt.title = 'Ask for reproduction steps' AND rt.instructor_id = u.user_id);

INSERT INTO review_template (instructor_id, title, content, is_deleted, created_at, updated_at)
SELECT u.user_id, 'Share extra material', 'I added a follow up explanation and extra material so you can review the topic in smaller steps.', FALSE, '2026-01-15 00:00:00', '2026-01-15 00:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM review_template rt WHERE rt.title = 'Share extra material' AND rt.instructor_id = u.user_id);

-- [4] refund_request
INSERT INTO refund_request (learner_id, course_id, instructor_id, reason, enrolled_at, progress_percent_snapshot, refund_amount, status, is_deleted, requested_at, processed_at)
SELECT u.user_id, c.course_id, c.instructor_id, 'Schedule mismatch', '2026-02-01 00:00:00', 15, COALESCE(CAST(c.price AS BIGINT), 0), 'PENDING', FALSE, '2026-02-05 00:00:00', NULL
FROM users u, courses c
WHERE u.email = 'learner@devpath.com' AND c.title = 'Spring Boot Intro'
  AND NOT EXISTS (SELECT 1 FROM refund_request rr WHERE rr.reason = 'Schedule mismatch' AND rr.learner_id = u.user_id AND rr.course_id = c.course_id);

INSERT INTO refund_request (learner_id, course_id, instructor_id, reason, enrolled_at, progress_percent_snapshot, refund_amount, status, is_deleted, requested_at, processed_at)
SELECT u.user_id, c.course_id, c.instructor_id, 'Duplicate purchase', '2026-02-03 00:00:00', 10, COALESCE(CAST(c.price AS BIGINT), 0), 'APPROVED', FALSE, '2026-02-08 00:00:00', '2026-02-10 00:00:00'
FROM users u, courses c
WHERE u.email = 'learner@devpath.com' AND c.title = 'JPA Practical Design'
  AND NOT EXISTS (SELECT 1 FROM refund_request rr WHERE rr.reason = 'Duplicate purchase' AND rr.learner_id = u.user_id AND rr.course_id = c.course_id);

INSERT INTO refund_request (learner_id, course_id, instructor_id, reason, enrolled_at, progress_percent_snapshot, refund_amount, status, is_deleted, requested_at, processed_at)
SELECT u.user_id, c.course_id, c.instructor_id, 'Not what I expected', '2026-02-06 00:00:00', 25, COALESCE(CAST(c.price AS BIGINT), 0), 'REJECTED', FALSE, '2026-02-12 00:00:00', '2026-02-13 00:00:00'
FROM users u, courses c
WHERE u.email = 'learner@devpath.com' AND c.title = 'Spring Boot Intro'
  AND NOT EXISTS (SELECT 1 FROM refund_request rr WHERE rr.reason = 'Not what I expected' AND rr.learner_id = u.user_id AND rr.course_id = c.course_id);

-- [5] settlement
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

-- [6] coupon
INSERT INTO coupon (instructor_id, coupon_code, discount_type, discount_value, target_course_id, max_usage_count, usage_count, expires_at, is_deleted, created_at)
SELECT u.user_id, 'HELLO2026', 'RATE', 30, NULL, 100, 45, '2026-02-28 23:59:59', FALSE, '2026-01-20 00:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM coupon c WHERE c.coupon_code = 'HELLO2026');

INSERT INTO coupon (instructor_id, coupon_code, discount_type, discount_value, target_course_id, max_usage_count, usage_count, expires_at, is_deleted, created_at)
SELECT u.user_id, 'JAVA_LAUNCH', 'AMOUNT', 15000, c.course_id, 200, 82, '2026-03-15 23:59:59', FALSE, '2026-01-20 00:00:00'
FROM users u, courses c
WHERE u.email = 'instructor@devpath.com' AND c.title = 'Spring Boot Intro'
  AND NOT EXISTS (SELECT 1 FROM coupon cp WHERE cp.coupon_code = 'JAVA_LAUNCH');

-- [7] promotion
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

-- [8] notice
INSERT INTO notice (author_id, title, content, is_pinned, is_deleted, created_at, updated_at)
SELECT u.user_id, 'Platform maintenance window', 'DevPath maintenance is scheduled for 2026-02-15 from 02:00 to 04:00 KST. Course playback and QnA posting may be briefly delayed.', TRUE, FALSE, '2026-02-10 00:00:00', '2026-02-10 00:00:00'
FROM users u
WHERE u.email = 'admin@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM notice n WHERE n.title = 'Platform maintenance window');

INSERT INTO notice (author_id, title, content, is_pinned, is_deleted, created_at, updated_at)
SELECT u.user_id, 'Refund policy reminder', 'Refund requests are reviewed against enrollment date and progress snapshot. Please attach a clear reason when filing a request.', FALSE, FALSE, '2026-02-20 00:00:00', '2026-02-20 00:00:00'
FROM users u
WHERE u.email = 'admin@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM notice n WHERE n.title = 'Refund policy reminder');

INSERT INTO notice (author_id, title, content, is_pinned, is_deleted, created_at, updated_at)
SELECT u.user_id, 'Streaming quality update', 'Adaptive streaming and OCR search quality were updated for recent lessons. Please report any playback regression through support.', FALSE, FALSE, '2026-03-01 00:00:00', '2026-03-01 00:00:00'
FROM users u
WHERE u.email = 'admin@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM notice n WHERE n.title = 'Streaming quality update');

-- [9] admin_role
INSERT INTO admin_role (role_name, description, is_deleted, created_at, updated_at)
SELECT 'SUPER_ADMIN', 'Owns full platform level operations and approval authority.', FALSE, '2026-01-01 00:00:00', '2026-01-01 00:00:00'
WHERE NOT EXISTS (SELECT 1 FROM admin_role ar WHERE ar.role_name = 'SUPER_ADMIN');

INSERT INTO admin_role (role_name, description, is_deleted, created_at, updated_at)
SELECT 'CONTENT_MANAGER', 'Handles content governance, notices, and moderation workflows.', FALSE, '2026-01-01 00:00:00', '2026-01-01 00:00:00'
WHERE NOT EXISTS (SELECT 1 FROM admin_role ar WHERE ar.role_name = 'CONTENT_MANAGER');

INSERT INTO admin_role (role_name, description, is_deleted, created_at, updated_at)
SELECT 'CS_MANAGER', 'Handles support, refund operations, and learner issue escalation.', FALSE, '2026-01-01 00:00:00', '2026-01-01 00:00:00'
WHERE NOT EXISTS (SELECT 1 FROM admin_role ar WHERE ar.role_name = 'CS_MANAGER');

-- [10] instructor_post
INSERT INTO instructor_post (instructor_id, title, content, post_type, like_count, comment_count, is_deleted, created_at, updated_at)
SELECT u.user_id, '[Notice] Weekly live QnA schedule', 'Weekly live QnA will be held every Tuesday. Please post questions in advance.', 'NOTICE', 0, 1, FALSE, '2026-01-15 00:00:00', '2026-01-15 00:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM instructor_post ip WHERE ip.title = '[Notice] Weekly live QnA schedule');

INSERT INTO instructor_post (instructor_id, title, content, post_type, like_count, comment_count, is_deleted, created_at, updated_at)
SELECT u.user_id, 'How to avoid N plus one with JPA', 'Check fetch joins, entity graphs, and batch size settings before changing repository structure.', 'GENERAL', 0, 1, FALSE, '2026-01-20 00:00:00', '2026-01-20 00:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM instructor_post ip WHERE ip.title = 'How to avoid N plus one with JPA');

INSERT INTO instructor_post (instructor_id, title, content, post_type, like_count, comment_count, is_deleted, created_at, updated_at)
SELECT u.user_id, 'HTTP status code guide', 'Review the difference between 200, 201, 400, 401, 403, 404, and 500 before debugging API flows.', 'GENERAL', 0, 1, FALSE, '2026-01-25 00:00:00', '2026-01-25 00:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM instructor_post ip WHERE ip.title = 'HTTP status code guide');

INSERT INTO instructor_post (instructor_id, title, content, post_type, like_count, comment_count, is_deleted, created_at, updated_at)
SELECT u.user_id, 'Docker Compose local setup tips', 'Keep app, database, and cache startup simple when debugging local environments.', 'GENERAL', 0, 1, FALSE, '2026-02-03 00:00:00', '2026-02-03 00:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM instructor_post ip WHERE ip.title = 'Docker Compose local setup tips');

INSERT INTO instructor_post (instructor_id, title, content, post_type, like_count, comment_count, is_deleted, created_at, updated_at)
SELECT u.user_id, 'JWT access and refresh token strategy', 'Use short lived access tokens and store refresh tokens securely with rotation rules.', 'GENERAL', 0, 1, FALSE, '2026-02-10 00:00:00', '2026-02-10 00:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM instructor_post ip WHERE ip.title = 'JWT access and refresh token strategy');

-- [11] instructor_comment
INSERT INTO instructor_comment (post_id, author_id, parent_comment_id, content, like_count, is_deleted, created_at)
SELECT ip.id, u.user_id, NULL, 'The weekly QnA slot is useful. Please share the agenda early if possible.', 0, FALSE, '2026-01-16 00:00:00'
FROM instructor_post ip, users u
WHERE ip.title = '[Notice] Weekly live QnA schedule' AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM instructor_comment ic WHERE ic.post_id = ip.id AND ic.content = 'The weekly QnA slot is useful. Please share the agenda early if possible.');

INSERT INTO instructor_comment (post_id, author_id, parent_comment_id, content, like_count, is_deleted, created_at)
SELECT ip.id, u.user_id, NULL, 'This helped. A side by side example of fetch join versus lazy loading would be even better.', 0, FALSE, '2026-01-21 00:00:00'
FROM instructor_post ip, users u
WHERE ip.title = 'How to avoid N plus one with JPA' AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM instructor_comment ic WHERE ic.post_id = ip.id AND ic.content = 'This helped. A side by side example of fetch join versus lazy loading would be even better.');

INSERT INTO instructor_comment (post_id, author_id, parent_comment_id, content, like_count, is_deleted, created_at)
SELECT ip.id, u.user_id, NULL, 'A compact table for common status codes would make this easier to review.', 0, FALSE, '2026-01-26 00:00:00'
FROM instructor_post ip, users u
WHERE ip.title = 'HTTP status code guide' AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM instructor_comment ic WHERE ic.post_id = ip.id AND ic.content = 'A compact table for common status codes would make this easier to review.');

INSERT INTO instructor_comment (post_id, author_id, parent_comment_id, content, like_count, is_deleted, created_at)
SELECT ip.id, u.user_id, NULL, 'The Docker examples were helpful for local setup. Please add one troubleshooting checklist.', 0, FALSE, '2026-02-04 00:00:00'
FROM instructor_post ip, users u
WHERE ip.title = 'Docker Compose local setup tips' AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM instructor_comment ic WHERE ic.post_id = ip.id AND ic.content = 'The Docker examples were helpful for local setup. Please add one troubleshooting checklist.');

INSERT INTO instructor_comment (post_id, author_id, parent_comment_id, content, like_count, is_deleted, created_at)
SELECT ip.id, u.user_id, NULL, 'Please add guidance on refresh token rotation and logout handling.', 0, FALSE, '2026-02-11 00:00:00'
FROM instructor_post ip, users u
WHERE ip.title = 'JWT access and refresh token strategy' AND u.email = 'learner@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM instructor_comment ic WHERE ic.post_id = ip.id AND ic.content = 'Please add guidance on refresh token rotation and logout handling.');

-- [12] qna_questions
INSERT INTO qna_questions (user_id, template_type, difficulty, title, content, adopted_answer_id, course_id, lecture_timestamp, qna_status, view_count, is_deleted, created_at, updated_at)
SELECT u.user_id, 'DEBUGGING', 'EASY', 'BeanCreationException during startup', 'Spring Boot startup fails with BeanCreationException. Which bean should I inspect first and how do I narrow the cause?', NULL, c.course_id, '00:12:30', 'UNANSWERED', 0, FALSE, '2026-02-05 00:00:00', '2026-02-05 00:00:00'
FROM users u, courses c
WHERE u.email = 'learner@devpath.com' AND c.title = 'Spring Boot Intro'
  AND NOT EXISTS (SELECT 1 FROM qna_questions q WHERE q.title = 'BeanCreationException during startup');

INSERT INTO qna_questions (user_id, template_type, difficulty, title, content, adopted_answer_id, course_id, lecture_timestamp, qna_status, view_count, is_deleted, created_at, updated_at)
SELECT u.user_id, 'IMPLEMENTATION', 'MEDIUM', 'How to avoid JPA infinite recursion', 'My entity graph loops when I serialize it to JSON. What is the safest way to stop recursive references?', NULL, c.course_id, '00:28:10', 'UNANSWERED', 0, FALSE, '2026-02-08 00:00:00', '2026-02-08 00:00:00'
FROM users u, courses c
WHERE u.email = 'learner@devpath.com' AND c.title = 'JPA Practical Design'
  AND NOT EXISTS (SELECT 1 FROM qna_questions q WHERE q.title = 'How to avoid JPA infinite recursion');

-- [13] qna_answer_draft
INSERT INTO qna_answer_draft (question_id, instructor_id, draft_content, is_deleted, saved_at, updated_at)
SELECT q.question_id, u.user_id, 'Start from the root cause in the stack trace, then check configuration classes, component scanning, and constructor dependencies.', FALSE, '2026-02-06 00:00:00', '2026-02-06 00:00:00'
FROM qna_questions q, users u
WHERE q.title = 'BeanCreationException during startup' AND u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM qna_answer_draft d WHERE d.question_id = q.question_id AND d.instructor_id = u.user_id);

INSERT INTO qna_answer_draft (question_id, instructor_id, draft_content, is_deleted, saved_at, updated_at)
SELECT q.question_id, u.user_id, 'Prefer response DTOs for API output, and use reference annotations only when you must serialize the entity graph directly.', FALSE, '2026-02-09 00:00:00', '2026-02-09 00:00:00'
FROM qna_questions q, users u
WHERE q.title = 'How to avoid JPA infinite recursion' AND u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM qna_answer_draft d WHERE d.question_id = q.question_id AND d.instructor_id = u.user_id);

-- [14] qna_template
INSERT INTO qna_template (instructor_id, title, content, is_deleted, created_at, updated_at)
SELECT u.user_id, 'Debugging startup errors', 'Check stack trace order, configuration classes, environment variables, and recent dependency changes first.', FALSE, '2026-01-10 00:00:00', '2026-01-10 00:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM qna_template qt WHERE qt.title = 'Debugging startup errors' AND qt.instructor_id = u.user_id);

INSERT INTO qna_template (instructor_id, title, content, is_deleted, created_at, updated_at)
SELECT u.user_id, 'N plus one review checklist', 'Compare repository query count, fetch strategy, and entity graph usage before changing domain structure.', FALSE, '2026-01-10 00:00:00', '2026-01-10 00:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM qna_template qt WHERE qt.title = 'N plus one review checklist' AND qt.instructor_id = u.user_id);

INSERT INTO qna_template (instructor_id, title, content, is_deleted, created_at, updated_at)
SELECT u.user_id, 'API error triage guide', 'Write down request payload, response code, logs, and reproduction steps before escalating the issue.', FALSE, '2026-01-10 00:00:00', '2026-01-10 00:00:00'
FROM users u
WHERE u.email = 'instructor@devpath.com'
  AND NOT EXISTS (SELECT 1 FROM qna_template qt WHERE qt.title = 'API error triage guide' AND qt.instructor_id = u.user_id);

-- B SECTION identity restart
ALTER TABLE review ALTER COLUMN id RESTART WITH 1000;
ALTER TABLE review_reply ALTER COLUMN id RESTART WITH 1000;
ALTER TABLE review_template ALTER COLUMN id RESTART WITH 1000;
ALTER TABLE refund_request ALTER COLUMN id RESTART WITH 1000;
ALTER TABLE settlement ALTER COLUMN id RESTART WITH 1000;
ALTER TABLE coupon ALTER COLUMN id RESTART WITH 1000;
ALTER TABLE promotion ALTER COLUMN id RESTART WITH 1000;
ALTER TABLE notice ALTER COLUMN id RESTART WITH 1000;
ALTER TABLE admin_role ALTER COLUMN id RESTART WITH 1000;
ALTER TABLE instructor_post ALTER COLUMN id RESTART WITH 1000;
ALTER TABLE instructor_comment ALTER COLUMN id RESTART WITH 1000;
ALTER TABLE qna_questions ALTER COLUMN question_id RESTART WITH 1000;
ALTER TABLE qna_answer_draft ALTER COLUMN id RESTART WITH 1000;
ALTER TABLE qna_template ALTER COLUMN id RESTART WITH 1000;
