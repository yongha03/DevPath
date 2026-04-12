content = """

-- ========================================
-- Backend Master Roadmap 노드 태그 연결 (노드 추천 시스템용)
-- ========================================

-- 추가 태그
INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'OOP', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'OOP');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'Git', 'DevOps', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'Git');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'SQL', 'Database', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'SQL');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'REST', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'REST');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'Testing', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'Testing');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'Kafka', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'Kafka');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'MSA', 'Backend', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'MSA');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'CI/CD', 'DevOps', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'CI/CD');

INSERT INTO tags (name, category, is_official, is_deleted)
SELECT 'Linux', 'DevOps', TRUE, FALSE
WHERE NOT EXISTS (SELECT 1 FROM tags WHERE name = 'Linux');

-- 인터넷 & 웹 기초: HTTP
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = '인터넷 & 웹 기초' AND t.name = 'HTTP'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- OS & 터미널: Linux
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'OS & 터미널' AND t.name = 'Linux'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- Java 기초: Java, OOP
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Java 기초' AND t.name = 'Java'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Java 기초' AND t.name = 'OOP'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- Git & 버전 관리: Git
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Git & 버전 관리' AND t.name = 'Git'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- RDB & SQL: PostgreSQL, SQL
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'RDB & SQL' AND t.name = 'PostgreSQL'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'RDB & SQL' AND t.name = 'SQL'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- REST API 설계: HTTP, REST
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'REST API 설계' AND t.name = 'HTTP'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'REST API 설계' AND t.name = 'REST'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- Spring Boot & MVC: Spring Boot, Java
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Spring Boot & MVC' AND t.name = 'Spring Boot'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Spring Boot & MVC' AND t.name = 'Java'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- Spring Data JPA: JPA, Spring Boot
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Spring Data JPA' AND t.name = 'JPA'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Spring Data JPA' AND t.name = 'Spring Boot'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- Redis 기초: Redis
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Redis 기초' AND t.name = 'Redis'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- Redis 심화: Redis
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Redis 심화' AND t.name = 'Redis'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- JUnit5 & Mockito: Java, Testing
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'JUnit5 & Mockito' AND t.name = 'Java'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'JUnit5 & Mockito' AND t.name = 'Testing'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- Spring Boot 테스트: Spring Boot, Testing
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Spring Boot 테스트' AND t.name = 'Spring Boot'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Spring Boot 테스트' AND t.name = 'Testing'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- Spring Security & JWT: Spring Security, JWT
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Spring Security & JWT' AND t.name = 'Spring Security'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Spring Security & JWT' AND t.name = 'JWT'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- Docker & CI/CD: Docker, CI/CD
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Docker & CI/CD' AND t.name = 'Docker'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'Docker & CI/CD' AND t.name = 'CI/CD'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- SOLID & 디자인패턴: Java
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = 'SOLID & 디자인패턴' AND t.name = 'Java'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- 웹 보안 기초: Spring Security, HTTP
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = '웹 보안 기초' AND t.name = 'Spring Security'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = '웹 보안 기초' AND t.name = 'HTTP'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

-- 메시지 큐 & MSA: Kafka, MSA
INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = '메시지 큐 & MSA' AND t.name = 'Kafka'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);

INSERT INTO node_required_tags (node_id, tag_id)
SELECT rn.node_id, t.tag_id FROM roadmap_nodes rn, tags t
WHERE rn.title = '메시지 큐 & MSA' AND t.name = 'MSA'
  AND NOT EXISTS (SELECT 1 FROM node_required_tags WHERE node_id = rn.node_id AND tag_id = t.tag_id);
"""
with open('src/main/resources/data.sql', 'a', encoding='utf-8') as f:
    f.write(content)
print('done')