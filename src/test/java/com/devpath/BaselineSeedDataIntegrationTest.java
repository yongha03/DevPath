package com.devpath;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:baseline-seed-test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE",
      "spring.sql.init.mode=always",
      "spring.jpa.defer-datasource-initialization=true"
    })
@ActiveProfiles("test")
class BaselineSeedDataIntegrationTest {

  @Autowired private JdbcTemplate jdbcTemplate;

  @Test
  void week2BaselineSeedIsLoaded() {
    assertThat(count("users")).isGreaterThanOrEqualTo(3);
    assertThat(count("user_profiles")).isGreaterThanOrEqualTo(2);
    assertThat(count("courses")).isGreaterThanOrEqualTo(2);
    assertThat(count("roadmaps")).isGreaterThanOrEqualTo(2);
    assertThat(count("roadmap_nodes")).isGreaterThanOrEqualTo(6);
    assertThat(count("tags")).isGreaterThanOrEqualTo(10);
    assertThat(count("course_tag_maps")).isGreaterThanOrEqualTo(5);
    assertThat(count("course_announcements")).isGreaterThanOrEqualTo(2);
    assertThat(count("qna_questions")).isGreaterThanOrEqualTo(2);
    assertThat(count("instructor_notification")).isGreaterThanOrEqualTo(2);
  }

  @Test
  void seededProfilesUseReadableBioAndDefaultAvatarFallback() {
    assertThat(profileField("instructor@devpath.com", "bio"))
        .isEqualTo("Spring Boot와 Security를 실전 중심으로 가르치는 강사입니다.");
    assertThat(profileField("admin@devpath.com", "bio"))
        .isEqualTo("DevPath 플랫폼 운영과 학습 경험 개선을 담당하고 있습니다.");
    assertThat(profileField("instructor@devpath.com", "profile_image")).isNull();
    assertThat(profileField("admin@devpath.com", "profile_image")).isNull();
  }

  private Integer count(String tableName) {
    return jdbcTemplate.queryForObject("select count(*) from " + tableName, Integer.class);
  }

  private String profileField(String email, String columnName) {
    return jdbcTemplate.queryForObject(
        "select "
            + columnName
            + " from user_profiles up join users u on u.user_id = up.user_id where u.email = ?",
        String.class,
        email);
  }
}
