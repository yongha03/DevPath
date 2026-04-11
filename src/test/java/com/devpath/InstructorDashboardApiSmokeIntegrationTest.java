package com.devpath;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:instructor-dashboard-smoke;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE",
      "spring.sql.init.mode=always",
      "spring.jpa.defer-datasource-initialization=true"
    })
@AutoConfigureMockMvc
@ActiveProfiles("test")
class InstructorDashboardApiSmokeIntegrationTest {

  @Autowired private MockMvc mockMvc;
  @Autowired private JdbcTemplate jdbcTemplate;

  private Long instructorId;

  @BeforeEach
  void setUp() {
    instructorId =
        jdbcTemplate.queryForObject(
            "select user_id from users where email = ?", Long.class, "instructor@devpath.com");
  }

  @Test
  void coursesEndpointLoads() throws Exception {
    performOk("/api/instructor/courses");
  }

  @Test
  void notificationsEndpointLoads() throws Exception {
    performOk("/api/instructor/notifications");
  }

  @Test
  void reviewSummaryEndpointLoads() throws Exception {
    performOk("/api/instructor/reviews/summary");
  }

  @Test
  void reviewsEndpointLoads() throws Exception {
    performOk("/api/instructor/reviews");
  }

  @Test
  void qnaInboxEndpointLoads() throws Exception {
    performOk("/api/instructor/qna-inbox?status=UNANSWERED");
  }

  @Test
  void revenueEndpointLoads() throws Exception {
    performOk("/api/instructor/revenues");
  }

  @Test
  void mentoringBoardEndpointLoads() throws Exception {
    performOk("/api/instructor/mentoring/board");
  }

  private void performOk(String path) throws Exception {
    mockMvc
        .perform(get(path).with(authentication(instructorAuthentication())))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.success").value(true));
  }

  private UsernamePasswordAuthenticationToken instructorAuthentication() {
    return new UsernamePasswordAuthenticationToken(
        instructorId, null, AuthorityUtils.createAuthorityList("ROLE_INSTRUCTOR"));
  }
}
