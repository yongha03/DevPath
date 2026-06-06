package com.devpath.config;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.FileCopyUtils;

@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@org.springframework.context.annotation.Profile({"local", "dev"})
@RequiredArgsConstructor
public class LocalLegacySeedInitializer implements CommandLineRunner {

  private static final ClassPathResource LEGACY_SEED =
      new ClassPathResource("db/legacy/seed-data.sql");

  // 시드 INSERT가 is_deleted(NOT NULL) 값을 생략하는 경우가 있어, 시드 실행 전에 모든 is_deleted 컬럼에
  // DEFAULT false 를 보장한다(엔티티별 columnDefinition 누락 보완, 멱등). local/dev(PostgreSQL) 전용.
  private static final String ENSURE_BOOLEAN_FLAG_DEFAULTS_SQL =
      """
      DO $$
      DECLARE r record;
      BEGIN
        FOR r IN
          SELECT table_name FROM information_schema.columns
          WHERE table_schema = 'public' AND column_name = 'is_deleted'
        LOOP
          EXECUTE format('ALTER TABLE public.%I ALTER COLUMN is_deleted SET DEFAULT false', r.table_name);
        END LOOP;
      END $$;
      """;

  private final JdbcTemplate jdbcTemplate;

  @Override
  @Transactional
  public void run(String... args) {
    if (!isLegacyDatasetMissing()) {
      log.debug("Legacy local seed data is already present. Skipping restore.");
      return;
    }

    log.info("Legacy local seed data is missing. Restoring db/legacy/seed-data.sql.");
    jdbcTemplate.execute(ENSURE_BOOLEAN_FLAG_DEFAULTS_SQL);
    jdbcTemplate.execute(readLegacySeedSql());
    log.info("Legacy local seed data restore completed.");
  }

  private boolean isLegacyDatasetMissing() {
    return countRows("users") == 0
        || countRows("courses") == 0
        || countRows("roadmaps") == 0
        || countRows("course_enrollments") == 0
        || countRows("qna_questions") == 0;
  }

  private long countRows(String tableName) {
    if (!tableExists(tableName)) {
      return 0;
    }

    Long count = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM " + tableName, Long.class);
    return count == null ? 0 : count;
  }

  private boolean tableExists(String tableName) {
    try {
      Integer count =
          jdbcTemplate.queryForObject(
              """
              SELECT COUNT(*)
              FROM information_schema.tables
              WHERE table_schema = 'public'
                AND table_name = ?
              """,
              Integer.class,
              tableName);
      return count != null && count > 0;
    } catch (DataAccessException ex) {
      return false;
    }
  }

  private String readLegacySeedSql() {
    try (InputStreamReader reader =
        new InputStreamReader(LEGACY_SEED.getInputStream(), StandardCharsets.UTF_8)) {
      return FileCopyUtils.copyToString(reader);
    } catch (IOException ex) {
      throw new IllegalStateException("Failed to read db/legacy/seed-data.sql", ex);
    }
  }
}
