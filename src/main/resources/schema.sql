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
