-- +goose Up

-- The analysis decision behind a closed finding, in CycloneDX VEX terms:
-- state (exploitable, not_affected, false_positive), justification for
-- not_affected, response (will_not_fix for an accepted risk), the reason,
-- and who approved it when.
ALTER TABLE findings ADD COLUMN analysis_state         TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN analysis_justification TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN analysis_response      TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN analysis_detail        TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN analysis_by            TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN analysis_at            TEXT;

-- Not-affected requests carry a justification.
ALTER TABLE exception_requests ADD COLUMN justification TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE exception_requests DROP COLUMN justification;
ALTER TABLE findings DROP COLUMN analysis_at;
ALTER TABLE findings DROP COLUMN analysis_by;
ALTER TABLE findings DROP COLUMN analysis_detail;
ALTER TABLE findings DROP COLUMN analysis_response;
ALTER TABLE findings DROP COLUMN analysis_justification;
ALTER TABLE findings DROP COLUMN analysis_state;
