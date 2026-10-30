-- +goose Up

-- What a VEX needs to point into the uploaded SBOM with BOM-Links
-- (urn:cdx:<serial>/<version>#<bom-ref>): each component's bom-ref and the
-- SBOM's version. The serial is source_projects.last_bom_serial.
ALTER TABLE sbom_components ADD COLUMN bom_ref TEXT NOT NULL DEFAULT '';
ALTER TABLE source_projects ADD COLUMN last_bom_version INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE source_projects DROP COLUMN last_bom_version;
ALTER TABLE sbom_components DROP COLUMN bom_ref;
