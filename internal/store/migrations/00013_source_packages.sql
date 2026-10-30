-- +goose Up

-- OS packages are matched by their source package (Debian advisories name
-- "openssl", not "libssl1.1"): name and full version ([epoch:]version[-release]).
ALTER TABLE sbom_components ADD COLUMN src_name    TEXT NOT NULL DEFAULT '';
ALTER TABLE sbom_components ADD COLUMN src_version TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE sbom_components DROP COLUMN src_version;
ALTER TABLE sbom_components DROP COLUMN src_name;
