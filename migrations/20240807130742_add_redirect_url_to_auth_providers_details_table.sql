-- +goose Up
-- +goose StatementBegin
ALTER TABLE auth_providers_details ADD COLUMN redirect_url TEXT;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE auth_providers_details DROP COLUMN redirect_url;
-- +goose StatementEnd
