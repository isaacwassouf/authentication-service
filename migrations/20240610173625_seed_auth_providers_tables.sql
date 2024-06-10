-- +goose Up
-- +goose StatementBegin
INSERT INTO auth_providers (name) VALUES ('google');
INSERT INTO auth_providers_details (auth_provider_id) VALUES ((SELECT id FROM auth_providers WHERE name = 'google'));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM auth_providers WHERE name = 'google';
-- +goose StatementEnd
