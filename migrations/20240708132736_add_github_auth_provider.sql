-- +goose Up
-- +goose StatementBegin
INSERT INTO auth_providers (name) VALUES ('github');
INSERT INTO auth_providers_details (auth_provider_id) VALUES ((SELECT id FROM auth_providers WHERE name = 'github'));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM auth_providers WHERE name = 'github';
DELETE FROM auth_providers_details WHERE auth_provider_id = (SELECT id FROM auth_providers WHERE name = 'github');
-- +goose StatementEnd
