-- +goose Up
-- +goose StatementBegin
INSERT INTO settings (name, value) VALUES ('mfa', 'disabled');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM settings WHERE name = 'mfa';
-- +goose StatementEnd
