-- +goose Up
-- +goose StatementBegin
CREATE TABLE auth_providers_details (
  id SERIAL,
  auth_provider_id BIGINT UNSIGNED NOT NULL,
  client_id VARCHAR(255),
  client_secret VARCHAR(255),
  active BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (auth_provider_id),
  PRIMARY KEY (id),
  FOREIGN KEY (auth_provider_id) REFERENCES auth_providers (id) ON DELETE CASCADE
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS auth_providers_details CASCADE;
-- +goose StatementEnd
