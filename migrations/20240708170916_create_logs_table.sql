-- +goose Up
-- +goose StatementBegin
CREATE TABLE logs (
  id SERIAL PRIMARY KEY,
  service VARCHAR(255) NOT NULL,
  level VARCHAR(50) NOT NULL,
  message TEXT,
  metadata JSON,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS logs;
-- +goose StatementEnd
