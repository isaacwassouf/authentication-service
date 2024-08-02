package models

import "time"

type EmailVerification struct {
	ID        int       `json:"id"`
	UserID    string    `json:"user_id"`
	Code      string    `json:"code"`
	CreatedAt time.Time `json:"created_at"`
}
