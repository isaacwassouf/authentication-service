package utils

import (
	"github.com/matoous/go-nanoid/v2"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func GeneratePasswordResetCode() (string, error) {
	return gonanoid.New()
}

func HashPasswordResetCode(code string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	return string(bytes), err
}
