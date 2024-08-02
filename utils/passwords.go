package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

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
	hash := sha256.New()
	_, err := hash.Write([]byte(code))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func IsExpired(createdAt time.Time) bool {
	return time.Since(createdAt) > time.Hour*24
}
