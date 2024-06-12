package main

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type UserPayload struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
}

// AuthCustomClaims Claims struct
type AuthCustomClaims struct {
	User UserPayload `json:"user"`
	jwt.RegisteredClaims
}

type VerifyEmailCustomClaims struct {
	ID int `json:"id"`
	jwt.RegisteredClaims
}

// GenerateToken Function to generate a JWT token
func GenerateToken(user User) (string, error) {
	// Get the JWT secret key from the environment
	jwtSecret := os.Getenv("JWT_SECRET")
	// Create the claims for the JWT token
	claims := AuthCustomClaims{
		User: UserPayload{
			ID:       user.ID,
			Name:     user.Name,
			Email:    user.Email,
			Verified: user.Verified,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 72)),
		},
	}
	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

func GenerateEmailVerificationToken(user User) (string, error) {
	// Get the JWT secret key from the environment
	jwtSecret := os.Getenv("JWT_SECRET")
	// Create the claims for the JWT token
	claims := VerifyEmailCustomClaims{
		ID: user.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 72)),
		},
	}
	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

// VerifyEmailToken Verify the email JWT token
func VerifyEmailToken(tokenString string) (int, error) {
	// Get the JWT secret key from the environment
	jwtSecret := os.Getenv("JWT_SECRET")
	// Parse the token
	token, err := jwt.ParseWithClaims(
		tokenString,
		&VerifyEmailCustomClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtSecret), nil
		},
	)
	if err != nil {
		return -1, err
	}
	claims, ok := token.Claims.(*VerifyEmailCustomClaims)
	if !ok || !token.Valid {
		return -1, err
	}
	return claims.ID, nil
}
