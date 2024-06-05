package main

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type UserPayload struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// Claims struct
type CustomClaims struct {
	User UserPayload `json:"user"`
	jwt.RegisteredClaims
}

// Function to generate a JWT token
func GenerateToken(user User) (string, error) {
	// Get the JWT secret key from the environment
	jwtSecret := os.Getenv("JWT_SECRET")
	// Create the claims for the JWT token
	claims := CustomClaims{
		User: UserPayload{
			ID:    user.ID,
			Name:  user.Name,
			Email: user.Email,
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
