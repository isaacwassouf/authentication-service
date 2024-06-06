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

// Claims struct
type AuthCustomClaims struct {
	User UserPayload `json:"user"`
	jwt.RegisteredClaims
}

type EmailCustomClaims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

// Function to generate a JWT token
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
	claims := EmailCustomClaims{
		Email: user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 72)),
		},
	}
	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

// Verify the email JWT token
func VerifyEmailToken(tokenString string) (string, error) {
	// Get the JWT secret key from the environment
	jwtSecret := os.Getenv("JWT_SECRET")
	// Parse the token
	token, err := jwt.ParseWithClaims(
		tokenString,
		&EmailCustomClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtSecret), nil
		},
	)
	if err != nil {
		return "", err
	}
	claims, ok := token.Claims.(*EmailCustomClaims)
	if !ok || !token.Valid {
		return "", err
	}
	return claims.Email, nil
}
