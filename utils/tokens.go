package utils

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/matoous/go-nanoid/v2"

	"github.com/isaacwassouf/authentication-service/models"
)

type UserPayload struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
	Provider string `json:"provider"`
	IsAdmin  bool   `json:"is_admin"`
}

type AdminPayload struct {
	ID      int    `json:"id"`
	Email   string `json:"email"`
	IsAdmin bool   `json:"is_admin"`
}

// AuthCustomClaims Claims struct
type AuthCustomClaims struct {
	User UserPayload `json:"user"`
	jwt.RegisteredClaims
}

type AdminCustomClaims struct {
	User AdminPayload `json:"user"`
	jwt.RegisteredClaims
}

// GenerateToken Function to generate a JWT token
func GenerateToken(user models.User) (string, error) {
	// generate a random id
	id, err := gonanoid.New()
	if err != nil {
		return "", err
	}

	// Get the JWT secret key from the environment
	jwtSecret := os.Getenv("JWT_SECRET")
	userPayload := UserPayload{
		ID:       user.ID,
		Name:     user.Name,
		Email:    user.Email,
		Verified: user.Verified,
		IsAdmin:  false,
	}
	if user.Provider != "" {
		userPayload.Provider = user.Provider
	}
	// Create the claims for the JWT token
	claims := AuthCustomClaims{
		User: userPayload,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 72)),
			ID:        id,
		},
	}
	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

func GenerateAdminToken(admin models.Admin) (string, error) {
	// Get the JWT secret key from the environment
	jwtSecret := os.Getenv("JWT_SECRET")
	// Create the claims for the JWT token
	claims := AdminCustomClaims{
		User: AdminPayload{
			ID:      admin.ID,
			Email:   admin.Email,
			IsAdmin: true,
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
