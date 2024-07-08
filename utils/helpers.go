package utils

import (
	"database/sql"

	sq "github.com/Masterminds/squirrel"

	"github.com/isaacwassouf/authentication-service/models"
)

// CheckAuthProviderIsActive checks if an auth provider is active
func CheckAuthProviderIsActive(provider string, db *sql.DB) (bool, error) {
	var active bool
	query := sq.Select("auth_providers_details.active").
		From("auth_providers").
		Join("auth_providers_details ON auth_providers.id = auth_providers_details.auth_provider_id").
		Where(sq.Eq{"auth_providers.name": provider})

	err := query.RunWith(db).QueryRow().Scan(&active)
	if err != nil {
		return false, err
	}
	return active, nil
}

// GetExternalAuthUserByEmail ets a user by their external auth provider ID
func GetExternalAuthUserByEmail(provider string, email string, db *sql.DB) (models.User, error) {
	var user models.User
	query := sq.Select("users.id", "users.name", "users_email.email", "users_email.is_verified", "auth_providers.name").
		From("users").
		Join("users_email ON users.id = users_email.user_id").
		Join("users_authentication ON users.id = users_authentication.user_id").
		Join("auth_providers ON users_authentication.auth_provider_id = auth_providers.id").
		Where(sq.Eq{"auth_providers.name": provider}).
		Where(sq.Eq{"users_email.email": email})

	err := query.RunWith(db).QueryRow().Scan(&user.ID, &user.Name, &user.Email, &user.Verified, &user.Provider)
	if err != nil {
		return user, err
	}
	return user, nil
}

// GetExternalAuthUserByID ets a user by their external auth provider ID
func GetExternalAuthUserByID(provider string, id int, db *sql.DB) (models.User, error) {
	var user models.User
	query := sq.Select("users.id", "users.name", "users_email.email", "users_email.is_verified", "auth_providers.name").
		From("users").
		Join("users_email ON users.id = users_email.user_id").
		Join("users_authentication ON users.id = users_authentication.user_id").
		Join("auth_providers ON users_authentication.auth_provider_id = auth_providers.id").
		Where(sq.Eq{"auth_providers.name": provider}).
		Where(sq.Eq{"users.id": id})

	err := query.RunWith(db).QueryRow().Scan(&user.ID, &user.Name, &user.Email, &user.Verified, &user.Provider)
	if err != nil {
		return user, err
	}
	return user, nil
}

func GetAuthProviderClientID(provider string, db *sql.DB) (sql.NullString, error) {
	var clientID sql.NullString
	query := sq.Select("auth_providers_details.client_id").
		From("auth_providers").
		Join("auth_providers_details ON auth_providers.id = auth_providers_details.auth_provider_id").
		Where(sq.Eq{"auth_providers.name": provider})

	err := query.RunWith(db).QueryRow().Scan(&clientID)
	if err != nil {
		return sql.NullString{}, err
	}
	return clientID, nil
}
