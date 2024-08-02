package utils

import (
	"database/sql"
	"os"

	sq "github.com/Masterminds/squirrel"
	"github.com/joho/godotenv"
	"github.com/matoous/go-nanoid/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/isaacwassouf/authentication-service/models"
	pbEmail "github.com/isaacwassouf/authentication-service/protobufs/email_management_service"
)

func GetEnvVar(key string, defaultValue string) string {
	value, found := os.LookupEnv(key)
	if !found {
		return defaultValue
	}
	return value
}

func LoadEnvVarsFromFile() error {
	// get the environment
	environment := GetEnvVar("GO_ENV", "development")
	// load the environment variables from the .env file if the environment is development
	if environment == "development" {
		err := godotenv.Load()
		if err != nil {
			return err
		}
	}
	return nil
}

// get the gRPC email service client
func NewEmailServiceClient() (pbEmail.EmailManagerClient, error) {
	// get host and port from the environment
	host, found := os.LookupEnv("EMAIL_SERVICE_HOST")
	if !found {
		host = "localhost"
	}

	port, found := os.LookupEnv("EMAIL_SERVICE_PORT")
	if !found {
		port = "8080"
	}

	connectionURI := host + ":" + port

	// Create a connection to the email service
	conn, err := grpc.Dial(
		connectionURI,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}
	return pbEmail.NewEmailManagerClient(conn), nil
}

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

func GenerateEmailVerificationCode() (string, error) {
	return gonanoid.New()
}
