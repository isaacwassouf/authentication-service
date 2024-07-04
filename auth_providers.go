package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/matoous/go-nanoid/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/isaacwassouf/authentication-service/actions"
	"github.com/isaacwassouf/authentication-service/consts"
	pb "github.com/isaacwassouf/authentication-service/protobufs/users_management_service"
	"github.com/isaacwassouf/authentication-service/utils"
)

func (s *UserManagementService) ListAuthProviders(ctx context.Context, in *emptypb.Empty) (*pb.ListAuthProvidersResponse, error) {
	// get the list of auth providers
	rows, err := sq.Select(
		"auth_providers.id",
		"auth_providers.name",
		"auth_providers_details.client_id",
		"auth_providers_details.active",
	).
		From("auth_providers").
		Join("auth_providers_details ON auth_providers.id = auth_providers_details.auth_provider_id").
		RunWith(s.userManagementServiceDB.db).
		Query()
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to query the database")
	}

	var authProviders []*pb.AuthProvider
	for rows.Next() {
		var id uint64
		var name string
		var clientId sql.NullString
		var active bool
		err := rows.Scan(&id, &name, &clientId, &active)
		if err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}

		authProvider := pb.AuthProvider{
			Id:       id,
			Name:     name,
			ClientId: clientId.String,
			Active:   active,
		}

		authProviders = append(authProviders, &authProvider)
	}

	return &pb.ListAuthProvidersResponse{AuthProviders: authProviders}, nil
}

// SetAuthProviderCredentials sets the client_id and client_secret for an external auth provider
func (s *UserManagementService) SetAuthProviderCredentials(
	ctx context.Context,
	in *pb.SetAuthProviderCredentialsRequest,
) (*pb.SetAuthProviderCredentialsResponse, error) {
	// check if the provider exists
	var count int
	err := sq.Select("COUNT(*)").
		From("auth_providers").
		Where(sq.Eq{"id": in.AuthProviderId}).
		RunWith(s.userManagementServiceDB.db).
		QueryRow().
		Scan(&count)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed query the database")
	}

	if count == 0 {
		return nil, status.Error(codes.NotFound, "Auth provider not found")
	}

	// set the credentials i.e., client_id and client_secret
	_, err = sq.Update("auth_providers_details").
		Where(sq.Eq{"auth_provider_id": in.AuthProviderId}).
		Set("client_id", in.ClientId).
		Set("client_secret", in.ClientSecret).
		Set("updated_at", time.Now()).
		RunWith(s.userManagementServiceDB.db).
		Exec()
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to set the credentials")
	}

	return &pb.SetAuthProviderCredentialsResponse{Message: "Credentials set successfully"}, nil
}

// EnableAuthProvider enables an external auth provider
func (s *UserManagementService) EnableAuthProvider(
	ctx context.Context,
	in *pb.EnableAuthProviderRequest,
) (*pb.EnableAuthProviderResponse, error) {
	// check if the provider exists
	var count int
	err := sq.Select("COUNT(*)").
		From("auth_providers").
		Where(sq.Eq{"id": in.AuthProviderId}).
		RunWith(s.userManagementServiceDB.db).
		QueryRow().
		Scan(&count)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed query the database")
	}

	if count == 0 {
		return nil, status.Error(codes.NotFound, "Auth provider not found")
	}

	// set the active field to true in the auth_providers_details table
	_, err = sq.Update("auth_providers_details").
		Where(sq.Eq{"auth_provider_id": in.AuthProviderId}).
		Set("active", true).
		Set("updated_at", time.Now()).
		RunWith(s.userManagementServiceDB.db).
		Exec()
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to enable the auth provider")
	}

	return &pb.EnableAuthProviderResponse{Message: "Auth provider enabled successfully"}, nil
}

// DisableAuthProvider disables an external auth provider
func (s *UserManagementService) DisableAuthProvider(
	ctx context.Context,
	in *pb.DisableAuthProviderRequest,
) (*pb.DisableAuthProviderResponse, error) {
	// check if the provider exists
	var count int
	err := sq.Select("COUNT(*)").
		From("auth_providers").
		Where(sq.Eq{"id": in.AuthProviderId}).
		RunWith(s.userManagementServiceDB.db).
		QueryRow().
		Scan(&count)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed query the database")
	}

	if count == 0 {
		return nil, status.Error(codes.NotFound, "Auth provider not found")
	}

	// set the active field to true in the auth_providers_details table
	_, err = sq.Update("auth_providers_details").
		Where(sq.Eq{"auth_provider_id": in.AuthProviderId}).
		Set("active", false).
		Set("updated_at", time.Now()).
		RunWith(s.userManagementServiceDB.db).
		Exec()
	if err != nil {
		fmt.Println(err)
		return nil, status.Error(codes.Internal, "Failed to enable the auth provider")
	}

	return &pb.DisableAuthProviderResponse{Message: "Auth provider disabled successfully"}, nil
}

func (s *UserManagementService) GetGoogleAuthorizationUrl(
	ctx context.Context,
	in *emptypb.Empty,
) (*pb.GoogleAuthorizationUrlResponse, error) {
	// set the base url for the google authorization url
	baseURL, err := url.ParseRequestURI("https://accounts.google.com/o/oauth2/v2/auth")
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to parse the base url")
	}

	var clientId string
	var active bool
	// get the client_id and active fields from the auth_providers_details table
	query := sq.Select("auth_providers_details.client_id", "auth_providers_details.active").
		From("auth_providers").
		Join("auth_providers_details ON auth_providers.id = auth_providers_details.auth_provider_id").
		Where(sq.Eq{"auth_providers.name": consts.GOOGLE})

	err = query.RunWith(s.userManagementServiceDB.db).QueryRow().Scan(&clientId, &active)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "Auth provider not found")
		}
		return nil, status.Error(codes.Internal, "Failed to query the database")
	}

	// check if the auth provider is active
	if !active {
		return nil, status.Error(codes.PermissionDenied, "Auth provider is not active")
	}

	params := url.Values{}
	params.Add("client_id", clientId)
	params.Add("response_type", "code")
	params.Add("scope", "openid email profile")

	// generate a random state
	state, err := gonanoid.New()
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to generate a random state")
	}
	params.Add("state", state)

	// get the redirect_uri from the environment variables
	redirectURI := os.Getenv("API_GATEWAY_GOOGLE_AUTHORIZATION_URL")
	// if the redirect_uri is not set, use the default value
	if redirectURI == "" {
		redirectURI = "http://localhost:5173/api/auth/google/callback"
	}
	params.Add("redirect_uri", redirectURI)

	baseURL.RawQuery = params.Encode()

	return &pb.GoogleAuthorizationUrlResponse{Url: baseURL.String(), State: state}, nil
}

func (s *UserManagementService) HandleGoogleLogin(
	ctx context.Context,
	in *pb.GoogleLoginRequest,
) (*pb.GoogleLoginResponse, error) {
	// check if Google is enabled
	active, err := utils.CheckAuthProviderIsActive(consts.GOOGLE, s.userManagementServiceDB.db)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to check if Google is enabled")
	}
	if !active {
		return nil, status.Error(codes.PermissionDenied, "Google is not enabled")
	}

	// get the external auth user by email
	user, err := utils.GetExternalAuthUserByEmail(consts.GOOGLE, in.Email, s.userManagementServiceDB.db)
	if err != nil {
		// the user does not exist, create a new user
		if errors.Is(err, sql.ErrNoRows) {
			id, err := actions.CreateGoogleUser(in, s.userManagementServiceDB.db)
			if err != nil {
				return nil, err
			}
			// get the user from the database from its id
			user, err = utils.GetExternalAuthUserByID(consts.GOOGLE, id, s.userManagementServiceDB.db)
			if err != nil {
				return nil, status.Error(codes.Internal, "Failed to get the user")
			}

			// generate a JWT token
			token, err := utils.GenerateToken(user)
			if err != nil {
				return nil, status.Error(codes.Internal, "Failed to generate token")
			}

			return &pb.GoogleLoginResponse{Message: "Logged in successfully", Token: token}, nil
		}
		return nil, status.Error(codes.Internal, "Failed to get the user")
	}

	// generate a JWT token
	token, err := utils.GenerateToken(user)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to generate token")
	}

	return &pb.GoogleLoginResponse{Message: "Logged in successfully", Token: token}, nil
}
