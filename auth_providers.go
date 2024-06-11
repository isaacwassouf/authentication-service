package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/matoous/go-nanoid/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/isaacwassouf/authentication-service/protobufs/users_management_service"
)

// Set the auth provider credentials
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

// Set the auth provider credentials
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

	return &pb.DisableAuthProviderResponse{Message: "Auth provider enabled successfully"}, nil
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
		Where(sq.Eq{"auth_providers.name": "google"})

	err = query.RunWith(s.userManagementServiceDB.db).QueryRow().Scan(&clientId, &active)
	if err != nil {
		if err == sql.ErrNoRows {
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
	redirect_uri := os.Getenv("API_GATEWAY_GOOGLE_AUTHORIZATION_URL")
	// if the redirect_uri is not set, use the default value
	if redirect_uri == "" {
		redirect_uri = "http://localhost:5173/api/auth/google/callback"
	}
	params.Add("redirect_uri", redirect_uri)

	baseURL.RawQuery = params.Encode()

	return &pb.GoogleAuthorizationUrlResponse{Url: baseURL.String(), State: state}, nil
}
