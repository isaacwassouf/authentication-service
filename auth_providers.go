package main

import (
	"context"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
