package main

import (
	"context"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb_email "github.com/isaacwassouf/authentication-service/protobufs/email_management_service"
	pb "github.com/isaacwassouf/authentication-service/protobufs/users_management_service"
)

type UserManagementService struct {
	pb.UnimplementedUserManagerServer
	userManagementServiceDB *UserManagementServiceDB
	emailServiceClient      *pb_email.EmailManagerClient
}

// RegisterUser registers a user
func (s *UserManagementService) RegisterUser(
	ctx context.Context,
	in *pb.RegisterRequest,
) (*pb.RegisterResponse, error) {
	// check if the email is already registered
	var count int
	err := sq.Select("COUNT(*)").
		From("users").
		Where(sq.Eq{"email": in.Email}).
		RunWith(s.userManagementServiceDB.db).
		QueryRow().
		Scan(&count)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to query the database")
	}
	if count > 0 {
		return nil, status.Error(codes.InvalidArgument, "email already registered")
	}

	// hash the password
	hashedPassword, err := HashPassword(in.Password)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to hash the password")
	}

	// insert the user into the database
	_, err = sq.Insert("users").
		Columns("name", "email", "password").
		Values(in.Name, in.Email, hashedPassword).
		RunWith(s.userManagementServiceDB.db).
		Exec()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to insert user into the database")
	}

	// create the email verification Token
	token, err := GenerateEmailVerificationToken(User{Email: in.Email})
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate email verification token")
	}

	// send the email verification token to the user
	_, err = (*s.emailServiceClient).SendEmail(context.Background(), &pb_email.EmailRequest{
		To:      in.Email,
		Subject: "Email Verification",
		Body:    "Please verify your email by clicking the following link: http://localhost:50051/verify_email?token=" + token,
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to send email verification token")
	}

	return &pb.RegisterResponse{Message: "successfully registerd user"}, nil
}

// LoginUser logs in a user
func (s *UserManagementService) LoginUser(
	ctx context.Context,
	in *pb.LoginRequest,
) (*pb.LoginResponse, error) {
	// get the user from the database
	var user User
	err := sq.Select("*").
		From("users").
		Where(sq.Eq{"email": in.Email}).
		RunWith(s.userManagementServiceDB.db).
		QueryRow().
		Scan(&user.ID, &user.Name, &user.Email, &user.Password, &user.Verified, &user.CreatedAt, &user.UpdatedAt)
		// if the user does not exist return an error
	if err != nil {
		return nil, status.Error(codes.NotFound, "user not found")
	}

	// check if the password is correct
	if !CheckPasswordHash(in.Password, user.Password) {
		return nil, status.Error(codes.InvalidArgument, "incorrect password")
	}

	// generate a JWT token
	token, err := GenerateToken(user)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate token")
	}

	return &pb.LoginResponse{Message: "Logged in successfully", Token: token}, nil
}

// VerifyUser verifies a user by Email
func (s *UserManagementService) VerifyEmail(
	ctx context.Context,
	in *pb.VerifyEmailRequest,
) (*pb.VerifyEmailResponse, error) {
	// verify the token
	email, err := VerifyEmailToken(in.Token)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid token")
	}

	// update the user in the database
	_, err = sq.Update("users").
		Where(sq.Eq{"email": email}).
		Set("verified", true).
		RunWith(s.userManagementServiceDB.db).
		Exec()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to update user in the database")
	}

	return &pb.VerifyEmailResponse{Message: "User verified successfully"}, nil
}

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
