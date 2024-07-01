package main

import (
	"context"
	"database/sql"
	"errors"

	sq "github.com/Masterminds/squirrel"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/isaacwassouf/authentication-service/actions"
	"github.com/isaacwassouf/authentication-service/models"
	pbEmail "github.com/isaacwassouf/authentication-service/protobufs/email_management_service"
	pb "github.com/isaacwassouf/authentication-service/protobufs/users_management_service"
	"github.com/isaacwassouf/authentication-service/utils"
)

type UserManagementService struct {
	pb.UnimplementedUserManagerServer
	userManagementServiceDB *UserManagementServiceDB
	emailServiceClient      *pbEmail.EmailManagerClient
}

// RegisterUser registers a user
func (s *UserManagementService) RegisterUser(
	ctx context.Context,
	in *pb.RegisterRequest,
) (*pb.RegisterResponse, error) {
	// check if the email is already registered
	err := actions.ValidateStandardUser(in, s.userManagementServiceDB.db)
	if err != nil {
		return nil, err
	}

	// hash the password
	hashedPassword, err := HashPassword(in.Password)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to hash the password")
	}

	// insert the user in the users table and the users_email and users_password table in a transaction
	id, err := actions.CreateStandardUser(in, hashedPassword, s.userManagementServiceDB.db)
	if err != nil {
		return nil, err
	}
	// create the email verification Token
	token, err := utils.GenerateEmailVerificationToken(models.User{ID: id})
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate email verification token")
	}

	// send the email verification token to the user
	_, err = (*s.emailServiceClient).SendEmail(context.Background(), &pbEmail.EmailRequest{
		To:      in.Email,
		Subject: "Email Verification",
		Body:    "Please verify your email by clicking the following link: http://localhost:50051/verify_email?token=" + token,
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to send email verification token")
	}

	return &pb.RegisterResponse{Message: "successfully registered user"}, nil
}

// LoginUser logs in a user
func (s *UserManagementService) LoginUser(
	ctx context.Context,
	in *pb.LoginRequest,
) (*pb.LoginResponse, error) {
	// get the user from the database
	var user models.User
	err := sq.Select("users.id", "users.name", "users_email.email", "users_password.password", "users_email.is_verified").
		From("users").
		InnerJoin("users_email ON users.id = users_email.user_id").
		InnerJoin("users_password ON users.id = users_password.user_id").
		Where(sq.Eq{"email": in.Email}).
		RunWith(s.userManagementServiceDB.db).
		QueryRow().
		Scan(&user.ID, &user.Name, &user.Email, &user.Password, &user.Verified)
		// if the user does not exist return an error
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "failed to query the database")
	}

	// check if the password is correct
	if !CheckPasswordHash(in.Password, user.Password) {
		return nil, status.Error(codes.InvalidArgument, "incorrect password")
	}

	// generate a JWT token
	token, err := utils.GenerateToken(user)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate token")
	}

	return &pb.LoginResponse{Message: "Logged in successfully", Token: token}, nil
}

// VerifyEmail verifies a user by Email
func (s *UserManagementService) VerifyEmail(
	ctx context.Context,
	in *pb.VerifyEmailRequest,
) (*pb.VerifyEmailResponse, error) {
	// verify the token
	id, err := utils.VerifyEmailToken(in.Token)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid token")
	}

	// update the user in the database
	_, err = sq.Update("users_email").
		Where(sq.Eq{"user_id": id}).
		Set("is_verified", true).
		RunWith(s.userManagementServiceDB.db).
		Exec()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to update user in the database")
	}

	return &pb.VerifyEmailResponse{Message: "User verified successfully"}, nil
}
