package modules

import (
	"context"
	"database/sql"
	"errors"

	sq "github.com/Masterminds/squirrel"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/isaacwassouf/authentication-service/models"
	pb "github.com/isaacwassouf/authentication-service/protobufs/users_management_service"
	"github.com/isaacwassouf/authentication-service/utils"
)

func (s *UserManagementService) RegisterAdmin(ctx context.Context, in *pb.RegisterAdminRequest) (*pb.RegisterAdminResponse, error) {
	var count int
	err := sq.Select("count(*)").
		From("admins").
		Where(sq.Eq{"email": in.Email}).
		RunWith(s.UserManagementServiceDB.DB).
		QueryRow().
		Scan(&count)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to query the database")
	}

	if count > 0 {
		return nil, status.Error(codes.AlreadyExists, "admin already exists")
	}

	hashedPassword, err := utils.HashPassword(in.Password)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to hash the password")
	}

	_, err = sq.Insert("admins").
		Columns("email", "password").
		Values(in.Email, hashedPassword).
		RunWith(s.UserManagementServiceDB.DB).
		Exec()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to insert admin in the database")
	}

	return &pb.RegisterAdminResponse{Message: "successfully registered admin"}, nil
}

func (s *UserManagementService) LoginAdmin(ctx context.Context, in *pb.LoginRequest) (*pb.LoginResponse, error) {
	var admin models.Admin
	err := sq.Select("id", "email", "password").
		From("admins").
		Where(sq.Eq{"email": in.Email}).
		RunWith(s.UserManagementServiceDB.DB).
		QueryRow().
		Scan(&admin.ID, &admin.Email, &admin.Password)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "admin not found")
		}
		return nil, status.Error(codes.Internal, "failed to query the database")
	}

	if !utils.CheckPasswordHash(in.Password, admin.Password) {
		return nil, status.Error(codes.InvalidArgument, "incorrect password")
	}

	token, err := utils.GenerateAdminToken(admin)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate token")
	}

	return &pb.LoginResponse{Message: "Logged in successfully", Token: token}, nil
}
