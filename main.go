package main

import (
	"context"
	"fmt"
	"log"
	"net"

	sq "github.com/Masterminds/squirrel"
	"github.com/joho/godotenv"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/isaacwassouf/authentication-service/protobufs"
)

type User struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type UserManagementService struct {
	pb.UnimplementedUserManagerServer
	UserManagementServiceDB *UserManagementServiceDB
}

func (s *UserManagementService) RegisterUser(
	ctx context.Context,
	in *pb.RegisterRequest,
) (*pb.RegisterResponse, error) {
	// check if the email is already registered
	var count int
	err := sq.Select("COUNT(*)").
		From("users").
		Where(sq.Eq{"email": in.Email}).
		RunWith(s.UserManagementServiceDB.db).
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
		RunWith(s.UserManagementServiceDB.db).
		Exec()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to insert user into the database")
	}

	return &pb.RegisterResponse{Message: "Registered user successfully"}, nil
}

func (s *UserManagementService) LoginUser(
	ctx context.Context,
	in *pb.LoginRequest,
) (*pb.LoginResponse, error) {
	// get the user from the database
	var user User
	err := sq.Select("*").
		From("users").
		Where(sq.Eq{"email": in.Email}).
		RunWith(s.UserManagementServiceDB.db).
		QueryRow().
		Scan(&user.ID, &user.Name, &user.Email, &user.Password, &user.CreatedAt, &user.UpdatedAt)
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
		fmt.Println(err)
		return nil, status.Error(codes.Internal, "failed to generate token")
	}

	return &pb.LoginResponse{Message: "Logged in successfully", Token: token}, nil
}

func main() {
	// load the environment variables from the .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	// create database connetion
	db, err := NewUserManagementServiceDB()
	if err != nil {
		log.Fatalf("failed to connect to the database: %v", err)
	}
	defer db.db.Close()
	// ping the database to check the connection
	if err := db.db.Ping(); err != nil {
		log.Fatalf("failed to ping the database: %v", err)
	}

	// Create a listener on TCP port 50051
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	// Create a gRPC server object
	s := grpc.NewServer()
	// Attach the UserManager service to the server
	pb.RegisterUserManagerServer(s, &UserManagementService{UserManagementServiceDB: db})
	log.Printf("Server listening at %v", lis.Addr())

	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
