package main

import (
	"context"
	"log"
	"net"

	sq "github.com/Masterminds/squirrel"
	"github.com/joho/godotenv"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	pb_email "github.com/isaacwassouf/authentication-service/protobufs/email_management_service"
	pb "github.com/isaacwassouf/authentication-service/protobufs/users_management_service"
)

type User struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	Verified  bool   `json:"verified"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

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

// start the gRPC email service client
func newEmailServiceClient() (pb_email.EmailManagerClient, error) {
	// Create a connection to the email service
	conn, err := grpc.Dial(
		"localhost:8080",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}
	return pb_email.NewEmailManagerClient(conn), nil
}

func main() {
	// start the email service client
	emailServiceClient, err := newEmailServiceClient()
	if err != nil {
		log.Fatalf("failed to start the email service client: %v", err)
	}

	// load the environment variables from the .env file
	err = godotenv.Load()
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
	pb.RegisterUserManagerServer(
		s,
		&UserManagementService{
			userManagementServiceDB: db,
			emailServiceClient:      &emailServiceClient,
		},
	)
	log.Printf("Server listening at %v", lis.Addr())

	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
