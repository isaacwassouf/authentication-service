package main

import (
	"log"
	"net"

	"github.com/joho/godotenv"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pbEmail "github.com/isaacwassouf/authentication-service/protobufs/email_management_service"
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

// start the gRPC email service client
func newEmailServiceClient() (pbEmail.EmailManagerClient, error) {
	// Create a connection to the email service
	conn, err := grpc.Dial(
		"localhost:8080",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}
	return pbEmail.NewEmailManagerClient(conn), nil
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

	// create database connection
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
