package main

import (
	"log"
	"net"

	"github.com/pressly/goose"
	"google.golang.org/grpc"

	"github.com/isaacwassouf/authentication-service/database"
	"github.com/isaacwassouf/authentication-service/modules"
	pb "github.com/isaacwassouf/authentication-service/protobufs/users_management_service"
	"github.com/isaacwassouf/authentication-service/utils"
)

func main() {
	// load the environment variables from the .env file
	err := utils.LoadEnvVarsFromFile()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	cryptographyServiceClient, err := utils.NewCryptographyServiceClient()
	if err != nil {
		log.Fatalf("failed to start the cryptography service client: %v", err)
	}

	// start the email service client
	emailServiceClient, err := utils.NewEmailServiceClient()
	if err != nil {
		log.Fatalf("failed to start the email service client: %v", err)
	}

	// create database connection
	db, err := database.NewUserManagementServiceDB()
	if err != nil {
		log.Fatalf("failed to connect to the database: %v", err)
	}
	defer db.DB.Close()
	// ping the database to check the connection
	if err := db.DB.Ping(); err != nil {
		log.Fatalf("failed to ping the database: %v", err)
	}

	// // preapre the db connection for the migrations
	databaseURL := database.GetDatabaseURL()
	gooseDB, err := goose.OpenDBWithDriver("mysql", databaseURL)
	if err != nil {
		log.Fatalf("failed to open the database connection for the migrations: %v", err)
	}

	// run the migrations
	if err := goose.Up(gooseDB, "migrations"); err != nil {
		log.Fatalf("failed to run the migrations: %v", err)
	}
	//
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
		&modules.UserManagementService{
			UserManagementServiceDB:   db,
			EmailServiceClient:        &emailServiceClient,
			CryptographyServiceClient: &cryptographyServiceClient,
		},
	)
	log.Printf("Server listening at %v", lis.Addr())

	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
