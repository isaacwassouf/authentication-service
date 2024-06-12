package actions

import (
	"database/sql"
	sq "github.com/Masterminds/squirrel"
	"github.com/isaacwassouf/authentication-service/consts"
	pb "github.com/isaacwassouf/authentication-service/protobufs/users_management_service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func CreateGoogleUser(in *pb.GoogleLoginRequest, db *sql.DB) (int, error) {
	tx, err := db.Begin()
	if err != nil {
		status.Error(codes.Internal, "failed to start transaction")
	}

	// insert the user in the users table
	result, err := sq.Insert("users").
		Columns("name").
		Values(in.Name).
		RunWith(tx).
		Exec()
	if err != nil {
		return -1, status.Error(codes.Internal, "failed to insert user in the database")
	}

	id, err := result.LastInsertId()
	if err != nil {
		return -1, status.Error(codes.Internal, "failed to get the last inserted id")
	}

	// insert the user in the users_email table
	_, err = sq.Insert("users_email").
		Columns("user_id", "email", "is_verified").
		Values(id, in.Email, true).
		RunWith(tx).
		Exec()
	if err != nil {
		return -1, status.Error(codes.Internal, "failed to insert user in the database")
	}

	// get the auth provider id
	var authProviderID int
	err = sq.Select("id").
		From("auth_providers").
		Where(sq.Eq{"name": consts.GOOGLE}).
		RunWith(tx).
		QueryRow().
		Scan(&authProviderID)
	if err != nil {
		return -1, status.Error(codes.Internal, "failed to get the auth provider id")
	}

	// insert the user in the users_authentication table
	_, err = sq.Insert("users_authentication").
		Columns("user_id", "auth_provider_id", "auth_provider_identifier").
		Values(id, authProviderID, in.Identifier).
		RunWith(tx).
		Exec()
	if err != nil {
		return -1, status.Error(codes.Internal, "failed to insert user in the database")
	}

	// commit the transaction
	err = tx.Commit()
	if err != nil {
		return -1, status.Error(codes.Internal, "failed to commit transaction")
	}

	return int(id), nil
}
