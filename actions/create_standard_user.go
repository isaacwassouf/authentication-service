package actions

import (
	"database/sql"

	sq "github.com/Masterminds/squirrel"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/isaacwassouf/authentication-service/protobufs/users_management_service"
)

func ValidateStandardUser(in *pb.RegisterRequest, db *sql.DB) error {
	var count int
	err := sq.Select("COUNT(*)").
		From("users").
		InnerJoin("users_email ON users.id = users_email.user_id").
		InnerJoin("users_password ON users.id = users_password.user_id").
		Where(sq.Eq{"email": in.Email}).
		RunWith(db).
		QueryRow().
		Scan(&count)
	if err != nil {
		return status.Error(codes.Internal, "failed to query the database")
	}
	if count != 0 {
		return status.Error(codes.AlreadyExists, "email already registered")
	}

	return nil
}

func CreateStandardUser(in *pb.RegisterRequest, hashedPassword string, db *sql.DB) (int, error) {
	tx, err := db.Begin()
	if err != nil {
		status.Error(codes.Internal, "failed to start transaction")
	}

	// insert the user in the users table
	result, err := sq.Insert("users").
		Columns("name", "is_admin").
		Values(in.Name, false).
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
		Columns("user_id", "email").
		Values(id, in.Email).
		RunWith(tx).
		Exec()
	if err != nil {
		return -1, status.Error(codes.Internal, "failed to insert user in the database")
	}

	// insert the user in the users_password table
	_, err = sq.Insert("users_password").
		Columns("user_id", "password").
		Values(id, hashedPassword).
		RunWith(tx).
		Exec()
	if err != nil {
		return -1, status.Error(codes.Internal, "failed to insert user in the database")
	}

	err = tx.Commit()
	if err != nil {
		return -1, status.Error(codes.Internal, "failed to commit transaction")
	}

	return int(id), nil
}
