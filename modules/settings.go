package modules

import (
	"context"

	sq "github.com/Masterminds/squirrel"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/isaacwassouf/authentication-service/consts"
	pb "github.com/isaacwassouf/authentication-service/protobufs/users_management_service"
)

func (s *UserManagementService) GetMFA(ctx context.Context, in *emptypb.Empty) (*pb.GetMFAResponse, error) {
	var mfaStatus string
	err := sq.Select("value").
		From("settings").
		Where(sq.Eq{"name": "mfa"}).
		RunWith(s.UserManagementServiceDB.DB).
		QueryRow().
		Scan(&mfaStatus)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to get MFA status")
	}

	if mfaStatus == "" {
		mfaStatus = consts.DISABLED
	}

	if mfaStatus == consts.ENABLED {
		return &pb.GetMFAResponse{Enabled: true}, nil
	} else {
		return &pb.GetMFAResponse{Enabled: false}, nil
	}
}

func (s *UserManagementService) ToggleMFA(ctx context.Context, in *emptypb.Empty) (*emptypb.Empty, error) {
	// get MFA status
	var mfaStatus string
	err := sq.Select("value").
		From("settings").
		Where(sq.Eq{"name": "mfa"}).
		RunWith(s.UserManagementServiceDB.DB).
		QueryRow().
		Scan(&mfaStatus)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to get MFA status")
	}

	// toggle MFA status
	if mfaStatus == consts.ENABLED {
		_, err = sq.Update("settings").
			Set("value", consts.DISABLED).
			Where(sq.Eq{"name": "mfa"}).
			RunWith(s.UserManagementServiceDB.DB).
			Exec()
		if err != nil {
			return nil, status.Error(codes.Internal, "failed to disable MFA")
		}
	} else {
		_, err = sq.Update("settings").
			Set("value", consts.ENABLED).
			Where(sq.Eq{"name": "mfa"}).
			RunWith(s.UserManagementServiceDB.DB).
			Exec()
		if err != nil {
			return nil, status.Error(codes.Internal, "failed to enable MFA")
		}
	}

	return &emptypb.Empty{}, nil
}
