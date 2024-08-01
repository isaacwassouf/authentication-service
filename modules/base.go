package modules

import (
	"github.com/isaacwassouf/authentication-service/database"
	pbEmail "github.com/isaacwassouf/authentication-service/protobufs/email_management_service"
	pb "github.com/isaacwassouf/authentication-service/protobufs/users_management_service"
)

type UserManagementService struct {
	pb.UnimplementedUserManagerServer
	UserManagementServiceDB *database.UserManagementServiceDB
	EmailServiceClient      *pbEmail.EmailManagerClient
}
