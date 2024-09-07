package modules

import (
	"context"
	"database/sql"
	"errors"

	sq "github.com/Masterminds/squirrel"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/isaacwassouf/authentication-service/actions"
	"github.com/isaacwassouf/authentication-service/models"
	pbEmail "github.com/isaacwassouf/authentication-service/protobufs/email_management_service"
	pb "github.com/isaacwassouf/authentication-service/protobufs/users_management_service"
	"github.com/isaacwassouf/authentication-service/utils"
)

// RegisterUser registers a user
func (s *UserManagementService) RegisterUser(
	ctx context.Context,
	in *pb.RegisterRequest,
) (*pb.RegisterResponse, error) {
	// check if the email is already registered
	err := actions.ValidateStandardUser(in, s.UserManagementServiceDB.DB)
	if err != nil {
		return nil, err
	}

	// hash the password
	hashedPassword, err := utils.HashPassword(in.Password)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to hash the password")
	}

	// insert the user in the users table and the users_email and users_password table in a transaction
	_, err = actions.CreateStandardUser(in, hashedPassword, s.UserManagementServiceDB.DB)
	if err != nil {
		return nil, err
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
		RunWith(s.UserManagementServiceDB.DB).
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
	if !utils.CheckPasswordHash(in.Password, user.Password) {
		return nil, status.Error(codes.InvalidArgument, "incorrect password")
	}

	MFAStatus, err := utils.GetMFAStatus(s.UserManagementServiceDB.DB)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to get MFA status")
	}

	// if the MFA is not enabled then send the MFA token to the user
	if !MFAStatus {
		// generate a JWT token
		token, err := utils.GenerateToken(user)
		if err != nil {
			return nil, status.Error(codes.Internal, "failed to generate token")
		}

		return &pb.LoginResponse{Message: "Logged in successfully", Token: token}, nil
	}

	// if the MFA is enabled then send the MFA token to the user
	// generate a MFA token
	MFACode, err := utils.GenerateMFACode()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate MFA token")
	}

	// hash the code
	hashedMFACode, err := utils.HashMFACode(MFACode)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to hash MFA token")
	}

	// save the MFA token in the database
	_, err = sq.Insert("mfa_verification").
		Columns("user_id", "code").
		Values(user.ID, hashedMFACode).
		RunWith(s.UserManagementServiceDB.DB).
		Exec()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to save the MFA token")
	}

	// send the MFA token to the user
	_, err = (*s.EmailServiceClient).SendMFAEmail(context.Background(), &pbEmail.SendEmailRequest{To: user.Email, Token: MFACode})
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to send MFA token")
	}

	return &pb.LoginResponse{Message: "MFA token sent successfully"}, nil
}

func (s *UserManagementService) LogoutUser(ctx context.Context, in *pb.LogoutRequest) (*emptypb.Empty, error) {
	_, err := sq.Insert("tokens_blacklist").
		Columns("user_id", "jti").
		Values(in.UserId, in.Jti).
		RunWith(s.UserManagementServiceDB.DB).
		Exec()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &emptypb.Empty{}, nil
}

func (s *UserManagementService) VerifyTokenRevoation(ctx context.Context, in *pb.VerifyTokenRevoationRequest) (*pb.VerifyTokenRevoationResponse, error) {
	var count int
	err := sq.Select("count(*)").
		From("tokens_blacklist").
		Where(sq.Eq{"user_id": in.UserId, "jti": in.Jti}).
		RunWith(s.UserManagementServiceDB.DB).
		QueryRow().
		Scan(&count)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	if count == 0 {
		return &pb.VerifyTokenRevoationResponse{IsRevoked: false}, nil
	}

	return &pb.VerifyTokenRevoationResponse{IsRevoked: true}, nil
}

func (s *UserManagementService) ListUsers(empty *emptypb.Empty, stream pb.UserManager_ListUsersServer) error {
	rows, err := sq.Select(
		"users.id",
		"users.name",
		"users_email.email",
		"users_email.is_verified",
		"auth_providers.name as auth_provider_name",
		"users.created_at",
		"users.updated_at",
	).
		From("users").
		InnerJoin("users_email ON users.id = users_email.user_id").
		LeftJoin("users_authentication on users.id = users_authentication.user_id").
		LeftJoin("auth_providers on users_authentication.auth_provider_id = auth_providers.id").
		RunWith(s.UserManagementServiceDB.DB).
		Query()
	if err != nil {
		return status.Error(codes.Internal, "failed to query the database")
	}

	for rows.Next() {
		var id uint64
		var name, email, createdAt, updatedAt string
		var verified bool
		var authProvider sql.NullString
		err := rows.Scan(
			&id,
			&name,
			&email,
			&verified,
			&authProvider,
			&createdAt,
			&updatedAt,
		)
		if err != nil {
			return status.Error(codes.Internal, "failed to scan the database")
		}

		err = stream.Send(&pb.User{
			Id:           id,
			Name:         name,
			Email:        email,
			IsVerified:   verified,
			AuthProvider: authProvider.String,
			CreatedAt:    createdAt,
			UpdatedAt:    updatedAt,
		})
		if err != nil {
			return status.Error(codes.Internal, "failed to send the response")
		}
	}
	return nil
}

func (s *UserManagementService) RequestPasswordReset(ctx context.Context, in *pb.RequestPasswordResetRequest) (*pb.RequestPasswordResetResponse, error) {
	// check if the email exists
	var id uint64
	err := sq.Select("users.id").
		From("users").
		InnerJoin("users_email ON users.id = users_email.user_id").
		InnerJoin("users_password ON users.id = users_password.user_id").
		Where(sq.Eq{"email": in.Email}).
		RunWith(s.UserManagementServiceDB.DB).
		QueryRow().
		Scan(&id)
		// if the user does not exist return an error
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	// create the password reset Token
	code, err := utils.GeneratePasswordResetCode()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate password reset code")
	}

	// hash the password reset codes
	hashedCode, err := utils.HashPasswordResetCode(code)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to hash password reset code")
	}
	println(hashedCode)

	// insert the password reset code in the database
	_, err = sq.Insert("passwords_reset").
		Columns("user_id", "code").
		Values(id, hashedCode).
		RunWith(s.UserManagementServiceDB.DB).
		Exec()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// send the password reset code to the user
	_, err = (*s.EmailServiceClient).SendPasswordResetEmail(context.Background(), &pbEmail.SendEmailRequest{To: in.Email, Token: code})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.RequestPasswordResetResponse{Message: "Password reset code sent successfully"}, nil
}

func (s *UserManagementService) ConfirmPasswordReset(ctx context.Context, in *pb.ConfirmPasswordResetRequest) (*pb.ConfirmPasswordResetResponse, error) {
	// check if the code is sent
	if in.Code == "" {
		return nil, status.Error(codes.InvalidArgument, "code is required")
	}

	// hash the code
	hashedCode, err := utils.HashPasswordResetCode(in.Code)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to hash password reset code")
	}

	// check if the code exists
	var passwordReset models.PasswordReset
	err = sq.Select("user_id", "code", "created_at").
		From("passwords_reset").
		Where(sq.Eq{"code": hashedCode}).
		RunWith(s.UserManagementServiceDB.DB).
		QueryRow().
		Scan(&passwordReset.UserID, &passwordReset.Code, &passwordReset.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "code not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	// check if the code is expired
	if utils.IsExpired(passwordReset.CreatedAt) {
		return nil, status.Error(codes.InvalidArgument, "code is expired")
	}

	// check if the passwords are the same
	if in.Password != in.PasswordConfirmation {
		return nil, status.Error(codes.InvalidArgument, "passwords do not match")
	}

	// hash the password
	hashedPassword, err := utils.HashPassword(in.Password)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to hash the password")
	}

	// update the password in the database
	_, err = sq.Update("users_password").
		Where(sq.Eq{"user_id": passwordReset.UserID}).
		Set("password", hashedPassword).
		RunWith(s.UserManagementServiceDB.DB).
		Exec()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// delete the password reset code
	_, err = sq.Delete("passwords_reset").
		Where(sq.Eq{"code": hashedCode}).
		RunWith(s.UserManagementServiceDB.DB).
		Exec()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.ConfirmPasswordResetResponse{Message: "Password reset successfully"}, nil
}

func (s *UserManagementService) RequestEmailVerification(ctx context.Context, in *pb.RequestEmailVerificationRequest) (*pb.RequestEmailVerificationResponse, error) {
	// check if the email is sent
	if in.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	// get the user from the database
	var user models.User
	err := sq.Select("users.id", "users_email.is_verified").
		From("users").
		InnerJoin("users_email ON users.id = users_email.user_id").
		InnerJoin("users_password ON users.id = users_password.user_id").
		Where(sq.Eq{"email": in.Email}).
		RunWith(s.UserManagementServiceDB.DB).
		QueryRow().
		Scan(&user.ID, &user.Verified)
		// if the user does not exist return an error
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "failed to query the database")
	}

	// check if the user is already Verified
	if user.Verified {
		return nil, status.Error(codes.InvalidArgument, "user is already verified")
	}

	// create the email verification Token
	code, err := utils.GenerateEmailVerificationCode()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate email verification code")
	}

	// save the request into the database
	_, err = sq.Insert("email_verification").
		Columns("user_id", "code").
		Values(user.ID, code).
		RunWith(s.UserManagementServiceDB.DB).
		Exec()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to save the email verification request")
	}

	// send the email verification token to the user
	_, err = (*s.EmailServiceClient).SendVerifyEmailEmail(context.Background(), &pbEmail.SendEmailRequest{To: in.Email, Token: code})
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to send email verification token")
	}

	return &pb.RequestEmailVerificationResponse{Message: "Email verification code sent successfully"}, nil
}

// VerifyEmail verifies a user by Email
func (s *UserManagementService) VerifyEmail(ctx context.Context, in *pb.VerifyEmailRequest) (*pb.VerifyEmailResponse, error) {
	// check if the code is sent
	if in.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "code is required")
	}

	// get the email verification code from the database
	var emailVerification models.EmailVerification
	err := sq.Select("user_id", "code", "created_at").
		From("email_verification").
		Where(sq.Eq{"code": in.Token}).
		RunWith(s.UserManagementServiceDB.DB).
		QueryRow().
		Scan(&emailVerification.UserID, &emailVerification.Code, &emailVerification.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "code not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	// check if the code is expired
	if utils.IsExpired(emailVerification.CreatedAt) {
		return nil, status.Error(codes.InvalidArgument, "code is expired")
	}

	// update the email verification status in the database
	_, err = sq.Update("users_email").
		Where(sq.Eq{"user_id": emailVerification.UserID}).
		Set("is_verified", true).
		RunWith(s.UserManagementServiceDB.DB).
		Exec()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// delete the email verification code
	_, err = sq.Delete("email_verification").
		Where(sq.Eq{"code": emailVerification.Code}).
		RunWith(s.UserManagementServiceDB.DB).
		Exec()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.VerifyEmailResponse{Message: "Email verified successfully"}, nil
}

func (s *UserManagementService) ConfirmMFA(ctx context.Context, in *pb.ConfirmMFARequest) (*pb.ConfirmMFAResponse, error) {
	// check if the code is sent
	if in.Code == "" {
		return nil, status.Error(codes.InvalidArgument, "code is required")
	}

	// hash the code
	hashedCode, err := utils.HashMFACode(in.Code)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to hash MFA code")
	}

	// get the MFA code from the database
	var mfaVerification models.MFAVerifiction
	err = sq.Select("user_id", "code", "created_at").
		From("mfa_verification").
		Where(sq.Eq{"code": hashedCode}).
		RunWith(s.UserManagementServiceDB.DB).
		QueryRow().
		Scan(&mfaVerification.UserID, &mfaVerification.Code, &mfaVerification.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "code not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	// check if the code is expired
	if utils.MFAExpired(mfaVerification.CreatedAt) {
		return nil, status.Error(codes.InvalidArgument, "code is expired")
	}

	// delete the MFA code
	_, err = sq.Delete("mfa_verification").
		Where(sq.Eq{"code": mfaVerification.Code}).
		RunWith(s.UserManagementServiceDB.DB).
		Exec()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// get the user from the database
	var user models.User
	err = sq.Select("users.id", "users.name", "users_email.email", "users_email.is_verified").
		From("users").
		InnerJoin("users_email ON users.id = users_email.user_id").
		Where(sq.Eq{"users.id": mfaVerification.UserID}).
		RunWith(s.UserManagementServiceDB.DB).
		QueryRow().
		Scan(&user.ID, &user.Name, &user.Email, &user.Verified)
		// if the user does not exist return an error
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "failed to query the database")
	}

	// generate a JWT token
	token, err := utils.GenerateToken(user)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate token")
	}

	return &pb.ConfirmMFAResponse{Token: token}, nil
}
