package modules

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/matoous/go-nanoid/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/isaacwassouf/authentication-service/actions"
	"github.com/isaacwassouf/authentication-service/consts"
	pbcryptography "github.com/isaacwassouf/authentication-service/protobufs/cryptography_service"
	pb "github.com/isaacwassouf/authentication-service/protobufs/users_management_service"
	"github.com/isaacwassouf/authentication-service/utils"
)

func (s *UserManagementService) ListAuthProviders(ctx context.Context, in *emptypb.Empty) (*pb.ListAuthProvidersResponse, error) {
	// get the list of auth providers
	rows, err := sq.Select(
		"auth_providers.id",
		"auth_providers.name",
		"auth_providers_details.client_id",
		"auth_providers_details.redirect_url",
		"auth_providers_details.active",
	).
		From("auth_providers").
		Join("auth_providers_details ON auth_providers.id = auth_providers_details.auth_provider_id").
		RunWith(s.UserManagementServiceDB.DB).
		Query()
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to query the database")
	}

	var authProviders []*pb.AuthProvider
	for rows.Next() {
		var id uint64
		var name string
		var clientId sql.NullString
		var redirectUrl sql.NullString
		var active bool
		err := rows.Scan(&id, &name, &clientId, &redirectUrl, &active)
		if err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}

		authProvider := pb.AuthProvider{
			Id:          id,
			Name:        name,
			ClientId:    clientId.String,
			RedirectUri: redirectUrl.String,
			Active:      active,
		}

		authProviders = append(authProviders, &authProvider)
	}

	return &pb.ListAuthProvidersResponse{AuthProviders: authProviders}, nil
}

func (s *UserManagementService) GetAuthProviderCredentials(ctx context.Context, in *pb.GetAuthProviderCredentialsRequest) (*pb.GetAuthProviderCredentialsResponse, error) {
	// check if auth provider is enabled

	var authProviderName string

	switch in.AuthProvider {
	case pb.AuthProviderName_GOOGLE:
		authProviderName = consts.GOOGLE
	case pb.AuthProviderName_GITHUB:
		authProviderName = consts.GITHUB
	default:
		return nil, status.Error(codes.InvalidArgument, "Invalid auth provider")
	}

	active, err := utils.CheckAuthProviderIsActive(authProviderName, s.UserManagementServiceDB.DB)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to check if GitHub is enabled")
	}

	if !active {
		return nil, status.Error(codes.PermissionDenied, "Auth provider is not enabled")
	}

	// get the client_id and client_secret for the auth provider
	var clientId sql.NullString
	var clientSecret sql.NullString
	var redirectUrl sql.NullString

	err = sq.Select("client_id", "client_secret", "redirect_url").
		From("auth_providers_details").
		Join("auth_providers ON auth_providers.id = auth_providers_details.auth_provider_id").
		Where(sq.Eq{"auth_providers.name": authProviderName}).RunWith(s.UserManagementServiceDB.DB).Scan(&clientId, &clientSecret, &redirectUrl)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "Auth provider not found")
		}
		return nil, status.Error(codes.Internal, "Failed to get the credentials")
	}

	// check if the client_id and client_secret are set
	if !clientId.Valid || !clientSecret.Valid || !redirectUrl.Valid {
		return nil, status.Error(codes.InvalidArgument, "Client ID, Client Secret, or redirectURL are not set")
	}

	// decrypt the client_secret
	decryptedClientSecret, err := (*s.CryptographyServiceClient).Decrypt(ctx, &pbcryptography.DecryptRequest{Ciphertext: clientSecret.String})
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to decrypt the client secret")
	}

	return &pb.GetAuthProviderCredentialsResponse{ClientId: clientId.String, ClientSecret: decryptedClientSecret.Plaintext, RedirectUri: redirectUrl.String}, nil
}

// SetAuthProviderCredentials sets the client_id and client_secret for an external auth provider
func (s *UserManagementService) SetAuthProviderCredentials(
	ctx context.Context,
	in *pb.SetAuthProviderCredentialsRequest,
) (*pb.SetAuthProviderCredentialsResponse, error) {
	// check if the provider exists
	var count int
	err := sq.Select("COUNT(*)").
		From("auth_providers").
		Where(sq.Eq{"id": in.AuthProviderId}).
		RunWith(s.UserManagementServiceDB.DB).
		QueryRow().
		Scan(&count)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed query the database")
	}

	if count == 0 {
		return nil, status.Error(codes.NotFound, "Auth provider not found")
	}

	// encrypt the client_secret
	encryptedClientSecret, err := (*s.CryptographyServiceClient).Encrypt(ctx, &pbcryptography.EncryptRequest{Plaintext: in.ClientSecret})
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to encrypt the client secret")
	}

	// set the credentials i.e., client_id and client_secret
	_, err = sq.Update("auth_providers_details").
		Where(sq.Eq{"auth_provider_id": in.AuthProviderId}).
		Set("client_id", in.ClientId).
		Set("client_secret", encryptedClientSecret.Ciphertext).
		Set("redirect_url", in.RedirectUri).
		Set("updated_at", time.Now()).
		RunWith(s.UserManagementServiceDB.DB).
		Exec()
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to set the credentials")
	}

	return &pb.SetAuthProviderCredentialsResponse{Message: "Credentials set successfully"}, nil
}

// EnableAuthProvider enables an external auth provider
func (s *UserManagementService) EnableAuthProvider(
	ctx context.Context,
	in *pb.EnableAuthProviderRequest,
) (*pb.EnableAuthProviderResponse, error) {
	var clientid, clientsecret, redirectURL sql.NullString
	err := sq.Select("client_id", "client_secret", "redirect_url").
		From("auth_providers_details").
		Where(sq.Eq{"auth_provider_id": in.AuthProviderId}).
		RunWith(s.UserManagementServiceDB.DB).
		QueryRow().
		Scan(&clientid, &clientsecret, &redirectURL)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "Auth provider not found")
		}
		return nil, status.Error(codes.Internal, "Failed to query the database")
	}

	// check if the client_id and client_secret are set
	if !clientid.Valid || !clientsecret.Valid || !redirectURL.Valid {
		return nil, status.Error(codes.InvalidArgument, "Client ID, Client Secret, or redirectURL are not set")
	}

	// set the active field to true in the auth_providers_details table
	_, err = sq.Update("auth_providers_details").
		Where(sq.Eq{"auth_provider_id": in.AuthProviderId}).
		Set("active", true).
		Set("updated_at", time.Now()).
		RunWith(s.UserManagementServiceDB.DB).
		Exec()
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to enable the auth provider")
	}

	return &pb.EnableAuthProviderResponse{Message: "Auth provider enabled successfully"}, nil
}

// DisableAuthProvider disables an external auth provider
func (s *UserManagementService) DisableAuthProvider(
	ctx context.Context,
	in *pb.DisableAuthProviderRequest,
) (*pb.DisableAuthProviderResponse, error) {
	// check if the provider exists
	var count int
	err := sq.Select("COUNT(*)").
		From("auth_providers").
		Where(sq.Eq{"id": in.AuthProviderId}).
		RunWith(s.UserManagementServiceDB.DB).
		QueryRow().
		Scan(&count)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed query the database")
	}

	if count == 0 {
		return nil, status.Error(codes.NotFound, "Auth provider not found")
	}

	// set the active field to true in the auth_providers_details table
	_, err = sq.Update("auth_providers_details").
		Where(sq.Eq{"auth_provider_id": in.AuthProviderId}).
		Set("active", false).
		Set("updated_at", time.Now()).
		RunWith(s.UserManagementServiceDB.DB).
		Exec()
	if err != nil {
		fmt.Println(err)
		return nil, status.Error(codes.Internal, "Failed to enable the auth provider")
	}

	return &pb.DisableAuthProviderResponse{Message: "Auth provider disabled successfully"}, nil
}

func (s *UserManagementService) GetGoogleAuthorizationUrl(
	ctx context.Context,
	in *emptypb.Empty,
) (*pb.GoogleAuthorizationUrlResponse, error) {
	// set the base url for the google authorization url
	baseURL, err := url.ParseRequestURI("https://accounts.google.com/o/oauth2/v2/auth")
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to parse the base url")
	}

	var clientId, redirectURL sql.NullString
	var active bool
	// get the client_id and active fields from the auth_providers_details table
	query := sq.Select("auth_providers_details.client_id", "auth_providers_details.redirect_url", "auth_providers_details.active").
		From("auth_providers").
		Join("auth_providers_details ON auth_providers.id = auth_providers_details.auth_provider_id").
		Where(sq.Eq{"auth_providers.name": consts.GOOGLE})

	err = query.RunWith(s.UserManagementServiceDB.DB).QueryRow().Scan(&clientId, &redirectURL, &active)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "Auth provider not found")
		}
		return nil, status.Error(codes.Internal, "Failed to query the database")
	}

	// check if the client_id and the redirect_url are set
	if !clientId.Valid || !redirectURL.Valid {
		return nil, status.Error(codes.InvalidArgument, "Client ID or redirect URL are not set")
	}

	// check if the auth provider is active
	if !active {
		return nil, status.Error(codes.PermissionDenied, "Auth provider is not active")
	}

	// generate a random state
	state, err := gonanoid.New()
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to generate a random state")
	}

	params := url.Values{}
	params.Add("client_id", clientId.String)
	params.Add("response_type", "code")
	params.Add("scope", "openid email profile")
	params.Add("state", state)
	params.Add("redirect_uri", redirectURL.String)

	baseURL.RawQuery = params.Encode()

	return &pb.GoogleAuthorizationUrlResponse{Url: baseURL.String(), State: state}, nil
}

func (s *UserManagementService) HandleGoogleLogin(
	ctx context.Context,
	in *pb.GoogleLoginRequest,
) (*pb.GoogleLoginResponse, error) {
	// check if Google is enabled
	active, err := utils.CheckAuthProviderIsActive(consts.GOOGLE, s.UserManagementServiceDB.DB)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to check if Google is enabled")
	}
	if !active {
		return nil, status.Error(codes.PermissionDenied, "Google is not enabled")
	}

	// get the external auth user by email
	user, err := utils.GetExternalAuthUserByEmail(consts.GOOGLE, in.Email, s.UserManagementServiceDB.DB)
	if err != nil {
		// the user does not exist, create a new user
		if errors.Is(err, sql.ErrNoRows) {
			id, err := actions.CreateGoogleUser(in, s.UserManagementServiceDB.DB)
			if err != nil {
				return nil, err
			}
			// get the user from the database from its id
			user, err = utils.GetExternalAuthUserByID(consts.GOOGLE, id, s.UserManagementServiceDB.DB)
			if err != nil {
				return nil, status.Error(codes.Internal, "Failed to get the user")
			}

			// generate a JWT token
			token, err := utils.GenerateToken(user)
			if err != nil {
				return nil, status.Error(codes.Internal, "Failed to generate token")
			}

			return &pb.GoogleLoginResponse{Message: "Logged in successfully", Token: token}, nil
		}
		return nil, status.Error(codes.Internal, "Failed to get the user")
	}

	// generate a JWT token
	token, err := utils.GenerateToken(user)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to generate token")
	}

	return &pb.GoogleLoginResponse{Message: "Logged in successfully", Token: token}, nil
}

func (s *UserManagementService) GetGitHubAuthorizationUrl(
	ctx context.Context, in *emptypb.Empty,
) (*pb.GitHubAuthorizationUrlResponse, error) {
	// set the base url for the github authorization url
	baseURL, err := url.ParseRequestURI("https://github.com/login/oauth/authorize")
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to parse the base url")
	}

	var clientID, redirectURL sql.NullString
	var active bool
	query := sq.Select("auth_providers_details.client_id", "auth_providers_details.redirect_url", "auth_providers_details.active").
		From("auth_providers").
		Join("auth_providers_details ON auth_providers.id = auth_providers_details.auth_provider_id").
		Where(sq.Eq{"auth_providers.name": consts.GITHUB})

	err = query.RunWith(s.UserManagementServiceDB.DB).QueryRow().Scan(&clientID, &redirectURL, &active)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "Auth provider not found")
		}
		return nil, status.Error(codes.Internal, "Failed to query the database")
	}

	if !clientID.Valid || !redirectURL.Valid {
		return nil, status.Error(codes.Internal, "Client ID or Redirect URL are not set")
	}

	if !active {
		return nil, status.Error(codes.PermissionDenied, "Auth provider is not active")
	}

	params := url.Values{}
	params.Add("client_id", clientID.String)
	params.Add("scope", "read:user user:email")
	params.Add("state", "random_state")
	params.Add("redirect_uri", redirectURL.String)

	baseURL.RawQuery = params.Encode()

	return &pb.GitHubAuthorizationUrlResponse{Url: baseURL.String()}, nil
}

func (s *UserManagementService) HandleGitHubLogin(ctx context.Context, in *pb.GitHubLoginRequest) (*pb.GitHubLoginResponse, error) {
	// check if GitHub is enabled
	active, err := utils.CheckAuthProviderIsActive(consts.GITHUB, s.UserManagementServiceDB.DB)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to check if GitHub is enabled")
	}
	if !active {
		return nil, status.Error(codes.PermissionDenied, "GitHub is not enabled")
	}

	// get the external auth user by email
	user, err := utils.GetExternalAuthUserByEmail(consts.GITHUB, in.Email, s.UserManagementServiceDB.DB)
	if err != nil {
		// the user does not exist, create a new user
		if errors.Is(err, sql.ErrNoRows) {
			id, err := actions.CreateGitHubUser(in, s.UserManagementServiceDB.DB)
			if err != nil {
				return nil, err
			}
			// get the user from the database from its id
			user, err = utils.GetExternalAuthUserByID(consts.GITHUB, id, s.UserManagementServiceDB.DB)
			if err != nil {
				return nil, status.Error(codes.Internal, "Failed to get the user")
			}

			// generate a JWT token
			token, err := utils.GenerateToken(user)
			if err != nil {
				return nil, status.Error(codes.Internal, "Failed to generate token")
			}

			return &pb.GitHubLoginResponse{Message: "Logged in successfully", Token: token}, nil
		}
		return nil, status.Error(codes.Internal, "Failed to get the user")
	}

	// generate a JWT token
	token, err := utils.GenerateToken(user)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to generate token")
	}

	return &pb.GitHubLoginResponse{Message: "Logged in successfully", Token: token}, nil
}
