package idp

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dexidp/dex/api/v2"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/netbirdio/netbird/management/server/telemetry"
)

// DexManager implements the Manager interface for Dex IDP.
// It uses Dex's gRPC API to manage users in the password database.
type DexManager struct {
	grpcAddr   string
	httpClient ManagerHTTPClient
	helper     ManagerHelper
	appMetrics telemetry.AppMetrics
	mux        sync.Mutex
	conn       *grpc.ClientConn
}

// DexClientConfig Dex manager client configuration.
type DexClientConfig struct {
	// GRPCAddr is the address of Dex's gRPC API (e.g., "localhost:5557")
	GRPCAddr string
	// Issuer is the Dex issuer URL (e.g., "https://dex.example.com/dex")
	Issuer string
}

// NewDexManager creates a new instance of DexManager.
func NewDexManager(config DexClientConfig, appMetrics telemetry.AppMetrics) (*DexManager, error) {
	if config.GRPCAddr == "" {
		return nil, fmt.Errorf("dex IdP configuration is incomplete, GRPCAddr is missing")
	}

	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxIdleConns = 5

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: httpTransport,
	}
	helper := JsonParser{}

	return &DexManager{
		grpcAddr:   config.GRPCAddr,
		httpClient: httpClient,
		helper:     helper,
		appMetrics: appMetrics,
	}, nil
}

// getConnection returns a gRPC connection to Dex, creating one if necessary.
// It also checks if an existing connection is still healthy and reconnects if needed.
func (dm *DexManager) getConnection(ctx context.Context) (*grpc.ClientConn, error) {
	dm.mux.Lock()
	defer dm.mux.Unlock()

	if dm.conn != nil {
		state := dm.conn.GetState()
		// If connection is shutdown or in a transient failure, close and reconnect
		if state == connectivity.Shutdown || state == connectivity.TransientFailure {
			log.WithContext(ctx).Debugf("Dex gRPC connection in state %s, reconnecting", state)
			_ = dm.conn.Close()
			dm.conn = nil
		} else {
			return dm.conn, nil
		}
	}

	log.WithContext(ctx).Debugf("connecting to Dex gRPC API at %s", dm.grpcAddr)

	conn, err := grpc.NewClient(dm.grpcAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Dex gRPC API: %w", err)
	}

	dm.conn = conn
	return conn, nil
}

// getDexClient returns a Dex API client.
func (dm *DexManager) getDexClient(ctx context.Context) (api.DexClient, error) {
	conn, err := dm.getConnection(ctx)
	if err != nil {
		return nil, err
	}
	return api.NewDexClient(conn), nil
}

// encodeDexUserID encodes a user ID and connector ID into Dex's composite format.
// This is the reverse of parseDexUserID - it creates the base64-encoded protobuf
// format that Dex uses in JWT tokens.
func encodeDexUserID(userID, connectorID string) string {
	// Build simple protobuf structure:
	// Field 1 (tag 0x0a): user ID string
	// Field 2 (tag 0x12): connector ID string
	buf := make([]byte, 0, 2+len(userID)+2+len(connectorID))

	// Field 1: user ID
	buf = append(buf, 0x0a)              // tag for field 1, wire type 2 (length-delimited)
	buf = append(buf, byte(len(userID))) // length
	buf = append(buf, []byte(userID)...) // value

	// Field 2: connector ID
	buf = append(buf, 0x12)                   // tag for field 2, wire type 2 (length-delimited)
	buf = append(buf, byte(len(connectorID))) // length
	buf = append(buf, []byte(connectorID)...) // value

	return base64.StdEncoding.EncodeToString(buf)
}

// parseDexUserID extracts the actual user ID from Dex's composite user ID.
// Dex encodes user IDs in JWT tokens as base64-encoded protobuf with format:
// - Field 1 (string): actual user ID
// - Field 2 (string): connector ID (e.g., "local")
// If the ID is not in this format, it returns the original ID.
func parseDexUserID(compositeID string) string {
	// Try to decode as standard base64
	decoded, err := base64.StdEncoding.DecodeString(compositeID)
	if err != nil {
		// Try URL-safe base64
		decoded, err = base64.RawURLEncoding.DecodeString(compositeID)
		if err != nil {
			// Not base64 encoded, return as-is
			return compositeID
		}
	}

	// Parse the simple protobuf structure
	// Field 1 (tag 0x0a): user ID string
	// Field 2 (tag 0x12): connector ID string
	if len(decoded) < 2 {
		return compositeID
	}

	// Check for field 1 tag (0x0a = field 1, wire type 2/length-delimited)
	if decoded[0] != 0x0a {
		return compositeID
	}

	// Read the length of the user ID string
	length := int(decoded[1])
	if len(decoded) < 2+length {
		return compositeID
	}

	// Extract the user ID
	userID := string(decoded[2 : 2+length])
	return userID
}

// UpdateUserAppMetadata updates user app metadata based on userID and metadata map.
// Dex doesn't support app metadata, so this is a no-op.
func (dm *DexManager) UpdateUserAppMetadata(_ context.Context, _ string, _ AppMetadata) error {
	return nil
}

// GetUserDataByID requests user data from Dex via user ID.
func (dm *DexManager) GetUserDataByID(ctx context.Context, userID string, _ AppMetadata) (*UserData, error) {
	if dm.appMetrics != nil {
		dm.appMetrics.IDPMetrics().CountGetUserDataByID()
	}

	client, err := dm.getDexClient(ctx)
	if err != nil {
		if dm.appMetrics != nil {
			dm.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, err
	}

	resp, err := client.ListPasswords(ctx, &api.ListPasswordReq{})
	if err != nil {
		if dm.appMetrics != nil {
			dm.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, fmt.Errorf("failed to list passwords from Dex: %w", err)
	}

	// Try to parse the composite user ID from Dex JWT token
	actualUserID := parseDexUserID(userID)

	for _, p := range resp.Passwords {
		// Match against both the raw userID and the parsed actualUserID
		if p.UserId == userID || p.UserId == actualUserID {
			return &UserData{
				Email: p.Email,
				Name:  p.Username,
				ID:    userID, // Return the original ID for consistency
			}, nil
		}
	}

	return nil, fmt.Errorf("user with ID %s not found", userID)
}

// GetAccount returns all the users for a given account.
// Since Dex doesn't have account concepts, this returns all users.
func (dm *DexManager) GetAccount(ctx context.Context, accountID string) ([]*UserData, error) {
	if dm.appMetrics != nil {
		dm.appMetrics.IDPMetrics().CountGetAccount()
	}

	users, err := dm.getAllUsers(ctx)
	if err != nil {
		return nil, err
	}

	// Set the account ID for all users
	for _, user := range users {
		user.AppMetadata.WTAccountID = accountID
	}

	return users, nil
}

// GetAllAccounts gets all registered accounts with corresponding user data.
// Since Dex doesn't have account concepts, all users are returned under UnsetAccountID.
func (dm *DexManager) GetAllAccounts(ctx context.Context) (map[string][]*UserData, error) {
	if dm.appMetrics != nil {
		dm.appMetrics.IDPMetrics().CountGetAllAccounts()
	}

	users, err := dm.getAllUsers(ctx)
	if err != nil {
		return nil, err
	}

	indexedUsers := make(map[string][]*UserData)
	indexedUsers[UnsetAccountID] = users

	return indexedUsers, nil
}

// CreateUser creates a new user in Dex's password database.
func (dm *DexManager) CreateUser(ctx context.Context, email, name, accountID, invitedByEmail string) (*UserData, error) {
	if dm.appMetrics != nil {
		dm.appMetrics.IDPMetrics().CountCreateUser()
	}

	client, err := dm.getDexClient(ctx)
	if err != nil {
		if dm.appMetrics != nil {
			dm.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, err
	}

	// Generate a random password for the new user
	password := GeneratePassword(16, 2, 2, 2)

	// Hash the password using bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Generate a user ID from email (Dex uses email as the key, but we need a stable ID)
	userID := strings.ReplaceAll(email, "@", "-at-")
	userID = strings.ReplaceAll(userID, ".", "-")

	req := &api.CreatePasswordReq{
		Password: &api.Password{
			Email:    email,
			Username: name,
			UserId:   userID,
			Hash:     hashedPassword,
		},
	}

	resp, err := client.CreatePassword(ctx, req)
	if err != nil {
		if dm.appMetrics != nil {
			dm.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, fmt.Errorf("failed to create user in Dex: %w", err)
	}

	if resp.AlreadyExists {
		return nil, fmt.Errorf("user with email %s already exists", email)
	}

	log.WithContext(ctx).Debugf("created user %s in Dex", email)

	return &UserData{
		Email: email,
		Name:  name,
		ID:    userID,
		AppMetadata: AppMetadata{
			WTAccountID: accountID,
			WTInvitedBy: invitedByEmail,
		},
	}, nil
}

// GetUserByEmail searches users with a given email.
// If no users have been found, this function returns an empty list.
func (dm *DexManager) GetUserByEmail(ctx context.Context, email string) ([]*UserData, error) {
	if dm.appMetrics != nil {
		dm.appMetrics.IDPMetrics().CountGetUserByEmail()
	}

	client, err := dm.getDexClient(ctx)
	if err != nil {
		if dm.appMetrics != nil {
			dm.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, err
	}

	resp, err := client.ListPasswords(ctx, &api.ListPasswordReq{})
	if err != nil {
		if dm.appMetrics != nil {
			dm.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, fmt.Errorf("failed to list passwords from Dex: %w", err)
	}

	users := make([]*UserData, 0)
	for _, p := range resp.Passwords {
		if strings.EqualFold(p.Email, email) {
			// Encode the user ID in Dex's composite format to match stored IDs
			encodedID := encodeDexUserID(p.UserId, "local")
			users = append(users, &UserData{
				Email: p.Email,
				Name:  p.Username,
				ID:    encodedID,
			})
		}
	}

	return users, nil
}

// InviteUserByID resends an invitation to a user.
// Dex doesn't support invitations, so this returns an error.
func (dm *DexManager) InviteUserByID(_ context.Context, _ string) error {
	return fmt.Errorf("method InviteUserByID not implemented for Dex")
}

// DeleteUser deletes a user from Dex by user ID.
func (dm *DexManager) DeleteUser(ctx context.Context, userID string) error {
	if dm.appMetrics != nil {
		dm.appMetrics.IDPMetrics().CountDeleteUser()
	}

	client, err := dm.getDexClient(ctx)
	if err != nil {
		if dm.appMetrics != nil {
			dm.appMetrics.IDPMetrics().CountRequestError()
		}
		return err
	}

	// First, find the user's email by ID
	resp, err := client.ListPasswords(ctx, &api.ListPasswordReq{})
	if err != nil {
		if dm.appMetrics != nil {
			dm.appMetrics.IDPMetrics().CountRequestError()
		}
		return fmt.Errorf("failed to list passwords from Dex: %w", err)
	}

	// Try to parse the composite user ID from Dex JWT token
	actualUserID := parseDexUserID(userID)

	var email string
	for _, p := range resp.Passwords {
		if p.UserId == userID || p.UserId == actualUserID {
			email = p.Email
			break
		}
	}

	if email == "" {
		return fmt.Errorf("user with ID %s not found", userID)
	}

	// Delete the user by email
	deleteResp, err := client.DeletePassword(ctx, &api.DeletePasswordReq{
		Email: email,
	})
	if err != nil {
		if dm.appMetrics != nil {
			dm.appMetrics.IDPMetrics().CountRequestError()
		}
		return fmt.Errorf("failed to delete user from Dex: %w", err)
	}

	if deleteResp.NotFound {
		return fmt.Errorf("user with email %s not found", email)
	}

	log.WithContext(ctx).Debugf("deleted user %s from Dex", email)

	return nil
}

// getAllUsers retrieves all users from Dex's password database.
func (dm *DexManager) getAllUsers(ctx context.Context) ([]*UserData, error) {
	client, err := dm.getDexClient(ctx)
	if err != nil {
		if dm.appMetrics != nil {
			dm.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, err
	}

	resp, err := client.ListPasswords(ctx, &api.ListPasswordReq{})
	if err != nil {
		if dm.appMetrics != nil {
			dm.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, fmt.Errorf("failed to list passwords from Dex: %w", err)
	}

	users := make([]*UserData, 0, len(resp.Passwords))
	for _, p := range resp.Passwords {
		// Encode the user ID in Dex's composite format (base64-encoded protobuf)
		// to match how NetBird stores user IDs from Dex JWT tokens.
		// The connector ID "local" is used for Dex's password database.
		encodedID := encodeDexUserID(p.UserId, "local")
		users = append(users, &UserData{
			Email: p.Email,
			Name:  p.Username,
			ID:    encodedID,
		})
	}

	return users, nil
}
