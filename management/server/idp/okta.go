package idp

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/okta/okta-sdk-golang/v5/okta"

	"github.com/netbirdio/netbird/management/server/telemetry"
)

// OktaManager okta manager client instance.
type OktaManager struct {
	client      *okta.APIClient
	httpClient  ManagerHTTPClient
	credentials ManagerCredentials
	helper      ManagerHelper
	appMetrics  telemetry.AppMetrics
}

// OktaClientConfig okta manager client configurations.
type OktaClientConfig struct {
	APIToken      string
	Issuer        string
	TokenEndpoint string
	GrantType     string
}

// OktaCredentials okta authentication information.
type OktaCredentials struct {
	clientConfig OktaClientConfig
	helper       ManagerHelper
	httpClient   ManagerHTTPClient
	appMetrics   telemetry.AppMetrics
}

// NewOktaManager creates a new instance of the OktaManager.
func NewOktaManager(config OktaClientConfig, appMetrics telemetry.AppMetrics) (*OktaManager, error) {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxIdleConns = 5

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: httpTransport,
	}

	helper := JsonParser{}
	config.Issuer = baseURL(config.Issuer)

	if config.APIToken == "" {
		return nil, fmt.Errorf("okta IdP configuration is incomplete, APIToken is missing")
	}

	if config.Issuer == "" {
		return nil, fmt.Errorf("okta IdP configuration is incomplete, Issuer is missing")
	}

	if config.TokenEndpoint == "" {
		return nil, fmt.Errorf("okta IdP configuration is incomplete, TokenEndpoint is missing")
	}

	if config.GrantType == "" {
		return nil, fmt.Errorf("okta IdP configuration is incomplete, GrantType is missing")
	}

	oktaConfig, err := okta.NewConfiguration(
		okta.WithOrgUrl(config.Issuer),
		okta.WithToken(config.APIToken),
		okta.WithHttpClientPtr(httpClient),
	)
	if err != nil {
		return nil, err
	}

	credentials := &OktaCredentials{
		clientConfig: config,
		httpClient:   httpClient,
		helper:       helper,
		appMetrics:   appMetrics,
	}

	return &OktaManager{
		client:      okta.NewAPIClient(oktaConfig),
		httpClient:  httpClient,
		credentials: credentials,
		helper:      helper,
		appMetrics:  appMetrics,
	}, nil
}

// Authenticate retrieves access token to use the okta user API.
func (oc *OktaCredentials) Authenticate(_ context.Context) (JWTToken, error) {
	return JWTToken{}, nil
}

// CreateUser creates a new user in okta Idp and sends an invitation.
func (om *OktaManager) CreateUser(_ context.Context, _, _, _, _ string) (*UserData, error) {
	return nil, fmt.Errorf("method CreateUser not implemented")
}

// GetUserDataByID requests user data from Okta via ID.
func (om *OktaManager) GetUserDataByID(ctx context.Context, userID string, appMetadata AppMetadata) (*UserData, error) {
	user, resp, err := om.client.UserAPI.GetUser(ctx, userID).Execute()
	if err != nil {
		return nil, err
	}

	if om.appMetrics != nil {
		om.appMetrics.IDPMetrics().CountGetUserDataByID()
	}

	if resp.StatusCode != http.StatusOK {
		if om.appMetrics != nil {
			om.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return nil, fmt.Errorf("unable to get user %s, statusCode %d", userID, resp.StatusCode)
	}

	userData := parseOktaUser(user)
	userData.AppMetadata = appMetadata

	return userData, nil
}

// GetUserByEmail searches users with a given email.
// If no users have been found, this function returns an empty list.
func (om *OktaManager) GetUserByEmail(_ context.Context, email string) ([]*UserData, error) {
	filter := fmt.Sprintf("profile.email eq \"%s\"", email)
	users, resp, err := om.client.UserAPI.ListUsers(context.Background()).Filter(filter).Execute()
	if err != nil {
		return nil, err
	}

	if om.appMetrics != nil {
		om.appMetrics.IDPMetrics().CountGetUserByEmail()
	}

	if resp.StatusCode != http.StatusOK {
		if om.appMetrics != nil {
			om.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return nil, fmt.Errorf("unable to get user %s, statusCode %d", email, resp.StatusCode)
	}

	usersData := make([]*UserData, 0, len(users))
	for _, user := range users {
		usersData = append(usersData, parseOktaUser(&user))
	}

	return usersData, nil
}

// GetAccount returns all the users for a given profile.
func (om *OktaManager) GetAccount(_ context.Context, accountID string) ([]*UserData, error) {
	users, err := om.getAllUsers()
	if err != nil {
		return nil, err
	}

	if om.appMetrics != nil {
		om.appMetrics.IDPMetrics().CountGetAccount()
	}

	for index, user := range users {
		user.AppMetadata.WTAccountID = accountID
		users[index] = user
	}

	return users, nil
}

// GetAllAccounts gets all registered accounts with corresponding user data.
// It returns a list of users indexed by accountID.
func (om *OktaManager) GetAllAccounts(_ context.Context) (map[string][]*UserData, error) {
	users, err := om.getAllUsers()
	if err != nil {
		return nil, err
	}

	indexedUsers := make(map[string][]*UserData)
	indexedUsers[UnsetAccountID] = append(indexedUsers[UnsetAccountID], users...)

	if om.appMetrics != nil {
		om.appMetrics.IDPMetrics().CountGetAllAccounts()
	}

	return indexedUsers, nil
}

// getAllUsers returns all users in an Okta account.
func (om *OktaManager) getAllUsers() ([]*UserData, error) {
	userList, resp, err := om.client.UserAPI.ListUsers(context.Background()).Limit(200).Execute()
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		if om.appMetrics != nil {
			om.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return nil, fmt.Errorf("unable to get all accounts, statusCode %d", resp.StatusCode)
	}

	for resp.HasNextPage() {
		paginatedUsers := make([]okta.User, 0)
		resp, err = resp.Next(&paginatedUsers)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			if om.appMetrics != nil {
				om.appMetrics.IDPMetrics().CountRequestStatusError()
			}
			return nil, fmt.Errorf("unable to get all accounts, statusCode %d", resp.StatusCode)
		}

		userList = append(userList, paginatedUsers...)
	}

	users := make([]*UserData, 0, len(userList))
	for _, user := range userList {
		users = append(users, parseOktaUser(&user))
	}

	return users, nil
}

// UpdateUserAppMetadata updates user app metadata based on userID and metadata map.
func (om *OktaManager) UpdateUserAppMetadata(_ context.Context, _ string, _ AppMetadata) error {
	return nil
}

// InviteUserByID resend invitations to users who haven't activated,
// their accounts prior to the expiration period.
func (om *OktaManager) InviteUserByID(_ context.Context, _ string) error {
	return fmt.Errorf("method InviteUserByID not implemented")
}

// DeleteUser from Okta
func (om *OktaManager) DeleteUser(_ context.Context, userID string) error {
	resp, err := om.client.UserAPI.DeleteUser(context.Background(), userID).Execute()
	if err != nil {
		return err
	}

	if om.appMetrics != nil {
		om.appMetrics.IDPMetrics().CountDeleteUser()
	}

	if resp.StatusCode != http.StatusOK {
		if om.appMetrics != nil {
			om.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return fmt.Errorf("unable to delete user, statusCode %d", resp.StatusCode)
	}

	return nil
}

// oktaUser interface for Okta user.
type oktaUser interface {
	GetId() string
	GetProfile() okta.UserProfile
}

// parseOktaUser parse okta user to UserData.
func parseOktaUser(user oktaUser) *UserData {
	profile := user.GetProfile()

	var names []string
	if firstName := profile.GetFirstName(); firstName != "" {
		names = append(names, firstName)
	}
	if lastName := profile.GetLastName(); lastName != "" {
		names = append(names, lastName)
	}

	return &UserData{
		Email: profile.GetEmail(),
		Name:  strings.Join(names, " "),
		ID:    user.GetId(),
	}
}
