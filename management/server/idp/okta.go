package idp

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"

	"github.com/netbirdio/netbird/management/server/telemetry"
)

// OktaManager okta manager client instance.
type OktaManager struct {
	client      *okta.Client
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

	_, client, err := okta.NewClient(context.Background(),
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
		client:      client,
		httpClient:  httpClient,
		credentials: credentials,
		helper:      helper,
		appMetrics:  appMetrics,
	}, nil
}

// Authenticate retrieves access token to use the okta user API.
func (oc *OktaCredentials) Authenticate() (JWTToken, error) {
	return JWTToken{}, nil
}

// CreateUser creates a new user in okta Idp and sends an invitation.
func (om *OktaManager) CreateUser(_, _, _, _ string) (*UserData, error) {
	return nil, fmt.Errorf("method CreateUser not implemented")
}

// GetUserDataByID requests user data from keycloak via ID.
func (om *OktaManager) GetUserDataByID(userID string, appMetadata AppMetadata) (*UserData, error) {
	user, resp, err := om.client.User.GetUser(context.Background(), userID)
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

	userData, err := parseOktaUser(user)
	if err != nil {
		return nil, err
	}
	userData.AppMetadata = appMetadata

	return userData, nil
}

// GetUserByEmail searches users with a given email.
// If no users have been found, this function returns an empty list.
func (om *OktaManager) GetUserByEmail(email string) ([]*UserData, error) {
	user, resp, err := om.client.User.GetUser(context.Background(), url.QueryEscape(email))
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

	userData, err := parseOktaUser(user)
	if err != nil {
		return nil, err
	}
	users := make([]*UserData, 0)
	users = append(users, userData)

	return users, nil
}

// GetAccount returns all the users for a given profile.
func (om *OktaManager) GetAccount(accountID string) ([]*UserData, error) {
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
func (om *OktaManager) GetAllAccounts() (map[string][]*UserData, error) {
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
	qp := query.NewQueryParams(query.WithLimit(200))
	userList, resp, err := om.client.User.ListUsers(context.Background(), qp)
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
		paginatedUsers := make([]*okta.User, 0)
		resp, err = resp.Next(context.Background(), &paginatedUsers)
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
		userData, err := parseOktaUser(user)
		if err != nil {
			return nil, err
		}

		users = append(users, userData)
	}

	return users, nil
}

// UpdateUserAppMetadata updates user app metadata based on userID and metadata map.
func (om *OktaManager) UpdateUserAppMetadata(userID string, appMetadata AppMetadata) error {
	return nil
}

// InviteUserByID resend invitations to users who haven't activated,
// their accounts prior to the expiration period.
func (om *OktaManager) InviteUserByID(_ string) error {
	return fmt.Errorf("method InviteUserByID not implemented")
}

// DeleteUser from Okta
func (om *OktaManager) DeleteUser(userID string) error {
	resp, err := om.client.User.DeactivateOrDeleteUser(context.Background(), userID, nil)
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

// parseOktaUser parse okta user to UserData.
func parseOktaUser(user *okta.User) (*UserData, error) {
	var oktaUser struct {
		Email     string `json:"email"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	}

	if user == nil {
		return nil, fmt.Errorf("invalid okta user")
	}

	if user.Profile != nil {
		helper := JsonParser{}
		buf, err := helper.Marshal(*user.Profile)
		if err != nil {
			return nil, err
		}

		err = helper.Unmarshal(buf, &oktaUser)
		if err != nil {
			return nil, err
		}
	}

	return &UserData{
		Email: oktaUser.Email,
		Name:  strings.Join([]string{oktaUser.FirstName, oktaUser.LastName}, " "),
		ID:    user.Id,
	}, nil
}
