package idp

import (
	"context"
	"fmt"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type OktaManager struct {
	client      *okta.Client
	httpClient  ManagerHTTPClient
	credentials ManagerCredentials
	helper      ManagerHelper
	appMetrics  telemetry.AppMetrics
}

// OktaClientConfig okta manager client configurations.
type OktaClientConfig struct {
	ApiToken      string
	Issuer        string
	TokenEndpoint string
	GrantType     string
}

// OktaCredentials okta authentication information.
type OktaCredentials struct {
	clientConfig OktaClientConfig
	helper       ManagerHelper
	httpClient   ManagerHTTPClient
	jwtToken     JWTToken
	mux          sync.Mutex
	appMetrics   telemetry.AppMetrics
}

// NewOktaManager creates a new instance of the OktaManager.
func NewOktaManager(oidcConfig OIDCConfig, config OktaClientConfig,
	appMetrics telemetry.AppMetrics) (*OktaManager, error) {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxIdleConns = 5

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: httpTransport,
	}

	helper := JsonParser{}
	config.Issuer = oidcConfig.Issuer
	config.TokenEndpoint = oidcConfig.TokenEndpoint
	config.GrantType = "client_credentials"

	if config.ApiToken == "" {
		return nil, fmt.Errorf("okta IdP configuration is incomplete, ApiToken is missing")
	}

	_, client, err := okta.NewClient(context.Background(),
		okta.WithOrgUrl(config.Issuer),
		okta.WithToken(config.ApiToken),
	)
	if err != nil {
		return nil, err
	}

	err = updateUserProfileSchema(client)
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

func (oc *OktaCredentials) Authenticate() (JWTToken, error) {
	return JWTToken{}, nil
}

func (om *OktaManager) CreateUser(email string, name string, accountID string) (*UserData, error) {
	var (
		sendEmail   = true
		activate    = true
		userProfile = okta.UserProfile{
			"email":         email,
			"login":         email,
			wtAccountID:     accountID,
			wtPendingInvite: true,
		}
	)

	fields := strings.Fields(name)
	if n := len(fields); n > 0 {
		userProfile["firstName"] = strings.Join(fields[:n-1], " ")
		userProfile["lastName"] = fields[n-1]
	}

	user, resp, err := om.client.User.CreateUser(context.Background(),
		okta.CreateUserRequest{
			Profile: &userProfile,
		},
		&query.Params{
			Activate:  &activate,
			SendEmail: &sendEmail,
		},
	)
	if err != nil {
		return nil, err
	}

	if om.appMetrics != nil {
		om.appMetrics.IDPMetrics().CountCreateUser()
	}

	if resp.StatusCode != http.StatusOK {
		if om.appMetrics != nil {
			om.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return nil, fmt.Errorf("unable to create user, statusCode %d", resp.StatusCode)
	}

	return parseOktaUser(user)
}

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

	return parseOktaUser(user)
}

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

func (om *OktaManager) GetAccount(accountID string) ([]*UserData, error) {
	search := fmt.Sprintf("profile.wt_account_id eq %q", accountID)
	users, resp, err := om.client.User.ListUsers(context.Background(), &query.Params{Search: search})
	if err != nil {
		return nil, err
	}

	if om.appMetrics != nil {
		om.appMetrics.IDPMetrics().CountGetAccount()
	}

	if resp.StatusCode != http.StatusOK {
		if om.appMetrics != nil {
			om.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return nil, fmt.Errorf("unable to get account, statusCode %d", resp.StatusCode)
	}

	list := make([]*UserData, 0)
	for _, user := range users {
		userData, err := parseOktaUser(user)
		if err != nil {
			return nil, err
		}

		list = append(list, userData)
	}

	return list, nil
}

func (om *OktaManager) GetAllAccounts() (map[string][]*UserData, error) {
	//TODO implement me
	panic("implement me")
}

func (om *OktaManager) UpdateUserAppMetadata(userID string, appMetadata AppMetadata) error {
	var pendingInvite bool
	if appMetadata.WTPendingInvite != nil {
		pendingInvite = *appMetadata.WTPendingInvite
	}

	_, resp, err := om.client.User.UpdateUser(context.Background(), userID,
		okta.User{
			Profile: &okta.UserProfile{
				wtAccountID:     appMetadata.WTAccountID,
				wtPendingInvite: pendingInvite,
			},
		},
		nil,
	)
	if err != nil {
		return err
	}

	if om.appMetrics != nil {
		om.appMetrics.IDPMetrics().CountUpdateUserAppMetadata()
	}

	if resp.StatusCode != http.StatusOK {
		if om.appMetrics != nil {
			om.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return fmt.Errorf("unable to update user, statusCode %d", resp.StatusCode)
	}

	return nil
}

// updateUserProfileSchema updates the Okta user schema to include custom fields,
// wt_account_id and wt_pending_invite.
func updateUserProfileSchema(client *okta.Client) error {
	required := true
	_, resp, err := client.UserSchema.UpdateUserProfile(
		context.Background(),
		"default",
		okta.UserSchema{
			Definitions: &okta.UserSchemaDefinitions{
				Custom: &okta.UserSchemaPublic{
					Id:   "#custom",
					Type: "object",
					Properties: map[string]*okta.UserSchemaAttribute{
						wtAccountID: {
							MaxLength: 100,
							MinLength: 1,
							Required:  &required,
							Scope:     "NONE",
							Title:     "Wt Account Id",
							Type:      "string",
						},
						wtPendingInvite: {
							Required: new(bool),
							Scope:    "NONE",
							Title:    "Wt Account Id",
							Type:     "boolean",
						},
					},
				},
			},
		})
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unable to update user profile schema, statusCode %d", resp.StatusCode)
	}

	return nil
}

// parseOktaUserToUserData parse okta user
func parseOktaUser(user *okta.User) (*UserData, error) {
	var oktaUser struct {
		Email         string `json:"email"`
		FirstName     string `json:"firstName"`
		LastName      string `json:"lastName"`
		AccountID     string `json:"wt_account_id"`
		PendingInvite bool   `json:"wt_pending_invite"`
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
		AppMetadata: AppMetadata{
			WTAccountID:     oktaUser.AccountID,
			WTPendingInvite: &oktaUser.PendingInvite,
		},
	}, nil
}
